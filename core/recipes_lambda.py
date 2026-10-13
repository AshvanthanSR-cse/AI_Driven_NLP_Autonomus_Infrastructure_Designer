"""Lambda recipes.

lambda_function  create (or update the code of) a function from a local folder (zip) or a Dockerfile (container
                 image in ECR); runtime, handler, memory, timeout, architecture, environment variables, layers,
                 VPC, tracing, ephemeral storage, log retention, reserved concurrency, dead-letter target; a trigger
                 (schedule, S3 event, SQS queue, DynamoDB stream, SNS topic, HTTP API, function URL); optional
                 version + alias with provisioned concurrency.
lambda_manage    an existing function: change settings, add a trigger, publish a version / move an alias (with
                 weighted traffic shifting), function URL, concurrency, delete.

Schedules: 'daily 10:00' is converted to UTC by code for EventBridge rules. Public function URLs (no auth) need
the typed confirmation. Secrets are never put in environment variables (rejected by name/value).
"""
import re
from pathlib import Path

from core import lookups, templates, workspace
from core.recipe_kit import (action_is, both, choice, custom, extra_params_field, ids, kv_pairs, merge_extra,
                             no_secrets, number, opts, pick, pick_many, settings_field, static, yes, yes_no)
from core.recipes import (MANAGED_POLICIES, RUNTIMES, _check_tools, _folder, _guess_handler, _guess_runtime,
                          _lambda_exists, _lambda_notes, _name_validator, _role_options, _src, _validate_handler,
                          _validate_role, _validate_schedule, aws_step, docker_context, image_steps, role_steps,
                          tag_dict, tag_list, undo)
from core.scripts import ScriptDraft
from core.templates import FieldSpec, Template, TemplateError, _choice, _int
from core.workspace import WorkspaceError

POLICY_SQS = "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole"
POLICY_DDB = "arn:aws:iam::aws:policy/service-role/AWSLambdaDynamoDBExecutionRole"
POLICY_VPC = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
POLICY_XRAY = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
TRIGGERS = opts(("none", "No trigger (invoke it yourself / from other services)"),
                ("schedule", "On a schedule (EventBridge)"), ("s3", "When files change in an S3 bucket"),
                ("sqs", "Messages in an SQS queue"), ("dynamodb", "Changes in a DynamoDB table (stream)"),
                ("sns", "Messages on an SNS topic"), ("api", "HTTP API (API Gateway, public HTTPS endpoint)"),
                ("url", "Function URL (simple HTTPS endpoint, no API Gateway)"))
PACKAGES = opts(("zip", "Code folder (zip)"), ("image", "Container image from a Dockerfile (pushed to ECR)"))
_LAYER_RE = re.compile(r"arn:aws[\w-]*:lambda:[a-z0-9-]+:\d{12}:layer:[\w-]+:\d+")


def _fn_options(env, inputs):
    return [{"value": f["name"], "label": f"{f['name']} ({f['runtime']})"} for f in lookups.lambda_functions(env)]


def _validate_layers(env, inputs, v) -> list[str]:
    out = ids(v)
    bad = [x for x in out if not _LAYER_RE.fullmatch(x)]
    if bad:
        raise ValueError(f"not a layer version ARN (arn:aws:lambda:<region>:<account>:layer:<name>:<version>): {bad[0]}")
    if len(out) > 5:
        raise ValueError("a function can use at most 5 layers")
    return out


def _validate_env(env, inputs, v) -> str:
    no_secrets(kv_pairs(v, "environment variables"), "environment variables")
    return str(v or "").strip()


def _validate_origins(env, inputs, v) -> str:
    out = []
    for o in ids(v):
        if o != "*" and not re.fullmatch(r"https?://[\w.-]+(:\d+)?", o):
            raise ValueError(f"'{o}' must look like https://example.com (or *)")
        out.append(o)
    return ",".join(out)


def _queue_options(env, inputs):
    return [{"value": u, "label": u.rsplit("/", 1)[-1]} for u in lookups.sqs_queues(env)]


def _topic_options(env, inputs):
    return [{"value": t, "label": t.rsplit(":", 1)[-1]} for t in lookups.sns_topics(env)]


def _bucket_options(env, inputs):
    return [{"value": b, "label": b} for b in lookups.buckets(env)]


def _stream_options(env, inputs):
    def load():
        ddb = env.conn.client("dynamodb", "read", env.region)
        out = []
        for name in ddb.list_tables().get("TableNames", []):
            t = ddb.describe_table(TableName=name)["Table"]
            if t.get("LatestStreamArn") and t.get("StreamSpecification", {}).get("StreamEnabled"):
                out.append({"value": t["LatestStreamArn"], "label": f"{name} (stream on)"})
        return out
    return env._memo("ddb_streams", load)


def _subnet_options(env, inputs):
    return [{"value": s["id"], "label": f"{s['id']} · {s['az']} · {s['cidr']} · {'public' if s['public'] else 'private'}"}
            for s in env.subnets()]


def _sg_options(env, inputs):
    vpc = lookups.vpc_of_subnets(env, ids(inputs.get("subnets")))
    return [{"value": g["id"], "label": f"{g['id']} · {g['name']}"} for g in env.security_groups(vpc)] if vpc else []


def _first(options: list[dict]):
    return options[0]["value"] if options else None


def _schedule_text(env, inputs, v):
    out = _validate_schedule(env, inputs, v)
    if out == "none":
        raise ValueError("give a schedule, e.g. 'daily 10:00' or rate(1 hour)")
    return out


def trigger_fields(rel=lambda i: True) -> list[FieldSpec]:
    """Questions for one trigger (shared by lambda_function and lambda_manage)."""
    t = lambda *names: (lambda i: rel(i) and i.get("trigger", "none") in names)
    return [
        FieldSpec("trigger_schedule", "When? ('daily 10:00' in your timezone, 'hourly', cron(...) in UTC or rate(...))",
                  "text", must_ask=True, default="daily 10:00", validate=_schedule_text, relevant=t("schedule")),
        FieldSpec("trigger_bucket", "Which bucket?", "choice", must_ask=True, options=_bucket_options,
                  default=lambda e, i: _first(_bucket_options(e, i)),
                  validate=pick(_bucket_options, "bucket"), relevant=t("s3"), empty_hint="You have no S3 buckets."),
        choice("trigger_events", "Which events?", opts(("created", "Object created"), ("removed", "Object deleted"),
                                                       ("both", "Created and deleted")), default="created",
               relevant=t("s3")),
        FieldSpec("trigger_prefix", "Only keys starting with? (optional, e.g. uploads/)", "text", default="",
                  allow_empty=True, relevant=t("s3")),
        FieldSpec("trigger_suffix", "Only keys ending with? (optional, e.g. .jpg)", "text", default="",
                  allow_empty=True, relevant=t("s3")),
        FieldSpec("trigger_queue", "Which queue?", "choice", must_ask=True, options=_queue_options,
                  default=lambda e, i: _first(_queue_options(e, i)),
                  validate=pick(_queue_options, "queue"), relevant=t("sqs"), empty_hint="No SQS queues in this region."),
        FieldSpec("trigger_stream", "Which table (with streams on)?", "choice", must_ask=True, options=_stream_options,
                  default=lambda e, i: _first(_stream_options(e, i)),
                  validate=pick(_stream_options, "table stream"), relevant=t("dynamodb"),
                  empty_hint="No DynamoDB table has a stream turned on (database recipe: streams)."),
        number("batch_size", "Batch size (records per invocation)?", 10, 1, 10000, relevant=t("sqs", "dynamodb")),
        FieldSpec("trigger_topic", "Which topic?", "choice", must_ask=True, options=_topic_options,
                  default=lambda e, i: _first(_topic_options(e, i)),
                  validate=pick(_topic_options, "topic"), relevant=t("sns"), empty_hint="No SNS topics in this region."),
        choice("url_auth", "Who may call the URL?",
               opts(("AWS_IAM", "Only signed requests from AWS identities (IAM auth)"),
                    ("NONE", "Anyone on the internet (public; needs the typed confirmation)")),
               default="AWS_IAM", must_ask=True, relevant=t("url", "api")),
        FieldSpec("cors_origins", "CORS: which websites may call it from a browser? (optional)", "text", default="",
                  allow_empty=True, validate=_validate_origins, relevant=t("url", "api")),
    ]


def trigger_steps(env, v: dict, fn: str, fn_arn: str) -> tuple[list[dict], list[str]]:
    """Steps that connect the function to its trigger. Returns (steps, notes)."""
    trig = v.get("trigger", "none")
    acct, region = env.account_id(), env.region_name
    steps: list[dict] = []
    notes: list[str] = []
    if trig == "schedule":
        rule = f"{fn}-schedule"[:64]
        steps += [
            aws_step("events", "put_rule", {"Name": rule, "ScheduleExpression": v["trigger_schedule"], "State": "ENABLED",
                                            "Description": f"Kintsugi schedule for {fn}", "Tags": tag_list(rule)},
                     f"Create EventBridge schedule {rule}: {v['trigger_schedule']}", save_as="rule",
                     undo=undo("events", "delete_rule", {"Name": rule}, f"Delete schedule {rule}")),
            aws_step("lambda", "add_permission",
                     {"FunctionName": fn, "StatementId": f"kintsugi-{rule}"[:100], "Action": "lambda:InvokeFunction",
                      "Principal": "events.amazonaws.com", "SourceArn": "{{rule.RuleArn}}"},
                     "Allow EventBridge to invoke the function",
                     undo=undo("lambda", "remove_permission", {"FunctionName": fn, "StatementId": f"kintsugi-{rule}"[:100]},
                               "Remove the EventBridge permission")),
            aws_step("events", "put_targets", {"Rule": rule, "Targets": [{"Id": "1", "Arn": fn_arn}]},
                     f"Point the schedule at {fn}",
                     undo=undo("events", "remove_targets", {"Rule": rule, "Ids": ["1"]}, "Remove the schedule target")),
        ]
        from core.recipes import _schedule_note
        if (n := _schedule_note(v["trigger_schedule"])):
            notes.append(n)
    elif trig == "s3":
        from core.recipes_storage import _bucket_region, _notification_steps
        bucket = v["trigger_bucket"]
        steps += _notification_steps(env, {"notify": "lambda", "notify_target": fn_arn, "action": "configure",
                                           "notify_events": v.get("trigger_events", "created"),
                                           "notify_prefix": v.get("trigger_prefix", ""),
                                           "notify_suffix": v.get("trigger_suffix", "")},
                                     bucket, _bucket_region(env, bucket))
        notes.append("Do not let the function write back into the same prefix it is triggered by (endless loop).")
    elif trig in ("sqs", "dynamodb"):
        src = lookups.queue_arn(env, v["trigger_queue"]) if trig == "sqs" else v["trigger_stream"]
        p = {"EventSourceArn": src, "FunctionName": fn, "BatchSize": int(v.get("batch_size", 10)), "Enabled": True,
             "Tags": tag_dict(f"{fn}-{trig}")}
        if trig == "dynamodb":
            p["StartingPosition"] = "LATEST"
        steps.append(aws_step("lambda", "create_event_source_mapping", p,
                              f"Feed {'messages from ' + src.rsplit(':', 1)[-1] if trig == 'sqs' else 'table changes'} "
                              f"to {fn} in batches of {p['BatchSize']}", save_as="esm",
                              undo=undo("lambda", "delete_event_source_mapping", {"UUID": "{{esm.UUID}}"},
                                        "Remove the event source mapping")))
        notes.append(f"The function's role needs {'SQS receive/delete' if trig == 'sqs' else 'DynamoDB stream read'} "
                     "permissions (added automatically to a new role).")
    elif trig == "sns":
        topic = v["trigger_topic"]
        sid = f"kintsugi-sns-{topic.rsplit(':', 1)[-1]}"[:100]
        steps += [
            aws_step("lambda", "add_permission", {"FunctionName": fn, "StatementId": sid, "Action": "lambda:InvokeFunction",
                                                  "Principal": "sns.amazonaws.com", "SourceArn": topic},
                     "Allow the topic to invoke the function",
                     undo=undo("lambda", "remove_permission", {"FunctionName": fn, "StatementId": sid},
                               "Remove the SNS permission")),
            aws_step("sns", "subscribe", {"TopicArn": topic, "Protocol": "lambda", "Endpoint": fn_arn,
                                          "ReturnSubscriptionArn": True},
                     f"Subscribe {fn} to {topic.rsplit(':', 1)[-1]}", save_as="sub",
                     undo=undo("sns", "unsubscribe", {"SubscriptionArn": "{{sub.SubscriptionArn}}"}, "Unsubscribe")),
        ]
    elif trig == "api":
        cors = [o for o in str(v.get("cors_origins", "")).split(",") if o]
        p = {"Name": f"{fn}-api", "ProtocolType": "HTTP", "Target": fn_arn, "Tags": tag_dict(f"{fn}-api")}
        if cors:
            p["CorsConfiguration"] = {"AllowOrigins": cors, "AllowMethods": ["*"], "AllowHeaders": ["*"]}
        steps += [
            aws_step("apigatewayv2", "create_api", p, f"Create HTTP API {fn}-api in front of the function", save_as="api",
                     undo=undo("apigatewayv2", "delete_api", {"ApiId": "{{api.ApiId}}"}, "Delete the HTTP API")),
            aws_step("lambda", "add_permission",
                     {"FunctionName": fn, "StatementId": f"kintsugi-api-{fn}"[:100], "Action": "lambda:InvokeFunction",
                      "Principal": "apigateway.amazonaws.com",
                      "SourceArn": f"arn:aws:execute-api:{region}:{acct}:{{{{api.ApiId}}}}/*/*"},
                     "Allow the API to invoke the function",
                     undo=undo("lambda", "remove_permission", {"FunctionName": fn, "StatementId": f"kintsugi-api-{fn}"[:100]},
                               "Remove the API permission")),
        ]
        notes.append("The API URL (https://<id>.execute-api....amazonaws.com) is in the run log; it is public. Add "
                     "authorization in API Gateway if the function must be private. HTTP APIs cost ~$1 per million "
                     "requests (free tier: 1 million/month for 12 months).")
    elif trig == "url":
        cors = [o for o in str(v.get("cors_origins", "")).split(",") if o]
        p = {"FunctionName": fn, "AuthType": v.get("url_auth", "AWS_IAM")}
        if cors:
            p["Cors"] = {"AllowOrigins": cors, "AllowMethods": ["*"], "AllowHeaders": ["*"]}
        steps.append(aws_step("lambda", "create_function_url_config", p,
                              f"Create a function URL ({'public' if p['AuthType'] == 'NONE' else 'IAM auth'})",
                              save_as="url", undo=undo("lambda", "delete_function_url_config", {"FunctionName": fn},
                                                       "Delete the function URL")))
        if p["AuthType"] == "NONE":
            for sid, action, extra in ((f"kintsugi-url-{fn}", "lambda:InvokeFunctionUrl", {"FunctionUrlAuthType": "NONE"}),
                                       (f"kintsugi-url-invoke-{fn}", "lambda:InvokeFunction",
                                        {"InvokedViaFunctionUrl": True})):
                steps.append(aws_step("lambda", "add_permission",
                                      {"FunctionName": fn, "StatementId": sid[:100], "Action": action, "Principal": "*",
                                       **extra},
                                      f"Allow anyone to call the function through its URL ({action})",
                                      undo=undo("lambda", "remove_permission", {"FunctionName": fn,
                                                                                "StatementId": sid[:100]},
                                                "Remove the public URL permission")))
            notes.append("PUBLIC: anyone who knows the URL can run the function (and you pay per call). Use IAM auth "
                         "unless it is a public website or webhook.")
    return steps, notes


def _trigger_policies(v: dict) -> list[str]:
    out = []
    if v.get("trigger") == "sqs":
        out.append(POLICY_SQS)
    if v.get("trigger") == "dynamodb":
        out.append(POLICY_DDB)
    if v.get("subnets"):
        out.append(POLICY_VPC)
    if yes(v, "tracing"):
        out.append(POLICY_XRAY)
    return out


def config_params(v: dict) -> dict:
    """Function settings shared by create_function and update_function_configuration."""
    p = {"MemorySize": int(v.get("memory_mb", 128)), "Timeout": int(v.get("timeout_s", 30))}
    if v.get("env_vars"):
        p["Environment"] = {"Variables": kv_pairs(v["env_vars"])}
    if v.get("layers"):
        p["Layers"] = v["layers"]
    if v.get("subnets"):
        p["VpcConfig"] = {"SubnetIds": v["subnets"], "SecurityGroupIds": v.get("security_groups") or []}
    if yes(v, "tracing"):
        p["TracingConfig"] = {"Mode": "Active"}
    if int(v.get("ephemeral_mb", 512) or 512) != 512:
        p["EphemeralStorage"] = {"Size": int(v["ephemeral_mb"])}
    if str(v.get("dlq", "none")).startswith("arn:"):
        p["DeadLetterConfig"] = {"TargetArn": v["dlq"]}
    return p


def _dlq_options(env, inputs):
    return [{"value": "none", "label": "No dead-letter target"}] + \
           [{"value": lookups.queue_arn(env, u), "label": f"SQS {u.rsplit('/', 1)[-1]}"} for u in lookups.sqs_queues(env)] + \
           [{"value": t, "label": f"SNS {t.rsplit(':', 1)[-1]}"} for t in lookups.sns_topics(env)]


def setting_fields(rel=lambda i: True) -> list[FieldSpec]:
    r = both(custom, rel)
    return [
        choice("architecture", "CPU architecture?", opts(("x86_64", "x86_64"), ("arm64", "arm64 (Graviton, ~20% cheaper)")),
               default="x86_64", relevant=r),
        FieldSpec("env_vars", "Environment variables? (optional: KEY=value; OTHER=value, no secrets)", "text",
                  default="", allow_empty=True, validate=_validate_env, relevant=r),
        FieldSpec("layers", "Layers? (optional layer version ARNs)", "text", default="", allow_empty=True,
                  validate=lambda e, i, v: _validate_layers(e, i, v) if str(v).strip() else "", relevant=r),
        FieldSpec("subnets", "Run inside a VPC? (optional: pick private subnets)", "multichoice", default=[],
                  options=_subnet_options, validate=pick_many(_subnet_options, "subnets", 0), relevant=r,
                  allow_empty=True, why="Needed to reach private databases. Internet access then needs a NAT gateway."),
        FieldSpec("security_groups", "Security groups for the function?", "multichoice", must_ask=True,
                  options=_sg_options, validate=pick_many(_sg_options, "security groups", 1),
                  relevant=lambda i: r(i) and bool(i.get("subnets"))),
        yes_no("tracing", "X-Ray tracing?", relevant=r),
        number("ephemeral_mb", "/tmp storage (MB, 512-10240)?", 512, 512, 10240, relevant=r),
        number("reserved", "Reserved concurrency (0 = no limit; caps parallel runs)?", 0, 0, 1000, relevant=r),
        number("log_days", "Keep logs for how many days?", 14, 1, 3653, relevant=r),
        FieldSpec("dlq", "Send failed async events to?", "choice", default="none", options=_dlq_options,
                  validate=pick(_dlq_options, "target"), relevant=r),
        yes_no("alias", "Publish a version and point an alias 'live' at it?", relevant=r),
        number("provisioned", "Provisioned concurrency on the alias (0 = none; billed per hour)?", 0, 0, 100,
               relevant=lambda i: r(i) and yes(i, "alias")),
    ]


def _extra_steps(env, v: dict, fn: str, existing: dict | None) -> list[dict]:
    steps = []
    if int(v.get("reserved", 0) or 0):
        steps.append(aws_step("lambda", "put_function_concurrency",
                              {"FunctionName": fn, "ReservedConcurrentExecutions": int(v["reserved"])},
                              f"Reserve {v['reserved']} concurrent executions",
                              undo=undo("lambda", "delete_function_concurrency", {"FunctionName": fn},
                                        "Remove the concurrency limit")))
    if custom(v):
        group = f"/aws/lambda/{fn}"
        if not existing:
            steps.append(aws_step("logs", "create_log_group", {"logGroupName": group, "tags": tag_dict(fn)},
                                  f"Create log group {group}",
                                  undo=undo("logs", "delete_log_group", {"logGroupName": group}, "Delete the log group")))
        steps.append(aws_step("logs", "put_retention_policy", {"logGroupName": group,
                                                               "retentionInDays": int(v.get("log_days", 14))},
                              f"Keep logs {v.get('log_days', 14)} days"))
    if yes(v, "alias"):
        steps.append(aws_step("lambda", "publish_version", {"FunctionName": fn, "Description": "Published by Kintsugi"},
                              "Publish an immutable version", save_as="ver"))
        steps.append(aws_step("lambda", "create_alias", {"FunctionName": fn, "Name": "live",
                                                         "FunctionVersion": "{{ver.Version}}"},
                              "Point alias 'live' at the new version",
                              undo=undo("lambda", "delete_alias", {"FunctionName": fn, "Name": "live"},
                                        "Delete the alias")))
        if int(v.get("provisioned", 0) or 0):
            steps.append(aws_step("lambda", "put_provisioned_concurrency_config",
                                  {"FunctionName": fn, "Qualifier": "live",
                                   "ProvisionedConcurrentExecutions": int(v["provisioned"])},
                                  f"Keep {v['provisioned']} instances warm (provisioned concurrency)",
                                  undo=undo("lambda", "delete_provisioned_concurrency_config",
                                            {"FunctionName": fn, "Qualifier": "live"},
                                            "Remove provisioned concurrency")))
    return steps


def _notes(v: dict) -> list[str]:
    notes = _lambda_notes({"schedule": "none"})
    if int(v.get("provisioned", 0) or 0):
        notes.append(f"Provisioned concurrency is billed per hour even with no traffic (~${0.0000041667 * 128 / 1024 * 3600 * int(v['provisioned']):.3f}"
                     "/hour per 128 MB instance).")
    if v.get("package") == "image":
        notes.append("Container images are stored in ECR (~$0.10/GB-month).")
    return notes


def _build_lambda(env, v) -> ScriptDraft:
    if v.get("schedule", "none") != "none" and v.get("trigger", "none") == "none":
        v = {**v, "trigger": "schedule", "trigger_schedule": v["schedule"]}
    name = v["name"]
    existing = env.lambda_function(name)
    steps: list[dict] = []
    notes = _notes(v)
    image = v.get("package", "zip") == "image"
    if image:
        _check_tools("docker")
        arch = v.get("architecture", "x86_64")
        img_steps, uri, warns = image_steps(env, name, v["source_folder"],
                                            platform="linux/arm64" if arch == "arm64" else "linux/amd64",
                                            extra_build_args=["--provenance=false"])
        steps += img_steps
        notes += warns + [f"Image: {uri}"]
        code = {"ImageUri": uri}
    else:
        d = workspace.new_task_dir(f"lambda-{name}")
        try:
            scan = workspace.zip_folder(Path(v["source_folder"]), d / "function.zip")
        except WorkspaceError as e:
            raise TemplateError(str(e)) from None
        code = {"ZipFile": f"@file:{d / 'function.zip'}"}
        notes += scan["warnings"] + [f"Code package: {d / 'function.zip'}"]
    if existing:
        fn_arn = existing["FunctionArn"]
        steps.append(aws_step("lambda", "update_function_code", {"FunctionName": name, **code},
                              f"Upload new code to the existing function {name}",
                              wait={"waiter": "function_updated_v2", "params": {"FunctionName": name}}))
        if custom(v):
            cfg = config_params(v)
            old = {k: existing[k] for k in ("MemorySize", "Timeout") if k in existing}
            steps.append(aws_step("lambda", "update_function_configuration", {"FunctionName": name, **cfg},
                                  "Apply the new settings",
                                  wait={"waiter": "function_updated_v2", "params": {"FunctionName": name}},
                                  undo=undo("lambda", "update_function_configuration", {"FunctionName": name, **old},
                                            "Put memory and timeout back") if old else None))
        title = f"Update Lambda {name}"
        notes.append("The function already exists: its code is replaced" + (" and the settings are updated."
                                                                            if custom(v) else "; settings stay the same."))
    else:
        if v.get("role", "new") == "new":
            role = f"{name}-lambda-role"[:64]
            steps += role_steps(role, "lambda.amazonaws.com",
                                [MANAGED_POLICIES["AWSLambdaBasicExecutionRole"]] + _trigger_policies(v))
            role_arn = "{{role.Role.Arn}}"
        else:
            role_arn = v["role"]
        p = {"FunctionName": name, "Role": role_arn, "Code": code, "Description": "Created by Kintsugi",
             "Tags": tag_dict(name), "Architectures": [v.get("architecture", "x86_64")], **config_params(v)}
        if image:
            p["PackageType"] = "Image"
        else:
            p.update({"Runtime": v["runtime"], "Handler": v["handler"]})
        merge_extra(p, v)
        steps.append(aws_step("lambda", "create_function", p,
                              f"Create Lambda function {name} ("
                              + ("container image" if image else f"{v['runtime']}, handler {v['handler']}") + ")",
                              save_as="fn", wait={"waiter": "function_active_v2", "params": {"FunctionName": name}},
                              undo=undo("lambda", "delete_function", {"FunctionName": name},
                                        f"Delete Lambda function {name}")))
        fn_arn = "{{fn.FunctionArn}}"
        title = f"Create Lambda {name}"
    steps += _extra_steps(env, v, name, existing)
    trig, tnotes = trigger_steps(env, v, name, fn_arn)
    steps += trig
    notes += tnotes
    if v.get("trigger", "none") != "none":
        title += f" (trigger: {v['trigger']})"
    return ScriptDraft(title=title, steps=steps, notes=notes)


def _new(e, i) -> bool:
    return not _lambda_exists(e, i)


def _validate_source(env, inputs, v) -> str:
    if inputs.get("package") == "image":
        folder, name = docker_context(v)
        return str(folder / name) if name.lower() != "dockerfile" else str(folder)
    return _folder(env, inputs, v)


LAMBDA = Template(
    name="lambda_function",
    description="Create or update a Lambda function from a local folder (zip) or a Dockerfile (image), with a "
                "trigger (schedule, S3, SQS, DynamoDB stream, SNS, HTTP API, function URL) and every setting",
    fields=[
        FieldSpec("name", "What is the function name?", "text", default="kintsugi-function",
                  validate=_name_validator(r"[A-Za-z0-9_-]{1,64}", "letters, numbers, - and _ (max 64)")),
        choice("package", "Code folder or container image?", PACKAGES, default="zip"),
        FieldSpec("source_folder", "Which local folder has the function code (or the Dockerfile)?", "folder",
                  must_ask=True, validate=_validate_source,
                  why="The folder is zipped (secret files like .env and keys are skipped)."),
        FieldSpec("runtime", "Which runtime?", "choice",
                  default=lambda e, i: _guess_runtime(_src(i)) if _src(i) else "python3.12",
                  options=lambda e, i: [{"value": r, "label": r} for r in RUNTIMES],
                  validate=lambda e, i, v: _choice([{"value": r, "label": r} for r in RUNTIMES], v, "runtime"),
                  relevant_env=lambda e, i: _new(e, i) and i.get("package", "zip") == "zip"),
        FieldSpec("handler", "Which handler (file.function)?", "text",
                  default=lambda e, i: _guess_handler(_src(i), i.get("runtime", "python3.12")) if _src(i) else None,
                  validate=_validate_handler, relevant_env=lambda e, i: _new(e, i) and i.get("package", "zip") == "zip",
                  why="Python: lambda_function.lambda_handler means def lambda_handler in lambda_function.py"),
        FieldSpec("role", "Which IAM role should the function run as?", "choice", default="new",
                  options=_role_options("lambda.amazonaws.com", "basic logging permissions"),
                  validate=_validate_role("lambda.amazonaws.com", "basic logging permissions"),
                  relevant_env=lambda e, i: _new(e, i),
                  why="A new role gets CloudWatch Logs access plus what the trigger needs (SQS, DynamoDB, VPC)."),
        FieldSpec("memory_mb", "Memory (MB)?", "number", default=128,
                  validate=lambda e, i, v: _int(v, 128, 10240, "memory"),
                  relevant_env=lambda e, i: _new(e, i) or custom(i)),
        FieldSpec("timeout_s", "Timeout (seconds)?", "number", default=30,
                  validate=lambda e, i, v: _int(v, 1, 900, "timeout"),
                  relevant_env=lambda e, i: _new(e, i) or custom(i)),
        FieldSpec("trigger", "What should run the function?", "choice", default="none", options=static(TRIGGERS),
                  validate=pick(static(TRIGGERS), "trigger")),
        FieldSpec("schedule", "Run it on a schedule? (none, 'daily 10:00', 'hourly', cron(...) in UTC, or rate(...))",
                  "text", default="none", optional=True, validate=_validate_schedule,
                  relevant=lambda i: i.get("trigger", "none") == "none"),
        *trigger_fields(),
        settings_field(),
        *setting_fields(),
        extra_params_field(lambda i: ("lambda", "create_function"),
                           {"FunctionName", "Role", "Code", "Runtime", "Handler", "PackageType", "Tags"}),
    ],
    title=lambda i: f"Lambda function '{i.get('name', 'kintsugi-function')}'",
    build=_build_lambda, notes=_notes,
)


MANAGE_ACTIONS = opts(("configure", "Change settings (memory, timeout, env vars, layers, VPC ...)"),
                      ("trigger", "Add a trigger"), ("release", "Publish a version and move an alias (traffic shifting)"),
                      ("concurrency", "Reserved / provisioned concurrency"), ("delete", "Delete the function"))


def _fn_config(env, inputs) -> dict:
    return env.lambda_function(inputs.get("function", "")) or {}


def _alias_options(env, inputs):
    def load():
        try:
            got = env.conn.client("lambda", "read", env.region).list_aliases(FunctionName=inputs["function"])
            return got.get("Aliases", [])
        except Exception:
            return []
    aliases = env._memo(("aliases", inputs.get("function")), load) if inputs.get("function") else []
    return [{"value": "live", "label": "live (create it if missing)"}] + [
        {"value": a["Name"], "label": f"{a['Name']} -> version {a['FunctionVersion']}"} for a in aliases
        if a["Name"] != "live"]


def _current_alias(env, inputs) -> dict | None:
    def load():
        try:
            return env.conn.client("lambda", "read", env.region).get_alias(FunctionName=inputs["function"],
                                                                          Name=inputs.get("alias_name", "live"))
        except Exception:
            return None
    return env._memo(("alias", inputs.get("function"), inputs.get("alias_name", "live")), load)


def _build_manage(env, v) -> ScriptDraft:
    fn, a = v["function"], v["action"]
    cur = _fn_config(env, v)
    steps: list[dict] = []
    notes: list[str] = []
    if a == "configure":
        cfg = config_params({**v, "settings": "custom"})
        old = {"MemorySize": cur.get("MemorySize", 128), "Timeout": cur.get("Timeout", 3),
               "Environment": {"Variables": (cur.get("Environment") or {}).get("Variables", {})}}
        steps.append(aws_step("lambda", "update_function_configuration", {"FunctionName": fn, **cfg},
                              f"Update settings of {fn}: memory {cfg['MemorySize']} MB, timeout {cfg['Timeout']} s",
                              wait={"waiter": "function_updated_v2", "params": {"FunctionName": fn}},
                              undo=undo("lambda", "update_function_configuration", {"FunctionName": fn, **old},
                                        "Restore memory, timeout and environment variables")))
        if cfg.get("VpcConfig") and v.get("subnets"):
            notes.append(f"The function's role needs {POLICY_VPC.rsplit('/', 1)[-1]} to run in a VPC.")
        title = f"Configure Lambda {fn}"
    elif a == "trigger":
        trig, notes = trigger_steps(env, v, fn, cur.get("FunctionArn", fn))
        steps += trig
        if v.get("trigger") in ("sqs", "dynamodb"):
            notes.append(f"Attach {(POLICY_SQS if v['trigger'] == 'sqs' else POLICY_DDB).rsplit('/', 1)[-1]} to the "
                         "function's role if it is missing (iam_role or aws_write).")
        title = f"Trigger {v.get('trigger')} for {fn}"
    elif a == "release":
        alias = v.get("alias_name", "live")
        existing = _current_alias(env, v)
        steps.append(aws_step("lambda", "publish_version", {"FunctionName": fn, "Description": "Published by Kintsugi"},
                              "Publish the current code and settings as a new version", save_as="ver"))
        weight = int(v.get("shift_percent", 100) or 100)
        if existing:
            p = {"FunctionName": fn, "Name": alias}
            if weight >= 100:
                p["FunctionVersion"] = "{{ver.Version}}"
                p["RoutingConfig"] = {"AdditionalVersionWeights": {}}
                desc = f"Move alias {alias} fully to the new version"
            else:
                p["FunctionVersion"] = existing["FunctionVersion"]
                p["RoutingConfig"] = {"AdditionalVersionWeights": {"{{ver.Version}}": weight / 100}}
                desc = f"Send {weight}% of alias {alias} traffic to the new version (canary)"
            steps.append(aws_step("lambda", "update_alias", p, desc,
                                  undo=undo("lambda", "update_alias",
                                            {"FunctionName": fn, "Name": alias,
                                             "FunctionVersion": existing["FunctionVersion"],
                                             "RoutingConfig": {"AdditionalVersionWeights": {}}},
                                            f"Point {alias} back at version {existing['FunctionVersion']}")))
            if weight < 100:
                notes.append("When the new version looks good, run this again with 100% to finish the release.")
        else:
            steps.append(aws_step("lambda", "create_alias", {"FunctionName": fn, "Name": alias,
                                                             "FunctionVersion": "{{ver.Version}}"},
                                  f"Create alias {alias} on the new version",
                                  undo=undo("lambda", "delete_alias", {"FunctionName": fn, "Name": alias},
                                            "Delete the alias")))
        title = f"Release a new version of {fn}"
    elif a == "concurrency":
        if int(v.get("reserved", 0) or 0):
            steps.append(aws_step("lambda", "put_function_concurrency",
                                  {"FunctionName": fn, "ReservedConcurrentExecutions": int(v["reserved"])},
                                  f"Reserve {v['reserved']} concurrent executions",
                                  undo=undo("lambda", "delete_function_concurrency", {"FunctionName": fn},
                                            "Remove the concurrency limit")))
        else:
            steps.append(aws_step("lambda", "delete_function_concurrency", {"FunctionName": fn},
                                  "Remove the reserved concurrency limit"))
        if int(v.get("provisioned", 0) or 0):
            steps.append(aws_step("lambda", "put_provisioned_concurrency_config",
                                  {"FunctionName": fn, "Qualifier": v.get("alias_name", "live"),
                                   "ProvisionedConcurrentExecutions": int(v["provisioned"])},
                                  f"Keep {v['provisioned']} instances warm on alias {v.get('alias_name', 'live')}",
                                  undo=undo("lambda", "delete_provisioned_concurrency_config",
                                            {"FunctionName": fn, "Qualifier": v.get("alias_name", "live")},
                                            "Remove provisioned concurrency")))
            notes.append("Provisioned concurrency is billed per hour even without traffic.")
        title = f"Concurrency of {fn}"
    else:
        steps.append(aws_step("lambda", "delete_function", {"FunctionName": fn}, f"Delete Lambda function {fn}"))
        notes.append("Triggers that point at it (rules, queues, buckets), its role and its log group are not deleted.")
        title = f"Delete Lambda {fn}"
    return ScriptDraft(title=title, steps=steps, notes=notes or ["Lambda changes are free; you pay per invocation."])


LAMBDA_MANAGE = Template(
    name="lambda_manage",
    description="Existing Lambda function: settings, add a trigger (schedule/S3/SQS/DynamoDB/SNS/API/URL), publish a "
                "version + alias with canary traffic shifting, concurrency, delete",
    fields=[
        FieldSpec("function", "Which function?", "choice", must_ask=True, options=_fn_options,
                  validate=pick(_fn_options, "function"), empty_hint="No Lambda functions in this region."),
        choice("action", "What do you want to do?", MANAGE_ACTIONS, default="configure", must_ask=True),
        FieldSpec("memory_mb", "Memory (MB)?", "number", default=lambda e, i: _fn_config(e, i).get("MemorySize", 128),
                  validate=lambda e, i, v: _int(v, 128, 10240, "memory"), relevant=action_is("configure")),
        FieldSpec("timeout_s", "Timeout (seconds)?", "number", default=lambda e, i: _fn_config(e, i).get("Timeout", 3),
                  validate=lambda e, i, v: _int(v, 1, 900, "timeout"), relevant=action_is("configure")),
        FieldSpec("env_vars", "Environment variables (replaces the current ones; KEY=value; ...)", "text",
                  default=lambda e, i: "; ".join(f"{k}={val}" for k, val in ((_fn_config(e, i).get("Environment") or {})
                                                                             .get("Variables", {})).items()),
                  allow_empty=True, validate=_validate_env, relevant=action_is("configure")),
        FieldSpec("layers", "Layers? (layer version ARNs; empty = none)", "text",
                  default=lambda e, i: ", ".join(x["Arn"] for x in _fn_config(e, i).get("Layers", [])), allow_empty=True,
                  validate=lambda e, i, v: _validate_layers(e, i, v) if str(v).strip() else "",
                  relevant=action_is("configure")),
        yes_no("tracing", "X-Ray tracing?", default=lambda e, i: "yes" if (_fn_config(e, i).get("TracingConfig") or {})
               .get("Mode") == "Active" else "no", relevant=action_is("configure")),
        number("ephemeral_mb", "/tmp storage (MB)?", lambda e, i: (_fn_config(e, i).get("EphemeralStorage") or {})
               .get("Size", 512), 512, 10240, relevant=action_is("configure")),
        FieldSpec("trigger", "Which trigger?", "choice", must_ask=True, default="schedule",
                  options=static([o for o in TRIGGERS if o["value"] != "none"]),
                  validate=pick(static([o for o in TRIGGERS if o["value"] != "none"]), "trigger"),
                  relevant=action_is("trigger")),
        *trigger_fields(action_is("trigger")),
        FieldSpec("alias_name", "Which alias?", "choice", default="live", options=_alias_options,
                  validate=lambda e, i, v: str(v).strip() if re.fullmatch(r"[A-Za-z][\w-]{0,127}", str(v).strip())
                  else _choice([], v, "alias"), allow_custom=True, relevant=action_is("release", "concurrency")),
        number("shift_percent", "Send what % of traffic to the new version? (100 = all at once)", 100, 1, 100,
               relevant=action_is("release")),
        number("reserved", "Reserved concurrency (0 = remove the limit)?", 0, 0, 1000, relevant=action_is("concurrency")),
        number("provisioned", "Provisioned concurrency on the alias (0 = none)?", 0, 0, 100,
               relevant=action_is("concurrency")),
    ],
    title=lambda i: f"Lambda '{i.get('function', '')}' ({i.get('action', 'configure')})",
    build=_build_manage, notes=lambda i: [],
)


RECIPES = [LAMBDA, LAMBDA_MANAGE]
templates.TEMPLATES.update({t.name: t for t in RECIPES})
