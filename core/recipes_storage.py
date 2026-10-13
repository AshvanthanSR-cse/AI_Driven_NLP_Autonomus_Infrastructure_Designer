"""Storage and delivery recipes: S3 buckets with every feature, bulk S3 object actions (storage classes,
Glacier restore, copy/move/delete), S3 Glacier vaults, and CloudFront distributions.

s3_bucket       create or configure: versioning, encryption (SSE-S3 / SSE-KMS + bucket key), Block Public Access,
                object lock, lifecycle rules (Standard-IA, Intelligent-Tiering, Glacier Instant / Flexible
                Retrieval, Deep Archive, expiration, old versions, incomplete uploads), Intelligent-Tiering archive
                tiers, CORS, event notifications (Lambda / SQS / SNS), access logging, replication, transfer
                acceleration, requester pays, inventory. Existing configurations are merged, never silently lost.
s3_objects      run-time bulk actions under a prefix (core/aws_steps.py): change storage class, restore from
                Glacier (Expedited / Standard / Bulk), copy, move, delete.
glacier_vault   the original S3 Glacier vault API: vaults, archive upload, inventory / retrieval jobs,
                notifications, deletes.
cloudfront_distribution  S3 (private, Origin Access Control), S3 website, load balancer or any HTTP origin;
                HTTPS, cache policies, price class, custom domains (ACM in us-east-1), WAF, geo restriction, SPA
                error pages; cache invalidation; disable + delete.
"""
import json
import re
import shutil
from pathlib import Path

from core import lookups, templates, workspace
from core.local_steps import ARCHIVE_CLASSES, STORAGE_CLASSES, check_prefix
from core.recipe_kit import action_is, both, choice, custom, ids, number, opts, pick, settings_field, static, yes, yes_no
from core.recipes import (_bucket_region, _stamp, _validate_new_bucket, aws_step, check, role_steps, tag_dict, tag_list,
                          undo, website_url)
from core.scripts import ScriptDraft
from core.templates import FieldSpec, Template, TemplateError, _choice, _int

S3_PRICES = {"STANDARD": 0.023, "STANDARD_IA": 0.0125, "ONEZONE_IA": 0.01, "INTELLIGENT_TIERING": 0.023,
             "GLACIER_IR": 0.004, "GLACIER": 0.0036, "DEEP_ARCHIVE": 0.00099}
CLASS_LABELS = {"STANDARD": "Standard (frequent access)", "STANDARD_IA": "Standard-IA (infrequent, min 30 days)",
                "ONEZONE_IA": "One Zone-IA (infrequent, one zone)",
                "INTELLIGENT_TIERING": "Intelligent-Tiering (AWS moves objects automatically)",
                "GLACIER_IR": "Glacier Instant Retrieval (archive, millisecond access, min 90 days)",
                "GLACIER": "Glacier Flexible Retrieval (archive, minutes-hours to restore, min 90 days)",
                "DEEP_ARCHIVE": "Glacier Deep Archive (cheapest, 12-48 h to restore, min 180 days)"}
CLASS_OPTIONS = [{"value": c, "label": f"{CLASS_LABELS[c]} ~${S3_PRICES[c]}/GB-month"} for c in STORAGE_CLASSES]
TRANSITIONS = [("it_days", "INTELLIGENT_TIERING"), ("ia_days", "STANDARD_IA"), ("glacier_ir_days", "GLACIER_IR"),
               ("glacier_days", "GLACIER"), ("deep_archive_days", "DEEP_ARCHIVE")]


def _bucket_options(env, inputs):
    return [{"value": b, "label": b} for b in lookups.buckets(env)]


def _validate_bucket(env, inputs, v) -> str:
    v = str(v).strip().removeprefix("s3://").strip("/")
    return _choice(_bucket_options(env, inputs), v, "bucket")


def _bucket(v: dict) -> str:
    return v.get("name") if v.get("action", "create") == "create" else v.get("bucket")


def _read(env, bucket: str, op: str, **kw):
    """A read of the bucket's current configuration; None when it is not set."""
    from botocore.exceptions import ClientError
    try:
        region = _bucket_region(env, bucket)
        return getattr(env.conn.client("s3", "read", region), op)(Bucket=bucket, **kw)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code.startswith("NoSuch") or code in ("ServerSideEncryptionConfigurationNotFoundError",
                                                 "ReplicationConfigurationNotFoundError",
                                                 "NoSuchLifecycleConfiguration", "NoSuchCORSConfiguration",
                                                 "NoSuchBucketPolicy", "ObjectLockConfigurationNotFoundError"):
            return None
        raise


def lifecycle_rule(v: dict, rule_id: str) -> dict | None:
    """One lifecycle rule from the day fields; None if nothing is set."""
    trans = [{"Days": int(v[k]), "StorageClass": cls} for k, cls in TRANSITIONS if int(v.get(k, 0) or 0)]
    rule = {"ID": rule_id, "Status": "Enabled", "Filter": {"Prefix": v.get("lifecycle_prefix", "") or ""}}
    if trans:
        rule["Transitions"] = trans
    if int(v.get("expire_days", 0) or 0):
        rule["Expiration"] = {"Days": int(v["expire_days"])}
    if int(v.get("old_versions_days", 0) or 0):
        rule["NoncurrentVersionExpiration"] = {"NoncurrentDays": int(v["old_versions_days"])}
    if int(v.get("old_versions_glacier_days", 0) or 0):
        rule["NoncurrentVersionTransitions"] = [{"NoncurrentDays": int(v["old_versions_glacier_days"]),
                                                 "StorageClass": "GLACIER"}]
    if int(v.get("abort_uploads_days", 0) or 0):
        rule["AbortIncompleteMultipartUpload"] = {"DaysAfterInitiation": int(v["abort_uploads_days"])}
    return rule if len(rule) > 3 else None


def check_lifecycle(v: dict) -> None:
    """S3's own rules, checked before saving: increasing days, IA after >= 30 days, 30 days in IA before
    the next transition, expiration after the last transition."""
    days = [(k, cls, int(v.get(k, 0) or 0)) for k, cls in TRANSITIONS if int(v.get(k, 0) or 0)]
    prev = 0
    prev_cls = "STANDARD"
    for k, cls, d in days:
        if d <= prev:
            raise ValueError(f"{CLASS_LABELS[cls].split(' (')[0]} after {d} days must come later than the previous "
                             f"step ({prev} days)")
        if cls == "STANDARD_IA" and d < 30:
            raise ValueError("objects can move to Standard-IA only after at least 30 days")
        if prev_cls == "STANDARD_IA" and d - prev < 30:
            raise ValueError("objects must stay 30 days in Standard-IA before the next transition")
        prev, prev_cls = d, cls
    exp = int(v.get("expire_days", 0) or 0)
    if exp and exp <= prev:
        raise ValueError(f"expiration ({exp} days) must be after the last transition ({prev} days)")


def _validate_days(key: str):
    def check_(env, inputs, v):
        n = _int(v, 0, 36500, key.replace("_", " "))
        check_lifecycle({**inputs, key: n})
        return n
    return check_


def _notif_targets(env, inputs):
    kind = inputs.get("notify", "none")
    if kind == "lambda":
        return [{"value": f["arn"], "label": f["name"]} for f in lookups.lambda_functions(env)]
    if kind == "sqs":
        return [{"value": u, "label": u.rsplit("/", 1)[-1]} for u in lookups.sqs_queues(env)]
    if kind == "sns":
        return [{"value": t, "label": t.rsplit(":", 1)[-1]} for t in lookups.sns_topics(env)]
    return []


def _merged_policy(old: str | None, statement: dict) -> str:
    doc = json.loads(old) if old else {"Version": "2012-10-17", "Statement": []}
    doc["Statement"] = [s for s in doc.get("Statement", []) if s.get("Sid") != statement["Sid"]] + [statement]
    return json.dumps(doc)


def _notification_steps(env, v: dict, bucket: str, region: str) -> list[dict]:
    kind = v.get("notify", "none")
    if kind == "none":
        return []
    target = v["notify_target"]
    events = {"created": ["s3:ObjectCreated:*"], "removed": ["s3:ObjectRemoved:*"],
              "both": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"],
              "restored": ["s3:ObjectRestore:Completed"]}[v.get("notify_events", "created")]
    flt = [{"Name": "prefix", "Value": v["notify_prefix"]}] if v.get("notify_prefix") else []
    flt += [{"Name": "suffix", "Value": v["notify_suffix"]}] if v.get("notify_suffix") else []
    acct = env.account_id()
    steps = []
    cfg_id = f"kintsugi-{_stamp()}"
    entry = {"Id": cfg_id, "Events": events}
    if flt:
        entry["Filter"] = {"Key": {"FilterRules": flt}}
    if kind == "lambda":
        entry["LambdaFunctionArn"] = target
        sid = f"kintsugi-s3-{bucket}"[:100]
        steps.append(aws_step("lambda", "add_permission",
                              {"FunctionName": target, "StatementId": sid, "Action": "lambda:InvokeFunction",
                               "Principal": "s3.amazonaws.com", "SourceArn": f"arn:aws:s3:::{bucket}",
                               "SourceAccount": acct},
                              f"Allow S3 bucket {bucket} to invoke the function",
                              undo=undo("lambda", "remove_permission", {"FunctionName": target, "StatementId": sid},
                                        "Remove the S3 invoke permission")))
        key = "LambdaFunctionConfigurations"
    elif kind == "sqs":
        arn = lookups.queue_arn(env, target)
        entry["QueueArn"] = arn
        old = env.conn.client("sqs", "read", env.region).get_queue_attributes(
            QueueUrl=target, AttributeNames=["Policy"]).get("Attributes", {}).get("Policy")
        stmt = {"Sid": f"KintsugiS3{re.sub(r'[^A-Za-z0-9]', '', bucket)[:40]}", "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": arn,
                "Condition": {"ArnLike": {"aws:SourceArn": f"arn:aws:s3:::{bucket}"},
                              "StringEquals": {"aws:SourceAccount": acct}}}
        steps.append(aws_step("sqs", "set_queue_attributes",
                              {"QueueUrl": target, "Attributes": {"Policy": _merged_policy(old, stmt)}},
                              "Let this bucket (only) send messages to the queue (existing policy kept)",
                              undo=undo("sqs", "set_queue_attributes",
                                        {"QueueUrl": target, "Attributes": {"Policy": old or ""}},
                                        "Restore the previous queue policy")))
        key = "QueueConfigurations"
    else:
        entry["TopicArn"] = target
        old = env.conn.client("sns", "read", env.region).get_topic_attributes(TopicArn=target).get(
            "Attributes", {}).get("Policy")
        stmt = {"Sid": f"KintsugiS3{re.sub(r'[^A-Za-z0-9]', '', bucket)[:40]}", "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"}, "Action": "SNS:Publish", "Resource": target,
                "Condition": {"ArnLike": {"aws:SourceArn": f"arn:aws:s3:::{bucket}"},
                              "StringEquals": {"aws:SourceAccount": acct}}}
        steps.append(aws_step("sns", "set_topic_attributes",
                              {"TopicArn": target, "AttributeName": "Policy", "AttributeValue": _merged_policy(old, stmt)},
                              "Let this bucket (only) publish to the topic (existing policy kept)",
                              undo=undo("sns", "set_topic_attributes",
                                        {"TopicArn": target, "AttributeName": "Policy", "AttributeValue": old},
                                        "Restore the previous topic policy") if old else None))
        key = "TopicConfigurations"
    current = {} if v.get("action", "create") == "create" else (
        _read(env, bucket, "get_bucket_notification_configuration") or {})
    current.pop("ResponseMetadata", None)
    new = {k: (list(val) if isinstance(val, list) else val) for k, val in current.items()}
    new.setdefault(key, []).append(entry)
    steps.append(aws_step("s3", "put_bucket_notification_configuration",
                          {"Bucket": bucket, "NotificationConfiguration": new},
                          f"Send {', '.join(events)} events{' for ' + v['notify_prefix'] if v.get('notify_prefix') else ''} "
                          f"to the {kind.upper()} target (other notifications kept)", region=region,
                          undo=undo("s3", "put_bucket_notification_configuration",
                                    {"Bucket": bucket, "NotificationConfiguration": current},
                                    "Restore the previous event notifications")))
    return steps


def _replication_steps(env, v: dict, bucket: str, region: str) -> list[dict]:
    dest = v["replicate_to"]
    role = f"kintsugi-s3-repl-{bucket}"[:64]
    steps = role_steps(role, "s3.amazonaws.com", [], key="replrole", pause=1)
    doc = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetReplicationConfiguration", "s3:ListBucket"],
         "Resource": f"arn:aws:s3:::{bucket}"},
        {"Effect": "Allow", "Action": ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl",
                                       "s3:GetObjectVersionTagging"], "Resource": f"arn:aws:s3:::{bucket}/*"},
        {"Effect": "Allow", "Action": ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"],
         "Resource": f"arn:aws:s3:::{dest}/*"}]}
    steps.append(aws_step("iam", "put_role_policy", {"RoleName": role, "PolicyName": "replicate",
                                                     "PolicyDocument": json.dumps(doc)},
                          f"Allow replication from {bucket} to {dest} only",
                          undo=undo("iam", "delete_role_policy", {"RoleName": role, "PolicyName": "replicate"},
                                    "Remove the replication policy"), pause_after=15))
    rule = {"ID": f"kintsugi-to-{dest}"[:255], "Priority": 1, "Status": "Enabled", "Filter": {"Prefix": ""},
            "DeleteMarkerReplication": {"Status": "Enabled" if yes(v, "replicate_deletes") else "Disabled"},
            "Destination": {"Bucket": f"arn:aws:s3:::{dest}", "StorageClass": v.get("replica_class", "STANDARD")}}
    steps.append(aws_step("s3", "put_bucket_replication",
                          {"Bucket": bucket, "ReplicationConfiguration": {"Role": "{{replrole.Role.Arn}}",
                                                                          "Rules": [rule]}},
                          f"Replicate new objects to {dest} ({v.get('replica_class', 'STANDARD')})", region=region,
                          undo=undo("s3", "delete_bucket_replication", {"Bucket": bucket}, "Stop replication")))
    return steps


def _validate_dest_bucket(env, inputs, v) -> str:
    b = _validate_bucket(env, inputs, v)
    if b == _bucket(inputs):
        raise ValueError("pick a different bucket than the source")
    st = _read(env, b, "get_bucket_versioning") or {}
    if st.get("Status") != "Enabled":
        raise ValueError(f"versioning must be ON in {b} before it can receive replicas (turn it on with "
                         "s3_bucket configure)")
    return b


def _validate_origins(env, inputs, v) -> str:
    out = []
    for o in ids(v):
        if o != "*" and not re.fullmatch(r"https?://[\w.-]+(:\d+)?", o):
            raise ValueError(f"'{o}' must look like https://example.com (or *)")
        out.append(o)
    return ",".join(out)


def _s3_notes(v: dict) -> list[str]:
    notes = ["COST: S3 Standard ~$0.023/GB-month; Standard-IA ~$0.0125; Glacier Instant Retrieval ~$0.004; Glacier "
             "Flexible Retrieval ~$0.0036; Deep Archive ~$0.00099 (us-east-1, verify). Archive classes charge per "
             "restore and have minimum storage days (90 / 180); transitions cost ~$0.05 per 1,000 objects."]
    if yes(v, "versioning") or v.get("object_lock", "none") != "none":
        notes.append("Versioning keeps every old version (each one is billed); add an 'old versions' expiration rule.")
    if v.get("object_lock", "none") == "compliance":
        notes.append("COMPLIANCE object lock: locked versions cannot be deleted by anyone, including the root user, "
                     "until the retention ends; this bucket cannot be torn down before then.")
    if v.get("encryption") == "kms":
        notes.append("SSE-KMS adds KMS request charges (the bucket key reduces them ~99%).")
    if yes(v, "acceleration"):
        notes.append("Transfer acceleration adds ~$0.04/GB on accelerated transfers.")
    if v.get("logging_bucket"):
        notes.append("The log bucket must allow the S3 logging service (logging.s3.amazonaws.com) to write; S3 "
                     "shows an error on the first delivery if it does not.")
    return notes


def _build_s3_bucket(env, v) -> ScriptDraft:
    creating = v.get("action", "create") == "create"
    bucket = _bucket(v)
    region = env.region_name if creating else _bucket_region(env, bucket)
    steps: list[dict] = []
    if creating:
        p = {"Bucket": bucket, "ObjectOwnership": "BucketOwnerEnforced"}
        if region != "us-east-1":
            p["CreateBucketConfiguration"] = {"LocationConstraint": region}
        if v.get("object_lock", "none") != "none":
            p["ObjectLockEnabledForBucket"] = True
        steps.append(aws_step("s3", "create_bucket", p, f"Create private bucket {bucket} in {region}", region=region,
                              undo=undo("s3", "delete_bucket", {"Bucket": bucket}, f"Delete bucket {bucket}")))
        steps.append(aws_step("s3", "put_bucket_tagging", {"Bucket": bucket, "Tagging": {"TagSet": tag_list(bucket)}},
                              "Tag the bucket (CreatedBy=kintsugi)", region=region,
                              undo={"kind": "s3_empty", "bucket": bucket, "region": region,
                                    "description": f"Empty {bucket} (every object version) so it can be deleted"}))
        steps.append(aws_step("s3", "put_public_access_block",
                              {"Bucket": bucket, "PublicAccessBlockConfiguration": {
                                  "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True,
                                  "RestrictPublicBuckets": True}},
                              "Block all public access (for a public website use s3_static_website)", region=region))
    if v.get("encryption", "sse_s3") == "kms" or creating:
        rule = {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms" if v.get("encryption") == "kms"
                                                       else "AES256"}}
        if v.get("encryption") == "kms":
            if v.get("kms_key"):
                rule["ApplyServerSideEncryptionByDefault"]["KMSMasterKeyID"] = v["kms_key"]
            rule["BucketKeyEnabled"] = True
        steps.append(aws_step("s3", "put_bucket_encryption",
                              {"Bucket": bucket, "ServerSideEncryptionConfiguration": {"Rules": [rule]}},
                              f"Default encryption: {'SSE-KMS with bucket key' if v.get('encryption') == 'kms' else 'SSE-S3 (AES-256)'}",
                              region=region))
    need_versions = yes(v, "versioning") or v.get("object_lock", "none") != "none" or bool(v.get("replicate_to"))
    if need_versions:
        status = "Enabled"
        prev = None if creating else (_read(env, bucket, "get_bucket_versioning") or {}).get("Status")
        steps.append(aws_step("s3", "put_bucket_versioning",
                              {"Bucket": bucket, "VersioningConfiguration": {"Status": status}},
                              f"Versioning: {status.lower()}", region=region,
                              undo=undo("s3", "put_bucket_versioning",
                                        {"Bucket": bucket, "VersioningConfiguration": {"Status": "Suspended"}},
                                        "Suspend versioning again") if not creating and prev != "Enabled"
                              and status == "Enabled" else None))
    if v.get("object_lock", "none") != "none":
        steps.append(aws_step("s3", "put_object_lock_configuration",
                              {"Bucket": bucket, "ObjectLockConfiguration": {
                                  "ObjectLockEnabled": "Enabled",
                                  "Rule": {"DefaultRetention": {"Mode": v["object_lock"].upper(),
                                                                "Days": int(v.get("lock_days", 30))}}}},
                              f"Object lock: {v['object_lock'].upper()} for {v.get('lock_days', 30)} days by default",
                              region=region))
    rule = lifecycle_rule(v, f"kintsugi-{_stamp()}")
    if rule:
        old = None if creating else _read(env, bucket, "get_bucket_lifecycle_configuration")
        rules = [r for r in (old or {}).get("Rules", [])] + [rule]
        desc = ", ".join([f"{cls.replace('_', ' ').title()} after {v[k]}d" for k, cls in TRANSITIONS
                          if int(v.get(k, 0) or 0)]
                         + ([f"expire after {v['expire_days']}d"] if int(v.get("expire_days", 0) or 0) else [])
                         + ([f"old versions after {v['old_versions_days']}d"] if int(v.get("old_versions_days", 0) or 0)
                            else []))
        steps.append(aws_step("s3", "put_bucket_lifecycle_configuration",
                              {"Bucket": bucket, "LifecycleConfiguration": {"Rules": rules}},
                              f"Lifecycle{' for ' + v['lifecycle_prefix'] if v.get('lifecycle_prefix') else ''}: "
                              f"{desc or 'abort incomplete uploads'}" + (" (existing rules kept)" if old else ""),
                              region=region,
                              undo=None if creating else (
                                  undo("s3", "put_bucket_lifecycle_configuration",
                                       {"Bucket": bucket, "LifecycleConfiguration": {"Rules": old["Rules"]}},
                                       "Restore the previous lifecycle rules") if old else
                                  undo("s3", "delete_bucket_lifecycle", {"Bucket": bucket}, "Remove the lifecycle rules"))))
    if int(v.get("it_archive_days", 0) or 0) or int(v.get("it_deep_days", 0) or 0):
        tiers = []
        if int(v.get("it_archive_days", 0) or 0):
            tiers.append({"Days": int(v["it_archive_days"]), "AccessTier": "ARCHIVE_ACCESS"})
        if int(v.get("it_deep_days", 0) or 0):
            tiers.append({"Days": int(v["it_deep_days"]), "AccessTier": "DEEP_ARCHIVE_ACCESS"})
        steps.append(aws_step("s3", "put_bucket_intelligent_tiering_configuration",
                              {"Bucket": bucket, "Id": "kintsugi-archive",
                               "IntelligentTieringConfiguration": {"Id": "kintsugi-archive", "Status": "Enabled",
                                                                   "Tierings": tiers}},
                              "Intelligent-Tiering archive tiers: " + ", ".join(f"{t['AccessTier']} after {t['Days']}d"
                                                                                for t in tiers), region=region,
                              undo=None if creating else undo("s3", "delete_bucket_intelligent_tiering_configuration",
                                                              {"Bucket": bucket, "Id": "kintsugi-archive"},
                                                              "Remove the archive tiers")))
    if v.get("cors_origins"):
        methods = ["GET", "HEAD"] if v.get("cors_methods", "read") == "read" else ["GET", "HEAD", "PUT", "POST", "DELETE"]
        steps.append(aws_step("s3", "put_bucket_cors",
                              {"Bucket": bucket, "CORSConfiguration": {"CORSRules": [{
                                  "AllowedOrigins": v["cors_origins"].split(","), "AllowedMethods": methods,
                                  "AllowedHeaders": ["*"], "MaxAgeSeconds": 3000}]}},
                              f"CORS: {', '.join(methods)} from {v['cors_origins']}", region=region,
                              undo=None if creating else undo("s3", "delete_bucket_cors", {"Bucket": bucket},
                                                              "Remove the CORS rules")))
    steps += _notification_steps(env, v, bucket, region)
    if v.get("logging_bucket"):
        steps.append(aws_step("s3", "put_bucket_logging",
                              {"Bucket": bucket, "BucketLoggingStatus": {"LoggingEnabled": {
                                  "TargetBucket": v["logging_bucket"], "TargetPrefix": f"s3-logs/{bucket}/"}}},
                              f"Access logs to s3://{v['logging_bucket']}/s3-logs/{bucket}/", region=region,
                              undo=None if creating else undo("s3", "put_bucket_logging",
                                                              {"Bucket": bucket, "BucketLoggingStatus": {}},
                                                              "Turn access logging off")))
    if v.get("replicate_to"):
        steps += _replication_steps(env, v, bucket, region)
    if yes(v, "acceleration"):
        steps.append(aws_step("s3", "put_bucket_accelerate_configuration",
                              {"Bucket": bucket, "AccelerateConfiguration": {"Status": "Enabled"}},
                              "Transfer acceleration on", region=region,
                              undo=None if creating else undo("s3", "put_bucket_accelerate_configuration",
                                                              {"Bucket": bucket, "AccelerateConfiguration": {
                                                                  "Status": "Suspended"}}, "Transfer acceleration off")))
    if yes(v, "requester_pays"):
        steps.append(aws_step("s3", "put_bucket_request_payment",
                              {"Bucket": bucket, "RequestPaymentConfiguration": {"Payer": "Requester"}},
                              "Requester pays for downloads", region=region,
                              undo=undo("s3", "put_bucket_request_payment",
                                        {"Bucket": bucket, "RequestPaymentConfiguration": {"Payer": "BucketOwner"}},
                                        "Bucket owner pays again")))
    if v.get("inventory_bucket"):
        steps.append(aws_step("s3", "put_bucket_inventory_configuration",
                              {"Bucket": bucket, "Id": "kintsugi-inventory", "InventoryConfiguration": {
                                  "Id": "kintsugi-inventory", "IsEnabled": True, "IncludedObjectVersions": "Current",
                                  "Schedule": {"Frequency": "Daily"},
                                  "OptionalFields": ["Size", "LastModifiedDate", "StorageClass", "EncryptionStatus"],
                                  "Destination": {"S3BucketDestination": {
                                      "Bucket": f"arn:aws:s3:::{v['inventory_bucket']}", "Format": "CSV",
                                      "Prefix": f"inventory/{bucket}"}}}},
                              f"Daily inventory CSV to {v['inventory_bucket']}", region=region,
                              undo=None if creating else undo("s3", "delete_bucket_inventory_configuration",
                                                              {"Bucket": bucket, "Id": "kintsugi-inventory"},
                                                              "Remove the inventory")))
    if not steps:
        raise TemplateError("Nothing to change: pick at least one setting (versioning, lifecycle, encryption ...)")
    return ScriptDraft(title=("Create S3 bucket " if creating else "Configure S3 bucket ") + bucket, steps=steps,
                       notes=_s3_notes(v), region=region)


def _lc(i) -> bool:
    return i.get("lifecycle", "no") == "yes"


S3_BUCKET = Template(
    name="s3_bucket",
    description="S3 bucket create/configure: versioning, encryption, object lock, lifecycle to Standard-IA / "
                "Intelligent-Tiering / Glacier IR / Glacier / Deep Archive + expiration, CORS, events (Lambda/SQS/SNS), "
                "logging, replication, acceleration, requester pays, inventory",
    fields=[
        choice("action", "Create a new bucket or change an existing one?",
               opts(("create", "Create a new bucket"), ("configure", "Configure an existing bucket")), default="create"),
        FieldSpec("name", "Bucket name (globally unique)?", "text", must_ask=True,
                  default=lambda e, i: f"kintsugi-{e.account_id()}-{_stamp()[:8]}", validate=_validate_new_bucket,
                  relevant=action_is("create")),
        FieldSpec("bucket", "Which bucket?", "choice", must_ask=True, options=_bucket_options, validate=_validate_bucket,
                  relevant=action_is("configure"), empty_hint="You have no S3 buckets."),
        yes_no("versioning", "Versioning (keep old versions, protects against deletes)?",
               default=lambda e, i: "yes" if i.get("action", "create") == "create" else "no"),
        choice("encryption", "Default encryption?", opts(("sse_s3", "SSE-S3 (AES-256, free)"),
                                                         ("kms", "SSE-KMS (your KMS key, audit trail)")),
               default="sse_s3"),
        FieldSpec("kms_key", "KMS key ARN or alias? (empty = aws/s3)", "text", default="", allow_empty=True,
                  relevant=lambda i: i.get("encryption") == "kms"),
        yes_no("lifecycle", "Add lifecycle rules (move old objects to cheaper classes / Glacier, or delete them)?",
               default="no"),
        FieldSpec("lifecycle_prefix", "Only for objects under which prefix? (empty = whole bucket)", "text",
                  default="", allow_empty=True, relevant=_lc),
        FieldSpec("it_days", "Move to Intelligent-Tiering after how many days? (0 = no)", "number", default=0,
                  validate=_validate_days("it_days"), relevant=_lc),
        FieldSpec("ia_days", "Move to Standard-IA after how many days? (0 = no, min 30)", "number", default=0,
                  validate=_validate_days("ia_days"), relevant=_lc),
        FieldSpec("glacier_ir_days", "Move to Glacier Instant Retrieval after how many days? (0 = no)", "number",
                  default=0, validate=_validate_days("glacier_ir_days"), relevant=_lc),
        FieldSpec("glacier_days", "Move to Glacier Flexible Retrieval after how many days? (0 = no)", "number",
                  default=90, validate=_validate_days("glacier_days"), relevant=_lc),
        FieldSpec("deep_archive_days", "Move to Glacier Deep Archive after how many days? (0 = no)", "number",
                  default=0, validate=_validate_days("deep_archive_days"), relevant=_lc),
        FieldSpec("expire_days", "Delete objects after how many days? (0 = never)", "number", default=0,
                  validate=_validate_days("expire_days"), relevant=_lc),
        number("old_versions_glacier_days", "Move OLD versions to Glacier after how many days? (0 = no)", 0, 0, 36500,
               relevant=lambda i: _lc(i) and yes(i, "versioning")),
        number("old_versions_days", "Delete OLD versions after how many days? (0 = never)", 30, 0, 36500,
               relevant=lambda i: _lc(i) and yes(i, "versioning")),
        number("abort_uploads_days", "Clean up unfinished multipart uploads after how many days? (0 = no)", 7, 0, 3650,
               relevant=_lc),
        choice("notify", "Send an event when objects change?",
               opts(("none", "No"), ("lambda", "To a Lambda function"), ("sqs", "To an SQS queue"),
                    ("sns", "To an SNS topic")), default="none"),
        FieldSpec("notify_target", "Which one?", "choice", must_ask=True, options=_notif_targets,
                  validate=pick(_notif_targets, "target"), relevant=lambda i: i.get("notify", "none") != "none",
                  empty_hint="None found in this region; create it first."),
        choice("notify_events", "Which events?", opts(("created", "Object created"), ("removed", "Object deleted"),
                                                      ("both", "Created and deleted"),
                                                      ("restored", "Restore from Glacier completed")),
               default="created", relevant=lambda i: i.get("notify", "none") != "none"),
        FieldSpec("notify_prefix", "Only keys starting with? (optional, e.g. uploads/)", "text", default="",
                  allow_empty=True, relevant=lambda i: i.get("notify", "none") != "none"),
        FieldSpec("notify_suffix", "Only keys ending with? (optional, e.g. .jpg)", "text", default="", allow_empty=True,
                  relevant=lambda i: i.get("notify", "none") != "none"),
        settings_field(),
        choice("object_lock", "Object lock (WORM: versions cannot be deleted for a time)?",
               opts(("none", "No"), ("governance", "Governance (admins with a special permission can override)"),
                    ("compliance", "Compliance (nobody can delete until it expires)")),
               default="none", relevant=lambda i: custom(i) and i.get("action", "create") == "create"),
        number("lock_days", "Default retention (days)?", 30, 1, 36500,
               relevant=lambda i: i.get("object_lock", "none") != "none"),
        number("it_archive_days", "Intelligent-Tiering: Archive Access tier after how many days? (0 = no, min 90)",
               0, 0, 730, relevant=custom),
        number("it_deep_days", "Intelligent-Tiering: Deep Archive Access tier after how many days? (0 = no, min 180)",
               0, 0, 730, relevant=custom),
        FieldSpec("cors_origins", "CORS: which websites may call the bucket from a browser? (optional)", "text",
                  default="", allow_empty=True, validate=_validate_origins, relevant=custom),
        choice("cors_methods", "CORS methods?", opts(("read", "Read (GET, HEAD)"), ("write", "Read and upload")),
               default="read", relevant=lambda i: custom(i) and bool(i.get("cors_origins"))),
        FieldSpec("logging_bucket", "Write access logs to which bucket? (optional)", "choice", default="none",
                  options=lambda e, i: [{"value": "none", "label": "No access logs"}] + _bucket_options(e, i),
                  validate=lambda e, i, v: "" if str(v) in ("none", "") else _validate_bucket(e, i, v), relevant=custom,
                  allow_empty=True),
        FieldSpec("replicate_to", "Replicate to which bucket? (optional; it needs versioning on)", "choice",
                  default="none",
                  options=lambda e, i: [{"value": "none", "label": "No replication"}] + _bucket_options(e, i),
                  validate=lambda e, i, v: "" if str(v) in ("none", "") else _validate_dest_bucket(e, i, v),
                  relevant=custom, allow_empty=True),
        choice("replica_class", "Storage class for the replicas?", CLASS_OPTIONS, default="STANDARD",
               relevant=lambda i: custom(i) and bool(i.get("replicate_to"))),
        yes_no("replicate_deletes", "Replicate delete markers too?",
               relevant=lambda i: custom(i) and bool(i.get("replicate_to"))),
        yes_no("acceleration", "Transfer acceleration (faster long-distance uploads, paid)?", relevant=custom),
        yes_no("requester_pays", "Requester pays (downloaders pay the transfer)?", relevant=custom),
        FieldSpec("inventory_bucket", "Daily inventory report to which bucket? (optional)", "choice", default="none",
                  options=lambda e, i: [{"value": "none", "label": "No inventory"}] + _bucket_options(e, i),
                  validate=lambda e, i, v: "" if str(v) in ("none", "") else _validate_bucket(e, i, v), relevant=custom,
                  allow_empty=True),
    ],
    title=lambda i: f"S3 bucket '{_bucket(i) or 'new'}'",
    build=_build_s3_bucket, notes=_s3_notes,
)


OBJECT_ACTIONS = opts(("storage_class", "Change storage class (e.g. move to Glacier / Deep Archive)"),
                      ("restore", "Restore archived objects from Glacier (temporary copy)"),
                      ("copy", "Copy to another bucket / prefix"), ("move", "Move to another bucket / prefix"),
                      ("delete", "Delete objects"))


def _object_summary(env, bucket: str, prefix: str) -> dict:
    def load():
        s3 = env.conn.client("s3", "read", _bucket_region(env, bucket))
        count = size = 0
        classes: dict[str, int] = {}
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix,
                                                                  PaginationConfig={"MaxItems": 20000}):
            for o in page.get("Contents", []):
                count += 1
                size += o.get("Size", 0)
                classes[o.get("StorageClass", "STANDARD")] = classes.get(o.get("StorageClass", "STANDARD"), 0) + 1
        return {"count": count, "size": size, "classes": classes}
    return env._memo(("objsum", bucket, prefix), load)


def _validate_obj_prefix(env, inputs, v) -> str:
    from core.local_steps import StepError
    try:
        p = check_prefix(str(v or ""))
    except StepError as e:
        raise ValueError(str(e)) from None
    if inputs.get("bucket") and _object_summary(env, inputs["bucket"], p)["count"] == 0:
        raise ValueError(f"no objects under '{p or '/'}' in {inputs['bucket']}")
    return p


def _objects_notes(v: dict) -> list[str]:
    a = v.get("action", "storage_class")
    if a == "restore":
        return ["Restore makes a temporary copy readable; the archived object stays in Glacier. Price per GB: "
                "Expedited ~$0.03, Standard ~$0.01, Bulk ~$0.0025 (Deep Archive: Standard ~$0.02, no Expedited).",
                "Restores finish later: Expedited 1-5 min, Standard 3-5 h (Deep Archive 12 h), Bulk 5-12 h (48 h)."]
    if a == "storage_class":
        return ["Moving to an archive class bills a minimum storage time (Glacier 90 days, Deep Archive 180 days) and "
                "a per-request transition fee; objects already in Glacier must be restored before changing class."]
    if a in ("delete", "move"):
        return ["Deleting is permanent unless versioning is on (then a delete marker is added)."]
    return ["Copies are encrypted with SSE-S3 and keep their metadata."]


def _build_s3_objects(env, v) -> ScriptDraft:
    bucket, prefix, a = v["bucket"], v.get("prefix", ""), v["action"]
    region = _bucket_region(env, bucket)
    summary = _object_summary(env, bucket, prefix)
    step = {"kind": "s3_objects", "bucket": bucket, "prefix": prefix, "action": a, "region": region,
            "timeout": 3600}
    if a in ("storage_class", "copy", "move"):
        step["storage_class"] = v.get("storage_class", "STANDARD")
    if a == "restore":
        step["days"], step["tier"] = int(v.get("days", 7)), v.get("tier", "Standard")
    if a in ("copy", "move"):
        step["dest_bucket"], step["dest_prefix"] = v["dest_bucket"], v.get("dest_prefix", "")
    verb = dict((o["value"], o["label"]) for o in OBJECT_ACTIONS)[a]
    step["description"] = f"{verb}: s3://{bucket}/{prefix} ({summary['count']} object(s))"
    classes = ", ".join(f"{k}: {n}" for k, n in sorted(summary["classes"].items()))
    notes = _objects_notes(v) + [f"Found {summary['count']} object(s), {summary['size'] / 1048576:.1f} MB ({classes})."]
    if a == "restore" and not any(c in ARCHIVE_CLASSES or c == "INTELLIGENT_TIERING" for c in summary["classes"]):
        raise TemplateError("None of these objects is in an archive class; there is nothing to restore")
    return ScriptDraft(title=f"S3 objects: {a.replace('_', ' ')} s3://{bucket}/{prefix}", steps=[step], notes=notes,
                       region=region)


S3_OBJECTS = Template(
    name="s3_objects",
    description="Bulk S3 object actions under a prefix: change storage class (Glacier, Deep Archive ...), restore "
                "from Glacier, copy, move, delete",
    fields=[
        FieldSpec("bucket", "Which bucket?", "choice", must_ask=True, options=_bucket_options, validate=_validate_bucket,
                  empty_hint="You have no S3 buckets."),
        choice("action", "What should happen to the objects?", OBJECT_ACTIONS, default="storage_class", must_ask=True),
        FieldSpec("prefix", "Which objects? (prefix like photos/2024/; empty = the whole bucket)", "text", default="",
                  allow_empty=True, validate=_validate_obj_prefix, must_ask=True),
        choice("storage_class", "Target storage class?", CLASS_OPTIONS, default="GLACIER",
               relevant=action_is("storage_class", "copy", "move")),
        choice("tier", "Restore speed?", opts(("Standard", "Standard (3-5 hours; Deep Archive 12 h)"),
                                             ("Bulk", "Bulk (cheapest, 5-12 hours; Deep Archive 48 h)"),
                                             ("Expedited", "Expedited (1-5 minutes, Flexible Retrieval only)")),
               default="Standard", relevant=action_is("restore")),
        number("days", "Keep the restored copy for how many days?", 7, 1, 365, relevant=action_is("restore")),
        FieldSpec("dest_bucket", "Destination bucket?", "choice", must_ask=True, options=_bucket_options,
                  validate=_validate_bucket, relevant=action_is("copy", "move")),
        FieldSpec("dest_prefix", "Destination prefix? (optional)", "text", default="", allow_empty=True,
                  relevant=action_is("copy", "move")),
    ],
    title=lambda i: f"S3 objects in '{i.get('bucket', '')}'",
    build=_build_s3_objects, notes=_objects_notes,
)


VAULT_ACTIONS = opts(("create", "Create a vault"), ("upload", "Upload a file as an archive"),
                     ("inventory", "Request the vault inventory (list of archives; ready in ~4 hours)"),
                     ("retrieve", "Request an archive download (retrieval job)"),
                     ("notifications", "Send job-completed notifications to an SNS topic"),
                     ("delete_archive", "Delete an archive"), ("delete_vault", "Delete an empty vault"))


def _vault_options(env, inputs):
    return [{"value": x["name"], "label": f"{x['name']} · {x['archives']} archive(s) · {x['size'] / 1048576:.1f} MB"}
            for x in lookups.glacier_vaults(env)]


def _validate_vault_name(env, inputs, v) -> str:
    v = str(v).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", v):
        raise ValueError("letters, numbers, _ . - (max 255)")
    if v in {x["name"] for x in lookups.glacier_vaults(env)}:
        raise ValueError("a vault with this name already exists")
    return v


def _validate_archive_file(env, inputs, v) -> str:
    from core.scripts import MAX_FILE_BYTES
    p = Path(str(v).strip().strip('"'))
    if not p.is_file():
        raise ValueError(f"file not found: {p}")
    if workspace._excluded_file(p.name):
        raise ValueError(f"{p.name} looks like a secret file; it is never uploaded")
    if p.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"{p.name} is over {MAX_FILE_BYTES // 1048576} MB; use S3 with the GLACIER / DEEP_ARCHIVE "
                         "storage class (s3_upload) for big files")
    return str(p)


def _validate_archive_id(env, inputs, v) -> str:
    v = str(v).strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{100,200}", v):
        raise ValueError("an archive ID (about 138 characters, from the upload result or the inventory)")
    return v


def _build_vault(env, v) -> ScriptDraft:
    a = v.get("action", "create")
    note = ["COST: Glacier vault storage ~$0.0036/GB-month (90-day minimum); retrievals cost per GB. For new data "
            "AWS recommends S3 with the Glacier storage classes (s3_upload / s3_bucket lifecycle)."]
    if a == "create":
        name = v["vault_name"]
        steps = [aws_step("glacier", "create_vault", {"accountId": "-", "vaultName": name},
                          f"Create Glacier vault {name}",
                          undo=undo("glacier", "delete_vault", {"accountId": "-", "vaultName": name},
                                    f"Delete vault {name} (only works when empty)")),
                 aws_step("glacier", "add_tags_to_vault", {"accountId": "-", "vaultName": name, "Tags": tag_dict(name)},
                          "Tag the vault")]
        if v.get("topic", "none") != "none":
            steps.append(aws_step("glacier", "set_vault_notifications",
                                  {"accountId": "-", "vaultName": name, "vaultNotificationConfig": {
                                      "SNSTopic": v["topic"], "Events": ["ArchiveRetrievalCompleted",
                                                                         "InventoryRetrievalCompleted"]}},
                                  "Notify the SNS topic when jobs finish"))
        return ScriptDraft(title=f"Glacier vault {name}", steps=steps, notes=note)
    vault = v["vault"]
    if a == "upload":
        d = workspace.new_task_dir(f"glacier-{vault}")
        src = Path(v["file"])
        copy = d / src.name
        shutil.copy2(src, copy)
        steps = [aws_step("glacier", "upload_archive",
                          {"accountId": "-", "vaultName": vault, "archiveDescription": src.name[:1000],
                           "body": f"@file:{copy}"},
                          f"Upload {src.name} ({src.stat().st_size / 1048576:.1f} MB) as an archive", save_as="arch",
                          undo=undo("glacier", "delete_archive", {"accountId": "-", "vaultName": vault,
                                                                  "archiveId": "{{arch.archiveId}}"},
                                    "Delete the uploaded archive"))]
        return ScriptDraft(title=f"Upload {src.name} to Glacier vault {vault}", steps=steps,
                           notes=note + ["Keep the archive ID from the run log: Glacier has no file names, you need the "
                                         "ID to download or delete it later."])
    if a in ("inventory", "retrieve"):
        params = {"Type": "inventory-retrieval", "Format": "JSON"} if a == "inventory" else \
            {"Type": "archive-retrieval", "ArchiveId": v["archive_id"], "Tier": v.get("tier", "Standard")}
        if v.get("topic", "none") != "none":
            params["SNSTopic"] = v["topic"]
        steps = [aws_step("glacier", "initiate_job", {"accountId": "-", "vaultName": vault, "jobParameters": params},
                          f"Start a {'n inventory' if a == 'inventory' else 'n archive retrieval'} job".replace("a n", "an"),
                          save_as="job")]
        return ScriptDraft(title=f"Glacier {a} job for {vault}", steps=steps,
                           notes=note + ["The job ID is in the run log. When it completes (hours), download the output "
                                         "with: aws glacier get-job-output --account-id - --vault-name "
                                         f"{vault} --job-id <id> output.json"])
    if a == "notifications":
        steps = [aws_step("glacier", "set_vault_notifications",
                          {"accountId": "-", "vaultName": vault, "vaultNotificationConfig": {
                              "SNSTopic": v["topic"], "Events": ["ArchiveRetrievalCompleted", "InventoryRetrievalCompleted"]}},
                          "Notify the SNS topic when jobs finish",
                          undo=undo("glacier", "delete_vault_notifications", {"accountId": "-", "vaultName": vault},
                                    "Remove the notifications"))]
        return ScriptDraft(title=f"Notifications for vault {vault}", steps=steps, notes=note)
    if a == "delete_archive":
        steps = [aws_step("glacier", "delete_archive", {"accountId": "-", "vaultName": vault,
                                                        "archiveId": v["archive_id"]}, "Delete the archive")]
        return ScriptDraft(title=f"Delete an archive from {vault}", steps=steps,
                           notes=["Archives deleted before 90 days are billed for the remaining days."])
    steps = [aws_step("glacier", "delete_vault", {"accountId": "-", "vaultName": vault}, f"Delete vault {vault}")]
    return ScriptDraft(title=f"Delete Glacier vault {vault}", steps=steps,
                       notes=["A vault can only be deleted when it has no archives AND no writes since the last "
                              "inventory (Glacier updates the inventory about once a day)."])


def _topic_options(env, inputs):
    return [{"value": "none", "label": "No notifications"}] + [{"value": t, "label": t.rsplit(":", 1)[-1]}
                                                               for t in lookups.sns_topics(env)]


GLACIER = Template(
    name="glacier_vault",
    description="S3 Glacier vaults (original API): create, upload a file as an archive, inventory and retrieval "
                "jobs, notifications, delete archive / vault",
    fields=[
        choice("action", "What do you want to do in Glacier?", VAULT_ACTIONS, default="create", must_ask=True),
        FieldSpec("vault_name", "Vault name?", "text", default="kintsugi-vault", validate=_validate_vault_name,
                  relevant=action_is("create")),
        FieldSpec("vault", "Which vault?", "choice", must_ask=True, options=_vault_options,
                  validate=pick(_vault_options, "vault"), relevant=lambda i: i.get("action", "create") != "create",
                  empty_hint="You have no Glacier vaults in this region."),
        FieldSpec("file", "Which file?", "file", must_ask=True, validate=_validate_archive_file,
                  relevant=action_is("upload")),
        FieldSpec("archive_id", "Archive ID?", "text", must_ask=True, validate=_validate_archive_id,
                  relevant=action_is("retrieve", "delete_archive")),
        choice("tier", "Retrieval speed?", opts(("Standard", "Standard (3-5 hours)"), ("Bulk", "Bulk (5-12 hours, cheapest)"),
                                               ("Expedited", "Expedited (1-5 minutes, most expensive)")),
               default="Standard", relevant=action_is("retrieve")),
        FieldSpec("topic", "SNS topic for notifications?", "choice", default="none", options=_topic_options,
                  validate=pick(_topic_options, "topic"),
                  relevant=lambda i: i.get("action", "create") in ("create", "inventory", "retrieve", "notifications")),
    ],
    title=lambda i: f"Glacier ({i.get('action', 'create')})",
    build=_build_vault, notes=lambda i: ["COST: Glacier vault storage ~$0.0036/GB-month."],
)


CACHE_POLICIES = {"optimized": "658327ea-f89d-4fab-a63d-7e88639e58f6", "disabled": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"}
ALL_VIEWER_EXCEPT_HOST = "b689b0a8-53d0-40ab-baf2-68738e2966ac"
ORIGINS = opts(("s3", "Private S3 bucket (Origin Access Control; bucket stays private)"),
               ("s3_website", "S3 static website endpoint (public bucket website)"),
               ("alb", "Load balancer"), ("custom", "Any website / API by domain name"))
CF_ACTIONS = opts(("create", "Create a distribution"), ("invalidate", "Clear cached files (invalidation)"),
                  ("delete", "Disable and delete a distribution"))


def _cf_options(env, inputs):
    return [{"value": d["id"], "label": f"{d['id']} · {d['domain']} · {', '.join(d['aliases']) or d['comment'][:40]}"}
            for d in lookups.distributions(env)]


def _lb_options(env, inputs):
    return [{"value": lb["dns"], "label": f"{lb['name']} · {lb['dns']}"} for lb in lookups.load_balancers(env)
            if lb["scheme"] == "internet-facing"]


def _cert_options_global(env, inputs):
    return [{"value": c["arn"], "label": c["domain"]} for c in lookups.certificates(env, "us-east-1")]


def _validate_aliases(env, inputs, v) -> str:
    out = []
    for a in ids(v):
        if not re.fullmatch(r"(\*\.)?([a-z0-9-]+\.)+[a-z]{2,}", a.lower()):
            raise ValueError(f"'{a}' is not a domain name")
        out.append(a.lower())
    return ",".join(out)


def _validate_domain(env, inputs, v) -> str:
    v = str(v).strip().lower().removeprefix("https://").removeprefix("http://").strip("/")
    if not re.fullmatch(r"([a-z0-9-]+\.)+[a-z]{2,}", v):
        raise ValueError("a domain name like api.example.com (no path)")
    return v


def _validate_paths(env, inputs, v) -> list[str]:
    out = [p if p.startswith("/") else "/" + p for p in ids(v)]
    if not out:
        raise ValueError("give at least one path, e.g. /* or /index.html")
    return out


def _validate_countries(env, inputs, v) -> str:
    codes = [c.upper() for c in ids(v)]
    if not codes or any(not re.fullmatch(r"[A-Z]{2}", c) for c in codes):
        raise ValueError("two-letter country codes like IN, US, DE")
    return ",".join(codes)


def _waf_options(env, inputs):
    try:
        acls = env.conn.client("wafv2", "read", "us-east-1").list_web_acls(Scope="CLOUDFRONT").get("WebACLs", [])
    except Exception:
        acls = []
    return [{"value": "none", "label": "No WAF"}] + [{"value": a["ARN"], "label": a["Name"]} for a in acls]


def _cf_notes(v: dict) -> list[str]:
    if v.get("action", "create") == "invalidate":
        return ["COST: the first 1,000 invalidation paths each month are free; '/*' counts as one path."]
    if v.get("action") == "delete":
        return ["Disabling takes 5-15 minutes to reach every edge location before the distribution can be deleted."]
    return ["COST: CloudFront free tier: 1 TB data out and 10 million requests per month; then ~$0.085/GB (varies "
            "by region and price class). Approximate prices; verify current pricing.",
            "A new distribution takes 5-15 minutes to deploy worldwide.",
            "Custom domains need a DNS CNAME (or Route 53 alias) pointing to the distribution's domain name."]


def _build_cf(env, v) -> ScriptDraft:
    a = v.get("action", "create")
    if a == "invalidate":
        ref = f"kintsugi-{_stamp()}"
        steps = [aws_step("cloudfront", "create_invalidation",
                          {"DistributionId": v["distribution"], "InvalidationBatch": {
                              "Paths": {"Quantity": len(v["paths"]), "Items": v["paths"]}, "CallerReference": ref}},
                          f"Clear cached {', '.join(v['paths'])} (waits until done)", save_as="inv",
                          wait={"waiter": "invalidation_completed",
                                "params": {"DistributionId": v["distribution"], "Id": "{{inv.Invalidation.Id}}"},
                                "delay": 20, "max_attempts": 60})]
        return ScriptDraft(title=f"Invalidate {v['distribution']}", steps=steps, notes=_cf_notes(v))
    if a == "delete":
        steps = [{"kind": "cf_delete", "distribution_id": v["distribution"], "timeout": 2400,
                  "description": f"Disable, wait until deployed, then delete {v['distribution']}"}]
        return ScriptDraft(title=f"Delete CloudFront distribution {v['distribution']}", steps=steps, notes=_cf_notes(v))
    origin = v["origin_type"]
    steps: list[dict] = []
    oid = "origin-1"
    bucket = v.get("bucket")
    if origin == "s3":
        region = _bucket_region(env, bucket)
        steps.append(aws_step("cloudfront", "create_origin_access_control",
                              {"OriginAccessControlConfig": {
                                  "Name": f"kintsugi-{bucket}"[:64], "Description": f"Kintsugi OAC for {bucket}",
                                  "SigningProtocol": "sigv4", "SigningBehavior": "always",
                                  "OriginAccessControlOriginType": "s3"}},
                              f"Create Origin Access Control so only CloudFront can read {bucket}", save_as="oac",
                              undo=undo("cloudfront", "delete_origin_access_control",
                                        {"Id": "{{oac.OriginAccessControl.Id}}", "IfMatch": "{{oac.ETag}}"},
                                        "Delete the Origin Access Control")))
        o = {"Id": oid, "DomainName": f"{bucket}.s3.{region}.amazonaws.com",
             "S3OriginConfig": {"OriginAccessIdentity": ""}, "OriginAccessControlId": "{{oac.OriginAccessControl.Id}}"}
    else:
        domain = {"s3_website": lambda: website_url(bucket, _bucket_region(env, bucket)).removeprefix("http://"),
                  "alb": lambda: v["load_balancer"], "custom": lambda: v["origin_domain"]}[origin]()
        proto = "http-only" if origin == "s3_website" else v.get("origin_protocol", "http-only" if origin == "alb"
                                                                  else "https-only")
        o = {"Id": oid, "DomainName": domain,
             "CustomOriginConfig": {"HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": proto,
                                    "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                                    "OriginReadTimeout": 30, "OriginKeepaliveTimeout": 5}}
    dynamic = origin in ("alb", "custom")
    cache = v.get("cache", "disabled" if dynamic else "optimized")
    methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"] if v.get("methods", "all" if dynamic
                                                                                    else "read") == "all" \
        else ["GET", "HEAD"]
    behavior = {"TargetOriginId": oid, "ViewerProtocolPolicy": v.get("viewer_protocol", "redirect-to-https"),
                "CachePolicyId": CACHE_POLICIES[cache], "Compress": True,
                "AllowedMethods": {"Quantity": len(methods), "Items": methods,
                                   "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}}}
    if dynamic and cache == "disabled":
        behavior["OriginRequestPolicyId"] = ALL_VIEWER_EXCEPT_HOST
    aliases = [x for x in str(v.get("aliases", "")).split(",") if x]
    cfg = {"CallerReference": f"kintsugi-{_stamp()}", "Comment": f"Kintsugi {v.get('name', 'distribution')}"[:128],
           "Enabled": True, "Origins": {"Quantity": 1, "Items": [o]}, "DefaultCacheBehavior": behavior,
           "PriceClass": v.get("price_class", "PriceClass_200"), "HttpVersion": "http2and3", "IsIPV6Enabled": True,
           "Aliases": {"Quantity": len(aliases), "Items": aliases}}
    if origin in ("s3", "s3_website") and v.get("root_object", "index.html"):
        cfg["DefaultRootObject"] = v.get("root_object", "index.html")
    if aliases:
        cfg["ViewerCertificate"] = {"ACMCertificateArn": v["certificate"], "SSLSupportMethod": "sni-only",
                                    "MinimumProtocolVersion": "TLSv1.2_2021"}
    else:
        cfg["ViewerCertificate"] = {"CloudFrontDefaultCertificate": True}
    if v.get("geo", "none") != "none":
        codes = v["countries"].split(",")
        cfg["Restrictions"] = {"GeoRestriction": {"RestrictionType": v["geo"], "Quantity": len(codes), "Items": codes}}
    if v.get("waf", "none") != "none":
        cfg["WebACLId"] = v["waf"]
    if yes(v, "spa"):
        cfg["CustomErrorResponses"] = {"Quantity": 2, "Items": [
            {"ErrorCode": c, "ResponsePagePath": "/" + v.get("root_object", "index.html"), "ResponseCode": "200",
             "ErrorCachingMinTTL": 10} for c in (403, 404)]}
    did = "{{cf.Distribution.Id}}"
    steps.append(aws_step("cloudfront", "create_distribution_with_tags",
                          {"DistributionConfigWithTags": {"DistributionConfig": cfg,
                                                          "Tags": {"Items": tag_list(v.get("name", "kintsugi-cdn"))}}},
                          f"Create CloudFront distribution for {o['DomainName']} (waits until deployed, 5-15 min)",
                          save_as="cf", wait={"waiter": "distribution_deployed", "params": {"Id": did}, "delay": 30,
                                              "max_attempts": 60},
                          undo={"kind": "cf_delete", "distribution_id": did, "timeout": 2400,
                                "description": "Disable and delete the distribution (waits ~15 min)"}))
    if origin == "s3":
        old = (_read(env, bucket, "get_bucket_policy") or {}).get("Policy")
        stmt = {"Sid": "KintsugiCloudFrontRead", "Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"},
                "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"StringEquals": {"AWS:SourceArn": "{{cf.Distribution.ARN}}"}}}
        steps.append(aws_step("s3", "put_bucket_policy", {"Bucket": bucket, "Policy": _merged_policy(old, stmt)},
                              f"Let ONLY this distribution read {bucket} (bucket stays private; existing policy kept)",
                              region=_bucket_region(env, bucket),
                              undo=undo("s3", "put_bucket_policy", {"Bucket": bucket, "Policy": old},
                                        "Restore the previous bucket policy") if old else
                              undo("s3", "delete_bucket_policy", {"Bucket": bucket}, "Remove the bucket policy")))
    steps.append(check("http", {"url": "https://{{cf.Distribution.DomainName}}/" +
                                       ("" if dynamic else v.get("root_object", "index.html"))},
                       "Check the site answers through CloudFront", timeout=900))
    return ScriptDraft(title=f"CloudFront for {o['DomainName']}", steps=steps,
                       notes=_cf_notes(v) + (["URL after the run: https://<distribution domain in the run log>"]))


def _creating_cf(i) -> bool:
    return i.get("action", "create") == "create"


CLOUDFRONT = Template(
    name="cloudfront_distribution",
    description="CloudFront: distribution for a private S3 bucket (OAC), S3 website, load balancer or any domain; "
                "HTTPS, caching, price class, custom domains, WAF, geo blocking, SPA routing; invalidation; delete",
    fields=[
        choice("action", "What do you want to do in CloudFront?", CF_ACTIONS, default="create"),
        FieldSpec("distribution", "Which distribution?", "choice", must_ask=True, options=_cf_options,
                  validate=pick(_cf_options, "distribution"), relevant=action_is("invalidate", "delete"),
                  empty_hint="No CloudFront distributions in this account."),
        FieldSpec("paths", "Which paths? (/* = everything, or /index.html, /css/*)", "text", default="/*",
                  validate=_validate_paths, relevant=action_is("invalidate")),
        FieldSpec("name", "Name (tag)?", "text", default="kintsugi-cdn", relevant=_creating_cf),
        FieldSpec("origin_type", "What should CloudFront serve?", "choice", must_ask=True, default="s3",
                  options=static(ORIGINS), validate=pick(static(ORIGINS), "origin"), relevant=_creating_cf),
        FieldSpec("bucket", "Which bucket?", "choice", must_ask=True, options=_bucket_options, validate=_validate_bucket,
                  relevant=lambda i: _creating_cf(i) and i.get("origin_type", "s3") in ("s3", "s3_website"),
                  empty_hint="You have no S3 buckets."),
        FieldSpec("load_balancer", "Which load balancer?", "choice", must_ask=True, options=_lb_options,
                  validate=pick(_lb_options, "load balancer"),
                  relevant=lambda i: _creating_cf(i) and i.get("origin_type") == "alb",
                  empty_hint="No internet-facing load balancers; create one first (load_balancer)."),
        FieldSpec("origin_domain", "Origin domain name?", "text", must_ask=True, validate=_validate_domain,
                  relevant=lambda i: _creating_cf(i) and i.get("origin_type") == "custom"),
        choice("origin_protocol", "How should CloudFront talk to the origin?",
               opts(("http-only", "HTTP only"), ("https-only", "HTTPS only"), ("match-viewer", "Same as the viewer")),
               default=lambda e, i: "http-only" if i.get("origin_type") == "alb" else "https-only",
               relevant=lambda i: _creating_cf(i) and i.get("origin_type") in ("alb", "custom")),
        FieldSpec("root_object", "Default page?", "text", default="index.html",
                  relevant=lambda i: _creating_cf(i) and i.get("origin_type", "s3") in ("s3", "s3_website")),
        choice("viewer_protocol", "Viewer HTTPS?", opts(("redirect-to-https", "Redirect HTTP to HTTPS (recommended)"),
                                                       ("https-only", "HTTPS only"), ("allow-all", "HTTP and HTTPS")),
               default="redirect-to-https", relevant=_creating_cf),
        choice("cache", "Caching?", opts(("optimized", "Cache (static files; recommended for S3)"),
                                        ("disabled", "No caching (dynamic apps / APIs)")),
               default=lambda e, i: "disabled" if i.get("origin_type") in ("alb", "custom") else "optimized",
               relevant=_creating_cf),
        choice("price_class", "Which edge locations?",
               opts(("PriceClass_100", "North America + Europe (cheapest)"),
                    ("PriceClass_200", "+ Asia incl. India, Middle East, Africa"), ("PriceClass_All", "All locations")),
               default="PriceClass_200", relevant=_creating_cf),
        yes_no("spa", "Single-page app (send 403/404 to index.html)?", relevant=lambda i: _creating_cf(i)
               and i.get("origin_type", "s3") in ("s3", "s3_website")),
        settings_field(),
        choice("methods", "Allowed methods?", opts(("read", "GET, HEAD"), ("all", "All (forms, APIs)")),
               default=lambda e, i: "all" if i.get("origin_type") in ("alb", "custom") else "read",
               relevant=both(_creating_cf, custom)),
        FieldSpec("aliases", "Custom domains? (optional: www.example.com, example.com)", "text", default="",
                  allow_empty=True, validate=_validate_aliases, relevant=both(_creating_cf, custom)),
        FieldSpec("certificate", "ACM certificate in us-east-1 for those domains?", "choice", must_ask=True,
                  options=_cert_options_global, validate=pick(_cert_options_global, "certificate"),
                  default=lambda e, i: next((o["value"] for o in _cert_options_global(e, i)), None),
                  relevant=lambda i: _creating_cf(i) and bool(i.get("aliases")),
                  empty_hint="CloudFront needs an ISSUED certificate in us-east-1 for custom domains; request one in "
                             "ACM (N. Virginia) first."),
        FieldSpec("waf", "Protect with a WAF web ACL?", "choice", default="none", options=_waf_options,
                  validate=pick(_waf_options, "web ACL"), relevant=both(_creating_cf, custom)),
        choice("geo", "Geographic restriction?", opts(("none", "None"), ("whitelist", "Only allow some countries"),
                                                      ("blacklist", "Block some countries")),
               default="none", relevant=both(_creating_cf, custom)),
        FieldSpec("countries", "Which countries? (IN, US, DE ...)", "text", must_ask=True, validate=_validate_countries,
                  relevant=lambda i: _creating_cf(i) and i.get("geo", "none") != "none"),
    ],
    title=lambda i: f"CloudFront ({i.get('action', 'create')})",
    build=_build_cf, notes=_cf_notes,
)


RECIPES = [S3_BUCKET, S3_OBJECTS, GLACIER, CLOUDFRONT]
templates.TEMPLATES.update({t.name: t for t in RECIPES})
