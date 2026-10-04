"""Typed tools the LLM may choose from. The LLM never calls AWS directly.

Each tool declares: name, pydantic input schema, risk (read | operate | deploy), destructive flag.
The risk decides which identity is used — chosen here in code, never by the LLM.
Read tools run immediately. Write tools only produce a ScriptDraft, which is saved to the Scripts page;
it runs only when the user clicks Run now or at a time the user scheduled (core/scripts.py).
"""
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal, Optional
from zoneinfo import ZoneInfo

from pydantic import BaseModel, Field, ValidationError, field_validator

from core import audit, schedules, scripts, templates
from core.audit import redact
from core.aws_conn import AwsConnection
from core.config import PROJECT_ROOT, settings
from core.scripts import ScriptDraft, ScriptError


# ---- framework -----------------------------------------------------------------------

@dataclass
class ToolContext:
    conn: AwsConnection
    request: str = ""          # original user request, for the audit log
    pending_task: dict | None = None   # questions payload the user is currently answering (task templates)

    @property
    def owner(self) -> str:
        return self.conn.owner


@dataclass
class Tool:
    name: str
    description: str
    args_model: type[BaseModel]
    risk: Literal["read", "operate", "deploy"]
    func: Callable                       # read: func(ctx, args) -> data ; write: func(ctx, args) -> ScriptDraft
    destructive: bool = False

    @property
    def is_write(self) -> bool:
        return self.risk != "read"


REGISTRY: dict[str, Tool] = {}


def register(tool: Tool) -> Tool:
    REGISTRY[tool.name] = tool
    return tool


class ToolError(Exception):
    """Safe message for the LLM and the user."""


def _clean_schema(schema, in_properties: bool = False):
    """Pydantic JSON schema without 'title' metadata noise; small models do better with short schemas.
    Keys inside a 'properties' mapping are parameter names (a parameter may be called 'title') and are kept."""
    if isinstance(schema, dict):
        return {k: _clean_schema(v, in_properties=(k == "properties" and not in_properties))
                for k, v in schema.items() if in_properties or k != "title"}
    if isinstance(schema, list):
        return [_clean_schema(v) for v in schema]
    return schema


def openai_tool_specs() -> list[dict]:
    return [
        {"type": "function",
         "function": {"name": t.name, "description": t.description,
                      "parameters": _clean_schema(t.args_model.model_json_schema())}}
        for t in REGISTRY.values()
    ]


def validate_args(name: str, raw_args) -> BaseModel:
    """Validate LLM-provided arguments (JSON string or dict). Raises ToolError with a short reason."""
    tool = REGISTRY.get(name)
    if tool is None:
        raise ToolError(f"unknown tool '{name}'")
    if isinstance(raw_args, str):
        try:
            raw_args = json.loads(raw_args) if raw_args.strip() else {}
        except json.JSONDecodeError as e:
            raise ToolError(f"arguments are not valid JSON ({e.msg})") from None
    if raw_args is None:
        raw_args = {}
    if not isinstance(raw_args, dict):
        raise ToolError("arguments must be a JSON object")
    try:
        return tool.args_model.model_validate(raw_args)
    except ValidationError as e:
        errs = "; ".join(f"{'.'.join(map(str, x['loc'])) or 'args'}: {x['msg']}" for x in e.errors()[:3])
        raise ToolError(f"invalid arguments: {errs}") from None


def to_llm_text(data: Any, limit: int | None = None) -> str:
    """Serialize a tool result for the LLM: redacted, compact, truncated (~6000 chars)."""
    limit = limit or settings.max_tool_result_chars
    text = json.dumps(redact(data), default=str, ensure_ascii=False, separators=(",", ":"))
    if len(text) > limit:
        text = text[:limit] + f'... [truncated {len(text) - limit} chars; ask for something narrower]'
    return text


def _summary(data: Any) -> str:
    if isinstance(data, list):
        return f"{len(data)} item(s)"
    if isinstance(data, dict):
        if "count" in data:
            return f"{data['count']} item(s)"
        return ", ".join(f"{k}" for k in list(data)[:6])
    return str(data)[:200]


def run_read_tool(name: str, args: BaseModel, ctx: ToolContext) -> Any:
    tool = REGISTRY[name]
    assert not tool.is_write
    a = args.model_dump()
    try:
        data = tool.func(ctx, args)
    except ToolError as e:
        audit.log_action(actor=ctx.owner, request=ctx.request, tool_name=name, tool_args=a,
                         risk="read", approval="not_required", status="blocked", result_summary=str(e))
        raise
    except Exception as e:
        msg = _aws_error_text(e)
        audit.log_action(actor=ctx.owner, request=ctx.request, tool_name=name, tool_args=a,
                         risk="read", approval="not_required", status="failed", result_summary=msg)
        raise ToolError(msg) from None
    audit.log_action(actor=ctx.owner, request=ctx.request, tool_name=name, tool_args=a,
                     risk="read", approval="not_required", status="success", result_summary=_summary(data))
    return data


def create_script(name: str, args: BaseModel, ctx: ToolContext) -> dict:
    """Write tool -> validated script saved for review on the Scripts page. Nothing runs here."""
    tool = REGISTRY[name]
    assert tool.is_write
    a = args.model_dump()
    try:
        draft = tool.func(ctx, args)
        if isinstance(draft, templates.TaskQuestions):
            return {"questions": draft.to_dict()}  # details missing: nothing saved yet
        saved = scripts.save_draft(ctx.owner, ctx.request, draft)
    except (ToolError, ScriptError, templates.TemplateError) as e:
        audit.log_action(actor=ctx.owner, request=ctx.request, tool_name=name, tool_args=a,
                         risk=tool.risk, approval="not_required", status="blocked", result_summary=str(e))
        raise ToolError(str(e)) from None
    except Exception as e:
        msg = _aws_error_text(e)
        audit.log_action(actor=ctx.owner, request=ctx.request, tool_name=name, tool_args=a,
                         risk=tool.risk, approval="not_required", status="failed", result_summary=msg)
        raise ToolError(msg) from None
    audit.log_action(actor=ctx.owner, request=ctx.request, tool_name=name, tool_args=a, risk=tool.risk,
                     approval="pending", status="pending",
                     result_summary=f"script #{saved['id']} saved for review: {saved['title']}")
    return saved


def _aws_error_text(e: Exception) -> str:
    """Short, secret-free error text."""
    resp = getattr(e, "response", None)
    if isinstance(resp, dict) and "Error" in resp:
        code = resp["Error"].get("Code", "Error")
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            return f"{code}: this identity is not allowed to do that (IAM denied it)"
        return f"{code}: {str(resp['Error'].get('Message', ''))[:200]}"
    return f"{type(e).__name__}: {str(e)[:200]}"


def _local(dt) -> str:
    if not isinstance(dt, datetime):
        return str(dt or "")
    return dt.astimezone(ZoneInfo(settings.app_timezone)).strftime("%Y-%m-%d %H:%M")


def _tags(resource: dict) -> dict:
    return {t["Key"]: t["Value"] for t in resource.get("Tags", []) or []}


# ---- generic aws_read ------------------------------------------------------------------

READ_PREFIXES = ("list_", "describe_", "get_")

# Operations that return secrets, credentials or object contents. Never reachable from the LLM.
BLOCKED_OPERATIONS = {
    ("secretsmanager", "get_secret_value"), ("secretsmanager", "batch_get_secret_value"),
    ("secretsmanager", "get_random_password"),
    ("ssm", "get_parameter"), ("ssm", "get_parameters"), ("ssm", "get_parameters_by_path"),
    ("ssm", "get_parameter_history"),
    ("lambda", "get_function"),            # returns a presigned code download link
    ("ec2", "get_password_data"), ("ec2", "get_console_output"), ("ec2", "get_launch_template_data"),
    ("ecr", "get_authorization_token"), ("ecr-public", "get_authorization_token"),
    ("codeartifact", "get_authorization_token"),
    ("lightsail", "get_instance_access_details"), ("lightsail", "get_relational_database_master_user_password"),
    ("redshift", "get_cluster_credentials"), ("redshift", "get_cluster_credentials_with_iam"),
    ("redshift-serverless", "get_credentials"),
    ("s3", "get_object"), ("s3", "get_object_torrent"),
    ("iam", "get_credential_report"),
    ("cognito-identity", "get_credentials_for_identity"), ("cognito-identity", "get_open_id_token"),
    ("sso", "get_role_credentials"), ("glue", "get_connection"), ("glue", "get_connections"),
    ("rds", "generate_db_auth_token"), ("kms", "decrypt"), ("kms", "get_parameters_for_import"),
}
BLOCKED_SERVICES = {"sts", "sso-oidc", "secretsmanager-data"}
ALLOWED_IN_BLOCKED_SERVICES = {("sts", "get_caller_identity")}
BLOCKED_OP_WORDS = ("password", "credentials", "secret_value", "auth_token", "authorization_token",
                    "access_details", "session_token", "login")


def check_read_allowed(service: str, operation: str) -> None:
    if not re.fullmatch(r"[a-z0-9-]+", service or ""):
        raise ToolError("service must be a boto3 service name like 'ec2' or 'lambda'")
    if not re.fullmatch(r"[a-z0-9_]+", operation or ""):
        raise ToolError("operation must be a snake_case boto3 method like 'describe_instances'")
    if not operation.startswith(READ_PREFIXES):
        raise ToolError("aws_read only allows operations starting with list_, describe_ or get_")
    if (service, operation) in ALLOWED_IN_BLOCKED_SERVICES:
        return
    if service in BLOCKED_SERVICES or (service, operation) in BLOCKED_OPERATIONS \
            or any(w in operation for w in BLOCKED_OP_WORDS):
        raise ToolError(f"{service}.{operation} is blocked because it can return secrets")


class AwsReadArgs(BaseModel):
    service: str = Field(description="boto3 service name, e.g. ec2, lambda, s3, rds, events, scheduler, ecs, iam")
    operation: str = Field(description="boto3 snake_case read method, must start with list_, describe_ or get_")
    params: dict = Field(default_factory=dict, description="Parameters for the call, in boto3 PascalCase")
    region: Optional[str] = Field(default=None, description="AWS region; default is the app region")


def aws_read(ctx: ToolContext, args: AwsReadArgs):
    service, op = args.service.strip().lower(), args.operation.strip()
    check_read_allowed(service, op)
    params = dict(args.params)
    if service == "ssm":
        params.pop("WithDecryption", None)
    client = ctx.conn.client(service, "read", args.region)
    if op not in client.meta.method_to_api_mapping:
        raise ToolError(f"{service} has no operation '{op}'")
    if client.can_paginate(op):
        pages = client.get_paginator(op).paginate(**params, PaginationConfig={"MaxItems": 200})
        result = pages.build_full_result()
    else:
        result = getattr(client, op)(**params)
    result.pop("ResponseMetadata", None)
    return result


register(Tool(
    name="aws_read",
    description=("Generic read-only AWS call for anything the specific tools do not cover. "
                 "Use a boto3 service and a list_/describe_/get_ operation. Prefer the specific tools when they fit."),
    args_model=AwsReadArgs, risk="read", func=aws_read,
))


# ---- curated read tools (clean, flat output for the 14B model) -----------------------------

class NoArgs(BaseModel):
    pass


class ListEc2Args(BaseModel):
    state: Literal["all", "running", "stopped", "pending", "stopping", "terminated"] = Field(
        default="all", description="Filter by instance state")


def list_ec2_instances(ctx: ToolContext, args: ListEc2Args):
    ec2 = ctx.conn.client("ec2", "read")
    filters = [] if args.state == "all" else [{"Name": "instance-state-name", "Values": [args.state]}]
    rows = []
    for page in ec2.get_paginator("describe_instances").paginate(Filters=filters):
        for res in page["Reservations"]:
            for i in res["Instances"]:
                tags = _tags(i)
                rows.append({
                    "id": i["InstanceId"], "name": tags.get("Name", ""), "state": i["State"]["Name"],
                    "type": i.get("InstanceType", ""), "public_ip": i.get("PublicIpAddress", ""),
                    "private_ip": i.get("PrivateIpAddress", ""),
                    "launch_time": _local(i.get("LaunchTime")), "env": tags.get("Env", ""),
                })
    rows.sort(key=lambda r: (r["state"] != "running", r["name"], r["id"]))
    return {"count": len(rows), "region": settings.aws_region, "timezone": settings.app_timezone,
            "instances": rows}


register(Tool(
    name="list_ec2_instances",
    description="List EC2 instances with id, name, state, type, IPs and launch time. Use for any question about instances/servers/VMs.",
    args_model=ListEc2Args, risk="read", func=list_ec2_instances,
))


def list_lambda_functions(ctx: ToolContext, args: NoArgs):
    lam = ctx.conn.client("lambda", "read")
    rows = []
    for page in lam.get_paginator("list_functions").paginate():
        for f in page["Functions"]:
            rows.append({"name": f["FunctionName"], "runtime": f.get("Runtime", ""),
                         "memory_mb": f.get("MemorySize"), "timeout_s": f.get("Timeout"),
                         "last_modified": f.get("LastModified", "")[:16].replace("T", " ")})
    return {"count": len(rows), "functions": sorted(rows, key=lambda r: r["name"]),
            "note": "Lambda does not store schedules; use list_scheduled_lambdas for run times."}


register(Tool(
    name="list_lambda_functions",
    description="List Lambda functions (name, runtime, memory, timeout). NOT for schedules or run times.",
    args_model=NoArgs, risk="read", func=list_lambda_functions,
))


def list_s3_buckets(ctx: ToolContext, args: NoArgs):
    s3 = ctx.conn.client("s3", "read")
    buckets = s3.list_buckets().get("Buckets", [])
    rows = [{"name": b["Name"], "created": _local(b.get("CreationDate"))} for b in buckets]
    return {"count": len(rows), "buckets": rows}


register(Tool(
    name="list_s3_buckets", description="List S3 buckets with creation dates.",
    args_model=NoArgs, risk="read", func=list_s3_buckets,
))


def list_rds_instances(ctx: ToolContext, args: NoArgs):
    rds = ctx.conn.client("rds", "read")
    rows = []
    for page in rds.get_paginator("describe_db_instances").paginate():
        for d in page["DBInstances"]:
            rows.append({"id": d["DBInstanceIdentifier"], "engine": f"{d.get('Engine')} {d.get('EngineVersion', '')}",
                         "class": d.get("DBInstanceClass"), "status": d.get("DBInstanceStatus"),
                         "storage_gb": d.get("AllocatedStorage"), "multi_az": d.get("MultiAZ"),
                         "public": d.get("PubliclyAccessible")})
    return {"count": len(rows), "databases": rows}


register(Tool(
    name="list_rds_instances", description="List RDS database instances (engine, class, status, storage).",
    args_model=NoArgs, risk="read", func=list_rds_instances,
))


def resolve_instance(ec2, ref: str) -> dict:
    """Instance ID or Name tag -> {'id','name','state','tags'}. Must match exactly one instance."""
    ref = ref.strip()
    if re.fullmatch(r"i-[0-9a-f]{8,17}", ref):
        flt = [{"Name": "instance-id", "Values": [ref]}]
    else:
        flt = [{"Name": "tag:Name", "Values": [ref]}]
    flt.append({"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]})
    found = []
    for page in ec2.get_paginator("describe_instances").paginate(Filters=flt):
        for res in page["Reservations"]:
            found.extend(res["Instances"])
    if not found:
        raise ToolError(f"No instance found with ID or Name '{ref}'")
    if len(found) > 1:
        ids = ", ".join(i["InstanceId"] for i in found)
        raise ToolError(f"'{ref}' matches several instances ({ids}); use the instance ID")
    i = found[0]
    tags = _tags(i)
    return {"id": i["InstanceId"], "name": tags.get("Name", ""), "state": i["State"]["Name"], "tags": tags}


class CpuArgs(BaseModel):
    instance: str = Field(description="Instance ID (i-...) or its Name tag")
    hours: int = Field(default=24, ge=1, le=336, description="How many past hours to look at")


def get_ec2_cpu(ctx: ToolContext, args: CpuArgs):
    inst = resolve_instance(ctx.conn.client("ec2", "read"), args.instance)
    cw = ctx.conn.client("cloudwatch", "read")
    end = datetime.now(timezone.utc)
    period = 300 if args.hours <= 6 else 3600
    pts = cw.get_metric_statistics(
        Namespace="AWS/EC2", MetricName="CPUUtilization",
        Dimensions=[{"Name": "InstanceId", "Value": inst["id"]}],
        StartTime=end - timedelta(hours=args.hours), EndTime=end, Period=period,
        Statistics=["Average", "Maximum"],
    ).get("Datapoints", [])
    pts.sort(key=lambda p: p["Timestamp"])
    out = {"instance_id": inst["id"], "name": inst["name"], "state": inst["state"],
           "hours": args.hours, "datapoints": len(pts)}
    if pts:
        avgs = [p["Average"] for p in pts]
        out.update({
            "avg_cpu_percent": round(sum(avgs) / len(avgs), 2),
            "max_cpu_percent": round(max(p["Maximum"] for p in pts), 2),
            "min_avg_cpu_percent": round(min(avgs), 2),
            "latest_avg_cpu_percent": round(avgs[-1], 2),
            "latest_at": _local(pts[-1]["Timestamp"]),
        })
    else:
        out["note"] = "No CPU datapoints in this window (instance stopped or too new)."
    return out


register(Tool(
    name="get_ec2_cpu",
    description="CPU utilization statistics (average, max, latest) for one EC2 instance over the last N hours.",
    args_model=CpuArgs, risk="read", func=get_ec2_cpu,
))


class CostArgs(BaseModel):
    days: int = Field(default=30, ge=1, le=365, description="Number of past days to include")


_COST_CACHE: dict[int, tuple[float, dict]] = {}
_COST_TTL_S = 6 * 3600  # each Cost Explorer call costs ~$0.01, so cache


def get_cost_by_service(ctx: ToolContext, args: CostArgs):
    cached = _COST_CACHE.get(args.days)
    if cached and time.time() - cached[0] < _COST_TTL_S:
        return {**cached[1], "cached": True}
    ce = ctx.conn.client("ce", "read", region="us-east-1")  # Cost Explorer endpoint is global (us-east-1)
    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=args.days)
    totals: dict[str, float] = {}
    unit = "USD"
    kwargs = dict(TimePeriod={"Start": start.isoformat(), "End": end.isoformat()}, Granularity="MONTHLY",
                  Metrics=["UnblendedCost"], GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}])
    while True:
        resp = ce.get_cost_and_usage(**kwargs)
        for period in resp.get("ResultsByTime", []):
            for g in period.get("Groups", []):
                amt = g["Metrics"]["UnblendedCost"]
                unit = amt.get("Unit", unit)
                totals[g["Keys"][0]] = totals.get(g["Keys"][0], 0.0) + float(amt["Amount"])
        if not resp.get("NextPageToken"):
            break
        kwargs["NextPageToken"] = resp["NextPageToken"]
    total = sum(totals.values())
    rows = [{"service": s, "cost": round(c, 2),
             "share_percent": round(100 * c / total, 1) if total else 0.0}
            for s, c in sorted(totals.items(), key=lambda kv: -kv[1]) if round(c, 2) > 0]
    data = {"from": start.isoformat(), "to": end.isoformat(), "currency": unit,
            "total": round(total, 2), "by_service": rows}
    _COST_CACHE[args.days] = (time.time(), data)
    return data


register(Tool(
    name="get_cost_by_service",
    description="AWS spend for the last N days broken down by service, with totals and percentages (from Cost Explorer).",
    args_model=CostArgs, risk="read", func=get_cost_by_service,
))


class ScheduledArgs(BaseModel):
    after_time: str = Field(default="10:00", description="Time of day, e.g. '10:00', '10am', '14:30'")
    timezone: str = Field(default=settings.app_timezone, description="IANA timezone of the user")

    @field_validator("after_time")
    @classmethod
    def _valid_time(cls, v):
        schedules.parse_hhmm(v)
        return v

    @field_validator("timezone")
    @classmethod
    def _valid_tz(cls, v):
        ZoneInfo(v)
        return v


def list_scheduled_lambdas(ctx: ToolContext, args: ScheduledArgs):
    errors, clients = [], {}
    for service in ("events", "scheduler"):
        try:
            clients[service] = ctx.conn.client(service, "read")
        except Exception as e:
            clients[service] = None
            errors.append(f"{service}: {type(e).__name__}")
    entries, warnings = schedules.collect_schedules(clients["events"], clients["scheduler"])
    result = schedules.scheduled_lambdas(entries, args.after_time, args.timezone)
    result["errors"] = errors + warnings
    return result


register(Tool(
    name="list_scheduled_lambdas",
    description=("Lambda functions that run on a schedule (EventBridge rules and EventBridge Scheduler) with "
                 "their next run times in the user's timezone, filtered to runs at or after a time of day. "
                 "Use for: scheduled, cron, runs at, triggers, 'what runs after 10am'."),
    args_model=ScheduledArgs, risk="read", func=list_scheduled_lambdas,
))


# ---- more read tools: load balancers, Lambda code --------------------------------------

def list_load_balancers(ctx: ToolContext, args: NoArgs):
    elb = ctx.conn.client("elbv2", "read")
    rows = []
    for page in elb.get_paginator("describe_load_balancers").paginate():
        for lb in page["LoadBalancers"]:
            dns = lb.get("DNSName", "")
            rows.append({"name": lb["LoadBalancerName"], "type": lb.get("Type"), "scheme": lb.get("Scheme"),
                         "state": lb.get("State", {}).get("Code"), "dns_name": dns,
                         "url": f"http://{dns}" if dns else "", "vpc": lb.get("VpcId")})
    return {"count": len(rows), "load_balancers": rows,
            "note": "url uses http://; use https:// if the load balancer has an HTTPS listener."}


register(Tool(
    name="list_load_balancers",
    description="List Application/Network Load Balancers (ALB/NLB) with their DNS name and URL. Use for 'URL of the ALB'.",
    args_model=NoArgs, risk="read", func=list_load_balancers,
))


class LambdaCodeArgs(BaseModel):
    function_name: str = Field(description="Exact Lambda function name")


LAMBDA_DOWNLOAD_DIR = PROJECT_ROOT / "downloads" / "lambda"
_MAX_LAMBDA_ZIP = 50 * 1024 * 1024


def download_lambda_code(ctx: ToolContext, args: LambdaCodeArgs):
    """Download and extract a function's code locally. The presigned URL and the code never go to the LLM."""
    import io
    import urllib.request
    import zipfile

    name = args.function_name.strip()
    if not re.fullmatch(r"[\w-]{1,64}", name):
        raise ToolError("function_name must be a plain Lambda function name")
    fn = ctx.conn.client("lambda", "read").get_function(FunctionName=name)
    code = fn.get("Code", {})
    if code.get("RepositoryType") != "S3" or not code.get("Location"):
        raise ToolError(f"{name} is a container-image function; its code is in ECR, not downloadable here")
    with urllib.request.urlopen(code["Location"], timeout=60) as resp:
        blob = resp.read(_MAX_LAMBDA_ZIP + 1)
    if len(blob) > _MAX_LAMBDA_ZIP:
        raise ToolError("code package is larger than 50 MB")
    target = (LAMBDA_DOWNLOAD_DIR / name).resolve()
    target.mkdir(parents=True, exist_ok=True)
    files = []
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for info in zf.infolist():
            dest = (target / info.filename).resolve()
            if not str(dest).startswith(str(target)):  # zip-slip protection
                continue
            zf.extract(info, target)
            if not info.is_dir():
                files.append({"file": info.filename, "bytes": info.file_size})
    cfg = fn.get("Configuration", {})
    return {"function": name, "runtime": cfg.get("Runtime"), "handler": cfg.get("Handler"),
            "saved_to": str(target), "files": files[:100], "file_count": len(files),
            "note": "Code was saved locally and was not sent to the AI."}


register(Tool(
    name="download_lambda_code",
    description="Extract/download a Lambda function's code to a local folder and list its files. Use for 'extract this lambda script'.",
    args_model=LambdaCodeArgs, risk="read", func=download_lambda_code,
))


# ---- write tools: each one produces a script for the Scripts page ----------------------

DEMO_TAG = ("Env", "demo")


class InstanceArgs(BaseModel):
    instance: str = Field(description="Instance ID (i-...) or its Name tag")


def _instance_script(ctx: ToolContext, args: InstanceArgs, verb: str, ok_states: set[str]) -> ScriptDraft:
    inst = resolve_instance(ctx.conn.client("ec2", "read"), args.instance)
    k, v = DEMO_TAG
    if inst["tags"].get(k) != v:
        raise ToolError(f"{inst['id']} ({inst['name'] or 'no name'}) is not tagged {k}={v}; "
                        f"the app only {verb}s demo instances.")
    if inst["state"] not in ok_states:
        raise ToolError(f"{inst['id']} ({inst['name'] or 'no name'}) is '{inst['state']}', cannot {verb} it now.")
    label = f"{inst['id']} ({inst['name']})" if inst["name"] else inst["id"]
    return ScriptDraft(
        title=f"{verb.capitalize()} {label}",
        steps=[{
            "service": "ec2", "operation": f"{verb}_instances", "params": {"InstanceIds": [inst["id"]]},
            "description": f"{verb.capitalize()} {label}",
            "guard": {"ec2_tag": {"instance_id": inst["id"], "key": k, "value": v},
                      "text": f"{inst['id']} must still be tagged {k}={v}"},
        }],
    )


register(Tool(
    name="stop_instance",
    description="Create a script (saved on the Scripts page) that stops one EC2 instance by ID or Name. Only Env=demo instances. Does not run until the user runs or schedules it.",
    args_model=InstanceArgs, risk="operate",
    func=lambda ctx, a: _instance_script(ctx, a, "stop", {"running", "pending"}),
))

register(Tool(
    name="start_instance",
    description="Create a script (saved on the Scripts page) that starts one stopped EC2 instance by ID or Name. Only Env=demo instances. Does not run until the user runs or schedules it.",
    args_model=InstanceArgs, risk="operate",
    func=lambda ctx, a: _instance_script(ctx, a, "start", {"stopped"}),
))


class AwsWriteArgs(BaseModel):
    title: str = Field(description="Short title for the script, e.g. 'Tag web-demo with Owner=ash'")
    service: str = Field(description="boto3 service name, e.g. ec2, s3, lambda, ecs")
    operation: str = Field(description="boto3 snake_case write method, e.g. create_tags, put_function_concurrency")
    params: dict = Field(default_factory=dict, description="Parameters in boto3 PascalCase")
    region: Optional[str] = Field(default=None, description="AWS region; default is the app region")


def _s3_create_bucket_region(params: dict, region: str) -> str:
    """S3 needs the API region to match LocationConstraint (and no constraint in us-east-1). Fix it in code."""
    cfg = params.get("CreateBucketConfiguration") or {}
    location = cfg.get("LocationConstraint")
    if location:
        region = location  # the bucket's location wins over a mismatched API region
    if region == "us-east-1":
        params.pop("CreateBucketConfiguration", None)
    else:
        params["CreateBucketConfiguration"] = {**cfg, "LocationConstraint": region}
    return region


def aws_write(ctx: ToolContext, args: AwsWriteArgs) -> ScriptDraft:
    service, op = args.service.strip().lower(), args.operation.strip()
    region = args.region or settings.aws_region
    params = dict(args.params)
    if service == "s3" and op == "create_bucket":
        region = _s3_create_bucket_region(params, region)
    step = {"service": service, "operation": op, "params": params, "region": region,
            "description": args.title}
    scripts.validate_step(step)  # policy + botocore parameter validation, before saving
    return ScriptDraft(title=args.title, steps=[step], region=region)


register(Tool(
    name="aws_write",
    description=("Create a script (saved on the Scripts page) for any other AWS change, as one boto3 call. "
                 "The user reviews it and runs or schedules it. IAM, billing and account changes are blocked."),
    args_model=AwsWriteArgs, risk="operate", func=aws_write,
))


class PlanTaskArgs(BaseModel):
    template: Literal["vpc_network", "ec2_instance"] = Field(
        description="vpc_network: VPC with public/private subnets, internet gateway, route tables, optional NAT. "
                    "ec2_instance: launch one EC2 instance.")
    inputs: dict = Field(default_factory=dict, description=(
        "ONLY details the user actually said. vpc_network keys: name, cidr, public_subnets, private_subnets, "
        "azs (list), nat_gateway (yes/no). ec2_instance keys: name, purpose (web/admin/private), "
        "os (amazon-linux-2023/ubuntu-24.04/windows-2022), instance_type, subnet_id, security_group "
        "('new' or sg-id), admin_cidr, key_name, volume_gb. Leave out anything the user did not say."))


def plan_task(ctx: ToolContext, args: PlanTaskArgs):
    """The LLM may guess values; key decisions are only accepted once the user has seen the questions."""
    given = {k: v for k, v in args.inputs.items() if v not in (None, "", [])}
    pending = ctx.pending_task if ctx.pending_task and ctx.pending_task.get("template") == args.template else None
    if pending:  # the user is answering earlier questions: merge, and treat what they said now as confirmed
        inputs = {**pending.get("inputs", {}), **given}
        confirmed = set(pending.get("confirmed", [])) | set(given)
    else:
        inputs = given
        confirmed = set(given) - templates.must_ask_keys(args.template)
    return templates.plan(args.template, inputs, ctx.conn, confirmed)


register(Tool(
    name="plan_task",
    description=("Build infrastructure that needs details from the user: a VPC network (subnets, internet "
                 "gateway, NAT gateway, route tables) or a new EC2 instance. The app asks the user for "
                 "anything missing, then saves a script on the Scripts page."),
    args_model=PlanTaskArgs, risk="operate", func=plan_task,
))
