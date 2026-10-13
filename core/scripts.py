"""Scripts: every write request becomes a reviewable script (Scripts page) that runs only when the user
clicks Run now, or at a time the user scheduled.

A script is a list of typed steps. Most are AWS calls {service, operation, params, description, guard?};
others run local tools, log in to ECR, run Ansible or check a URL (core/local_steps.py, field "kind").
The LLM never writes free-form code: it picks a typed tool or recipe, this module validates every step
(botocore API model + write policy, or the local tool allowlist) and renders a review script. Execution
is done by code with the identity chosen from the script's risk tier.
"""
import json
import re
import threading
import time
from functools import lru_cache
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, ParamValidationError
from botocore.validate import validate_parameters

from core import audit, db, local_steps, workspace
from core.config import settings
from core.local_steps import StepError

READ_PREFIXES = ("list_", "describe_", "get_")
BLOCKED_WRITE_SERVICES = {"organizations", "account", "billing", "sts", "sso", "sso-admin",
                          "identitystore", "controltower"}
SENSITIVE_SERVICES = {"iam"}
BLOCKED_IAM_OPERATIONS = {
    "create_access_key", "create_login_profile", "update_login_profile", "create_service_specific_credential",
    "reset_service_specific_credential", "create_virtual_mfa_device", "enable_mfa_device", "resync_mfa_device",
    "deactivate_mfa_device", "upload_server_certificate",
    "delete_account_password_policy",
}
ADMIN_POLICY_NAMES = {"AdministratorAccess"}
POLICY_DOC_KEYS = ("PolicyDocument", "AssumeRolePolicyDocument")
BLOCKED_WRITE_OPERATIONS = {
    ("cloudtrail", "stop_logging"), ("cloudtrail", "delete_trail"), ("cloudtrail", "update_trail"),
    ("guardduty", "delete_detector"), ("config", "stop_configuration_recorder"),
    ("config", "delete_configuration_recorder"), ("securityhub", "disable_security_hub"),
    ("s3", "put_bucket_acl"), ("s3", "put_object_acl"),
    ("secretsmanager", "get_secret_value"), ("kms", "schedule_key_deletion"), ("kms", "disable_key"),
}
DESTRUCTIVE_PREFIXES = ("delete_", "terminate_", "remove_", "deregister_", "purge_", "detach_",
                        "disassociate_", "revoke_", "cancel_", "release_", "disable_")
MANAGED_PASSWORD = {
    ("rds", "create_db_instance"): ("MasterUsername", "ManageMasterUserPassword"),
    ("rds", "create_db_cluster"): ("MasterUsername", "ManageMasterUserPassword"),
    ("docdb", "create_db_cluster"): ("MasterUsername", "ManageMasterUserPassword"),
    ("redshift", "create_cluster"): ("MasterUsername", "ManageMasterPassword"),
    ("redshift-serverless", "create_namespace"): ("adminUsername", "manageAdminPassword"),
}
PUBLIC_READ_ACTIONS = {"s3:GetObject", "s3:GetObjectVersion"}
_PASSWORD_PARAM_RE = re.compile(r"password|^authtoken$", re.I)


class ScriptError(Exception):
    """Safe-to-display error."""


def is_destructive(operation: str) -> bool:
    return operation.startswith(DESTRUCTIVE_PREFIXES)


def needs_confirmation(step: dict) -> bool:
    """Typed confirmation: deletes/terminations, IAM changes, destructive local commands."""
    if local_steps.kind_of(step) != "aws":
        return local_steps.is_destructive(step)
    return (is_destructive(step["operation"]) or step["service"] in SENSITIVE_SERVICES
            or (step.get("params") or {}).get("PubliclyAccessible") is True or makes_public(step))


def makes_public(step: dict) -> bool:
    """Opens S3 to the internet: Block Public Access turned off, or a bucket policy for Principal '*'."""
    svc, op, params = step.get("service"), step.get("operation"), step.get("params") or {}
    if svc in ("s3", "s3control") and op == "delete_public_access_block":
        return True
    if svc in ("s3", "s3control") and op == "put_public_access_block":
        cfg = params.get("PublicAccessBlockConfiguration") or {}
        return not all(cfg.get(k) is True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy",
                                                     "RestrictPublicBuckets"))
    if svc == "s3" and op == "put_bucket_policy":
        return bool(_public_statements(params.get("Policy")))
    if svc == "lambda" and op == "add_permission" and params.get("Principal") == "*":
        return True
    return False


def _public_statements(doc) -> list[dict]:
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except json.JSONDecodeError:
            return []
    if not isinstance(doc, dict):
        return []
    out = []
    for st in _as_list(doc.get("Statement", [])):
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        pr = st.get("Principal")
        values = [pr] if isinstance(pr, str) else             [v for p in pr.values() for v in _as_list(p)] if isinstance(pr, dict) else []
        if "*" in values:
            out.append(st)
    return out


def _check_public_bucket_policy(params: dict) -> None:
    """A public bucket policy may only let everyone READ objects (a website), never write, delete or list."""
    doc = params.get("Policy")
    if isinstance(doc, str):
        try:
            json.loads(doc)
        except json.JSONDecodeError:
            raise ScriptError("the bucket policy is not valid JSON") from None
    for st in _public_statements(doc):
        if "NotAction" in st or "NotResource" in st:
            raise ScriptError("a public bucket policy may not use NotAction/NotResource")
        actions = set(_as_list(st.get("Action", [])))
        if not actions or not actions <= PUBLIC_READ_ACTIONS:
            raise ScriptError("a public bucket policy (Principal '*') may only allow s3:GetObject / "
                              "s3:GetObjectVersion, so anyone can view files but nobody can change or delete them")
        if not all(str(r).endswith("/*") for r in _as_list(st.get("Resource", []))):
            raise ScriptError("a public bucket policy may only cover objects (arn:aws:s3:::<bucket>/*)")


def check_write_allowed(service: str, operation: str, params: dict) -> None:
    if not re.fullmatch(r"[a-z0-9-]+", service or "") or not re.fullmatch(r"[a-z0-9_]+", operation or ""):
        raise ScriptError("service/operation must be boto3 names like 'ec2' and 'stop_instances'")
    if operation.startswith(READ_PREFIXES):
        raise ScriptError(f"{operation} is a read; ask it as a question in chat instead")
    if service in BLOCKED_WRITE_SERVICES:
        raise ScriptError(f"Changes to '{service}' (accounts, organizations, identity center) are blocked; do "
                          f"them yourself in the AWS console.")
    if (service, operation) in BLOCKED_WRITE_OPERATIONS:
        raise ScriptError(f"{service}.{operation} is blocked by the app's safety policy")
    if service == "ec2" and operation == "authorize_security_group_ingress":
        _check_no_open_ssh(params)
    if service == "iam":
        _check_iam(operation, params)
    if service == "s3" and operation == "put_bucket_policy" and not has_placeholders(params):
        _check_public_bucket_policy(params)
    if service == "ec2" and operation in ("modify_image_attribute", "modify_snapshot_attribute"):
        _check_not_public_image(params)
    _check_no_plain_password(service, operation, params)


def _check_not_public_image(params: dict) -> None:
    """AMIs and snapshots may be shared with specific accounts, never made public (they can contain data)."""
    perm = params.get("LaunchPermission") or {}
    groups = [p.get("Group") for p in perm.get("Add", []) if isinstance(p, dict)]
    groups += [params.get("Attribute") == "createVolumePermission" and params.get("OperationType") == "add"
               and g for g in params.get("GroupNames", [])]
    groups += [p.get("Group") for p in (params.get("CreateVolumePermission") or {}).get("Add", []) if isinstance(p, dict)]
    if "all" in groups:
        raise ScriptError("Making an AMI or snapshot public is blocked: anyone could copy your disk. Share it with "
                          "specific account IDs instead.")


def _check_no_plain_password(service: str, operation: str, params) -> None:
    """A literal password in a script would be stored and shown; let AWS generate and manage it."""
    if isinstance(params, list):
        for v in params:
            _check_no_plain_password(service, operation, v)
        return
    if not isinstance(params, dict):
        return
    for k, v in params.items():
        if _PASSWORD_PARAM_RE.search(str(k)) and isinstance(v, str) and v:
            hint = (f" Leave it out: the app sets {MANAGED_PASSWORD[(service, operation)][1]}=true so AWS creates "
                    f"the password and keeps it in Secrets Manager." if (service, operation) in MANAGED_PASSWORD
                    else " Set it yourself in the AWS console so only you see it.")
            raise ScriptError(f"Scripts may not contain passwords ('{k}').{hint}")
        _check_no_plain_password(service, operation, v)


def _check_iam(operation: str, params: dict) -> None:
    if operation in BLOCKED_IAM_OPERATIONS:
        raise ScriptError(f"iam.{operation} creates or changes secrets (keys, passwords, MFA). Do it yourself in "
                          f"the IAM console so the secret is shown only to you.")
    arn = str(params.get("PolicyArn", ""))
    if arn.rsplit("/", 1)[-1] in ADMIN_POLICY_NAMES:
        raise ScriptError("Granting AdministratorAccess through the app is blocked. Give full admin rights "
                          "yourself in the IAM console if you really need them.")
    for key in POLICY_DOC_KEYS:
        if key in params and not has_placeholders(params[key]):
            _check_policy_document(params[key], trust=(key == "AssumeRolePolicyDocument"))


def _as_list(v) -> list:
    return v if isinstance(v, list) else [v]


def _check_policy_document(doc, trust: bool) -> None:
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except json.JSONDecodeError:
            raise ScriptError("the policy document is not valid JSON") from None
    if not isinstance(doc, dict):
        raise ScriptError("the policy document must be a JSON object")
    for st in _as_list(doc.get("Statement", [])):
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        if trust:
            principal = st.get("Principal")
            values = [principal] if isinstance(principal, str) else \
                [v for p in (principal or {}).values() for v in _as_list(p)] if isinstance(principal, dict) else []
            if "*" in values:
                raise ScriptError("A trust policy that lets anyone ('*') assume the role is blocked.")
            continue
        if "NotAction" in st:
            raise ScriptError("Allow + NotAction grants almost everything; write the actions you need instead.")
        actions = [str(a).lower() for a in _as_list(st.get("Action", []))]
        resources = [str(r) for r in _as_list(st.get("Resource", []))]
        if any(a in ("*", "iam:*") for a in actions) and "*" in resources:
            raise ScriptError("A policy that allows '*' or 'iam:*' on every resource is full admin and is blocked. "
                              "List the specific actions you need.")


def normalize_params(service: str, operation: str, params: dict) -> dict:
    """Small-model friendliness: IAM policy documents given as objects are sent as JSON strings."""
    out = dict(params)
    for key in POLICY_DOC_KEYS:
        if isinstance(out.get(key), dict):
            out[key] = json.dumps(out[key])
    if (service, operation) in MANAGED_PASSWORD:
        user_key, flag = MANAGED_PASSWORD[(service, operation)]
        has_password = any(_PASSWORD_PARAM_RE.search(k) for k in out if k != flag)
        if user_key in out and not has_password:
            out.setdefault(flag, True)
    return out


def _check_no_open_ssh(params: dict) -> None:
    """Never 0.0.0.0/0 (or ::/0) on port 22."""
    perms = params.get("IpPermissions") or [params]
    for p in perms:
        lo, hi = p.get("FromPort", -1), p.get("ToPort", -1)
        covers_22 = p.get("IpProtocol") in ("-1", "all") or (isinstance(lo, int) and lo <= 22 <= hi)
        cidrs = [r.get("CidrIp") for r in p.get("IpRanges", [])] + [r.get("CidrIpv6") for r in p.get("Ipv6Ranges", [])]
        cidrs.append(params.get("CidrIp"))
        if covers_22 and any(c in ("0.0.0.0/0", "::/0") for c in cidrs):
            raise ScriptError("Opening SSH (port 22) to the whole internet is blocked. Use your own IP /32.")


_model_lock = threading.Lock()


@lru_cache(maxsize=64)
def _model_client(service: str):
    """A credential-less client used only to read the botocore API model (cached; no AWS calls)."""
    with _model_lock:
        return boto3.session.Session().client(service, region_name="us-east-1")


_FAKE_ID_RE = re.compile(r"\b(?:vpc|subnet|sg|igw|nat|rtb|eipalloc|i|ami|vol|snap|eni|acl|lt)-"
                         r"(?:12345678\w*|0123456789abcdef\w*|x{4,}\w*|0{8,}|abcdef\w*|example\w*)\b", re.I)


def check_no_fake_ids(params) -> None:
    for m in _FAKE_ID_RE.finditer(json.dumps(params, default=str)):
        raise ScriptError(f"'{m.group(0)}' looks like a made-up example ID, not a real resource. Ask a question "
                          f"to find the real ID, or use a task template so the app asks you.")


FILE_PREFIX = "@file:"
MAX_FILE_BYTES = 70 * 1024 * 1024


def _file_ref_path(value: str) -> Path:
    p = Path(value[len(FILE_PREFIX):])
    if not workspace.in_workspace(p):
        raise ScriptError(f"{value}: only files the app generated in its workspace folder can be uploaded")
    return p


def load_files(value):
    """Replace "@file:..." strings with the file contents (bytes), at run time."""
    if isinstance(value, dict):
        return {k: load_files(v) for k, v in value.items()}
    if isinstance(value, list):
        return [load_files(v) for v in value]
    if isinstance(value, str) and value.startswith(FILE_PREFIX):
        p = _file_ref_path(value)
        if not p.is_file():
            raise ScriptError(f"file not found: {p} (generated files live in the workspace folder)")
        if p.stat().st_size > MAX_FILE_BYTES:
            raise ScriptError(f"{p.name} is too large to upload directly")
        return p.read_bytes()
    return value


def _files_as_placeholders(value):
    """For validation only: file references become empty bytes, checked for location."""
    if isinstance(value, dict):
        return {k: _files_as_placeholders(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_files_as_placeholders(v) for v in value]
    if isinstance(value, str) and value.startswith(FILE_PREFIX):
        _file_ref_path(value)
        return b""
    return value


def validate_step(step: dict) -> None:
    """Policy + botocore model validation (rejects made-up operations, parameters and example IDs).
    Steps of another kind (local tools, checks) are validated by core/local_steps.py."""
    if local_steps.kind_of(step) != "aws":
        try:
            local_steps.validate(step)
        except StepError as e:
            raise ScriptError(str(e)) from None
        check_no_fake_ids({k: v for k, v in step.items() if k != "undo"})
        return
    service, op, params = step["service"], step["operation"], step.get("params", {})
    check_write_allowed(service, op, params)
    check_no_fake_ids(params)
    try:
        client = _model_client(service)
    except Exception:
        raise ScriptError(f"'{service}' is not an AWS service known to boto3") from None
    api = client.meta.method_to_api_mapping.get(op)
    if not api:
        raise ScriptError(f"{service} has no operation '{op}'")
    shape = client.meta.service_model.operation_model(api).input_shape
    try:
        validate_parameters(_files_as_placeholders(params), shape) if shape else None
    except ParamValidationError as e:
        raise ScriptError(f"Invalid parameters for {service}.{op}: {str(e)[:300]}") from None


def supports_dry_run(step: dict) -> bool:
    if local_steps.kind_of(step) != "aws":
        return False
    try:
        client = _model_client(step["service"])
        api = client.meta.method_to_api_mapping[step["operation"]]
        shape = client.meta.service_model.operation_model(api).input_shape
        return bool(shape and "DryRun" in shape.members)
    except Exception:
        return False


def _kebab(name: str) -> str:
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "-", name)
    s = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "-", s)
    return s.replace("_", "-").lower()


def _cli_value(v) -> str:
    if isinstance(v, bool):
        return ""
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str) and v.startswith(FILE_PREFIX):
        return f'fileb://"{v[len(FILE_PREFIX):]}"'
    if isinstance(v, str):
        return v if re.fullmatch(r"[\w./:@=+-]+", v) else "'" + v.replace("'", "'\\''") + "'"
    if isinstance(v, list) and all(isinstance(x, (str, int)) for x in v):
        return " ".join(_cli_value(x) for x in v)
    return "'" + json.dumps(v, separators=(",", ":")).replace("'", "'\\''") + "'"


def _cli_command(s: dict, region: str) -> str:
    parts = [f"aws {s['service']} {_kebab(s['operation'])}"]
    for k, v in s.get("params", {}).items():
        if isinstance(v, bool):
            parts.append(f"--{_kebab(k)}" if v else f"--no-{_kebab(k)}")
        else:
            parts.append(f"--{_kebab(k)} {_cli_value(v)}")
    parts.append(f"--region {s.get('region') or region}")
    return " \\\n    ".join(parts)


def render_cli(steps: list[dict], region: str, notes: list[str] | None = None) -> str:
    lines = ["# Equivalent commands (for review). Kintsugi runs these steps itself (AWS calls with boto3, local",
             "# tools without a shell) using your 'Write' connection, only when you click Run now or at the",
             "# scheduled time."]
    if any(has_placeholders({k: v for k, v in s.items() if k not in ("undo", "description")}) for s in steps):
        lines.append("# Values like {{vpc.Vpc.VpcId}} are IDs created by an earlier step, filled in while running.")
    if any(s.get("undo") for s in steps):
        lines.append("# After running (or if a step fails) Kintsugi saves a teardown script that deletes what was created.")
    for note in notes or []:
        lines.append(f"# NOTE: {note}")
    lines.append("")
    for n, s in enumerate(steps, 1):
        lines.append(f"# Step {n}: {s.get('description', '')}")
        if g := s.get("guard"):
            lines.append(f"# Safety check before running: {g.get('text', '')}")
        if local_steps.kind_of(s) != "aws":
            lines.append(local_steps.render(s, region))
        else:
            lines.append(_cli_command(s, region))
            if w := s.get("wait"):
                lines.append(_cli_command({"service": s["service"], "operation": "wait_" + w["waiter"],
                                           "params": w.get("params", {}), "region": s.get("region")}, region)
                             .replace(f"aws {s['service']} wait-", f"aws {s['service']} wait ", 1))
        if s.get("pause_after"):
            lines.append(f"sleep {s['pause_after']}   # give AWS time to propagate the change")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


@dataclass
class ScriptDraft:
    title: str
    steps: list[dict]
    risk: str = "operate"
    region: str = field(default_factory=lambda: settings.aws_region)
    notes: list[str] = field(default_factory=list)

    @property
    def destructive(self) -> bool:
        """True when running it needs a typed confirmation (deletes, IAM changes, destructive commands)."""
        return any(needs_confirmation(s) for s in self.steps)


def confirm_phrase(script_id: int) -> str:
    return f"run script {script_id}"


STEP_KEYS = {"service", "operation", "params", "description", "region", "save_as", "wait", "undo", "guard",
             "pause_after"}
RUNNABLE = ("approved", "failed")
STATUS_TEXT = {"draft": "waiting for your review", "approved": "approved", "denied": "denied",
               "scheduled": "scheduled", "running": "running", "succeeded": "succeeded", "failed": "failed"}


def _check_pause(st: dict, where: str) -> None:
    p = st.get("pause_after", 0)
    if not isinstance(p, int) or not 0 <= p <= local_steps.MAX_PAUSE_S:
        raise ScriptError(f"{where}: pause_after must be 0..{local_steps.MAX_PAUSE_S} seconds")


def _validate_undo(u, n: int) -> None:
    if not isinstance(u, dict):
        raise ScriptError(f"Step {n}: 'undo' must be an object")
    _check_pause(u, f"Step {n} undo")
    if local_steps.kind_of(u) != "aws":
        try:
            local_steps.validate({k: v for k, v in u.items() if k != "pause_after"})
        except StepError as e:
            raise ScriptError(f"Step {n} undo: {e}") from None
        return
    check_write_allowed(u.get("service", ""), u.get("operation", ""), {})


def validate_steps(steps: list[dict]) -> None:
    """Every step: policy + botocore model (or local tool allowlist) + fake-ID check; undo actions: policy;
    placeholders must refer to a 'save_as' name of an EARLIER step."""
    if not isinstance(steps, list) or not steps:
        raise ScriptError("A script needs at least one step")
    defined: set[str] = set()
    for n, st in enumerate(steps, 1):
        if not isinstance(st, dict):
            raise ScriptError(f"Step {n} must be an object")
        if local_steps.kind_of(st) == "aws":
            if not {"service", "operation"} <= set(st):
                raise ScriptError(f"Step {n} needs at least 'service' and 'operation' (or a 'kind')")
            extra = set(st) - STEP_KEYS
            if extra:
                raise ScriptError(f"Step {n} has unknown field(s): {', '.join(sorted(extra))}")
            if not isinstance(st.get("params", {}), dict):
                raise ScriptError(f"Step {n}: 'params' must be an object")
        _check_pause(st, f"Step {n}")
        body = {k: v for k, v in st.items() if k not in ("undo", "wait", "save_as", "description")}
        for ref in _PLACEHOLDER_RE.findall(json.dumps(body, default=str)):
            if ref.split(".")[0] not in defined:
                raise ScriptError(f"Step {n} uses {{{{{ref}}}}} but no earlier step has save_as '{ref.split('.')[0]}'")
        try:
            validate_step(st)
        except ScriptError as e:
            raise ScriptError(f"Step {n}: {e}") from None
        if st.get("undo"):
            _validate_undo(st["undo"], n)
        if st.get("save_as"):
            defined.add(st["save_as"])


def save_draft(owner: str, request: str, draft: ScriptDraft) -> dict:
    validate_steps(draft.steps)
    text = render_cli(draft.steps, draft.region, draft.notes)
    sid = db.execute(
        """INSERT INTO scripts (owner, title, request, steps, script_text, risk, destructive, region)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (owner, draft.title[:200], request, json.dumps(draft.steps), text, draft.risk, draft.destructive,
         draft.region),
    )
    return {"id": sid, "title": draft.title, "destructive": draft.destructive, "risk": draft.risk}


def list_scripts(owner: str) -> list[dict]:
    return db.fetch_all(
        """SELECT id, title, status, risk, destructive, region, run_at, created_at, last_run_at
           FROM scripts WHERE owner = %s ORDER BY id DESC""", (owner,))


def get_script(owner: str, script_id: int) -> dict:
    row = db.fetch_one("SELECT * FROM scripts WHERE id = %s AND owner = %s", (script_id, owner))
    if not row:
        raise ScriptError(f"Script #{script_id} no longer exists (it was deleted). The list has been refreshed.")
    return row


def _set(script_id: int, **cols):
    sets = ", ".join(f"{k} = %s" for k in cols)
    db.execute(f"UPDATE scripts SET {sets} WHERE id = %s", (*cols.values(), script_id))


def _check_confirmation(row: dict, typed: str):
    if row["destructive"] and typed.strip().lower() != confirm_phrase(row["id"]):
        raise ScriptError(f"This script deletes or removes resources. Type '{confirm_phrase(row['id'])}' to confirm.")


def schedule_script(owner: str, script_id: int, run_at: datetime, typed_confirmation: str = "") -> dict:
    row = get_script(owner, script_id)
    if row["status"] not in RUNNABLE:
        raise ScriptError(_not_runnable(row))
    if run_at.tzinfo is None:
        raise ScriptError("run_at must include a timezone")
    if run_at <= datetime.now(timezone.utc):
        raise ScriptError("Pick a time in the future (or use Run now)")
    _check_confirmation(row, typed_confirmation)
    _set(script_id, status="scheduled", run_at=run_at)
    audit.log_action(actor=owner, request=row["request"], tool_name=f"script#{script_id}",
                     tool_args={"title": row["title"], "run_at": run_at.isoformat()}, risk=row["risk"],
                     approval="approved", status="pending", result_summary="scheduled")
    return get_script(owner, script_id)


def cancel_script(owner: str, script_id: int) -> None:
    row = get_script(owner, script_id)
    if row["status"] != "scheduled":
        raise ScriptError("Script is not scheduled")
    _set(script_id, status="approved", run_at=None)
    audit.log_action(actor=owner, request=row["request"], tool_name=f"script#{script_id}",
                     tool_args={"title": row["title"]}, risk=row["risk"], approval="approved",
                     status="blocked", result_summary="schedule cancelled by user (still approved)")


def _not_runnable(row: dict) -> str:
    st = row["status"]
    if st == "draft":
        return f"Script #{row['id']} is waiting for your review. Click Approve first."
    if st == "denied":
        return f"Script #{row['id']} was denied. Approve it (or edit it) before running."
    return f"Script #{row['id']} is {STATUS_TEXT.get(st, st)} and cannot be run now."


def approve_script(owner: str, script_id: int) -> dict:
    row = get_script(owner, script_id)
    if row["status"] not in ("draft", "denied"):
        raise ScriptError(f"Script #{script_id} is {STATUS_TEXT.get(row['status'], row['status'])}; nothing to approve")
    _set(script_id, status="approved", approved_at=datetime.now(timezone.utc), result=None)
    audit.log_action(actor=owner, request=row["request"], tool_name=f"script#{script_id}",
                     tool_args={"title": row["title"]}, risk=row["risk"], approval="approved",
                     status="pending", result_summary="approved by user (not run yet)")
    return get_script(owner, script_id)


def deny_script(owner: str, script_id: int, reason: str = "") -> dict:
    row = get_script(owner, script_id)
    if row["status"] in ("running", "succeeded"):
        raise ScriptError(f"Script #{script_id} is {row['status']}; it cannot be denied")
    reason = reason.strip()[:500]
    _set(script_id, status="denied", run_at=None, approved_at=None,
         result=f"Denied by you{': ' + reason if reason else ''}")
    audit.log_action(actor=owner, request=row["request"], tool_name=f"script#{script_id}",
                     tool_args={"title": row["title"], "reason": reason}, risk=row["risk"], approval="rejected",
                     status="blocked", result_summary=f"denied by user{': ' + reason if reason else ''}")
    return get_script(owner, script_id)


def editable_steps_text(row: dict) -> str:
    steps = row["steps"] if isinstance(row["steps"], list) else json.loads(row["steps"])
    return json.dumps(steps, indent=2)


def update_steps(owner: str, script_id: int, steps_text: str) -> dict:
    """Manual edit: validate everything again, re-render, and require a fresh approval."""
    row = get_script(owner, script_id)
    if row["status"] == "running":
        raise ScriptError("Script is running and cannot be edited")
    try:
        steps = json.loads(steps_text)
    except json.JSONDecodeError as e:
        raise ScriptError(f"Not valid JSON (line {e.lineno}, column {e.colno}): {e.msg}") from None
    if isinstance(steps, dict) and "steps" in steps:
        steps = steps["steps"]
    if isinstance(steps, list):
        steps = [{**st, "params": normalize_params(st["service"], st["operation"], st["params"])}
                 if isinstance(st, dict) and isinstance(st.get("params"), dict) and "service" in st
                 and "operation" in st else st for st in steps]
    validate_steps(steps)
    notes = [ln[len("# NOTE: "):] for ln in (row["script_text"] or "").splitlines() if ln.startswith("# NOTE: ")]
    destructive = any(needs_confirmation(st) for st in steps)
    text = render_cli(steps, row["region"], notes + ["Edited manually by you."])
    _set(script_id, steps=json.dumps(steps), script_text=text, destructive=destructive, status="draft",
         approved_at=None, run_at=None, result="Edited by you. Review it and click Approve again.")
    audit.log_action(actor=owner, request=row["request"], tool_name=f"script#{script_id}",
                     tool_args={"title": row["title"], "steps": steps}, risk=row["risk"], approval="pending",
                     status="pending", result_summary="script edited manually; needs approval again")
    return get_script(owner, script_id)


_RUNNING: set[int] = set()
_running_lock = threading.Lock()


def _is_running(row: dict) -> bool:
    with _running_lock:
        return row["status"] == "running" and row["id"] in _RUNNING


def delete_script(owner: str, script_id: int) -> None:
    """Deletes only the script (and its history), never anything in AWS."""
    row = get_script(owner, script_id)
    if _is_running(row):
        raise ScriptError("Script is running and cannot be deleted")
    db.execute("DELETE FROM scripts WHERE id = %s AND owner = %s", (script_id, owner))
    audit.log_action(actor=owner, request=row["request"], tool_name=f"script#{script_id}",
                     tool_args={"title": row["title"], "status": row["status"]}, risk=row["risk"],
                     approval="not_required", status="success", result_summary="script deleted by user")


def delete_scripts(owner: str, script_ids: list[int]) -> dict:
    """Delete several scripts. Running ones are skipped. Returns {'deleted': [...], 'skipped': [...]}"""
    deleted, skipped = [], []
    for sid in script_ids:
        try:
            delete_script(owner, int(sid))
            deleted.append(int(sid))
        except ScriptError:
            skipped.append(int(sid))
    return {"deleted": deleted, "skipped": skipped}


def delete_unapproved(owner: str) -> dict:
    """Delete every script that is still waiting for review or was denied."""
    ids = [r["id"] for r in db.fetch_all(
        "SELECT id FROM scripts WHERE owner = %s AND status IN ('draft', 'denied')", (owner,))]
    return delete_scripts(owner, ids)


def recover_stale(owner: str) -> int:
    """At startup: scripts left 'running' by a closed or crashed app are marked failed (they can be re-run)."""
    with _running_lock:
        active = list(_RUNNING) or [0]
    with db.cursor() as cur:
        cur.execute("""UPDATE scripts SET status = 'failed',
                         result = COALESCE(result || E'\\n', '') || 'Interrupted: Kintsugi was closed while this script was running. Check AWS before running it again.'
                       WHERE owner = %s AND status = 'running' AND NOT (id = ANY(%s))""", (owner, active))
        return cur.rowcount


def _check_guard(conn, step: dict) -> None:
    g = step.get("guard") or {}
    if tag := g.get("ec2_tag"):
        ec2 = conn.client("ec2", "read", step.get("region"))
        res = ec2.describe_instances(InstanceIds=[tag["instance_id"]])["Reservations"]
        tags = {t["Key"]: t["Value"] for r in res for i in r["Instances"] for t in i.get("Tags", [])}
        if tags.get(tag["key"]) != tag["value"]:
            raise ScriptError(f"{tag['instance_id']} is not tagged {tag['key']}={tag['value']}; nothing was changed")


def _error_text(e: Exception) -> str:
    if isinstance(e, ClientError):
        code = e.response["Error"].get("Code", "Error")
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            return f"{code}: your Write connection is not allowed to do this (IAM denied it)"
        return f"{code}: {e.response['Error'].get('Message', '')[:200]}"
    return f"{type(e).__name__}: {str(e)[:200]}"


_PLACEHOLDER_RE = re.compile(r"\{\{\s*([\w.]+)\s*\}\}")


def _lookup(outputs: dict, path: str):
    """'vpc.Vpc.VpcId' or 'inst.Instances.0.InstanceId' -> value from earlier step outputs."""
    cur = outputs
    for part in path.split("."):
        if isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        elif isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            raise ScriptError(f"value {{{{{path}}}}} is not available (the step that creates it did not run)")
    return cur


def resolve(value, outputs: dict):
    """Replace {{name.Path}} placeholders with values captured from earlier steps."""
    if isinstance(value, dict):
        return {k: resolve(v, outputs) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve(v, outputs) for v in value]
    if isinstance(value, str) and "{{" in value:
        whole = _PLACEHOLDER_RE.fullmatch(value.strip())
        if whole:
            return _lookup(outputs, whole.group(1))
        return _PLACEHOLDER_RE.sub(lambda m: str(_lookup(outputs, m.group(1))), value)
    return value


def has_placeholders(value) -> bool:
    return "{{" in json.dumps(value, default=str)


def _main_id(resp: dict) -> str:
    """First '...Id' value in a create response, for the run log (e.g. vpc-0abc)."""
    queue = [resp]
    while queue:
        cur = queue.pop(0)
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k.endswith("Id") and isinstance(v, str) and k not in ("OwnerId", "RequesterId"):
                    return v
            queue.extend(v for v in cur.values() if isinstance(v, (dict, list)))
        elif isinstance(cur, list):
            queue.extend(cur)
    return ""


def _wait(client, wait: dict, outputs: dict):
    waiter = client.get_waiter(wait["waiter"])
    waiter.wait(**resolve(wait.get("params", {}), outputs),
                WaiterConfig={"Delay": wait.get("delay", 15), "MaxAttempts": wait.get("max_attempts", 40)})


def _save_teardown(owner: str, row: dict, done: list[dict], outputs: dict) -> dict | None:
    """Undo steps of everything that was created, newest first, with the real IDs filled in."""
    undo_steps = []
    for st in reversed(done):
        u = st.get("undo")
        if not u:
            continue
        try:
            desc = u.get("description") or f"Undo: {st.get('description', '')}"
            if local_steps.kind_of(u) != "aws":
                step = {**resolve({k: v for k, v in u.items() if k != "description"}, outputs), "description": desc}
                if st.get("region") and "region" not in step:
                    step["region"] = st["region"]
                undo_steps.append(step)
                continue
            step = {"service": u["service"], "operation": u["operation"],
                    "params": resolve(u.get("params", {}), outputs),
                    "region": st.get("region") or row["region"], "description": desc}
            if u.get("wait"):
                step["wait"] = {**u["wait"], "params": resolve(u["wait"].get("params", {}), outputs)}
            if u.get("pause_after"):
                step["pause_after"] = u["pause_after"]
            undo_steps.append(step)
        except ScriptError:
            continue
    if not undo_steps:
        return None
    draft = ScriptDraft(title=f"Teardown of script #{row['id']}: {row['title']}"[:200], steps=undo_steps,
                        risk=row["risk"], region=row["region"],
                        notes=[f"Deletes the resources created by script #{row['id']}, newest first."])
    return save_draft(owner, f"teardown of script #{row['id']}", draft)


def step_name(step: dict) -> str:
    kind = local_steps.kind_of(step)
    if kind == "aws":
        return f"{step['service']}.{step['operation']}"
    if kind == "command":
        return f"{step['tool']} {local_steps._subcommand(step)}".strip()
    return kind if kind != "check" else f"check:{step.get('check')}"


def _audit_args(step: dict, params) -> dict:
    if local_steps.kind_of(step) == "aws":
        return params
    return {k: v for k, v in step.items() if k not in ("undo", "ssh_key_path")}


def _dry_run_step(step: dict, client, params) -> tuple[str, bool]:
    """Returns (log text, whether something was actually checked)."""
    if local_steps.kind_of(step) != "aws":
        missing = [t for t in sorted(local_steps.tools_needed(step)) if not local_steps.which(t)]
        if missing:
            raise ScriptError(f"not installed: {', '.join(missing)}. "
                              + " ".join(local_steps.INSTALL_HINT.get(t, "") for t in missing))
        return "local step: required tools are installed (not run in a dry run)", True
    if not supports_dry_run(step):
        return "dry run not supported for this API (skipped)", False
    try:
        getattr(client, step["operation"])(**params, DryRun=True)
        return "dry run OK", True
    except ClientError as e:
        if e.response["Error"].get("Code") == "DryRunOperation":
            return "dry run OK (would succeed)", True
        raise


def run_script(owner: str, script_id: int, conn, typed_confirmation: str = "", *, dry_run: bool = False,
               _scheduled: bool = False, progress=None) -> dict:
    """Run every step in order with the identity for the script's risk; stop at the first failure.
    IDs created by earlier steps fill {{placeholders}} in later ones. After a real run that created
    anything, a teardown script is saved (also after a partial failure, so the user can clean up).
    progress(line) receives live log lines (local tool output, waits) while it runs."""
    row = get_script(owner, script_id)
    if not _scheduled:
        if _is_running(row):
            raise ScriptError("Script is already running")
        if not dry_run:
            if row["status"] not in RUNNABLE:
                raise ScriptError(_not_runnable(row))
            _check_confirmation(row, typed_confirmation)
    purpose = "operate" if row["risk"] == "operate" else "deploy"
    steps = row["steps"] if isinstance(row["steps"], list) else json.loads(row["steps"])
    if not dry_run:
        _set(script_id, status="running")
        with _running_lock:
            _RUNNING.add(script_id)
    say = progress or (lambda _line: None)
    log, ok, checked = [], True, 0
    outputs: dict = {}
    done: list[dict] = []
    try:
        for n, step in enumerate(steps, 1):
            desc = step.get("description") or step_name(step)
            region = step.get("region") or row["region"]
            kind = local_steps.kind_of(step)
            try:
                body = {k: v for k, v in step.items() if k not in ("undo", "save_as", "description")}
                if dry_run and has_placeholders(body) and kind == "aws":
                    log.append(f"Step {n} {desc}: uses a resource created by an earlier step (skipped in dry run)")
                    continue
                if dry_run and kind != "aws":
                    text, did = _dry_run_step(step, None, None)
                    log.append(f"Step {n} {desc}: {text}")
                    checked += did
                    continue
                say(f"Step {n}/{len(steps)}: {desc}")
                if kind != "aws":
                    real = {**resolve({k: v for k, v in step.items() if k != "undo"}, outputs)}
                    validate_step(real)
                    res = local_steps.run(real, conn, purpose, region, progress=say)
                    if step.get("save_as"):
                        outputs[step["save_as"]] = res["output"]
                    done.append(step)
                    summary = res["summary"]
                    params = None
                else:
                    params = resolve(step.get("params", {}), outputs)
                    real = {**step, "params": params}
                    validate_step(real)
                    _check_guard(conn, real)
                    client = conn.client(step["service"], purpose, region)
                    if dry_run:
                        text, did = _dry_run_step(step, client, params)
                        log.append(f"Step {n} {desc}: {text}")
                        checked += did
                        continue
                    resp = getattr(client, step["operation"])(**load_files(params))
                    resp.pop("ResponseMetadata", None)
                    if step.get("save_as"):
                        outputs[step["save_as"]] = resp
                    done.append(step)
                    if step.get("wait"):
                        say(f"  waiting ({step['wait']['waiter']})...")
                        _wait(client, step["wait"], outputs)
                    summary = _main_id(resp) or json.dumps(audit.redact(resp), default=str)[:200]
                if step.get("pause_after"):
                    say(f"  pausing {step['pause_after']} s so AWS can propagate the change...")
                    time.sleep(step["pause_after"])
                log.append(f"Step {n} {desc}: OK {summary}")
                say(f"  ok: {summary}")
                audit.log_action(actor=owner, request=row["request"], tool_name=step_name(step),
                                 tool_args=_audit_args(step, params), risk=row["risk"], approval="approved",
                                 status="success", result_summary=f"script #{script_id} step {n}: {summary}")
            except Exception as e:
                ok = False
                msg = str(e) if isinstance(e, (ScriptError, StepError)) else _error_text(e)
                log.append(f"Step {n} {desc}: FAILED {msg}")
                say(f"  FAILED: {msg}")
                if not dry_run:
                    audit.log_action(actor=owner, request=row["request"], tool_name=step_name(step),
                                     tool_args=_audit_args(step, step.get("params")), risk=row["risk"],
                                     approval="approved", status="failed",
                                     result_summary=f"script #{script_id} step {n}: {msg}"[:1000])
                break
    finally:
        with _running_lock:
            _RUNNING.discard(script_id)
    if dry_run and ok and checked == 0:
        ok = None
        log.append("This AWS API has no dry-run mode, so nothing was checked. Review the script and use Run now.")
    teardown = None
    if not dry_run and done:
        try:
            teardown = _save_teardown(owner, row, done, outputs)
        except Exception as e:
            log.append(f"Could not save a teardown script: {_error_text(e)}")
        if teardown:
            after_failure = " (run it to clean up after the failure)" if not ok else ""
            log.append(f"Teardown script #{teardown['id']} saved: it deletes everything this run created"
                       f"{after_failure}.")
    result = "\n".join(log)
    if not dry_run:
        _set(script_id, status="succeeded" if ok else "failed", last_run_at=datetime.now(timezone.utc),
             result=result)
    return {"ok": ok, "dry_run": dry_run, "log": result, "teardown": teardown}


def claim_due_scripts(owner: str, now: datetime | None = None) -> list[int]:
    """Atomically move due scheduled scripts to 'running' so each runs exactly once."""
    now = now or datetime.now(timezone.utc)
    with db.cursor() as cur:
        cur.execute(
            """UPDATE scripts SET status = 'running'
               WHERE owner = %s AND status = 'scheduled' AND run_at <= %s RETURNING id""", (owner, now))
        return [r[0] for r in cur.fetchall()]


def run_due_scripts(owner: str, conn) -> list[dict]:
    """Called every 30 s by the GUI timer. Scheduled scripts only run while the app is open."""
    out = []
    for sid in claim_due_scripts(owner):
        try:
            res = run_script(owner, sid, conn, _scheduled=True)
        except Exception as e:
            _set(sid, status="failed", result=str(e)[:500], last_run_at=datetime.now(timezone.utc))
            res = {"ok": False, "log": str(e)}
        out.append({"id": sid, **res})
    return out
