"""Scripts: every write request becomes a reviewable script (Scripts page) that runs only when the user
clicks Run now, or at a time the user scheduled.

A script is a list of typed AWS steps {service, operation, params, description, guard?}. The LLM never
writes free-form code: it picks a typed tool, this module validates every step against the botocore API
model and the write policy, and renders an equivalent AWS CLI script for human review. Execution is done
by code with the identity chosen from the script's risk tier.
"""
import json
import re
import threading
from functools import lru_cache
from dataclasses import dataclass, field
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError, ParamValidationError
from botocore.validate import validate_parameters

from core import audit, db
from core.config import settings

# ---- write policy ----------------------------------------------------------------------

READ_PREFIXES = ("list_", "describe_", "get_")
# Sensitive services: the app never changes access, accounts or billing (IAM stays with the human).
BLOCKED_WRITE_SERVICES = {"iam", "organizations", "account", "billing", "sts", "sso", "sso-admin",
                          "identitystore", "controltower", "budgets", "ce"}
BLOCKED_WRITE_OPERATIONS = {
    # turning off audit / security tooling
    ("cloudtrail", "stop_logging"), ("cloudtrail", "delete_trail"), ("cloudtrail", "update_trail"),
    ("guardduty", "delete_detector"), ("config", "stop_configuration_recorder"),
    ("config", "delete_configuration_recorder"), ("securityhub", "disable_security_hub"),
    # making S3 data public
    ("s3", "put_bucket_acl"), ("s3", "put_object_acl"), ("s3", "put_bucket_policy"),
    ("s3", "delete_public_access_block"), ("s3", "put_public_access_block"),
    # secrets
    ("secretsmanager", "get_secret_value"), ("kms", "schedule_key_deletion"), ("kms", "disable_key"),
}
DESTRUCTIVE_PREFIXES = ("delete_", "terminate_", "remove_", "deregister_", "purge_", "detach_",
                        "disassociate_", "revoke_", "cancel_", "release_", "disable_")


class ScriptError(Exception):
    """Safe-to-display error."""


def is_destructive(operation: str) -> bool:
    return operation.startswith(DESTRUCTIVE_PREFIXES)


def check_write_allowed(service: str, operation: str, params: dict) -> None:
    if not re.fullmatch(r"[a-z0-9-]+", service or "") or not re.fullmatch(r"[a-z0-9_]+", operation or ""):
        raise ScriptError("service/operation must be boto3 names like 'ec2' and 'stop_instances'")
    if operation.startswith(READ_PREFIXES):
        raise ScriptError(f"{operation} is a read; ask it as a question in chat instead")
    if service in BLOCKED_WRITE_SERVICES:
        raise ScriptError(f"Changes to '{service}' (access, accounts, billing) are blocked; do them yourself "
                          f"in the AWS console.")
    if (service, operation) in BLOCKED_WRITE_OPERATIONS:
        raise ScriptError(f"{service}.{operation} is blocked by the app's safety policy")
    if service == "ec2" and operation == "authorize_security_group_ingress":
        _check_no_open_ssh(params)


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


# Example IDs a language model invents (vpc-12345678, subnet-xxxxxxxx, sg-0123456789abcdef0 ...)
_FAKE_ID_RE = re.compile(r"\b(?:vpc|subnet|sg|igw|nat|rtb|eipalloc|i|ami|vol|snap|eni|acl|lt)-"
                         r"(?:12345678\w*|0123456789abcdef\w*|x{4,}\w*|0{8,}|abcdef\w*|example\w*)\b", re.I)


def check_no_fake_ids(params) -> None:
    for m in _FAKE_ID_RE.finditer(json.dumps(params, default=str)):
        raise ScriptError(f"'{m.group(0)}' looks like a made-up example ID, not a real resource. Ask a question "
                          f"to find the real ID, or use a task template so the app asks you.")


def validate_step(step: dict) -> None:
    """Policy + botocore model validation (rejects made-up operations, parameters and example IDs)."""
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
        validate_parameters(params, shape) if shape else None
    except ParamValidationError as e:
        raise ScriptError(f"Invalid parameters for {service}.{op}: {str(e)[:300]}") from None


def supports_dry_run(step: dict) -> bool:
    try:
        client = _model_client(step["service"])
        api = client.meta.method_to_api_mapping[step["operation"]]
        shape = client.meta.service_model.operation_model(api).input_shape
        return bool(shape and "DryRun" in shape.members)
    except Exception:
        return False


# ---- AWS CLI rendering (for human review) ------------------------------------------------

def _kebab(name: str) -> str:
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "-", name)
    s = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "-", s)
    return s.replace("_", "-").lower()


def _cli_value(v) -> str:
    if isinstance(v, bool):
        return ""  # rendered as a flag
    if isinstance(v, (int, float)):
        return str(v)
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
    lines = ["# Equivalent AWS CLI commands (for review). CloudAI runs these steps itself with boto3",
             "# using your 'Write' connection, only when you click Run now or at the scheduled time."]
    if any("{{" in json.dumps(s.get("params", {})) for s in steps):
        lines.append("# Values like {{vpc.Vpc.VpcId}} are IDs created by an earlier step, filled in while running.")
    if any(s.get("undo") for s in steps):
        lines.append("# After running (or if a step fails) CloudAI saves a teardown script that deletes what was created.")
    for note in notes or []:
        lines.append(f"# NOTE: {note}")
    lines.append("")
    for n, s in enumerate(steps, 1):
        lines.append(f"# Step {n}: {s.get('description', '')}")
        if g := s.get("guard"):
            lines.append(f"# Safety check before running: {g.get('text', '')}")
        lines.append(_cli_command(s, region))
        if w := s.get("wait"):
            lines.append(_cli_command({"service": s["service"], "operation": "wait_" + w["waiter"],
                                       "params": w.get("params", {}), "region": s.get("region")}, region)
                         .replace(f"aws {s['service']} wait-", f"aws {s['service']} wait ", 1))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---- drafts, storage -------------------------------------------------------------------

@dataclass
class ScriptDraft:
    title: str
    steps: list[dict]
    risk: str = "operate"
    region: str = field(default_factory=lambda: settings.aws_region)
    notes: list[str] = field(default_factory=list)   # cost warnings etc., shown at the top of the script

    @property
    def destructive(self) -> bool:
        return any(is_destructive(s["operation"]) for s in self.steps)


def confirm_phrase(script_id: int) -> str:
    return f"run script {script_id}"


STEP_KEYS = {"service", "operation", "params", "description", "region", "save_as", "wait", "undo", "guard"}
RUNNABLE = ("approved", "failed")          # a script runs only after the user approved it
STATUS_TEXT = {"draft": "waiting for your review", "approved": "approved", "denied": "denied",
               "scheduled": "scheduled", "running": "running", "succeeded": "succeeded", "failed": "failed"}


def validate_steps(steps: list[dict]) -> None:
    """Every step: policy + botocore model + fake-ID check; undo actions: policy; placeholders must refer to
    a 'save_as' name of an EARLIER step."""
    if not isinstance(steps, list) or not steps:
        raise ScriptError("A script needs at least one step")
    defined: set[str] = set()
    for n, st in enumerate(steps, 1):
        if not isinstance(st, dict) or not {"service", "operation"} <= set(st):
            raise ScriptError(f"Step {n} needs at least 'service' and 'operation'")
        extra = set(st) - STEP_KEYS
        if extra:
            raise ScriptError(f"Step {n} has unknown field(s): {', '.join(sorted(extra))}")
        if not isinstance(st.get("params", {}), dict):
            raise ScriptError(f"Step {n}: 'params' must be an object")
        for ref in _PLACEHOLDER_RE.findall(json.dumps(st.get("params", {}))):
            if ref.split(".")[0] not in defined:
                raise ScriptError(f"Step {n} uses {{{{{ref}}}}} but no earlier step has save_as '{ref.split('.')[0]}'")
        try:
            validate_step(st)
        except ScriptError as e:
            raise ScriptError(f"Step {n}: {e}") from None
        if st.get("undo"):
            u = st["undo"]
            check_write_allowed(u.get("service", ""), u.get("operation", ""), u.get("params", {}))
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
    validate_steps(steps)
    notes = [ln[len("# NOTE: "):] for ln in (row["script_text"] or "").splitlines() if ln.startswith("# NOTE: ")]
    destructive = any(is_destructive(st["operation"]) for st in steps)
    text = render_cli(steps, row["region"], notes + ["Edited manually by you."])
    _set(script_id, steps=json.dumps(steps), script_text=text, destructive=destructive, status="draft",
         approved_at=None, run_at=None, result="Edited by you. Review it and click Approve again.")
    audit.log_action(actor=owner, request=row["request"], tool_name=f"script#{script_id}",
                     tool_args={"title": row["title"], "steps": steps}, risk=row["risk"], approval="pending",
                     status="pending", result_summary="script edited manually; needs approval again")
    return get_script(owner, script_id)


def delete_script(owner: str, script_id: int) -> None:
    row = get_script(owner, script_id)
    if row["status"] == "running":
        raise ScriptError("Script is running and cannot be deleted")
    db.execute("DELETE FROM scripts WHERE id = %s AND owner = %s", (script_id, owner))


# ---- execution ---------------------------------------------------------------------------

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
            step = {"service": u["service"], "operation": u["operation"],
                    "params": resolve(u.get("params", {}), outputs),
                    "region": st.get("region") or row["region"],
                    "description": u.get("description") or f"Undo: {st.get('description', '')}"}
            if u.get("wait"):
                step["wait"] = {**u["wait"], "params": resolve(u["wait"].get("params", {}), outputs)}
            undo_steps.append(step)
        except ScriptError:
            continue
    if not undo_steps:
        return None
    draft = ScriptDraft(title=f"Teardown of script #{row['id']}: {row['title']}"[:200], steps=undo_steps,
                        risk=row["risk"], region=row["region"],
                        notes=[f"Deletes the resources created by script #{row['id']}, newest first."])
    return save_draft(owner, f"teardown of script #{row['id']}", draft)


def run_script(owner: str, script_id: int, conn, typed_confirmation: str = "", *, dry_run: bool = False,
               _scheduled: bool = False) -> dict:
    """Run every step in order with the identity for the script's risk; stop at the first failure.
    IDs created by earlier steps fill {{placeholders}} in later ones. After a real run that created
    anything, a teardown script is saved (also after a partial failure, so the user can clean up)."""
    row = get_script(owner, script_id)
    if not _scheduled:
        if row["status"] == "running":
            raise ScriptError("Script is already running")
        if not dry_run:
            if row["status"] not in RUNNABLE:
                raise ScriptError(_not_runnable(row))
            _check_confirmation(row, typed_confirmation)
    purpose = "operate" if row["risk"] == "operate" else "deploy"
    steps = row["steps"] if isinstance(row["steps"], list) else json.loads(row["steps"])
    if not dry_run:
        _set(script_id, status="running")
    log, ok, checked = [], True, 0
    outputs: dict = {}
    done: list[dict] = []
    for n, step in enumerate(steps, 1):
        desc = step.get("description") or f"{step['service']}.{step['operation']}"
        try:
            if dry_run and has_placeholders(step.get("params", {})):
                log.append(f"Step {n} {desc}: uses a resource created by an earlier step (skipped in dry run)")
                continue
            params = resolve(step.get("params", {}), outputs)
            real = {**step, "params": params}
            validate_step(real)
            _check_guard(conn, real)
            client = conn.client(step["service"], purpose, step.get("region") or row["region"])
            if dry_run:
                if not supports_dry_run(step):
                    log.append(f"Step {n} {desc}: dry run not supported for this API (skipped)")
                    continue
                try:
                    getattr(client, step["operation"])(**params, DryRun=True)
                    log.append(f"Step {n} {desc}: dry run OK")
                except ClientError as e:
                    if e.response["Error"].get("Code") == "DryRunOperation":
                        log.append(f"Step {n} {desc}: dry run OK (would succeed)")
                    else:
                        raise
                checked += 1
                continue
            resp = getattr(client, step["operation"])(**params)
            resp.pop("ResponseMetadata", None)
            if step.get("save_as"):
                outputs[step["save_as"]] = resp
            done.append(step)
            if step.get("wait"):
                _wait(client, step["wait"], outputs)
            rid = _main_id(resp)
            summary = rid or json.dumps(audit.redact(resp), default=str)[:200]
            log.append(f"Step {n} {desc}: OK {summary}")
            audit.log_action(actor=owner, request=row["request"], tool_name=f"{step['service']}.{step['operation']}",
                             tool_args=params, risk=row["risk"], approval="approved",
                             status="success", result_summary=f"script #{script_id} step {n}: {summary}")
        except Exception as e:
            ok = False
            msg = str(e) if isinstance(e, ScriptError) else _error_text(e)
            log.append(f"Step {n} {desc}: FAILED {msg}")
            if not dry_run:
                audit.log_action(actor=owner, request=row["request"],
                                 tool_name=f"{step['service']}.{step['operation']}", tool_args=step.get("params"),
                                 risk=row["risk"], approval="approved", status="failed",
                                 result_summary=f"script #{script_id} step {n}: {msg}")
            break
    if dry_run and ok and checked == 0:
        ok = None  # nothing could be checked: neither a pass nor a failure
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
