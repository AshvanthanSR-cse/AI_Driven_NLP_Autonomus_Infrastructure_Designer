"""Audit log. Every AI action is recorded; secrets are redacted; failures never crash the app."""
import json
import re
import sys

from core import db
from core.config import settings

_SECRET_KEY_RE = re.compile(
    r"(secret|password|passwd|token|private_?key|credential|session_?token|access_?key_?secret)", re.I
)
REDACTED = "***REDACTED***"


def redact(value):
    """Recursively replace values whose key looks secret. Safe for tool args and AWS responses."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and _SECRET_KEY_RE.search(k):
                out[k] = REDACTED
            elif k == "Variables" and isinstance(v, dict):
                out[k] = {name: REDACTED for name in v}
            else:
                out[k] = redact(v)
        return out
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def log_action(
    *,
    actor: str,
    request: str,
    tool_name: str,
    tool_args: dict | None,
    risk: str,
    approval: str,
    status: str,
    result_summary: str = "",
) -> int | None:
    """risk: read|operate|deploy  approval: not_required|pending|approved|rejected  status: success|failed|blocked|pending"""
    try:
        row_id = db.execute(
            """INSERT INTO audit_logs (actor, request, tool_name, tool_args, risk, approval, status, result_summary)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (
                actor,
                (request or "")[:2000],
                tool_name,
                json.dumps(redact(tool_args or {}), default=str),
                risk,
                approval,
                status,
                (result_summary or "")[:1000],
            ),
        )
    except Exception as e:
        print(f"[audit] could not write audit row: {type(e).__name__}", file=sys.stderr)
        return None
    prune(settings.audit_keep_last)
    return row_id


def prune(keep_last: int) -> None:
    """Delete all but the newest `keep_last` audit rows (0 or less = keep everything). Never raises."""
    if keep_last <= 0:
        return
    try:
        db.execute(
            """DELETE FROM audit_logs
               WHERE id NOT IN (SELECT id FROM audit_logs ORDER BY id DESC LIMIT %s)""",
            (keep_last,),
        )
    except Exception as e:
        print(f"[audit] could not prune old audit rows: {type(e).__name__}", file=sys.stderr)


def recent(limit: int = 200) -> list[dict]:
    return db.fetch_all(
        """SELECT id, ts, actor, request, tool_name, tool_args, risk, approval, status, result_summary
           FROM audit_logs ORDER BY id DESC LIMIT %s""",
        (limit,),
    )
