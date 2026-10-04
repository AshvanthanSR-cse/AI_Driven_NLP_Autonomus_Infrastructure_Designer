"""Find Lambda functions triggered on a schedule (Acceptance test 1).

Schedules are NOT stored in Lambda. They live in:
  - EventBridge rules (events): ScheduleExpression is always UTC
  - EventBridge Scheduler (scheduler): own ScheduleExpressionTimezone
All time math is done here in code; the LLM only formats the returned rows.
"""
import json
from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

from core.cron import AwsCron, CronError, describe_rate, expression_kind, now_utc, parse_at

LOOKAHEAD_DAYS = 7
MAX_RUNS_SHOWN = 3


def function_name_from_arn(arn: str) -> str | None:
    """arn:aws:lambda:region:acct:function:name[:alias] -> name. None if not a Lambda function ARN."""
    if not arn or ":function:" not in arn:
        return None
    return arn.split(":function:", 1)[1].split(":", 1)[0] or None


def _paginate(client, op: str, key: str, **kwargs) -> list:
    if client.can_paginate(op):
        items = []
        for page in client.get_paginator(op).paginate(**kwargs):
            items.extend(page.get(key, []))
        return items
    items, token = [], None
    while True:
        resp = getattr(client, op)(**kwargs, **({"NextToken": token} if token else {}))
        items.extend(resp.get(key, []))
        token = resp.get("NextToken")
        if not token:
            return items


def _scheduler_target_function(target: dict) -> str | None:
    arn = target.get("Arn", "")
    name = function_name_from_arn(arn)
    if name:
        return name
    # Universal target: arn:aws:scheduler:::aws-sdk:lambda:invoke with FunctionName in Input
    if arn.endswith(":aws-sdk:lambda:invoke"):
        try:
            fn = json.loads(target.get("Input") or "{}").get("FunctionName", "")
            return function_name_from_arn(fn) or fn or None
        except (ValueError, AttributeError):
            return None
    return None


def collect_schedules(events_client, scheduler_client) -> tuple[list[dict], list[str]]:
    """Return (raw schedule entries targeting Lambda, warnings). Either client may be None."""
    entries, warnings = [], []

    if events_client is not None:
        try:
            for bus_rule in _paginate(events_client, "list_rules", "Rules"):
                expr = bus_rule.get("ScheduleExpression")
                if not expr:
                    continue  # event-pattern rule, not a schedule
                targets = _paginate(events_client, "list_targets_by_rule", "Targets", Rule=bus_rule["Name"],
                                    **({"EventBusName": bus_rule["EventBusName"]} if bus_rule.get("EventBusName") else {}))
                for t in targets:
                    fn = function_name_from_arn(t.get("Arn", ""))
                    if fn:
                        entries.append({
                            "function_name": fn, "source": f"EventBridge rule '{bus_rule['Name']}'",
                            "expression": expr, "timezone": "UTC", "state": bus_rule.get("State", "ENABLED"),
                        })
        except Exception as e:
            warnings.append(f"Could not read EventBridge rules: {_err(e)}")

    if scheduler_client is not None:
        try:
            for s in _paginate(scheduler_client, "list_schedules", "Schedules"):
                detail = scheduler_client.get_schedule(Name=s["Name"], GroupName=s.get("GroupName", "default"))
                fn = _scheduler_target_function(detail.get("Target", {}))
                if fn:
                    entries.append({
                        "function_name": fn, "source": f"EventBridge Scheduler '{s['Name']}'",
                        "expression": detail.get("ScheduleExpression", ""),
                        "timezone": detail.get("ScheduleExpressionTimezone") or "UTC",
                        "state": detail.get("State", s.get("State", "ENABLED")),
                    })
        except Exception as e:
            warnings.append(f"Could not read EventBridge Scheduler: {_err(e)}")

    return entries, warnings


def _err(e: Exception) -> str:
    resp = getattr(e, "response", None)
    if isinstance(resp, dict):
        return resp.get("Error", {}).get("Code", type(e).__name__)
    return type(e).__name__


def parse_hhmm(value: str) -> time:
    value = (value or "00:00").strip().lower().replace(".", ":")
    pm = value.endswith("pm")
    am = value.endswith("am")
    value = value.rstrip("apm").strip()
    parts = value.split(":")
    h, m = int(parts[0]), int(parts[1]) if len(parts) > 1 and parts[1] else 0
    if pm and h < 12:
        h += 12
    if am and h == 12:
        h = 0
    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise ValueError(f"invalid time '{value}'")
    return time(h, m)


def scheduled_lambdas(entries: list[dict], after_time: str, user_tz: str, now: datetime | None = None) -> dict:
    """Compute next runs (user timezone) and filter to runs at or after `after_time` local time-of-day."""
    now = now or now_utc()
    zone = ZoneInfo(user_tz)
    cutoff = parse_hhmm(after_time)
    horizon = now + timedelta(days=LOOKAHEAD_DAYS)
    fmt = "%a %d %b %H:%M"

    matching, not_matching, rate_based, disabled, errors = [], [], [], [], []
    for e in entries:
        row = {k: e[k] for k in ("function_name", "source", "expression", "timezone", "state")}
        if str(e["state"]).upper() != "ENABLED":
            disabled.append(row)
            continue
        kind = expression_kind(e["expression"])
        try:
            if kind == "rate":
                row["frequency"] = describe_rate(e["expression"])
                rate_based.append(row)
                continue
            if kind == "cron":
                runs = AwsCron.parse(e["expression"]).next_runs(now, tz=e["timezone"], count=200, max_days=LOOKAHEAD_DAYS + 2)
            elif kind == "at":
                at = parse_at(e["expression"], e["timezone"])
                runs = [at] if at and at > now else []
            else:
                raise CronError(f"unsupported expression '{e['expression']}'")
        except (CronError, ValueError) as ex:
            row["error"] = str(ex)
            errors.append(row)
            continue
        local = [r.astimezone(zone) for r in runs if r <= horizon]
        after = [r for r in local if r.time() >= cutoff]
        row["next_runs_local"] = [r.strftime(fmt) for r in (after or local)[:MAX_RUNS_SHOWN]]
        row["local_times_of_day"] = sorted({r.strftime("%H:%M") for r in local})
        (matching if after else not_matching).append(row)

    return {
        "question": f"Lambda functions with scheduled runs at or after {cutoff.strftime('%H:%M')} ({user_tz})",
        "timezone": user_tz,
        "computed_at_local": now.astimezone(zone).strftime("%Y-%m-%d %H:%M"),
        "lookahead_days": LOOKAHEAD_DAYS,
        "runs_after_time": matching,
        "runs_only_before_time": not_matching,
        "rate_based_no_clock_time": rate_based,
        "disabled_will_not_run": disabled,
        "could_not_parse": errors,
        "notes": [
            "EventBridge rule cron expressions are evaluated in UTC; Scheduler uses its own timezone.",
            "All times were converted to " + user_tz + " by code.",
        ],
    }
