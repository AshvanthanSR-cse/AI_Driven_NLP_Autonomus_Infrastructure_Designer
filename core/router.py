"""Keyword fallback router so the demo never fails if the model picks a wrong tool (or LM Studio is down).

route(text) -> (tool_name, args) or None. Pure code, deterministic, unit-tested.
"""
import re

INSTANCE_ID_RE = re.compile(r"\bi-[0-9a-f]{8,17}\b")
_TIME_RE = re.compile(r"\b(?:after|from|past|later than)\s+(\d{1,2}(?::\d{2})?\s*(?:am|pm)?)", re.I)
_NAME_AFTER_INSTANCE_RE = re.compile(
    r"\b(?:instance|server|vm|machine)\s+(?:named\s+|called\s+)?['\"]?([A-Za-z0-9][\w.-]*)['\"]?", re.I)
_NAME_STOPWORDS = {"is", "are", "that", "which", "the", "a", "an", "please", "now", "and", "in", "on",
                   "with", "for", "named", "called", "running", "stopped", "state", "status", "list"}

SCHEDULE_WORDS = ("schedule", "scheduled", "cron", "runs at", "run at", "trigger", "triggered", "every day",
                  "every hour", "after 1", "after 2", "after 3", "after 4", "after 5", "after 6", "after 7",
                  "after 8", "after 9")

# Rules the model is overridden by when it picks a different read tool (known 14B failure modes).
STRONG_ROUTES = {"list_scheduled_lambdas"}


def extract_instance(text: str) -> str | None:
    if m := INSTANCE_ID_RE.search(text):
        return m.group(0)
    for m in _NAME_AFTER_INSTANCE_RE.finditer(text):
        name = m.group(1).rstrip(".?!,")
        if name.lower() not in _NAME_STOPWORDS:
            return name
    return None


_FUNCTION_NAME_RE = re.compile(
    r"\b(?:lambda|function)\s+(?:function\s+)?(?:named\s+|called\s+)?['\"]?([A-Za-z0-9][\w-]*)['\"]?", re.I)
_FN_STOPWORDS = _NAME_STOPWORDS | {"function", "functions", "code", "script", "scripts", "source", "lambda"}


def extract_function(text: str) -> str | None:
    for m in _FUNCTION_NAME_RE.finditer(text):
        name = m.group(1).rstrip(".?!,")
        if name.lower() not in _FN_STOPWORDS:
            return name
    return None


def extract_after_time(text: str) -> str | None:
    m = _TIME_RE.search(text)
    return m.group(1).replace(" ", "") if m else None


def _has(text: str, *words: str) -> bool:
    return any(re.search(r"\b" + re.escape(w), text) for w in words)


def _has_word(text: str, *words: str) -> bool:
    """Whole-word match, so an instance named 'stopped-demo' is not read as the verb 'stop'."""
    return any(re.search(r"(?<![\w-])" + re.escape(w) + r"(?![\w-])", text) for w in words)


def route(text: str) -> tuple[str, dict] | None:
    t = (text or "").lower()
    if not t.strip():
        return None

    # writes (still require approval later)
    if _has_word(t, "stop", "shut down", "shutdown", "turn off", "power off"):
        inst = extract_instance(text)
        if inst:
            return "stop_instance", {"instance": inst}
    if _has_word(t, "start", "turn on", "power on", "boot"):
        inst = extract_instance(text)
        if inst:
            return "start_instance", {"instance": inst}

    # building infrastructure -> task templates (the app then asks for the missing details)
    if _has_word(t, "create", "launch", "build", "provision", "make", "spin up", "set up", "setup", "deploy", "need"):
        if _has(t, "vpc", "subnet", "nat gateway", "internet gateway", "route table", "routing table"):
            return "plan_task", {"template": "vpc_network", "inputs": {}}
        if _has(t, "instance", "ec2", "server", "vm", "machine"):
            return "plan_task", {"template": "ec2_instance", "inputs": {}}

    is_lambda = _has(t, "lambda", "function")
    if _has(t, "alb", "load balancer", "loadbalancer", "elb", "nlb"):
        return "list_load_balancers", {}
    if is_lambda and _has(t, "extract", "download", "code", "script", "source"):
        fn = extract_function(text)
        if fn:
            return "download_lambda_code", {"function_name": fn}
    if any(w in t for w in SCHEDULE_WORDS) and (is_lambda or _has(t, "schedule", "cron", "trigger")):
        args = {}
        if after := extract_after_time(text):
            args["after_time"] = after
        else:
            args["after_time"] = "00:00"
        return "list_scheduled_lambdas", args

    if _has(t, "cpu", "utili", "load"):
        inst = extract_instance(text)
        if inst:
            return "get_ec2_cpu", {"instance": inst}
    if _has(t, "cost", "bill", "spend", "spent", "expense", "charge"):
        m = re.search(r"(\d{1,3})\s*days?", t)
        return "get_cost_by_service", {"days": int(m.group(1))} if m else {}
    if _has(t, "instance", "ec2", "server", "vm", "machine"):
        for state in ("running", "stopped"):
            if state in t:
                return "list_ec2_instances", {"state": state}
        return "list_ec2_instances", {}
    if is_lambda:
        return "list_lambda_functions", {}
    if _has(t, "s3", "bucket"):
        return "list_s3_buckets", {}
    if _has(t, "rds", "database", "db instance"):
        return "list_rds_instances", {}
    return None
