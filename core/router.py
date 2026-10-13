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


_PATH_RE = re.compile(r"""["']([A-Za-z]:\\[^"']+)["']|([A-Za-z]:\\[^\s"',]+)""")
PATH_FIELD = {"lambda_function": "source_folder", "docker_image": "app_folder", "ecs_fargate_service": "app_folder",
              "eks_cluster": "app_folder", "ansible_website": "folder", "ansible_playbook": "folder",
              "terraform_project": "folder", "s3_upload": "source", "glacier_vault": "file",
              "s3_static_website": "source"}
_BUCKET_RE = re.compile(r"\b(?:bucket|s3://)\s*(?:named\s+|called\s+)?['\"]?([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])", re.I)
_BUCKET_STOP = {"named", "called", "the", "my", "a", "an", "in", "to", "and"}


def extract_path(text: str) -> str | None:
    r"""A Windows path like D:\work\mysite or "D:\my folder\site" from the request."""
    m = _PATH_RE.search(text or "")
    return (m.group(1) or m.group(2)).rstrip(".?!") if m else None


def extract_bucket(text: str) -> str | None:
    for m in _BUCKET_RE.finditer(text or ""):
        if m.group(1).lower() not in _BUCKET_STOP:
            return m.group(1).lower()
    return None


def _cloud_provider(t: str) -> str | None:
    if _has(t, "azure"):
        return "azure"
    if _has(t, "gcp", "google cloud", "gcs"):
        return "gcp"
    return None


def _recipe_for(t: str) -> str | None:
    """Most specific first: the recipe a build/deploy request is about."""
    if _has(t, "s3", "bucket") and (_has(t, "website", "web site", "static site", "web app", "webapp", "web application",
                                         "index.html", "public access", "public bucket")
                                    or _has_word(t, "host", "hosting", "public")):
        return "s3_static_website"
    if _has(t, "cloudfront", "cdn", "distribution", "invalidat"):
        return "cloudfront_distribution"
    if _has(t, "glacier vault", "vault") and not _has(t, "secret"):
        return "glacier_vault"
    if _has(t, "s3", "bucket") and _has(t, "lifecycle", "versioning", "replicat", "object lock", "cors",
                                         "encryption", "inventory", "event notification", "after 30 days",
                                         "after 60 days", "after 90 days", "after 180 days", "after 365 days"):
        return "s3_bucket"
    if _has(t, "restore") and _has(t, "glacier", "archive", "deep archive") or \
            _has(t, "s3", "bucket", "objects", "files") and _has(t, "storage class", "to glacier", "to deep archive",
                                                                   "archive them", "archive the"):
        return "s3_objects"
    if _has(t, "s3", "bucket") and _has_word(t, "upload", "put", "store", "copy", "save", "send", "move", "add"):
        return "s3_upload"
    if _has(t, "s3 bucket", "bucket") and _has_word(t, "create", "make", "new"):
        return "s3_bucket"
    if _has(t, "database", "rds", "dynamodb", "dynamo db", "aurora", "postgres", "mysql", "mariadb", "documentdb",
            "docdb", "mongodb", "redis", "valkey", "memcached", "elasticache", "db2", "oracle", "sql server", "sqlserver", "mssql")             or _has_word(t, "db"):
        return "database"
    if _has(t, "eks", "kubernetes", "k8s", "helm"):
        if _has(t, "node group", "nodegroup", "scale", "add-on", "addon", "upgrade", "existing cluster",
                "my cluster", "to the cluster", "on the cluster", "helm") and not _has_word(t, "new"):
            return "eks_manage"
        return "eks_cluster"
    if _has(t, "fargate", "ecs"):
        return "ecs_fargate_service"
    if _has(t, "auto scaling", "autoscaling", "auto-scaling", "asg", "scaling group", "scaling policy",
            "instance refresh"):
        return "auto_scaling_group"
    if _has(t, "launch template"):
        return "launch_template"
    if _has(t, "target group"):
        return "target_group"
    if _has(t, "load balancer", "loadbalancer", "alb", "nlb", "elb"):
        return "load_balancer"
    if _has(t, "ami", "machine image", "golden image"):
        return "ami"
    if _has(t, "ebs", "volume", "snapshot"):
        return "ebs_volume"
    if _has(t, "ecr", "repository", "registry") and not _has(t, "dockerfile", "docker image", "push"):
        return "ecr_repository"
    if _has(t, "jenkins"):
        return "jenkins_server"
    if _has(t, "terraform", ".tf "):
        return "terraform_project"
    if _has(t, "playbook"):
        return "ansible_playbook"
    if _has(t, "ansible", "website", "web site", "static site", "flask", "host the", "host it", "host my"):
        return "ansible_website"
    if _has(t, "ecr", "docker image", "dockerfile", "container image"):
        return "docker_image"
    if _has(t, "iam role", "role for", "execution role"):
        return "iam_role"
    if _has(t, "lambda", "function"):
        if _has(t, "alias", "version", "concurrency", "trigger", "memory", "timeout", "env var", "environment",
                "layer", "existing function", "delete") and not extract_path(t):
            return "lambda_manage"
        return "lambda_function"
    if _has(t, "security group", "firewall", "network acl", "nacl", "peering", "vpc endpoint", "endpoint",
            "flow log", "transit gateway", "elastic ip", "eip", "vpn", "prefix list", "dhcp", "egress-only") or \
            _has(t, "subnet", "route", "nat gateway", "internet gateway") and _has(t, "existing", "my vpc", "to the vpc",
                                                                                   "in vpc", "add a", "add an"):
        return "vpc_resource"
    if _has(t, "vpc", "subnet", "nat gateway", "internet gateway", "route table", "routing table"):
        return "vpc_network"
    if _has(t, "instance", "ec2", "server", "vm", "machine"):
        return "ec2_instance"
    return None


QUESTION_STARTS = ("what", "which", "when", "how many", "list", "show", "is ", "are ", "do i", "does", "where",
                   "who", "tell me", "get ")


def _is_question(t: str) -> bool:
    return t.strip().startswith(QUESTION_STARTS) or t.strip().endswith("?") and not _has_word(
        t, "create", "deploy", "build", "launch", "host")


def extract_after_time(text: str) -> str | None:
    m = _TIME_RE.search(text)
    return m.group(1).replace(" ", "") if m else None


def service_word(t: str) -> str | None:
    """The AWS service word in the text ('db2', 'neptune', 'redshift' ...), longest match first."""
    from core.prereqs import SERVICE_WORDS
    for word in sorted(SERVICE_WORDS, key=len, reverse=True):
        if re.search(r"\b" + re.escape(word) + r"\b", t):
            return word
    return None


def _no_recipe_service(word: str) -> bool:
    """'neptune graph database': the service (neptune) has no recipe even though 'database' matched one."""
    from core.prereqs import SERVICE_TEMPLATES, SERVICE_WORDS
    return SERVICE_WORDS[word] not in SERVICE_TEMPLATES


def _has(text: str, *words: str) -> bool:
    return any(re.search(r"\b" + re.escape(w), text) for w in words)


def _has_word(text: str, *words: str) -> bool:
    """Whole-word match, so an instance named 'stopped-demo' is not read as the verb 'stop'."""
    return any(re.search(r"(?<![\w-])" + re.escape(w) + r"(?![\w-])", text) for w in words)


def route(text: str, attachments: list[dict] | None = None) -> tuple[str, dict] | None:
    t = (text or "").lower()
    if not t.strip():
        return None

    if provider := _cloud_provider(t):
        if _has(t, "vm", "virtual machine", "instance", "server", "compute"):
            return "list_cloud_vms", {"provider": provider}
        if _has(t, "storage", "bucket", "blob", "container"):
            return "list_cloud_storage", {"provider": provider}
        return None

    if _has_word(t, "stop", "shut down", "shutdown", "turn off", "power off"):
        inst = extract_instance(text)
        if inst:
            return "stop_instance", {"instance": inst}
    if _has_word(t, "start", "turn on", "power on", "boot"):
        inst = extract_instance(text)
        if inst:
            return "start_instance", {"instance": inst}

    if _has(t, "prerequisite", "pre-requisite", "requirement", "what do i need", "what is needed", "what's needed",
            "what all is needed", "needed to", "need before", "need first"):
        if word := service_word(t):
            return "check_prerequisites", {"service": word}

    builds = _has_word(t, "create", "launch", "build", "provision", "make", "spin up", "set up", "setup", "deploy",
                       "need", "host", "install", "push", "apply", "upload", "add", "attach", "detach", "resize",
                       "scale", "share", "copy", "restore", "archive", "invalidate", "configure", "enable", "delete",
                       "remove", "release", "publish", "allocate", "snapshot", "upgrade", "change", "update", "move")
    uploads = _has_word(t, "upload", "put", "store", "copy", "save", "send", "move")
    if not _is_question(t) and (builds or uploads or attachments or
                                _has(t, "terraform", "ansible", "playbook", "dockerfile")):
        recipe = _recipe_for(t)
        word = service_word(t)
        if builds and word and (not recipe or _no_recipe_service(word)):
            return "check_prerequisites", {"service": word}
        if recipe:
            inputs = {}
            path = extract_path(text) or (attachments[0]["path"] if attachments else None)
            if path and recipe in PATH_FIELD:
                inputs[PATH_FIELD[recipe]] = path
            if recipe in ("s3_upload", "s3_static_website") and (bucket := extract_bucket(text)):
                inputs["bucket"] = bucket
            if recipe == "database":
                from core.recipes import engine_from_text
                if engine := engine_from_text(t):
                    inputs["engine"] = engine
            return "plan_task", {"template": recipe, "inputs": inputs}

    is_lambda = _has(t, "lambda", "function")
    if _has(t, "alb", "load balancer", "loadbalancer", "elb", "nlb") and not _has(t, "target group"):
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
    if _has(t, "rds", "database", "db instance"):
        return "list_rds_instances", {}
    if _has(t, "instance", "ec2", "server", "vm", "machine"):
        for state in ("running", "stopped"):
            if state in t:
                return "list_ec2_instances", {"state": state}
        return "list_ec2_instances", {}
    if is_lambda:
        return "list_lambda_functions", {}
    if _has(t, "s3", "bucket"):
        if (bucket := extract_bucket(text)) and _has(t, "in ", "inside", "files", "objects", "contents", "list"):
            return "list_s3_objects", {"bucket": bucket}
        return "list_s3_buckets", {}
    return None
