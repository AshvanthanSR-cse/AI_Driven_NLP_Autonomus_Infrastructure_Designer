"""Prerequisites: what must already exist (in the AWS account or on this computer) before something is built.

The app does not create prerequisites silently and the LLM never guesses them. Before a build, CODE makes a
checklist with read-only lookups:
    ready    - found in the account (the matching resources are listed)
    missing  - not found: the user must create it first; a required missing item BLOCKS the build
    created  - the app's script creates it (shown so the user knows what will appear)
    manual   - only a human can do or confirm it (licences, Marketplace subscriptions, quotas)
    provide  - a value the user must give (no lookup possible)
    unknown  - the lookup failed (e.g. no read permission); not blocking

Two sources:
1. Curated checklists for the app's recipes (database, EC2, ECS, EKS, Ansible ...), checked live.
2. ANY other AWS service: the botocore API model of its create_* operation. Required parameters that point
   at other resources (subnets, security groups, IAM roles, subnet groups, key pairs, certificates ...)
   become checklist items, and the well-known kinds are checked live.
"""
import html
import re
from dataclasses import asdict, dataclass, field

import boto3

from core.local_steps import INSTALL_HINT, which

STATUS_ICON = {"ready": "✅", "missing": "❌", "created": "🛠", "manual": "⚠️", "provide": "✏️", "unknown": "❔"}
STATUS_TEXT = {"ready": "you have it", "missing": "MISSING - create it first", "created": "the script creates it",
               "manual": "you must arrange/confirm this yourself", "provide": "you give this value",
               "unknown": "could not check"}
VPC_HOW = ("In chat: 'Create a VPC with 2 public and 2 private subnets' (approve and run that script), "
           "or create it in the AWS console: VPC -> Create VPC -> 'VPC and more'.")


class PrereqError(ValueError):
    pass


@dataclass
class PrereqItem:
    key: str
    title: str
    status: str
    why: str = ""
    how: str = ""
    found: list[str] = field(default_factory=list)
    required: bool = True


@dataclass
class PrereqReport:
    title: str
    items: list[PrereqItem]
    template: str | None = None
    inputs: dict = field(default_factory=dict)
    confirmed: list[str] = field(default_factory=list)
    service: str = ""
    operation: str = ""
    other_operations: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def missing(self) -> list[PrereqItem]:
        return [i for i in self.items if i.required and i.status == "missing"]

    @property
    def blocking(self) -> bool:
        return bool(self.missing)

    def to_dict(self) -> dict:
        return {"title": self.title, "items": [asdict(i) for i in self.items], "template": self.template,
                "inputs": self.inputs, "confirmed": self.confirmed, "service": self.service,
                "operation": self.operation, "other_operations": self.other_operations, "notes": self.notes,
                "blocking": self.blocking, "missing": [i.title for i in self.missing]}


def status_text(item: dict) -> str:
    if item["status"] == "missing" and not item["required"]:
        return "not found (optional: AWS uses a default when you leave it out)"
    return STATUS_TEXT[item["status"]]


def format_report(r: dict) -> str:
    """Markdown checklist, rendered by code (the chat card and the LLM both get exactly this)."""
    head = (f"Prerequisites for {r['title']}: {len(r['missing'])} MISSING. Nothing can be built until the user "
            f"creates them." if r["blocking"] else f"Prerequisites for {r['title']}: all required items are ready.")
    lines = [head]
    for n, i in enumerate(r["items"], 1):
        opt = "" if i["required"] else " (optional)"
        line = f"{n}. {STATUS_ICON[i['status']]} {i['title']}{opt}: {status_text(i)}"
        if i["found"]:
            line += " - found: " + ", ".join(i["found"][:5]) + (" ..." if len(i["found"]) > 5 else "")
        if i["why"]:
            line += f". Why: {i['why'].rstrip('.')}"
        if i["how"] and i["status"] in ("missing", "manual", "provide", "unknown"):
            line += f". How: {i['how']}"
        lines.append(line)
    lines += r.get("notes", [])
    return "\n".join(lines)


def _lookup(fn):
    try:
        return fn(), None
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
        return None, code


def _unknown(key, title, why, how, err, required: bool = True) -> PrereqItem:
    return PrereqItem(key, title, "unknown", why, f"{how} (lookup failed: {err})", required=required)


def subnets_item(env, min_azs: int = 2, public: bool = False, required: bool = True,
                 why: str = "AWS places it in your VPC, spread over availability zones (AZs).") -> PrereqItem:
    kind = "public " if public else ""
    title = f"VPC with {kind}subnets in {min_azs} different availability zones" if min_azs > 1 else \
        f"VPC with a {kind}subnet"
    subs, err = _lookup(env.subnets)
    if err:
        return _unknown("subnets", title, why, VPC_HOW, err, required)
    found = []
    for vpc in dict.fromkeys(s["vpc"] for s in subs):
        mine = [s for s in subs if s["vpc"] == vpc and (s["public"] or not public)]
        azs = sorted({s["az"] for s in mine})
        if len(azs) >= min_azs:
            name = next((s["vpc_name"] for s in mine if s["vpc_name"]), "") or vpc
            found.append(f"{name} ({len(mine)} {kind}subnets in {', '.join(azs)})")
    return PrereqItem("subnets", title, "ready" if found else "missing", why, VPC_HOW, found, required)


def vpc_item(env, required: bool = True) -> PrereqItem:
    title, why = "A VPC", "The resource is added to an existing VPC."
    subs, err = _lookup(env.subnets)
    if err:
        return _unknown("vpc", title, why, VPC_HOW, err, required)
    found = list(dict.fromkeys(s["vpc_name"] or s["vpc"] for s in subs))
    if not found:
        try:
            found = [v["VpcId"] for v in env.ec2().describe_vpcs().get("Vpcs", [])]
        except Exception:
            found = []
    return PrereqItem("vpc", title, "ready" if found else "missing", why, VPC_HOW, found, required)


def key_pair_item(env, required: bool = False) -> PrereqItem:
    title, why = "EC2 key pair (for SSH)", "Needed to log in with SSH."
    how = "EC2 console -> Key pairs -> Create key pair (download the .pem file and keep it safe)."
    keys, err = _lookup(env.key_pairs)
    if err:
        return _unknown("key_pair", title, why, how, err, required)
    return PrereqItem("key_pair", title, "ready" if keys else "missing", why, how, keys, required)


def tool_item(tool: str, why: str) -> PrereqItem:
    found = which(tool)
    return PrereqItem(f"tool_{tool}", f"{tool} installed on this computer", "ready" if found else "missing", why,
                      INSTALL_HINT.get(tool, f"Install {tool}."), [found] if found else [])


def instance_item(env) -> PrereqItem:
    title = "A running EC2 instance with a public IP"
    why, how = "The playbook connects to it over SSH.", "In chat: 'Launch an EC2 instance' (then run that script)."
    inst, err = _lookup(env.instances)
    if err:
        return _unknown("instance", title, why, how, err)
    found = [f"{i['name'] or i['id']} ({i['ip']})" for i in inst if i["ip"]]
    return PrereqItem("instance", title, "ready" if found else "missing", why, how, found)


def created(key: str, title: str, why: str = "") -> PrereqItem:
    return PrereqItem(key, title, "created", why)


def manual(key: str, title: str, why: str, how: str, required: bool = True) -> PrereqItem:
    return PrereqItem(key, title, "manual", why, how, required=required)


def db_parameter_groups(env, family_prefix: str) -> list[str]:
    rds = env.conn.client("rds", "read", env.region)
    out = []
    for page in rds.get_paginator("describe_db_parameter_groups").paginate():
        out += [g["DBParameterGroupName"] for g in page["DBParameterGroups"]
                if g.get("DBParameterGroupFamily", "").startswith(family_prefix)]
    return sorted(out)


DB2_LICENSE_HOW = ("Either (a) AWS Marketplace: subscribe to 'IBM Db2' (pay-as-you-go, hourly IBM fee), or (b) "
                   "your own IBM licence (BYOL): RDS console -> Parameter groups -> Create, family db2-se-11.5, then "
                   "set rds.ibm_customer_id and rds.ibm_site_id to your IBM Customer ID and Site ID.")


def db2_license_item(env, license_model: str | None) -> PrereqItem:
    title, why = "IBM Db2 licence", "RDS for Db2 needs an IBM licence (AWS does not include it)."
    if license_model == "marketplace-license":
        return manual("db2_license", "AWS Marketplace subscription to IBM Db2", why,
                      "AWS Marketplace -> search 'IBM Db2' -> Subscribe. Only a human can subscribe.")
    groups, err = _lookup(lambda: db_parameter_groups(env, "db2"))
    if err:
        return _unknown("db2_license", title, why, DB2_LICENSE_HOW, err)
    if license_model == "bring-your-own-license":
        return PrereqItem("db2_license", "Db2 parameter group with your IBM Customer ID and Site ID",
                          "ready" if groups else "missing", why, DB2_LICENSE_HOW, groups)
    return PrereqItem("db2_license", title, "ready" if groups else "manual", why, DB2_LICENSE_HOW, groups)


def _database_items(env, i: dict) -> list[PrereqItem] | None:
    from core.recipes import DB_ENGINES
    engine = i.get("engine")
    if engine not in DB_ENGINES:
        return None
    fam = DB_ENGINES[engine][1]
    if fam == "dynamodb":
        return [created("table", "DynamoDB table (serverless: no VPC, server or licence needed)")]
    public = i.get("access") == "my_ip"
    items = [subnets_item(env, 2, public=public,
                          why="RDS, DocumentDB and ElastiCache must be placed in subnets of at least 2 AZs.")]
    items.append(created("sg", "Security group that opens only the database port"))
    items.append(created("subnet_group", "Database subnet group (from the subnets you pick)"))
    if engine.startswith("db2"):
        items.append(db2_license_item(env, i.get("license_model")))
    elif engine.startswith("oracle") and i.get("license_model") == "bring-your-own-license":
        items.append(manual("oracle_license", "Your own Oracle licence (BYOL)", "You chose bring-your-own-license.",
                            "Make sure your Oracle licence covers RDS; or choose license-included instead."))
    if fam in ("rds", "aurora", "docdb"):
        items.append(created("password", "Master password (generated by AWS, kept in Secrets Manager)"))
    return items


def _template_items(template: str, env, i: dict) -> list[PrereqItem] | None:
    if template == "database":
        return _database_items(env, i)
    if template == "ec2_instance":
        return [subnets_item(env, 1, why="An instance is launched into a subnet of a VPC."),
                key_pair_item(env, required=False), created("sg", "Security group (or pick an existing one)")]
    if template == "jenkins_server":
        return [subnets_item(env, 1, public=True, why="Jenkins must be reachable from your IP."),
                key_pair_item(env, required=False)]
    if template == "docker_image":
        return [tool_item("docker", "The image is built on this computer."), created("ecr", "ECR repository")]
    if template == "ecs_fargate_service":
        return [tool_item("docker", "The image is built on this computer."),
                subnets_item(env, 1, public=True, why="Tasks get a public IP in a public subnet (no NAT, no ALB)."),
                created("ecr", "ECR repository"), created("role", "Task execution role (or pick an existing one)")]
    if template == "eks_cluster":
        items = [tool_item("eksctl", "eksctl creates the cluster."), tool_item("kubectl", "Used to deploy the app.")]
        if i.get("app_source") == "dockerfile":
            items.append(tool_item("docker", "The app image is built on this computer."))
        items.append(manual("eks_cost", "Budget for EKS (~$0.25/hour or more)",
                            "The control plane alone is about $0.10/hour.", "Confirm in the form; run the teardown.",
                            required=False))
        return items
    if template in ("ansible_website", "ansible_playbook"):
        return [tool_item("docker", "Ansible runs in a local Docker container."), instance_item(env),
                manual("pem", "The instance's SSH private key file (.pem)", "Ansible logs in with it.",
                       "The .pem you downloaded when the key pair was created.")]
    if template == "terraform_project":
        return [tool_item("terraform", "Runs terraform plan/apply.")]
    if template == "lambda_function":
        items = [created("role", "Lambda execution role (or pick an existing one)")]
        if i.get("package") == "image":
            items.insert(0, tool_item("docker", "The container image is built on this computer."))
        return items
    if template in ("load_balancer", "auto_scaling_group") or (template == "ecs_fargate_service"
                                                               and i.get("exposure") == "alb"):
        need = 2 if template != "auto_scaling_group" or i.get("load_balancing", "new_alb") == "new_alb" else 1
        if template == "auto_scaling_group" and i.get("action", "create") != "create":
            return None
        return [subnets_item(env, need, public=i.get("scheme", "internet-facing") == "internet-facing",
                             why="An internet-facing load balancer needs public subnets in 2 availability zones."),
                created("sg", "Security groups (load balancer and instances)")]
    if template == "launch_template":
        return [key_pair_item(env, required=False), created("sg", "Security group (or pick an existing one)")]
    if template == "vpc_resource" and i.get("resource") not in (None, "transit_gateway", "prefix_list"):
        return [vpc_item(env)]
    if template == "eks_manage":
        items = [tool_item("kubectl", "Talks to the cluster."), tool_item("aws", "Writes the kubeconfig.")]
        if i.get("action") in ("add_nodegroup", "delete"):
            items.append(tool_item("eksctl", "Manages node groups and clusters."))
        if i.get("app_source") == "dockerfile":
            items.append(tool_item("docker", "The app image is built on this computer."))
        if i.get("app_source") == "helm":
            items.append(tool_item("helm", "Installs the chart."))
        return items
    if template == "cloudfront_distribution" and i.get("aliases"):
        return [manual("dns", "A DNS record for your custom domain", "Visitors reach CloudFront through it.",
                       "After the run, add a CNAME (or Route 53 alias) to the distribution domain.", required=False)]
    return None


def for_template(template: str, inputs: dict, env) -> PrereqReport | None:
    items = _template_items(template, env, inputs or {})
    if not items:
        return None
    from core import templates
    title = templates.TEMPLATES[template].title(inputs or {})
    return PrereqReport(title=title, items=items, template=template, inputs=dict(inputs or {}))


SERVICE_TEMPLATES = {
    "rds": ("database", {}), "dynamodb": ("database", {"engine": "dynamodb"}),
    "docdb": ("database", {"engine": "docdb"}), "elasticache": ("database", {"engine": "redis"}),
    "ec2": ("ec2_instance", {}), "ecs": ("ecs_fargate_service", {}), "eks": ("eks_cluster", {}),
    "lambda": ("lambda_function", {}), "ecr": ("ecr_repository", {}), "s3": ("s3_bucket", {}),
    "iam": ("iam_role", {}), "elbv2": ("load_balancer", {}), "autoscaling": ("auto_scaling_group", {}),
    "cloudfront": ("cloudfront_distribution", {}), "glacier": ("glacier_vault", {}),
}
SERVICE_WORDS = {
    "db2": "rds", "oracle": "rds", "sql server": "rds", "sqlserver": "rds", "mssql": "rds", "postgres": "rds",
    "mysql": "rds", "mariadb": "rds", "aurora": "rds", "rds": "rds", "dynamodb": "dynamodb", "dynamo": "dynamodb",
    "documentdb": "docdb", "docdb": "docdb", "mongodb": "docdb", "redis": "elasticache", "valkey": "elasticache",
    "elasticache": "elasticache", "memcached": "elasticache", "neptune": "neptune", "graph database": "neptune",
    "redshift": "redshift", "data warehouse": "redshift", "memorydb": "memorydb", "keyspaces": "keyspaces",
    "cassandra": "keyspaces", "timestream": "timestream-write", "opensearch": "opensearch",
    "elasticsearch": "opensearch", "kafka": "kafka", "msk": "kafka", "sqs": "sqs", "queue": "sqs", "sns": "sns",
    "kinesis": "kinesis", "cloudfront": "cloudfront", "api gateway": "apigateway", "efs": "efs",
    "file system": "efs", "fsx": "fsx", "emr": "emr", "sagemaker": "sagemaker", "glue": "glue", "athena": "athena",
    "beanstalk": "elasticbeanstalk", "lightsail": "lightsail", "route53": "route53", "route 53": "route53",
    "cognito": "cognito-idp", "step function": "stepfunctions", "state machine": "stepfunctions",
    "aws batch": "batch", "appsync": "appsync", "amplify": "amplify", "app runner": "apprunner",
    "apprunner": "apprunner", "secrets manager": "secretsmanager", "kms": "kms", "waf": "wafv2",
    "aws backup": "backup", "cloudwatch alarm": "cloudwatch", "eventbridge": "events", "codebuild": "codebuild",
    "codepipeline": "codepipeline", "codecommit": "codecommit", "transfer family": "transfer", "sftp": "transfer",
    "workspaces": "workspaces", "dms": "dms", "amazon mq": "mq", "activemq": "mq", "rabbitmq": "mq",
    "load balancer": "elbv2", "alb": "elbv2", "nlb": "elbv2", "ec2": "ec2", "instance": "ec2", "ecs": "ecs",
    "fargate": "ecs", "eks": "eks", "kubernetes": "eks", "lambda": "lambda", "s3": "s3", "bucket": "s3",
    "ecr": "ecr", "iam": "iam", "vpc": "ec2", "cloudformation": "cloudformation", "ses": "sesv2",
    "acm": "acm", "certificate": "acm", "auto scaling": "autoscaling", "autoscaling": "autoscaling",
    "launch template": "ec2", "target group": "elbv2", "ami": "ec2", "ebs": "ec2", "volume": "ec2",
    "snapshot": "ec2", "glacier": "glacier", "cdn": "cloudfront", "security group": "ec2",
}
MAIN_CREATE = ["create_db_cluster", "create_cluster", "create_cluster_v2", "create_domain", "create_db_instance",
               "create_function", "create_table", "create_environment", "create_workgroup", "create_file_system",
               "create_queue", "create_topic", "create_stream", "create_distribution", "create_rest_api",
               "create_api", "create_state_machine", "create_user_pool", "create_broker", "create_service",
               "create_load_balancer", "create_secret", "create_key", "create_web_acl", "create_backup_plan",
               "create_project", "create_pipeline", "create_repository", "create_server", "create_application",
               "create_job_queue", "create_hosted_zone", "create_stack", "create_keyspace", "create_database",
               "create_graphql_api", "create_app", "create_bucket", "create_instance", "create_workspaces",
               "create_replication_instance", "create_alarm", "put_metric_alarm", "create_event_bus"]


def service_from_text(text: str) -> str | None:
    t = (text or "").lower()
    for word, svc in sorted(SERVICE_WORDS.items(), key=lambda kv: -len(kv[0])):
        if re.search(r"\b" + re.escape(word) + r"\b", t):
            return svc
    names = set(boto3.session.Session().get_available_services())
    return next((w for w in re.findall(r"[a-z0-9-]+", t) if w in names and len(w) > 2), None)


REF_PATTERNS = [
    (r"(?i)^(vpc)?subnet(ids?|s|_?ids?)?$|^subnetIds$|subnetid", "subnets", "Subnets in your VPC"),
    (r"(?i)securitygroup(id|ids|s)?$|^vpcsecuritygroupids$", "security_group", "Security group(s)"),
    (r"(?i)^vpcid$|^vpc_?id$", "vpc", "A VPC"),
    (r"(?i)subnetgroup(name)?$", "subnet_group", "A subnet group of this service"),
    (r"(?i)(role|rolearn|servicerole|iamrole|executionrolearn|instanceprofile)(arn|name)?$", "role", "An IAM role"),
    (r"(?i)^keyname$", "key_pair", "An EC2 key pair"),
    (r"(?i)kmskey(id|arn)?$|^kmskeyid$|^kmskeyarn$", "kms", "A KMS key"),
    (r"(?i)certificatearn$", "certificate", "An ACM certificate"),
    (r"(?i)^imageid$", "ami", "An AMI (machine image)"),
    (r"(?i)parametergroupname$", "parameter_group", "A parameter group"),
    (r"(?i)(targetgroup|loadbalancer)arn$", "elb", "A load balancer / target group"),
    (r"(?i)bucket(name)?$|^s3bucket", "bucket", "An S3 bucket"),
]


def _ref_kind(param: str) -> tuple[str, str] | None:
    for pat, kind, title in REF_PATTERNS:
        if re.search(pat, param):
            return kind, title
    return None


def _doc(shape) -> str:
    text = html.unescape(re.sub(r"<[^>]+>", " ", getattr(shape, "documentation", "") or ""))
    text = re.sub(r"\s+", " ", text).strip()
    m = re.match(r"(.{20,220}?[.])(\s|$)", text)
    return (m.group(1) if m else text[:200]).strip()


def _check_ref(env, service: str, kind: str, title: str, param: str, required: bool, why: str) -> PrereqItem:
    key = f"{kind}:{param}"
    if kind == "subnets":
        it = subnets_item(env, 1, required=required, why=why or "The resource is placed in your VPC.")
        it.key = key
        return it
    if kind == "vpc":
        it = subnets_item(env, 1, required=required, why=why)
        it.key, it.title = key, "A VPC (with subnets)"
        return it
    if kind == "key_pair":
        it = key_pair_item(env, required)
        it.key = key
        return it
    if kind == "security_group":
        how = "EC2 console -> Security groups -> Create (open only the ports you need, from the sources you need)."
        sgs, err = _lookup(lambda: env.security_groups(None))
        if err:
            return _unknown(key, title, why, how, err, required)
        found = [f"{g['name']} ({g['id']})" for g in sgs if g["name"] != "default"]
        return PrereqItem(key, title, "ready" if found else "missing", why, how, found, required)
    if kind == "role":
        principal = f"{service.split('-')[0]}.amazonaws.com"
        how = (f"IAM console -> Roles -> Create role -> AWS service '{service}' (or in chat: 'Create an IAM role "
               f"for {service}'). Then use its ARN.")
        roles, err = _lookup(lambda: env.roles(principal))
        if err:
            return _unknown(key, f"IAM role that {service} can assume", why, how, err, required)
        return PrereqItem(key, f"IAM role that {service} can assume ({param})", "ready" if roles else "missing",
                          why, how, [r["name"] for r in roles], required)
    if kind == "subnet_group":
        how = (f"{service} console -> Subnet groups -> Create (pick subnets in 2+ AZs of your VPC). "
               f"Needs: {VPC_HOW}")

        def load():
            client = env.conn.client(service, "read", env.region)
            op = next((o for o in client.meta.method_to_api_mapping
                       if re.fullmatch(r"describe_\w*subnet_groups", o)), None)
            if not op:
                raise PrereqError("no describe call")
            resp = getattr(client, op)()
            rows = next((v for v in resp.values() if isinstance(v, list)), [])
            return [next((str(r[k]) for k in r if k.endswith("SubnetGroupName") or k == "Name"), "?") for r in rows]
        groups, err = _lookup(load)
        if err:
            return _unknown(key, title, why, how, err, required)
        return PrereqItem(key, f"{title} ({param})", "ready" if groups else "missing", why, how, groups, required)
    if kind == "certificate":
        how = "ACM console -> Request certificate (needs a domain you own; DNS validation)."
        certs, err = _lookup(lambda: [c["DomainName"] for c in env.conn.client("acm", "read", env.region)
                                      .list_certificates()["CertificateSummaryList"]])
        if err:
            return _unknown(key, title, why, how, err, required)
        return PrereqItem(key, title, "ready" if certs else "missing", why, how, certs, required)
    hows = {"kms": "Optional: AWS uses its own managed key when omitted. Or KMS console -> Create key.",
            "ami": "Use an official AMI (the ec2_instance recipe picks the latest one for you).",
            "parameter_group": "Optional: AWS uses the default parameter group when omitted.",
            "elb": "In chat: ask for a load balancer, or EC2 console -> Load balancers.",
            "bucket": "In chat: 'Create an S3 bucket', or S3 console -> Create bucket."}
    return PrereqItem(key, f"{title} ({param})", "provide", why, hows.get(kind, ""), required=required)


def _default_vpc(env) -> bool | None:
    """True/False = the region has/has no default VPC; None = could not check."""
    vpcs, err = _lookup(lambda: env.ec2().describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"])
    return None if err else bool(vpcs)


def check_service(service: str, env, operation: str | None = None, engine: str | None = None) -> PrereqReport:
    """Checklist for creating something with ANY AWS service (from its API model)."""
    service = (service or "").strip().lower()
    if service in SERVICE_TEMPLATES and not operation:
        template, inputs = SERVICE_TEMPLATES[service]
        inputs = {**inputs, **({"engine": engine} if engine else {})}
        report = for_template(template, inputs, env)
        if report:
            report.service = service
            report.notes.append(f"The app has a guided recipe for this: plan_task '{template}'.")
            return report
        from core import templates
        return PrereqReport(templates.TEMPLATES[template].title(inputs), [], template=template, inputs=inputs,
                            service=service, notes=["Nothing has to exist first; the app asks for the details."])
    try:
        client = boto3.session.Session().client(service, region_name="us-east-1")
    except Exception:
        raise PrereqError(f"'{service}' is not an AWS service name known to boto3") from None
    creates = sorted(o for o in client.meta.method_to_api_mapping
                     if o.startswith(("create_", "put_metric_alarm", "run_", "launch_")))
    if not creates:
        raise PrereqError(f"{service} has no create operation")
    if operation and operation not in client.meta.method_to_api_mapping:
        raise PrereqError(f"{service} has no operation '{operation}'. Create operations: {', '.join(creates[:25])}")
    op = operation or next((o for o in MAIN_CREATE if o in creates), creates[0])
    shape = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op]).input_shape
    members = shape.members if shape else {}
    required = set(shape.required_members) if shape else set()
    items: list[PrereqItem] = []
    for name, sub in members.items():
        ref = _ref_kind(name)
        if ref and (name in required or ref[0] in ("subnets", "security_group", "vpc", "subnet_group")):
            items.append(_check_ref(env, service, ref[0], ref[1], name, name in required, _doc(sub)))
        elif name in required and not ref:
            items.append(PrereqItem(f"value:{name}", f"{name}", "provide", _doc(sub), required=True))
    no_default_vpc = _default_vpc(env) is False
    for it in items:
        if no_default_vpc and it.key.split(":")[0] in ("subnets", "vpc", "subnet_group") and not it.required:
            it.required = True
            it.why = (it.why.rstrip(".") + ". Required here: this region has no default VPC").lstrip(". ")
    seen, unique = set(), []
    for it in items:
        k = it.key.split(":")[0] if it.key.split(":")[0] in ("subnets", "security_group", "vpc") else it.key
        if k not in seen:
            seen.add(k)
            unique.append(it)
    notes = [f"From the AWS API model of {service}.{op}. Items marked ✏️ are values you give when asking for it.",
             "Also check: service quotas and any AWS Marketplace subscription or licence the product needs "
             "(only a human can arrange those)."]
    return PrereqReport(title=f"{service}.{op}", items=unique[:14], service=service, operation=op,
                        other_operations=[o for o in creates if o != op][:20], notes=notes)


def check_references(service: str, operation: str, params: dict, env) -> list[str]:
    """Problems with resources a create call points at (missing subnet group, unknown subnet ...).
    Placeholders ({{...}}) and failed lookups are skipped. Returns readable problems (empty = fine)."""
    problems = []

    def literal(v):
        return isinstance(v, str) and v and "{{" not in v

    def ids(v):
        return [x for x in (v if isinstance(v, list) else [v]) if literal(x)]

    subnet_ids = ids(params.get("SubnetIds") or params.get("SubnetId") or [])
    if subnet_ids:
        subs, err = _lookup(env.subnets)
        if not err:
            known = {s["id"] for s in subs}
            problems += [f"subnet {s} does not exist in {env.region_name}" for s in subnet_ids if s not in known]
    sg_ids = ids(params.get("VpcSecurityGroupIds") or params.get("SecurityGroupIds") or [])
    if sg_ids:
        sgs, err = _lookup(lambda: env.security_groups(None))
        if not err:
            known = {g["id"] for g in sgs}
            problems += [f"security group {g} does not exist in {env.region_name}" for g in sg_ids if g not in known]
    if literal(params.get("KeyName")) and service == "ec2":
        keys, err = _lookup(env.key_pairs)
        if not err and params["KeyName"] not in keys:
            problems.append(f"key pair '{params['KeyName']}' does not exist in {env.region_name}")
    for key in ("DBSubnetGroupName", "CacheSubnetGroupName"):
        if literal(params.get(key)) and service in ("rds", "docdb", "neptune", "elasticache"):
            def load(k=key):
                c = env.conn.client(service, "read", env.region)
                if k == "CacheSubnetGroupName":
                    return c.describe_cache_subnet_groups(CacheSubnetGroupName=params[k])
                return c.describe_db_subnet_groups(DBSubnetGroupName=params[k])
            _, err = _lookup(load)
            if err and "NotFound" in err:
                problems.append(f"subnet group '{params[key]}' does not exist in {env.region_name}")
    return problems


def recheck(owner: str, conn, report: dict, request: str = "") -> dict:
    """'Check again' button: re-run the checklist. For a recipe this continues the task when everything is
    ready: returns {'prerequisites'} (still missing), {'questions'} (next: details) or {'script'} (saved)."""
    from core import templates
    if report.get("template"):
        return templates.submit(owner, request, report["template"], report.get("inputs", {}), conn,
                                confirmed=set(report.get("confirmed", [])))
    fresh = check_service(report["service"], templates.Env(conn), report.get("operation") or None)
    return {"prerequisites": fresh.to_dict()}
