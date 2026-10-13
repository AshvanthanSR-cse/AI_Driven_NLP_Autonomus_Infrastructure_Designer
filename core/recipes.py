"""Recipes: multi-step goals built on the task-template engine (core/templates.py).

Each recipe = questions (FieldSpec) + a build function that returns a ScriptDraft made of typed steps:
AWS calls, local tools (docker / terraform / kubectl / eksctl), ECR login, Ansible and URL checks
(core/local_steps.py). The LLM only picks the recipe and passes what the user said; code asks for the
rest, generates files from FIXED templates into the workspace folder, adds tags, cost notes and undo
actions (teardown). Nothing runs until the user approves the script on the Scripts page.

Recipes: iam_role, docker_image, jenkins_server, ansible_website, ansible_playbook,
         terraform_project, s3_upload, s3_static_website, database. More recipes live in recipes_compute.py
         (load balancers, Auto Scaling, launch templates, AMI, EBS), recipes_containers.py (ECS, EKS, ECR),
         recipes_network.py (VPC), recipes_storage.py (S3, Glacier, CloudFront) and recipes_lambda.py.
"""
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core import templates, workspace
from core.config import settings
from core.cron import AwsCron, CronError, describe_rate, expression_kind, parse_rate
from core.local_steps import StepError, upload_plan, which
from core.scripts import ScriptDraft
from core.templates import (FieldSpec, HOURS_PER_MONTH, PUBLIC_IPV4_HOURLY, Template, TemplateError,
                            _choice, _int, _key_options, _admin_default, _validate_admin_cidr, _yes_no)
from core.workspace import WorkspaceError

FARGATE_VCPU_HOUR, FARGATE_GB_HOUR = 0.04048, 0.004445
EKS_CONTROL_PLANE_HOUR, CLASSIC_LB_HOUR = 0.10, 0.025
EC2_HOURLY = {"t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


def _expires() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=3)).strftime("%Y-%m-%d")


def tag_dict(name: str, extra: dict | None = None) -> dict:
    return {"Name": name, "Project": "kintsugi", "CreatedBy": "kintsugi", "ExpiresAt": _expires(), **(extra or {})}


def tag_list(name: str, key="Key", value="Value", extra: dict | None = None) -> list[dict]:
    return [{key: k, value: v} for k, v in tag_dict(name, extra).items()]


def _name_validator(pattern: str, hint: str):
    def check(env, inputs, v):
        v = str(v).strip()
        if not re.fullmatch(pattern, v):
            raise ValueError(hint)
        return v
    return check


_aws_name = _name_validator(r"[A-Za-z][A-Za-z0-9-]{1,39}", "start with a letter; letters, numbers and - only (max 40)")
_repo_name = _name_validator(r"[a-z0-9][a-z0-9._/-]{1,99}", "lowercase letters, numbers, . _ - / only")


def _folder(env, inputs, v) -> str:
    return str(workspace.user_folder(v))


def _check_tools(*tools: str) -> None:
    missing = [t for t in tools if not which(t)]
    if missing:
        from core.local_steps import INSTALL_HINT
        raise TemplateError("Missing on this computer: " + ", ".join(missing) + ". " +
                            " ".join(INSTALL_HINT.get(t, "") for t in missing))


def aws_step(service, operation, params, desc, save_as=None, undo=None, wait=None, pause_after=None,
             region=None) -> dict:
    st = {"service": service, "operation": operation, "params": params, "description": desc}
    for k, v in (("save_as", save_as), ("undo", undo), ("wait", wait), ("pause_after", pause_after),
                 ("region", region)):
        if v:
            st[k] = v
    return st


def undo(service, operation, params, desc, wait=None, pause_after=None) -> dict:
    u = {"service": service, "operation": operation, "params": params, "description": desc}
    if wait:
        u["wait"] = wait
    if pause_after:
        u["pause_after"] = pause_after
    return u


def cmd(tool: str, args: list[str], desc: str, cwd: str | None = None, timeout: int = 0, undo_step=None,
        save_as=None) -> dict:
    st = {"kind": "command", "tool": tool, "args": args, "description": desc}
    if cwd:
        st["cwd"] = cwd
    if timeout:
        st["timeout"] = timeout
    if undo_step:
        st["undo"] = undo_step
    if save_as:
        st["save_as"] = save_as
    return st


def check(kind: str, params: dict, desc: str, timeout: int = 600) -> dict:
    return {"kind": "check", "check": kind, "params": params, "description": desc, "timeout": timeout}


TRUSTED_SERVICES = {
    "lambda": ("lambda.amazonaws.com", "AWS Lambda functions"),
    "ecs-tasks": ("ecs-tasks.amazonaws.com", "ECS / Fargate tasks"),
    "ec2": ("ec2.amazonaws.com", "EC2 instances (adds an instance profile)"),
    "eks": ("eks.amazonaws.com", "EKS cluster control plane"),
    "states": ("states.amazonaws.com", "Step Functions"),
    "events": ("events.amazonaws.com", "EventBridge rules"),
    "scheduler": ("scheduler.amazonaws.com", "EventBridge Scheduler"),
    "codebuild": ("codebuild.amazonaws.com", "CodeBuild projects"),
}
MANAGED_POLICIES = {
    "AWSLambdaBasicExecutionRole": "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    "AmazonECSTaskExecutionRolePolicy": "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    "AmazonSSMManagedInstanceCore": "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "CloudWatchAgentServerPolicy": "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
    "AmazonEC2ContainerRegistryReadOnly": "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "AmazonS3ReadOnlyAccess": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    "AmazonS3FullAccess": "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "AmazonDynamoDBFullAccess": "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess",
    "AmazonSQSFullAccess": "arn:aws:iam::aws:policy/AmazonSQSFullAccess",
    "AmazonSNSFullAccess": "arn:aws:iam::aws:policy/AmazonSNSFullAccess",
    "AmazonEKSClusterPolicy": "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
    "AmazonEKSWorkerNodePolicy": "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "AmazonEKS_CNI_Policy": "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "ReadOnlyAccess": "arn:aws:iam::aws:policy/ReadOnlyAccess",
}
_POLICY_ARN_RE = re.compile(r"arn:aws[a-z-]*:iam::(aws|\d{12}):policy/[\w+=,.@/-]+")


def trust_policy(principal: str) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}]})


def role_steps(role_name: str, principal: str, policy_arns: list[str], key: str = "role",
               instance_profile: bool = False, pause: int = 15) -> list[dict]:
    """create_role + attach policies (+ instance profile). Undo detaches and deletes in reverse order."""
    steps = [aws_step("iam", "create_role",
                      {"RoleName": role_name, "AssumeRolePolicyDocument": trust_policy(principal),
                       "Description": f"Created by Kintsugi for {principal}", "Tags": tag_list(role_name)},
                      f"Create IAM role {role_name} (trusted by {principal})", save_as=key,
                      undo=undo("iam", "delete_role", {"RoleName": role_name}, f"Delete IAM role {role_name}"))]
    for arn in policy_arns:
        steps.append(aws_step("iam", "attach_role_policy", {"RoleName": role_name, "PolicyArn": arn},
                              f"Attach {arn.rsplit('/', 1)[-1]} to {role_name}",
                              undo=undo("iam", "detach_role_policy", {"RoleName": role_name, "PolicyArn": arn},
                                        f"Detach {arn.rsplit('/', 1)[-1]}")))
    if instance_profile:
        steps.append(aws_step("iam", "create_instance_profile",
                              {"InstanceProfileName": role_name, "Tags": tag_list(role_name)},
                              f"Create instance profile {role_name}",
                              undo=undo("iam", "delete_instance_profile", {"InstanceProfileName": role_name},
                                        "Delete the instance profile")))
        steps.append(aws_step("iam", "add_role_to_instance_profile",
                              {"InstanceProfileName": role_name, "RoleName": role_name},
                              "Put the role into the instance profile",
                              undo=undo("iam", "remove_role_from_instance_profile",
                                        {"InstanceProfileName": role_name, "RoleName": role_name},
                                        "Remove the role from the instance profile")))
    steps[-1]["pause_after"] = pause
    return steps


def _policy_options(env, inputs):
    return [{"value": arn, "label": name} for name, arn in MANAGED_POLICIES.items()]


def _validate_policies(env, inputs, v) -> list[str]:
    items = [x.strip() for x in (v if isinstance(v, list) else str(v).split(",")) if str(x).strip()]
    out = []
    for x in items:
        arn = MANAGED_POLICIES.get(x, x)
        if not _POLICY_ARN_RE.fullmatch(arn):
            raise ValueError(f"'{x}' is not a policy name from the list or a policy ARN")
        if arn.rsplit("/", 1)[-1] == "AdministratorAccess":
            raise ValueError("AdministratorAccess cannot be granted through the app")
        out.append(arn)
    return list(dict.fromkeys(out))


def _iam_notes(inputs) -> list[str]:
    return ["IAM roles and policies are free. Running this script needs a typed confirmation because it "
            "changes access in your account.",
            "Your Write connection must be allowed to create IAM roles (IAM is the real security boundary)."]


def _build_iam_role(env, v) -> ScriptDraft:
    principal = TRUSTED_SERVICES[v["service"]][0]
    steps = role_steps(v["name"], principal, v["policies"], instance_profile=(v["service"] == "ec2"))
    return ScriptDraft(title=f"Create IAM role {v['name']} for {v['service']}", steps=steps, notes=_iam_notes(v))


IAM_ROLE = Template(
    name="iam_role",
    description="IAM role for a service (Lambda, ECS, EC2, EKS ...) with AWS managed policies",
    fields=[
        FieldSpec("name", "What should the role be called?", "text", default="kintsugi-role",
                  validate=_name_validator(r"[\w+=,.@-]{1,64}", "letters, numbers and +=,.@_- (max 64)")),
        FieldSpec("service", "Which AWS service will use (assume) this role?", "choice", must_ask=True,
                  options=lambda e, i: [{"value": k, "label": f"{k}: {d}"} for k, (_, d) in TRUSTED_SERVICES.items()],
                  validate=lambda e, i, v: _choice([{"value": k, "label": k} for k in TRUSTED_SERVICES], v, "service"),
                  why="This becomes the role's trust policy."),
        FieldSpec("policies", "Which permissions (AWS managed policies) should it get?", "multichoice",
                  must_ask=True, options=_policy_options, validate=_validate_policies,
                  why="Pick the fewest that do the job. AdministratorAccess is not offered on purpose."),
    ],
    title=lambda i: f"IAM role '{i.get('name', 'kintsugi-role')}'",
    build=_build_iam_role, notes=_iam_notes,
)


RUNTIMES = ["python3.13", "python3.12", "python3.11", "nodejs22.x", "nodejs20.x"]


def _guess_runtime(folder: Path) -> str:
    return "nodejs20.x" if any(folder.glob("*.js")) or any(folder.glob("*.mjs")) else "python3.12"


def _guess_handler(folder: Path, runtime: str) -> str:
    if runtime.startswith("python"):
        for name in ("lambda_function", "app", "handler", "main", "index"):
            if (folder / f"{name}.py").is_file():
                return f"{name}.lambda_handler" if name == "lambda_function" else f"{name}.handler"
        first = next(folder.glob("*.py"), None)
        return f"{first.stem}.lambda_handler" if first else "lambda_function.lambda_handler"
    for name in ("index", "app", "handler"):
        if (folder / f"{name}.js").is_file() or (folder / f"{name}.mjs").is_file():
            return f"{name}.handler"
    return "index.handler"


def _src(inputs) -> Path | None:
    try:
        return workspace.user_folder(inputs.get("source_folder", ""))
    except WorkspaceError:
        return None


def _validate_handler(env, inputs, v) -> str:
    v = str(v).strip()
    if not re.fullmatch(r"[\w/.-]+\.[A-Za-z_]\w*", v):
        raise ValueError("handler looks like file.function, e.g. lambda_function.lambda_handler")
    folder = _src(inputs)
    module = v.rsplit(".", 1)[0]
    exts = (".py",) if str(inputs.get("runtime", "python")).startswith("python") else (".js", ".mjs", ".cjs")
    if folder and not any((folder / (module.replace(".", "/") + e)).is_file() or (folder / (module + e)).is_file()
                          for e in exts):
        raise ValueError(f"no file {module}{exts[0]} in the source folder")
    return v


_DAILY_RE = re.compile(r"(?:daily|every\s*day)(?:\s+at)?\s+(.+)", re.I)


def daily_to_cron(text: str, tz: str | None = None) -> str | None:
    """'daily 10:00' / 'every day at 10am' in the app timezone -> UTC EventBridge cron (code does the math)."""
    m = _DAILY_RE.fullmatch(text.strip())
    if not m:
        return None
    from zoneinfo import ZoneInfo
    from core.schedules import parse_hhmm
    t = parse_hhmm(m.group(1))
    local = datetime.now(ZoneInfo(tz or settings.app_timezone)).replace(hour=t.hour, minute=t.minute, second=0,
                                                                        microsecond=0)
    utc = local.astimezone(timezone.utc)
    return f"cron({utc.minute} {utc.hour} * * ? *)"


def _validate_schedule(env, inputs, v) -> str:
    v = str(v or "none").strip()
    if v.lower() in ("none", "no", ""):
        return "none"
    if v.lower() in ("hourly", "every hour"):
        return "rate(1 hour)"
    try:
        if cron := daily_to_cron(v):
            return cron
    except ValueError as e:
        raise ValueError(f"time not understood: {e}") from None
    kind = expression_kind(v)
    try:
        if kind == "cron":
            AwsCron.parse(v)
        elif kind == "rate":
            if parse_rate(v) is None:
                raise CronError("use rate(5 minutes), rate(1 hour) or rate(1 day)")
        else:
            raise CronError("use none, cron(min hour day month weekday year) or rate(N minutes|hours|days)")
    except CronError as e:
        raise ValueError(str(e)) from None
    return v


def _lambda_exists(env, inputs) -> bool:
    return bool(inputs.get("name")) and env.lambda_function(inputs["name"]) is not None


def _role_options(principal: str, label: str):
    def opts(env, inputs):
        return [{"value": "new", "label": f"Create a new role with {label} (recommended)"}] + \
               [{"value": r["arn"], "label": f"{r['name']}"} for r in env.roles(principal)]
    return opts


def _validate_role(principal: str, label: str):
    def check(env, inputs, v):
        if str(v).strip().lower() in ("new", "create", "create new"):
            return "new"
        return _choice(_role_options(principal, label)(env, inputs), v, "role")
    return check


def _schedule_note(expr: str) -> str:
    if expr == "none":
        return ""
    if expression_kind(expr) == "rate":
        return f"Schedule: {describe_rate(expr)}."
    try:
        runs = AwsCron.parse(expr).next_runs(datetime.now(timezone.utc), tz="UTC", count=3, max_days=400)
    except (CronError, ValueError):
        return ""
    from zoneinfo import ZoneInfo
    local = ", ".join(r.astimezone(ZoneInfo(settings.app_timezone)).strftime("%Y-%m-%d %H:%M") for r in runs)
    return (f"Schedule {expr} is evaluated in UTC by EventBridge. Next runs ({settings.app_timezone}): {local}.")


def _lambda_notes(inputs) -> list[str]:
    notes = ["COST: Lambda includes 1 million requests and 400,000 GB-seconds per month in the free tier; "
             "light use is usually free. The code zip is built from your folder (secret files skipped)."]
    if (n := _schedule_note(inputs.get("schedule", "none") or "none")):
        notes.append(n)
    return notes


def docker_context(value) -> tuple[Path, str]:
    """A folder with a Dockerfile, or the Dockerfile itself (e.g. an attached file) -> (build folder, file name)."""
    raw = str(value).strip().strip('"')
    p = Path(raw)
    if p.is_file():
        if not p.name.lower().startswith("dockerfile") and p.suffix.lower() != ".dockerfile":
            raise WorkspaceError(f"{p.name} is not a Dockerfile")
        return p.parent.resolve(), p.name
    folder = workspace.user_folder(raw)
    return folder, workspace.find_dockerfile(folder).name


def _validate_docker_folder(env, inputs, v) -> str:
    folder, name = docker_context(v)
    return str(folder / name) if name.lower() != "dockerfile" else str(folder)


def _docker_port_default(env, inputs):
    try:
        folder, name = docker_context(inputs.get("app_folder", ""))
        return workspace.dockerfile_info(folder, name).get("port") or 80
    except Exception:
        return 80


def image_steps(env, repo: str, path: str, platform: str = "linux/amd64", immutable: bool = False,
                extra_build_args: list[str] | None = None) -> tuple[list[dict], str, list[str]]:
    """ECR repository (if missing) + docker build/login/push. Returns (steps, image URI, warnings)."""
    _check_tools("docker")
    ctx, dockerfile = docker_context(path)
    folder = str(ctx)
    info = workspace.dockerfile_info(ctx, dockerfile)
    region = env.region_name
    uri = env.ecr_repo_uri(repo) or f"{env.account_id()}.dkr.ecr.{region}.amazonaws.com/{repo}"
    image = f"{uri}:{_stamp()}"
    steps = []
    if not env.ecr_repo_uri(repo):
        steps.append(aws_step("ecr", "create_repository",
                              {"repositoryName": repo, "imageScanningConfiguration": {"scanOnPush": True},
                               "imageTagMutability": "IMMUTABLE" if immutable else "MUTABLE", "tags": tag_list(repo)},
                              f"Create ECR repository {repo} (image scanning on push)", save_as="repo",
                              undo=undo("ecr", "delete_repository", {"repositoryName": repo, "force": True},
                                        f"Delete ECR repository {repo} and its images")))
    steps += [
        cmd("docker", ["build", "--platform", platform, *(extra_build_args or []), "-t", image, "-f", dockerfile, "."],
            f"Build the image from {folder} ({dockerfile}, on this computer)", cwd=folder, timeout=3600),
        {"kind": "ecr_login", "repository_uri": uri, "description": "Log Docker in to ECR (temporary password)"},
        cmd("docker", ["push", image], f"Push the image to ECR ({repo})", timeout=3600),
    ]
    return steps, image, info["warnings"]


def _build_docker_image(env, v) -> ScriptDraft:
    steps, image, warns = image_steps(env, v["repository"], v["app_folder"])
    return ScriptDraft(title=f"Build and push {v['repository']} to ECR", steps=steps,
                       notes=["COST: ECR storage ~$0.10 per GB-month (500 MB/month free for 12 months).",
                              f"Image: {image}", "Docker Desktop must be running."] + warns)


DOCKER_IMAGE = Template(
    name="docker_image",
    description="Build a Docker image from a local folder (Dockerfile) and push it to Amazon ECR",
    fields=[
        FieldSpec("app_folder", "Which Dockerfile (or the folder that has it)?", "path", must_ask=True,
                  validate=_validate_docker_folder),
        FieldSpec("repository", "ECR repository name?", "text", default="kintsugi-app", validate=_repo_name),
    ],
    title=lambda i: f"Docker image '{i.get('repository', 'kintsugi-app')}'",
    build=_build_docker_image, notes=lambda i: ["COST: ECR storage ~$0.10 per GB-month."],
)


JENKINS_USER_DATA = """#!/bin/bash
# Installs Jenkins LTS on Amazon Linux 2023 (generated by Kintsugi from a fixed template).
set -euxo pipefail
dnf install -y java-21-amazon-corretto-headless fontconfig
curl -fsSL -o /etc/yum.repos.d/jenkins.repo https://pkg.jenkins.io/redhat-stable/jenkins.repo
rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io-2023.key
dnf install -y jenkins
systemctl enable --now jenkins
"""


def _jenkins_notes(inputs) -> list[str]:
    t = inputs.get("instance_type", "t3.small")
    p = EC2_HOURLY.get(t, 0.0208)
    return [f"COST: {t} ~${p}/hour (~${p * HOURS_PER_MONTH:.0f}/month) + 20 GB gp3 ~$1.60/month + public IP "
            f"~${PUBLIC_IPV4_HOURLY}/hour. Approximate us-east-1 prices. Stop or tear down when idle.",
            "Jenkins (port 8080) and SSH are opened ONLY to your IP, never to the whole internet.",
            "Installation takes 3-6 minutes after the instance starts. The first-login password is on the server: "
            "ssh to it and run 'sudo cat /var/lib/jenkins/secrets/initialAdminPassword' (Kintsugi never reads it).",
            "If the install fails, check /var/log/cloud-init-output.log on the instance."]


def _build_jenkins(env, v) -> ScriptDraft:
    name = v["name"]
    sub = {s["id"]: s for s in env.subnets()}[v["subnet_id"]]
    ami = env.ami("amazon-linux-2023")
    rules = [{"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": v["admin_cidr"],
                                                                            "Description": desc}]}
             for p, desc in ((22, "SSH from your IP"), (8080, "Jenkins from your IP"))]
    inst = "{{inst.Instances.0.InstanceId}}"
    run = {"ImageId": ami["id"], "InstanceType": v["instance_type"], "SubnetId": sub["id"],
           "SecurityGroupIds": ["{{sg.GroupId}}"], "MinCount": 1, "MaxCount": 1, "UserData": JENKINS_USER_DATA,
           "BlockDeviceMappings": [{"DeviceName": ami["root_device"], "Ebs": {
               "VolumeSize": 20, "VolumeType": "gp3", "DeleteOnTermination": True, "Encrypted": True}}],
           "MetadataOptions": {"HttpTokens": "required"},
           "TagSpecifications": templates._tags("instance", name, {"Env": "demo", "Purpose": "jenkins"}) +
                                templates._tags("volume", f"{name}-root", {"Env": "demo"})}
    if v.get("key_name") and v["key_name"] != "none":
        run["KeyName"] = v["key_name"]
    steps = [
        aws_step("ec2", "create_security_group",
                 {"GroupName": f"{name}-sg-{_stamp()}", "Description": f"Kintsugi Jenkins {name}", "VpcId": sub["vpc"],
                  "TagSpecifications": templates._tags("security-group", f"{name}-sg")},
                 f"Create security group for {name}", save_as="sg",
                 undo=undo("ec2", "delete_security_group", {"GroupId": "{{sg.GroupId}}"}, "Delete the security group")),
        aws_step("ec2", "authorize_security_group_ingress", {"GroupId": "{{sg.GroupId}}", "IpPermissions": rules},
                 f"Allow SSH (22) and Jenkins (8080) only from {v['admin_cidr']}"),
        aws_step("ec2", "run_instances", run,
                 f"Launch {name} (Amazon Linux 2023, {v['instance_type']}) with the Jenkins install script",
                 save_as="inst", wait={"waiter": "instance_running", "params": {"InstanceIds": [inst]}},
                 undo=undo("ec2", "terminate_instances", {"InstanceIds": [inst]}, f"Terminate {name}",
                           wait={"waiter": "instance_terminated", "params": {"InstanceIds": [inst]}})),
        check("ec2_url", {"instance_id": inst, "port": 8080, "path": "/login"},
              "Wait until Jenkins answers on port 8080 (install takes a few minutes)", timeout=1500),
    ]
    return ScriptDraft(title=f"Jenkins server {name} on EC2", steps=steps, notes=_jenkins_notes(v))


def _subnet_choice(public_only: bool):
    def opts(env, inputs):
        return [{"value": s["id"], "label": f"{s['id']} · {s['cidr']} · {s['az']} · "
                                            f"{'public' if s['public'] else 'private'} · {s['vpc_name'] or s['vpc']}"}
                for s in env.subnets() if s["public"] or not public_only]
    return opts


JENKINS = Template(
    name="jenkins_server",
    description="Jenkins CI server on a small EC2 instance, reachable only from your IP",
    fields=[
        FieldSpec("name", "Instance name?", "text", default="kintsugi-jenkins", validate=_aws_name),
        FieldSpec("subnet_id", "Which public subnet?", "choice", must_ask=True, options=_subnet_choice(True),
                  validate=lambda e, i, v: _choice(_subnet_choice(True)(e, i), v, "public subnet"),
                  empty_hint="No public subnets in this region. First ask: 'Create a VPC with 2 public subnets'."),
        FieldSpec("admin_cidr", "Which IP may open Jenkins and SSH?", "text", must_ask=True, default=_admin_default,
                  validate=_validate_admin_cidr, why="Pre-filled with your current public IP."),
        FieldSpec("key_name", "Key pair for SSH (needed to read the first-login password)?", "choice",
                  default=lambda e, i: (e.key_pairs() or ["none"])[0], options=_key_options,
                  validate=lambda e, i, v: _choice(_key_options(e, i), v, "key pair")),
        FieldSpec("instance_type", "Instance size?", "choice", default="t3.small",
                  options=lambda e, i: [{"value": t, "label": f"{t} (~${EC2_HOURLY[t]}/hour)"} for t in ("t3.small", "t3.medium")],
                  validate=lambda e, i, v: _choice([{"value": t, "label": t} for t in ("t3.small", "t3.medium")], v, "size"),
                  why="Jenkins needs at least 2 GB of memory."),
    ],
    title=lambda i: f"Jenkins server '{i.get('name', 'kintsugi-jenkins')}'",
    build=_build_jenkins, notes=_jenkins_notes,
)


def _instance_options(env, inputs):
    return [{"value": i["id"], "label": f"{i['name'] or '(no name)'} · {i['id']} · {i['ip']}"}
            for i in env.instances() if i["ip"]]


def _instance(env, iid) -> dict:
    return next(i for i in env.instances() if i["id"] == iid)


def _ssh_user_default(env, inputs):
    try:
        img = env.image_name(_instance(env, inputs["instance"])["image"]).lower()
        return "ubuntu" if "ubuntu" in img else "ec2-user"
    except Exception:
        return "ec2-user"


SSH_USERS = [{"value": "ec2-user", "label": "ec2-user (Amazon Linux)"}, {"value": "ubuntu", "label": "ubuntu (Ubuntu)"},
             {"value": "admin", "label": "admin (Debian)"}]


def _validate_key(env, inputs, v) -> str:
    return str(workspace.user_file(v, (".pem",)))


def _validate_site_folder(env, inputs, v) -> str:
    folder = workspace.user_folder(v)
    if not (folder / "index.html").is_file() and not (folder / "requirements.txt").is_file():
        raise ValueError("expected a static site (index.html) or a Flask app (requirements.txt) in that folder")
    return str(folder)


def _site_type_default(env, inputs):
    try:
        return "flask" if (workspace.user_folder(inputs.get("folder", "")) / "requirements.txt").is_file() else "static"
    except WorkspaceError:
        return "static"


def _validate_site_type(env, inputs, v) -> str:
    kind = _choice(SITE_TYPES, v, "app type")
    try:
        folder = workspace.user_folder(inputs.get("folder", ""))
    except WorkspaceError:
        return kind
    if kind == "static" and not (folder / "index.html").is_file():
        raise ValueError("a static website needs an index.html in the folder")
    if kind == "flask" and not (folder / "requirements.txt").is_file():
        raise ValueError("a Flask app needs a requirements.txt in the folder")
    return kind


SITE_TYPES = [{"value": "static", "label": "Static website (HTML/CSS/JS)"},
              {"value": "flask", "label": "Python Flask app (gunicorn behind nginx)"}]


def _wsgi_default(env, inputs):
    try:
        folder = workspace.user_folder(inputs.get("folder", ""))
        for f in ("app.py", "main.py", "wsgi.py", "application.py"):
            if (folder / f).is_file():
                text = (folder / f).read_text(encoding="utf-8", errors="replace")
                m = re.search(r"^(\w+)\s*=\s*Flask\(", text, re.M)
                return f"{f[:-3]}:{m.group(1) if m else 'app'}"
    except Exception:
        pass
    return "app:app"


SITE_PLAYBOOK = """# Generated by Kintsugi from the fixed '{template}' template. Review before running.
- name: Deploy {app} ({template})
  hosts: web
  become: true
  vars:
    app: {app}
    release: "{release}"
    app_root: /var/www/{app}
  handlers:
    - name: Reload nginx
      ansible.builtin.service:
        name: nginx
        state: reloaded
  tasks:
    - name: Refresh the package index (Debian/Ubuntu)
      ansible.builtin.apt:
        update_cache: true
        cache_valid_time: 3600
      when: ansible_facts['pkg_mgr'] == 'apt'
      tags: [packages]
    - name: Install packages
      ansible.builtin.package:
        name: "{{{{ item }}}}"
        state: present
      loop: {packages}
      tags: [packages]
    - name: Remove the default nginx site (Debian/Ubuntu)
      ansible.builtin.file:
        path: /etc/nginx/sites-enabled/default
        state: absent
      notify: Reload nginx
      tags: [nginx]
    - name: Create the release folder
      ansible.builtin.file:
        path: "{{{{ app_root }}}}/releases/{{{{ release }}}}"
        state: directory
        mode: "0755"
      tags: [deploy]
    - name: Copy the files
      ansible.builtin.copy:
        src: site/
        dest: "{{{{ app_root }}}}/releases/{{{{ release }}}}/"
        mode: preserve
      tags: [deploy]
{extra_tasks}    - name: Switch 'current' to the new release (rollback = point it at an older release)
      ansible.builtin.file:
        src: "{{{{ app_root }}}}/releases/{{{{ release }}}}"
        dest: "{{{{ app_root }}}}/current"
        state: link
        force: true
      tags: [deploy]
{service_tasks}    - name: Write the nginx site configuration
      ansible.builtin.copy:
        dest: /etc/nginx/conf.d/kintsugi-{app}.conf
        mode: "0644"
        content: |
          server {{
            listen 80 default_server;
            server_name _;
{nginx_body}          }}
      notify: Reload nginx
      tags: [nginx]
    - name: Check the nginx configuration
      ansible.builtin.command: nginx -t
      changed_when: false
      tags: [nginx]
    - name: Start nginx now and at boot
      ansible.builtin.service:
        name: nginx
        state: started
        enabled: true
      tags: [nginx]
"""

FLASK_EXTRA = """    - name: Install python3-venv (Debian/Ubuntu)
      ansible.builtin.apt:
        name: python3-venv
        state: present
      when: ansible_facts['pkg_mgr'] == 'apt'
      tags: [packages]
    - name: Create the Python virtual environment and install requirements
      ansible.builtin.pip:
        requirements: "{{ app_root }}/releases/{{ release }}/requirements.txt"
        virtualenv: "{{ app_root }}/venv"
        virtualenv_command: python3 -m venv
      tags: [deploy]
    - name: Install gunicorn
      ansible.builtin.pip:
        name: gunicorn
        virtualenv: "{{ app_root }}/venv"
        virtualenv_command: python3 -m venv
      tags: [deploy]
"""

FLASK_SERVICE = """    - name: Write the app service (gunicorn on 127.0.0.1:8000, unprivileged dynamic user)
      ansible.builtin.copy:
        dest: /etc/systemd/system/kintsugi-{app}.service
        mode: "0644"
        content: |
          [Unit]
          Description=Kintsugi app {app}
          After=network.target
          [Service]
          DynamicUser=yes
          WorkingDirectory={{{{ app_root }}}}/current
          ExecStart={{{{ app_root }}}}/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:8000 {wsgi}
          Restart=on-failure
          [Install]
          WantedBy=multi-user.target
      tags: [service]
    - name: Restart the app service
      ansible.builtin.systemd:
        name: kintsugi-{app}
        state: restarted
        enabled: true
        daemon_reload: true
      tags: [service]
"""

STATIC_NGINX = "            root /var/www/{app}/current;\n            index index.html;\n"
FLASK_NGINX = ("            location / {{\n              proxy_pass http://127.0.0.1:8000;\n"
               "              proxy_set_header Host $host;\n              proxy_set_header X-Forwarded-For $remote_addr;\n"
               "            }}\n")


def render_site_playbook(app: str, app_type: str, release: str, wsgi: str = "app:app") -> str:
    if app_type == "flask":
        return SITE_PLAYBOOK.format(template="flask_gunicorn_nginx", app=app, release=release,
                                    packages="[nginx, python3, python3-pip]",
                                    extra_tasks=FLASK_EXTRA, service_tasks=FLASK_SERVICE.format(app=app, wsgi=wsgi),
                                    nginx_body=FLASK_NGINX.format())
    return SITE_PLAYBOOK.format(template="static_site_nginx", app=app, release=release, packages="[nginx]",
                                extra_tasks="", service_tasks="", nginx_body=STATIC_NGINX.format(app=app))


def inventory(hosts: list[str], user: str) -> str:
    ssh = "-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/work/known_hosts"
    lines = ["# Generated by Kintsugi", "[web]"]
    lines += [f"{h} ansible_user={user} ansible_python_interpreter=auto_silent ansible_ssh_common_args='{ssh}'"
              for h in hosts]
    return "\n".join(lines) + "\n"


def _sg_warnings(env, inst: dict, need_ports: tuple[int, ...] = (80,)) -> list[str]:
    try:
        rules = env.sg_rules(inst["sgs"])
    except Exception:
        return ["Could not read the instance's security groups; make sure ports 22 (your IP) and 80 are open."]
    def open_from(port, cidr_ok):
        return any(r["from"] is not None and r["from"] <= port <= (r["to"] or port) and any(cidr_ok(c) for c in r["cidrs"])
                   for r in rules)
    warns = []
    for port in need_ports:
        if not open_from(port, lambda c: c == "0.0.0.0/0"):
            warns.append(f"Warning: the instance's security group does not open port {port} to the internet, so the site "
                         f"will not be reachable. Add an inbound rule for TCP {port}.")
    if not open_from(22, lambda c: True):
        warns.append("Warning: port 22 (SSH) is not open in the instance's security group; Ansible cannot connect. "
                     "Open it to your IP only.")
    return warns


def _ansible_site_notes(inputs) -> list[str]:
    return ["Ansible runs inside a local Docker container (image kintsugi-ansible, built automatically the first "
            "time), so Docker Desktop must be running. Your SSH key is passed to it on stdin and is never saved.",
            "Files are deployed to /var/www/<app>/releases/<time> and 'current' points to the newest release, so "
            "an older release can be restored by pointing 'current' back at it."]


def _build_ansible_site(env, v) -> ScriptDraft:
    _check_tools("docker")
    inst = _instance(env, v["instance"])
    d = workspace.new_task_dir(f"site-{v['app_name']}")
    try:
        scan = workspace.stage_folder(Path(v["folder"]), d / "site")
    except WorkspaceError as e:
        raise TemplateError(str(e)) from None
    release = datetime.now().strftime("%Y%m%d-%H%M%S")
    workspace.write(d / "site.yml", render_site_playbook(v["app_name"], v["app_type"], release, v.get("wsgi", "app:app")))
    workspace.write(d / "inventory.ini", inventory([inst["ip"]], v["ssh_user"]))
    base = {"kind": "ansible", "workdir": str(d), "playbook": "site.yml", "inventory": "inventory.ini"}
    steps = [
        {**base, "extra_args": ["--syntax-check"], "description": "Check the playbook syntax"},
        {**base, "ssh_key_path": v["ssh_key_path"], "extra_args": ["--diff"], "timeout": 1800,
         "description": f"Deploy {len(scan['files'])} files to {inst['name'] or inst['id']} ({inst['ip']}) with nginx"},
        check("http", {"url": f"http://{inst['ip']}/"}, f"Check http://{inst['ip']}/ answers HTTP 200", timeout=300),
    ]
    notes = _ansible_site_notes(v) + _sg_warnings(env, inst) + scan["warnings"] + [f"Playbook and files: {d}"]
    return ScriptDraft(title=f"Deploy {Path(v['folder']).name} to {inst['name'] or inst['id']} ({v['app_type']})",
                       steps=steps, notes=notes)


def _validate_app_name(env, inputs, v) -> str:
    v = str(v).strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", v):
        raise ValueError("lowercase letters, numbers and - (max 31)")
    return v


def _app_name_default(env, inputs):
    try:
        raw = workspace.user_folder(inputs.get("folder", "")).name.lower()
        name = re.sub(r"[^a-z0-9-]+", "-", raw).strip("-")
        return name if re.fullmatch(r"[a-z][a-z0-9-]{0,30}", name or "") else "site"
    except Exception:
        return "site"


ANSIBLE_SITE = Template(
    name="ansible_website",
    description="Deploy a local website folder (static HTML or Flask) to a running EC2 instance with Ansible + nginx",
    fields=[
        FieldSpec("instance", "Which running instance should host it?", "choice", must_ask=True,
                  options=_instance_options, validate=lambda e, i, v: _choice(_instance_options(e, i), v, "instance"),
                  empty_hint="No running instance with a public IP. First create one ('Create an EC2 web server')."),
        FieldSpec("folder", "Which local folder should be deployed?", "folder", must_ask=True,
                  validate=_validate_site_folder, why="Secret files (.env, keys, .git) are never copied."),
        FieldSpec("app_type", "What kind of app is it?", "choice", must_ask=True, default=_site_type_default,
                  options=lambda e, i: SITE_TYPES, validate=_validate_site_type),
        FieldSpec("wsgi", "Flask entry point (module:app object)?", "text", default=_wsgi_default,
                  validate=_name_validator(r"[\w.]+:[\w]+", "looks like app:app"),
                  relevant=lambda i: i.get("app_type") == "flask"),
        FieldSpec("app_name", "Short app name (folder and config names on the server)?", "text",
                  default=_app_name_default, validate=_validate_app_name),
        FieldSpec("ssh_user", "SSH login user?", "choice", default=_ssh_user_default,
                  options=lambda e, i: SSH_USERS, validate=lambda e, i, v: _choice(SSH_USERS, v, "user")),
        FieldSpec("ssh_key_path", "Path to the instance's SSH private key (.pem)?", "file", must_ask=True,
                  validate=_validate_key, why="Used only for this run; never stored or shown to the AI."),
    ],
    title=lambda i: "Deploy a website with Ansible",
    build=_build_ansible_site, notes=_ansible_site_notes,
)


RISKY_PLAYBOOK = [
    (re.compile(r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"), "pipes a download straight into a shell"),
    (re.compile(r"\brm\s+-[a-z]*r[a-z]*f?\s+/(\s|$|etc\b|usr\b|var\b|boot\b|bin\b|lib\b|home\b)"),
     "deletes a system directory"),
    (re.compile(r"NOPASSWD", re.I), "grants password-less sudo"),
    (re.compile(r"groups?:\s*['\"]?[\w, ]*\b(sudo|wheel|admin)\b"), "adds a user to an admin group"),
    (re.compile(r"chmod\s+(-R\s+)?777\s+/(\s|$)"), "makes the root filesystem world-writable"),
]


def scan_playbooks(folder: Path) -> list[str]:
    problems = []
    for p in sorted(folder.rglob("*")):
        if p.suffix.lower() not in (".yml", ".yaml", ".j2", ".sh") or not p.is_file():
            continue
        for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for rx, why in RISKY_PLAYBOOK:
                if rx.search(line):
                    problems.append(f"{p.relative_to(folder)} line {n}: {why}")
    return problems


def _playbook_options(env, inputs):
    try:
        folder = workspace.user_folder(inputs.get("folder", ""))
    except WorkspaceError:
        return []
    return [{"value": p.name, "label": p.name} for p in sorted(folder.glob("*.y*ml"))]


def _validate_instances(env, inputs, v) -> list[str]:
    ids = [x.strip() for x in (v if isinstance(v, list) else str(v).split(",")) if str(x).strip()]
    ok = {o["value"] for o in _instance_options(env, inputs)}
    if not ids or any(x not in ok for x in ids):
        raise ValueError("pick running instances that have a public IP")
    return ids


def _build_ansible_playbook(env, v) -> ScriptDraft:
    _check_tools("docker")
    problems = scan_playbooks(Path(v["folder"]))
    if problems:
        raise TemplateError("The playbook has blocked, risky tasks:\n- " + "\n- ".join(problems[:10]))
    d = workspace.new_task_dir("ansible")
    try:
        scan = workspace.stage_folder(Path(v["folder"]), d)
    except WorkspaceError as e:
        raise TemplateError(str(e)) from None
    hosts = [_instance(env, i)["ip"] for i in v["instances"]]
    workspace.write(d / "kintsugi-inventory.ini", inventory(hosts, v["ssh_user"]).replace("[web]", "[all_targets]"))
    base = {"kind": "ansible", "workdir": str(d), "playbook": v["playbook"], "inventory": "kintsugi-inventory.ini"}
    steps = [{**base, "extra_args": ["--syntax-check"], "description": f"Check the syntax of {v['playbook']}"},
             {**base, "ssh_key_path": v["ssh_key_path"], "extra_args": ["--diff"], "timeout": 3600,
              "description": f"Run {v['playbook']} on {', '.join(hosts)}"}]
    return ScriptDraft(title=f"Run Ansible playbook {v['playbook']} on {len(hosts)} instance(s)", steps=steps,
                       notes=_ansible_site_notes(v)[:1] + scan["warnings"] +
                             ["Inventory group: all_targets (use 'hosts: all' or 'hosts: all_targets').",
                              f"Copy of your folder used for the run: {d}"])


ANSIBLE_PLAYBOOK = Template(
    name="ansible_playbook",
    description="Run your own Ansible playbook from a local folder against running EC2 instances",
    fields=[
        FieldSpec("folder", "Which local folder has the playbook?", "folder", must_ask=True, validate=_folder),
        FieldSpec("playbook", "Which playbook file?", "choice", must_ask=True, options=_playbook_options,
                  validate=lambda e, i, v: _choice(_playbook_options(e, i), v, "playbook")),
        FieldSpec("instances", "Which instances?", "multichoice", must_ask=True, options=_instance_options,
                  validate=_validate_instances),
        FieldSpec("ssh_user", "SSH login user?", "choice", default="ec2-user",
                  options=lambda e, i: SSH_USERS, validate=lambda e, i, v: _choice(SSH_USERS, v, "user")),
        FieldSpec("ssh_key_path", "Path to the SSH private key (.pem)?", "file", must_ask=True, validate=_validate_key),
    ],
    title=lambda i: "Run an Ansible playbook",
    build=_build_ansible_playbook, notes=_ansible_site_notes,
)


TF_ACTIONS = [
    {"value": "plan", "label": "Plan only: show what would change (safe, recommended first)"},
    {"value": "apply", "label": "Plan and apply: create/change the resources"},
    {"value": "destroy", "label": "Destroy everything this Terraform folder manages"},
]
RISKY_TF = [
    (re.compile(r"AdministratorAccess"), "attaches AdministratorAccess"),
    (re.compile(r"""["']?Action["']?\s*[:=]\s*\[?\s*["']\*["']"""), "allows Action '*'"),
    (re.compile(r"""\bacl\s*=\s*["']public-read(-write)?["']"""), "makes an S3 bucket public"),
]


def scan_terraform(folder: Path) -> list[str]:
    problems = []
    for p in sorted(folder.glob("*.tf")):
        text = p.read_text(encoding="utf-8", errors="replace")
        for rx, why in RISKY_TF:
            for m in rx.finditer(text):
                problems.append(f"{p.name} line {text.count(chr(10), 0, m.start()) + 1}: {why}")
        for block in re.finditer(r"(ingress\s*\{[^{}]*\}|resource\s+\"aws_(?:vpc_)?security_group_(?:ingress_)?rule\"[^{]*\{[^{}]*\})", text):
            body = block.group(0)
            if re.search(r"from_port\s*=\s*22\b", body) and "0.0.0.0/0" in body:
                problems.append(f"{p.name} line {text.count(chr(10), 0, block.start()) + 1}: opens SSH (22) to 0.0.0.0/0")
    return problems


def _validate_tf_folder(env, inputs, v) -> str:
    folder = workspace.user_folder(v)
    if not any(folder.glob("*.tf")):
        raise ValueError("no .tf files in that folder")
    return str(folder)


def _tf_notes(inputs) -> list[str]:
    return ["Terraform runs in your folder (state and .terraform stay there), with your Write connection's "
            "credentials passed only to the terraform process.",
            "Recommended: run 'Plan only' first, read the plan in the Result box, then ask again with 'apply'.",
            "Costs depend on what your files create; Kintsugi cannot estimate them for custom Terraform."]


def _build_terraform(env, v) -> ScriptDraft:
    _check_tools("terraform")
    folder, action = v["folder"], v["action"]
    problems = scan_terraform(Path(folder))
    if problems and action != "destroy":
        raise TemplateError("Blocked: the Terraform files contain risky settings:\n- " + "\n- ".join(problems[:10]))
    tf = lambda args, desc, **kw: cmd("terraform", args, desc, cwd=folder, timeout=3600, **kw)
    steps = [tf(["init", "-input=false", "-no-color"], "terraform init (download providers)")]
    if action == "destroy":
        steps.append(tf(["destroy", "-input=false", "-no-color", "-auto-approve"], "terraform destroy (deletes everything it manages)"))
    else:
        steps += [tf(["validate", "-no-color"], "terraform validate"),
                  tf(["plan", "-input=false", "-no-color", "-out=tfplan"], "terraform plan (saved to tfplan)")]
        if action == "apply":
            steps.append(tf(["apply", "-input=false", "-no-color", "tfplan"], "terraform apply tfplan (exactly the plan above)",
                            undo_step={"kind": "command", "tool": "terraform", "cwd": folder, "timeout": 3600,
                                       "args": ["destroy", "-input=false", "-no-color", "-auto-approve"],
                                       "description": "terraform destroy (removes what was applied)"}))
    labels = {"plan": "Plan", "apply": "Plan and apply", "destroy": "Destroy"}
    return ScriptDraft(title=f"Terraform {labels[action].lower()}: {Path(folder).name}", steps=steps, notes=_tf_notes(v))


TERRAFORM = Template(
    name="terraform_project",
    description="Run your own Terraform folder: plan, apply (with automatic destroy teardown) or destroy",
    fields=[
        FieldSpec("folder", "Which local folder has the Terraform (.tf) files?", "folder", must_ask=True,
                  validate=_validate_tf_folder),
        FieldSpec("action", "What should Terraform do?", "choice", must_ask=True, default="plan",
                  options=lambda e, i: TF_ACTIONS, validate=lambda e, i, v: _choice(TF_ACTIONS, v, "action")),
    ],
    title=lambda i: "Terraform project",
    build=_build_terraform, notes=_tf_notes,
)


S3_GB_MONTH = 0.023
_BUCKET_NAME_RE = re.compile(r"(?!xn--)(?!.*\.\.)[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")


def _buckets(env) -> list[str]:
    return env._memo("buckets", lambda: sorted(b["Name"] for b in env.conn.client("s3", "read", env.region)
                                                .list_buckets().get("Buckets", [])))


def _bucket_region(env, bucket: str) -> str:
    def load():
        loc = env.conn.client("s3", "read", env.region).get_bucket_location(Bucket=bucket).get("LocationConstraint")
        return loc or "us-east-1"
    return env._memo(("bucket-region", bucket), load)


def _existing_keys(env, bucket: str, region: str, keys: list[str]) -> set[str]:
    """Which of these keys already exist (they are overwritten, and never deleted by the teardown)."""
    s3 = env.conn.client("s3", "read", region)
    prefixes = sorted({k.rsplit("/", 1)[0] + "/" if "/" in k else "" for k in keys})
    found: set[str] = set()
    for pref in prefixes[:50]:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=pref,
                                                                  PaginationConfig={"MaxItems": 10000}):
            found |= {o["Key"] for o in page.get("Contents", [])}
    return found & set(keys)


def _bucket_options(env, inputs):
    return [{"value": "new", "label": "Create a new private bucket"}] + \
           [{"value": b, "label": b} for b in _buckets(env)]


def _validate_bucket(env, inputs, v) -> str:
    v = str(v).strip().removeprefix("s3://").strip("/")
    if v.lower() in ("new", "create", "create new"):
        return "new"
    return _choice(_bucket_options(env, inputs), v, "bucket (pick one of yours, or 'new')")


_NOT_A_NAME = {"true", "false", "yes", "no", "y", "n", "ok", "new", "none", "null", "default", "bucket"}


def _bucket_taken_elsewhere(env, bucket: str) -> bool:
    """Bucket names are global across ALL AWS accounts. 404 = free; 403/301 = someone else owns it."""
    from botocore.exceptions import ClientError

    def load():
        try:
            env.conn.client("s3", "read", env.region).head_bucket(Bucket=bucket)
            return True
        except ClientError as e:
            code = str(e.response.get("Error", {}).get("Code", ""))
            status = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if code in ("404", "NoSuchBucket", "NotFound") or status == 404:
                return False
            if code in ("403", "Forbidden", "301", "PermanentRedirect") or status in (301, 403):
                return True
            raise
    return env._memo(("bucket-taken", bucket), load)


def _validate_new_bucket(env, inputs, v) -> str:
    if not isinstance(v, str):
        raise ValueError("type a name for the bucket, e.g. kintsugi-mysite-2026")
    v = v.strip().lower()
    if v in _NOT_A_NAME:
        raise ValueError(f"'{v}' is not a bucket name; type a unique name, e.g. kintsugi-mysite-2026")
    if not _BUCKET_NAME_RE.fullmatch(v) or re.fullmatch(r"\d+\.\d+\.\d+\.\d+", v):
        raise ValueError("3-63 characters: lowercase letters, numbers, dots and hyphens")
    if v in _buckets(env):
        raise ValueError("you already have a bucket with this name; pick it in the list instead")
    if _bucket_taken_elsewhere(env, v):
        raise ValueError(f"the name '{v}' is already used by another AWS account (bucket names are global); "
                         "pick a more unique one")
    return v


def _validate_source(env, inputs, v) -> str:
    p = Path(str(v).strip().strip('"'))
    if not p.is_absolute() or not p.exists():
        raise ValueError(f"file or folder not found: {p}")
    try:
        upload_plan(p.resolve(), "")
    except StepError as e:
        raise ValueError(str(e)) from None
    return str(p.resolve())


def _validate_prefix(env, inputs, v) -> str:
    try:
        from core.local_steps import check_prefix
        return check_prefix(str(v or "").strip())
    except StepError as e:
        raise ValueError(str(e)) from None


def _s3_notes(inputs) -> list[str]:
    return [f"COST: S3 Standard ~${S3_GB_MONTH}/GB-month storage (5 GB free for 12 months) + small request fees. "
            "Objects are encrypted (SSE-S3). Buckets created here stay private (S3 Block Public Access).",
            "Secret-looking files (.env, *.pem, keys, Terraform state) and .git / node_modules are never uploaded."]


UPLOAD_CLASSES = [
    {"value": "STANDARD", "label": "Standard (frequent access, ~$0.023/GB-month)"},
    {"value": "INTELLIGENT_TIERING", "label": "Intelligent-Tiering (AWS moves it automatically)"},
    {"value": "STANDARD_IA", "label": "Standard-IA (infrequent access, ~$0.0125/GB-month)"},
    {"value": "ONEZONE_IA", "label": "One Zone-IA (~$0.01/GB-month, one zone only)"},
    {"value": "GLACIER_IR", "label": "Glacier Instant Retrieval (archive, ms access, ~$0.004/GB-month)"},
    {"value": "GLACIER", "label": "Glacier Flexible Retrieval (archive, restore in minutes-hours, ~$0.0036)"},
    {"value": "DEEP_ARCHIVE", "label": "Glacier Deep Archive (cheapest ~$0.001, restore in 12-48 hours)"},
]


def _build_s3_upload(env, v) -> ScriptDraft:
    source = Path(v["source"])
    steps: list[dict] = []
    if v["bucket"] == "new":
        bucket, region = v["new_bucket"], env.region_name
        params = {"Bucket": bucket}
        if region != "us-east-1":
            params["CreateBucketConfiguration"] = {"LocationConstraint": region}
        steps.append(aws_step("s3", "create_bucket", params, f"Create private bucket {bucket} in {region}",
                              region=region,
                              undo=undo("s3", "delete_bucket", {"Bucket": bucket}, f"Delete bucket {bucket} (if empty)")))
        steps.append(aws_step("s3", "put_bucket_tagging",
                              {"Bucket": bucket, "Tagging": {"TagSet": tag_list(bucket)}}, "Tag the bucket",
                              region=region))
        existing: set[str] = set()
    else:
        bucket = v["bucket"]
        region = _bucket_region(env, bucket)
    try:
        files = upload_plan(source, v.get("prefix", ""))
    except StepError as e:
        raise TemplateError(str(e)) from None
    keys = [k for _, k, _ in files]
    if v["bucket"] != "new":
        existing = _existing_keys(env, bucket, region, keys)
    new_keys = [k for k in keys if k not in existing]
    sc = v.get("storage_class", "STANDARD")
    up = {"kind": "s3_upload", "source": str(source), "bucket": bucket, "prefix": v.get("prefix", ""),
          "region": region, "description": f"Upload {len(files)} file(s) to s3://{bucket}/{v.get('prefix', '')}"
                                           + (f" as {sc}" if sc != "STANDARD" else "")}
    if sc != "STANDARD":
        up["storage_class"] = sc
    if new_keys:
        up["undo"] = undo("s3", "delete_objects", {"Bucket": bucket, "Delete": {
            "Objects": [{"Key": k} for k in new_keys[:1000]], "Quiet": True}},
            f"Delete the {min(len(new_keys), 1000)} uploaded object(s)")
    steps.append(up)
    size = sum(sz for _, _, sz in files)
    notes = _s3_notes(v) + [f"{len(files)} file(s), {size / 1048576:.1f} MB. First key: s3://{bucket}/{keys[0]}"]
    if existing:
        notes.append(f"Warning: {len(existing)} object(s) with the same name already exist and will be OVERWRITTEN "
                     f"(e.g. {sorted(existing)[0]}). The teardown will not delete them.")
    what = source.name if source.is_file() else f"folder {source.name}"
    return ScriptDraft(title=f"Upload {what} to s3://{bucket}/{v.get('prefix', '')}", steps=steps, notes=notes,
                       region=region)


S3_UPLOAD = Template(
    name="s3_upload",
    description="Upload a local file or folder (documents, images, a website, backups) to an S3 bucket",
    fields=[
        FieldSpec("source", "Which file or folder should be uploaded?", "path", must_ask=True,
                  validate=_validate_source, why="Attach it in chat or browse. Secret files are skipped."),
        FieldSpec("bucket", "Which bucket?", "choice", must_ask=True, options=_bucket_options,
                  validate=_validate_bucket, allow_custom=True),
        FieldSpec("new_bucket", "Name for the new bucket (globally unique)?", "text", must_ask=True,
                  default=lambda e, i: f"kintsugi-{e.account_id()}-{_stamp()[:8]}",
                  validate=_validate_new_bucket, relevant=lambda i: i.get("bucket") == "new"),
        FieldSpec("prefix", "Folder (prefix) inside the bucket? Leave empty for the top level.", "text",
                  default="", validate=_validate_prefix, allow_empty=True, why="Example: documents/2026/"),
        FieldSpec("storage_class", "Storage class?", "choice", default="STANDARD",
                  options=lambda e, i: UPLOAD_CLASSES,
                  validate=lambda e, i, v: _choice(UPLOAD_CLASSES, str(v).upper().replace(" ", "_"), "storage class"),
                  why="Archive classes (Glacier, Deep Archive) are much cheaper but must be restored before reading."),
    ],
    title=lambda i: "Upload to S3",
    build=_build_s3_upload, notes=_s3_notes,
)


S3_WEBSITE_DASH_REGIONS = {"us-east-1", "us-west-1", "us-west-2", "ap-southeast-1", "ap-southeast-2",
                           "ap-northeast-1", "eu-west-1", "sa-east-1", "us-gov-west-1"}
BPA_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def website_url(bucket: str, region: str) -> str:
    sep = "-" if region in S3_WEBSITE_DASH_REGIONS else "."
    return f"http://{bucket}.s3-website{sep}{region}.amazonaws.com"


def public_read_policy(bucket: str) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": [{
        "Sid": "PublicReadForWebsite", "Effect": "Allow", "Principal": "*",
        "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"}]})


def _bpa(on: bool) -> dict:
    return {k: on for k in BPA_KEYS}


def account_blocks_public(env) -> bool | None:
    """True when the ACCOUNT-level S3 Block Public Access stops public bucket policies everywhere."""
    from botocore.exceptions import ClientError

    def load():
        try:
            cfg = env.conn.client("s3control", "read", env.region).get_public_access_block(
                AccountId=env.account_id())["PublicAccessBlockConfiguration"]
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchPublicAccessBlockConfiguration":
                return False
            return None
        return bool(cfg.get("BlockPublicPolicy") or cfg.get("RestrictPublicBuckets"))
    return env._memo("account-bpa", load)


def _index_name(source: Path) -> str:
    return source.name if source.is_file() else "index.html"


def _validate_site_source(env, inputs, v) -> str:
    p = Path(str(v).strip().strip('"'))
    if not p.is_absolute() or not p.exists():
        raise ValueError(f"file or folder not found: {p}")
    if p.is_file() and p.suffix.lower() not in (".html", ".htm"):
        raise ValueError("pick the index.html file, or the folder that contains index.html")
    if p.is_dir() and not (p / "index.html").is_file():
        raise ValueError(f"the folder {p.name} has no index.html at its top level")
    try:
        upload_plan(p.resolve(), "", flatten=True)
    except StepError as e:
        raise ValueError(str(e)) from None
    return str(p.resolve())


def _site_bucket_options(env, inputs):
    return [{"value": "new", "label": "Create a new public website bucket"}] + \
           [{"value": b, "label": b} for b in _buckets(env)]


def _validate_site_bucket(env, inputs, v) -> str:
    v = str(v).strip().removeprefix("s3://").strip("/")
    if v.lower() in ("new", "create", "create new"):
        return "new"
    return _choice(_site_bucket_options(env, inputs), v, "bucket (pick one of yours, or 'new')")


def _validate_account_bpa(env, inputs, v) -> str:
    if _yes_no(v) != "yes":
        raise ValueError("the site cannot be public while the account blocks public access; answer yes, or turn "
                         "it off yourself in S3 > Block Public Access settings for this account")
    return "yes"


def _site_notes(inputs) -> list[str]:
    return ["PUBLIC: anyone on the internet who has the link can VIEW every file in this bucket. Do not put "
            "private files in it. The bucket policy only allows reading (s3:GetObject); nobody can upload, change "
            "or delete files through the link.",
            "S3 Block Public Access is turned OFF for this bucket (all 4 settings), so running the script needs "
            "the typed confirmation.",
            f"COST: S3 Standard ~${S3_GB_MONTH}/GB-month + ~$0.09/GB data out after the free tier. With versioning "
            "every overwrite keeps the old copy (also billed).",
            "The website endpoint is HTTP only. For HTTPS put CloudFront in front of it (future recipe)."]


def _build_s3_website(env, v) -> ScriptDraft:
    source = Path(v["source"])
    new = v["bucket"] == "new"
    bucket = v["new_bucket"] if new else v["bucket"]
    region = env.region_name if new else _bucket_region(env, bucket)
    versioning = v.get("versioning", "yes") == "yes"
    try:
        files = upload_plan(source, "", flatten=True)
    except StepError as e:
        raise TemplateError(str(e)) from None
    steps: list[dict] = []
    if v.get("account_bpa") == "yes":
        steps.append(aws_step("s3control", "put_public_access_block",
                              {"AccountId": env.account_id(), "PublicAccessBlockConfiguration": _bpa(False)},
                              "Turn OFF account-level S3 Block Public Access (needed for any public bucket)",
                              undo=undo("s3control", "put_public_access_block",
                                        {"AccountId": env.account_id(), "PublicAccessBlockConfiguration": _bpa(True)},
                                        "Turn account-level S3 Block Public Access back ON")))
    if new:
        params = {"Bucket": bucket, "ObjectOwnership": "BucketOwnerEnforced"}
        if region != "us-east-1":
            params["CreateBucketConfiguration"] = {"LocationConstraint": region}
        steps.append(aws_step("s3", "create_bucket", params, f"Create bucket {bucket} in {region}", region=region,
                              undo=undo("s3", "delete_bucket", {"Bucket": bucket}, f"Delete bucket {bucket}")))
        steps.append(aws_step("s3", "put_bucket_tagging",
                              {"Bucket": bucket, "Tagging": {"TagSet": tag_list(bucket)}}, "Tag the bucket",
                              region=region))
    if versioning:
        steps.append(aws_step("s3", "put_bucket_versioning",
                              {"Bucket": bucket, "VersioningConfiguration": {"Status": "Enabled"}},
                              "Enable bucket versioning (old copies of overwritten/deleted files are kept)",
                              region=region,
                              undo=None if new else undo("s3", "put_bucket_versioning", {
                                  "Bucket": bucket, "VersioningConfiguration": {"Status": "Suspended"}},
                                  "Suspend bucket versioning")))
    steps.append(aws_step("s3", "put_public_access_block",
                          {"Bucket": bucket, "PublicAccessBlockConfiguration": _bpa(False)},
                          "Turn OFF all 4 Block Public Access settings for this bucket", region=region,
                          pause_after=5,
                          undo=undo("s3", "put_public_access_block",
                                    {"Bucket": bucket, "PublicAccessBlockConfiguration": _bpa(True)},
                                    "Turn Block Public Access back ON for this bucket")))
    steps.append(aws_step("s3", "put_bucket_policy", {"Bucket": bucket, "Policy": public_read_policy(bucket)},
                          "Bucket policy: everyone may READ objects (s3:GetObject), nothing else", region=region,
                          undo=undo("s3", "delete_bucket_policy", {"Bucket": bucket}, "Remove the public bucket policy")))
    index = _index_name(source)
    steps.append(aws_step("s3", "put_bucket_website", {"Bucket": bucket, "WebsiteConfiguration": {
        "IndexDocument": {"Suffix": index}, "ErrorDocument": {"Key": index}}},
        f"Turn on static website hosting (index document {index})", region=region,
        undo=undo("s3", "delete_bucket_website", {"Bucket": bucket}, "Turn off static website hosting")))
    keys = [k for _, k, _ in files]
    up = {"kind": "s3_upload", "source": str(source), "bucket": bucket, "prefix": "", "flatten": True,
          "region": region, "description": f"Upload {len(files)} file(s) to the root of s3://{bucket}/"}
    if new:
        up["undo"] = {"kind": "s3_empty", "bucket": bucket,
                      "description": f"Delete every file and old version in {bucket} (so the bucket can be deleted)"}
    else:
        up["undo"] = undo("s3", "delete_objects", {"Bucket": bucket, "Delete": {
            "Objects": [{"Key": k} for k in keys[:1000]], "Quiet": True}},
            f"Delete the {min(len(keys), 1000)} uploaded object(s)")
    steps.append(up)
    url = website_url(bucket, region)
    steps.append(check("http", {"url": url + "/", "expect": 200}, f"Check the website answers at {url}", timeout=180))
    size = sum(sz for _, _, sz in files)
    notes = [f"WEBSITE URL (after the run): {url}"] + _site_notes(v) + \
            [f"{len(files)} file(s), {size / 1048576:.1f} MB, uploaded to the bucket root."]
    if not versioning:
        notes.append("Versioning stays off.")
    if not new:
        notes.append(f"Existing bucket {bucket}: EVERY file already in it also becomes public.")
    return ScriptDraft(title=f"Public static website: s3://{bucket}", steps=steps, notes=notes, region=region)


S3_WEBSITE = Template(
    name="s3_static_website",
    description="Host a static website (index.html or a site folder) in a PUBLIC S3 bucket with website hosting, "
                "optional versioning",
    fields=[
        FieldSpec("source", "Which index.html file, or site folder containing index.html?", "path", must_ask=True,
                  validate=_validate_site_source, why="Attach it in chat or browse. A folder's contents go to the "
                  "bucket root. Secret files are skipped."),
        FieldSpec("bucket", "Which bucket?", "choice", must_ask=True, default="new", options=_site_bucket_options,
                  validate=_validate_site_bucket, allow_custom=True),
        FieldSpec("new_bucket", "Name for the new bucket (globally unique; it is part of the website URL)?", "text",
                  must_ask=True, default=lambda e, i: f"kintsugi-site-{e.account_id()}-{_stamp()[:8]}",
                  validate=_validate_new_bucket, relevant=lambda i: i.get("bucket") == "new"),
        FieldSpec("versioning", "Enable bucket versioning?", "choice", default="yes",
                  options=lambda e, i: [{"value": "yes", "label": "Yes"}, {"value": "no", "label": "No"}],
                  validate=lambda e, i, v: _yes_no(v)),
        FieldSpec("account_bpa", "Your AWS account blocks public access for ALL buckets (account-level Block Public "
                  "Access). Turn that off so this site can be public?", "choice", must_ask=True,
                  options=lambda e, i: [{"value": "yes", "label": "Yes, turn it off for the account"}],
                  validate=_validate_account_bpa, relevant_env=lambda e, i: account_blocks_public(e) is True,
                  why="This affects the whole account, not only this bucket. Each bucket keeps its own block "
                      "settings, so other buckets stay private."),
    ],
    title=lambda i: "Public static website on S3",
    build=_build_s3_website, notes=_site_notes,
)


DB_ENGINES = {
    "postgres": ("PostgreSQL (RDS)", "rds", 5432),
    "mysql": ("MySQL (RDS)", "rds", 3306),
    "mariadb": ("MariaDB (RDS)", "rds", 3306),
    "aurora-postgresql": ("Aurora PostgreSQL (Serverless v2 or provisioned)", "aurora", 5432),
    "aurora-mysql": ("Aurora MySQL (Serverless v2 or provisioned)", "aurora", 3306),
    "dynamodb": ("DynamoDB table (NoSQL key-value, serverless)", "dynamodb", 0),
    "docdb": ("DocumentDB (MongoDB-compatible)", "docdb", 27017),
    "redis": ("Redis OSS cache (ElastiCache)", "redis", 6379),
    "valkey": ("Valkey cache (ElastiCache, Redis-compatible)", "redis", 6379),
    "memcached": ("Memcached cache (ElastiCache)", "memcached", 11211),
    "sqlserver-ex": ("SQL Server Express (RDS)", "rds", 1433),
    "sqlserver-web": ("SQL Server Web (RDS)", "rds", 1433),
    "sqlserver-se": ("SQL Server Standard (RDS)", "rds", 1433),
    "sqlserver-ee": ("SQL Server Enterprise (RDS)", "rds", 1433),
    "oracle-se2": ("Oracle Standard Edition 2 (RDS)", "rds", 1521),
    "oracle-ee": ("Oracle Enterprise Edition (RDS, BYOL)", "rds", 1521),
    "db2-se": ("IBM Db2 Standard Edition (RDS)", "rds", 50000),
    "db2-ae": ("IBM Db2 Advanced Edition (RDS)", "rds", 50000),
}
_SQLSERVER_BIG = ["db.t3.xlarge", "db.m5.large", "db.m5.xlarge", "db.m6i.large", "db.m6i.xlarge", "db.r5.large",
                  "db.r6i.large"]
RDS_CLASS_CANDIDATES = {
    "sqlserver-ex": ["db.t3.micro", "db.t3.small"],
    "sqlserver-web": ["db.t3.small", "db.t3.medium"] + _SQLSERVER_BIG,
    "sqlserver-se": _SQLSERVER_BIG,
    "sqlserver-ee": _SQLSERVER_BIG,
    "oracle-se2": ["db.t3.small", "db.t3.medium", "db.m5.large"],
    "oracle-ee": ["db.t3.medium", "db.m5.large", "db.r5.large"],
    "db2-se": ["db.t3.small", "db.t3.medium", "db.m6i.large"],
    "db2-ae": ["db.m6i.large", "db.r6i.large"],
}
LICENSED_ENGINES = ("oracle-se2", "oracle-ee", "db2-se", "db2-ae")
LICENSE_LABELS = {"license-included": "Licence included in the AWS price",
                  "bring-your-own-license": "Bring your own licence (BYOL)",
                  "marketplace-license": "AWS Marketplace subscription (pay-as-you-go, needs a subscription first)"}
LICENSE_DEFAULTS = {"oracle-se2": ["license-included", "bring-your-own-license"],
                    "oracle-ee": ["bring-your-own-license"],
                    "db2-se": ["bring-your-own-license", "marketplace-license"],
                    "db2-ae": ["bring-your-own-license", "marketplace-license"]}
SHORT_DBNAME_ENGINES = ("oracle-se2", "oracle-ee", "db2-se", "db2-ae")
NO_DBNAME_ENGINES = ("sqlserver-ex", "sqlserver-web", "sqlserver-se", "sqlserver-ee")
NO_MULTI_AZ_ENGINES = ("sqlserver-ex", "sqlserver-web")
NO_REPLICA_ENGINES = ("sqlserver-ex", "sqlserver-web")
IAM_AUTH_ENGINES = ("postgres", "mysql", "mariadb", "aurora-postgresql", "aurora-mysql")
OPTION_GROUP_ENGINES = ("mysql", "mariadb", "oracle-se2", "oracle-ee", "sqlserver-ex", "sqlserver-web",
                        "sqlserver-se", "sqlserver-ee", "db2-se", "db2-ae")
DB_CLASSES = {
    "rds": {"db.t3.micro": 0.018, "db.t4g.micro": 0.016, "db.t3.small": 0.036},
    "aurora": {"db.t4g.medium": 0.073, "db.t3.medium": 0.082, "db.r6g.large": 0.26, "db.r5.large": 0.29},
    "docdb": {"db.t3.medium": 0.078},
    "redis": {"cache.t3.micro": 0.017, "cache.t4g.micro": 0.016, "cache.t3.small": 0.034},
    "memcached": {"cache.t3.micro": 0.017, "cache.t4g.micro": 0.016, "cache.t3.small": 0.034},
}
MORE_CLASSES = {
    "rds": ["db.t4g.small", "db.t3.medium", "db.t4g.medium", "db.t3.large", "db.m6g.large", "db.m5.large",
            "db.m6i.large", "db.r6g.large", "db.r5.large", "db.m6g.xlarge", "db.r6g.xlarge"],
    "aurora": ["db.r6g.xlarge", "db.r6i.large", "db.r7g.large"],
    "docdb": ["db.t4g.medium", "db.r6g.large", "db.r5.large"],
    "redis": ["cache.t4g.small", "cache.t3.medium", "cache.t4g.medium", "cache.m6g.large", "cache.r6g.large"],
    "memcached": ["cache.t4g.small", "cache.t3.medium", "cache.m6g.large", "cache.r6g.large"],
}
CLASS_PRICES = {"db.t4g.small": 0.032, "db.t3.medium": 0.072, "db.t4g.medium": 0.065, "db.t3.large": 0.145,
                "db.m6g.large": 0.152, "db.m5.large": 0.171, "db.m6i.large": 0.171, "db.r6g.large": 0.225,
                "db.r5.large": 0.25, "cache.t4g.small": 0.032, "cache.t3.medium": 0.068, "cache.t4g.medium": 0.065,
                "cache.m6g.large": 0.149, "cache.r6g.large": 0.206}
AURORA_ACU_HOUR, AURORA_MIN_ACU, AURORA_MAX_ACU = 0.12, 0.5, 2.0
RDS_GB_MONTH, DOCDB_IO_NOTE = 0.115, "DocumentDB also bills storage (~$0.10/GB-month) and I/O."
DYNAMO_RCU_HOUR, DYNAMO_WCU_HOUR = 0.00013, 0.00065
LOG_TYPES = {
    "postgres": ["postgresql", "upgrade"], "aurora-postgresql": ["postgresql"],
    "mysql": ["error", "general", "slowquery"], "mariadb": ["error", "general", "slowquery"],
    "aurora-mysql": ["error", "general", "slowquery"],
    "sqlserver-ex": ["error"], "sqlserver-web": ["error", "agent"], "sqlserver-se": ["error", "agent"],
    "sqlserver-ee": ["error", "agent"],
    "oracle-se2": ["alert", "audit", "listener", "trace"], "oracle-ee": ["alert", "audit", "listener", "trace"],
    "db2-se": ["diag.log", "notify.log"], "db2-ae": ["diag.log", "notify.log"],
    "docdb": ["audit", "profiler"],
}
_ENGINE_WORDS = [("aurora-postgresql", ("aurora postgres",)), ("aurora-mysql", ("aurora mysql", "aurora")),
                 ("dynamodb", ("dynamodb", "dynamo db", "dynamo")), ("docdb", ("documentdb", "docdb", "mongo")),
                 ("valkey", ("valkey",)), ("memcached", ("memcached", "memcache")),
                 ("redis", ("redis", "elasticache")),
                 ("db2-ae", ("db2 advanced", "db2 ae")), ("db2-se", ("db2",)),
                 ("oracle-ee", ("oracle enterprise", "oracle ee")), ("oracle-se2", ("oracle",)),
                 ("sqlserver-ee", ("sql server enterprise", "sqlserver enterprise", "mssql enterprise")),
                 ("sqlserver-se", ("sql server standard", "sqlserver standard", "mssql standard")),
                 ("sqlserver-web", ("sql server web", "sqlserver web", "mssql web")),
                 ("sqlserver-ex", ("sql server", "sqlserver", "mssql")), ("mariadb", ("mariadb", "maria db")),
                 ("mysql", ("mysql",)), ("postgres", ("postgres", "postgresql", "psql"))]
YES_NO = [{"value": "yes", "label": "Yes"}, {"value": "no", "label": "No"}]
SETTINGS_OPTIONS = [
    {"value": "default", "label": "Quick: safe, cheap defaults (recommended for a demo)"},
    {"value": "custom", "label": "Customize: versions, size, storage, Multi-AZ, replicas, backups, windows, "
                                 "encryption, logs, parameter groups, any extra AWS setting"},
]
ADVANCED_KEYS = ("engine_version", "aurora_capacity", "storage_type", "iops", "max_storage_gb", "multi_az",
                 "replicas", "cache_nodes", "backup_retention", "read_replicas", "backup_window",
                 "maintenance_window", "min_acu", "max_acu", "port", "encryption_in_transit", "kms_key",
                 "custom_parameter_group", "option_group", "performance_insights", "log_exports", "iam_auth",
                 "auto_minor_upgrade", "deletion_protection", "final_snapshot", "billing_mode", "read_capacity",
                 "write_capacity", "table_class", "gsis", "stream", "ttl_attribute", "pitr", "extra_params")
RESERVED_EXTRA = {"DBInstanceIdentifier", "DBClusterIdentifier", "Engine", "MasterUsername", "MasterUserPassword",
                  "ManageMasterUserPassword", "DBSubnetGroupName", "VpcSecurityGroupIds", "PubliclyAccessible",
                  "Tags", "TableName", "KeySchema", "AttributeDefinitions", "CacheClusterId", "ReplicationGroupId",
                  "CacheSubnetGroupName", "SecurityGroupIds", "AuthToken", "ReplicationGroupDescription"}
STREAM_OPTIONS = [{"value": "off", "label": "Off"}, {"value": "NEW_AND_OLD_IMAGES", "label": "New and old images"},
                  {"value": "NEW_IMAGE", "label": "New image"}, {"value": "OLD_IMAGE", "label": "Old image"},
                  {"value": "KEYS_ONLY", "label": "Keys only"}]
STORAGE_TYPES = [{"value": "gp3", "label": "gp3 (general purpose SSD, recommended)"},
                 {"value": "gp2", "label": "gp2 (older general purpose SSD)"},
                 {"value": "io2", "label": "io2 (provisioned IOPS, high performance, expensive)"},
                 {"value": "io1", "label": "io1 (provisioned IOPS, older)"},
                 {"value": "standard", "label": "magnetic (legacy)"}]


def engine_from_text(text: str) -> str | None:
    t = (text or "").lower()
    for engine, words in _ENGINE_WORDS:
        if any(w in t for w in words):
            return engine
    return None


def _family(inputs) -> str:
    return DB_ENGINES.get(inputs.get("engine"), ("", "", 0))[1]


def _custom(i) -> bool:
    if "settings" in i:
        return i["settings"] == "custom"
    return any(k in i for k in ADVANCED_KEYS)


def _adv(*fams):
    return lambda i: _custom(i) and _family(i) in fams


def _yes(v: dict, key: str, default: str = "no") -> bool:
    return v.get(key, default) == "yes"


def _uses_replication_group(i) -> bool:
    return i.get("engine") == "valkey" or (i.get("engine") == "redis" and _custom(i))


def _validate_engine(env, inputs, v) -> str:
    v = str(v).strip().lower()
    if v in DB_ENGINES:
        return v
    return engine_from_text(v) or _choice(_engine_options(env, inputs), v, "database engine")


def _engine_options(env, inputs):
    out = []
    for k, (label, fam, _) in DB_ENGINES.items():
        if fam == "aurora":
            cost = f"from ~${AURORA_MIN_ACU * AURORA_ACU_HOUR:.2f}/hour"
        elif fam == "dynamodb":
            cost = "pay per request, ~free when idle"
        elif k in RDS_CLASS_CANDIDATES:
            cost = "see AWS pricing" + ("" if k.startswith("sqlserver") else " + licence")
        else:
            cost = f"from ~${min(DB_CLASSES[fam].values())}/hour"
        out.append({"value": k, "label": f"{label} · {cost}"})
    return out


def _settings_default(env, inputs):
    return "custom" if any(k in inputs for k in ADVANCED_KEYS) else "default"


_db_name = _name_validator(r"[a-z](?!.*--)[a-z0-9-]{0,38}[a-z0-9]",
                           "lowercase letters, numbers and - (2-40), start with a letter, no '--', not ending in '-'")


def _validate_username(env, inputs, v) -> str:
    v = str(v).strip()
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,15}", v):
        raise ValueError("start with a letter; letters, numbers and _ only (max 16)")
    if v.lower() in ("rdsadmin", "rdsrepladmin", "root", "serviceadmin", "sa", "sys", "system", "db2inst1"):
        raise ValueError(f"'{v}' is reserved by AWS or the database engine; pick another name")
    return v


def _validate_initial_db(env, inputs, v) -> str:
    v = str(v).strip()
    if inputs.get("engine") in SHORT_DBNAME_ENGINES:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,7}", v):
            raise ValueError("Oracle/Db2: start with a letter; letters and numbers only (max 8)")
        return v.upper()
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,62}", v):
        raise ValueError("start with a letter; letters, numbers and _ only (max 63)")
    return v


def _validate_key_name(env, inputs, v) -> str:
    v = str(v).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", v):
        raise ValueError("letters, numbers, _ . - only")
    return v


def _validate_sort_key(env, inputs, v) -> str:
    v = str(v or "").strip()
    if v and v == inputs.get("partition_key"):
        raise ValueError("the sort key must differ from the partition key")
    return _validate_key_name(env, inputs, v) if v else ""


def _orderable(env, engine: str, cls: str) -> list[dict]:
    """What AWS can create for this engine and size in the region (read-only; [] = not offered)."""
    def load():
        rds = env.conn.client("rds", "read", env.region)
        return rds.describe_orderable_db_instance_options(Engine=engine, DBInstanceClass=cls, Vpc=True,
                                                          MaxRecords=20)["OrderableDBInstanceOptions"]
    return env._memo(("orderable", engine, cls), load)


def _price_label(cls: str, fam: str) -> str:
    price = DB_CLASSES.get(fam, {}).get(cls) or CLASS_PRICES.get(cls)
    return f"{cls} (~${price}/hour)" if price else f"{cls} (see AWS pricing)"


def _class_options(env, inputs):
    engine, fam = inputs.get("engine"), _family(inputs)
    if engine in RDS_CLASS_CANDIDATES:
        out = []
        for c in RDS_CLASS_CANDIDATES[engine]:
            try:
                if not _orderable(env, engine, c):
                    continue
            except Exception:
                pass
            out.append({"value": c, "label": f"{c} (see AWS pricing; licence costs extra unless included)"})
        return out
    classes = list(DB_CLASSES.get(fam, {}))
    if _custom(inputs) or fam == "aurora":
        classes += [c for c in MORE_CLASSES.get(fam, []) if c not in classes]
    return [{"value": c, "label": _price_label(c, fam)} for c in classes]


def _validate_class(env, inputs, v) -> str:
    v = str(v).strip()
    opts = _class_options(env, inputs)
    if v in [o["value"] for o in opts]:
        return v
    fam = _family(inputs)
    prefix = "cache." if fam in ("redis", "memcached") else "db."
    if _custom(inputs) and re.fullmatch(re.escape(prefix) + r"[a-z0-9-]+\.[a-z0-9]+", v):
        if fam in ("rds", "aurora"):
            try:
                if not _orderable(env, inputs["engine"], v):
                    raise ValueError(f"AWS does not offer {v} for {inputs['engine']} in this region")
            except ValueError:
                raise
            except Exception:
                pass
        return v
    return _choice(opts, v, "size")


def _license_options(env, inputs):
    engine, cls = inputs.get("engine"), inputs.get("instance_class")
    models = []
    if cls:
        try:
            models = sorted({o["LicenseModel"] for o in _orderable(env, engine, cls)})
        except Exception:
            models = []
    models = models or LICENSE_DEFAULTS.get(engine, [])
    return [{"value": m, "label": LICENSE_LABELS.get(m, m)} for m in models]


def _db2_group_options(env, inputs):
    from core.prereqs import db_parameter_groups
    return [{"value": g, "label": g} for g in db_parameter_groups(env, "db2")]


def _version_options(env, inputs):
    engine, fam = inputs.get("engine"), _family(inputs)

    def load():
        out = []
        try:
            if fam in ("rds", "aurora", "docdb"):
                client = env.conn.client("docdb" if fam == "docdb" else "rds", "read", env.region)
                for page in client.get_paginator("describe_db_engine_versions").paginate(Engine=engine):
                    out += [(x["EngineVersion"], x.get("DBEngineVersionDescription", "")) for x in page["DBEngineVersions"]]
            elif fam in ("redis", "memcached"):
                client = env.conn.client("elasticache", "read", env.region)
                for page in client.get_paginator("describe_cache_engine_versions").paginate(Engine=engine):
                    out += [(x["EngineVersion"], x.get("CacheEngineVersionDescription", ""))
                            for x in page["CacheEngineVersions"]]
        except Exception:
            return []
        return out
    versions = env._memo(("versions", engine), load)
    return [{"value": "default", "label": "AWS default version (recommended)"}] + \
           [{"value": ver, "label": f"{ver} · {desc}" if desc else ver} for ver, desc in reversed(versions[-30:])]


def _validate_version(env, inputs, v) -> str:
    v = str(v or "").strip()
    if v.lower() in ("", "default", "latest"):
        return "default"
    opts = [o["value"] for o in _version_options(env, inputs)]
    if len(opts) > 1 and v not in opts:
        raise ValueError(f"AWS does not offer version {v} for {inputs.get('engine')} here; pick one from the list")
    if not re.fullmatch(r"[0-9][0-9A-Za-z._-]{0,40}", v):
        raise ValueError("an engine version looks like 16.4 or 8.0.39")
    return v


def _lookup_names(env, key, fn) -> list[str]:
    def load():
        try:
            return fn()
        except Exception:
            return []
    return env._memo(key, load)


def _param_group_options(env, inputs):
    engine, fam = inputs.get("engine"), _family(inputs)

    def fetch():
        if fam == "rds":
            c, op, lst, nm, famkey = "rds", "describe_db_parameter_groups", "DBParameterGroups", "DBParameterGroupName", "DBParameterGroupFamily"
        elif fam in ("aurora", "docdb"):
            c, op, lst, nm, famkey = ("docdb" if fam == "docdb" else "rds", "describe_db_cluster_parameter_groups",
                                      "DBClusterParameterGroups", "DBClusterParameterGroupName", "DBParameterGroupFamily")
        else:
            c, op, lst, nm, famkey = "elasticache", "describe_cache_parameter_groups", "CacheParameterGroups", "CacheParameterGroupName", "CacheParameterGroupFamily"
        client = env.conn.client(c, "read", env.region)
        out = []
        for page in client.get_paginator(op).paginate():
            out += [g[nm] for g in page[lst] if g.get(famkey, "").startswith(engine.split("-")[0])
                    and not g[nm].startswith("default.")]
        return sorted(out)
    names = _lookup_names(env, ("pgroups", engine), fetch)
    return [{"value": "default", "label": "AWS default parameter group"}] + [{"value": n, "label": n} for n in names]


def _option_group_options(env, inputs):
    engine = inputs.get("engine")

    def fetch():
        rds = env.conn.client("rds", "read", env.region)
        out = []
        for page in rds.get_paginator("describe_option_groups").paginate(EngineName=engine):
            out += [g["OptionGroupName"] for g in page["OptionGroupsList"] if not g["OptionGroupName"].startswith("default:")]
        return sorted(out)
    names = _lookup_names(env, ("ogroups", engine), fetch)
    return [{"value": "default", "label": "AWS default option group"}] + [{"value": n, "label": n} for n in names]


def _validate_group_name(env, inputs, v) -> str:
    v = str(v or "").strip()
    if v.lower() in ("", "default", "none"):
        return "default"
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,254}", v):
        raise ValueError("a group name: letters, numbers and - only, starting with a letter")
    return v


_WINDOW = r"([01]\d|2[0-3]):[0-5]\d"
_DAY = r"(mon|tue|wed|thu|fri|sat|sun)"


def _validate_backup_window(env, inputs, v) -> str:
    v = str(v or "").strip()
    if v and not re.fullmatch(f"{_WINDOW}-{_WINDOW}", v):
        raise ValueError("format hh:mm-hh:mm in UTC, at least 30 minutes, e.g. 20:00-21:00 (empty = AWS picks)")
    return v


def _validate_maintenance_window(env, inputs, v) -> str:
    v = str(v or "").strip().lower()
    if v and not re.fullmatch(f"{_DAY}:{_WINDOW}-{_DAY}:{_WINDOW}", v):
        raise ValueError("format ddd:hh:mm-ddd:hh:mm in UTC, e.g. sun:21:00-sun:22:00 (empty = AWS picks)")
    return v


_KMS_RE = re.compile(r"arn:aws[\w-]*:kms:[a-z0-9-]+:\d{12}:(key|alias)/[\w/+=,.@-]+|alias/[\w/+=,.@-]+|"
                     r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32}")


def _validate_kms(env, inputs, v) -> str:
    v = str(v or "").strip()
    if v and not _KMS_RE.fullmatch(v):
        raise ValueError("a KMS key ID, key ARN or alias/name (empty = the AWS-managed key)")
    return v


def _float(v, lo: float, hi: float, what: str) -> float:
    try:
        n = float(str(v).strip())
    except ValueError:
        raise ValueError(f"{what} must be a number") from None
    if not lo <= n <= hi:
        raise ValueError(f"{what} must be between {lo:g} and {hi:g}")
    return n


def _validate_min_acu(env, inputs, v) -> float:
    n = _float(v, 0, 256, "minimum ACU")
    if n * 2 != int(n * 2):
        raise ValueError("ACU values go in steps of 0.5")
    return n


def _validate_max_acu(env, inputs, v) -> float:
    n = _float(v, 1, 256, "maximum ACU")
    if n * 2 != int(n * 2):
        raise ValueError("ACU values go in steps of 0.5")
    if n < float(inputs.get("min_acu", AURORA_MIN_ACU)):
        raise ValueError("the maximum must be at least the minimum")
    return n


def _validate_storage(env, inputs, v) -> int:
    return _int(v, 20, 65536 if _custom(inputs) else 100, "storage (GB)")


def _iops_default(env, inputs):
    return 0 if inputs.get("storage_type", "gp3") == "gp3" else 3000


def _validate_iops(env, inputs, v) -> int:
    st = inputs.get("storage_type", "gp3")
    n = _int(v, 0, 256000, "IOPS")
    if st == "gp3" and n and not 3000 <= n <= 80000:
        raise ValueError("gp3: 0 (baseline, included) or 3000-80000 (only for larger volumes, often 400 GB+)")
    if st in ("io1", "io2") and n < 1000:
        raise ValueError(f"{st} needs at least 1000 IOPS")
    return n


def _validate_max_storage(env, inputs, v) -> int:
    n = _int(v, 0, 65536, "maximum storage (GB)")
    if n and n <= int(inputs.get("storage_gb", 20)):
        raise ValueError("must be larger than the storage size (or 0 to turn storage autoscaling off)")
    return n


def _validate_replicas(env, inputs, v) -> int:
    hi = 5 if _family(inputs) == "redis" else 15
    return _int(v, 0, hi, "replicas")


def _validate_multi_az(env, inputs, v) -> str:
    v = _yes_no(v)
    if v == "yes" and _family(inputs) == "redis" and int(inputs.get("replicas", 0)) == 0:
        raise ValueError("Multi-AZ for a cache needs at least 1 replica")
    return v


def _backup_default(env, inputs):
    return 0 if _family(inputs) == "redis" else 1


def _validate_backup_retention(env, inputs, v) -> int:
    lo = 1 if _family(inputs) in ("aurora", "docdb") else 0
    return _int(v, lo, 35, "backup retention (days)")


def _validate_read_replicas(env, inputs, v) -> int:
    n = _int(v, 0, 5, "read replicas")
    if n and int(inputs.get("backup_retention", 1)) < 1:
        raise ValueError("read replicas need automated backups (backup retention of at least 1 day)")
    return n


def _port_default(env, inputs):
    return DB_ENGINES.get(inputs.get("engine"), ("", "", 0))[2]


def _validate_port(env, inputs, v) -> int:
    if _family(inputs) in ("redis", "memcached"):
        return _int(v, 1024, 65535, "port")
    return _int(v, 1150, 65535, "port")


def _validate_capacity(env, inputs, v) -> int:
    return _int(v, 1, 40000, "capacity units")


def parse_gsis(text: str) -> list[tuple[str, str, str, str, str]]:
    """'byCustomer:customer_id:S; byDate:customer_id:S:created_at:N' -> [(name, pk, pk_type, sk, sk_type)]."""
    out = []
    for part in re.split(r"[;\n]+", text or ""):
        part = part.strip()
        if not part:
            continue
        bits = [b.strip() for b in part.split(":")]
        if len(bits) not in (3, 5) or any(not b for b in bits):
            raise ValueError(f"'{part}': use name:partition_key:S|N|B or name:pk:S:sort_key:N")
        name, pk, pkt = bits[:3]
        sk, skt = (bits[3], bits[4]) if len(bits) == 5 else ("", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", name):
            raise ValueError(f"index name '{name}': 3-255 letters, numbers, _ . -")
        for t in (pkt, skt):
            if t and t.upper() not in ("S", "N", "B"):
                raise ValueError(f"'{part}': attribute types are S (string), N (number) or B (binary)")
        out.append((name, pk, pkt.upper(), sk, skt.upper()))
    if len(out) > 20:
        raise ValueError("DynamoDB allows at most 20 global secondary indexes")
    if len({g[0] for g in out}) != len(out):
        raise ValueError("index names must be unique")
    return out


def _validate_gsis(env, inputs, v) -> str:
    gsis = parse_gsis(str(v or ""))
    types = {inputs.get("partition_key"): inputs.get("partition_key_type", "S")}
    if inputs.get("sort_key"):
        types[inputs["sort_key"]] = inputs.get("sort_key_type", "S")
    for name, pk, pkt, sk, skt in gsis:
        for a, t in ((pk, pkt), (sk, skt)):
            if a and types.setdefault(a, t) != t:
                raise ValueError(f"attribute '{a}' is used with two different types")
    return "; ".join(":".join(x for x in g if x) for g in gsis)


def _validate_ttl(env, inputs, v) -> str:
    v = str(v or "").strip()
    return _validate_key_name(env, inputs, v) if v else ""


def _main_operation(i) -> tuple[str, str]:
    fam = _family(i)
    if fam == "rds":
        return "rds", "create_db_instance"
    if fam == "aurora":
        return "rds", "create_db_cluster"
    if fam == "docdb":
        return "docdb", "create_db_cluster"
    if fam == "dynamodb":
        return "dynamodb", "create_table"
    return "elasticache", "create_replication_group" if _uses_replication_group(i) else "create_cache_cluster"


def _validate_extra(env, inputs, v) -> str:
    """Any other AWS setting of the main create call, checked against the botocore API model."""
    import difflib
    from botocore.validate import ParamValidator
    from core.scripts import ScriptError, _model_client, check_write_allowed
    if isinstance(v, dict):
        obj = v
    else:
        s = str(v or "").strip()
        if not s or s == "{}":
            return ""
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            raise ValueError('must be a JSON object, e.g. {"StorageThroughput": 500, "CACertificateIdentifier": '
                             '"rds-ca-rsa2048-g1"}') from None
    if not isinstance(obj, dict):
        raise ValueError("must be a JSON object of AWS parameter names and values")
    if not obj:
        return ""
    service, op = _main_operation(inputs)
    client = _model_client(service)
    shape = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op]).input_shape
    members = list(shape.members)
    for k in obj:
        if k in RESERVED_EXTRA:
            raise ValueError(f"'{k}' is set by the recipe itself (use the matching question instead)")
        if k not in shape.members:
            near = difflib.get_close_matches(k, members, n=3)
            raise ValueError(f"'{k}' is not a parameter of {service}.{op}"
                             + (f"; did you mean {', '.join(near)}?" if near else ""))
    report = ParamValidator().validate(obj, shape)
    if report.has_errors():
        lines = [ln for ln in report.generate_report().splitlines()[1:] if "Missing required parameter" not in ln]
        if lines:
            raise ValueError("; ".join(ln.strip() for ln in lines)[:300])
    try:
        check_write_allowed(service, op, obj)
    except ScriptError as e:
        raise ValueError(str(e)) from None
    return json.dumps(obj, sort_keys=True)


def _db_subnet_options(env, inputs):
    public_only = inputs.get("access") == "my_ip"
    return [{"value": s["id"], "label": f"{s['id']} · {s['az']} · {s['cidr']} · "
                                        f"{'public' if s['public'] else 'private'} · {s['vpc_name'] or s['vpc']}"}
            for s in env.subnets() if s["public"] or not public_only]


def _db_subnet_default(env, inputs):
    """Two subnets in different AZs of one VPC; private ones first (a database should not face the internet)."""
    subs = [s for s in env.subnets() if s["public"] or inputs.get("access") != "my_ip"]
    for vpc in dict.fromkeys(s["vpc"] for s in subs):
        picked, azs = [], set()
        for s in sorted((s for s in subs if s["vpc"] == vpc), key=lambda s: s["public"]):
            if s["az"] not in azs:
                picked.append(s["id"])
                azs.add(s["az"])
        if len(picked) >= 2:
            return picked[:2]
    return None


def _validate_db_subnets(env, inputs, v) -> list[str]:
    ids = [x.strip() for x in (v if isinstance(v, list) else str(v).split(",")) if str(x).strip()]
    subs = {s["id"]: s for s in env.subnets()}
    bad = [x for x in ids if x not in subs]
    if bad:
        raise ValueError(f"not a subnet in this region: {', '.join(bad)}")
    if len({subs[x]["vpc"] for x in ids}) > 1:
        raise ValueError("all subnets must be in the same VPC")
    if len({subs[x]["az"] for x in ids}) < 2:
        raise ValueError("AWS needs subnets in at least 2 different availability zones for a database")
    if inputs.get("access") == "my_ip" and not all(subs[x]["public"] for x in ids):
        raise ValueError("a database reachable from your IP needs public subnets")
    return ids


ACCESS_OPTIONS = [
    {"value": "vpc", "label": "Private: only from inside the VPC (EC2, Lambda, ECS in the same VPC) - safest"},
    {"value": "my_ip", "label": "Also from my computer: public endpoint, open only to my IP (needs public subnets)"},
]
AURORA_CAPACITY = [{"value": "serverless", "label": "Serverless v2 (scales with load, pay per ACU-hour)"},
                   {"value": "provisioned", "label": "Provisioned instances (fixed size, pick an instance class)"}]
BILLING_MODES = [{"value": "on_demand", "label": "On-demand (pay per request, ~free when idle)"},
                 {"value": "provisioned", "label": "Provisioned capacity (fixed read/write units; 25 each free)"}]
TABLE_CLASSES = [{"value": "STANDARD", "label": "Standard"},
                 {"value": "STANDARD_INFREQUENT_ACCESS", "label": "Standard-Infrequent Access (cheaper storage)"}]


def _node_count(i) -> int:
    fam = _family(i)
    if fam == "rds":
        return (2 if i.get("multi_az") == "yes" else 1) + int(i.get("read_replicas", 0) or 0)
    if fam in ("aurora", "docdb", "redis"):
        return 1 + int(i.get("replicas", 0) or 0)
    if fam == "memcached":
        return int(i.get("cache_nodes", 1) or 1)
    return 1


def _db_notes(inputs) -> list[str]:
    fam = _family(inputs)
    if not fam:
        return []
    if fam == "dynamodb":
        if inputs.get("billing_mode") == "provisioned":
            r, w = int(inputs.get("read_capacity", 5) or 5), int(inputs.get("write_capacity", 5) or 5)
            gsis = len(parse_gsis(inputs.get("gsis", ""))) if inputs.get("gsis") else 0
            hourly = (r * DYNAMO_RCU_HOUR + w * DYNAMO_WCU_HOUR) * (1 + gsis)
            notes = [f"COST: provisioned {r} RCU / {w} WCU (each index too) ~${hourly:.4f}/hour "
                     f"(~${hourly * HOURS_PER_MONTH:.2f}/month) + $0.25/GB-month storage. 25 RCU/25 WCU are free."]
        else:
            notes = ["COST: on-demand DynamoDB, ~$1.25 per million writes and ~$0.25 per million reads, $0.25/GB-month "
                     "storage (25 GB free). Nothing is charged while idle. Approximate prices; verify."]
        if inputs.get("pitr") == "yes":
            notes.append("Point-in-time recovery adds ~$0.20/GB-month.")
        if inputs.get("deletion_protection") == "yes":
            notes.append("Deletion protection is on; the teardown turns it off first, then deletes the table.")
        return notes + ["Run the teardown script to delete the table (and all its data) when you are done."]
    notes = []
    count = _node_count(inputs)
    if fam == "aurora" and inputs.get("aurora_capacity", "serverless") == "serverless":
        lo = float(inputs.get("min_acu", AURORA_MIN_ACU) or 0)
        hi = float(inputs.get("max_acu", AURORA_MAX_ACU) or AURORA_MAX_ACU)
        hourly = lo * AURORA_ACU_HOUR * count
        notes.append(f"COST: Aurora Serverless v2 scales {lo:g}-{hi:g} ACU at ~${AURORA_ACU_HOUR}/ACU-hour per "
                     f"instance ({count} instance(s)): at least ~${hourly:.2f}/hour (~${hourly * HOURS_PER_MONTH:.0f}"
                     f"/month) while it exists, up to ~${hi * AURORA_ACU_HOUR * count:.2f}/hour under load, plus "
                     f"storage and I/O. This can exceed a $5 budget in a few days."
                     + (" Min 0 ACU = auto-pause when idle (needs a recent engine version)." if lo == 0 else ""))
    else:
        engine = inputs.get("engine")
        cls = inputs.get("instance_class") or (RDS_CLASS_CANDIDATES.get(engine) or list(DB_CLASSES[fam]))[0]
        hourly = DB_CLASSES[fam].get(cls) or CLASS_PRICES.get(cls)
        extra = ""
        if fam == "rds":
            gb = int(inputs.get("storage_gb", 20) or 20)
            copies = count
            extra = f" + {gb} GB storage x{copies} ~${gb * RDS_GB_MONTH * copies:.2f}/month"
            if inputs.get("storage_type") in ("io1", "io2") or int(inputs.get("iops", 0) or 0):
                extra += " + provisioned IOPS (billed per IOPS-month)"
        if engine in RDS_CLASS_CANDIDATES:
            lic = inputs.get("license_model", "")
            notes.append(f"COST: {engine} on {cls} x{count}: check the AWS pricing page for this engine{extra}. "
                         + ("Licence is included in the hourly price." if lic == "license-included" or
                            engine.startswith("sqlserver") else
                            "Marketplace: IBM bills an extra hourly fee." if lic == "marketplace-license" else
                            "BYOL: you pay your licence vendor separately.")
                         + " Commercial engines cost much more than PostgreSQL/MySQL and are not free tier "
                           "(SQL Server Express on db.t3.micro may be; verify).")
        elif hourly:
            notes.append(f"COST: {cls} ~${hourly}/hour x{count} node(s) = ~${hourly * count:.3f}/hour "
                         f"(~${hourly * count * HOURS_PER_MONTH:.0f}/month){extra}. Approximate us-east-1 prices; "
                         f"verify current pricing."
                         + (" db.t3.micro/db.t4g.micro RDS is in the 12-month free tier (750 h/month, single-AZ)."
                            if fam == "rds" and count == 1 else ""))
        else:
            notes.append(f"COST: {cls} x{count}: see the AWS pricing page{extra}.")
        if fam == "docdb":
            notes.append(DOCDB_IO_NOTE)
    if fam in ("rds", "aurora", "docdb"):
        notes.append("The master password is created by AWS and kept in Secrets Manager (the app never sees it). "
                     "Find it in the AWS console: Secrets Manager -> the secret named rds!db-... or rds!cluster-....")
    if _uses_replication_group(inputs) and inputs.get("encryption_in_transit", "yes") == "yes":
        notes.append("Encryption in transit is on: clients must connect with TLS (e.g. redis-cli --tls).")
    if inputs.get("extra_params"):
        notes.append(f"Extra AWS settings added to the create call: {inputs['extra_params']}")
    notes.append("Creating it takes about 5-15 minutes (longer with replicas/Multi-AZ); the script waits until it "
                 "is available.")
    if inputs.get("access") == "my_ip":
        notes.append("Public endpoint: only the IP you entered may connect (security group). Running it needs the "
                     "typed confirmation.")
    if inputs.get("deletion_protection") == "yes":
        notes.append("Deletion protection is on; the teardown turns it off first, then deletes.")
    snap = "keeps a FINAL SNAPSHOT (billed as backup storage until you delete it)" \
        if inputs.get("final_snapshot") == "yes" else "deletes it WITHOUT a final snapshot (all data is lost)"
    notes.append(f"Run the teardown script when you are done: it {snap}, then its security group and subnet group.")
    return notes


def _db_security_group(name: str, v: dict, sub: dict, port: int) -> list[dict]:
    sources = [(sub["vpc_cidr"] or sub["cidr"], "clients inside the VPC")]
    if v.get("access") == "my_ip":
        sources.append((v["admin_cidr"], "your IP"))
    return [
        aws_step("ec2", "create_security_group",
                 {"GroupName": f"{name}-db-{_stamp()}", "Description": f"Kintsugi database {name}",
                  "VpcId": sub["vpc"], "TagSpecifications": templates._tags("security-group", f"{name}-db-sg")},
                 f"Create security group for {name}", save_as="sg",
                 undo=undo("ec2", "delete_security_group", {"GroupId": "{{sg.GroupId}}"}, "Delete the security group")),
        aws_step("ec2", "authorize_security_group_ingress",
                 {"GroupId": "{{sg.GroupId}}", "IpPermissions": [
                     {"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                      "IpRanges": [{"CidrIp": c, "Description": d} for c, d in sources]}]},
                 f"Allow the database port {port} only from " + " and ".join(c for c, _ in sources)),
    ]


def _protection_step(service: str, arn_ref: str, off: dict, what: str) -> dict:
    """A harmless tag step whose undo turns deletion protection off, so the teardown can delete afterwards."""
    tags = [{"Key": "kintsugi-deletion-protection", "Value": "on"}]
    if service == "dynamodb":
        op, params = "tag_resource", {"ResourceArn": arn_ref, "Tags": tags}
    else:
        op, params = "add_tags_to_resource", {"ResourceName": arn_ref, "Tags": tags}
    return aws_step(service, op, params, f"Mark {what} as deletion-protected",
                    undo=undo(service, off["operation"], off["params"], f"Turn off deletion protection of {what}",
                              pause_after=15))


def _set(params: dict, key: str, value, when=True) -> None:
    if when and value not in (None, "", "default"):
        params[key] = value


def _final(v: dict, key: str, name: str) -> dict:
    if v.get("final_snapshot") == "yes":
        return {key: f"{name}-final-{_stamp()}"}
    return {}


def _build_dynamodb(env, v, name, tags) -> ScriptDraft:
    custom = _custom(v)
    types = {v["partition_key"]: v["partition_key_type"]}
    keys = [{"AttributeName": v["partition_key"], "KeyType": "HASH"}]
    if v.get("sort_key"):
        types[v["sort_key"]] = v["sort_key_type"]
        keys.append({"AttributeName": v["sort_key"], "KeyType": "RANGE"})
    provisioned = custom and v.get("billing_mode") == "provisioned"
    throughput = {"ReadCapacityUnits": int(v.get("read_capacity", 5)), "WriteCapacityUnits": int(v.get("write_capacity", 5))}
    gsis = []
    for gname, pk, pkt, sk, skt in parse_gsis(v.get("gsis", "")) if custom else []:
        types.setdefault(pk, pkt)
        ks = [{"AttributeName": pk, "KeyType": "HASH"}]
        if sk:
            types.setdefault(sk, skt)
            ks.append({"AttributeName": sk, "KeyType": "RANGE"})
        g = {"IndexName": gname, "KeySchema": ks, "Projection": {"ProjectionType": "ALL"}}
        if provisioned:
            g["ProvisionedThroughput"] = dict(throughput)
        gsis.append(g)
    sse = {"Enabled": True}
    if custom and v.get("kms_key"):
        sse.update({"SSEType": "KMS", "KMSMasterKeyId": v["kms_key"]})
    protect = custom and _yes(v, "deletion_protection")
    params = {"TableName": name, "AttributeDefinitions": [{"AttributeName": a, "AttributeType": t} for a, t in types.items()],
              "KeySchema": keys, "BillingMode": "PROVISIONED" if provisioned else "PAY_PER_REQUEST",
              "SSESpecification": sse, "DeletionProtectionEnabled": protect, "Tags": tags}
    _set(params, "ProvisionedThroughput", throughput, provisioned)
    _set(params, "GlobalSecondaryIndexes", gsis, bool(gsis))
    if custom:
        _set(params, "TableClass", v.get("table_class"), v.get("table_class") not in (None, "STANDARD"))
        if v.get("stream", "off") != "off":
            params["StreamSpecification"] = {"StreamEnabled": True, "StreamViewType": v["stream"]}
        params.update(json.loads(v["extra_params"]) if v.get("extra_params") else {})
    mode = "provisioned" if provisioned else "on-demand"
    steps = [aws_step(
        "dynamodb", "create_table", params,
        f"Create DynamoDB table {name} ({mode}, encrypted{', ' + str(len(gsis)) + ' index(es)' if gsis else ''})",
        save_as="table", wait={"waiter": "table_exists", "params": {"TableName": name}},
        undo=undo("dynamodb", "delete_table", {"TableName": name}, f"Delete table {name} and all its data",
                  wait={"waiter": "table_not_exists", "params": {"TableName": name}}))]
    if protect:
        steps.append(_protection_step("dynamodb", "{{table.TableDescription.TableArn}}", {
            "operation": "update_table", "params": {"TableName": name, "DeletionProtectionEnabled": False}},
            f"table {name}"))
    if custom and v.get("ttl_attribute"):
        steps.append(aws_step("dynamodb", "update_time_to_live", {"TableName": name, "TimeToLiveSpecification": {
            "Enabled": True, "AttributeName": v["ttl_attribute"]}},
            f"Turn on TTL: items expire at the epoch time in '{v['ttl_attribute']}'"))
    if custom and _yes(v, "pitr"):
        steps.append(aws_step("dynamodb", "update_continuous_backups", {"TableName": name,
                              "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True}},
                              "Turn on point-in-time recovery (continuous backups, 35 days)"))
    return ScriptDraft(title=f"DynamoDB table {name}", steps=steps, notes=_db_notes(v))


def _build_database(env, v) -> ScriptDraft:
    engine, name = v["engine"], v["name"]
    label, fam, default_port = DB_ENGINES[engine]
    tags = tag_list(name)
    if fam == "dynamodb":
        return _build_dynamodb(env, v, name, tags)

    custom = _custom(v)
    extra = json.loads(v["extra_params"]) if custom and v.get("extra_params") else {}
    port = int(v.get("port") or default_port) if custom else default_port
    sub = {s["id"]: s for s in env.subnets()}[v["subnets"][0]]
    public = v.get("access") == "my_ip"
    protect = custom and _yes(v, "deletion_protection")
    steps = _db_security_group(name, v, sub, port)
    long_wait = {"delay": 30, "max_attempts": 80}
    version = v.get("engine_version") if custom else None
    logs = LOG_TYPES.get(engine, []) if custom and _yes(v, "log_exports") else []
    pgroup = v.get("custom_parameter_group") if custom else None
    if fam in ("rds", "aurora"):
        steps.append(aws_step(
            "rds", "create_db_subnet_group",
            {"DBSubnetGroupName": f"{name}-subnets", "DBSubnetGroupDescription": f"Kintsugi database {name}",
             "SubnetIds": v["subnets"], "Tags": tags},
            f"Create DB subnet group {name}-subnets ({len(v['subnets'])} subnets)",
            undo=undo("rds", "delete_db_subnet_group", {"DBSubnetGroupName": f"{name}-subnets"},
                      "Delete the DB subnet group")))
        common = {"MasterUsername": v["username"], "ManageMasterUserPassword": True,
                  "DBSubnetGroupName": f"{name}-subnets", "VpcSecurityGroupIds": ["{{sg.GroupId}}"],
                  "StorageEncrypted": True, "BackupRetentionPeriod": int(v.get("backup_retention", 1)),
                  "DeletionProtection": protect, "Tags": tags}
        if custom:
            _set(common, "PreferredBackupWindow", v.get("backup_window"))
            _set(common, "PreferredMaintenanceWindow", v.get("maintenance_window"))
            _set(common, "KmsKeyId", v.get("kms_key"))
            _set(common, "EnableCloudwatchLogsExports", logs, bool(logs))
            _set(common, "EnableIAMDatabaseAuthentication", True, _yes(v, "iam_auth") and engine in IAM_AUTH_ENGINES)
            _set(common, "EngineVersion", version)
            common["Port"] = port
    if fam == "rds":
        params = {"DBInstanceIdentifier": name, "Engine": engine, "DBInstanceClass": v["instance_class"],
                  "AllocatedStorage": v["storage_gb"], "StorageType": v.get("storage_type", "gp3") if custom else "gp3",
                  "MultiAZ": custom and _yes(v, "multi_az") and engine not in NO_MULTI_AZ_ENGINES,
                  "PubliclyAccessible": public, "CopyTagsToSnapshot": True, **common}
        _set(params, "DBName", v.get("initial_db"))
        if v.get("license_model"):
            params["LicenseModel"] = v["license_model"]
        elif engine.startswith("sqlserver"):
            params["LicenseModel"] = "license-included"
        _set(params, "DBParameterGroupName", v.get("parameter_group"))
        if custom:
            _set(params, "DBParameterGroupName", pgroup, "DBParameterGroupName" not in params)
            _set(params, "OptionGroupName", v.get("option_group"), engine in OPTION_GROUP_ENGINES)
            _set(params, "Iops", int(v.get("iops", 0) or 0) or None, params["StorageType"] in ("gp3", "io1", "io2"))
            _set(params, "MaxAllocatedStorage", int(v.get("max_storage_gb", 0) or 0) or None)
            _set(params, "EnablePerformanceInsights", True, _yes(v, "performance_insights"))
            params["AutoMinorVersionUpgrade"] = _yes(v, "auto_minor_upgrade", "yes")
            params.update(extra)
        az = " Multi-AZ" if params["MultiAZ"] else ""
        steps.append(aws_step(
            "rds", "create_db_instance", params,
            f"Create {label} {name} ({v['instance_class']}{az}, {v['storage_gb']} GB) - takes 5-15 minutes",
            save_as="db", wait={"waiter": "db_instance_available", "params": {"DBInstanceIdentifier": name}, **long_wait},
            undo=undo("rds", "delete_db_instance",
                      {"DBInstanceIdentifier": name, "DeleteAutomatedBackups": True,
                       "SkipFinalSnapshot": v.get("final_snapshot") != "yes",
                       **_final(v, "FinalDBSnapshotIdentifier", name)},
                      f"Delete database {name}" + (" (final snapshot kept)" if v.get("final_snapshot") == "yes"
                                                   else " (no final snapshot)"),
                      wait={"waiter": "db_instance_deleted", "params": {"DBInstanceIdentifier": name}, **long_wait})))
        if protect:
            steps.append(_protection_step("rds", "{{db.DBInstance.DBInstanceArn}}", {
                "operation": "modify_db_instance", "params": {"DBInstanceIdentifier": name, "DeletionProtection": False,
                                                              "ApplyImmediately": True}}, f"database {name}"))
        for n in range(1, int(v.get("read_replicas", 0) or 0) + 1 if custom and engine not in NO_REPLICA_ENGINES else 1):
            rid = f"{name}-replica-{n}"
            steps.append(aws_step(
                "rds", "create_db_instance_read_replica",
                {"DBInstanceIdentifier": rid, "SourceDBInstanceIdentifier": name, "DBInstanceClass": v["instance_class"],
                 "PubliclyAccessible": public, "Tags": tags},
                f"Create read replica {rid} - takes 5-15 minutes",
                wait={"waiter": "db_instance_available", "params": {"DBInstanceIdentifier": rid}, **long_wait},
                undo=undo("rds", "delete_db_instance", {"DBInstanceIdentifier": rid, "SkipFinalSnapshot": True},
                          f"Delete read replica {rid}",
                          wait={"waiter": "db_instance_deleted", "params": {"DBInstanceIdentifier": rid}, **long_wait})))
    elif fam == "aurora":
        serverless = v.get("aurora_capacity", "serverless") == "serverless"
        cparams = {"DBClusterIdentifier": name, "Engine": engine, "DatabaseName": v["initial_db"], **common}
        if serverless:
            cparams["ServerlessV2ScalingConfiguration"] = {
                "MinCapacity": float(v.get("min_acu", AURORA_MIN_ACU)) if custom else AURORA_MIN_ACU,
                "MaxCapacity": float(v.get("max_acu", AURORA_MAX_ACU)) if custom else AURORA_MAX_ACU}
        if custom:
            _set(cparams, "DBClusterParameterGroupName", pgroup)
            cparams.update(extra)
        steps.append(aws_step(
            "rds", "create_db_cluster", cparams, f"Create {label} cluster {name}", save_as="cluster",
            wait={"waiter": "db_cluster_available", "params": {"DBClusterIdentifier": name}, **long_wait},
            undo=undo("rds", "delete_db_cluster",
                      {"DBClusterIdentifier": name, "SkipFinalSnapshot": v.get("final_snapshot") != "yes",
                       **_final(v, "FinalDBSnapshotIdentifier", name)},
                      f"Delete cluster {name}" + (" (final snapshot kept)" if v.get("final_snapshot") == "yes"
                                                  else " (no final snapshot)"),
                      wait={"waiter": "db_cluster_deleted", "params": {"DBClusterIdentifier": name}, **long_wait})))
        if protect:
            steps.append(_protection_step("rds", "{{cluster.DBCluster.DBClusterArn}}", {
                "operation": "modify_db_cluster", "params": {"DBClusterIdentifier": name, "DeletionProtection": False,
                                                             "ApplyImmediately": True}}, f"cluster {name}"))
        cls = "db.serverless" if serverless else v["instance_class"]
        for n in range(1, _node_count(v) + 1 if custom else 2):
            iid = f"{name}-{n}"
            ip = {"DBInstanceIdentifier": iid, "DBClusterIdentifier": name, "Engine": engine,
                  "DBInstanceClass": cls, "PubliclyAccessible": public, "Tags": tags}
            if custom:
                _set(ip, "EnablePerformanceInsights", True, _yes(v, "performance_insights"))
                ip["AutoMinorVersionUpgrade"] = _yes(v, "auto_minor_upgrade", "yes")
            role = "writer" if n == 1 else "reader"
            steps.append(aws_step(
                "rds", "create_db_instance", ip,
                f"Add {'a serverless' if serverless else 'an ' + cls} {role} instance {iid} to the cluster - takes "
                f"5-15 minutes", save_as="db" if n == 1 else None,
                wait={"waiter": "db_instance_available", "params": {"DBInstanceIdentifier": iid}, **long_wait},
                undo=undo("rds", "delete_db_instance", {"DBInstanceIdentifier": iid}, f"Delete instance {iid}",
                          wait={"waiter": "db_instance_deleted", "params": {"DBInstanceIdentifier": iid}, **long_wait})))
    elif fam == "docdb":
        steps.append(aws_step(
            "docdb", "create_db_subnet_group",
            {"DBSubnetGroupName": f"{name}-subnets", "DBSubnetGroupDescription": f"Kintsugi database {name}",
             "SubnetIds": v["subnets"], "Tags": tags},
            f"Create DocumentDB subnet group {name}-subnets",
            undo=undo("docdb", "delete_db_subnet_group", {"DBSubnetGroupName": f"{name}-subnets"},
                      "Delete the DocumentDB subnet group")))
        cparams = {"DBClusterIdentifier": name, "Engine": "docdb", "MasterUsername": v["username"],
                   "ManageMasterUserPassword": True, "DBSubnetGroupName": f"{name}-subnets",
                   "VpcSecurityGroupIds": ["{{sg.GroupId}}"], "StorageEncrypted": True,
                   "BackupRetentionPeriod": int(v.get("backup_retention", 1)), "DeletionProtection": protect,
                   "Tags": tags}
        if custom:
            _set(cparams, "EngineVersion", version)
            cparams["Port"] = port
            _set(cparams, "PreferredBackupWindow", v.get("backup_window"))
            _set(cparams, "PreferredMaintenanceWindow", v.get("maintenance_window"))
            _set(cparams, "KmsKeyId", v.get("kms_key"))
            _set(cparams, "EnableCloudwatchLogsExports", logs, bool(logs))
            _set(cparams, "DBClusterParameterGroupName", pgroup)
            cparams.update(extra)
        steps.append(aws_step(
            "docdb", "create_db_cluster", cparams, f"Create DocumentDB cluster {name}", save_as="cluster",
            undo=undo("docdb", "delete_db_cluster",
                      {"DBClusterIdentifier": name, "SkipFinalSnapshot": v.get("final_snapshot") != "yes",
                       **_final(v, "FinalDBSnapshotIdentifier", name)},
                      f"Delete DocumentDB cluster {name}" + (" (final snapshot kept)" if v.get("final_snapshot") == "yes"
                                                             else " (no final snapshot)"), pause_after=300)))
        if protect:
            steps.append(_protection_step("docdb", "{{cluster.DBCluster.DBClusterArn}}", {
                "operation": "modify_db_cluster", "params": {"DBClusterIdentifier": name, "DeletionProtection": False,
                                                             "ApplyImmediately": True}}, f"cluster {name}"))
        for n in range(1, _node_count(v) + 1 if custom else 2):
            iid = f"{name}-{n}"
            ip = {"DBInstanceIdentifier": iid, "DBClusterIdentifier": name, "Engine": "docdb",
                  "DBInstanceClass": v["instance_class"], "Tags": tags}
            if custom:
                ip["AutoMinorVersionUpgrade"] = _yes(v, "auto_minor_upgrade", "yes")
            steps.append(aws_step(
                "docdb", "create_db_instance", ip,
                f"Add instance {iid} ({v['instance_class']}) - takes 5-15 minutes", save_as="db" if n == 1 else None,
                wait={"waiter": "db_instance_available", "params": {"DBInstanceIdentifier": iid}, **long_wait},
                undo=undo("docdb", "delete_db_instance", {"DBInstanceIdentifier": iid}, f"Delete instance {iid}",
                          wait={"waiter": "db_instance_deleted", "params": {"DBInstanceIdentifier": iid}, **long_wait})))
    else:
        steps.append(aws_step(
            "elasticache", "create_cache_subnet_group",
            {"CacheSubnetGroupName": f"{name}-subnets", "CacheSubnetGroupDescription": f"Kintsugi cache {name}",
             "SubnetIds": v["subnets"], "Tags": tags},
            f"Create cache subnet group {name}-subnets",
            undo=undo("elasticache", "delete_cache_subnet_group", {"CacheSubnetGroupName": f"{name}-subnets"},
                      "Delete the cache subnet group")))
        if _uses_replication_group(v):
            replicas = int(v.get("replicas", 0) or 0) if custom else 0
            rp = {"ReplicationGroupId": name, "ReplicationGroupDescription": f"Kintsugi cache {name}", "Engine": engine,
                  "CacheNodeType": v["instance_class"], "NumCacheClusters": 1 + replicas,
                  "AutomaticFailoverEnabled": replicas > 0, "MultiAZEnabled": replicas > 0 and _yes(v, "multi_az"),
                  "CacheSubnetGroupName": f"{name}-subnets", "SecurityGroupIds": ["{{sg.GroupId}}"],
                  "AtRestEncryptionEnabled": True, "TransitEncryptionEnabled": _yes(v, "encryption_in_transit", "yes"),
                  "Port": port, "SnapshotRetentionLimit": int(v.get("backup_retention", 0) or 0) if custom else 0,
                  "Tags": tags}
            if custom:
                _set(rp, "EngineVersion", version)
                _set(rp, "SnapshotWindow", v.get("backup_window"))
                _set(rp, "PreferredMaintenanceWindow", v.get("maintenance_window"))
                _set(rp, "KmsKeyId", v.get("kms_key"))
                _set(rp, "CacheParameterGroupName", pgroup)
                rp["AutoMinorVersionUpgrade"] = _yes(v, "auto_minor_upgrade", "yes")
                rp.update(extra)
            steps.append(aws_step(
                "elasticache", "create_replication_group", rp,
                f"Create {label} {name} ({v['instance_class']}, {1 + replicas} node(s)) - takes 5-15 minutes",
                save_as="db", wait={"waiter": "replication_group_available", "params": {"ReplicationGroupId": name},
                                    **long_wait},
                undo=undo("elasticache", "delete_replication_group",
                          {"ReplicationGroupId": name, **_final(v, "FinalSnapshotIdentifier", name)},
                          f"Delete {label} {name}",
                          wait={"waiter": "replication_group_deleted", "params": {"ReplicationGroupId": name},
                                **long_wait})))
        else:
            nodes = int(v.get("cache_nodes", 1) or 1) if fam == "memcached" and custom else 1
            cp = {"CacheClusterId": name, "Engine": engine, "CacheNodeType": v["instance_class"],
                  "NumCacheNodes": nodes, "CacheSubnetGroupName": f"{name}-subnets",
                  "SecurityGroupIds": ["{{sg.GroupId}}"], "Tags": tags}
            if nodes > 1:
                cp["AZMode"] = "cross-az"
            if custom:
                _set(cp, "EngineVersion", version)
                cp["Port"] = port
                _set(cp, "PreferredMaintenanceWindow", v.get("maintenance_window"))
                _set(cp, "CacheParameterGroupName", pgroup)
                cp["AutoMinorVersionUpgrade"] = _yes(v, "auto_minor_upgrade", "yes")
                cp.update(extra)
            steps.append(aws_step(
                "elasticache", "create_cache_cluster", cp,
                f"Create {label} {name} ({v['instance_class']}, {nodes} node(s)) - takes 5-10 minutes", save_as="db",
                wait={"waiter": "cache_cluster_available", "params": {"CacheClusterId": name}, **long_wait},
                undo=undo("elasticache", "delete_cache_cluster", {"CacheClusterId": name}, f"Delete {label} {name}",
                          wait={"waiter": "cache_cluster_deleted", "params": {"CacheClusterId": name}, **long_wait})))
    return ScriptDraft(title=f"{label} {name}", steps=steps, notes=_db_notes(v))


def _not_dynamo(i):
    return bool(_family(i)) and _family(i) != "dynamodb"


def _yes_no_field(key, question, fams, default="no", why="", when=None, validate=None):
    rel = _adv(*fams)
    return FieldSpec(key, question, "choice", default=default, options=lambda e, i: YES_NO,
                     validate=validate or (lambda e, i, v: _yes_no(v)), why=why,
                     relevant=(lambda i: rel(i) and when(i)) if when else rel)


_KEY_TYPES = [{"value": "S", "label": "String"}, {"value": "N", "label": "Number"}]
_SQL_FAMS = ("rds", "aurora", "docdb")
_CACHE_FAMS = ("redis", "memcached")
_ALL_SERVER = ("rds", "aurora", "docdb", "redis", "memcached")


DATABASE = Template(
    name="database",
    description="Create a database: RDS PostgreSQL/MySQL/MariaDB/SQL Server/Oracle/Db2, Aurora (Serverless v2 or "
                "provisioned), DynamoDB, DocumentDB (MongoDB-compatible), ElastiCache Redis/Valkey/Memcached, with "
                "its network, security group, optional advanced settings and teardown",
    fields=[
        FieldSpec("engine", "Which kind of database?", "choice", must_ask=True, options=_engine_options,
                  validate=_validate_engine, why="The price shown is the smallest size, while it exists."),
        FieldSpec("settings", "Quick defaults or customize every setting?", "choice", default=_settings_default,
                  options=lambda e, i: SETTINGS_OPTIONS, validate=lambda e, i, v: _choice(SETTINGS_OPTIONS, v, "settings"),
                  relevant=lambda i: bool(_family(i)),
                  why="Pick Customize and submit to see the advanced questions."),
        FieldSpec("name", "Name for the database?", "text", default="kintsugi-db", validate=_db_name),
        FieldSpec("aurora_capacity", "Aurora capacity type?", "choice", default="serverless",
                  options=lambda e, i: AURORA_CAPACITY, validate=lambda e, i, v: _choice(AURORA_CAPACITY, v, "capacity"),
                  relevant=_adv("aurora")),
        FieldSpec("partition_key", "Partition key (the unique ID attribute of each item)?", "text", must_ask=True,
                  default="id", validate=_validate_key_name, relevant=lambda i: _family(i) == "dynamodb"),
        FieldSpec("partition_key_type", "Partition key type?", "choice", default="S",
                  options=lambda e, i: _KEY_TYPES, validate=lambda e, i, v: _choice(_KEY_TYPES, v, "key type"),
                  relevant=lambda i: _family(i) == "dynamodb"),
        FieldSpec("sort_key", "Sort key (optional, e.g. a timestamp)? Leave empty for none.", "text", default="",
                  allow_empty=True, validate=_validate_sort_key, relevant=lambda i: _family(i) == "dynamodb"),
        FieldSpec("sort_key_type", "Sort key type?", "choice", default="S",
                  options=lambda e, i: _KEY_TYPES, validate=lambda e, i, v: _choice(_KEY_TYPES, v, "key type"),
                  relevant=lambda i: _family(i) == "dynamodb" and bool(i.get("sort_key"))),
        FieldSpec("access", "Who may connect to it?", "choice", must_ask=True, default="vpc",
                  options=lambda e, i: ACCESS_OPTIONS, validate=lambda e, i, v: _choice(ACCESS_OPTIONS, v, "access"),
                  relevant=lambda i: _family(i) in ("rds", "aurora")),
        FieldSpec("admin_cidr", "Your IP address (only this IP may connect)?", "text", must_ask=True,
                  default=_admin_default, validate=_validate_admin_cidr, why="Pre-filled with your current public IP.",
                  relevant=lambda i: i.get("access") == "my_ip" and _family(i) in ("rds", "aurora")),
        FieldSpec("subnets", "Which subnets (2 different availability zones, same VPC)?", "multichoice",
                  must_ask=True, options=_db_subnet_options, default=_db_subnet_default,
                  validate=_validate_db_subnets, relevant=_not_dynamo,
                  empty_hint="No suitable subnets in this region. First ask: 'Create a VPC with 2 public and 2 "
                             "private subnets', run that script, then try again."),
        FieldSpec("instance_class", "Size (instance class)?", "choice", options=_class_options,
                  default=lambda e, i: next((o["value"] for o in _class_options(e, i)), None),
                  validate=_validate_class, allow_custom=True,
                  relevant=lambda i: _family(i) in ("rds", "docdb", "redis", "memcached")
                  or (_family(i) == "aurora" and i.get("aurora_capacity") == "provisioned"),
                  why="With Customize you can also type any class AWS offers, e.g. db.m7g.large.",
                  empty_hint="AWS offers none of the listed sizes for this engine in this region. Try another "
                             "region or engine."),
        FieldSpec("license_model", "Which licence?", "choice", must_ask=True, options=_license_options,
                  default=lambda e, i: next((o["value"] for o in _license_options(e, i)), None),
                  validate=lambda e, i, v: _choice(_license_options(e, i), v, "licence"),
                  relevant=lambda i: i.get("engine") in LICENSED_ENGINES,
                  why="Db2 has no licence-included option: BYOL needs your IBM IDs in a parameter group; "
                      "Marketplace needs a subscription first. Oracle EE is BYOL only."),
        FieldSpec("parameter_group", "Which Db2 parameter group (with your IBM Customer ID and Site ID)?", "choice",
                  must_ask=True, options=_db2_group_options,
                  default=lambda e, i: next((o["value"] for o in _db2_group_options(e, i)), None),
                  validate=lambda e, i, v: _choice(_db2_group_options(e, i), v, "Db2 parameter group"),
                  relevant=lambda i: str(i.get("engine", "")).startswith("db2")
                  and i.get("license_model") == "bring-your-own-license",
                  empty_hint="No Db2 parameter group yet. Create it first (see the prerequisites)."),
        FieldSpec("engine_version", "Engine version?", "choice", default="default", options=_version_options,
                  validate=_validate_version, allow_custom=True, relevant=_adv(*_ALL_SERVER)),
        FieldSpec("storage_gb", "Storage in GB?", "number", default=20, validate=_validate_storage,
                  why="20 GB is in the free tier.", relevant=lambda i: _family(i) == "rds"),
        FieldSpec("storage_type", "Storage type?", "choice", default="gp3", options=lambda e, i: STORAGE_TYPES,
                  validate=lambda e, i, v: _choice(STORAGE_TYPES, v, "storage type"), relevant=_adv("rds")),
        FieldSpec("iops", "Provisioned IOPS? (gp3: 0 = included baseline)", "number", default=_iops_default,
                  validate=_validate_iops,
                  relevant=lambda i: _adv("rds")(i) and i.get("storage_type", "gp3") in ("gp3", "io1", "io2")),
        FieldSpec("max_storage_gb", "Storage autoscaling up to how many GB? (0 = off)", "number", default=0,
                  validate=_validate_max_storage, relevant=_adv("rds")),
        FieldSpec("replicas", "How many replicas (readers)?", "number", default=0, validate=_validate_replicas,
                  relevant=_adv("aurora", "docdb", "redis"),
                  why="Aurora/DocumentDB: extra reader instances. Redis/Valkey: replica nodes (automatic failover)."),
        _yes_no_field("multi_az", "Multi-AZ (a standby in another AZ for automatic failover)?", ("rds", "redis"),
                      why="Roughly doubles the cost.", when=lambda i: i.get("engine") not in NO_MULTI_AZ_ENGINES,
                      validate=_validate_multi_az),
        FieldSpec("cache_nodes", "How many Memcached nodes?", "number", default=1,
                  validate=lambda e, i, v: _int(v, 1, 40, "nodes"), relevant=_adv("memcached")),
        FieldSpec("backup_retention", "Keep automated backups for how many days?", "number", default=_backup_default,
                  validate=_validate_backup_retention, relevant=_adv("rds", "aurora", "docdb", "redis"),
                  why="0 turns automated backups off (RDS/Redis only)."),
        FieldSpec("read_replicas", "How many read replicas?", "number", default=0, validate=_validate_read_replicas,
                  relevant=lambda i: _adv("rds")(i) and i.get("engine") not in NO_REPLICA_ENGINES),
        FieldSpec("backup_window", "Daily backup window in UTC (hh:mm-hh:mm)? Empty = AWS picks.", "text", default="",
                  allow_empty=True, validate=_validate_backup_window, relevant=_adv("rds", "aurora", "docdb", "redis")),
        FieldSpec("maintenance_window", "Weekly maintenance window in UTC (ddd:hh:mm-ddd:hh:mm)? Empty = AWS picks.",
                  "text", default="", allow_empty=True, validate=_validate_maintenance_window,
                  relevant=_adv(*_ALL_SERVER)),
        FieldSpec("min_acu", "Minimum capacity (ACU, 0-256 in steps of 0.5)?", "text", default=str(AURORA_MIN_ACU),
                  validate=_validate_min_acu,
                  relevant=lambda i: _adv("aurora")(i) and i.get("aurora_capacity", "serverless") == "serverless"),
        FieldSpec("max_acu", "Maximum capacity (ACU, 1-256)?", "text", default=str(AURORA_MAX_ACU),
                  validate=_validate_max_acu,
                  relevant=lambda i: _adv("aurora")(i) and i.get("aurora_capacity", "serverless") == "serverless"),
        FieldSpec("port", "Port?", "number", default=_port_default, validate=_validate_port, relevant=_adv(*_ALL_SERVER)),
        _yes_no_field("encryption_in_transit", "Encryption in transit (TLS)?", ("redis",), default="yes",
                      why="Clients must then connect with TLS."),
        FieldSpec("kms_key", "KMS key for encryption at rest? Empty = the AWS-managed key.", "text", default="",
                  allow_empty=True, validate=_validate_kms, relevant=lambda i: _adv("rds", "aurora", "docdb", "dynamodb",
                                                                                  "redis")(i)),
        FieldSpec("custom_parameter_group", "Parameter group?", "choice", default="default",
                  options=_param_group_options, validate=_validate_group_name, allow_custom=True,
                  relevant=lambda i: _adv(*_ALL_SERVER)(i) and not (str(i.get("engine", "")).startswith("db2")
                                                                    and i.get("license_model") == "bring-your-own-license"),
                  why="Create custom groups in the console (RDS/ElastiCache -> Parameter groups) to tune engine settings."),
        FieldSpec("option_group", "Option group?", "choice", default="default", options=_option_group_options,
                  validate=_validate_group_name, allow_custom=True,
                  relevant=lambda i: _adv("rds")(i) and i.get("engine") in OPTION_GROUP_ENGINES),
        _yes_no_field("performance_insights", "Performance Insights?", ("rds", "aurora"),
                      why="7 days of history is free."),
        _yes_no_field("log_exports", "Export the database logs to CloudWatch Logs?", _SQL_FAMS,
                      why="Logs are billed by CloudWatch (~$0.50/GB ingested)."),
        _yes_no_field("iam_auth", "IAM database authentication?", ("rds", "aurora"),
                      when=lambda i: i.get("engine") in IAM_AUTH_ENGINES),
        _yes_no_field("auto_minor_upgrade", "Automatic minor version upgrades?", _ALL_SERVER, default="yes"),
        _yes_no_field("deletion_protection", "Deletion protection?", ("rds", "aurora", "docdb", "dynamodb"),
                      why="The teardown script turns it off before deleting."),
        _yes_no_field("final_snapshot", "Keep a final snapshot when the teardown deletes it?",
                      ("rds", "aurora", "docdb", "redis")),
        FieldSpec("billing_mode", "Billing mode?", "choice", default="on_demand", options=lambda e, i: BILLING_MODES,
                  validate=lambda e, i, v: _choice(BILLING_MODES, v, "billing mode"), relevant=_adv("dynamodb")),
        FieldSpec("read_capacity", "Read capacity units (RCU)?", "number", default=5, validate=_validate_capacity,
                  relevant=lambda i: _adv("dynamodb")(i) and i.get("billing_mode") == "provisioned"),
        FieldSpec("write_capacity", "Write capacity units (WCU)?", "number", default=5, validate=_validate_capacity,
                  relevant=lambda i: _adv("dynamodb")(i) and i.get("billing_mode") == "provisioned"),
        FieldSpec("table_class", "Table class?", "choice", default="STANDARD", options=lambda e, i: TABLE_CLASSES,
                  validate=lambda e, i, v: _choice(TABLE_CLASSES, v, "table class"), relevant=_adv("dynamodb")),
        FieldSpec("gsis", "Global secondary indexes? Empty = none.", "text", default="", allow_empty=True,
                  validate=_validate_gsis, relevant=_adv("dynamodb"),
                  why="Format: name:partition_key:S or name:pk:S:sort_key:N, separated by ';'. "
                      "Example: byCustomer:customer_id:S; byDate:status:S:created_at:N"),
        FieldSpec("stream", "DynamoDB stream (change feed for Lambda etc.)?", "choice", default="off",
                  options=lambda e, i: STREAM_OPTIONS, validate=lambda e, i, v: _choice(STREAM_OPTIONS, v, "stream"),
                  relevant=_adv("dynamodb")),
        FieldSpec("ttl_attribute", "TTL attribute (items expire at this epoch time)? Empty = off.", "text", default="",
                  allow_empty=True, validate=_validate_ttl, relevant=_adv("dynamodb")),
        _yes_no_field("pitr", "Point-in-time recovery (continuous backups)?", ("dynamodb",)),
        FieldSpec("username", "Master user name? (the password is generated by AWS)", "text", default="dbadmin",
                  validate=_validate_username, relevant=lambda i: _family(i) in ("rds", "aurora", "docdb")),
        FieldSpec("initial_db", "Name of the first database inside it?", "text",
                  default=lambda e, i: "APPDB" if i.get("engine") in SHORT_DBNAME_ENGINES else "appdb",
                  validate=_validate_initial_db,
                  relevant=lambda i: _family(i) in ("rds", "aurora") and i.get("engine") not in NO_DBNAME_ENGINES),
        FieldSpec("extra_params", "Any other AWS settings (JSON)? Empty = none.", "text", default="",
                  allow_empty=True, validate=_validate_extra, relevant=lambda i: _custom(i) and bool(_family(i)),
                  why="Optional JSON with any other parameter of the main create call (AWS API names), e.g. "
                      '{"StorageThroughput": 500} or {"CACertificateIdentifier": "rds-ca-rsa2048-g1"}. '
                      "Checked against the AWS API model before saving."),
    ],
    title=lambda i: f"{DB_ENGINES.get(i.get('engine'), ('Database',))[0]} '{i.get('name', 'kintsugi-db')}'",
    build=_build_database, notes=_db_notes,
)


RECIPES = [IAM_ROLE, DOCKER_IMAGE, JENKINS, ANSIBLE_SITE, ANSIBLE_PLAYBOOK, TERRAFORM, S3_UPLOAD, S3_WEBSITE,
           DATABASE]
templates.TEMPLATES.update({t.name: t for t in RECIPES})
