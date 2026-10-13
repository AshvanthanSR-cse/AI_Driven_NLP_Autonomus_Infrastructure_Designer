"""Container recipes: ECS services (Fargate, Fargate Spot, EC2), EKS clusters and their management, ECR repositories.

ECS: image from a local Dockerfile (built and pushed to ECR) or an existing image; public IP, a new Application
Load Balancer, or private; task auto scaling (CPU / memory target tracking); environment variables and
secrets referenced from Secrets Manager / SSM (never the values); task role, ECS Exec, Container Insights;
long-running service, scheduled task (EventBridge Scheduler, in the app timezone) or a one-off task.
EKS: eksctl cluster with managed nodes, Spot nodes, EKS Auto Mode or Fargate; version, add-ons, control
plane logs, endpoint access; deploys a Dockerfile app (+ HPA), YAML manifests or a Helm chart. eks_manage
works on existing clusters. ECR: repositories with tag immutability, scanning, encryption, lifecycle rules,
cross-account pull, replication, pull-through cache.
"""
import json
import re
from pathlib import Path

from core import lookups, templates, workspace
from core.recipe_kit import (account_ids, action_is, choice, custom, extra_params_field, ids, kv_pairs,
                             merge_extra, no_secrets, number, opts, pick, pick_many, region_options, settings_field,
                             static, yes, yes_no)
from core.recipes import (CLASSIC_LB_HOUR, EC2_HOURLY, EKS_CONTROL_PLANE_HOUR, FARGATE_GB_HOUR, FARGATE_VCPU_HOUR,
                          MANAGED_POLICIES, _check_tools, _docker_port_default, _name_validator, _repo_name, _role_options,
                          _stamp, _validate_docker_folder, _validate_role, aws_step, check, cmd, docker_context,
                          image_steps, role_steps, tag_dict, tag_list, undo)
from core.recipes_compute import INSTANCE_PRICES, LB_HOUR, LCU_HOUR, _cert_options, _type_options, _validate_type, lb_steps
from core.scripts import ScriptDraft
from core.templates import FieldSpec, HOURS_PER_MONTH, PUBLIC_IPV4_HOURLY, Template, _choice, _int, _yes_no

SIZES = {"256/512": (0.25, 0.5), "512/1024": (0.5, 1.0), "1024/2048": (1.0, 2.0), "2048/4096": (2.0, 4.0),
         "4096/8192": (4.0, 8.0)}
ECS_AMI_PARAM = {"X86_64": "/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id",
                 "ARM64": "/aws/service/ecs/optimized-ami/amazon-linux-2023/arm64/recommended/image_id"}
ECS_INSTANCE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
_IMAGE_RE = re.compile(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*(?::\d+)?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
                       r"(?::[\w][\w.-]{0,127})?(?:@sha256:[0-9a-f]{64})?|"
                       r"\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/[\w./-]+(?::[\w.-]+)?(?:@sha256:[0-9a-f]{64})?")
_SECRET_REF_RE = re.compile(r"arn:aws[\w-]*:(secretsmanager|ssm):[a-z0-9-]+:\d{12}:[\w/+=.@:-]+|/[\w/.-]{1,1000}")


def _public_subnet_options(env, inputs):
    return [{"value": s["id"], "label": f"{s['id']} · {s['az']} · {s['cidr']} · {s['vpc_name'] or s['vpc']}"
                                         f"{' · ' + s['name'] if s['name'] else ''}"}
            for s in env.subnets() if s["public"]]


def _all_subnet_options(env, inputs):
    return [{"value": s["id"], "label": f"{s['id']} · {s['az']} · {s['cidr']} · "
                                         f"{'public' if s['public'] else 'private'} · {s['vpc_name'] or s['vpc']}"}
            for s in env.subnets()]


def _validate_public_subnets(min_azs: int, public: bool = True):
    def check_(env, inputs, v):
        chosen = ids(v)
        subs = {s["id"]: s for s in env.subnets() if s["public"] or not public}
        bad = [x for x in chosen if x not in subs]
        if bad:
            raise ValueError(f"not a {'public ' if public else ''}subnet in this region: {', '.join(bad)}")
        if not chosen:
            raise ValueError("pick at least one subnet")
        if len({subs[x]['vpc'] for x in chosen}) > 1:
            raise ValueError("all subnets must be in the same VPC")
        if len({subs[x]['az'] for x in chosen}) < min_azs:
            raise ValueError(f"pick subnets in at least {min_azs} different availability zones")
        return chosen
    return check_


EXPOSURE = opts(("public_ip", "Public IP on each task (cheapest; no load balancer)"),
                ("alb", "New Application Load Balancer in front (stable URL, health checks, ~$16+/month)"),
                ("private", "Private: no inbound access (workers, queues, internal services)"))
LAUNCH_TYPES = opts(("fargate", "Fargate (serverless, pay per task)"),
                    ("fargate_spot", "Fargate Spot (~70% cheaper, tasks can be interrupted)"),
                    ("ec2", "EC2 instances managed by an Auto Scaling group (capacity provider)"))
MODES = opts(("service", "Long-running service (always on)"),
             ("scheduled", "Scheduled task (runs on a schedule, then stops)"),
             ("once", "Run one task now"))
SCALE = opts(("none", "No auto scaling (fixed number of tasks)"),
             ("cpu", "Target tracking on average CPU"), ("memory", "Target tracking on average memory"))
IMAGE_SOURCES = opts(("dockerfile", "Build my local Dockerfile and push it to ECR"),
                     ("image", "Use an existing image (ECR URI or public image like nginx:latest)"))


def _validate_image_uri(env, inputs, v) -> str:
    v = str(v).strip()
    if not _IMAGE_RE.fullmatch(v):
        raise ValueError("an image like nginx:1.27, public.ecr.aws/nginx/nginx:latest or "
                         "<account>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>")
    return v


def _validate_secret_refs(env, inputs, v) -> str:
    pairs = kv_pairs(v, "NAME=secret ARN or SSM parameter")
    for k, ref in pairs.items():
        if not _SECRET_REF_RE.fullmatch(ref):
            raise ValueError(f"{k}: give a Secrets Manager ARN or an SSM parameter name like /app/db_password "
                             f"(never the secret value itself)")
    return str(v or "").strip()


def _validate_env(env, inputs, v) -> str:
    no_secrets(kv_pairs(v, "environment variables"), "environment variables")
    return str(v or "").strip()


def _schedule_text(env, inputs, v) -> str:
    from core.recipes import _DAILY_RE
    from core.cron import AwsCron, CronError, expression_kind, parse_rate
    from core.schedules import parse_hhmm
    v = str(v).strip()
    if m := _DAILY_RE.fullmatch(v):
        t = parse_hhmm(m.group(1))
        return f"cron({t.minute} {t.hour} * * ? *)"
    if v.lower() in ("hourly", "every hour"):
        return "rate(1 hour)"
    try:
        if expression_kind(v) == "cron":
            AwsCron.parse(v)
        elif expression_kind(v) == "rate":
            if parse_rate(v) is None:
                raise CronError("use rate(5 minutes), rate(1 hour) or rate(1 day)")
        else:
            raise CronError("use 'daily 10:00', 'hourly', cron(min hour day month weekday year) or rate(...)")
    except CronError as e:
        raise ValueError(str(e)) from None
    return v


def _cluster_options(env, inputs):
    try:
        existing = lookups.ecs_clusters(env)
    except Exception:
        existing = []
    return [{"value": "new", "label": "Create a new cluster (recommended)"}] + \
           [{"value": c, "label": c} for c in existing]


def _ecs_subnet_options(env, inputs):
    if inputs.get("exposure", "public_ip") in ("public_ip", "alb"):
        return _public_subnet_options(env, inputs)
    return _all_subnet_options(env, inputs)


def _validate_ecs_subnets(env, inputs, v):
    exposure = inputs.get("exposure", "public_ip")
    return _validate_public_subnets(2 if exposure == "alb" else 1, public=exposure in ("public_ip", "alb"))(env, inputs, v)


def _validate_exposure(env, inputs, v):
    v = _choice(EXPOSURE, v, "exposure")
    if v == "public_ip" and inputs.get("launch_type") == "ec2":
        raise ValueError("tasks on EC2 cannot get their own public IP; pick a load balancer or private")
    return v


def _ecs_hourly(v: dict) -> float:
    vcpu, gb = SIZES.get(v.get("size", "256/512"), (0.25, 0.5))
    n = int(v.get("count", 1) or 1)
    task = vcpu * FARGATE_VCPU_HOUR + gb * FARGATE_GB_HOUR
    if v.get("launch_type") == "fargate_spot":
        task *= 0.3
    total = 0.0
    if v.get("launch_type") == "ec2":
        t = v.get("instance_type", "t3.small")
        total += int(v.get("instances", 1) or 1) * (INSTANCE_PRICES.get(t, 0.0208) + PUBLIC_IPV4_HOURLY)
    else:
        total += n * task
    if v.get("exposure", "public_ip") == "public_ip":
        total += n * PUBLIC_IPV4_HOURLY
    if v.get("exposure") == "alb":
        total += LB_HOUR + LCU_HOUR + 2 * PUBLIC_IPV4_HOURLY
    return total


def _ecs_notes(v: dict) -> list[str]:
    mode = v.get("mode", "service")
    if mode != "service":
        vcpu, gb = SIZES.get(v.get("size", "256/512"), (0.25, 0.5))
        per = vcpu * FARGATE_VCPU_HOUR + gb * FARGATE_GB_HOUR
        return [f"COST: you pay only while a task runs: ~${per:.4f}/hour per task (Fargate, approximate "
                "us-east-1 prices; verify current pricing) + ECR storage ~$0.10/GB-month + CloudWatch Logs.",
                "Run the teardown script when you no longer need it."]
    h = _ecs_hourly(v)
    lt = {"fargate": "Fargate", "fargate_spot": "Fargate Spot", "ec2": "EC2"}[v.get("launch_type", "fargate")]
    notes = [f"COST: {v.get('count', 1)} task(s) on {lt}"
             + {"public_ip": " + public IPs", "alb": " + an Application Load Balancer", "private": ""}[
                 v.get("exposure", "public_ip")]
             + f" ~${h:.3f}/hour (~${h * HOURS_PER_MONTH:.0f}/month) + ECR storage ~$0.10/GB-month + CloudWatch "
               "Logs. Approximate us-east-1 prices; verify current pricing. No NAT gateway is created.",
             "Run the teardown script when you are done testing.",
             "First ECS use in an account also creates the AWS service-linked role for ECS (needs iam permission)."]
    if v.get("autoscaling", "none") != "none":
        notes.append(f"Auto scaling keeps between {v.get('min_tasks', 1)} and {v.get('max_tasks', 4)} tasks; more "
                     "tasks cost more.")
    if v.get("exposure") == "private" and not all(s["public"] for s in v.get("_subnets", [])):
        notes.append("Tasks in private subnets need a NAT gateway or VPC endpoints (ECR, S3, Logs) to pull the image.")
    return notes


def _ecs_role_steps(name: str, v: dict, secrets: dict) -> tuple[list[dict], str, str | None]:
    steps: list[dict] = []
    if v.get("exec_role", "new") == "new":
        role = f"{name}-ecs-exec"[:64]
        steps += role_steps(role, "ecs-tasks.amazonaws.com", [MANAGED_POLICIES["AmazonECSTaskExecutionRolePolicy"]],
                            key="exec_role")
        exec_arn = "{{exec_role.Role.Arn}}"
        if secrets:
            refs = sorted(set(secrets.values()))
            sm = [r for r in refs if ":secretsmanager:" in r]
            ssm = [r if r.startswith("arn:") else f"arn:aws:ssm:*:*:parameter{r}" for r in refs if ":secretsmanager:" not in r]
            stmts = []
            if sm:
                stmts.append({"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": sm})
            if ssm:
                stmts.append({"Effect": "Allow", "Action": ["ssm:GetParameters"], "Resource": ssm})
            steps.append(aws_step("iam", "put_role_policy",
                                  {"RoleName": role, "PolicyName": "read-task-secrets",
                                   "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": stmts})},
                                  "Let ECS read ONLY the referenced secrets when starting the task",
                                  undo=undo("iam", "delete_role_policy", {"RoleName": role, "PolicyName": "read-task-secrets"},
                                            "Remove the secrets policy")))
    else:
        exec_arn = v["exec_role"]
    task_arn = None
    task = v.get("task_role", "none")
    if task == "new" or yes(v, "exec_command"):
        role = f"{name}-ecs-task"[:64]
        policies = [MANAGED_POLICIES[p] for p in v.get("task_policies", []) if p in MANAGED_POLICIES]
        steps += role_steps(role, "ecs-tasks.amazonaws.com", policies, key="task_role")
        if yes(v, "exec_command"):
            doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Resource": "*", "Action": [
                "ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel", "ssmmessages:OpenControlChannel",
                "ssmmessages:OpenDataChannel"]}]}
            steps.append(aws_step("iam", "put_role_policy",
                                  {"RoleName": role, "PolicyName": "ecs-exec", "PolicyDocument": json.dumps(doc)},
                                  "Allow ECS Exec (interactive shell into containers via SSM)",
                                  undo=undo("iam", "delete_role_policy", {"RoleName": role, "PolicyName": "ecs-exec"},
                                            "Remove the ECS Exec policy")))
        task_arn = "{{task_role.Role.Arn}}"
    elif task != "none":
        task_arn = task
    return steps, exec_arn, task_arn


def _ec2_capacity_steps(env, v: dict, name: str, cluster: str, subnets: list[str], vpc: str,
                        task_sg: str) -> tuple[list[dict], str]:
    arch = v.get("cpu_arch", "X86_64")
    ami = env.conn.client("ssm", "read", env.region).get_parameter(Name=ECS_AMI_PARAM[arch])["Parameter"]["Value"]
    role = f"{name}-ecs-instance"[:64]
    steps = role_steps(role, "ec2.amazonaws.com", [ECS_INSTANCE_POLICY, MANAGED_POLICIES["AmazonSSMManagedInstanceCore"]],
                       key="inst_role", instance_profile=True)
    import base64
    user_data = base64.b64encode(f"#!/bin/bash\necho ECS_CLUSTER={cluster} >> /etc/ecs/ecs.config\n".encode()).decode()
    data = {"ImageId": ami, "InstanceType": v.get("instance_type", "t3.small"), "IamInstanceProfile": {"Name": role},
            "SecurityGroupIds": [task_sg], "UserData": user_data,
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
            "TagSpecifications": [{"ResourceType": "instance", "Tags": tag_list(f"{name}-ecs-node", extra={"Env": "demo"})}]}
    lt_name, asg = f"{name}-ecs-lt", f"{name}-ecs-asg"
    n = int(v.get("instances", 1) or 1)
    steps += [
        aws_step("ec2", "create_launch_template",
                 {"LaunchTemplateName": lt_name, "LaunchTemplateData": data,
                  "TagSpecifications": [{"ResourceType": "launch-template", "Tags": tag_list(lt_name)}]},
                 f"Create launch template {lt_name} (ECS-optimized Amazon Linux 2023, {data['InstanceType']})",
                 save_as="ecs_lt", undo=undo("ec2", "delete_launch_template",
                                             {"LaunchTemplateId": "{{ecs_lt.LaunchTemplate.LaunchTemplateId}}"},
                                             f"Delete launch template {lt_name}")),
        aws_step("autoscaling", "create_auto_scaling_group",
                 {"AutoScalingGroupName": asg, "MinSize": 0, "MaxSize": max(n, int(v.get("max_instances", n) or n)),
                  "DesiredCapacity": n, "VPCZoneIdentifier": ",".join(subnets),
                  "LaunchTemplate": {"LaunchTemplateId": "{{ecs_lt.LaunchTemplate.LaunchTemplateId}}", "Version": "$Latest"},
                  "Tags": [{"Key": t["Key"], "Value": t["Value"], "PropagateAtLaunch": True}
                           for t in tag_list(f"{name}-ecs-node", extra={"AmazonECSManaged": "true"})]},
                 f"Create Auto Scaling group {asg} for the container instances ({n} instance(s))",
                 undo=undo("autoscaling", "delete_auto_scaling_group", {"AutoScalingGroupName": asg, "ForceDelete": True},
                           f"Delete {asg} and its instances (waits)",
                           wait={"waiter": "group_not_exists", "params": {"AutoScalingGroupNames": [asg]},
                                 "delay": 15, "max_attempts": 80})),
        aws_step("ecs", "create_capacity_provider",
                 {"name": f"{name}-cp", "autoScalingGroupProvider": {
                     "autoScalingGroupArn": asg, "managedTerminationProtection": "DISABLED",
                     "managedScaling": {"status": "ENABLED", "targetCapacity": 100}},
                  "tags": tag_list(f"{name}-cp", "key", "value")},
                 f"Create capacity provider {name}-cp (ECS scales the instances for the tasks)",
                 undo=undo("ecs", "delete_capacity_provider", {"capacityProvider": f"{name}-cp"},
                           "Delete the capacity provider", pause_after=20)),
        aws_step("ecs", "put_cluster_capacity_providers",
                 {"cluster": cluster, "capacityProviders": [f"{name}-cp"],
                  "defaultCapacityProviderStrategy": [{"capacityProvider": f"{name}-cp", "weight": 1}]},
                 f"Use {name}-cp as the cluster's default capacity",
                 undo=undo("ecs", "put_cluster_capacity_providers",
                           {"cluster": cluster, "capacityProviders": [], "defaultCapacityProviderStrategy": []},
                           "Detach the capacity provider from the cluster")),
    ]
    return steps, f"{name}-cp"


def _build_ecs(env, v) -> ScriptDraft:
    name, port, mode = v["name"], int(v.get("container_port", 80)), v.get("mode", "service")
    exposure, lt = v.get("exposure", "public_ip"), v.get("launch_type", "fargate")
    subs_all = {s["id"]: s for s in env.subnets()}
    subnets = v["subnets"]
    vpc = subs_all[subnets[0]]["vpc"]
    v = {**v, "_subnets": [subs_all[s] for s in subnets]}
    arch = v.get("cpu_arch", "X86_64")
    steps: list[dict] = []
    warns: list[str] = []
    if v.get("image_source", "dockerfile") == "dockerfile":
        _check_tools("docker")
        img_steps, image, warns = image_steps(env, name, v["app_folder"],
                                              platform="linux/arm64" if arch == "ARM64" else "linux/amd64")
        steps += img_steps
    else:
        image = v["image_uri"]
    env_vars = kv_pairs(v.get("env_vars", ""))
    secrets = kv_pairs(v.get("secrets", ""))
    role_s, exec_arn, task_arn = _ecs_role_steps(name, v, secrets)
    steps += role_s
    log_group = f"/ecs/{name}"
    steps.append(aws_step("logs", "create_log_group", {"logGroupName": log_group, "tags": tag_dict(name)},
                          f"Create log group {log_group}",
                          undo=undo("logs", "delete_log_group", {"logGroupName": log_group}, "Delete the log group")))
    steps.append(aws_step("logs", "put_retention_policy",
                          {"logGroupName": log_group, "retentionInDays": int(v.get("log_days", 14))},
                          f"Keep logs for {v.get('log_days', 14)} days (saves money)"))
    if v.get("cluster", "new") == "new":
        cluster = f"{name}-cluster"
        cp = {"clusterName": cluster, "tags": tag_list(name, "key", "value"),
              "capacityProviders": ["FARGATE", "FARGATE_SPOT"],
              "settings": [{"name": "containerInsights", "value": "enabled" if yes(v, "insights") else "disabled"}]}
        steps.append(aws_step("ecs", "create_cluster", cp, f"Create ECS cluster {cluster}", save_as="cluster",
                              undo=undo("ecs", "delete_cluster", {"cluster": cluster}, f"Delete ECS cluster {cluster}")))
        cluster_arn = "{{cluster.cluster.clusterArn}}"
    else:
        cluster = v["cluster"]
        cluster_arn = f"arn:aws:ecs:{env.region_name}:{env.account_id()}:cluster/{cluster}"
    steps.append(aws_step("ec2", "create_security_group",
                          {"GroupName": f"{name}-ecs-{_stamp()}", "Description": f"Kintsugi ECS service {name}",
                           "VpcId": vpc, "TagSpecifications": templates._tags("security-group", f"{name}-ecs-sg")},
                          f"Create security group for {name}", save_as="sg",
                          undo=undo("ec2", "delete_security_group", {"GroupId": "{{sg.GroupId}}"},
                                    "Delete the security group")))
    refs = None
    if exposure == "alb" and mode == "service":
        lb_v = {"lb_type": "application", "scheme": "internet-facing", "target_type": "ip", "port": port,
                "health_path": v.get("health_path", "/"), "ingress_cidr": "0.0.0.0/0", "target_protocol": "HTTP",
                "https": v.get("https", "no"), "certificate": v.get("certificate"), "redirect_http": "yes"}
        lbs, refs = lb_steps(env, lb_v, f"{name}-alb"[:28], subnets, vpc)
        steps += lbs
        steps.append(aws_step("ec2", "authorize_security_group_ingress",
                              {"GroupId": "{{sg.GroupId}}", "IpPermissions": [
                                  {"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                                   "UserIdGroupPairs": [{"GroupId": refs["sg"], "Description": "from the load balancer"}]}]},
                              f"Allow port {port} into the tasks only from the load balancer"))
    elif exposure == "public_ip" and mode == "service":
        steps.append(aws_step("ec2", "authorize_security_group_ingress",
                              {"GroupId": "{{sg.GroupId}}", "IpPermissions": [
                                  {"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                                   "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "web app"}]}]},
                              f"Allow inbound TCP {port} from the internet (the app's port)"))
    strategy = None
    if lt == "ec2":
        cap_steps, cp_name = _ec2_capacity_steps(env, v, name, cluster, subnets, vpc, "{{sg.GroupId}}")
        steps += cap_steps
        strategy = [{"capacityProvider": cp_name, "weight": 1}]
    elif lt == "fargate_spot":
        strategy = [{"capacityProvider": "FARGATE_SPOT", "weight": 1}]
    cpu, mem = v.get("size", "256/512").split("/")
    container = {"name": name, "image": image, "essential": True,
                 "portMappings": [{"containerPort": port, "protocol": "tcp"}],
                 "logConfiguration": {"logDriver": "awslogs", "options": {
                     "awslogs-group": log_group, "awslogs-region": env.region_name, "awslogs-stream-prefix": name}}}
    if env_vars:
        container["environment"] = [{"name": k, "value": val} for k, val in env_vars.items()]
    if secrets:
        container["secrets"] = [{"name": k, "valueFrom": ref} for k, ref in secrets.items()]
    td = {"family": name, "networkMode": "awsvpc", "requiresCompatibilities": ["EC2" if lt == "ec2" else "FARGATE"],
          "cpu": cpu, "memory": mem, "executionRoleArn": exec_arn,
          "runtimePlatform": {"cpuArchitecture": arch, "operatingSystemFamily": "LINUX"},
          "containerDefinitions": [container], "tags": tag_list(name, "key", "value")}
    if task_arn:
        td["taskRoleArn"] = task_arn
    steps.append(aws_step("ecs", "register_task_definition", merge_extra(td, v, "td_extra"),
                          f"Register task definition {name} ({cpu} CPU units / {mem} MB, {arch})", save_as="td",
                          undo=undo("ecs", "deregister_task_definition",
                                    {"taskDefinition": "{{td.taskDefinition.taskDefinitionArn}}"},
                                    "Deregister the task definition")))
    public_net = all(s["public"] for s in v["_subnets"])
    net = {"awsvpcConfiguration": {"subnets": subnets, "securityGroups": ["{{sg.GroupId}}"],
                                   "assignPublicIp": "ENABLED" if public_net and lt != "ec2" else "DISABLED"}}
    if mode == "service":
        svc = {"cluster": cluster, "serviceName": name, "taskDefinition": "{{td.taskDefinition.taskDefinitionArn}}",
               "desiredCount": int(v.get("count", 1)), "networkConfiguration": net,
               "deploymentConfiguration": {"deploymentCircuitBreaker": {"enable": True, "rollback": True},
                                           "maximumPercent": 200, "minimumHealthyPercent": 100},
               "enableExecuteCommand": yes(v, "exec_command"), "tags": tag_list(name, "key", "value"),
               "propagateTags": "SERVICE"}
        if strategy:
            svc["capacityProviderStrategy"] = strategy
        else:
            svc["launchType"] = "FARGATE"
        if refs:
            svc["loadBalancers"] = [{"targetGroupArn": refs["tg_arn"], "containerName": name, "containerPort": port}]
            svc["healthCheckGracePeriodSeconds"] = 60
        steps.append(aws_step("ecs", "create_service", merge_extra(svc, v, "svc_extra"),
                              f"Create service {name} with {v.get('count', 1)} task(s) (waits until stable)",
                              save_as="svc",
                              wait={"waiter": "services_stable", "params": {"cluster": cluster, "services": [name]},
                                    "delay": 15, "max_attempts": 60},
                              undo=undo("ecs", "delete_service", {"cluster": cluster, "service": name, "force": True},
                                        f"Delete service {name} (waits until gone)",
                                        wait={"waiter": "services_inactive",
                                              "params": {"cluster": cluster, "services": [name]}},
                                        pause_after=45)))
        if v.get("autoscaling", "none") != "none":
            rid = f"service/{cluster}/{name}"
            steps.append(aws_step("application-autoscaling", "register_scalable_target",
                                  {"ServiceNamespace": "ecs", "ResourceId": rid,
                                   "ScalableDimension": "ecs:service:DesiredCount",
                                   "MinCapacity": int(v.get("min_tasks", 1)), "MaxCapacity": int(v.get("max_tasks", 4))},
                                  f"Let the service scale between {v.get('min_tasks', 1)} and {v.get('max_tasks', 4)} tasks",
                                  undo=undo("application-autoscaling", "deregister_scalable_target",
                                            {"ServiceNamespace": "ecs", "ResourceId": rid,
                                             "ScalableDimension": "ecs:service:DesiredCount"},
                                            "Remove auto scaling from the service")))
            metric = "ECSServiceAverageCPUUtilization" if v["autoscaling"] == "cpu" else \
                "ECSServiceAverageMemoryUtilization"
            steps.append(aws_step("application-autoscaling", "put_scaling_policy",
                                  {"PolicyName": f"{name}-{v['autoscaling']}", "ServiceNamespace": "ecs",
                                   "ResourceId": rid, "ScalableDimension": "ecs:service:DesiredCount",
                                   "PolicyType": "TargetTrackingScaling",
                                   "TargetTrackingScalingPolicyConfiguration": {
                                       "TargetValue": float(v.get("target_value", 60)),
                                       "PredefinedMetricSpecification": {"PredefinedMetricType": metric},
                                       "ScaleInCooldown": 120, "ScaleOutCooldown": 60}},
                                  f"Target tracking: keep average {v['autoscaling']} at {v.get('target_value', 60)}%"))
        if refs and not refs["https"]:
            steps.append(check("http", {"url": f"http://{refs['dns']}{v.get('health_path', '/')}"},
                               "Check that the app answers through the load balancer", timeout=900))
        elif exposure == "public_ip":
            steps.append(check("ecs_url", {"cluster": cluster, "service": name, "port": port,
                                           "path": v.get("health_path", "/")},
                               "Check that the app answers on its public IP", timeout=600))
        title = f"Run {name} on ECS ({dict((o['value'], o['label'].split(' (')[0]) for o in LAUNCH_TYPES)[lt]})"
    elif mode == "scheduled":
        from core.config import settings
        role = f"{name}-ecs-scheduler"[:64]
        acct = env.account_id()
        pass_roles = [f"arn:aws:iam::{acct}:role/{name}-ecs-exec"[:200]] if v.get("exec_role", "new") == "new" \
            else [exec_arn]
        if task_arn:
            pass_roles.append(f"arn:aws:iam::{acct}:role/{name}-ecs-task" if task_arn.startswith("{{") else task_arn)
        doc = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "ecs:RunTask",
             "Resource": f"arn:aws:ecs:{env.region_name}:{acct}:task-definition/{name}:*"},
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": pass_roles}]}
        steps += role_steps(role, "scheduler.amazonaws.com", [], key="sched_role", pause=1)
        steps.append(aws_step("iam", "put_role_policy",
                              {"RoleName": role, "PolicyName": "run-task", "PolicyDocument": json.dumps(doc)},
                              "Allow the scheduler to start only this task definition",
                              undo=undo("iam", "delete_role_policy", {"RoleName": role, "PolicyName": "run-task"},
                                        "Remove the scheduler policy"), pause_after=15))
        target = {"Arn": cluster_arn, "RoleArn": "{{sched_role.Role.Arn}}",
                  "EcsParameters": {"TaskDefinitionArn": "{{td.taskDefinition.taskDefinitionArn}}", "TaskCount": 1,
                                    "NetworkConfiguration": {"awsvpcConfiguration": {
                                        "Subnets": subnets, "SecurityGroups": ["{{sg.GroupId}}"],
                                        "AssignPublicIp": "ENABLED" if public_net else "DISABLED"}}}}
        if strategy:
            target["EcsParameters"]["CapacityProviderStrategy"] = strategy
        else:
            target["EcsParameters"]["LaunchType"] = "FARGATE"
        steps.append(aws_step("scheduler", "create_schedule",
                              {"Name": f"{name}-schedule"[:64], "ScheduleExpression": v["schedule"],
                               "ScheduleExpressionTimezone": settings.app_timezone,
                               "FlexibleTimeWindow": {"Mode": "OFF"}, "Target": target, "State": "ENABLED"},
                              f"Run the task on schedule {v['schedule']} ({settings.app_timezone})",
                              undo=undo("scheduler", "delete_schedule", {"Name": f"{name}-schedule"[:64]},
                                        "Delete the schedule")))
        title = f"Scheduled ECS task {name} ({v['schedule']})"
    else:
        run = {"cluster": cluster, "taskDefinition": "{{td.taskDefinition.taskDefinitionArn}}", "count": 1,
               "networkConfiguration": net, "tags": tag_list(name, "key", "value")}
        if strategy:
            run["capacityProviderStrategy"] = strategy
        else:
            run["launchType"] = "FARGATE"
        steps.append(aws_step("ecs", "run_task", run, "Run one task now (it stops when the container exits)",
                              save_as="task"))
        title = f"Run one ECS task {name}"
    notes = _ecs_notes(v) + ([f"Image: {image}", "Docker Desktop must be running."]
                             if v.get("image_source", "dockerfile") == "dockerfile" else [f"Image: {image}"]) + warns
    if secrets:
        notes.append("Secrets are injected by ECS from Secrets Manager / SSM at start; their values never appear "
                     "in the script or the logs.")
    return ScriptDraft(title=title, steps=steps, notes=notes)


def _uses_folder(i) -> bool:
    return i.get("image_source", "dockerfile") == "dockerfile"


def _service(i) -> bool:
    return i.get("mode", "service") == "service"


ECS_SERVICE = Template(
    name="ecs_fargate_service",
    description="ECS: Dockerfile or image on Fargate / Fargate Spot / EC2; public IP, new ALB or private; auto "
                "scaling; env vars and secret references; service, scheduled task or one-off task",
    fields=[
        choice("mode", "Long-running service, scheduled task, or one task now?", MODES, default="service"),
        choice("image_source", "Where does the container image come from?", IMAGE_SOURCES, default="dockerfile"),
        FieldSpec("app_folder", "Which Dockerfile (or the folder that has it)?", "path", must_ask=True,
                  validate=_validate_docker_folder, relevant=_uses_folder,
                  why="The Dockerfile's folder is the build context."),
        FieldSpec("image_uri", "Which image?", "text", must_ask=True, default="public.ecr.aws/nginx/nginx:latest",
                  validate=_validate_image_uri, relevant=lambda i: not _uses_folder(i)),
        FieldSpec("name", "Name for the app (used for ECR, cluster, service)?", "text", default="kintsugi-app",
                  validate=_name_validator(r"[a-z][a-z0-9-]{1,30}", "lowercase letters, numbers and - (max 31)")),
        FieldSpec("container_port", "Which port does the app listen on inside the container?", "number",
                  must_ask=True, default=lambda e, i: _docker_port_default(e, i) if _uses_folder(i) else 80,
                  validate=lambda e, i, v: _int(v, 1, 65535, "port"),
                  why="Taken from EXPOSE in the Dockerfile when present."),
        choice("launch_type", "Where should the containers run?", LAUNCH_TYPES, default="fargate"),
        FieldSpec("exposure", "How should it be reachable?", "choice", must_ask=True, default="public_ip",
                  options=static(EXPOSURE), validate=_validate_exposure, relevant=_service,
                  why="A load balancer gives one stable URL and replaces unhealthy tasks."),
        FieldSpec("cluster", "Which ECS cluster?", "choice", default="new", options=_cluster_options,
                  validate=pick(_cluster_options, "cluster"), relevant=custom),
        FieldSpec("subnets", "Which subnets should the tasks run in?", "multichoice", must_ask=True,
                  options=_ecs_subnet_options, validate=_validate_ecs_subnets,
                  default=lambda e, i: [o["value"] for o in _ecs_subnet_options(e, i)][:2],
                  empty_hint="No public subnets in this region. First ask: 'Create a VPC with 2 public subnets', "
                             "run that script, then try again."),
        yes_no("https", "Add HTTPS on the load balancer (needs an ACM certificate)?",
               relevant=lambda i: _service(i) and i.get("exposure") == "alb"),
        FieldSpec("certificate", "Which certificate?", "choice", must_ask=True, options=_cert_options,
                  validate=pick(_cert_options, "certificate"),
                  default=lambda e, i: next((o["value"] for o in _cert_options(e, i)), None),
                  relevant=lambda i: _service(i) and i.get("exposure") == "alb" and yes(i, "https"),
                  empty_hint="No issued ACM certificate in this region; answer HTTPS = no or request one first."),
        FieldSpec("health_path", "Health check path?", "text", default="/",
                  relevant=lambda i: custom(i) and _service(i) and i.get("exposure", "public_ip") in ("alb", "public_ip")),
        FieldSpec("schedule", "When should it run? ('daily 10:00' in your timezone, 'hourly', cron(...) or rate(...))",
                  "text", must_ask=True, default="daily 02:00", validate=_schedule_text,
                  relevant=lambda i: i.get("mode") == "scheduled",
                  why="EventBridge Scheduler runs it in your timezone, so no UTC conversion is needed."),
        FieldSpec("size", "Task size (CPU units / memory MB)?", "choice", default="256/512",
                  options=lambda e, i: [{"value": k, "label": f"{k} ({c} vCPU, {m} GB)"} for k, (c, m) in SIZES.items()],
                  validate=lambda e, i, v: _choice([{"value": k, "label": k} for k in SIZES], v, "size")),
        FieldSpec("count", "How many copies (tasks)?", "number", default=1,
                  validate=lambda e, i, v: _int(v, 1, 10, "tasks"), relevant=_service),
        FieldSpec("instance_type", "Instance size for the container hosts?", "choice", default="t3.small",
                  options=_type_options, validate=_validate_type, relevant=lambda i: i.get("launch_type") == "ec2"),
        number("instances", "How many container instances to start with?", 1, 1, 10,
               relevant=lambda i: i.get("launch_type") == "ec2"),
        number("max_instances", "Maximum container instances (capacity provider scales up to this)?", 3, 1, 20,
               relevant=lambda i: i.get("launch_type") == "ec2"),
        choice("autoscaling", "Auto scale the number of tasks?", SCALE, default="none", relevant=_service),
        number("min_tasks", "Minimum tasks?", 1, 0, 50, relevant=lambda i: _service(i) and i.get("autoscaling", "none") != "none"),
        number("max_tasks", "Maximum tasks?", 4, 1, 50, relevant=lambda i: _service(i) and i.get("autoscaling", "none") != "none"),
        number("target_value", "Target average utilisation (%)?", 60, 10, 95,
               relevant=lambda i: _service(i) and i.get("autoscaling", "none") != "none"),
        FieldSpec("env_vars", "Environment variables? (optional: KEY=value; OTHER=value, no secrets)", "text",
                  default="", allow_empty=True, validate=_validate_env, relevant=custom),
        FieldSpec("secrets", "Secrets from Secrets Manager / SSM? (optional: DB_PASSWORD=<secret ARN or "
                             "/ssm/parameter>)", "text", default="", allow_empty=True, validate=_validate_secret_refs,
                  relevant=custom,
                  why="Only the reference is stored; ECS injects the value when the task starts."),
        FieldSpec("exec_role", "Task execution role (lets ECS pull the image and write logs)?", "choice",
                  default="new", options=_role_options("ecs-tasks.amazonaws.com", "AmazonECSTaskExecutionRolePolicy"),
                  validate=_validate_role("ecs-tasks.amazonaws.com", "AmazonECSTaskExecutionRolePolicy"),
                  relevant=custom),
        FieldSpec("task_role", "Task role (permissions for YOUR code to call AWS)?", "choice", default="none",
                  options=lambda e, i: [{"value": "none", "label": "None"}] + _role_options(
                      "ecs-tasks.amazonaws.com", "the AWS managed policies you pick")(e, i),
                  validate=lambda e, i, v: "none" if str(v).lower() == "none" else _validate_role(
                      "ecs-tasks.amazonaws.com", "policies")(e, i, v), relevant=custom),
        FieldSpec("task_policies", "Which permissions for the new task role?", "multichoice", must_ask=True,
                  options=lambda e, i: [{"value": k, "label": k} for k in MANAGED_POLICIES
                                        if k not in ("ReadOnlyAccess", "AmazonEKSClusterPolicy",
                                                     "AmazonEKSWorkerNodePolicy", "AmazonEKS_CNI_Policy")],
                  validate=lambda e, i, v: [x for x in ids(v) if x in MANAGED_POLICIES] or _choice([], v, "policy"),
                  relevant=lambda i: i.get("task_role") == "new"),
        settings_field(),
        choice("cpu_arch", "CPU architecture?", opts(("X86_64", "x86_64 (Intel/AMD)"), ("ARM64", "ARM64 (Graviton, "
                                                                                            "~20% cheaper)")),
               default="X86_64", relevant=custom),
        yes_no("exec_command", "Enable ECS Exec (shell into running containers)?", relevant=custom),
        yes_no("insights", "Container Insights (extra CloudWatch metrics, paid)?", relevant=custom),
        number("log_days", "Keep logs for how many days?", 14, 1, 3653, relevant=custom),
        extra_params_field(lambda i: ("ecs", "create_service"),
                           {"cluster", "serviceName", "taskDefinition", "desiredCount", "networkConfiguration",
                            "loadBalancers", "launchType", "capacityProviderStrategy", "tags"},
                           relevant=lambda i: custom(i) and _service(i), key="svc_extra"),
        extra_params_field(lambda i: ("ecs", "register_task_definition"),
                           {"family", "containerDefinitions", "executionRoleArn", "taskRoleArn", "tags",
                            "networkMode", "requiresCompatibilities", "cpu", "memory"}, key="td_extra"),
    ],
    title=lambda i: f"ECS app '{i.get('name', 'kintsugi-app')}'",
    build=_build_ecs, notes=_ecs_notes,
)


APP_SOURCES = opts(("dockerfile", "A folder with a Dockerfile: build it, push to ECR, deploy with a public load balancer"),
                   ("manifests", "A folder of Kubernetes YAML manifests: kubectl apply them"),
                   ("helm", "A Helm chart from a chart repository"),
                   ("none", "No app, just the cluster"))
NODE_TYPES = ["t3.small", "t3.medium", "t3.large", "t4g.medium", "m6i.large", "c6i.large"]
COMPUTE = opts(("managed", "Managed node group (EC2 nodes you size)"),
               ("spot", "Managed node group on Spot (cheaper, can be interrupted)"),
               ("auto", "EKS Auto Mode (AWS manages nodes, scaling, load balancers and storage; extra fee)"),
               ("fargate", "Fargate (no nodes; pods run serverless; default + kube-system namespaces)"))
ADDONS = ["metrics-server", "aws-ebs-csi-driver", "eks-pod-identity-agent", "amazon-cloudwatch-observability",
          "aws-efs-csi-driver", "snapshot-controller"]
LOG_TYPES = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
K8S_VERSIONS = ["1.33", "1.32", "1.31", "1.30"]


def _k8s_versions(env) -> list[str]:
    def load():
        try:
            eks = env.conn.client("eks", "read", env.region)
            got = [x["clusterVersion"] for x in eks.describe_cluster_versions(defaultOnly=False).get("clusterVersions", [])
                   if x.get("status") in ("STANDARD_SUPPORT", "standard-support", None)]
            return sorted(set(got), key=lambda s: [int(p) for p in s.split(".")], reverse=True) or K8S_VERSIONS
        except Exception:
            return K8S_VERSIONS
    return env._memo("k8s_versions", load)


def _eks_hourly(v: dict) -> float:
    if v.get("compute") == "fargate":
        return EKS_CONTROL_PLANE_HOUR + 2 * (0.25 * FARGATE_VCPU_HOUR + 0.5 * FARGATE_GB_HOUR)
    n = int(v.get("nodes", 2) or 2)
    node = INSTANCE_PRICES.get(v.get("node_type", "t3.medium"), EC2_HOURLY.get(v.get("node_type"), 0.0416))
    if v.get("compute") == "spot":
        node *= 0.35
    if v.get("compute") == "auto":
        node *= 1.12
    lb = CLASSIC_LB_HOUR if v.get("app_source") == "dockerfile" else 0
    return EKS_CONTROL_PLANE_HOUR + n * (node + PUBLIC_IPV4_HOURLY) + lb


def _eks_notes(v: dict) -> list[str]:
    h = _eks_hourly(v)
    notes = [f"COST WARNING: EKS control plane ~${EKS_CONTROL_PLANE_HOUR}/hour + nodes + load balancer ~ "
             f"${h:.2f}/hour (~${h * 24:.1f}/day, ~${h * HOURS_PER_MONTH:.0f}/month). A $5 budget is used up in "
             f"about {5 / h:.0f} hours. Run the teardown script right after testing. Approximate us-east-1 prices.",
             "Creating the cluster takes 15-25 minutes; deleting it takes about 10-15 minutes.",
             "eksctl creates IAM roles and CloudFormation stacks: your Write connection needs IAM, EC2, EKS and "
             "CloudFormation permissions.",
             "A new VPC made by eksctl has NO NAT gateway here (nodes get public IPs) to save money."]
    if v.get("compute") == "auto":
        notes.append("EKS Auto Mode adds a management fee on top of the instance price (~12%) and scales nodes "
                     "automatically (Karpenter).")
    if v.get("compute") == "fargate":
        notes.append("Fargate pods need private subnets with a NAT gateway to pull public images; with this cheap "
                     "no-NAT network use images from ECR via VPC endpoints, or choose managed nodes.")
    if yes(v, "hpa"):
        notes.append("Pod autoscaling (HPA) needs metrics-server; it is added automatically.")
    return notes


def _validate_cost_ok(env, inputs, v) -> str:
    if _yes_no(v) != "yes":
        raise ValueError("cancelled: nothing will be created")
    return "yes"


def _validate_manifests(env, inputs, v) -> str:
    folder = workspace.user_folder(v)
    files = [p for p in folder.rglob("*") if p.suffix.lower() in (".yaml", ".yml")]
    if not files:
        raise ValueError("no .yaml/.yml files in that folder")
    return str(folder)


def _validate_app_folder(env, inputs, v) -> str:
    if inputs.get("app_source") == "manifests":
        return _validate_manifests(env, inputs, v)
    return _validate_docker_folder(env, inputs, v)


def _validate_chart(env, inputs, v) -> str:
    v = str(v).strip()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9.-]*|oci://[\w./:-]+", v):
        raise ValueError("a chart like bitnami/nginx (repo-name/chart) or oci://registry/path/chart")
    return v


def _validate_repo_url(env, inputs, v) -> str:
    v = str(v).strip()
    if not re.fullmatch(r"https://[\w.-]+(/[\w./~-]*)?", v):
        raise ValueError("an https:// chart repository URL, e.g. https://charts.bitnami.com/bitnami")
    return v


def _validate_values_file(env, inputs, v) -> str:
    if not str(v or "").strip():
        return ""
    p = Path(str(v).strip().strip('"'))
    if not p.is_file() or p.suffix.lower() not in (".yaml", ".yml"):
        raise ValueError("a .yaml values file")
    return str(p)


def _validate_namespace(env, inputs, v) -> str:
    v = str(v).strip() or "default"
    if not re.fullmatch(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?", v):
        raise ValueError("lowercase letters, numbers and - (max 63)")
    return v


def eksctl_config(v: dict, region: str) -> str:
    """Fixed-template eksctl ClusterConfig (YAML) for the chosen compute, network, add-ons and logs."""
    tags = "\n".join(f"    {k}: \"{val}\"" for k, val in tag_dict(v["name"]).items())
    meta = f"  name: {v['name']}\n  region: {region}\n"
    if v.get("version"):
        meta += f"  version: \"{v['version']}\"\n"
    out = (f"# Generated by Kintsugi from a fixed template. Used by: eksctl create cluster -f cluster.yaml\n"
           f"apiVersion: eksctl.io/v1alpha5\nkind: ClusterConfig\nmetadata:\n{meta}  tags:\n{tags}\n")
    addons = list(dict.fromkeys(v.get("addons", []) + (["metrics-server"] if yes(v, "hpa") else [])))
    if "aws-ebs-csi-driver" in addons or "aws-efs-csi-driver" in addons:
        out += "iam:\n  withOIDC: true\n"
    endpoint = v.get("endpoint", "public")
    if v.get("network", "new") == "new":
        out += "vpc:\n  nat:\n    gateway: Disable\n"
    else:
        lines = [f"      {s['az']}: {{ id: {s['id']} }}" for s in v["_subnets"]]
        out += "vpc:\n  subnets:\n    public:\n" + "\n".join(lines) + "\n"
    if endpoint == "public_private":
        out += "  clusterEndpoints:\n    publicAccess: true\n    privateAccess: true\n"
    compute = v.get("compute", "managed")
    if compute == "auto":
        out += "autoModeConfig:\n  enabled: true\n"
    elif compute == "fargate":
        out += ("fargateProfiles:\n  - name: default\n    selectors:\n      - namespace: default\n"
                "      - namespace: kube-system\n")
    else:
        n = int(v.get("nodes", 2))
        lo, hi = int(v.get("min_nodes", 1) or 1), max(n, int(v.get("max_nodes", n) or n))
        spot = "    spot: true\n" if compute == "spot" else ""
        types = [v.get("node_type", "t3.medium")] + ([t for t in ("t3.medium", "t3a.medium", "t3.large")
                                                      if t != v.get("node_type")][:2] if compute == "spot" else [])
        itype = f"    instanceTypes: [{', '.join(types)}]\n" if compute == "spot" else \
            f"    instanceType: {v.get('node_type', 't3.medium')}\n"
        out += (f"managedNodeGroups:\n  - name: {v['name']}-nodes\n{itype}{spot}"
                f"    desiredCapacity: {n}\n    minSize: {lo}\n    maxSize: {hi}\n    volumeSize: 20\n"
                f"    tags:\n{tags.replace('    ', '      ')}\n")
    if addons and compute != "auto":
        out += "addons:\n"
        for a in addons:
            out += f"  - name: {a}\n"
            if a == "aws-ebs-csi-driver":
                out += "    wellKnownPolicies:\n      ebsCSIController: true\n"
            if a == "aws-efs-csi-driver":
                out += "    wellKnownPolicies:\n      efsCSIController: true\n"
    if v.get("logs"):
        out += f"cloudWatch:\n  clusterLogging:\n    enableTypes: [{', '.join(v['logs'])}]\n    logRetentionInDays: 7\n"
    return out


def k8s_app_manifest(name: str, image: str, port: int, replicas: int = 1, hpa: dict | None = None,
                     namespace: str = "default") -> str:
    out = f"""# Generated by Kintsugi from a fixed template.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
  namespace: {namespace}
  labels: {{app: {name}}}
spec:
  replicas: {replicas}
  selector:
    matchLabels: {{app: {name}}}
  template:
    metadata:
      labels: {{app: {name}}}
    spec:
      containers:
        - name: {name}
          image: {image}
          ports:
            - containerPort: {port}
          resources:
            requests: {{cpu: 100m, memory: 128Mi}}
            limits: {{memory: 512Mi}}
---
apiVersion: v1
kind: Service
metadata:
  name: {name}
  namespace: {namespace}
spec:
  type: LoadBalancer
  selector: {{app: {name}}}
  ports:
    - port: 80
      targetPort: {port}
"""
    if hpa:
        out += f"""---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {name}
  namespace: {namespace}
spec:
  scaleTargetRef: {{apiVersion: apps/v1, kind: Deployment, name: {name}}}
  minReplicas: {hpa['min']}
  maxReplicas: {hpa['max']}
  metrics:
    - type: Resource
      resource:
        name: cpu
        target: {{type: Utilization, averageUtilization: {hpa['cpu']}}}
"""
    return out


def app_steps(env, v: dict, name: str, d: Path, kubeconfig: str, region: str) -> tuple[list[dict], list[str]]:
    """Deploy a Dockerfile app, a manifests folder or a Helm chart to a cluster (kubeconfig in the task folder)."""
    steps, notes = [], []
    src = v.get("app_source", "none")
    ns = v.get("namespace", "default") or "default"
    app = None
    if src == "dockerfile":
        image = v.get("_image_built")
        if not image:
            img_steps, image, warns = image_steps(env, name, v["app_folder"])
            steps += img_steps
            notes += warns
        hpa = {"min": int(v.get("min_pods", 1)), "max": int(v.get("max_pods", 5)), "cpu": int(v.get("hpa_cpu", 70))} \
            if yes(v, "hpa") else None
        app = workspace.write(d / "k8s" / "app.yaml", k8s_app_manifest(name, image, int(v["container_port"]),
                                                                       int(v.get("replicas", 1)), hpa, ns))
    elif src == "manifests":
        app = Path(v["app_folder"])
    if app:
        apply_args = ["apply", "-f", str(app)] + (["-R"] if app.is_dir() else []) + ["--kubeconfig", kubeconfig]
        delete_args = ["delete", "-f", str(app)] + (["-R"] if app.is_dir() else []) + \
                      ["--kubeconfig", kubeconfig, "--ignore-not-found=true", "--wait=true"]
        steps.append(cmd("kubectl", apply_args, f"Deploy the app to the cluster ({app.name})", timeout=900,
                         undo_step={"kind": "command", "tool": "kubectl", "args": delete_args, "timeout": 900,
                                    "pause_after": 60,
                                    "description": "Delete the app (and its load balancer) from the cluster"}))
        steps.append(cmd("kubectl", ["get", "deployments,services,pods", "--kubeconfig", kubeconfig, "-o", "wide",
                                     "-n", ns], "Show what is running"))
    if src == "helm":
        release, chart = v.get("release") or name, v["chart"]
        if not chart.startswith("oci://"):
            repo = chart.split("/", 1)[0]
            steps.append(cmd("helm", ["repo", "add", repo, v["repo_url"], "--force-update"],
                             f"Add Helm repository {repo}"))
            steps.append(cmd("helm", ["repo", "update", repo], "Update the chart index"))
        args = ["upgrade", "--install", release, chart, "--namespace", ns, "--create-namespace",
                "--kubeconfig", kubeconfig, "--wait", "--timeout", "15m"]
        if v.get("values_file"):
            args += ["-f", v["values_file"]]
        steps.append(cmd("helm", args, f"Install Helm chart {chart} as release {release} in namespace {ns}",
                         timeout=1200,
                         undo_step={"kind": "command", "tool": "helm", "timeout": 900, "pause_after": 60,
                                    "args": ["uninstall", release, "--namespace", ns, "--kubeconfig", kubeconfig, "--wait"],
                                    "description": f"Uninstall Helm release {release}"}))
        steps.append(cmd("kubectl", ["get", "all", "-n", ns, "--kubeconfig", kubeconfig], "Show what is running"))
    if src == "dockerfile":
        steps.append(check("k8s_url", {"kubeconfig": kubeconfig, "service": name, "path": "/", "namespace": ns},
                           "Wait for the load balancer and check the app answers", timeout=1200))
    return steps, notes


def _app_fields(rel=lambda i: True) -> list[FieldSpec]:
    return [
        FieldSpec("app_source", "What should run on the cluster?", "choice", must_ask=True, options=static(APP_SOURCES),
                  validate=lambda e, i, v: _choice(APP_SOURCES, v, "app source"), relevant=rel),
        FieldSpec("app_folder", "Which Dockerfile / folder?", "path", must_ask=True, validate=_validate_app_folder,
                  relevant=lambda i: rel(i) and i.get("app_source") in ("dockerfile", "manifests")),
        FieldSpec("container_port", "Which port does the app listen on inside the container?", "number",
                  must_ask=True, default=_docker_port_default, validate=lambda e, i, v: _int(v, 1, 65535, "port"),
                  relevant=lambda i: rel(i) and i.get("app_source") == "dockerfile"),
        number("replicas", "How many copies (pods)?", 1, 1, 20,
               relevant=lambda i: rel(i) and i.get("app_source") == "dockerfile"),
        yes_no("hpa", "Autoscale pods on CPU (Horizontal Pod Autoscaler)?",
               relevant=lambda i: rel(i) and i.get("app_source") == "dockerfile"),
        number("min_pods", "Minimum pods?", 1, 1, 50, relevant=lambda i: rel(i) and yes(i, "hpa")),
        number("max_pods", "Maximum pods?", 5, 1, 100, relevant=lambda i: rel(i) and yes(i, "hpa")),
        number("hpa_cpu", "Target CPU % per pod?", 70, 10, 95, relevant=lambda i: rel(i) and yes(i, "hpa")),
        FieldSpec("chart", "Which Helm chart? (repo-name/chart, e.g. bitnami/nginx, or oci://...)", "text",
                  must_ask=True, validate=_validate_chart, relevant=lambda i: rel(i) and i.get("app_source") == "helm"),
        FieldSpec("repo_url", "Chart repository URL?", "text", must_ask=True, validate=_validate_repo_url,
                  relevant=lambda i: rel(i) and i.get("app_source") == "helm"
                  and not str(i.get("chart", "")).startswith("oci://")),
        FieldSpec("release", "Release name?", "text", default=lambda e, i: str(i.get("chart", "app")).rsplit("/", 1)[-1],
                  validate=_name_validator(r"[a-z0-9]([-a-z0-9]{0,51}[a-z0-9])?", "lowercase letters, numbers, - (max 53)"),
                  relevant=lambda i: rel(i) and i.get("app_source") == "helm"),
        FieldSpec("values_file", "Values file? (optional .yaml)", "file", default="", allow_empty=True,
                  validate=_validate_values_file, relevant=lambda i: rel(i) and i.get("app_source") == "helm"),
        FieldSpec("namespace", "Kubernetes namespace?", "text", default="default", validate=_validate_namespace,
                  relevant=lambda i: rel(i) and i.get("app_source", "none") != "none"),
    ]


def _build_eks(env, v) -> ScriptDraft:
    tools = ["eksctl", "kubectl", "aws"]
    if v["app_source"] == "dockerfile":
        tools.append("docker")
    if v["app_source"] == "helm":
        tools.append("helm")
    _check_tools(*tools)
    name, region = v["name"], env.region_name
    if v.get("network", "new") != "new":
        subs = {s["id"]: s for s in env.subnets()}
        v = {**v, "_subnets": [subs[x] for x in v["subnets"]]}
    d = workspace.new_task_dir(f"eks-{name}")
    cfg = workspace.write(d / "cluster.yaml", eksctl_config(v, region))
    kubeconfig = str(d / "kubeconfig")
    steps, notes = [], _eks_notes(v) + [f"Files: {d}"]
    if v.get("network", "new") != "new":
        sids = [s["id"] for s in v["_subnets"]]
        steps.append(aws_step("ec2", "create_tags",
                              {"Resources": sids, "Tags": [{"Key": "kubernetes.io/role/elb", "Value": "1"}]},
                              "Tag the subnets so Kubernetes can place public load balancers in them",
                              undo=undo("ec2", "delete_tags", {"Resources": sids,
                                                               "Tags": [{"Key": "kubernetes.io/role/elb"}]},
                                        "Remove the load balancer tag from the subnets")))
    if v["app_source"] == "dockerfile":
        img, image, warns = image_steps(env, name, v["app_folder"])
        steps += img
        notes += warns
        v = {**v, "_image_built": image}
    what = {"managed": f"{v.get('nodes', 2)} x {v.get('node_type', 't3.medium')} nodes",
            "spot": f"{v.get('nodes', 2)} Spot nodes", "auto": "EKS Auto Mode", "fargate": "Fargate"}[v.get("compute", "managed")]
    steps.append(cmd("eksctl", ["create", "cluster", "-f", str(cfg), "--write-kubeconfig=false"],
                     f"Create EKS cluster {name} with {what} (15-25 minutes)", timeout=3600,
                     undo_step={"kind": "command", "tool": "eksctl", "timeout": 3600,
                                "args": ["delete", "cluster", "-f", str(cfg), "--wait", "--disable-nodegroup-eviction"],
                                "description": f"Delete EKS cluster {name} and its node group (10-15 minutes)"}))
    steps.append(cmd("aws", ["eks", "update-kubeconfig", "--name", name, "--region", region, "--kubeconfig", kubeconfig],
                     "Write a kubeconfig for this cluster (in the task folder, not your default one)"))
    if v["app_source"] != "none":
        more, extra_notes = app_steps(env, v, name, d, kubeconfig, region)
        steps += more
        notes += extra_notes
    label = {"dockerfile": lambda: docker_context(v["app_folder"])[0].name, "manifests": lambda: Path(v["app_folder"]).name,
             "helm": lambda: v.get("chart", ""), "none": lambda: ""}[v["app_source"]]()
    return ScriptDraft(title=f"Create EKS cluster {name}" + (f" and deploy {label}" if label else ""),
                       steps=steps, notes=notes)


EKS = Template(
    name="eks_cluster",
    description="EKS cluster (eksctl): managed / Spot nodes, Auto Mode or Fargate, version, add-ons, logs; deploys "
                "a Dockerfile app (+HPA), YAML manifests or a Helm chart",
    fields=[
        FieldSpec("cost_ok", "EKS costs about $0.25/hour or more (~$5 per day). Continue?", "choice", must_ask=True,
                  options=lambda e, i: [{"value": "yes", "label": "Yes, I understand and will tear it down after testing"}],
                  validate=_validate_cost_ok, why="The control plane alone is billed per hour, even when idle."),
        FieldSpec("name", "Cluster name?", "text", default="kintsugi-eks",
                  validate=_name_validator(r"[a-z][a-z0-9-]{1,30}", "lowercase letters, numbers and - (max 31)")),
        choice("compute", "How should pods get compute?", COMPUTE, default="managed"),
        *_app_fields(),
        FieldSpec("network", "Which network?", "choice", must_ask=True, default="new",
                  options=lambda e, i: [{"value": "new", "label": "New VPC created by eksctl (no NAT gateway; recommended)"},
                                        {"value": "existing", "label": "Existing public subnets (pick 2+ zones)"}],
                  validate=lambda e, i, v: _choice([{"value": "new", "label": "new"},
                                                    {"value": "existing", "label": "existing"}], v, "network")),
        FieldSpec("subnets", "Which public subnets (2 or more availability zones)?", "multichoice", must_ask=True,
                  options=_public_subnet_options, validate=_validate_public_subnets(2),
                  relevant=lambda i: i.get("network") == "existing"),
        FieldSpec("node_type", "Node size?", "choice", must_ask=True, default="t3.medium",
                  options=lambda e, i: [{"value": t, "label": f"{t} (~${INSTANCE_PRICES.get(t, 0)}/hour each)"}
                                        for t in NODE_TYPES],
                  validate=lambda e, i, v: _choice([{"value": t, "label": t} for t in NODE_TYPES], v, "node size"),
                  relevant=lambda i: i.get("compute", "managed") in ("managed", "spot")),
        FieldSpec("nodes", "How many nodes?", "number", default=2, validate=lambda e, i, v: _int(v, 1, 10, "nodes"),
                  relevant=lambda i: i.get("compute", "managed") in ("managed", "spot")),
        settings_field(),
        FieldSpec("version", "Kubernetes version?", "choice", default=lambda e, i: _k8s_versions(e)[0],
                  options=lambda e, i: [{"value": x, "label": x} for x in _k8s_versions(e)],
                  validate=lambda e, i, v: _choice([{"value": x, "label": x} for x in _k8s_versions(e)], str(v), "version"),
                  relevant=custom),
        number("min_nodes", "Minimum nodes?", 1, 0, 10,
               relevant=lambda i: custom(i) and i.get("compute", "managed") in ("managed", "spot")),
        number("max_nodes", "Maximum nodes?", lambda e, i: i.get("nodes", 2), 1, 20,
               relevant=lambda i: custom(i) and i.get("compute", "managed") in ("managed", "spot")),
        FieldSpec("addons", "Extra add-ons?", "multichoice", default=["metrics-server"],
                  options=lambda e, i: [{"value": a, "label": a} for a in ADDONS],
                  validate=pick_many(lambda e, i: [{"value": a, "label": a} for a in ADDONS], "add-ons", 0),
                  relevant=lambda i: custom(i) and i.get("compute") != "auto"),
        FieldSpec("logs", "Control plane logs to CloudWatch? (paid)", "multichoice", default=["api", "audit"],
                  options=lambda e, i: [{"value": a, "label": a} for a in LOG_TYPES],
                  validate=pick_many(lambda e, i: [{"value": a, "label": a} for a in LOG_TYPES], "log types", 0),
                  relevant=custom),
        choice("endpoint", "API endpoint access?",
               opts(("public", "Public"), ("public_private", "Public and private (nodes use the private endpoint)")),
               default="public", relevant=custom),
    ],
    title=lambda i: f"EKS cluster '{i.get('name', 'kintsugi-eks')}'",
    build=_build_eks, notes=_eks_notes,
)


EKS_ACTIONS = opts(("deploy", "Deploy an app (Dockerfile, YAML manifests or Helm chart)"),
                   ("scale", "Scale a node group (desired / min / max)"),
                   ("add_nodegroup", "Add a node group"), ("addon", "Install an add-on"),
                   ("upgrade", "Upgrade the Kubernetes version"),
                   ("logging", "Turn control plane logs on or off"),
                   ("delete", "Delete the whole cluster"))
ADDON_NAMES = ["vpc-cni", "coredns", "kube-proxy"] + ADDONS


def _eks_cluster_options(env, inputs):
    return [{"value": c, "label": c} for c in lookups.eks_clusters(env)]


def _nodegroup_options(env, inputs):
    c = inputs.get("cluster")
    return [{"value": n, "label": n} for n in lookups.eks_nodegroups(env, c)] if c else []


def _nodegroup(env, inputs) -> dict:
    try:
        eks = env.conn.client("eks", "read", env.region)
        return eks.describe_nodegroup(clusterName=inputs["cluster"], nodegroupName=inputs["nodegroup"])["nodegroup"]
    except Exception:
        return {}


def _next_version(env, inputs) -> list[dict]:
    cur = lookups.eks_cluster(env, inputs["cluster"]).get("version", "1.30") if inputs.get("cluster") else "1.30"
    major, minor = (int(x) for x in cur.split("."))
    nxt = f"{major}.{minor + 1}"
    return [{"value": nxt, "label": f"{nxt} (from {cur}; one minor version at a time)"}]


def _build_eks_manage(env, v) -> ScriptDraft:
    name, region, a = v["cluster"], env.region_name, v["action"]
    if a == "deploy":
        tools = ["kubectl", "aws"] + (["docker"] if v.get("app_source") == "dockerfile" else []) + \
                (["helm"] if v.get("app_source") == "helm" else [])
        _check_tools(*tools)
        d = workspace.new_task_dir(f"eks-{name}-deploy")
        kubeconfig = str(d / "kubeconfig")
        steps = [cmd("aws", ["eks", "update-kubeconfig", "--name", name, "--region", region, "--kubeconfig", kubeconfig],
                     "Write a kubeconfig for this cluster (in the task folder)")]
        app_name = v.get("release") or (docker_context(v["app_folder"])[0].name.lower()[:30]
                                        if v.get("app_source") == "dockerfile" else name)
        app_name = re.sub(r"[^a-z0-9-]", "-", app_name).strip("-") or "app"
        more, notes = app_steps(env, v, app_name, d, kubeconfig, region)
        return ScriptDraft(title=f"Deploy to EKS cluster {name}", steps=steps + more,
                           notes=notes + ["The cluster keeps running; only the app is removed by the teardown."])
    if a == "scale":
        ng = _nodegroup(env, v)
        cur = ng.get("scalingConfig", {})
        steps = [aws_step("eks", "update_nodegroup_config",
                          {"clusterName": name, "nodegroupName": v["nodegroup"],
                           "scalingConfig": {"desiredSize": v["desired"], "minSize": v["min_nodes"],
                                             "maxSize": max(v["max_nodes"], v["desired"])}},
                          f"Scale {v['nodegroup']} to desired {v['desired']} (min {v['min_nodes']}, max {v['max_nodes']})",
                          undo=undo("eks", "update_nodegroup_config",
                                    {"clusterName": name, "nodegroupName": v["nodegroup"],
                                     "scalingConfig": {"desiredSize": cur.get("desiredSize", 1),
                                                       "minSize": cur.get("minSize", 1),
                                                       "maxSize": cur.get("maxSize", 1)}},
                                    "Put the node group back to its previous size") if cur else None)]
        return ScriptDraft(title=f"Scale node group {v['nodegroup']}", steps=steps,
                           notes=["Each node costs its instance price per hour."])
    if a == "add_nodegroup":
        _check_tools("eksctl")
        ng = v["new_nodegroup"]
        args = ["create", "nodegroup", "--cluster", name, "--region", region, "--name", ng, "--node-type",
                v.get("node_type", "t3.medium"), "--nodes", str(v["desired"]), "--nodes-min", str(v["min_nodes"]),
                "--nodes-max", str(max(v["max_nodes"], v["desired"])), "--managed"]
        if yes(v, "spot"):
            args.append("--spot")
        steps = [cmd("eksctl", args, f"Add node group {ng} ({v['desired']} x {v.get('node_type', 't3.medium')}"
                                     f"{', Spot' if yes(v, 'spot') else ''})", timeout=2400,
                     undo_step={"kind": "command", "tool": "eksctl", "timeout": 2400,
                                "args": ["delete", "nodegroup", "--cluster", name, "--region", region, "--name", ng,
                                         "--wait"],
                                "description": f"Delete node group {ng}"})]
        return ScriptDraft(title=f"Add node group {ng} to {name}", steps=steps,
                           notes=[f"COST: ~${INSTANCE_PRICES.get(v.get('node_type', 't3.medium'), 0.0416)}/hour per node."])
    if a == "addon":
        addon = v["addon"]
        steps = [aws_step("eks", "create_addon", {"clusterName": name, "addonName": addon, "resolveConflicts": "OVERWRITE",
                                                  "tags": tag_dict(f"{name}-{addon}")},
                          f"Install add-on {addon} (waits until active)",
                          wait={"waiter": "addon_active", "params": {"clusterName": name, "addonName": addon}},
                          undo=undo("eks", "delete_addon", {"clusterName": name, "addonName": addon},
                                    f"Remove add-on {addon}",
                                    wait={"waiter": "addon_deleted", "params": {"clusterName": name, "addonName": addon}}))]
        notes = []
        if addon in ("aws-ebs-csi-driver", "aws-efs-csi-driver"):
            notes.append(f"{addon} needs an IAM role for its service account (Pod Identity or IRSA); without it the "
                         "add-on installs but cannot create volumes.")
        return ScriptDraft(title=f"Add-on {addon} on {name}", steps=steps, notes=notes)
    if a == "upgrade":
        steps = [aws_step("eks", "update_cluster_version", {"name": name, "version": v["version"]},
                          f"Upgrade the control plane of {name} to Kubernetes {v['version']} (waits, 20-40 min)",
                          wait={"waiter": "cluster_active", "params": {"name": name}, "delay": 30, "max_attempts": 120})]
        return ScriptDraft(title=f"Upgrade {name} to {v['version']}", steps=steps,
                           notes=["Upgrades cannot be undone. Upgrade node groups and add-ons afterwards (eksctl "
                                  "upgrade nodegroup). Check your workloads for removed Kubernetes APIs first."])
    if a == "logging":
        on = v.get("logs", [])
        off = [t for t in LOG_TYPES if t not in on]
        cfg = {"clusterLogging": [x for x in ({"types": on, "enabled": True} if on else None,
                                              {"types": off, "enabled": False} if off else None) if x]}
        steps = [aws_step("eks", "update_cluster_config", {"name": name, "logging": cfg},
                          f"Control plane logs on: {', '.join(on) or 'none'}")]
        return ScriptDraft(title=f"Control plane logging for {name}", steps=steps,
                           notes=["CloudWatch Logs ingestion is ~$0.50/GB."])
    _check_tools("eksctl")
    steps = [cmd("eksctl", ["delete", "cluster", "--name", name, "--region", region, "--wait",
                            "--disable-nodegroup-eviction"], f"Delete EKS cluster {name} and all node groups", timeout=3600)]
    return ScriptDraft(title=f"Delete EKS cluster {name}", steps=steps,
                       notes=["Deletes the cluster, node groups and the eksctl-created VPC. Delete Kubernetes "
                              "Services of type LoadBalancer first, or their load balancers may be left behind."])


EKS_MANAGE = Template(
    name="eks_manage",
    description="Existing EKS cluster: deploy an app / manifests / Helm chart, scale or add node groups, add-ons, "
                "version upgrade, logging, delete",
    fields=[
        FieldSpec("cluster", "Which EKS cluster?", "choice", must_ask=True, options=_eks_cluster_options,
                  validate=pick(_eks_cluster_options, "cluster"),
                  empty_hint="No EKS clusters in this region. Create one first (eks_cluster)."),
        choice("action", "What do you want to do?", EKS_ACTIONS, default="deploy", must_ask=True),
        *_app_fields(action_is("deploy")),
        FieldSpec("nodegroup", "Which node group?", "choice", must_ask=True, options=_nodegroup_options,
                  validate=pick(_nodegroup_options, "node group"), relevant=action_is("scale"),
                  empty_hint="This cluster has no managed node groups."),
        FieldSpec("new_nodegroup", "Name for the new node group?", "text", default="extra-nodes",
                  validate=_name_validator(r"[a-z][a-z0-9-]{1,40}", "lowercase letters, numbers and -"),
                  relevant=action_is("add_nodegroup")),
        FieldSpec("node_type", "Node size?", "choice", default="t3.medium",
                  options=lambda e, i: [{"value": t, "label": f"{t} (~${INSTANCE_PRICES.get(t, 0)}/hour)"} for t in NODE_TYPES],
                  validate=lambda e, i, v: _choice([{"value": t, "label": t} for t in NODE_TYPES], v, "node size"),
                  relevant=action_is("add_nodegroup")),
        yes_no("spot", "Spot instances?", relevant=action_is("add_nodegroup")),
        FieldSpec("desired", "Desired nodes?", "number",
                  default=lambda e, i: _nodegroup(e, i).get("scalingConfig", {}).get("desiredSize", 2)
                  if i.get("nodegroup") else 2,
                  validate=lambda e, i, v: _int(v, 0, 20, "desired nodes"), relevant=action_is("scale", "add_nodegroup")),
        FieldSpec("min_nodes", "Minimum nodes?", "number",
                  default=lambda e, i: _nodegroup(e, i).get("scalingConfig", {}).get("minSize", 1)
                  if i.get("nodegroup") else 1,
                  validate=lambda e, i, v: _int(v, 0, 20, "minimum nodes"), relevant=action_is("scale", "add_nodegroup")),
        FieldSpec("max_nodes", "Maximum nodes?", "number",
                  default=lambda e, i: _nodegroup(e, i).get("scalingConfig", {}).get("maxSize", 3)
                  if i.get("nodegroup") else 3,
                  validate=lambda e, i, v: _int(v, 1, 30, "maximum nodes"), relevant=action_is("scale", "add_nodegroup")),
        FieldSpec("addon", "Which add-on?", "choice", must_ask=True,
                  options=lambda e, i: [{"value": a, "label": a} for a in ADDON_NAMES],
                  validate=lambda e, i, v: _choice([{"value": a, "label": a} for a in ADDON_NAMES], v, "add-on"),
                  relevant=action_is("addon")),
        FieldSpec("version", "Upgrade to which version?", "choice", must_ask=True, options=_next_version,
                  default=lambda e, i: _next_version(e, i)[0]["value"],
                  validate=lambda e, i, v: _choice(_next_version(e, i), str(v), "version"), relevant=action_is("upgrade")),
        FieldSpec("logs", "Which control plane logs should be ON?", "multichoice", default=["api", "audit"],
                  options=lambda e, i: [{"value": a, "label": a} for a in LOG_TYPES],
                  validate=pick_many(lambda e, i: [{"value": a, "label": a} for a in LOG_TYPES], "log types", 0),
                  relevant=action_is("logging")),
    ],
    title=lambda i: f"EKS cluster '{i.get('cluster', '')}' ({i.get('action', 'deploy')})",
    build=_build_eks_manage, notes=lambda i: [],
)


ECR_ACTIONS = opts(("create", "Create a repository"), ("configure", "Change settings of an existing repository"),
                   ("replication", "Replicate images to other regions (registry setting)"),
                   ("pull_through", "Pull-through cache for a public registry"),
                   ("scanning", "Registry-wide image scanning (basic or enhanced)"),
                   ("delete", "Delete a repository and its images"))
LIFECYCLE = opts(("standard", "Keep the last N images and delete untagged images after N days (recommended)"),
                 ("keep_last", "Keep only the last N images"), ("untagged", "Delete untagged images after N days"),
                 ("none", "No lifecycle rules (images are kept forever)"))
UPSTREAMS = {"ecr-public": "public.ecr.aws", "k8s": "registry.k8s.io", "quay": "quay.io"}


def _ecr_options(env, inputs):
    return [{"value": r["name"], "label": f"{r['name']} · {r['mutability']}"} for r in lookups.ecr_repositories(env)]


def lifecycle_policy(mode: str, keep: int, days: int) -> str | None:
    rules = []
    if mode in ("standard", "untagged"):
        rules.append({"rulePriority": 1, "description": f"Delete untagged images after {days} days",
                      "selection": {"tagStatus": "untagged", "countType": "sinceImagePushed", "countUnit": "days",
                                    "countNumber": days}, "action": {"type": "expire"}})
    if mode in ("standard", "keep_last"):
        rules.append({"rulePriority": len(rules) + 1, "description": f"Keep only the last {keep} images",
                      "selection": {"tagStatus": "any", "countType": "imageCountMoreThan", "countNumber": keep},
                      "action": {"type": "expire"}})
    return json.dumps({"rules": rules}) if rules else None


def _registry(env) -> dict:
    return env._memo("ecr_registry", lambda: env.conn.client("ecr", "read", env.region).describe_registry())


def _ecr_settings_steps(repo: str, v: dict, creating: bool) -> list[dict]:
    steps = []
    if not creating:
        steps.append(aws_step("ecr", "put_image_tag_mutability",
                              {"repositoryName": repo, "imageTagMutability": v.get("mutability", "IMMUTABLE")},
                              f"Tags: {v.get('mutability', 'IMMUTABLE').lower()}"))
        steps.append(aws_step("ecr", "put_image_scanning_configuration",
                              {"repositoryName": repo, "imageScanningConfiguration": {"scanOnPush": yes(v, "scan_on_push")}},
                              f"Scan on push: {v.get('scan_on_push', 'yes')}"))
    pol = lifecycle_policy(v.get("lifecycle", "standard"), int(v.get("keep", 20)), int(v.get("untagged_days", 7)))
    if pol:
        steps.append(aws_step("ecr", "put_lifecycle_policy", {"repositoryName": repo, "lifecyclePolicyText": pol},
                              "Lifecycle rules: " + {"standard": f"keep the last {v.get('keep', 20)}, delete untagged after "
                                                                 f"{v.get('untagged_days', 7)} days",
                                                     "keep_last": f"keep the last {v.get('keep', 20)}",
                                                     "untagged": f"delete untagged after {v.get('untagged_days', 7)} days"}[
                                  v.get("lifecycle", "standard")],
                              undo=None if creating else undo("ecr", "delete_lifecycle_policy", {"repositoryName": repo},
                                                              "Remove the lifecycle rules")))
    if v.get("pull_accounts"):
        principals = [f"arn:aws:iam::{a}:root" for a in v["pull_accounts"]]
        doc = {"Version": "2012-10-17", "Statement": [{
            "Sid": "KintsugiCrossAccountPull", "Effect": "Allow", "Principal": {"AWS": principals},
            "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]}]}
        steps.append(aws_step("ecr", "set_repository_policy", {"repositoryName": repo, "policyText": json.dumps(doc)},
                              f"Let account(s) {', '.join(v['pull_accounts'])} pull images (read only)",
                              undo=None if creating else undo("ecr", "delete_repository_policy", {"repositoryName": repo},
                                                              "Remove the repository policy")))
    return steps


def _build_ecr(env, v) -> ScriptDraft:
    a = v.get("action", "create")
    note = ["COST: ECR storage ~$0.10/GB-month (500 MB/month free for 12 months for private repositories); data "
            "transfer out is extra. Enhanced scanning (Inspector) is billed per image scan."]
    if a == "create":
        repo = v["name"]
        p = {"repositoryName": repo, "imageTagMutability": v.get("mutability", "IMMUTABLE"),
             "imageScanningConfiguration": {"scanOnPush": yes(v, "scan_on_push")}, "tags": tag_list(repo)}
        if v.get("encryption") == "KMS":
            p["encryptionConfiguration"] = {"encryptionType": "KMS", **({"kmsKey": v["kms_key"]} if v.get("kms_key") else {})}
        steps = [aws_step("ecr", "create_repository", merge_extra(p, v), f"Create ECR repository {repo}", save_as="repo",
                          undo=undo("ecr", "delete_repository", {"repositoryName": repo, "force": True},
                                    f"Delete ECR repository {repo} and its images"))]
        steps += _ecr_settings_steps(repo, v, True)
        return ScriptDraft(title=f"ECR repository {repo}", steps=steps,
                           notes=note + [f"Push with the docker_image recipe or: docker push "
                                         f"{env.account_id()}.dkr.ecr.{env.region_name}.amazonaws.com/{repo}:<tag>"])
    if a == "configure":
        return ScriptDraft(title=f"Configure ECR repository {v['repo']}",
                           steps=_ecr_settings_steps(v["repo"], v, False), notes=note)
    if a == "replication":
        current = _registry(env).get("replicationConfiguration", {"rules": []})
        rule = {"destinations": [{"region": r, "registryId": env.account_id()} for r in v["regions"]]}
        if v.get("repo_prefix"):
            rule["repositoryFilters"] = [{"filter": v["repo_prefix"], "filterType": "PREFIX_MATCH"}]
        new = {"rules": (current.get("rules") or []) + [rule]}
        steps = [aws_step("ecr", "put_replication_configuration", {"replicationConfiguration": new},
                          f"Replicate {'repositories starting with ' + v['repo_prefix'] if v.get('repo_prefix') else 'all repositories'}"
                          f" to {', '.join(v['regions'])} (existing rules kept)",
                          undo=undo("ecr", "put_replication_configuration",
                                    {"replicationConfiguration": {"rules": current.get("rules") or []}},
                                    "Restore the previous replication rules"))]
        return ScriptDraft(title="ECR cross-region replication", steps=steps,
                           notes=note + ["Only images pushed AFTER this change are replicated. Each region bills its "
                                         "own storage."])
    if a == "pull_through":
        prefix = v["cache_prefix"]
        steps = [aws_step("ecr", "create_pull_through_cache_rule",
                          {"ecrRepositoryPrefix": prefix, "upstreamRegistryUrl": UPSTREAMS[v["upstream"]]},
                          f"Cache images from {UPSTREAMS[v['upstream']]} under {prefix}/",
                          undo=undo("ecr", "delete_pull_through_cache_rule", {"ecrRepositoryPrefix": prefix},
                                    "Delete the pull-through cache rule"))]
        uri = f"{env.account_id()}.dkr.ecr.{env.region_name}.amazonaws.com/{prefix}/<image path>:<tag>"
        return ScriptDraft(title=f"ECR pull-through cache for {UPSTREAMS[v['upstream']]}", steps=steps,
                           notes=note + [f"Pull through the cache with: docker pull {uri}",
                                         "Docker Hub and GitHub need credentials in Secrets Manager; add those rules "
                                         "yourself in the ECR console."])
    if a == "scanning":
        steps = [aws_step("ecr", "put_registry_scanning_configuration",
                          {"scanType": v["scan_type"], "rules": [{"scanFrequency": "SCAN_ON_PUSH" if v["scan_type"] == "BASIC"
                                                                   else "CONTINUOUS_SCAN",
                                                                   "repositoryFilters": [{"filter": "*", "filterType": "WILDCARD"}]}]},
                          f"Registry scanning: {v['scan_type'].lower()} for every repository")]
        return ScriptDraft(title=f"ECR {v['scan_type'].lower()} scanning", steps=steps,
                           notes=note + (["Enhanced scanning uses Amazon Inspector (paid per image; 15-day free trial "
                                          "for new accounts)."] if v["scan_type"] == "ENHANCED" else []))
    steps = [aws_step("ecr", "delete_repository", {"repositoryName": v["repo"], "force": True},
                      f"Delete repository {v['repo']} and ALL its images")]
    return ScriptDraft(title=f"Delete ECR repository {v['repo']}", steps=steps,
                       notes=["Permanent: deleted images cannot be recovered."])


def _settings_rel(i) -> bool:
    return i.get("action", "create") in ("create", "configure")


ECR = Template(
    name="ecr_repository",
    description="ECR: create/configure repositories (immutable tags, scan on push, KMS, lifecycle rules, cross-account "
                "pull), replication, pull-through cache, registry scanning, delete",
    fields=[
        choice("action", "What do you want to do in ECR?", ECR_ACTIONS, default="create"),
        FieldSpec("name", "Repository name?", "text", default="kintsugi-app", validate=_repo_name,
                  relevant=action_is("create")),
        FieldSpec("repo", "Which repository?", "choice", must_ask=True, options=_ecr_options,
                  validate=pick(_ecr_options, "repository"), relevant=action_is("configure", "delete"),
                  empty_hint="No ECR repositories in this region."),
        choice("mutability", "Image tags?", opts(("IMMUTABLE", "Immutable: a tag can never be overwritten (recommended)"),
                                                 ("MUTABLE", "Mutable: tags like 'latest' can move")),
               default="IMMUTABLE", relevant=_settings_rel),
        yes_no("scan_on_push", "Scan images for vulnerabilities on push?", default="yes", relevant=_settings_rel),
        choice("lifecycle", "Clean up old images automatically?", LIFECYCLE, default="standard", relevant=_settings_rel),
        number("keep", "Keep how many images?", 20, 1, 10000,
               relevant=lambda i: _settings_rel(i) and i.get("lifecycle", "standard") in ("standard", "keep_last")),
        number("untagged_days", "Delete untagged images after how many days?", 7, 1, 3650,
               relevant=lambda i: _settings_rel(i) and i.get("lifecycle", "standard") in ("standard", "untagged")),
        FieldSpec("pull_accounts", "Let other AWS accounts pull? (optional account IDs)", "text", default="",
                  allow_empty=True, validate=lambda e, i, v: account_ids(v) if str(v).strip() else "",
                  relevant=_settings_rel),
        choice("encryption", "Encryption?", opts(("AES256", "AES-256 (default, free)"), ("KMS", "AWS KMS key")),
               default="AES256", relevant=action_is("create")),
        FieldSpec("kms_key", "KMS key ARN or alias? (empty = AWS managed key)", "text", default="", allow_empty=True,
                  relevant=lambda i: i.get("action", "create") == "create" and i.get("encryption") == "KMS"),
        FieldSpec("regions", "Replicate to which regions?", "multichoice", must_ask=True, options=region_options,
                  validate=lambda e, i, v: [r for r in pick_many(region_options, "regions")(e, i, v)
                                            if r != e.region_name] or _choice([], v, "other region"),
                  relevant=action_is("replication")),
        FieldSpec("repo_prefix", "Only repositories starting with? (optional)", "text", default="", allow_empty=True,
                  relevant=action_is("replication")),
        choice("upstream", "Cache which public registry?",
               opts(("ecr-public", "Amazon ECR Public (public.ecr.aws)"), ("k8s", "Kubernetes (registry.k8s.io)"),
                    ("quay", "Quay (quay.io)")), default="ecr-public", relevant=action_is("pull_through")),
        FieldSpec("cache_prefix", "Repository prefix for cached images?", "text",
                  default=lambda e, i: i.get("upstream", "ecr-public"),
                  validate=_name_validator(r"[a-z0-9][a-z0-9._-]{1,29}", "lowercase letters, numbers, . _ - (max 30)"),
                  relevant=action_is("pull_through")),
        choice("scan_type", "Scanning type?", opts(("BASIC", "Basic (free, on push)"),
                                                   ("ENHANCED", "Enhanced (Amazon Inspector, continuous, paid)")),
               default="BASIC", must_ask=True, relevant=action_is("scanning")),
        settings_field(),
        extra_params_field(lambda i: ("ecr", "create_repository"),
                           {"repositoryName", "imageTagMutability", "imageScanningConfiguration", "tags",
                            "encryptionConfiguration"}, relevant=lambda i: custom(i) and i.get("action", "create") == "create"),
    ],
    title=lambda i: f"ECR ({i.get('action', 'create')})",
    build=_build_ecr, notes=lambda i: ["COST: ECR storage ~$0.10/GB-month."],
)


RECIPES = [ECS_SERVICE, EKS, EKS_MANAGE, ECR]
templates.TEMPLATES.update({t.name: t for t in RECIPES})
