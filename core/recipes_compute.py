"""Compute recipes: load balancers (ALB/NLB), target groups, launch templates, Auto Scaling groups, AMIs, EBS.

Same rules as every recipe: the LLM only picks the recipe and passes what the user said; code asks for the
rest with live options, builds typed steps (validated against the AWS API model), adds tags, cost notes and
undo actions (teardown). Nothing runs until the user approves the script.
"""
import base64
import re

from core import lookups, templates
from core.recipe_kit import (account_ids, action_is, both, choice, custom, default_subnets, extra_params_field, ids, merge_extra,
                             number, opts, pick, pick_many, region_options, settings_field, sg_options, static,
                             subnet_options, utc_hhmm, validate_subnets, vpc_options, yes, yes_no)
from core.recipes import (MANAGED_POLICIES, _name_validator, _stamp, aws_step, check, role_steps, tag_dict, tag_list,
                          undo)
from core.scripts import ScriptDraft
from core.templates import (FieldSpec, HOURS_PER_MONTH, OS_CHOICES, Template, TemplateError, _admin_default,
                            _choice, _int, _key_options, _validate_admin_cidr)

LB_HOUR, LCU_HOUR, PUBLIC_IP_HOUR = 0.0225, 0.008, 0.005
INSTANCE_PRICES = {"t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416, "t3.large": 0.0832,
                   "t3a.micro": 0.0094, "t3a.small": 0.0188, "t4g.micro": 0.0084, "t4g.small": 0.0168,
                   "t4g.medium": 0.0336, "m6i.large": 0.096, "m7i.large": 0.1008, "c6i.large": 0.085,
                   "c7i.large": 0.0893, "r6i.large": 0.126}
VOLUME_PRICES = {"gp3": 0.08, "gp2": 0.10, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.015,
                 "standard": 0.05}
SNAPSHOT_GB_MONTH, ARCHIVE_GB_MONTH = 0.05, 0.0125
_TYPE_RE = re.compile(r"[a-z][a-z0-9-]*\.(nano|micro|small|medium|large|xlarge|2xlarge)")


def _price(t: str) -> str:
    p = INSTANCE_PRICES.get(t)
    return f" (~${p}/hour, ~${p * HOURS_PER_MONTH:.0f}/month)" if p else ""


def _type_options(env, inputs):
    return [{"value": t, "label": f"{t}{_price(t)}"} for t in INSTANCE_PRICES]


def _validate_type(env, inputs, v) -> str:
    v = str(v).strip().lower()
    if not _TYPE_RE.fullmatch(v):
        raise ValueError("pick a size from the list, or type one up to 2xlarge (bigger sizes are blocked "
                         "to protect your budget)")
    return v


def _is_arm(instance_type: str) -> bool:
    family = instance_type.split(".")[0]
    return bool(re.fullmatch(r"[a-z]+\d+[a-z]*g[a-z]*", family))


_lb_name = _name_validator(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,26}[A-Za-z0-9])?",
                           "letters, numbers and - (max 28, not starting or ending with -)")
_tg_name = _name_validator(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,30}[A-Za-z0-9])?",
                           "letters, numbers and - (max 32, not starting or ending with -)")


def _vpc_for(env, inputs) -> str | None:
    if inputs.get("vpc"):
        return inputs["vpc"]
    return lookups.vpc_of_subnets(env, ids(inputs.get("subnets")))


def _vpc_cidr(env, vpc: str | None) -> str:
    return next((v["cidr"] for v in lookups.vpcs(env) if v["id"] == vpc), "10.0.0.0/8")


LB_TYPES = opts(("application", "Application Load Balancer (HTTP/HTTPS, path and host routing)"),
                ("network", "Network Load Balancer (TCP/UDP/TLS, very high throughput)"))
SCHEMES = opts(("internet-facing", "Internet-facing (public DNS name)"),
               ("internal", "Internal (reachable only inside the VPC)"))
ALGORITHMS = opts(("round_robin", "Round robin"), ("least_outstanding_requests", "Least outstanding requests"),
                  ("weighted_random", "Weighted random"))


def _target_type_options(env, inputs):
    base = [("instance", "EC2 instances"), ("ip", "IP addresses (containers, other networks)")]
    if inputs.get("lb_type", "application") == "application":
        base.append(("lambda", "A Lambda function"))
    return opts(*base)


def _protocol_options(env, inputs):
    if inputs.get("lb_type", "application") == "network":
        return opts(("TCP", "TCP"), ("TLS", "TLS"), ("UDP", "UDP"), ("TCP_UDP", "TCP and UDP"))
    return opts(("HTTP", "HTTP"), ("HTTPS", "HTTPS (targets have their own certificate)"))


def _instance_target_options(env, inputs):
    vpc = _vpc_for(env, inputs)
    out = [{"value": "none", "label": "No targets now (register later, or an Auto Scaling group adds them)"}]
    out += [{"value": i["id"], "label": f"{i['id']} · {i['name'] or '-'} · {i['state']} · {i['az']}"}
            for i in lookups.all_instances(env) if i["state"] == "running" and (not vpc or i["vpc"] == vpc)]
    return out


def _validate_instance_targets(env, inputs, v):
    chosen = [x for x in ids(v) if x != "none"]
    allowed = {o["value"] for o in _instance_target_options(env, inputs)}
    bad = [x for x in chosen if x not in allowed]
    if bad:
        raise ValueError(f"not a running instance in the load balancer's VPC: {', '.join(bad)}")
    return chosen


def _validate_ips(env, inputs, v) -> str:
    import ipaddress
    out = []
    for x in ids(v):
        try:
            out.append(str(ipaddress.ip_address(x)))
        except ValueError:
            raise ValueError(f"'{x}' is not an IP address") from None
    return ",".join(out)


def _lambda_options(env, inputs):
    return [{"value": f["name"], "label": f"{f['name']} ({f['runtime']})"} for f in lookups.lambda_functions(env)]


def _cert_options(env, inputs):
    return [{"value": c["arn"], "label": f"{c['domain']} · {c['arn'].rsplit('/', 1)[-1][:8]}"}
            for c in lookups.certificates(env)]


def _ingress_default(env, inputs):
    if inputs.get("scheme", "internet-facing") == "internet-facing":
        return "0.0.0.0/0"
    return _vpc_cidr(env, _vpc_for(env, inputs))


def _validate_ingress(env, inputs, v) -> str:
    from core.recipe_kit import cidr
    return cidr(v, "who may connect")


def _validate_matcher(env, inputs, v) -> str:
    v = str(v).strip()
    if not re.fullmatch(r"\d{3}(-\d{3})?(,\d{3}(-\d{3})?)*", v):
        raise ValueError("HTTP codes like 200, 200-399 or 200,302")
    return v


def _validate_health_path(env, inputs, v) -> str:
    v = str(v).strip() or "/"
    if not v.startswith("/") or len(v) > 1024 or " " in v:
        raise ValueError("a path like / or /health")
    return v


def parse_rules(env, text: str, vpc: str | None) -> list[dict]:
    """'/api/*=api-tg; host:shop.example.com=shop-tg' -> [{field, values, tg_arn, tg}] (existing target groups)."""
    rules = []
    tgs = {t["name"]: t for t in lookups.target_groups(env)}
    tgs.update({t["arn"]: t for t in lookups.target_groups(env)})
    for part in re.split(r"[;\n]+", str(text or "")):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"'{part}': use /path/*=target-group or host:name.example.com=target-group")
        cond, tg = (x.strip() for x in part.rsplit("=", 1))
        if tg not in tgs:
            raise ValueError(f"target group '{tg}' does not exist (create it first with the target_group recipe)")
        if vpc and tgs[tg]["vpc"] and tgs[tg]["vpc"] != vpc:
            raise ValueError(f"target group '{tg}' is in another VPC")
        if cond.lower().startswith("host:"):
            field, values = "host-header", [cond[5:].strip()]
        else:
            if not cond.startswith("/"):
                raise ValueError(f"'{cond}' must be a path like /api/* or host:name.example.com")
            field, values = "path-pattern", [cond]
        rules.append({"field": field, "values": values, "tg_arn": tgs[tg]["arn"], "tg": tgs[tg]["name"]})
    if len(rules) > 20:
        raise ValueError("at most 20 rules at once")
    return rules


def _validate_rules(env, inputs, v) -> str:
    parse_rules(env, v, _vpc_for(env, inputs))
    return str(v or "").strip()


def _lb_public(i) -> bool:
    return i.get("scheme", "internet-facing") == "internet-facing"


def _alb(i) -> bool:
    return i.get("lb_type", "application") == "application"


def _http_target(i) -> bool:
    return i.get("target_protocol", "HTTP" if _alb(i) else "TCP") in ("HTTP", "HTTPS")


def health_fields(prefix_relevant=lambda i: True) -> list[FieldSpec]:
    rel = both(custom, prefix_relevant, lambda i: i.get("target_type") != "lambda")
    return [
        number("health_interval", "Health check interval (seconds)?", 15, 5, 300, relevant=rel),
        number("healthy_threshold", "Healthy after how many good checks?", 3, 2, 10, relevant=rel),
        number("unhealthy_threshold", "Unhealthy after how many failed checks?", 3, 2, 10, relevant=rel),
        FieldSpec("health_matcher", "Which HTTP codes count as healthy?", "text", default="200-399",
                  validate=_validate_matcher, relevant=both(rel, _http_target)),
        yes_no("stickiness", "Sticky sessions (same user -> same target)?", relevant=rel),
        number("stickiness_seconds", "Stickiness duration (seconds)?", 86400, 1, 604800,
               relevant=both(rel, lambda i: yes(i, "stickiness"), _alb)),
        number("deregistration_delay", "Deregistration delay (seconds to finish open requests)?", 60, 0, 3600,
               relevant=rel),
        choice("algorithm", "Load balancing algorithm?", ALGORITHMS, default="round_robin", relevant=both(rel, _alb)),
        number("slow_start", "Slow start (seconds, 0 = off; 30-900)?", 0, 0, 900, relevant=both(rel, _alb)),
    ]


def tg_params(name: str, v: dict, vpc: str | None) -> dict:
    p = {"Name": name, "TargetType": v.get("target_type", "instance"), "Tags": tag_list(name)}
    if p["TargetType"] == "lambda":
        p["HealthCheckEnabled"] = False
        return p
    proto = v.get("target_protocol") or ("HTTP" if _alb(v) else "TCP")
    p.update({"Protocol": proto, "Port": int(v.get("port", 80)), "VpcId": vpc,
              "HealthCheckIntervalSeconds": int(v.get("health_interval", 15)),
              "HealthyThresholdCount": int(v.get("healthy_threshold", 3)),
              "UnhealthyThresholdCount": int(v.get("unhealthy_threshold", 3))})
    if proto in ("HTTP", "HTTPS"):
        p.update({"HealthCheckPath": v.get("health_path", "/"), "Matcher": {"HttpCode": v.get("health_matcher", "200-399")},
                  "HealthCheckTimeoutSeconds": 5})
    elif proto in ("UDP", "TCP_UDP"):
        p["HealthCheckProtocol"] = "TCP"
    return p


def tg_attributes(v: dict) -> list[dict]:
    if v.get("target_type") == "lambda" or not custom(v):
        return []
    attrs = {"deregistration_delay.timeout_seconds": str(v.get("deregistration_delay", 60))}
    if yes(v, "stickiness"):
        attrs["stickiness.enabled"] = "true"
        attrs["stickiness.type"] = "lb_cookie" if _alb(v) else "source_ip"
        if _alb(v):
            attrs["stickiness.lb_cookie.duration_seconds"] = str(v.get("stickiness_seconds", 86400))
    if _alb(v):
        attrs["load_balancing.algorithm.type"] = v.get("algorithm", "round_robin")
        if int(v.get("slow_start", 0) or 0):
            attrs["slow_start.duration_seconds"] = str(max(30, int(v["slow_start"])))
    return [{"Key": k, "Value": val} for k, val in attrs.items()]


def target_steps(tg_ref: str, v: dict, name: str) -> list[dict]:
    """Register instances / IPs / a Lambda function with a target group (undo deregisters)."""
    steps = []
    port = int(v.get("port", 80))
    if v.get("target_type") == "lambda" and v.get("target_lambda"):
        fn = v["target_lambda"]
        sid = f"kintsugi-elb-{name}"[:100]
        steps.append(aws_step("lambda", "add_permission",
                              {"FunctionName": fn, "StatementId": sid, "Action": "lambda:InvokeFunction",
                               "Principal": "elasticloadbalancing.amazonaws.com", "SourceArn": tg_ref},
                              f"Allow the load balancer to invoke {fn}",
                              undo=undo("lambda", "remove_permission", {"FunctionName": fn, "StatementId": sid},
                                        "Remove the load balancer's invoke permission")))
        steps.append(aws_step("elbv2", "register_targets",
                              {"TargetGroupArn": tg_ref, "Targets": [{"Id": v["_lambda_arn"]}]},
                              f"Register Lambda {fn} as the target"))
        return steps
    targets = [{"Id": t, "Port": port} for t in v.get("targets_instances", []) or []]
    targets += [{"Id": ip, "Port": port} for ip in ids(v.get("target_ips", ""))]
    if targets:
        steps.append(aws_step("elbv2", "register_targets", {"TargetGroupArn": tg_ref, "Targets": targets},
                              f"Register {len(targets)} target(s) on port {port}",
                              undo=undo("elbv2", "deregister_targets", {"TargetGroupArn": tg_ref, "Targets": targets},
                                        "Deregister the targets")))
    return steps


def lb_steps(env, v: dict, name: str, subnets: list[str], vpc: str) -> tuple[list[dict], dict]:
    """Security group + load balancer + target group + listeners (+ rules). Returns (steps, refs)."""
    alb = _alb(v)
    https = alb and yes(v, "https")
    port = int(v.get("port", 80))
    proto = v.get("target_protocol") or ("HTTP" if alb else "TCP")
    listen_port = 443 if https else (80 if alb else int(v.get("listener_port") or port))
    steps: list[dict] = []
    if v.get("security_group", "new") == "new":
        ports = [80, 443] if https else [listen_port]
        ip_proto = "udp" if proto == "UDP" else "tcp"
        steps.append(aws_step("ec2", "create_security_group",
                              {"GroupName": f"{name}-lb-{_stamp()}", "Description": f"Kintsugi load balancer {name}",
                               "VpcId": vpc, "TagSpecifications": templates._tags("security-group", f"{name}-lb-sg")},
                              f"Create security group for load balancer {name}", save_as="lbsg",
                              undo=undo("ec2", "delete_security_group", {"GroupId": "{{lbsg.GroupId}}"},
                                        "Delete the load balancer security group")))
        src = v.get("ingress_cidr") or "0.0.0.0/0"
        steps.append(aws_step("ec2", "authorize_security_group_ingress",
                              {"GroupId": "{{lbsg.GroupId}}", "IpPermissions": [
                                  {"IpProtocol": ip_proto, "FromPort": p, "ToPort": p,
                                   "IpRanges": [{"CidrIp": src, "Description": "load balancer listener"}]}
                                  for p in ports]},
                              f"Allow inbound {', '.join(map(str, ports))} from {src}"))
        sg_ref = "{{lbsg.GroupId}}"
    else:
        sg_ref = v["security_group"]
    lb = {"Name": name, "Subnets": subnets, "SecurityGroups": [sg_ref], "Scheme": v.get("scheme", "internet-facing"),
          "Type": "application" if alb else "network", "IpAddressType": "ipv4", "Tags": tag_list(name)}
    lb_arn = "{{lb.LoadBalancers.0.LoadBalancerArn}}"
    steps.append(aws_step("elbv2", "create_load_balancer", merge_extra(lb, v, "lb_extra"),
                          f"Create {'Application' if alb else 'Network'} Load Balancer {name} "
                          f"({lb['Scheme']}, {len(subnets)} subnets; waits until active)", save_as="lb",
                          wait={"waiter": "load_balancer_available", "params": {"LoadBalancerArns": [lb_arn]},
                                "delay": 15, "max_attempts": 60},
                          undo=undo("elbv2", "delete_load_balancer", {"LoadBalancerArn": lb_arn},
                                    f"Delete load balancer {name} (waits until gone)",
                                    wait={"waiter": "load_balancers_deleted", "params": {"LoadBalancerArns": [lb_arn]}},
                                    pause_after=30)))
    attrs = []
    if custom(v):
        if alb:
            attrs += [{"Key": "idle_timeout.timeout_seconds", "Value": str(v.get("idle_timeout", 60))},
                      {"Key": "routing.http2.enabled", "Value": "true" if yes(v, "http2") or "http2" not in v else "false"}]
        else:
            attrs.append({"Key": "load_balancing.cross_zone.enabled", "Value": "true" if yes(v, "cross_zone") else "false"})
        if yes(v, "deletion_protection"):
            attrs.append({"Key": "deletion_protection.enabled", "Value": "true"})
    if attrs:
        off = [{"Key": "deletion_protection.enabled", "Value": "false"}]
        steps.append(aws_step("elbv2", "modify_load_balancer_attributes", {"LoadBalancerArn": lb_arn, "Attributes": attrs},
                              "Set load balancer attributes: " + ", ".join(f"{a['Key']}={a['Value']}" for a in attrs),
                              undo=undo("elbv2", "modify_load_balancer_attributes",
                                        {"LoadBalancerArn": lb_arn, "Attributes": off},
                                        "Turn off deletion protection so the load balancer can be deleted")
                              if yes(v, "deletion_protection") else None))
    tg_name = f"{name}-tg"[:32]
    tg_arn = "{{tg.TargetGroups.0.TargetGroupArn}}"
    tgp = tg_params(tg_name, v, vpc)
    steps.append(aws_step("elbv2", "create_target_group", tgp,
                          f"Create target group {tg_name} ({tgp['TargetType']}"
                          f"{', ' + tgp['Protocol'] + ':' + str(tgp['Port']) if 'Protocol' in tgp else ''})",
                          save_as="tg", undo=undo("elbv2", "delete_target_group", {"TargetGroupArn": tg_arn},
                                                  f"Delete target group {tg_name}")))
    if (attrs_tg := tg_attributes(v)):
        steps.append(aws_step("elbv2", "modify_target_group_attributes", {"TargetGroupArn": tg_arn, "Attributes": attrs_tg},
                              "Set target group attributes: " + ", ".join(f"{a['Key']}={a['Value']}" for a in attrs_tg)))
    steps += target_steps(tg_arn, v, name)
    forward = [{"Type": "forward", "TargetGroupArn": tg_arn}]
    main_key = "lsn"
    if https:
        steps.append(aws_step("elbv2", "create_listener",
                              {"LoadBalancerArn": lb_arn, "Protocol": "HTTPS", "Port": 443,
                               "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
                               "Certificates": [{"CertificateArn": v["certificate"]}], "DefaultActions": forward,
                               "Tags": tag_list(f"{name}-https")},
                              "Create HTTPS listener on 443 (TLS 1.2/1.3) forwarding to the target group", save_as="lsn",
                              undo=undo("elbv2", "delete_listener", {"ListenerArn": "{{lsn.Listeners.0.ListenerArn}}"},
                                        "Delete the HTTPS listener")))
        http_action = [{"Type": "redirect", "RedirectConfig": {"Protocol": "HTTPS", "Port": "443",
                                                                "StatusCode": "HTTP_301"}}] \
            if yes(v, "redirect_http") or "redirect_http" not in v else forward
        steps.append(aws_step("elbv2", "create_listener",
                              {"LoadBalancerArn": lb_arn, "Protocol": "HTTP", "Port": 80, "DefaultActions": http_action,
                               "Tags": tag_list(f"{name}-http")},
                              "Create HTTP listener on 80 " + ("(redirects to HTTPS)" if http_action != forward
                                                               else "forwarding to the target group"),
                              save_as="lsn80",
                              undo=undo("elbv2", "delete_listener", {"ListenerArn": "{{lsn80.Listeners.0.ListenerArn}}"},
                                        "Delete the HTTP listener")))
    else:
        lproto = "HTTP" if alb else proto
        steps.append(aws_step("elbv2", "create_listener",
                              {"LoadBalancerArn": lb_arn, "Protocol": lproto, "Port": listen_port,
                               "DefaultActions": forward, "Tags": tag_list(f"{name}-listener")},
                              f"Create {lproto} listener on {listen_port} forwarding to the target group", save_as="lsn",
                              undo=undo("elbv2", "delete_listener", {"ListenerArn": "{{lsn.Listeners.0.ListenerArn}}"},
                                        "Delete the listener")))
    if alb and v.get("path_rules"):
        for n, r in enumerate(parse_rules(env, v["path_rules"], vpc), 1):
            cfg = {"PathPatternConfig": {"Values": r["values"]}} if r["field"] == "path-pattern" else \
                {"HostHeaderConfig": {"Values": r["values"]}}
            key = f"rule{n}"
            steps.append(aws_step("elbv2", "create_rule",
                                  {"ListenerArn": "{{" + main_key + ".Listeners.0.ListenerArn}}", "Priority": n * 10,
                                   "Conditions": [{"Field": r["field"], **cfg}],
                                   "Actions": [{"Type": "forward", "TargetGroupArn": r["tg_arn"]}]},
                                  f"Rule {n}: {r['field']} {r['values'][0]} -> {r['tg']}", save_as=key,
                                  undo=undo("elbv2", "delete_rule", {"RuleArn": "{{" + key + ".Rules.0.RuleArn}}"},
                                            f"Delete rule {n}")))
    refs = {"lb_arn": lb_arn, "tg_arn": tg_arn, "sg": sg_ref, "dns": "{{lb.LoadBalancers.0.DNSName}}",
            "listen_port": listen_port, "https": https}
    return steps, refs


def open_target_sgs(env, v: dict, lb_sg: str) -> list[dict]:
    """Let the load balancer reach the chosen instances: add an inbound rule to their security groups."""
    if v.get("target_type") != "instance" or not yes(v, "open_targets") or not v.get("targets_instances"):
        return []
    port = int(v.get("port", 80))
    proto = "udp" if v.get("target_protocol") == "UDP" else "tcp"
    sgs = sorted({g for iid in v["targets_instances"] for g in (lookups.instance(env, iid) or {}).get("sgs", [])})
    steps = []
    for g in sgs:
        perm = [{"IpProtocol": proto, "FromPort": port, "ToPort": port,
                 "UserIdGroupPairs": [{"GroupId": lb_sg, "Description": "from the Kintsugi load balancer"}]}]
        steps.append(aws_step("ec2", "authorize_security_group_ingress", {"GroupId": g, "IpPermissions": perm},
                              f"Allow port {port} into {g} from the load balancer only",
                              undo=undo("ec2", "revoke_security_group_ingress", {"GroupId": g, "IpPermissions": perm},
                                        f"Remove the load balancer rule from {g}")))
    return steps


def _lb_hourly(v: dict) -> float:
    azs = len(ids(v.get("subnets"))) or 2
    ips = azs * PUBLIC_IP_HOUR if _lb_public(v) and _alb(v) else 0
    return LB_HOUR + LCU_HOUR + ips


def _lb_notes(v: dict) -> list[str]:
    h = _lb_hourly(v)
    kind = "ALB" if _alb(v) else "NLB"
    notes = [f"COST: {kind} ~${LB_HOUR}/hour + ~${LCU_HOUR}/hour per capacity unit"
             + (" + public IPv4 per zone" if _lb_public(v) and _alb(v) else "")
             + f" = ~${h:.3f}/hour (~${h * HOURS_PER_MONTH:.0f}/month) even with no traffic. Approximate us-east-1 "
             "prices; verify current pricing. Run the teardown script when you are done.",
             "Targets must allow traffic from the load balancer's security group on the target port."]
    if v.get("target_type") == "instance" and not v.get("targets_instances"):
        notes.append("No targets registered: the load balancer answers 503 until targets are added "
                     "(an Auto Scaling group can attach to this target group).")
    return notes


def _lb_fields(include_name=True) -> list[FieldSpec]:
    vpc_of = _vpc_for
    fields = []
    if include_name:
        fields.append(FieldSpec("name", "Load balancer name?", "text", default="kintsugi-alb", validate=_lb_name,
                                why="Also used for the target group (<name>-tg)."))
    fields += [
        choice("lb_type", "Which type of load balancer?", LB_TYPES, default="application",
               why="ALB for websites and APIs; NLB for raw TCP/UDP."),
        choice("scheme", "Internet-facing or internal?", SCHEMES, default="internet-facing", must_ask=True),
        FieldSpec("subnets", "Which subnets (one per availability zone)?", "multichoice", must_ask=True,
                  options=lambda e, i: subnet_options(public_only=_lb_public(i))(e, i),
                  default=lambda e, i: default_subnets(public_only=_lb_public(i))(e, i),
                  validate=lambda e, i, v: validate_subnets(2 if _alb(i) else 1, public_only=_lb_public(i))(e, i, v),
                  why="An ALB needs subnets in at least 2 availability zones. Internet-facing needs public subnets.",
                  empty_hint="No suitable subnets. First ask: 'Create a VPC with 2 public subnets', run it, then "
                             "try again."),
        FieldSpec("target_type", "What will receive the traffic?", "choice", must_ask=True, default="instance",
                  options=_target_type_options, validate=pick(_target_type_options, "target type")),
        FieldSpec("targets_instances", "Which instances should get traffic?", "multichoice", default=["none"],
                  options=_instance_target_options, validate=_validate_instance_targets,
                  relevant=lambda i: i.get("target_type", "instance") == "instance",
                  why="You can also leave it empty and attach an Auto Scaling group later."),
        FieldSpec("target_ips", "Which private IP addresses? (comma separated, optional)", "text", default="",
                  allow_empty=True, validate=_validate_ips, relevant=lambda i: i.get("target_type") == "ip"),
        FieldSpec("target_lambda", "Which Lambda function?", "choice", must_ask=True, options=_lambda_options,
                  validate=pick(_lambda_options, "function"), relevant=lambda i: i.get("target_type") == "lambda",
                  empty_hint="No Lambda functions in this region. Create one first (lambda_function recipe)."),
        FieldSpec("target_protocol", "Protocol between the load balancer and the targets?", "choice",
                  default=lambda e, i: "HTTP" if _alb(i) else "TCP", options=_protocol_options,
                  validate=pick(_protocol_options, "protocol"),
                  relevant=lambda i: i.get("target_type") != "lambda" and (custom(i) or not _alb(i))),
        number("port", "Which port do the targets listen on?", 80, 1, 65535,
               relevant=lambda i: i.get("target_type") != "lambda", must_ask=True),
        number("listener_port", "Which port should the load balancer listen on?", lambda e, i: i.get("port", 80), 1, 65535,
               relevant=lambda i: not _alb(i)),
        yes_no("https", "Add HTTPS (port 443) with an ACM certificate?", relevant=_alb,
               why="Needs an issued certificate in ACM for your domain."),
        FieldSpec("certificate", "Which certificate?", "choice", must_ask=True, options=_cert_options,
                  default=lambda e, i: next((o["value"] for o in _cert_options(e, i)), None),
                  validate=pick(_cert_options, "certificate"), relevant=lambda i: _alb(i) and yes(i, "https"),
                  empty_hint="No issued ACM certificate in this region. Request one in ACM (DNS validation) first, "
                             "or answer HTTPS = no."),
        yes_no("redirect_http", "Redirect HTTP (80) to HTTPS?", default="yes",
               relevant=lambda i: _alb(i) and yes(i, "https")),
        FieldSpec("health_path", "Health check path?", "text", default="/", validate=_validate_health_path,
                  relevant=lambda i: i.get("target_type") != "lambda" and _http_target(i)),
        FieldSpec("ingress_cidr", "Who may connect to the load balancer? (IP range)", "text", must_ask=True,
                  default=_ingress_default, validate=_validate_ingress,
                  relevant=lambda i: i.get("security_group", "new") == "new",
                  why="0.0.0.0/0 = everyone (a public website). Internal load balancers default to the VPC range."),
        FieldSpec("security_group", "Security group for the load balancer?", "choice", default="new",
                  options=sg_options(vpc_of, "Create a new one with only the listener ports open (recommended)"),
                  validate=pick(sg_options(vpc_of, "new"), "security group"), relevant=custom),
        yes_no("open_targets", "Allow the load balancer to reach the instances (adds a rule to their security "
                               "groups)?", default="yes",
               relevant=lambda i: i.get("target_type", "instance") == "instance" and bool(
                   [x for x in ids(i.get("targets_instances")) if x != "none"])),
        FieldSpec("path_rules", "Extra routing rules? (optional: /api/*=api-tg; host:shop.example.com=shop-tg)",
                  "text", default="", allow_empty=True, validate=_validate_rules, relevant=both(_alb, custom),
                  why="Routes matching requests to other EXISTING target groups (path or host based)."),
        settings_field(),
        *health_fields(),
        number("idle_timeout", "Idle timeout (seconds)?", 60, 1, 4000, relevant=both(custom, _alb)),
        yes_no("http2", "HTTP/2 enabled?", default="yes", relevant=both(custom, _alb)),
        yes_no("cross_zone", "Cross-zone load balancing?", default="no", relevant=both(custom, lambda i: not _alb(i))),
        yes_no("deletion_protection", "Deletion protection?", relevant=custom,
               why="The teardown script turns it off first."),
        extra_params_field(lambda i: ("elbv2", "create_load_balancer"),
                           {"Name", "Subnets", "SecurityGroups", "Scheme", "Type", "Tags", "SubnetMappings"},
                           key="lb_extra"),
    ]
    return fields


def _lambda_arn(env, v: dict) -> dict:
    if v.get("target_type") == "lambda" and v.get("target_lambda"):
        fn = next((f for f in lookups.lambda_functions(env) if f["name"] == v["target_lambda"]), None)
        if not fn:
            raise TemplateError(f"Lambda function {v['target_lambda']} not found")
        return {**v, "_lambda_arn": fn["arn"]}
    return v


def _build_lb(env, v) -> ScriptDraft:
    v = _lambda_arn(env, v)
    subnets = v["subnets"]
    vpc = lookups.vpc_of_subnets(env, subnets)
    steps, refs = lb_steps(env, v, v["name"], subnets, vpc)
    steps += open_target_sgs(env, v, refs["sg"])
    has_targets = bool(v.get("targets_instances") or v.get("target_ips") or v.get("target_lambda"))
    if has_targets and _lb_public(v) and _alb(v) and not refs["https"]:
        path = v.get("health_path", "/") if v.get("target_type") != "lambda" else "/"
        steps.append(check("http", {"url": f"http://{refs['dns']}{path}"},
                           "Check the load balancer answers HTTP 200 (targets must pass health checks)", timeout=600))
    kind = "Application" if _alb(v) else "Network"
    return ScriptDraft(title=f"{kind} Load Balancer {v['name']}", steps=steps,
                       notes=_lb_notes(v) + [f"URL after the run: http{'s' if refs['https'] else ''}://<DNS name in the "
                                             f"run log>{'' if refs['listen_port'] in (80, 443) else ':' + str(refs['listen_port'])}"])


LOAD_BALANCER = Template(
    name="load_balancer",
    description="Application or Network Load Balancer with target group, listeners (HTTP/HTTPS), targets and rules",
    fields=_lb_fields(),
    title=lambda i: f"Load balancer '{i.get('name', 'kintsugi-alb')}'",
    build=_build_lb, notes=_lb_notes,
)


def _listener_options(env, inputs):
    vpc = inputs.get("vpc")
    return [{"value": "none", "label": "Do not attach to a listener now"}] + [
        {"value": ln["arn"], "label": f"{ln['lb']} · {ln['protocol']}:{ln['port']}"}
        for ln in lookups.listeners(env) if ln["lb_type"] == "application" and (not vpc or ln["vpc"] == vpc)]


def _priority_default(env, inputs):
    ln = next((x for x in lookups.listeners(env) if x["arn"] == inputs.get("listener")), None)
    return ln["next_priority"] if ln else 10


def _validate_condition(env, inputs, v) -> str:
    v = str(v).strip()
    if v.lower().startswith("host:"):
        if not re.fullmatch(r"[A-Za-z0-9*?.-]{1,128}", v[5:].strip()):
            raise ValueError("host like shop.example.com or *.example.com")
        return v
    if not v.startswith("/") or " " in v:
        raise ValueError("a path pattern like /api/* or host:shop.example.com")
    return v


def _build_tg(env, v) -> ScriptDraft:
    net = v.get("target_protocol", "HTTP") in ("TCP", "UDP", "TLS", "TCP_UDP")
    v = _lambda_arn(env, {**v, "lb_type": "network" if net else "application"})
    name = v["name"]
    tgp = tg_params(name, v, v.get("vpc"))
    tg_arn = "{{tg.TargetGroups.0.TargetGroupArn}}"
    steps = [aws_step("elbv2", "create_target_group", tgp, f"Create target group {name} ({tgp['TargetType']})",
                      save_as="tg", undo=undo("elbv2", "delete_target_group", {"TargetGroupArn": tg_arn},
                                              f"Delete target group {name}"))]
    if (attrs := tg_attributes(v)):
        steps.append(aws_step("elbv2", "modify_target_group_attributes", {"TargetGroupArn": tg_arn, "Attributes": attrs},
                              "Set target group attributes"))
    steps += target_steps(tg_arn, v, name)
    if v.get("listener", "none") != "none":
        cond = v["condition"]
        field, cfg = ("host-header", {"HostHeaderConfig": {"Values": [cond[5:].strip()]}}) \
            if cond.lower().startswith("host:") else ("path-pattern", {"PathPatternConfig": {"Values": [cond]}})
        steps.append(aws_step("elbv2", "create_rule",
                              {"ListenerArn": v["listener"], "Priority": int(v["priority"]),
                               "Conditions": [{"Field": field, **cfg}],
                               "Actions": [{"Type": "forward", "TargetGroupArn": tg_arn}], "Tags": tag_list(f"{name}-rule")},
                              f"Route {cond} on the listener to {name} (priority {v['priority']})", save_as="rule",
                              undo=undo("elbv2", "delete_rule", {"RuleArn": "{{rule.Rules.0.RuleArn}}"},
                                        "Delete the listener rule")))
    return ScriptDraft(title=f"Target group {name}", steps=steps,
                       notes=["COST: target groups are free; you pay for the load balancer that uses them."])


TG_TYPES = opts(("instance", "EC2 instances"), ("ip", "IP addresses"), ("lambda", "A Lambda function"))

TARGET_GROUP = Template(
    name="target_group",
    description="Target group (instances, IPs or Lambda) with health checks, targets and an optional listener rule",
    fields=[
        FieldSpec("name", "Target group name?", "text", default="kintsugi-tg", validate=_tg_name),
        choice("target_type", "What will be registered?", TG_TYPES, default="instance", must_ask=True),
        FieldSpec("vpc", "Which VPC?", "choice", must_ask=True, options=vpc_options, validate=pick(vpc_options, "VPC"),
                  default=lambda e, i: next((o["value"] for o in vpc_options(e, i)), None),
                  relevant=lambda i: i.get("target_type") != "lambda", empty_hint="No VPC in this region."),
        FieldSpec("target_protocol", "Protocol?", "choice", default="HTTP",
                  options=static(opts(("HTTP", "HTTP"), ("HTTPS", "HTTPS"), ("TCP", "TCP (for a Network LB)"),
                                      ("UDP", "UDP (for a Network LB)"), ("TLS", "TLS (for a Network LB)"))),
                  validate=pick(static(opts(("HTTP", ""), ("HTTPS", ""), ("TCP", ""), ("UDP", ""), ("TLS", ""))),
                                "protocol"), relevant=lambda i: i.get("target_type") != "lambda"),
        number("port", "Target port?", 80, 1, 65535, relevant=lambda i: i.get("target_type") != "lambda"),
        FieldSpec("health_path", "Health check path?", "text", default="/", validate=_validate_health_path,
                  relevant=lambda i: i.get("target_type") != "lambda" and i.get("target_protocol", "HTTP") in ("HTTP", "HTTPS")),
        FieldSpec("targets_instances", "Which instances?", "multichoice", default=["none"],
                  options=_instance_target_options, validate=_validate_instance_targets,
                  relevant=lambda i: i.get("target_type", "instance") == "instance"),
        FieldSpec("target_ips", "Which IP addresses? (comma separated, optional)", "text", default="",
                  allow_empty=True, validate=_validate_ips, relevant=lambda i: i.get("target_type") == "ip"),
        FieldSpec("target_lambda", "Which Lambda function?", "choice", must_ask=True, options=_lambda_options,
                  validate=pick(_lambda_options, "function"), relevant=lambda i: i.get("target_type") == "lambda"),
        FieldSpec("listener", "Attach to an existing load balancer listener with a rule?", "choice", default="none",
                  options=_listener_options, validate=pick(_listener_options, "listener")),
        FieldSpec("condition", "Which requests go here? (/api/* or host:shop.example.com)", "text", must_ask=True,
                  default="/api/*", validate=_validate_condition, relevant=lambda i: i.get("listener", "none") != "none"),
        FieldSpec("priority", "Rule priority (lower = checked first)?", "number", default=_priority_default,
                  validate=lambda e, i, v: _int(v, 1, 50000, "priority"),
                  relevant=lambda i: i.get("listener", "none") != "none"),
        settings_field(),
        *health_fields(),
    ],
    title=lambda i: f"Target group '{i.get('name', 'kintsugi-tg')}'",
    build=_build_tg, notes=lambda i: ["COST: target groups are free; you pay for the load balancer that uses them."],
)


NGINX_HELLO = """#!/bin/bash
set -eux
if command -v dnf >/dev/null; then dnf install -y nginx; WEB=/usr/share/nginx/html;
elif command -v yum >/dev/null; then yum install -y nginx; WEB=/usr/share/nginx/html;
else apt-get update -y && apt-get install -y nginx; WEB=/var/www/html; fi
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
echo "<h1>Hello from Kintsugi</h1><p>Instance $ID in $AZ</p>" > $WEB/index.html
systemctl enable --now nginx
"""
USER_DATA = opts(("none", "Nothing"), ("nginx_hello", "Install nginx with a page showing the instance ID (good for "
                                                      "load balancer / Auto Scaling demos)"),
                 ("file", "My own script file"))
LT_SGS = [("new_web", "New: web (80/443 open, SSH/RDP only from your IP)"),
          ("new_admin", "New: admin only (SSH/RDP from your IP)"),
          ("new_private", "New: no inbound access")]
PUBLIC_IP = opts(("subnet", "Subnet default"), ("yes", "Yes, give each instance a public IP"), ("no", "No public IP"))
VOLUME_TYPES = opts(("gp3", "gp3 general purpose SSD (recommended)"), ("gp2", "gp2 general purpose SSD (older)"),
                    ("io2", "io2 provisioned IOPS SSD"), ("io1", "io1 provisioned IOPS SSD"),
                    ("st1", "st1 throughput HDD (min 125 GB)"), ("sc1", "sc1 cold HDD (min 125 GB)"),
                    ("standard", "magnetic (previous generation)"))


def _image_options(env, inputs):
    out = [{"value": k, "label": f"{o['label']} (latest official image)"} for k, o in OS_CHOICES.items()]
    out += [{"value": a["id"], "label": f"{a['id']} · {a['name']} · your AMI from {a['created']}"}
            for a in lookups.own_amis(env) if a["state"] == "available"]
    return out


def _validate_image(env, inputs, v) -> str:
    v = str(v).strip()
    if v in OS_CHOICES:
        return v
    low = v.lower()
    for k, o in OS_CHOICES.items():
        if low == o["label"].lower():
            return k
    if not re.fullmatch(r"ami-[0-9a-f]{8,17}", v):
        raise ValueError("pick an OS from the list or type an AMI ID (ami-...)")
    if not lookups.image(env, v):
        raise ValueError(f"{v} does not exist in this region (or you cannot use it)")
    return v


def resolve_image(env, key: str) -> dict:
    """{id, root, arch, windows} for an OS key or an AMI ID."""
    if key in OS_CHOICES:
        a = env.ami(key)
        return {"id": a["id"], "root": a["root_device"], "arch": OS_CHOICES[key].get("arch", "x86_64"),
                "windows": key.startswith("windows")}
    info = lookups.image(env, key)
    if not info:
        raise TemplateError(f"AMI {key} not found")
    return {"id": key, "root": info["root"], "arch": info["arch"], "windows": "windows" in info["platform"].lower()}


def _validate_user_data_file(env, inputs, v) -> str:
    from pathlib import Path
    from core.recipe_kit import SECRET_VALUE_RE
    p = Path(str(v).strip().strip('"'))
    if not p.is_file():
        raise ValueError(f"file not found: {p}")
    if p.stat().st_size > 12000:
        raise ValueError("user data must be under 12 KB (put bigger installers in S3 and download them)")
    text = p.read_text(encoding="utf-8", errors="replace")
    if SECRET_VALUE_RE.search(text) or re.search(r"(?i)(password|secret|token)\s*=\s*['\"]?[^\s'\"]{6,}", text):
        raise ValueError("the script seems to contain a secret; user data is readable from the instance and "
                         "the console. Use Secrets Manager / SSM Parameter Store instead")
    return str(p)


def _profile_options(env, inputs):
    return [{"value": "none", "label": "No IAM role"},
            {"value": "ssm", "label": "New role with SSM access (Session Manager, no SSH needed)"}] + \
           [{"value": p["name"], "label": f"{p['name']} ({', '.join(p['roles']) or 'no role'})"}
            for p in lookups.instance_profiles(env)]


def _lt_options(env, inputs):
    return [{"value": t["id"], "label": f"{t['name']} · {t['id']} · latest v{t['latest']}"}
            for t in lookups.launch_templates(env)]


def _lt_vpc(env, inputs) -> str | None:
    return inputs.get("vpc") or lookups.vpc_of_subnets(env, ids(inputs.get("subnets")))


def lt_fields(standalone: bool) -> list[FieldSpec]:
    """Launch template questions. In an Auto Scaling group they apply only when launch_template == 'new'."""
    active = (lambda i: True) if standalone else (lambda i: i.get("launch_template", "new") == "new")
    creating = (lambda i: i.get("action", "create") == "create") if standalone else active
    sg_opts = lambda e, i: [{"value": k, "label": label} for k, label in LT_SGS] + \
        sg_options(_lt_vpc)(e, i)
    fields = []
    if standalone:
        fields += [
            choice("action", "Create a new launch template or a new version of an existing one?",
                   opts(("create", "New launch template"), ("new_version", "New version of an existing template")),
                   default="create"),
            FieldSpec("template", "Which launch template?", "choice", must_ask=True, options=_lt_options,
                      validate=pick(_lt_options, "launch template"), relevant=lambda i: i.get("action") == "new_version",
                      empty_hint="No launch templates in this region."),
            FieldSpec("name", "Launch template name?", "text", default="kintsugi-lt",
                      validate=_name_validator(r"[A-Za-z0-9()./_-]{3,128}", "3-128 letters, numbers and ()./-_"),
                      relevant=creating),
            FieldSpec("vpc", "Which VPC will the instances run in?", "choice", options=vpc_options,
                      validate=pick(vpc_options, "VPC"), default=lambda e, i: next((o["value"] for o in vpc_options(e, i)), None),
                      why="Security groups belong to a VPC.", empty_hint="No VPC in this region."),
        ]
    fields += [
        FieldSpec("image", "Which operating system / AMI?", "choice", must_ask=True, options=_image_options,
                  validate=_validate_image, allow_custom=True, relevant=active,
                  why="Official images are the latest from AWS; your own AMIs are listed too. You can type an AMI ID."),
        FieldSpec("instance_type", "Instance size?", "choice", default="t3.micro", options=_type_options,
                  validate=_validate_type, allow_custom=True, relevant=active,
                  why="t4g sizes are ARM (Graviton) and need an arm64 image."),
        FieldSpec("key_name", "Key pair for SSH (or Windows password)?", "choice",
                  default=lambda e, i: (e.key_pairs() or ["none"])[0], options=_key_options,
                  validate=lambda e, i, v: _choice(_key_options(e, i), v, "key pair"), relevant=active),
        FieldSpec("lt_security_group", "Security group for the instances?", "choice", must_ask=True, default="new_web",
                  options=sg_opts, validate=pick(sg_opts, "security group"), relevant=active,
                  why="Behind a new load balancer, a new web group only accepts traffic from that load balancer."),
        FieldSpec("admin_cidr", "Which IP may connect with SSH/RDP?", "text", must_ask=True, default=_admin_default,
                  validate=_validate_admin_cidr,
                  relevant=both(active, lambda i: i.get("lt_security_group", "new_web") in ("new_web", "new_admin")),
                  why="Pre-filled with your current public IP. 0.0.0.0/0 on SSH is blocked."),
        FieldSpec("user_data", "Run a setup script at first boot?", "choice",
                  default=lambda e, i: "nginx_hello" if i.get("lt_security_group", "new_web") == "new_web" else "none",
                  options=static(USER_DATA), validate=pick(static(USER_DATA), "user data"), relevant=active),
        FieldSpec("user_data_file", "Which script file?", "file", must_ask=True, validate=_validate_user_data_file,
                  relevant=both(active, lambda i: i.get("user_data") == "file")),
        number("volume_gb", "Root disk size (GB)?", lambda e, i: 30 if str(i.get("image", "")).startswith("windows") else 8,
               8, 500, relevant=both(active, custom)),
        choice("volume_type", "Root disk type?", VOLUME_TYPES[:4], default="gp3", relevant=both(active, custom)),
        FieldSpec("instance_profile", "IAM role for the instances?", "choice", default="none",
                  options=_profile_options, validate=pick(_profile_options, "instance profile"),
                  relevant=both(active, custom),
                  why="Lets the instances call AWS (e.g. SSM) without storing keys on them."),
    ]
    if standalone:
        fields.append(settings_field())
    fields += [
        choice("public_ip", "Public IP addresses?", PUBLIC_IP, default="subnet", relevant=both(active, custom)),
        yes_no("imdsv2", "Require IMDSv2 (recommended)?", default="yes", relevant=both(active, custom)),
        yes_no("detailed_monitoring", "Detailed (1-minute) CloudWatch monitoring? (~$2/instance/month)",
               relevant=both(active, custom)),
        yes_no("spot", "Use Spot instances (up to 90% cheaper, can be interrupted)?",
               relevant=both(active, custom, lambda i: standalone)),
        yes_no("encrypted", "Encrypt the disk?", default="yes", relevant=both(active, custom)),
    ]
    if standalone:
        fields.append(yes_no("set_default", "Make the new version the default?", default="yes",
                             relevant=lambda i: i.get("action") == "new_version"))
        fields.append(extra_params_field(lambda i: ("ec2", "create_launch_template"),
                                         {"LaunchTemplateName", "LaunchTemplateData", "TagSpecifications"}))
    return fields


def _user_data(v: dict, img: dict) -> str | None:
    if v.get("user_data") == "nginx_hello":
        if img["windows"]:
            raise TemplateError("The nginx demo script is for Linux; pick 'Nothing' or your own script for Windows")
        text = NGINX_HELLO
    elif v.get("user_data") == "file":
        from pathlib import Path
        text = Path(v["user_data_file"]).read_text(encoding="utf-8", errors="replace")
    else:
        return None
    return base64.b64encode(text.encode()).decode()


def lt_steps(env, v: dict, name: str, vpc: str | None, lb_sg: str | None = None,
             app_port: int = 80) -> tuple[list[dict], dict]:
    """Security group (+ IAM role) + launch template data. Returns (steps, data)."""
    img = resolve_image(env, v["image"])
    itype = v.get("instance_type", "t3.micro")
    if _is_arm(itype) != (img["arch"] == "arm64"):
        raise TemplateError(f"{itype} is {'ARM' if _is_arm(itype) else 'x86'} but the image is {img['arch']}; "
                            "pick a matching size or image")
    steps: list[dict] = []
    sg = v.get("lt_security_group", "new_web")
    sg_ref = sg
    if sg.startswith("new_"):
        purpose = sg[4:]
        steps.append(aws_step("ec2", "create_security_group",
                              {"GroupName": f"{name}-{purpose}-{_stamp()}", "Description": f"Kintsugi {purpose} {name}",
                               "VpcId": vpc, "TagSpecifications": templates._tags("security-group", f"{name}-sg")},
                              f"Create security group for {name} ({purpose})", save_as="ltsg",
                              undo=undo("ec2", "delete_security_group", {"GroupId": "{{ltsg.GroupId}}"},
                                        "Delete the instances' security group")))
        perms = []
        admin_port = 3389 if img["windows"] else 22
        if purpose in ("web", "admin") and v.get("admin_cidr"):
            perms.append({"IpProtocol": "tcp", "FromPort": admin_port, "ToPort": admin_port,
                          "IpRanges": [{"CidrIp": v["admin_cidr"], "Description": "admin from your IP"}]})
        if purpose == "web" and lb_sg:
            perms.append({"IpProtocol": "tcp", "FromPort": app_port, "ToPort": app_port,
                          "UserIdGroupPairs": [{"GroupId": lb_sg, "Description": "from the load balancer"}]})
        elif purpose == "web":
            perms += [{"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": "0.0.0.0/0",
                                                                                      "Description": "web"}]}
                      for p in (80, 443)]
        if perms:
            steps.append(aws_step("ec2", "authorize_security_group_ingress", {"GroupId": "{{ltsg.GroupId}}",
                                                                              "IpPermissions": perms},
                                  "Allow inbound: " + ", ".join(
                                      f"{p['FromPort']} from " + (p['IpRanges'][0]['CidrIp'] if p.get('IpRanges')
                                                                  else "the load balancer") for p in perms)))
        sg_ref = "{{ltsg.GroupId}}"
    profile = v.get("instance_profile", "none")
    if profile == "ssm":
        role = f"{name}-ssm"[:64]
        steps += role_steps(role, "ec2.amazonaws.com", [MANAGED_POLICIES["AmazonSSMManagedInstanceCore"]],
                            key="ltrole", instance_profile=True)
        profile = role
    data = {"ImageId": img["id"], "InstanceType": itype,
            "BlockDeviceMappings": [{"DeviceName": img["root"], "Ebs": {
                "VolumeSize": int(v.get("volume_gb", 8)), "VolumeType": v.get("volume_type", "gp3"),
                "DeleteOnTermination": True, "Encrypted": v.get("encrypted", "yes") != "no"}}],
            "MetadataOptions": {"HttpTokens": "required" if v.get("imdsv2", "yes") != "no" else "optional",
                                "HttpEndpoint": "enabled"},
            "TagSpecifications": [{"ResourceType": "instance", "Tags": tag_list(name, extra={"Env": "demo"})},
                                  {"ResourceType": "volume", "Tags": tag_list(f"{name}-disk", extra={"Env": "demo"})}]}
    if v.get("public_ip", "subnet") in ("yes", "no"):
        data["NetworkInterfaces"] = [{"DeviceIndex": 0, "AssociatePublicIpAddress": v["public_ip"] == "yes",
                                      "Groups": [sg_ref], "DeleteOnTermination": True}]
    else:
        data["SecurityGroupIds"] = [sg_ref]
    if v.get("key_name") and v["key_name"] != "none":
        data["KeyName"] = v["key_name"]
    if profile != "none":
        data["IamInstanceProfile"] = {"Name": profile}
    if yes(v, "detailed_monitoring"):
        data["Monitoring"] = {"Enabled": True}
    if yes(v, "spot"):
        data["InstanceMarketOptions"] = {"MarketType": "spot"}
    if (ud := _user_data(v, img)):
        data["UserData"] = ud
    return steps, data


def _lt_notes(v: dict) -> list[str]:
    t = v.get("instance_type", "t3.micro")
    return ["COST: a launch template is free. Instances launched from it cost"
            f"{_price(t) or ' the on-demand price of ' + t} each + disk ~${VOLUME_PRICES.get(v.get('volume_type', 'gp3'), 0.08)}"
            "/GB-month. Approximate us-east-1 prices; verify current pricing."]


def _build_lt(env, v) -> ScriptDraft:
    if v.get("action") == "new_version":
        lt = next(t for t in lookups.launch_templates(env) if t["id"] == v["template"])
        steps, data = lt_steps(env, v, lt["name"], v.get("vpc"))
        steps.append(aws_step("ec2", "create_launch_template_version",
                              {"LaunchTemplateId": lt["id"], "SourceVersion": "$Latest",
                               "VersionDescription": "Created by Kintsugi", "LaunchTemplateData": data},
                              f"Create a new version of {lt['name']} (based on v{lt['latest']})", save_as="ltv"))
        if yes(v, "set_default") or "set_default" not in v:
            steps.append(aws_step("ec2", "modify_launch_template",
                                  {"LaunchTemplateId": lt["id"], "DefaultVersion": str(int(lt["latest"] or 0) + 1)},
                                  f"Make v{int(lt['latest'] or 0) + 1} the default version",
                                  undo=undo("ec2", "modify_launch_template",
                                            {"LaunchTemplateId": lt["id"], "DefaultVersion": str(lt["default"])},
                                            f"Make v{lt['default']} the default again")))
        return ScriptDraft(title=f"New version of launch template {lt['name']}", steps=steps, notes=_lt_notes(v))
    name = v["name"]
    steps, data = lt_steps(env, v, name, v.get("vpc"))
    params = merge_extra({"LaunchTemplateName": name, "VersionDescription": "Created by Kintsugi",
                          "LaunchTemplateData": data,
                          "TagSpecifications": [{"ResourceType": "launch-template", "Tags": tag_list(name)}]}, v)
    steps.append(aws_step("ec2", "create_launch_template", params, f"Create launch template {name}", save_as="lt",
                          undo=undo("ec2", "delete_launch_template",
                                    {"LaunchTemplateId": "{{lt.LaunchTemplate.LaunchTemplateId}}"},
                                    f"Delete launch template {name}")))
    return ScriptDraft(title=f"Launch template {name}", steps=steps, notes=_lt_notes(v))


LAUNCH_TEMPLATE = Template(
    name="launch_template",
    description="EC2 launch template (or a new version): AMI/OS, size, key, security group, user data, disk, IAM role",
    fields=lt_fields(standalone=True),
    title=lambda i: f"Launch template '{i.get('name', 'kintsugi-lt')}'",
    build=_build_lt, notes=_lt_notes,
)


SCALING = opts(("cpu", "Target tracking: keep average CPU at a target (recommended)"),
               ("requests", "Target tracking: requests per instance (existing target group only)"),
               ("network_in", "Target tracking: network in per instance"),
               ("network_out", "Target tracking: network out per instance"),
               ("step_cpu", "Step scaling: add/remove 1 instance when CPU crosses thresholds (CloudWatch alarms)"),
               ("predictive", "Predictive scaling: forecast load from history (machine learning) and scale ahead"),
               ("none", "No automatic scaling (fixed size, or scheduled actions only)"))
LB_MODES = opts(("new_alb", "Create a new Application Load Balancer in front (~$16+/month)"),
                ("existing", "Attach to existing target group(s)"), ("none", "No load balancer"))
CAPACITY = opts(("on_demand", "On-Demand"), ("spot", "Spot only (cheapest, can be interrupted)"),
                ("mixed", "Mixed: some On-Demand + Spot, several instance types"))
TERMINATION = opts(("Default", "Default"), ("OldestInstance", "Oldest instance first"),
                   ("NewestInstance", "Newest instance first"), ("OldestLaunchTemplate", "Oldest launch template first"),
                   ("ClosestToNextInstanceHour", "Closest to the next billing hour"))
ASG_ACTIONS = opts(("create", "Create a new Auto Scaling group"),
                   ("update", "Change size / launch template version of an existing group"),
                   ("refresh", "Instance refresh: replace instances with the latest launch template"),
                   ("delete", "Delete a group (terminates its instances)"))
_SCHED_RE = re.compile(r"(daily|weekdays|weekends|mon|tue|wed|thu|fri|sat|sun)\s+(\d{1,2}(?::\d{2})?\s*(?:am|pm)?)"
                       r"((?:\s+(?:min|max|desired)\s*=\s*\d+)+)", re.I)
_DOW = {"daily": "*", "weekdays": "1-5", "weekends": "0,6", "mon": "1", "tue": "2", "wed": "3", "thu": "4",
        "fri": "5", "sat": "6", "sun": "0"}


def parse_scheduled(text: str) -> list[dict]:
    """'daily 09:00 min=2 desired=2 max=4; weekdays 20:00 desired=0' -> scheduled actions (Recurrence cron in
    the app timezone; Auto Scaling evaluates it in that timezone, so no UTC math is needed)."""
    from core.schedules import parse_hhmm
    out = []
    for part in re.split(r"[;\n]+", str(text or "")):
        part = part.strip()
        if not part:
            continue
        m = _SCHED_RE.fullmatch(part)
        if not m:
            raise ValueError(f"'{part}': use e.g. 'daily 09:00 min=2 desired=2 max=4' or 'weekdays 20:00 desired=0'")
        t = parse_hhmm(m.group(2))
        sizes = {k.lower(): int(val) for k, val in re.findall(r"(min|max|desired)\s*=\s*(\d+)", m.group(3), re.I)}
        if any(n > 50 for n in sizes.values()):
            raise ValueError("scheduled sizes are limited to 50 instances")
        out.append({"recurrence": f"{t.minute} {t.hour} * * {_DOW[m.group(1).lower()]}", "sizes": sizes,
                    "label": part})
    return out


def _validate_scheduled(env, inputs, v) -> str:
    parse_scheduled(v)
    return str(v or "").strip()


def _asg_options(env, inputs):
    return [{"value": g["name"], "label": f"{g['name']} · {g['min']}/{g['desired']}/{g['max']} · {g['instances']} instance(s)"}
            for g in lookups.auto_scaling_groups(env)]


def _group(env, name: str) -> dict:
    return next((g for g in lookups.auto_scaling_groups(env) if g["name"] == name), {})


def _asg_lt_options(env, inputs):
    return [{"value": "new", "label": "Create a new launch template now (recommended)"}] + _lt_options(env, inputs)


def _asg_tg_options(env, inputs):
    vpc = lookups.vpc_of_subnets(env, ids(inputs.get("subnets")))
    return [{"value": t["arn"], "label": f"{t['name']} · {t['protocol']}:{t['port']} · "
                                         f"{'attached to a load balancer' if t['lbs'] else 'no load balancer yet'}"}
            for t in lookups.target_groups(env) if t["type"] == "instance" and (not vpc or t["vpc"] == vpc)]


def _target_default(env, inputs):
    return {"cpu": 50, "requests": 1000, "network_in": 5000000, "network_out": 5000000, "predictive": 50}.get(
        inputs.get("scaling", "cpu"), 50)


def _validate_sizes(key):
    def check(env, inputs, v):
        n = _int(v, 0, 50, key.replace("_", " "))
        lo, hi = int(inputs.get("min_size", 0) or 0), int(inputs.get("max_size", 50) or 50)
        if key == "max_size" and n < 1:
            raise ValueError("max size must be at least 1")
        if key == "desired" and not lo <= n <= hi:
            raise ValueError(f"desired must be between min ({lo}) and max ({hi})")
        if key == "max_size" and n < lo:
            raise ValueError(f"max must be at least min ({lo})")
        return n
    return check


def _creating(i) -> bool:
    return i.get("action", "create") == "create"


def _asg_fields() -> list[FieldSpec]:
    lt = [f for f in lt_fields(standalone=False)]
    for f in lt:
        rel = f.relevant
        f.relevant = (lambda r: (lambda i: _creating(i) and (r(i) if r else True)))(rel)
    return [
        choice("action", "What do you want to do?", ASG_ACTIONS, default="create"),
        FieldSpec("group", "Which Auto Scaling group?", "choice", must_ask=True, options=_asg_options,
                  validate=pick(_asg_options, "Auto Scaling group"), relevant=lambda i: not _creating(i),
                  empty_hint="No Auto Scaling groups in this region."),
        FieldSpec("name", "Auto Scaling group name?", "text", default="kintsugi-asg",
                  validate=_name_validator(r"[A-Za-z0-9][\w.-]{0,63}", "letters, numbers, . _ - (max 64)"),
                  relevant=_creating),
        FieldSpec("subnets", "Which subnets should instances launch in? (2+ zones recommended)", "multichoice",
                  must_ask=True, options=subnet_options(), default=default_subnets(public_only=True),
                  validate=validate_subnets(1), relevant=_creating,
                  why="Instances in private subnets need a NAT gateway to install packages."),
        FieldSpec("launch_template", "Launch template?", "choice", default="new", options=_asg_lt_options,
                  validate=pick(_asg_lt_options, "launch template"), relevant=_creating),
        choice("lt_version", "Which version of the launch template?",
               opts(("$Latest", "Latest"), ("$Default", "Default")), default="$Latest",
               relevant=lambda i: _creating(i) and i.get("launch_template", "new") != "new"),
        *lt,
        FieldSpec("min_size", "Minimum instances?", "number", default=1, validate=_validate_sizes("min_size"),
                  relevant=_creating),
        FieldSpec("max_size", "Maximum instances?", "number", default=3, validate=_validate_sizes("max_size"),
                  relevant=_creating),
        FieldSpec("desired", "Desired instances now?", "number", default=2, validate=_validate_sizes("desired"),
                  relevant=_creating),
        FieldSpec("load_balancing", "Load balancer?", "choice", must_ask=True, default="new_alb",
                  options=static(LB_MODES), validate=pick(static(LB_MODES), "load balancer option"), relevant=_creating),
        FieldSpec("target_groups", "Which target group(s)?", "multichoice", must_ask=True, options=_asg_tg_options,
                  validate=pick_many(_asg_tg_options, "target groups"),
                  relevant=lambda i: _creating(i) and i.get("load_balancing") == "existing",
                  empty_hint="No instance target groups in that VPC. Create one (target_group or load_balancer recipe)."),
        number("app_port", "Which port does the app listen on (on the instances)?", 80, 1, 65535,
               relevant=lambda i: _creating(i) and i.get("load_balancing") == "new_alb"),
        FieldSpec("health_path", "Health check path?", "text", default="/", validate=_validate_health_path,
                  relevant=lambda i: _creating(i) and custom(i) and i.get("load_balancing") == "new_alb"),
        FieldSpec("scaling", "How should it scale?", "choice", must_ask=True, default="cpu", options=static(SCALING),
                  validate=lambda e, i, v: _validate_scaling(i, v), relevant=_creating),
        FieldSpec("target_value", "Target value? (CPU %, requests per instance, or bytes)", "number",
                  default=_target_default, validate=lambda e, i, v: _int(v, 1, 100000000, "target value"),
                  relevant=lambda i: _creating(i) and i.get("scaling", "cpu") in ("cpu", "requests", "network_in",
                                                                                  "network_out", "predictive")),
        number("scale_out_at", "Add an instance when CPU is above (%)?", 70, 1, 100,
               relevant=lambda i: _creating(i) and i.get("scaling") == "step_cpu"),
        number("scale_in_at", "Remove an instance when CPU is below (%)?", 30, 0, 99,
               relevant=lambda i: _creating(i) and i.get("scaling") == "step_cpu"),
        choice("predictive_mode", "Predictive scaling mode?",
               opts(("ForecastAndScale", "Forecast and scale"), ("ForecastOnly", "Forecast only (see the forecast first)")),
               default="ForecastOnly", relevant=lambda i: _creating(i) and i.get("scaling") == "predictive"),
        FieldSpec("scheduled", "Scheduled size changes? (optional, in your timezone: 'daily 09:00 min=2 desired=2 "
                               "max=4; weekdays 20:00 min=0 desired=0')", "text", default="", allow_empty=True,
                  validate=_validate_scheduled, relevant=both(_creating, custom)),
        choice("capacity", "On-Demand or Spot?", CAPACITY, default="on_demand", relevant=both(_creating, custom)),
        FieldSpec("extra_types", "Other instance types it may use (more Spot capacity)?", "multichoice",
                  default=["t3.small", "t3a.micro"], options=_type_options,
                  validate=pick_many(_type_options, "instance types", 1, 10),
                  relevant=lambda i: _creating(i) and i.get("capacity") in ("spot", "mixed")),
        number("on_demand_base", "How many On-Demand instances always (base)?", 1, 0, 50,
               relevant=lambda i: _creating(i) and i.get("capacity") == "mixed"),
        number("on_demand_percent", "On-Demand % above the base?", 50, 0, 100,
               relevant=lambda i: _creating(i) and i.get("capacity") == "mixed"),
        settings_field(),
        choice("health_check_type", "Replace instances that fail which health check?",
               opts(("ELB", "Load balancer health check (recommended with a load balancer)"), ("EC2", "EC2 status only")),
               default=lambda e, i: "EC2" if i.get("load_balancing") == "none" else "ELB",
               relevant=both(_creating, custom)),
        number("grace", "Health check grace period (seconds)?", 300, 0, 7200, relevant=both(_creating, custom)),
        number("warmup", "Instance warm-up (seconds)?", 300, 0, 3600, relevant=both(_creating, custom)),
        choice("termination", "Which instances are removed first when scaling in?", TERMINATION, default="Default",
               relevant=both(_creating, custom)),
        number("max_lifetime_days", "Replace instances after how many days? (0 = never, 1-365)", 0, 0, 365,
               relevant=both(_creating, custom)),
        yes_no("scale_in_protection", "Protect new instances from scale-in?", relevant=both(_creating, custom)),
        yes_no("warm_pool", "Keep a warm pool of stopped instances (faster scale-out)?", relevant=both(_creating, custom)),
        FieldSpec("notify_topic", "Send launch/terminate notifications to an SNS topic?", "choice", default="none",
                  options=lambda e, i: [{"value": "none", "label": "No"}] + [{"value": t, "label": t.rsplit(":", 1)[-1]}
                                                                              for t in lookups.sns_topics(e)],
                  validate=lambda e, i, v: v if v == "none" or v in lookups.sns_topics(e) else _choice([], v, "topic"),
                  relevant=both(_creating, custom)),
        FieldSpec("new_min", "New minimum?", "number", default=lambda e, i: _group(e, i.get("group", "")).get("min", 1),
                  validate=lambda e, i, v: _int(v, 0, 50, "minimum"), relevant=action_is("update")),
        FieldSpec("new_max", "New maximum?", "number", default=lambda e, i: _group(e, i.get("group", "")).get("max", 3),
                  validate=lambda e, i, v: _int(v, 1, 50, "maximum"), relevant=action_is("update")),
        FieldSpec("new_desired", "New desired?", "number",
                  default=lambda e, i: _group(e, i.get("group", "")).get("desired", 1),
                  validate=lambda e, i, v: _new_desired(i, v), relevant=action_is("update")),
        choice("new_version", "Launch template version for new instances?",
               opts(("keep", "Keep the current setting"), ("$Latest", "Latest"), ("$Default", "Default")),
               default="keep", relevant=action_is("update")),
        number("min_healthy", "Keep at least what % healthy during the refresh?", 90, 0, 100,
               relevant=action_is("refresh", "update")),
        yes_no("start_refresh", "Start an instance refresh afterwards (replace running instances)?",
               relevant=action_is("update")),
        extra_params_field(lambda i: ("autoscaling", "create_auto_scaling_group"),
                           {"AutoScalingGroupName", "LaunchTemplate", "MixedInstancesPolicy", "MinSize", "MaxSize",
                            "DesiredCapacity", "VPCZoneIdentifier", "TargetGroupARNs", "Tags"},
                           relevant=both(_creating, custom)),
    ]


def _validate_scaling(i, v):
    v = _choice(SCALING, v, "scaling option")
    if v == "requests" and i.get("load_balancing") != "existing":
        raise ValueError("requests-per-instance scaling needs an existing target group that is attached to a load "
                         "balancer; pick CPU scaling for a new load balancer")
    return v


def _new_desired(i, v):
    n = _int(v, 0, 50, "desired")
    lo, hi = int(i.get("new_min", 0) or 0), int(i.get("new_max", 50) or 50)
    if not lo <= n <= hi:
        raise ValueError(f"desired must be between min ({lo}) and max ({hi})")
    return n


def _asg_hourly(v: dict) -> float:
    t = v.get("instance_type", "t3.micro")
    per = INSTANCE_PRICES.get(t, 0.0104)
    if v.get("capacity") == "spot":
        per *= 0.35
    lb = LB_HOUR + LCU_HOUR + 2 * PUBLIC_IP_HOUR if v.get("load_balancing", "new_alb") == "new_alb" else 0
    return int(v.get("desired", 2) or 2) * (per + PUBLIC_IP_HOUR) + lb


def _asg_notes(v: dict) -> list[str]:
    if not _creating(v):
        return ["Changing the size starts or terminates instances; instance refresh replaces them gradually."]
    h = _asg_hourly(v)
    notes = [f"COST: about ${h:.3f}/hour (~${h * HOURS_PER_MONTH:.0f}/month) for {v.get('desired', 2)} instance(s)"
             + (" + the load balancer" if v.get("load_balancing", "new_alb") == "new_alb" else "")
             + "; scaling out to the maximum costs more. Approximate us-east-1 prices; verify current pricing. "
               "Auto Scaling itself is free. Run the teardown script when you are done.",
             "The teardown deletes the group (and its instances) first, then the launch template and load balancer."]
    if v.get("scaling") == "predictive":
        notes.append("Predictive scaling needs at least 24 hours of history before it forecasts (up to 14 days used).")
    if v.get("scheduled"):
        from core.config import settings
        notes.append(f"Scheduled actions use the timezone {settings.app_timezone}.")
    return notes


def _scaling_steps(name: str, v: dict, label: str | None) -> list[dict]:
    mode = v.get("scaling", "cpu")
    steps = []
    metric = {"cpu": "ASGAverageCPUUtilization", "network_in": "ASGAverageNetworkIn",
              "network_out": "ASGAverageNetworkOut", "requests": "ALBRequestCountPerTarget"}.get(mode)
    if metric:
        spec = {"PredefinedMetricType": metric}
        if mode == "requests":
            spec["ResourceLabel"] = label
        steps.append(aws_step("autoscaling", "put_scaling_policy",
                              {"AutoScalingGroupName": name, "PolicyName": f"{name}-target-{mode}",
                               "PolicyType": "TargetTrackingScaling",
                               "TargetTrackingConfiguration": {"PredefinedMetricSpecification": spec,
                                                               "TargetValue": float(v.get("target_value", 50))}},
                              f"Target tracking: keep {mode.replace('_', ' ')} at {v.get('target_value', 50)}"))
    elif mode == "predictive":
        steps.append(aws_step("autoscaling", "put_scaling_policy",
                              {"AutoScalingGroupName": name, "PolicyName": f"{name}-predictive",
                               "PolicyType": "PredictiveScaling",
                               "PredictiveScalingConfiguration": {
                                   "MetricSpecifications": [{"TargetValue": float(v.get("target_value", 50)),
                                                             "PredefinedMetricPairSpecification": {
                                                                 "PredefinedMetricType": "ASGCPUUtilization"}}],
                                   "Mode": v.get("predictive_mode", "ForecastOnly"), "SchedulingBufferTime": 300}},
                              f"Predictive scaling on CPU (target {v.get('target_value', 50)}%, "
                              f"{v.get('predictive_mode', 'ForecastOnly')})"))
    elif mode == "step_cpu":
        for direction, adj, bound, threshold, op in (
                ("out", 1, {"MetricIntervalLowerBound": 0.0}, v.get("scale_out_at", 70), "GreaterThanOrEqualToThreshold"),
                ("in", -1, {"MetricIntervalUpperBound": 0.0}, v.get("scale_in_at", 30), "LessThanOrEqualToThreshold")):
            key = f"pol_{direction}"
            alarm = f"{name}-cpu-{'high' if direction == 'out' else 'low'}"
            steps.append(aws_step("autoscaling", "put_scaling_policy",
                                  {"AutoScalingGroupName": name, "PolicyName": f"{name}-step-{direction}",
                                   "PolicyType": "StepScaling", "AdjustmentType": "ChangeInCapacity",
                                   "MetricAggregationType": "Average",
                                   "StepAdjustments": [{**bound, "ScalingAdjustment": adj}]},
                                  f"Step policy: {'add' if adj > 0 else 'remove'} 1 instance", save_as=key))
            steps.append(aws_step("cloudwatch", "put_metric_alarm",
                                  {"AlarmName": alarm, "Namespace": "AWS/EC2", "MetricName": "CPUUtilization",
                                   "Statistic": "Average", "Period": 60, "EvaluationPeriods": 3,
                                   "Threshold": float(threshold), "ComparisonOperator": op,
                                   "Dimensions": [{"Name": "AutoScalingGroupName", "Value": name}],
                                   "AlarmActions": ["{{" + key + ".PolicyARN}}"], "Tags": tag_list(alarm)},
                                  f"Alarm {alarm}: CPU {'>=' if adj > 0 else '<='} {threshold}% for 3 minutes",
                                  undo=undo("cloudwatch", "delete_alarms", {"AlarmNames": [alarm]},
                                            f"Delete alarm {alarm}")))
    for n, s in enumerate(parse_scheduled(v.get("scheduled", "")), 1):
        from core.config import settings
        sizes = {"min": "MinSize", "max": "MaxSize", "desired": "DesiredCapacity"}
        steps.append(aws_step("autoscaling", "put_scheduled_update_group_action",
                              {"AutoScalingGroupName": name, "ScheduledActionName": f"{name}-sched-{n}",
                               "Recurrence": s["recurrence"], "TimeZone": settings.app_timezone,
                               **{sizes[k]: val for k, val in s["sizes"].items()}},
                              f"Scheduled action: {s['label']} ({settings.app_timezone})"))
    return steps


def _build_asg_create(env, v) -> ScriptDraft:
    name, subnets = v["name"], v["subnets"]
    vpc = lookups.vpc_of_subnets(env, subnets)
    steps: list[dict] = []
    tg_arns, label, lb_sg, refs = [], None, None, None
    if v.get("load_balancing") == "new_alb":
        lb_v = {"lb_type": "application", "scheme": "internet-facing", "target_type": "instance",
                "port": v.get("app_port", 80), "health_path": v.get("health_path", "/"), "ingress_cidr": "0.0.0.0/0",
                "target_protocol": "HTTP"}
        public = [s for s in subnets if next((x for x in env.subnets() if x["id"] == s), {}).get("public")]
        if len({next(x["az"] for x in env.subnets() if x["id"] == s) for s in public}) < 2:
            raise TemplateError("A new load balancer needs public subnets in 2 availability zones; pick them in "
                                "'subnets', or choose 'No load balancer'")
        lb_steps_, refs = lb_steps(env, lb_v, f"{name}-alb"[:28], public, vpc)
        steps += lb_steps_
        tg_arns, lb_sg = [refs["tg_arn"]], refs["sg"]
    elif v.get("load_balancing") == "existing":
        tg_arns = v["target_groups"]
        tg = next(t for t in lookups.target_groups(env) if t["arn"] == tg_arns[0])
        if v.get("scaling") == "requests":
            if not tg["lbs"]:
                raise TemplateError("requests-per-instance scaling needs a target group attached to a load balancer")
            label = tg["lbs"][0].split(":loadbalancer/", 1)[1] + "/" + tg["arn"].split(":", 5)[5]
    if v.get("launch_template", "new") == "new":
        lt_s, data = lt_steps(env, v, name, vpc, lb_sg=lb_sg, app_port=int(v.get("app_port", 80)))
        steps += lt_s
        steps.append(aws_step("ec2", "create_launch_template",
                              {"LaunchTemplateName": f"{name}-lt", "VersionDescription": "Created by Kintsugi",
                               "LaunchTemplateData": data,
                               "TagSpecifications": [{"ResourceType": "launch-template", "Tags": tag_list(f"{name}-lt")}]},
                              f"Create launch template {name}-lt", save_as="lt",
                              undo=undo("ec2", "delete_launch_template",
                                        {"LaunchTemplateId": "{{lt.LaunchTemplate.LaunchTemplateId}}"},
                                        f"Delete launch template {name}-lt")))
        lt_spec = {"LaunchTemplateId": "{{lt.LaunchTemplate.LaunchTemplateId}}", "Version": "$Latest"}
    else:
        lt_spec = {"LaunchTemplateId": v["launch_template"], "Version": v.get("lt_version", "$Latest")}
    params = {"AutoScalingGroupName": name, "MinSize": v["min_size"], "MaxSize": v["max_size"],
              "DesiredCapacity": v["desired"], "VPCZoneIdentifier": ",".join(subnets),
              "HealthCheckType": v.get("health_check_type") or ("EC2" if not tg_arns else "ELB"),
              "HealthCheckGracePeriod": int(v.get("grace", 300)), "DefaultInstanceWarmup": int(v.get("warmup", 300)),
              "Tags": [{"Key": t["Key"], "Value": t["Value"], "PropagateAtLaunch": True}
                       for t in tag_list(name, extra={"Env": "demo"})]}
    cap = v.get("capacity", "on_demand")
    if cap == "on_demand":
        params["LaunchTemplate"] = lt_spec
    else:
        types = list(dict.fromkeys([v.get("instance_type", "t3.micro")] + v.get("extra_types", [])))
        dist = {"SpotAllocationStrategy": "price-capacity-optimized",
                "OnDemandBaseCapacity": int(v.get("on_demand_base", 0)) if cap == "mixed" else 0,
                "OnDemandPercentageAboveBaseCapacity": int(v.get("on_demand_percent", 0)) if cap == "mixed" else 0}
        params["MixedInstancesPolicy"] = {"LaunchTemplate": {"LaunchTemplateSpecification": lt_spec,
                                                             "Overrides": [{"InstanceType": t} for t in types]},
                                          "InstancesDistribution": dist}
        params["CapacityRebalance"] = True
    if tg_arns:
        params["TargetGroupARNs"] = tg_arns
    if v.get("termination", "Default") != "Default":
        params["TerminationPolicies"] = [v["termination"]]
    if int(v.get("max_lifetime_days", 0) or 0):
        params["MaxInstanceLifetime"] = int(v["max_lifetime_days"]) * 86400
    if yes(v, "scale_in_protection"):
        params["NewInstancesProtectedFromScaleIn"] = True
    merge_extra(params, v)
    steps.append(aws_step("autoscaling", "create_auto_scaling_group", params,
                          f"Create Auto Scaling group {name} ({v['min_size']}-{v['max_size']}, desired {v['desired']}, "
                          f"{cap.replace('_', '-')}; waits until instances are in service)",
                          wait={"waiter": "group_in_service", "params": {"AutoScalingGroupNames": [name]},
                                "delay": 15, "max_attempts": 60},
                          undo=undo("autoscaling", "delete_auto_scaling_group",
                                    {"AutoScalingGroupName": name, "ForceDelete": True},
                                    f"Delete Auto Scaling group {name} and terminate its instances (waits)",
                                    wait={"waiter": "group_not_exists", "params": {"AutoScalingGroupNames": [name]},
                                          "delay": 15, "max_attempts": 80}, pause_after=30)))
    steps.append(aws_step("autoscaling", "enable_metrics_collection",
                          {"AutoScalingGroupName": name, "Granularity": "1Minute"},
                          "Turn on group metrics (free) for the dashboard"))
    steps += _scaling_steps(name, v, label)
    if yes(v, "warm_pool"):
        steps.append(aws_step("autoscaling", "put_warm_pool",
                              {"AutoScalingGroupName": name, "PoolState": "Stopped", "MinSize": 0},
                              "Keep a warm pool of stopped, pre-initialised instances"))
    if v.get("notify_topic", "none") != "none":
        steps.append(aws_step("autoscaling", "put_notification_configuration",
                              {"AutoScalingGroupName": name, "TopicARN": v["notify_topic"],
                               "NotificationTypes": ["autoscaling:EC2_INSTANCE_LAUNCH", "autoscaling:EC2_INSTANCE_TERMINATE",
                                                     "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
                                                     "autoscaling:EC2_INSTANCE_TERMINATE_ERROR"]},
                              "Send launch/terminate notifications to the SNS topic"))
    if refs and v.get("user_data", "nginx_hello") == "nginx_hello" and int(v["desired"]) > 0:
        steps.append(check("http", {"url": f"http://{refs['dns']}{v.get('health_path', '/')}"},
                           "Check the website answers through the load balancer", timeout=900))
    return ScriptDraft(title=f"Auto Scaling group {name}" + (" with a new load balancer" if refs else ""),
                       steps=steps, notes=_asg_notes(v))


def _build_asg(env, v) -> ScriptDraft:
    if _creating(v):
        return _build_asg_create(env, v)
    g = _group(env, v["group"])
    name = v["group"]
    if v["action"] == "delete":
        return ScriptDraft(title=f"Delete Auto Scaling group {name}", steps=[
            aws_step("autoscaling", "delete_auto_scaling_group", {"AutoScalingGroupName": name, "ForceDelete": True},
                     f"Delete {name} and terminate its {g.get('instances', 0)} instance(s) (waits)",
                     wait={"waiter": "group_not_exists", "params": {"AutoScalingGroupNames": [name]}, "delay": 15,
                           "max_attempts": 80})],
            notes=["This terminates every instance in the group. The launch template and load balancer stay."])
    steps = []
    if v["action"] == "update":
        params = {"AutoScalingGroupName": name, "MinSize": v["new_min"], "MaxSize": v["new_max"],
                  "DesiredCapacity": v["new_desired"]}
        if v.get("new_version", "keep") != "keep" and g.get("lt_id"):
            params["LaunchTemplate"] = {"LaunchTemplateId": g["lt_id"], "Version": v["new_version"]}
        steps.append(aws_step("autoscaling", "update_auto_scaling_group", params,
                              f"Set {name} to min {v['new_min']} / desired {v['new_desired']} / max {v['new_max']}",
                              undo=undo("autoscaling", "update_auto_scaling_group",
                                        {"AutoScalingGroupName": name, "MinSize": g.get("min", 0),
                                         "MaxSize": g.get("max", 1), "DesiredCapacity": g.get("desired", 0)},
                                        f"Put {name} back to {g.get('min')}/{g.get('desired')}/{g.get('max')}")))
    if v["action"] == "refresh" or yes(v, "start_refresh"):
        steps.append(aws_step("autoscaling", "start_instance_refresh",
                              {"AutoScalingGroupName": name, "Strategy": "Rolling",
                               "Preferences": {"MinHealthyPercentage": int(v.get("min_healthy", 90)),
                                               "SkipMatching": True}},
                              f"Instance refresh: replace instances gradually, keeping {v.get('min_healthy', 90)}% healthy"))
    return ScriptDraft(title=f"Update Auto Scaling group {name}", steps=steps, notes=_asg_notes(v))


AUTO_SCALING = Template(
    name="auto_scaling_group",
    description="Auto Scaling group (+ launch template, + optional new ALB): target tracking, step, predictive and "
                "scheduled scaling, Spot/mixed; or update / refresh / delete a group",
    fields=_asg_fields(),
    title=lambda i: f"Auto Scaling group '{i.get('name') or i.get('group') or 'kintsugi-asg'}'",
    build=_build_asg, notes=_asg_notes,
)


AMI_ACTIONS = opts(("create", "Create an AMI (image) from an instance"),
                   ("copy", "Copy an AMI to another region"),
                   ("share", "Share an AMI with other AWS accounts"),
                   ("unshare", "Stop sharing an AMI with accounts"),
                   ("deprecate", "Deprecate an AMI on a date (hidden from new launches)"),
                   ("deregister", "Deregister an AMI and delete its snapshots"))


def _instance_options(env, inputs):
    return [{"value": i["id"], "label": f"{i['id']} · {i['name'] or '-'} · {i['state']} · {i['type']}"}
            for i in lookups.all_instances(env)]


def _own_ami_options(env, inputs):
    return [{"value": a["id"], "label": f"{a['id']} · {a['name']} · {a['created']}"} for a in lookups.own_amis(env)]


def _validate_ami_name(env, inputs, v) -> str:
    v = str(v).strip()
    if not re.fullmatch(r"[A-Za-z0-9()\[\]./\-'@_ ]{3,128}", v):
        raise ValueError("3-128 characters: letters, numbers and ( ) [ ] . / - ' @ _ space")
    if v in {a["name"] for a in lookups.own_amis(env)}:
        raise ValueError(f"you already have an AMI named '{v}'")
    return v


def _validate_date(env, inputs, v) -> str:
    from datetime import datetime, timezone
    try:
        d = datetime.strptime(str(v).strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError("a date like 2026-12-31") from None
    if d <= datetime.now(timezone.utc):
        raise ValueError("the date must be in the future")
    return d.strftime("%Y-%m-%d")


def _ami_notes(v: dict) -> list[str]:
    a = v.get("action", "create")
    if a in ("create", "copy"):
        return [f"COST: an AMI is stored as EBS snapshots, ~${SNAPSHOT_GB_MONTH}/GB-month (only used blocks). "
                "Deregister it and delete its snapshots when you no longer need it (the teardown does both).",
                "Creating an image without reboot is faster but the file system may not be consistent."]
    if a == "share":
        return ["Shared accounts can launch instances from the AMI. Making AMIs public is blocked by the app."]
    return ["Deregistering is permanent; instances already running from the AMI keep running."]


def _build_ami(env, v) -> ScriptDraft:
    a = v.get("action", "create")
    if a == "create":
        inst = lookups.instance(env, v["instance"]) or {}
        name = v["ami_name"]
        img = "{{ami.ImageId}}"
        steps = [aws_step("ec2", "create_image",
                          {"InstanceId": v["instance"], "Name": name, "Description": "Created by Kintsugi",
                           "NoReboot": v.get("reboot", "yes") == "no",
                           "TagSpecifications": [{"ResourceType": "image", "Tags": tag_list(name)},
                                                 {"ResourceType": "snapshot", "Tags": tag_list(f"{name}-snap")}]},
                          f"Create AMI '{name}' from {v['instance']} ({inst.get('name') or '-'})"
                          + ("" if v.get("reboot", "yes") == "no" else ", rebooting it for a consistent image")
                          + " (waits until available)", save_as="ami",
                          wait={"waiter": "image_available", "params": {"ImageIds": [img]}, "delay": 20,
                                "max_attempts": 120},
                          undo={"kind": "ami_delete", "image_id": img,
                                "description": f"Deregister AMI {name} and delete its snapshots"})]
        return ScriptDraft(title=f"Create AMI {name}", steps=steps, notes=_ami_notes(v))
    ami = next((x for x in lookups.own_amis(env) if x["id"] == v["ami"]), {"id": v["ami"], "name": v["ami"]})
    if a == "copy":
        dest = v["dest_region"]
        params = {"SourceImageId": ami["id"], "SourceRegion": env.region_name, "Name": f"{ami['name']}-copy"[:128],
                  "Description": f"Copy of {ami['id']} by Kintsugi", "Encrypted": yes(v, "encrypt"),
                  "TagSpecifications": [{"ResourceType": "image", "Tags": tag_list(f"{ami['name']}-copy"[:128])}]}
        if yes(v, "encrypt") and v.get("kms_key"):
            params["KmsKeyId"] = v["kms_key"]
        steps = [aws_step("ec2", "copy_image", params, f"Copy {ami['id']} to {dest}" + (" (encrypted)" if yes(v, "encrypt") else ""),
                          save_as="copy", region=dest,
                          wait={"waiter": "image_available", "params": {"ImageIds": ["{{copy.ImageId}}"]},
                                "delay": 30, "max_attempts": 120},
                          undo={"kind": "ami_delete", "image_id": "{{copy.ImageId}}", "region": dest,
                                "description": f"Deregister the copy in {dest} and delete its snapshots"})]
        return ScriptDraft(title=f"Copy AMI {ami['id']} to {dest}", steps=steps, notes=_ami_notes(v))
    if a in ("share", "unshare"):
        accounts = [{"UserId": x} for x in v["accounts"]]
        key = "Add" if a == "share" else "Remove"
        other = "Remove" if a == "share" else "Add"
        steps = [aws_step("ec2", "modify_image_attribute",
                          {"ImageId": ami["id"], "LaunchPermission": {key: accounts}},
                          f"{'Share' if a == 'share' else 'Stop sharing'} {ami['id']} with {', '.join(v['accounts'])}",
                          undo=undo("ec2", "modify_image_attribute",
                                    {"ImageId": ami["id"], "LaunchPermission": {other: accounts}},
                                    "Undo the sharing change"))]
        if a == "share":
            for sid in ami.get("snapshots", []):
                steps.append(aws_step("ec2", "modify_snapshot_attribute",
                                      {"SnapshotId": sid, "Attribute": "createVolumePermission",
                                       "OperationType": "add", "UserIds": v["accounts"]},
                                      f"Let them create volumes from snapshot {sid} (needed to launch)",
                                      undo=undo("ec2", "modify_snapshot_attribute",
                                                {"SnapshotId": sid, "Attribute": "createVolumePermission",
                                                 "OperationType": "remove", "UserIds": v["accounts"]},
                                                f"Remove volume permission on {sid}")))
        return ScriptDraft(title=f"{'Share' if a == 'share' else 'Unshare'} AMI {ami['id']}", steps=steps,
                           notes=_ami_notes(v))
    if a == "deprecate":
        steps = [aws_step("ec2", "enable_image_deprecation", {"ImageId": ami["id"], "DeprecateAt": v["date"] + "T00:00:00Z"},
                          f"Deprecate {ami['id']} on {v['date']}",
                          undo=undo("ec2", "disable_image_deprecation", {"ImageId": ami["id"]}, "Cancel the deprecation"))]
        return ScriptDraft(title=f"Deprecate AMI {ami['id']}", steps=steps, notes=_ami_notes(v))
    steps = [{"kind": "ami_delete", "image_id": ami["id"],
              "description": f"Deregister {ami['id']} ({ami['name']}) and delete its {len(ami.get('snapshots', []))} snapshot(s)"}]
    return ScriptDraft(title=f"Deregister AMI {ami['id']}", steps=steps, notes=_ami_notes(v))


AMI = Template(
    name="ami",
    description="AMIs: create from an instance, copy to a region, share/unshare with accounts, deprecate, deregister",
    fields=[
        choice("action", "What do you want to do with AMIs?", AMI_ACTIONS, default="create", must_ask=True),
        FieldSpec("instance", "From which instance?", "choice", must_ask=True, options=_instance_options,
                  validate=pick(_instance_options, "instance"), relevant=action_is("create"),
                  empty_hint="No instances in this region."),
        FieldSpec("ami_name", "Name for the new AMI?", "text",
                  default=lambda e, i: f"{(lookups.instance(e, i.get('instance', '')) or {}).get('name') or 'kintsugi'}-{_stamp()[:8]}",
                  validate=_validate_ami_name, relevant=action_is("create")),
        choice("reboot", "Reboot the instance for a consistent image?",
               opts(("yes", "Yes, reboot (consistent; short downtime)"), ("no", "No reboot (no downtime)")),
               default="yes", must_ask=True, relevant=action_is("create")),
        FieldSpec("ami", "Which AMI?", "choice", must_ask=True, options=_own_ami_options,
                  validate=pick(_own_ami_options, "AMI"), relevant=lambda i: i.get("action", "create") != "create",
                  empty_hint="You have no AMIs in this region."),
        FieldSpec("dest_region", "Copy to which region?", "choice", must_ask=True, options=region_options,
                  validate=lambda e, i, v: _dest_region(e, v), relevant=action_is("copy")),
        yes_no("encrypt", "Encrypt the copy?", default="yes", relevant=action_is("copy")),
        FieldSpec("kms_key", "KMS key for the copy? (empty = AWS managed key)", "text", default="", allow_empty=True,
                  relevant=lambda i: i.get("action") == "copy" and yes(i, "encrypt")),
        FieldSpec("accounts", "Which AWS account IDs?", "text", must_ask=True,
                  validate=lambda e, i, v: account_ids(v),
                  relevant=action_is("share", "unshare")),
        FieldSpec("date", "Deprecate on which date (YYYY-MM-DD)?", "text", must_ask=True, validate=_validate_date,
                  relevant=action_is("deprecate")),
    ],
    title=lambda i: f"AMI ({i.get('action', 'create')})",
    build=_build_ami, notes=_ami_notes,
)


def _dest_region(env, v) -> str:
    v = str(v).strip()
    if v not in lookups.regions(env):
        raise ValueError(f"'{v}' is not an enabled region")
    if v == env.region_name:
        raise ValueError("pick a different region than the current one")
    return v


EBS_ACTIONS = opts(("create", "Create a volume (optionally attach it)"), ("attach", "Attach a volume to an instance"),
                   ("detach", "Detach a volume"), ("snapshot", "Snapshot a volume (backup)"),
                   ("modify", "Resize / change type, IOPS or throughput"),
                   ("restore", "Create a volume from a snapshot"), ("copy_snapshot", "Copy a snapshot to another region"),
                   ("archive", "Move a snapshot to the archive tier (75% cheaper storage)"),
                   ("restore_archive", "Restore an archived snapshot"),
                   ("schedule", "Automatic daily snapshots (Data Lifecycle Manager)"),
                   ("default_encryption", "Encrypt all new volumes by default (this region)"),
                   ("delete_volume", "Delete a volume"), ("delete_snapshot", "Delete a snapshot"))
DEVICES = ["/dev/sdf", "/dev/sdg", "/dev/sdh", "/dev/sdi", "/dev/sdj", "/dev/sdk"]


def _vol_options(state: str | None = None):
    def options(env, inputs):
        return [{"value": x["id"], "label": f"{x['id']} · {x['name'] or '-'} · {x['size']} GB {x['type']} · {x['az']} · "
                                            f"{x['state']}{' on ' + x['instance'] if x['instance'] else ''}"}
                for x in lookups.volumes(env) if not state or x["state"] == state]
    return options


def _snap_options(tier: str | None = None):
    def options(env, inputs):
        return [{"value": s["id"], "label": f"{s['id']} · {s['size']} GB · {s['started']} · {s['tier']} · "
                                            f"{s['name'] or s['desc']}"}
                for s in lookups.snapshots(env) if s["state"] == "completed" and (not tier or s["tier"] == tier)]
    return options


def _attach_instance_options(env, inputs):
    az = inputs.get("az") or (lookups.volume(env, inputs.get("volume", "")) or {}).get("az")
    out = [{"value": "none", "label": "Do not attach"}] if inputs.get("action") in ("create", "restore") else []
    return out + [{"value": i["id"], "label": f"{i['id']} · {i['name'] or '-'} · {i['state']} · {i['az']}"}
                  for i in lookups.all_instances(env) if not az or i["az"] == az]


def _az_default(env, inputs):
    iid = inputs.get("attach_to")
    if iid and iid != "none" and (inst := lookups.instance(env, iid)):
        return inst["az"]
    return (env.availability_zones() or [None])[0]


def _validate_iops(env, inputs, v) -> int:
    t = inputs.get("volume_type", "gp3")
    if t == "gp3":
        return _int(v, 3000, 16000, "gp3 IOPS")
    if t in ("io1", "io2"):
        return _int(v, 100, 64000, "IOPS")
    return 0


def _validate_size(env, inputs, v) -> int:
    t = inputs.get("volume_type", "gp3")
    lo = 125 if t in ("st1", "sc1") else (4 if t in ("io1", "io2") else 1)
    if inputs.get("action") == "restore" and (s := lookups.snapshot(env, inputs.get("snapshot", ""))):
        lo = max(lo, s["size"])
    if inputs.get("action") == "modify" and (vol := lookups.volume(env, inputs.get("volume", ""))):
        lo = max(lo, vol["size"])
    return _int(v, lo, 16384, "size (GB)")


def _ebs_notes(v: dict) -> list[str]:
    a = v.get("action", "create")
    t = v.get("volume_type", "gp3")
    gb = int(v.get("size_gb", 8) or 8)
    if a in ("create", "restore"):
        notes = [f"COST: {gb} GB {t} ~${gb * VOLUME_PRICES.get(t, 0.08):.2f}/month"
                 + (" + provisioned IOPS" if t in ("io1", "io2") else "") + ", billed while it exists (even detached). "
                 "Approximate us-east-1 prices; verify current pricing.",
                 "After attaching, format and mount it inside the OS (Linux: sudo mkfs -t xfs /dev/nvme1n1; "
                 "sudo mount /dev/nvme1n1 /data). Kintsugi does not run commands inside the instance."]
        return notes
    if a == "modify":
        return ["After growing a volume, extend the partition and file system inside the OS (Linux: sudo growpart "
                "/dev/nvme0n1 1; sudo xfs_growfs -d /). A volume can be modified once every 6 hours; it cannot shrink."]
    if a in ("snapshot", "copy_snapshot", "schedule"):
        return [f"COST: snapshots ~${SNAPSHOT_GB_MONTH}/GB-month of changed data. The archive tier is "
                f"~${ARCHIVE_GB_MONTH}/GB-month (min 90 days, restore takes up to 72 hours)."]
    if a == "archive":
        return ["Archived snapshots cost 75% less to store but must be restored (up to 72 hours) before use; "
                "minimum 90 days in the archive."]
    return []


def _build_ebs(env, v) -> ScriptDraft:
    a = v.get("action", "create")
    steps: list[dict] = []
    if a in ("create", "restore"):
        name = v.get("name", "kintsugi-volume")
        t = v.get("volume_type", "gp3")
        p = {"AvailabilityZone": v["az"], "Size": int(v["size_gb"]), "VolumeType": t,
             "Encrypted": v.get("encrypted", "yes") != "no", "TagSpecifications": templates._tags("volume", name)}
        if a == "restore":
            p["SnapshotId"] = v["snapshot"]
        if t in ("gp3", "io1", "io2") and int(v.get("iops", 0) or 0):
            p["Iops"] = int(v["iops"])
        if t == "gp3" and int(v.get("throughput", 0) or 0):
            p["Throughput"] = int(v["throughput"])
        if v.get("kms_key") and p["Encrypted"]:
            p["KmsKeyId"] = v["kms_key"]
        if t in ("io1", "io2") and yes(v, "multi_attach"):
            p["MultiAttachEnabled"] = True
        merge_extra(p, v)
        vol = "{{vol.VolumeId}}"
        steps.append(aws_step("ec2", "create_volume", p,
                              f"Create {v['size_gb']} GB {t} volume {name} in {v['az']}"
                              + (f" from {v['snapshot']}" if a == "restore" else "") + " (waits until available)",
                              save_as="vol", wait={"waiter": "volume_available", "params": {"VolumeIds": [vol]}},
                              undo=undo("ec2", "delete_volume", {"VolumeId": vol}, f"Delete volume {name}",
                                        wait={"waiter": "volume_deleted", "params": {"VolumeIds": [vol]}})))
        if v.get("attach_to", "none") != "none":
            steps.append(aws_step("ec2", "attach_volume", {"VolumeId": vol, "InstanceId": v["attach_to"],
                                                           "Device": v.get("device", "/dev/sdf")},
                                  f"Attach it to {v['attach_to']} as {v.get('device', '/dev/sdf')}",
                                  wait={"waiter": "volume_in_use", "params": {"VolumeIds": [vol]}},
                                  undo=undo("ec2", "detach_volume", {"VolumeId": vol}, "Detach the volume",
                                            wait={"waiter": "volume_available", "params": {"VolumeIds": [vol]}})))
        return ScriptDraft(title=f"EBS volume {name}", steps=steps, notes=_ebs_notes(v))
    if a == "attach":
        steps.append(aws_step("ec2", "attach_volume", {"VolumeId": v["volume"], "InstanceId": v["attach_to"],
                                                       "Device": v.get("device", "/dev/sdf")},
                              f"Attach {v['volume']} to {v['attach_to']} as {v.get('device', '/dev/sdf')}",
                              wait={"waiter": "volume_in_use", "params": {"VolumeIds": [v["volume"]]}},
                              undo=undo("ec2", "detach_volume", {"VolumeId": v["volume"]}, "Detach the volume",
                                        wait={"waiter": "volume_available", "params": {"VolumeIds": [v["volume"]]}})))
        return ScriptDraft(title=f"Attach {v['volume']}", steps=steps, notes=_ebs_notes(v))
    if a == "detach":
        steps.append(aws_step("ec2", "detach_volume", {"VolumeId": v["volume"], "Force": yes(v, "force")},
                              f"Detach {v['volume']}" + (" (forced: may lose unwritten data)" if yes(v, "force") else ""),
                              wait={"waiter": "volume_available", "params": {"VolumeIds": [v["volume"]]}}))
        return ScriptDraft(title=f"Detach {v['volume']}", steps=steps,
                           notes=["Unmount it inside the OS first to avoid data loss."])
    if a == "snapshot":
        snap = "{{snap.SnapshotId}}"
        steps.append(aws_step("ec2", "create_snapshot",
                              {"VolumeId": v["volume"], "Description": v.get("description") or "Created by Kintsugi",
                               "TagSpecifications": templates._tags("snapshot", f"{v['volume']}-snap")},
                              f"Snapshot {v['volume']} (waits until completed)", save_as="snap",
                              wait={"waiter": "snapshot_completed", "params": {"SnapshotIds": [snap]}, "delay": 20,
                                    "max_attempts": 180},
                              undo=undo("ec2", "delete_snapshot", {"SnapshotId": snap}, "Delete the snapshot")))
        return ScriptDraft(title=f"Snapshot {v['volume']}", steps=steps, notes=_ebs_notes(v))
    if a == "modify":
        vol = lookups.volume(env, v["volume"]) or {}
        p = {"VolumeId": v["volume"], "Size": int(v["size_gb"]), "VolumeType": v["volume_type"]}
        if v["volume_type"] in ("gp3", "io1", "io2") and int(v.get("iops", 0) or 0):
            p["Iops"] = int(v["iops"])
        if v["volume_type"] == "gp3" and int(v.get("throughput", 0) or 0):
            p["Throughput"] = int(v["throughput"])
        steps.append(aws_step("ec2", "modify_volume", p,
                              f"Change {v['volume']} from {vol.get('size')} GB {vol.get('type')} to {p['Size']} GB "
                              f"{p['VolumeType']}"))
        return ScriptDraft(title=f"Modify volume {v['volume']}", steps=steps, notes=_ebs_notes(v))
    if a == "copy_snapshot":
        dest = v["dest_region"]
        p = {"SourceSnapshotId": v["snapshot"], "SourceRegion": env.region_name, "Encrypted": yes(v, "encrypt"),
             "Description": f"Copy of {v['snapshot']} by Kintsugi",
             "TagSpecifications": templates._tags("snapshot", f"{v['snapshot']}-copy")}
        steps.append(aws_step("ec2", "copy_snapshot", p, f"Copy {v['snapshot']} to {dest}", save_as="copy", region=dest,
                              wait={"waiter": "snapshot_completed", "params": {"SnapshotIds": ["{{copy.SnapshotId}}"]},
                                    "delay": 30, "max_attempts": 120},
                              undo=undo("ec2", "delete_snapshot", {"SnapshotId": "{{copy.SnapshotId}}"},
                                        f"Delete the copy in {dest}")))
        return ScriptDraft(title=f"Copy snapshot {v['snapshot']} to {dest}", steps=steps, notes=_ebs_notes(v))
    if a == "archive":
        steps.append(aws_step("ec2", "modify_snapshot_tier", {"SnapshotId": v["snapshot"], "StorageTier": "archive"},
                              f"Move {v['snapshot']} to the archive tier"))
        return ScriptDraft(title=f"Archive snapshot {v['snapshot']}", steps=steps, notes=_ebs_notes(v))
    if a == "restore_archive":
        p = {"SnapshotId": v["snapshot"]}
        if int(v.get("restore_days", 0) or 0):
            p["TemporaryRestoreDays"] = int(v["restore_days"])
        else:
            p["PermanentRestore"] = True
        steps.append(aws_step("ec2", "restore_snapshot_tier", p,
                              f"Restore {v['snapshot']} from the archive "
                              + (f"for {v['restore_days']} days" if "TemporaryRestoreDays" in p else "permanently")))
        return ScriptDraft(title=f"Restore archived snapshot {v['snapshot']}", steps=steps,
                           notes=["Restoring from the archive tier takes up to 72 hours."])
    if a == "schedule":
        from core.config import settings
        utc = utc_hhmm(v.get("time", "02:00"))
        role_name = "AWSDataLifecycleManagerDefaultRole"
        role = f"arn:aws:iam::{env.account_id()}:role/{role_name}"
        if role_name not in {r["name"] for r in env.roles("dlm.amazonaws.com")}:
            steps += role_steps(role_name, "dlm.amazonaws.com",
                                ["arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole"],
                                key="dlmrole")
        steps.append(aws_step("dlm", "create_lifecycle_policy", {
            "ExecutionRoleArn": role, "Description": f"Kintsugi daily snapshots of {v['tag_key']}={v['tag_value']}",
            "State": "ENABLED", "Tags": tag_dict("kintsugi-dlm"),
            "PolicyDetails": {"PolicyType": "EBS_SNAPSHOT_MANAGEMENT", "ResourceTypes": ["VOLUME"],
                              "TargetTags": [{"Key": v["tag_key"], "Value": v["tag_value"]}],
                              "Schedules": [{"Name": "daily", "CopyTags": True,
                                             "CreateRule": {"Interval": 24, "IntervalUnit": "HOURS", "Times": [utc]},
                                             "RetainRule": {"Count": int(v.get("keep", 7))}}]}},
            f"Snapshot every volume tagged {v['tag_key']}={v['tag_value']} daily at {v.get('time', '02:00')} "
            f"{settings.app_timezone} ({utc} UTC), keep {v.get('keep', 7)}", save_as="dlm",
            undo=undo("dlm", "delete_lifecycle_policy", {"PolicyId": "{{dlm.PolicyId}}"}, "Delete the snapshot policy")))
        return ScriptDraft(title=f"Daily EBS snapshots for {v['tag_key']}={v['tag_value']}", steps=steps,
                           notes=_ebs_notes(v) + ["Tag volumes with that key/value to include them."])
    if a == "default_encryption":
        steps.append(aws_step("ec2", "enable_ebs_encryption_by_default", {},
                              f"Encrypt every new EBS volume and snapshot copy by default in {env.region_name}",
                              undo=undo("ec2", "disable_ebs_encryption_by_default", {}, "Turn default encryption off")))
        return ScriptDraft(title="EBS encryption by default", steps=steps,
                           notes=["Existing volumes are not changed. Encryption is free."])
    if a == "delete_volume":
        steps.append(aws_step("ec2", "delete_volume", {"VolumeId": v["volume"]}, f"Delete volume {v['volume']}",
                              wait={"waiter": "volume_deleted", "params": {"VolumeIds": [v["volume"]]}}))
        return ScriptDraft(title=f"Delete volume {v['volume']}", steps=steps,
                           notes=["Permanent: take a snapshot first if you may need the data."])
    steps.append(aws_step("ec2", "delete_snapshot", {"SnapshotId": v["snapshot"]}, f"Delete snapshot {v['snapshot']}"))
    return ScriptDraft(title=f"Delete snapshot {v['snapshot']}", steps=steps,
                       notes=["Permanent. Snapshots used by an AMI cannot be deleted until the AMI is deregistered."])


def _validate_device(env, inputs, v) -> str:
    v = str(v).strip()
    if not re.fullmatch(r"/dev/(sd[f-p]|xvd[f-p])", v):
        raise ValueError("a device name like /dev/sdf (f to p)")
    return v


def _validate_tag(env, inputs, v) -> str:
    v = str(v).strip()
    if not re.fullmatch(r"[\w .:/=+@-]{1,128}", v):
        raise ValueError("letters, numbers and _ . : / = + - @ (max 128)")
    return v


_vol_create = action_is("create", "restore")
EBS = Template(
    name="ebs_volume",
    description="EBS: create/attach/detach/resize volumes, snapshots (copy, archive, restore), daily snapshot "
                "schedules, default encryption, deletes",
    fields=[
        choice("action", "What do you want to do with EBS?", EBS_ACTIONS, default="create", must_ask=True),
        FieldSpec("name", "Volume name?", "text", default="kintsugi-volume",
                  validate=_name_validator(r"[\w .-]{1,64}", "letters, numbers, space . _ - (max 64)"),
                  relevant=_vol_create),
        FieldSpec("snapshot", "Which snapshot?", "choice", must_ask=True,
                  options=lambda e, i: _snap_options("archive" if i.get("action") == "restore_archive" else
                                                     "standard")(e, i),
                  validate=lambda e, i, v: pick(lambda e2, i2: _snap_options(
                      "archive" if i.get("action") == "restore_archive" else "standard")(e2, i2), "snapshot")(e, i, v),
                  relevant=action_is("restore", "copy_snapshot", "archive", "restore_archive", "delete_snapshot"),
                  empty_hint="No completed snapshots found."),
        FieldSpec("volume", "Which volume?", "choice", must_ask=True,
                  options=lambda e, i: _vol_options({"attach": "available", "detach": "in-use"}.get(i.get("action")))(e, i),
                  validate=lambda e, i, v: pick(lambda e2, i2: _vol_options(
                      {"attach": "available", "detach": "in-use"}.get(i.get("action")))(e2, i2), "volume")(e, i, v),
                  relevant=action_is("attach", "detach", "snapshot", "modify", "delete_volume"),
                  empty_hint="No suitable volumes found."),
        FieldSpec("attach_to", "Attach to which instance (same availability zone)?", "choice",
                  default=lambda e, i: "none" if i.get("action") in ("create", "restore") else None,
                  must_ask=True, options=_attach_instance_options, validate=pick(_attach_instance_options, "instance"),
                  relevant=action_is("create", "restore", "attach"), empty_hint="No instance in that availability zone."),
        FieldSpec("az", "Availability zone?", "choice", must_ask=True, default=_az_default,
                  options=lambda e, i: [{"value": z, "label": z} for z in e.availability_zones()],
                  validate=lambda e, i, v: _validate_volume_az(e, i, v), relevant=_vol_create),
        FieldSpec("device", "Device name?", "text", default="/dev/sdf", validate=_validate_device,
                  relevant=lambda i: i.get("action") == "attach" or (
                      i.get("action") in ("create", "restore") and i.get("attach_to", "none") != "none")),
        choice("volume_type", "Volume type?", VOLUME_TYPES, default=lambda e, i: (
            lookups.volume(e, i.get("volume", "")) or {}).get("type", "gp3") if i.get("action") == "modify" else "gp3",
               relevant=action_is("create", "restore", "modify")),
        FieldSpec("size_gb", "Size (GB)?", "number",
                  default=lambda e, i: max(8, (lookups.snapshot(e, i.get("snapshot", "")) or {}).get("size", 0),
                                           (lookups.volume(e, i.get("volume", "")) or {}).get("size", 0)),
                  validate=_validate_size, relevant=action_is("create", "restore", "modify")),
        FieldSpec("iops", "IOPS? (gp3: 3000-16000; io1/io2: 100-64000)", "number",
                  default=lambda e, i: 3000 if i.get("volume_type", "gp3") in ("gp3", "io1", "io2") else 0,
                  validate=_validate_iops,
                  relevant=lambda i: i.get("action") in ("create", "restore", "modify")
                  and i.get("volume_type", "gp3") in ("io1", "io2") or (custom(i) and i.get("volume_type", "gp3") == "gp3"
                                                                        and i.get("action") in ("create", "restore", "modify"))),
        number("throughput", "Throughput MB/s (gp3: 125-1000)?", 125, 125, 1000,
               relevant=lambda i: custom(i) and i.get("volume_type", "gp3") == "gp3"
               and i.get("action") in ("create", "restore", "modify")),
        yes_no("encrypted", "Encrypt it?", default="yes", relevant=_vol_create),
        FieldSpec("kms_key", "KMS key? (empty = AWS managed key)", "text", default="", allow_empty=True,
                  relevant=both(_vol_create, custom)),
        yes_no("multi_attach", "Multi-Attach (several instances, io1/io2 only)?",
               relevant=lambda i: _vol_create(i) and custom(i) and i.get("volume_type") in ("io1", "io2")),
        yes_no("force", "Force detach (only if a normal detach hangs)?", relevant=action_is("detach")),
        FieldSpec("description", "Snapshot description?", "text", default="Created by Kintsugi",
                  relevant=action_is("snapshot")),
        FieldSpec("dest_region", "Copy to which region?", "choice", must_ask=True, options=region_options,
                  validate=lambda e, i, v: _dest_region(e, v), relevant=action_is("copy_snapshot")),
        yes_no("encrypt", "Encrypt the copy?", default="yes", relevant=action_is("copy_snapshot")),
        number("restore_days", "Restore for how many days? (0 = permanently)", 7, 0, 180,
               relevant=action_is("restore_archive")),
        FieldSpec("tag_key", "Snapshot volumes with which tag key?", "text", default="Backup", validate=_validate_tag,
                  relevant=action_is("schedule")),
        FieldSpec("tag_value", "...and which tag value?", "text", default="daily", validate=_validate_tag,
                  relevant=action_is("schedule")),
        FieldSpec("time", "At what time each day (your timezone)?", "text", default="02:00",
                  validate=lambda e, i, v: (utc_hhmm(v), str(v).strip())[1], relevant=action_is("schedule")),
        number("keep", "Keep how many snapshots?", 7, 1, 1000, relevant=action_is("schedule")),
        FieldSpec("settings", "Use recommended defaults or customise every option?", "choice", default="default",
                  options=static(opts(("default", "Recommended defaults"), ("custom", "Custom: IOPS, throughput, KMS ..."))),
                  validate=pick(static(opts(("default", ""), ("custom", ""))), "settings"),
                  relevant=action_is("create", "restore", "modify")),
        extra_params_field(lambda i: ("ec2", "create_volume"),
                           {"AvailabilityZone", "Size", "VolumeType", "SnapshotId", "TagSpecifications"},
                           relevant=lambda i: custom(i) and _vol_create(i)),
    ],
    title=lambda i: f"EBS ({i.get('action', 'create')})",
    build=_build_ebs, notes=_ebs_notes,
)


def _validate_volume_az(env, inputs, v) -> str:
    v = _choice([{"value": z, "label": z} for z in env.availability_zones()], v, "availability zone")
    iid = inputs.get("attach_to")
    if iid and iid != "none" and (inst := lookups.instance(env, iid)) and inst["az"] != v:
        raise ValueError(f"{iid} is in {inst['az']}; a volume can only attach to an instance in the same zone")
    return v


RECIPES = [LOAD_BALANCER, TARGET_GROUP, LAUNCH_TEMPLATE, AUTO_SCALING, AMI, EBS]
templates.TEMPLATES.update({t.name: t for t in RECIPES})
