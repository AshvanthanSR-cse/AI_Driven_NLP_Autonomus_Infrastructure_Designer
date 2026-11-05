"""Task templates: infrastructure requests that need details from the user before a script is written.

The LLM only picks a template and passes the details the user actually said. Code decides what is still
missing and asks the user (with real options loaded from their AWS account: subnets, security groups,
availability zones, key pairs). Key decisions (IP range, NAT, subnet, OS, security group, SSH source) are
always confirmed by the user, even if the LLM guessed them. Code then builds the steps, computes subnet
ranges, adds tags, a cost note and an undo action for every resource (used for the teardown script).
"""
import ipaddress
import re
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from core import audit, scripts
from core.scripts import ScriptDraft

HOURLY_PRICE = {"t2.micro": 0.0116, "t3.micro": 0.0104, "t2.small": 0.023, "t3.small": 0.0208,
                "t3.medium": 0.0416}
NAT_HOURLY, PUBLIC_IPV4_HOURLY, NAT_PER_GB, GP3_GB_MONTH = 0.045, 0.005, 0.045, 0.08
HOURS_PER_MONTH = 730


class TemplateError(ValueError):
    pass


@dataclass
class Question:
    key: str
    question: str
    kind: str
    options: list[dict] = field(default_factory=list)
    default: Any = None
    why: str = ""
    error: str = ""
    allow_custom: bool = False


@dataclass
class TaskQuestions:
    template: str
    title: str
    inputs: dict
    questions: list[Question]
    notes: list[str]
    confirmed: list[str] = field(default_factory=list)
    prerequisites: dict | None = None

    def to_dict(self) -> dict:
        return {"template": self.template, "title": self.title, "inputs": self.inputs,
                "questions": [asdict(q) for q in self.questions], "notes": self.notes,
                "confirmed": self.confirmed, "prerequisites": self.prerequisites}


@dataclass
class FieldSpec:
    key: str
    question: str
    kind: str
    why: str = ""
    must_ask: bool = False
    default: Any = None
    options: Callable | None = None
    validate: Callable | None = None
    relevant: Callable | None = None
    relevant_env: Callable | None = None
    allow_custom: bool = False
    empty_hint: str = ""
    allow_empty: bool = False
    optional: bool = False


@dataclass
class Template:
    name: str
    description: str
    fields: list[FieldSpec]
    title: Callable
    build: Callable
    notes: Callable


class Env:
    """Read-only AWS lookups for options and validation (cached per planning call)."""

    def __init__(self, conn, region: str | None = None):
        self.conn, self.region, self._cache = conn, region, {}

    def _memo(self, key, fn):
        if key not in self._cache:
            self._cache[key] = fn()
        return self._cache[key]

    def ec2(self):
        return self.conn.client("ec2", "read", self.region)

    def availability_zones(self) -> list[str]:
        return self._memo("azs", lambda: sorted(
            z["ZoneName"] for z in self.ec2().describe_availability_zones(
                Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
            if z.get("ZoneType", "availability-zone") == "availability-zone"))

    def subnets(self) -> list[dict]:
        def load():
            raw = self.ec2().describe_vpcs()["Vpcs"]
            vpcs = {v["VpcId"]: _name(v) for v in raw}
            vpc_cidrs = {v["VpcId"]: v.get("CidrBlock", "") for v in raw}
            out = []
            for s in self.ec2().describe_subnets()["Subnets"]:
                out.append({"id": s["SubnetId"], "cidr": s["CidrBlock"], "az": s["AvailabilityZone"],
                            "vpc": s["VpcId"], "vpc_name": vpcs.get(s["VpcId"], ""), "name": _name(s),
                            "vpc_cidr": vpc_cidrs.get(s["VpcId"], ""),
                            "public": bool(s.get("MapPublicIpOnLaunch"))})
            return sorted(out, key=lambda x: (x["vpc"], not x["public"], x["az"], x["cidr"]))
        return self._memo("subnets", load)

    def security_groups(self, vpc_id: str | None) -> list[dict]:
        def load():
            flt = [{"Name": "vpc-id", "Values": [vpc_id]}] if vpc_id else []
            return [{"id": g["GroupId"], "name": g["GroupName"], "desc": g.get("Description", ""),
                     "vpc": g.get("VpcId")} for g in self.ec2().describe_security_groups(Filters=flt)["SecurityGroups"]]
        return self._memo(("sgs", vpc_id), load)

    def key_pairs(self) -> list[str]:
        return self._memo("keys", lambda: sorted(k["KeyName"] for k in self.ec2().describe_key_pairs()["KeyPairs"]))

    def my_ip(self) -> str | None:
        def load():
            try:
                with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=4) as r:
                    ip = r.read().decode().strip()
                ipaddress.ip_address(ip)
                return ip
            except Exception:
                return None
        return self._memo("myip", load)

    @property
    def region_name(self) -> str:
        from core.config import settings
        return self.region or settings.aws_region

    def account_id(self) -> str:
        return self._memo("account", lambda: self.conn.client("sts", "read", self.region)
                          .get_caller_identity()["Account"])

    def roles(self, principal: str) -> list[dict]:
        """IAM roles whose trust policy allows the given service principal (e.g. lambda.amazonaws.com)."""
        def load():
            iam = self.conn.client("iam", "read", self.region)
            out = []
            for page in iam.get_paginator("list_roles").paginate():
                for r in page["Roles"]:
                    doc = r.get("AssumeRolePolicyDocument") or {}
                    if isinstance(doc, str):
                        import json as _json
                        import urllib.parse
                        doc = _json.loads(urllib.parse.unquote(doc))
                    services = [s for st in doc.get("Statement", [])
                                for s in _listify((st.get("Principal") or {}).get("Service"))]
                    if principal in services:
                        out.append({"name": r["RoleName"], "arn": r["Arn"]})
            return sorted(out, key=lambda x: x["name"])
        return self._memo(("roles", principal), load)

    def instances(self) -> list[dict]:
        """Running instances (for Ansible targets)."""
        def load():
            out = []
            for page in self.ec2().get_paginator("describe_instances").paginate(
                    Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                for res in page["Reservations"]:
                    for i in res["Instances"]:
                        out.append({"id": i["InstanceId"], "name": _name(i), "ip": i.get("PublicIpAddress", ""),
                                    "image": i.get("ImageId", ""), "platform": i.get("PlatformDetails", ""),
                                    "sgs": [g["GroupId"] for g in i.get("SecurityGroups", [])]})
            return out
        return self._memo("instances", load)

    def image_name(self, image_id: str) -> str:
        def load():
            imgs = self.ec2().describe_images(ImageIds=[image_id]).get("Images", [])
            return imgs[0].get("Name", "") if imgs else ""
        return self._memo(("image", image_id), load)

    def sg_rules(self, group_ids: list[str]) -> list[dict]:
        """Inbound rules of security groups: [{port_from, port_to, cidrs}]"""
        def load():
            rules = []
            for g in self.ec2().describe_security_groups(GroupIds=group_ids)["SecurityGroups"]:
                for p in g.get("IpPermissions", []):
                    rules.append({"from": p.get("FromPort", 0 if p.get("IpProtocol") == "-1" else None),
                                  "to": p.get("ToPort", 65535 if p.get("IpProtocol") == "-1" else None),
                                  "cidrs": [r["CidrIp"] for r in p.get("IpRanges", [])]})
            return rules
        return self._memo(("sgrules", tuple(group_ids)), load)

    def lambda_function(self, name: str) -> dict | None:
        def load():
            try:
                return self.conn.client("lambda", "read", self.region).get_function_configuration(FunctionName=name)
            except Exception as e:
                if getattr(e, "response", {}).get("Error", {}).get("Code") == "ResourceNotFoundException":
                    return None
                raise
        return self._memo(("lambda", name), load)

    def ecr_repo_uri(self, name: str) -> str | None:
        def load():
            try:
                repos = self.conn.client("ecr", "read", self.region).describe_repositories(
                    repositoryNames=[name])["repositories"]
                return repos[0]["repositoryUri"] if repos else None
            except Exception as e:
                if getattr(e, "response", {}).get("Error", {}).get("Code") == "RepositoryNotFoundException":
                    return None
                raise
        return self._memo(("ecr", name), load)

    def ami(self, os_key: str) -> dict:
        """Latest official AMI for the chosen OS (from AWS public SSM parameters) + its root device."""
        def load():
            param = OS_CHOICES[os_key]["ssm"]
            ami_id = self.conn.client("ssm", "read", self.region).get_parameter(Name=param)["Parameter"]["Value"]
            img = self.ec2().describe_images(ImageIds=[ami_id])["Images"][0]
            return {"id": ami_id, "root_device": img.get("RootDeviceName", "/dev/xvda"), "name": img.get("Name", "")}
        return self._memo(("ami", os_key), load)


def _listify(v) -> list:
    return [] if v is None else v if isinstance(v, list) else [v]


def _name(resource: dict) -> str:
    return next((t["Value"] for t in resource.get("Tags", []) or [] if t["Key"] == "Name"), "")


def _tags(rtype: str, name: str, extra: dict | None = None) -> list[dict]:
    expires = (datetime.now(timezone.utc) + timedelta(days=3)).strftime("%Y-%m-%d")
    tags = {"Name": name, "Project": "kintsugi", "CreatedBy": "kintsugi", "ExpiresAt": expires, **(extra or {})}
    return [{"ResourceType": rtype, "Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}]


def _int(v, lo: int, hi: int, what: str) -> int:
    try:
        n = int(str(v).strip())
    except ValueError:
        raise ValueError(f"{what} must be a whole number") from None
    if not lo <= n <= hi:
        raise ValueError(f"{what} must be between {lo} and {hi}")
    return n


def _yes_no(v) -> str:
    s = str(v).strip().lower()
    if s in ("yes", "y", "true", "1", "on"):
        return "yes"
    if s in ("no", "n", "false", "0", "off", "none"):
        return "no"
    raise ValueError("answer yes or no")


def _choice(options: list[dict], v, what: str):
    values = [o["value"] for o in options]
    if v in values:
        return v
    low = str(v).strip().lower()
    for o in options:
        if low in (str(o["value"]).lower(), str(o["label"]).lower()):
            return o["value"]
    if not values:
        raise ValueError(f"no {what} options are available")
    raise ValueError(f"'{v}' is not one of the available {what} options")


def _safe_name(env, inputs, v) -> str:
    v = str(v).strip()
    if not re.fullmatch(r"[A-Za-z0-9][\w-]{0,39}", v):
        raise ValueError("use letters, numbers, - or _ (max 40 characters)")
    return v


def _subnet_prefix(net: ipaddress.IPv4Network) -> int:
    return max(24, net.prefixlen + 2)


def _validate_vpc_cidr(env, inputs, v) -> str:
    try:
        net = ipaddress.ip_network(str(v).strip(), strict=True)
    except ValueError:
        raise ValueError("enter a network like 10.0.0.0/16 (host bits must be zero)") from None
    if net.version != 4 or not net.is_private:
        raise ValueError("use a private IPv4 range: 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16")
    if not 16 <= net.prefixlen <= 24:
        raise ValueError("the VPC size must be between /16 and /24")
    needed = int(inputs.get("public_subnets", 2)) + int(inputs.get("private_subnets", 2))
    available = 2 ** (_subnet_prefix(net) - net.prefixlen)
    if needed > available:
        raise ValueError(f"{net} only fits {available} subnets; use a bigger range like 10.0.0.0/16")
    return str(net)


def _az_options(env, inputs):
    return [{"value": z, "label": z} for z in env.availability_zones()]


def _validate_azs(env, inputs, v) -> list[str]:
    zones = [z.strip() for z in (v if isinstance(v, list) else str(v).split(",")) if str(z).strip()]
    valid = env.availability_zones()
    bad = [z for z in zones if z not in valid]
    if bad:
        raise ValueError(f"unknown availability zone(s): {', '.join(bad)}")
    need = max(int(inputs.get("public_subnets", 2)), int(inputs.get("private_subnets", 2)), 1)
    if len(set(zones)) < min(need, len(valid)):
        raise ValueError(f"pick at least {min(need, len(valid))} availability zones (one per subnet pair)")
    return list(dict.fromkeys(zones))


def _az_default(env, inputs):
    need = max(int(inputs.get("public_subnets", 2)), int(inputs.get("private_subnets", 2)), 1)
    return env.availability_zones()[:need]


NAT_OPTIONS = [
    {"value": "yes", "label": "Yes, one NAT gateway (about $0.05/hour, about $36/month; over a $5 budget in ~4 days)"},
    {"value": "per_az", "label": "One NAT gateway per availability zone (highly available; multiplies the cost)"},
    {"value": "no", "label": "No NAT (private subnets get no internet access; free)"},
]


def _nat_choice(v) -> str:
    s = str(v).strip().lower()
    if s in ("per_az", "per az", "per-az", "ha", "one per zone"):
        return "per_az"
    return _yes_no(v)


def _vpc_notes(inputs) -> list[str]:
    extra = []
    if inputs.get("flow_logs") == "yes":
        extra.append("Flow logs go to CloudWatch Logs (~$0.50/GB ingested), kept 14 days.")
    if inputs.get("s3_endpoint", "yes") == "yes":
        extra.append("The S3 gateway endpoint is free and keeps S3 traffic off the NAT gateway.")
    if inputs.get("nat_gateway") in ("yes", "per_az"):
        n = len(inputs.get("azs") or [1]) if inputs.get("nat_gateway") == "per_az" else 1
        hourly = n * (NAT_HOURLY + PUBLIC_IPV4_HOURLY)
        return [f"COST: {n} NAT gateway(s) ~${NAT_HOURLY}/h + public IPv4 ~${PUBLIC_IPV4_HOURLY}/h each = "
                f"~${hourly:.3f}/hour (~${hourly * HOURS_PER_MONTH:.0f}/month) + ${NAT_PER_GB}/GB processed. "
                f"Approximate us-east-1 prices at time of writing; verify current pricing. Run the teardown script "
                f"when you are done.", "VPC, subnets, route tables and the internet gateway themselves are free."] + extra
    return ["COST: VPC, subnets, route tables and the internet gateway are free."] + extra


def _build_vpc(env, v) -> ScriptDraft:
    name, net = v["name"], ipaddress.ip_network(v["cidr"])
    n_pub, n_priv, azs = v["public_subnets"], v["private_subnets"], v["azs"]
    nat = v.get("nat_gateway") in ("yes", "per_az") and n_priv > 0
    per_az = v.get("nat_gateway") == "per_az" and nat
    blocks = list(net.subnets(new_prefix=_subnet_prefix(net)))
    steps: list[dict] = []

    def add(desc, op, params, save_as=None, undo=None, wait=None):
        st = {"service": "ec2", "operation": op, "params": params, "description": desc}
        if save_as:
            st["save_as"] = save_as
        if undo:
            st["undo"] = {"service": "ec2", **undo}
        if wait:
            st["wait"] = wait
        steps.append(st)

    vpc_id = "{{vpc.Vpc.VpcId}}"
    add(f"Create VPC {name} ({net})", "create_vpc",
        {"CidrBlock": str(net), "TagSpecifications": _tags("vpc", name)}, save_as="vpc",
        undo={"operation": "delete_vpc", "params": {"VpcId": vpc_id}, "description": f"Delete VPC {name}"})
    add("Enable DNS hostnames", "modify_vpc_attribute", {"VpcId": vpc_id, "EnableDnsHostnames": {"Value": True}})
    ipv6 = v.get("ipv6") == "yes"
    if ipv6:
        add("Add an Amazon-provided IPv6 range (/56)", "associate_vpc_cidr_block",
            {"VpcId": vpc_id, "AmazonProvidedIpv6CidrBlock": True}, save_as="v6")
    igw = "{{igw.InternetGateway.InternetGatewayId}}"
    add("Create internet gateway", "create_internet_gateway",
        {"TagSpecifications": _tags("internet-gateway", f"{name}-igw")}, save_as="igw",
        undo={"operation": "delete_internet_gateway", "params": {"InternetGatewayId": igw},
              "description": "Delete internet gateway"})
    add("Attach internet gateway to the VPC", "attach_internet_gateway", {"InternetGatewayId": igw, "VpcId": vpc_id},
        undo={"operation": "detach_internet_gateway", "params": {"InternetGatewayId": igw, "VpcId": vpc_id},
              "description": "Detach internet gateway"})

    def subnet(kind, i, block):
        key = f"{kind}{i + 1}"
        label = "public" if kind == "pub" else "private"
        az = azs[i % len(azs)]
        sid = "{{" + key + ".Subnet.SubnetId}}"
        add(f"Create {label} subnet {i + 1} ({block}, {az})", "create_subnet",
            {"VpcId": vpc_id, "CidrBlock": str(block), "AvailabilityZone": az,
             "TagSpecifications": _tags("subnet", f"{name}-{label}-{i + 1}")},
            save_as=key, undo={"operation": "delete_subnet", "params": {"SubnetId": sid},
                               "description": f"Delete subnet {block}"})
        return sid

    pub = [subnet("pub", i, blocks[i]) for i in range(n_pub)]
    priv = [subnet("priv", i, blocks[n_pub + i]) for i in range(n_priv)]
    for i, sid in enumerate(pub):
        add(f"Public subnet {i + 1}: give instances a public IP", "modify_subnet_attribute",
            {"SubnetId": sid, "MapPublicIpOnLaunch": {"Value": True}})

    def route_table(label, key, subnet_ids, route=None):
        rt = "{{" + key + ".RouteTable.RouteTableId}}"
        add(f"Create {label} route table", "create_route_table",
            {"VpcId": vpc_id, "TagSpecifications": _tags("route-table", f"{name}-{label}-rt")}, save_as=key,
            undo={"operation": "delete_route_table", "params": {"RouteTableId": rt},
                  "description": f"Delete {label} route table"})
        if route:
            add(f"{label.capitalize()} route table: 0.0.0.0/0 -> {route[0]}", "create_route",
                {"RouteTableId": rt, "DestinationCidrBlock": "0.0.0.0/0", route[1]: route[2]})
        for i, sid in enumerate(subnet_ids):
            akey = f"{key}_assoc{i + 1}"
            add(f"Associate {label} route table with {label} subnet {i + 1}", "associate_route_table",
                {"RouteTableId": rt, "SubnetId": sid}, save_as=akey,
                undo={"operation": "disassociate_route_table",
                      "params": {"AssociationId": "{{" + akey + ".AssociationId}}"},
                      "description": f"Disassociate {label} route table from subnet {i + 1}"})

    if pub:
        route_table("public", "rt_public", pub, ("internet gateway", "GatewayId", igw))
        if ipv6:
            add("Public route table: ::/0 -> internet gateway (IPv6)", "create_route",
                {"RouteTableId": "{{rt_public.RouteTable.RouteTableId}}", "DestinationIpv6CidrBlock": "::/0",
                 "GatewayId": igw})

    def nat_gateway(i):
        sfx = str(i + 1) if per_az else ""
        nid = "{{nat" + sfx + ".NatGateway.NatGatewayId}}"
        add(f"Allocate an Elastic IP for NAT gateway {sfx}".rstrip(), "allocate_address",
            {"Domain": "vpc", "TagSpecifications": _tags("elastic-ip", f"{name}-nat{sfx}-eip")}, save_as=f"eip{sfx}",
            undo={"operation": "release_address", "params": {"AllocationId": "{{eip" + sfx + ".AllocationId}}"},
                  "description": "Release the NAT Elastic IP"})
        add(f"Create NAT gateway in public subnet {i + 1} (waits until available, ~2 min)", "create_nat_gateway",
            {"SubnetId": pub[i], "AllocationId": "{{eip" + sfx + ".AllocationId}}",
             "TagSpecifications": _tags("natgateway", f"{name}-nat{sfx}")}, save_as=f"nat{sfx}",
            wait={"waiter": "nat_gateway_available", "params": {"NatGatewayIds": [nid]}},
            undo={"operation": "delete_nat_gateway", "params": {"NatGatewayId": nid},
                  "description": "Delete NAT gateway (waits until deleted)",
                  "wait": {"waiter": "nat_gateway_deleted", "params": {"NatGatewayIds": [nid]}}})
        return nid

    if per_az:
        nats = [nat_gateway(i) for i in range(min(len(pub), len(priv)))]
        for i, sid in enumerate(priv):
            route_table(f"private-{i + 1}", f"rt_private{i + 1}", [sid],
                        ("NAT gateway", "NatGatewayId", nats[i % len(nats)]))
    else:
        nat_id = nat_gateway(0) if nat else None
        if priv:
            route_table("private", "rt_private", priv, ("NAT gateway", "NatGatewayId", nat_id) if nat else None)
    if v.get("s3_endpoint", "yes") == "yes":
        rts = (["{{rt_public.RouteTable.RouteTableId}}"] if pub else []) + (
            ["{{rt_private" + str(i + 1) + ".RouteTable.RouteTableId}}" for i in range(len(priv))] if per_az
            else (["{{rt_private.RouteTable.RouteTableId}}"] if priv else []))
        add("S3 gateway endpoint (free; private S3 access without NAT)", "create_vpc_endpoint",
            {"VpcId": vpc_id, "ServiceName": f"com.amazonaws.{env.region_name}.s3", "VpcEndpointType": "Gateway",
             "RouteTableIds": rts, "TagSpecifications": _tags("vpc-endpoint", f"{name}-s3")}, save_as="s3ep",
            undo={"operation": "delete_vpc_endpoints",
                  "params": {"VpcEndpointIds": ["{{s3ep.VpcEndpoint.VpcEndpointId}}"]},
                  "description": "Delete the S3 endpoint"})
    if v.get("flow_logs") == "yes":
        import json as _json
        from core.recipes import role_steps, tag_dict
        group = f"/vpc/flowlogs/{name}"
        steps.append({"service": "logs", "operation": "create_log_group",
                      "params": {"logGroupName": group, "tags": tag_dict(name)}, "description": f"Log group {group}",
                      "undo": {"service": "logs", "operation": "delete_log_group", "params": {"logGroupName": group},
                               "description": "Delete the flow log group"}})
        steps.append({"service": "logs", "operation": "put_retention_policy",
                      "params": {"logGroupName": group, "retentionInDays": 14}, "description": "Keep flow logs 14 days"})
        role = f"{name}-flowlogs"[:64]
        steps.extend(role_steps(role, "vpc-flow-logs.amazonaws.com", [], key="flrole", pause=1))
        doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": [
            "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"],
            "Resource": f"arn:aws:logs:{env.region_name}:{env.account_id()}:log-group:{group}:*"}]}
        steps.append({"service": "iam", "operation": "put_role_policy", "pause_after": 15,
                      "params": {"RoleName": role, "PolicyName": "write-flow-logs", "PolicyDocument": _json.dumps(doc)},
                      "description": "Allow flow logs to write only to that log group",
                      "undo": {"service": "iam", "operation": "delete_role_policy",
                               "params": {"RoleName": role, "PolicyName": "write-flow-logs"},
                               "description": "Remove the flow logs policy"}})
        add("Record all VPC traffic to CloudWatch Logs (flow logs)", "create_flow_logs",
            {"ResourceIds": [vpc_id], "ResourceType": "VPC", "TrafficType": "ALL",
             "LogDestinationType": "cloud-watch-logs", "LogGroupName": group,
             "DeliverLogsPermissionArn": "{{flrole.Role.Arn}}"}, save_as="fl",
            undo={"operation": "delete_flow_logs", "params": {"FlowLogIds": ["{{fl.FlowLogIds.0}}"]},
                  "description": "Delete the flow log"})

    return ScriptDraft(title=f"Create VPC {name} ({net}) with {n_pub} public + {n_priv} private subnets"
                             f"{', NAT per zone' if per_az else ', NAT' if nat else ''}{', IPv6' if ipv6 else ''}",
                       steps=steps, notes=_vpc_notes(v))


VPC_TEMPLATE = Template(
    name="vpc_network",
    description="VPC with public/private subnets, internet gateway, route tables and optional NAT gateway",
    fields=[
        FieldSpec("name", "What name should the VPC have?", "text", default="kintsugi-vpc", validate=_safe_name,
                  why="Used in the Name tag of every resource."),
        FieldSpec("public_subnets", "How many public subnets?", "number", default=2,
                  validate=lambda e, i, v: _int(v, 1, 3, "public subnets"),
                  why="Public subnets route to the internet gateway."),
        FieldSpec("private_subnets", "How many private subnets?", "number", default=2,
                  validate=lambda e, i, v: _int(v, 0, 3, "private subnets"),
                  why="Private subnets have no direct inbound internet access."),
        FieldSpec("cidr", "Which IP address range (CIDR) should the VPC use?", "text", must_ask=True,
                  default="10.0.0.0/16", validate=_validate_vpc_cidr,
                  why="A private range such as 10.0.0.0/16. Subnet ranges are calculated from it automatically. "
                      "It must not overlap networks you want to connect later."),
        FieldSpec("azs", "Which availability zones should the subnets be spread across?", "multichoice",
                  must_ask=True, default=_az_default, options=_az_options, validate=_validate_azs,
                  why="Two zones keep the network working if one zone has an outage."),
        FieldSpec("nat_gateway", "Do you want a NAT gateway so private subnets can reach the internet?", "choice",
                  must_ask=True, default="no", options=lambda e, i: NAT_OPTIONS,
                  validate=lambda e, i, v: _nat_choice(v), relevant=lambda i: int(i.get("private_subnets", 2) or 0) > 0,
                  why="Needed for updates/downloads from private subnets. It is billed per hour even when idle."),
        FieldSpec("s3_endpoint", "Add a free S3 gateway endpoint?", "choice", default="yes",
                  options=lambda e, i: [{"value": "yes", "label": "Yes (free)"}, {"value": "no", "label": "No"}],
                  optional=True, validate=lambda e, i, v: _yes_no(v), why="Private subnets reach S3 without a NAT gateway."),
        FieldSpec("ipv6", "Add IPv6?", "choice", default="no",
                  options=lambda e, i: [{"value": "no", "label": "No (IPv4 only)"},
                                        {"value": "yes", "label": "Yes, an Amazon-provided IPv6 /56"}],
                  optional=True, validate=lambda e, i, v: _yes_no(v)),
        FieldSpec("flow_logs", "Record network traffic (flow logs to CloudWatch)?", "choice", default="no",
                  options=lambda e, i: [{"value": "no", "label": "No"},
                                        {"value": "yes", "label": "Yes (~$0.50/GB of logs)"}],
                  optional=True, validate=lambda e, i, v: _yes_no(v)),
    ],
    title=lambda i: f"VPC '{i.get('name', 'kintsugi-vpc')}'",
    build=_build_vpc,
    notes=_vpc_notes,
)


OS_CHOICES = {
    "amazon-linux-2023": {"label": "Amazon Linux 2023", "ssm": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64", "admin_port": 22, "min_gb": 8},
    "ubuntu-24.04": {"label": "Ubuntu 24.04 LTS", "ssm": "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id", "admin_port": 22, "min_gb": 8},
    "windows-2022": {"label": "Windows Server 2022", "ssm": "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base", "admin_port": 3389, "min_gb": 30},
}
PURPOSES = [
    {"value": "web", "label": "Web server: HTTP/HTTPS open to everyone, SSH/RDP only from your IP"},
    {"value": "admin", "label": "Dev / admin box: SSH/RDP only from your IP"},
    {"value": "private", "label": "Private worker: no inbound access at all"},
]


def _subnet_options(env, inputs):
    return [{"value": s["id"],
             "label": f"{s['id']} · {s['cidr']} · {s['az']} · {'public' if s['public'] else 'private'} · "
                      f"{s['vpc_name'] or s['vpc']}{' · ' + s['name'] if s['name'] else ''}"}
            for s in env.subnets()]


def _subnet_of(env, inputs) -> dict | None:
    return next((s for s in env.subnets() if s["id"] == inputs.get("subnet_id")), None)


def _sg_options(env, inputs):
    sub = _subnet_of(env, inputs)
    opts = [{"value": "new", "label": "Create a new security group with rules for this purpose (recommended)"}]
    if sub:
        opts += [{"value": g["id"], "label": f"{g['id']} · {g['name']} · {g['desc'][:50]}"}
                 for g in env.security_groups(sub["vpc"])]
    return opts


def _validate_sg(env, inputs, v):
    if str(v).strip().lower() in ("new", "create", "create new"):
        return "new"
    return _choice(_sg_options(env, inputs), v, "security group (pick one in the subnet's VPC)")


def _validate_admin_cidr(env, inputs, v) -> str:
    try:
        net = ipaddress.ip_network(str(v).strip(), strict=False)
    except ValueError:
        raise ValueError("enter an IP like 203.0.113.5 or a range like 203.0.113.0/24") from None
    if net.prefixlen < 24:
        raise ValueError("too wide: SSH/RDP may only be opened to your IP (/32) or at most a /24 range")
    return str(net)


def _admin_default(env, inputs):
    ip = env.my_ip()
    return f"{ip}/32" if ip else None


def _key_options(env, inputs):
    return [{"value": k, "label": k} for k in env.key_pairs()] + \
           [{"value": "none", "label": "No key pair (connect with SSM Session Manager, or not at all)"}]


def _instance_type_options(env, inputs):
    return [{"value": t, "label": f"{t} (~${p}/hour, ~${p * HOURS_PER_MONTH:.1f}/month)"}
            for t, p in HOURLY_PRICE.items()]


def _ec2_notes(inputs) -> list[str]:
    t = inputs.get("instance_type", "t3.micro")
    p = HOURLY_PRICE.get(t, 0)
    gb = int(inputs.get("volume_gb") or 8)
    notes = [f"COST: {t} ~${p}/hour (~${p * HOURS_PER_MONTH:.1f}/month) + {gb} GB gp3 disk ~${gb * GP3_GB_MONTH:.2f}/month. "
             f"Approximate us-east-1 Linux prices; verify current pricing. t2/t3.micro may be free-tier eligible.",
             "The instance is tagged Env=demo, so you can stop/start it from chat. Stop or tear it down when idle."]
    if inputs.get("os") == "windows-2022":
        notes.append("Windows instances cost more per hour (license included).")
    return notes


def _build_ec2(env, v) -> ScriptDraft:
    name, os_key, purpose = v["name"], v["os"], v["purpose"]
    osinfo = OS_CHOICES[os_key]
    sub = _subnet_of(env, v)
    ami = env.ami(os_key)
    steps: list[dict] = []
    if v["security_group"] == "new":
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
        add_sg = {"service": "ec2", "operation": "create_security_group", "save_as": "sg",
                  "description": f"Create security group for {name} ({purpose})",
                  "params": {"GroupName": f"{name}-sg-{stamp}", "Description": f"Kintsugi {purpose} security group for {name}",
                             "VpcId": sub["vpc"], "TagSpecifications": _tags("security-group", f"{name}-sg")},
                  "undo": {"service": "ec2", "operation": "delete_security_group",
                           "params": {"GroupId": "{{sg.GroupId}}"}, "description": "Delete the security group"}}
        steps.append(add_sg)
        perms = []
        if purpose in ("web", "admin"):
            port = osinfo["admin_port"]
            perms.append({"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                          "IpRanges": [{"CidrIp": v["admin_cidr"], "Description": "admin access from your IP"}]})
        if purpose == "web":
            for port in (80, 443):
                perms.append({"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                              "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "web"}]})
        if perms:
            rules = ", ".join(f"{p['FromPort']} from {p['IpRanges'][0]['CidrIp']}" for p in perms)
            steps.append({"service": "ec2", "operation": "authorize_security_group_ingress",
                          "description": f"Allow inbound: {rules}",
                          "params": {"GroupId": "{{sg.GroupId}}", "IpPermissions": perms}})
        sg_id = "{{sg.GroupId}}"
    else:
        sg_id = v["security_group"]
    run = {"ImageId": ami["id"], "InstanceType": v["instance_type"], "SubnetId": sub["id"],
           "SecurityGroupIds": [sg_id], "MinCount": 1, "MaxCount": 1,
           "BlockDeviceMappings": [{"DeviceName": ami["root_device"],
                                    "Ebs": {"VolumeSize": v["volume_gb"], "VolumeType": "gp3",
                                            "DeleteOnTermination": True, "Encrypted": True}}],
           "MetadataOptions": {"HttpTokens": "required"},
           "TagSpecifications": _tags("instance", name, {"Env": "demo", "Purpose": purpose}) +
                                _tags("volume", f"{name}-root", {"Env": "demo"})}
    if v.get("key_name") and v["key_name"] != "none":
        run["KeyName"] = v["key_name"]
    inst = "{{inst.Instances.0.InstanceId}}"
    steps.append({"service": "ec2", "operation": "run_instances", "save_as": "inst",
                  "description": f"Launch {name}: {osinfo['label']} ({ami['id']}), {v['instance_type']}, "
                                 f"{sub['id']} ({'public' if sub['public'] else 'private'}), waits until running",
                  "params": run, "wait": {"waiter": "instance_running", "params": {"InstanceIds": [inst]}},
                  "undo": {"service": "ec2", "operation": "terminate_instances", "params": {"InstanceIds": [inst]},
                           "description": f"Terminate {name} (waits until terminated)",
                           "wait": {"waiter": "instance_terminated", "params": {"InstanceIds": [inst]}}}})
    return ScriptDraft(title=f"Launch EC2 instance {name} ({osinfo['label']}, {v['instance_type']})",
                       steps=steps, notes=_ec2_notes(v))


EC2_TEMPLATE = Template(
    name="ec2_instance",
    description="One EC2 instance with OS, subnet, security group, key pair and disk chosen by the user",
    fields=[
        FieldSpec("name", "What name should the instance have?", "text", default="kintsugi-demo",
                  validate=_safe_name, why="Used in the Name tag; you can refer to it by name in chat later."),
        FieldSpec("purpose", "What is the purpose of the instance?", "choice", must_ask=True,
                  options=lambda e, i: PURPOSES, validate=lambda e, i, v: _choice(PURPOSES, v, "purpose"),
                  why="Decides which ports the new security group opens."),
        FieldSpec("os", "Which operating system?", "choice", must_ask=True,
                  options=lambda e, i: [{"value": k, "label": o["label"]} for k, o in OS_CHOICES.items()],
                  validate=lambda e, i, v: _choice([{"value": k, "label": o["label"]} for k, o in OS_CHOICES.items()], v, "OS"),
                  why="The latest official image for that OS is used."),
        FieldSpec("instance_type", "Which instance size?", "choice", default="t3.micro",
                  options=_instance_type_options,
                  validate=lambda e, i, v: _choice(_instance_type_options(e, i), v, "instance type (larger sizes are blocked)"),
                  why="Small sizes only, to stay within budget."),
        FieldSpec("subnet_id", "Which subnet should it be launched in?", "choice", must_ask=True,
                  options=_subnet_options, validate=lambda e, i, v: _choice(_subnet_options(e, i), v, "subnet"),
                  why="Public subnets give the instance a public IP; private subnets do not.",
                  empty_hint="There are no subnets (no VPC) in this region. Cancel and first ask: 'Create a VPC "
                             "with 2 public and 2 private subnets', run that script, then create the instance."),
        FieldSpec("security_group", "Which security group (firewall)?", "choice", must_ask=True, default="new",
                  options=_sg_options, validate=_validate_sg,
                  why="A new group gets exactly the rules needed for the purpose you chose."),
        FieldSpec("admin_cidr", "Which IP address may connect with SSH (or RDP for Windows)?", "text", must_ask=True,
                  default=_admin_default, validate=_validate_admin_cidr,
                  relevant=lambda i: i.get("security_group", "new") == "new" and i.get("purpose", "web") in ("web", "admin"),
                  why="Pre-filled with your current public IP. Opening SSH/RDP to everyone (0.0.0.0/0) is blocked."),
        FieldSpec("key_name", "Which key pair for login?", "choice",
                  default=lambda e, i: (e.key_pairs() or ["none"])[0], options=_key_options,
                  validate=lambda e, i, v: _choice(_key_options(e, i), v, "key pair"),
                  why="Needed for SSH (Linux) or to decrypt the Windows password."),
        FieldSpec("volume_gb", "Disk size in GB?", "number",
                  default=lambda e, i: OS_CHOICES.get(i.get("os"), {}).get("min_gb", 8),
                  validate=lambda e, i, v: _int(v, OS_CHOICES.get(i.get("os"), {}).get("min_gb", 8), 100, "disk size"),
                  why="gp3, encrypted, deleted together with the instance."),
    ],
    title=lambda i: f"EC2 instance '{i.get('name', 'kintsugi-demo')}'",
    build=_build_ec2,
    notes=_ec2_notes,
)

TEMPLATES = {t.name: t for t in (VPC_TEMPLATE, EC2_TEMPLATE)}


def _question(f: FieldSpec, env: Env, inputs: dict, default=None, error: str = "") -> Question:
    try:
        opts = f.options(env, inputs) if f.options else []
    except Exception as e:
        opts, error = [], error or f"could not load options from AWS ({audit_error(e)})"
    if f.kind in ("choice", "multichoice") and not opts and not error and not f.allow_empty:
        where = f" in {env.region}" if env.region else ""
        error = f.empty_hint or f"nothing found in your AWS account{where} for this"
    if default is None:
        try:
            default = f.default(env, inputs) if callable(f.default) else f.default
        except Exception:
            default = None
    return Question(key=f.key, question=f.question, kind=f.kind, options=opts, default=default, why=f.why,
                    error=error, allow_custom=f.allow_custom)


CLOCK_SKEW_CODES = {"RequestTimeTooSkewed", "SignatureDoesNotMatch", "InvalidSignatureException",
                    "RequestExpired"}


def audit_error(e: Exception) -> str:
    resp = getattr(e, "response", None)
    if isinstance(resp, dict):
        code = resp.get("Error", {}).get("Code", type(e).__name__)
        msg = str(resp.get("Error", {}).get("Message", ""))
        if code in CLOCK_SKEW_CODES and ("time" in msg.lower() or "expired" in msg.lower()
                                         or code == "RequestTimeTooSkewed"):
            return (f"{code}: your PC clock or timezone is wrong, so AWS rejects the request. "
                    "Fix it in Windows Settings > Time & language > Date & time: turn on "
                    "'Set time automatically' and 'Set time zone automatically', then click 'Sync now'")
        return code
    return type(e).__name__


def _implies_custom(t: Template, inputs: dict) -> bool:
    """An advanced option was given (it is only asked with settings='custom'), so the user wants custom settings."""
    sf = next((f for f in t.fields if f.key == "settings"), None)
    if "settings" in inputs or not sf or callable(sf.default):
        return False
    for f in t.fields:
        if f.key not in inputs or not f.relevant:
            continue
        try:
            if not f.relevant({**inputs, "settings": "default"}) and f.relevant({**inputs, "settings": "custom"}):
                return True
        except Exception:
            continue
    return False


def _normalize_numbers(t: Template, inputs: dict) -> dict[str, str]:
    """Make number fields numbers before anything calls int() on them.

    A list (e.g. subnet CIDRs where a count is expected) becomes its length; a numeric string becomes a number.
    Anything else is removed from inputs and returned as {key: error} so the field is asked with that error."""
    errors = {}
    for f in t.fields:
        if f.kind != "number" or f.key not in inputs:
            continue
        v = inputs[f.key]
        if isinstance(v, (list, tuple, set)):
            inputs[f.key] = len(v)
        elif isinstance(v, bool) or not isinstance(v, (int, float, str)):
            errors[f.key] = f"{f.key.replace('_', ' ')} must be a whole number"
        elif isinstance(v, str):
            try:
                inputs[f.key] = int(v.strip())
            except ValueError:
                try:
                    inputs[f.key] = float(v.strip())
                except ValueError:
                    errors[f.key] = f"{f.key.replace('_', ' ')} must be a whole number, not '{v}'"
    for k in errors:
        inputs.pop(k)
    return errors


def plan(template: str, inputs: dict, conn, confirmed: set | None = None, region: str | None = None):
    """Return TaskQuestions (something is missing or must be confirmed) or a ready ScriptDraft.

    confirmed = keys the user has explicitly answered. None means all given inputs are confirmed
    (the answer form). For an LLM call, pass only the keys of fields that are not must_ask."""
    load_catalog()
    if template not in TEMPLATES:
        raise TemplateError(f"unknown template '{template}'")
    t = TEMPLATES[template]
    env = Env(conn, region)
    empty_ok = {f.key for f in t.fields if f.allow_empty}
    inputs = {k: v for k, v in (inputs or {}).items() if v not in (None, "", []) or (k in empty_ok and v in ("", []))}
    bad_numbers = _normalize_numbers(t, inputs)
    confirmed = set(inputs) if confirmed is None else set(confirmed)
    if _implies_custom(t, inputs):
        inputs["settings"] = "custom"
        confirmed.add("settings")
    from core import prereqs
    report = prereqs.for_template(template, inputs, env)
    if report and report.blocking:
        report.confirmed = sorted(confirmed)
        return report
    values: dict = {}
    provisional: dict = {}
    questions: list[Question] = []
    for f in t.fields:
        cur = {**provisional, **inputs, **values}
        if f.relevant and not f.relevant(cur):
            continue
        if f.relevant_env:
            try:
                if not f.relevant_env(env, cur):
                    continue
            except Exception:
                pass
        if f.key not in inputs and f.optional:
            try:
                values[f.key] = f.default(env, cur) if callable(f.default) else f.default
            except Exception:
                pass
            continue
        if f.key in inputs:
            try:
                val = f.validate(env, cur, inputs[f.key]) if f.validate else inputs[f.key]
            except ValueError as e:
                bad = inputs[f.key]
                keep = None if f.kind == "text" and isinstance(bad, bool) else bad
                questions.append(_question(f, env, cur, default=keep, error=str(e)))
                continue
            except Exception as e:
                questions.append(_question(f, env, cur, default=inputs[f.key],
                                           error=f"could not check this in AWS ({audit_error(e)})"))
                continue
            values[f.key] = val
            if f.must_ask and f.key not in confirmed:
                questions.append(_question(f, env, {**inputs, **values}, default=val))
            continue
        q = _question(f, env, cur, error=bad_numbers.get(f.key, ""))
        questions.append(q)
        if q.default not in (None, "", []):
            provisional[f.key] = q.default
    merged = {**inputs, **values}
    if questions:
        asked = {q.key for q in questions}
        report = prereqs.for_template(template, merged, env)
        if report and report.blocking:
            report.confirmed = sorted(k for k in confirmed if k in values)
            return report
        return TaskQuestions(template, t.title(merged), merged, questions, t.notes(merged),
                             confirmed=sorted(k for k in confirmed if k in values and k not in asked),
                             prerequisites=report.to_dict() if report else None)
    report = prereqs.for_template(template, values, env)
    if report and report.blocking:
        report.confirmed = sorted(confirmed)
        return report
    draft = t.build(env, values)
    if report:
        draft.notes = ["Prerequisites checked: " + "; ".join(
            f"{prereqs.STATUS_ICON[i.status]} {i.title}" for i in report.items)] + draft.notes
    return draft


def submit(owner: str, request: str, template: str, inputs: dict, conn, confirmed: set | None = None) -> dict:
    """Plan and, when complete, save the script. Returns {'questions': {...}} or {'script': saved}."""
    try:
        result = plan(template, inputs, conn, confirmed)
    except TemplateError:
        raise
    if isinstance(result, TaskQuestions):
        return {"questions": result.to_dict()}
    from core.prereqs import PrereqReport
    if isinstance(result, PrereqReport):
        return {"prerequisites": result.to_dict()}
    saved = scripts.save_draft(owner, request, result)
    audit.log_action(actor=owner, request=request, tool_name=f"template:{template}", tool_args=inputs,
                     risk=result.risk, approval="pending", status="pending",
                     result_summary=f"script #{saved['id']} saved for review: {saved['title']}")
    return {"script": saved}


def load_catalog() -> None:
    """Every recipe module registers itself in TEMPLATES when imported (core/catalog.py imports them all)."""
    import importlib
    importlib.import_module("core.catalog")


def must_ask_keys(template: str) -> set[str]:
    load_catalog()
    return {f.key for f in TEMPLATES[template].fields if f.must_ask}
