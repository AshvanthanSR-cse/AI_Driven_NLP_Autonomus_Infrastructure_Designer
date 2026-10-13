"""VPC recipes: every networking building block, inside an existing VPC (the vpc_network template creates a
whole VPC). One recipe, vpc_resource, with a 'resource' choice:

subnet, security group, security group rules, network ACL, route table, route, internet gateway, NAT gateway,
Elastic IP, VPC peering, VPC endpoint (gateway / interface), flow logs, transit gateway, egress-only internet
gateway (IPv6), IPv6 / secondary CIDR, DHCP options, site-to-site VPN, managed prefix list, and deletes.

Rules: SSH (22) is never opened to 0.0.0.0/0; CIDRs are checked for overlaps by code; every created resource
is tagged and has an undo action (teardown); billable resources show their price first.
"""
import ipaddress
import json
import re

from core import lookups, templates
from core.recipe_kit import (choice, cidr, ids, number, opts, pick, pick_many, region_options, static,
                             yes, yes_no, vpc_options)
from core.recipes import aws_step, role_steps, tag_dict, undo
from core.scripts import ScriptDraft
from core.templates import (FieldSpec, HOURS_PER_MONTH, NAT_HOURLY, NAT_PER_GB, PUBLIC_IPV4_HOURLY, Template,
                            TemplateError, _choice, _int, _tags)

TGW_ATTACH_HOUR, VPN_HOUR, ENDPOINT_AZ_HOUR = 0.05, 0.05, 0.01
RESOURCES = opts(
    ("subnet", "Subnet"), ("security_group", "Security group (firewall) with rules"),
    ("sg_rules", "Add or remove rules on an existing security group"), ("network_acl", "Network ACL (subnet firewall)"),
    ("route_table", "Route table (+ routes, + subnet associations)"), ("route", "Add a route to a route table"),
    ("internet_gateway", "Internet gateway"), ("nat_gateway", "NAT gateway (internet for private subnets)"),
    ("elastic_ip", "Elastic IP (allocate / associate / release)"), ("peering", "VPC peering (connect two VPCs)"),
    ("endpoint", "VPC endpoint (private access to S3, DynamoDB or other AWS services)"),
    ("flow_logs", "Flow logs (record network traffic)"), ("transit_gateway", "Transit gateway (hub for many VPCs)"),
    ("egress_igw", "Egress-only internet gateway (IPv6 outbound)"), ("cidr", "Add an IPv6 or secondary IPv4 range"),
    ("dhcp_options", "DHCP options (DNS servers, domain name)"), ("vpn", "Site-to-site VPN"),
    ("prefix_list", "Managed prefix list (named group of IP ranges)"), ("delete", "Delete a VPC resource"))
TARGET_PARAM = {"igw-": "GatewayId", "vgw-": "GatewayId", "nat-": "NatGatewayId", "pcx-": "VpcPeeringConnectionId",
                "tgw-": "TransitGatewayId", "vpce-": "VpcEndpointId", "eni-": "NetworkInterfaceId", "i-": "InstanceId",
                "eigw-": "EgressOnlyInternetGatewayId", "lgw-": "LocalGatewayId", "cagw-": "CarrierGatewayId"}
PROTOCOLS = {"tcp": "6", "udp": "17", "icmp": "1", "icmpv6": "58", "all": "-1", "-1": "-1"}


def _res(*names):
    return lambda i: i.get("resource") in names


def _vpc(env, inputs) -> dict:
    return next((v for v in lookups.vpcs(env) if v["id"] == inputs.get("vpc")), {})


def _vpc_cidrs(env, vpc_id: str) -> list[ipaddress.IPv4Network]:
    v = next((x for x in lookups.vpcs(env) if x["id"] == vpc_id), None)
    nets = [ipaddress.ip_network(v["cidr"])] if v and v.get("cidr") else []
    try:
        for a in env.ec2().describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0].get("CidrBlockAssociationSet", []):
            if a.get("CidrBlockState", {}).get("State") == "associated":
                nets.append(ipaddress.ip_network(a["CidrBlock"]))
    except Exception:
        pass
    return list(dict.fromkeys(nets))


def _free_subnet_default(env, inputs):
    vpc = inputs.get("vpc")
    if not vpc:
        return None
    used = [ipaddress.ip_network(s["cidr"]) for s in env.subnets() if s["vpc"] == vpc]
    for net in _vpc_cidrs(env, vpc):
        for cand in net.subnets(new_prefix=max(24, net.prefixlen)):
            if not any(cand.overlaps(u) for u in used):
                return str(cand)
    return None


def _validate_subnet_cidr(env, inputs, v) -> str:
    net = ipaddress.ip_network(cidr(v, "subnet range"))
    vpc = inputs.get("vpc")
    if not 16 <= net.prefixlen <= 28:
        raise ValueError("a subnet must be between /16 and /28")
    if not any(net.subnet_of(c) for c in _vpc_cidrs(env, vpc) if c.version == net.version):
        raise ValueError(f"{net} is not inside the VPC's range(s): {', '.join(map(str, _vpc_cidrs(env, vpc)))}")
    clash = [s["cidr"] for s in env.subnets() if s["vpc"] == vpc and ipaddress.ip_network(s["cidr"]).overlaps(net)]
    if clash:
        raise ValueError(f"{net} overlaps existing subnet(s) {', '.join(clash)}")
    return str(net)


def _rt_options(env, inputs):
    vpc = inputs.get("vpc")
    return [{"value": r["id"], "label": f"{r['id']} · {r['name'] or ('main' if r['main'] else '-')} · routes "
                                         f"{', '.join(x for x in r['routes'] if x)[:60]}"}
            for r in lookups.route_tables(env, vpc)]


def _rt_options_opt(env, inputs):
    return [{"value": "none", "label": "Keep the main route table"}] + _rt_options(env, inputs)


def _subnets_in_vpc(env, inputs):
    vpc = inputs.get("vpc")
    return [{"value": s["id"], "label": f"{s['id']} · {s['az']} · {s['cidr']} · {'public' if s['public'] else 'private'}"
                                         f"{' · ' + s['name'] if s['name'] else ''}"}
            for s in env.subnets() if not vpc or s["vpc"] == vpc]


def _sgs_in_vpc(env, inputs):
    return [{"value": g["id"], "label": f"{g['id']} · {g['name']}"} for g in env.security_groups(inputs.get("vpc"))]


def parse_sg_rules(text: str) -> list[dict]:
    """'tcp 443 0.0.0.0/0; tcp 8000-8100 10.0.0.0/16; tcp 5432 sg-0abc; all all 10.0.0.0/16; icmp all ::/0'
    -> IpPermissions."""
    perms = []
    for part in re.split(r"[;\n]+", str(text or "")):
        words = part.split()
        if not words:
            continue
        if len(words) < 3:
            raise ValueError(f"'{part.strip()}': use 'tcp 443 0.0.0.0/0' (protocol, port or range, source)")
        proto, ports, src = words[0].lower(), words[1].lower(), words[2]
        desc = " ".join(words[3:])[:200]
        if proto not in PROTOCOLS:
            raise ValueError(f"'{proto}' is not tcp, udp, icmp, icmpv6 or all")
        p = {"IpProtocol": PROTOCOLS[proto] if proto in ("all", "-1") else proto}
        if proto not in ("all", "-1"):
            if ports == "all":
                lo, hi = (0, 65535) if proto in ("tcp", "udp") else (-1, -1)
            elif re.fullmatch(r"\d{1,5}(-\d{1,5})?", ports):
                lo, hi = (int(x) for x in (ports.split("-") * 2)[:2])
                if not 0 <= lo <= hi <= 65535:
                    raise ValueError(f"bad port range '{ports}'")
            else:
                raise ValueError(f"'{ports}' is not a port, a range like 8000-8100, or 'all'")
            p.update({"FromPort": lo, "ToPort": hi})
        if src.startswith("sg-"):
            p["UserIdGroupPairs"] = [{"GroupId": src, **({"Description": desc} if desc else {})}]
        elif src.startswith("pl-"):
            p["PrefixListIds"] = [{"PrefixListId": src, **({"Description": desc} if desc else {})}]
        else:
            net = ipaddress.ip_network(src, strict=False)
            key, field = ("Ipv6Ranges", "CidrIpv6") if net.version == 6 else ("IpRanges", "CidrIp")
            p[key] = [{field: str(net), **({"Description": desc} if desc else {})}]
            covers_ssh = p["IpProtocol"] == "-1" or p.get("FromPort", 0) <= 22 <= p.get("ToPort", 0)
            if covers_ssh and net.prefixlen == 0:
                raise ValueError("SSH (22) may not be open to the whole internet; use your IP /32 or a narrower "
                                 "port range")
        perms.append(p)
    if not perms:
        raise ValueError("give at least one rule")
    return perms


def _validate_sg_rules(env, inputs, v) -> str:
    parse_sg_rules(v)
    return str(v).strip()


def parse_nacl_rules(text: str) -> list[dict]:
    """'100 allow tcp 80 0.0.0.0/0 in; 110 allow tcp 1024-65535 0.0.0.0/0 in; 100 allow all all 0.0.0.0/0 out'."""
    rules, seen = [], set()
    for part in re.split(r"[;\n]+", str(text or "")):
        w = part.split()
        if not w:
            continue
        if len(w) != 6:
            raise ValueError(f"'{part.strip()}': use 'RULE# allow|deny PROTOCOL PORTS CIDR in|out'")
        num, action, proto, ports, src, direction = w
        if not num.isdigit() or not 1 <= int(num) <= 32766:
            raise ValueError(f"rule number {num} must be 1..32766")
        if action.lower() not in ("allow", "deny") or direction.lower() not in ("in", "out"):
            raise ValueError(f"'{part.strip()}': action allow/deny, direction in/out")
        if proto.lower() not in PROTOCOLS:
            raise ValueError(f"'{proto}' is not tcp, udp, icmp or all")
        key = (int(num), direction.lower())
        if key in seen:
            raise ValueError(f"rule {num} {direction} is used twice")
        seen.add(key)
        net = ipaddress.ip_network(src, strict=False)
        e = {"RuleNumber": int(num), "Protocol": PROTOCOLS[proto.lower()], "RuleAction": action.lower(),
             "Egress": direction.lower() == "out", ("Ipv6CidrBlock" if net.version == 6 else "CidrBlock"): str(net)}
        if proto.lower() in ("tcp", "udp"):
            lo, hi = (0, 65535) if ports == "all" else (int(x) for x in (ports.split("-") * 2)[:2])
            e["PortRange"] = {"From": lo, "To": hi}
        elif proto.lower() in ("icmp", "icmpv6"):
            e["IcmpTypeCode"] = {"Type": -1, "Code": -1}
        rules.append(e)
    if not rules:
        raise ValueError("give at least one rule")
    return rules


def _validate_nacl_rules(env, inputs, v) -> str:
    parse_nacl_rules(v)
    return str(v).strip()


def route_params(dest: str, target: str) -> dict:
    out = {}
    if dest.startswith("pl-"):
        out["DestinationPrefixListId"] = dest
    else:
        net = ipaddress.ip_network(dest, strict=False)
        out["DestinationIpv6CidrBlock" if net.version == 6 else "DestinationCidrBlock"] = str(net)
    key = next((v for k, v in TARGET_PARAM.items() if target.startswith(k)), None)
    if not key:
        raise ValueError(f"'{target}' is not a route target (igw-, nat-, pcx-, tgw-, vgw-, eni-, i-, vpce-, eigw-)")
    out[key] = target
    return out


def parse_routes(text: str) -> list[dict]:
    routes = []
    for part in re.split(r"[;\n]+", str(text or "")):
        part = part.strip()
        if not part:
            continue
        m = re.fullmatch(r"(\S+)\s*(?:->|=>|via|to)\s*(\S+)", part)
        if not m:
            raise ValueError(f"'{part}': use 'DESTINATION -> TARGET', e.g. 0.0.0.0/0 -> igw-0abc")
        try:
            routes.append(route_params(m.group(1), m.group(2)))
        except ValueError as e:
            raise ValueError(str(e)) from None
    return routes


def _validate_routes(env, inputs, v) -> str:
    if str(v or "").strip():
        parse_routes(v)
    return str(v or "").strip()


def _validate_route_dest(env, inputs, v) -> str:
    v = str(v).strip()
    if v.startswith("pl-"):
        return v
    return cidr(v, "destination")


def _target_options(env, inputs):
    vpc = inputs.get("vpc") or next((r["vpc"] for r in lookups.route_tables(env) if r["id"] == inputs.get("route_table")), None)
    out = [{"value": g["id"], "label": f"{g['id']} · internet gateway"} for g in lookups.internet_gateways(env)
           if vpc in g["vpcs"]]
    out += [{"value": n["id"], "label": f"{n['id']} · NAT gateway"} for n in lookups.nat_gateways(env) if n["vpc"] == vpc]
    out += [{"value": p["id"], "label": f"{p['id']} · peering {p['requester']} <-> {p['accepter']}"}
            for p in lookups.peering_connections(env) if p["status"] == "active" and vpc in (p["requester"], p["accepter"])]
    out += [{"value": t["id"], "label": f"{t['id']} · transit gateway"} for t in lookups.transit_gateways(env)]
    return out


def _validate_target(env, inputs, v) -> str:
    v = str(v).strip()
    route_params("0.0.0.0/0", v)
    return v


def _eip_options(env, inputs):
    return [{"value": e["id"], "label": f"{e['ip']} · {e['id']} · {e['instance'] or 'not associated'}"}
            for e in lookups.elastic_ips(env)]


def _instances_in_vpc(env, inputs):
    vpc = inputs.get("vpc")
    return [{"value": i["id"], "label": f"{i['id']} · {i['name'] or '-'} · {i['state']}"}
            for i in lookups.all_instances(env) if not vpc or i["vpc"] == vpc]


def _peer_vpc_options(env, inputs):
    region = inputs.get("peer_region") or env.region_name
    if region == env.region_name:
        return [o for o in vpc_options(env, inputs) if o["value"] != inputs.get("vpc")]
    ec2 = env.conn.client("ec2", "read", region)
    return [{"value": v["VpcId"], "label": f"{v['VpcId']} · {v.get('CidrBlock', '')} · {templates._name(v)}"}
            for v in ec2.describe_vpcs()["Vpcs"]]


def _peer_cidr(env, inputs) -> str:
    region = inputs.get("peer_region") or env.region_name
    if region == env.region_name:
        return next((v["cidr"] for v in lookups.vpcs(env) if v["id"] == inputs.get("peer_vpc")), "")
    ec2 = env.conn.client("ec2", "read", region)
    vs = ec2.describe_vpcs(VpcIds=[inputs["peer_vpc"]])["Vpcs"]
    return vs[0].get("CidrBlock", "") if vs else ""


def _validate_peer(env, inputs, v):
    v = _choice(_peer_vpc_options(env, inputs), v, "VPC")
    mine, theirs = _vpc(env, inputs).get("cidr"), _peer_cidr(env, {**inputs, "peer_vpc": v})
    if mine and theirs and ipaddress.ip_network(mine).overlaps(ipaddress.ip_network(theirs)):
        raise ValueError(f"the VPC ranges overlap ({mine} and {theirs}); peering needs different ranges")
    return v


def _peer_rt_options(env, inputs):
    region = inputs.get("peer_region") or env.region_name
    if region == env.region_name:
        return [{"value": r["id"], "label": f"{r['id']} · {r['name'] or ('main' if r['main'] else '-')}"}
                for r in lookups.route_tables(env, inputs.get("peer_vpc"))]
    ec2 = env.conn.client("ec2", "read", region)
    return [{"value": r["RouteTableId"], "label": r["RouteTableId"]} for r in ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [inputs.get("peer_vpc", "")]}])["RouteTables"]]


GATEWAY_ENDPOINTS = ("s3", "dynamodb")


def _endpoint_service_options(env, inputs):
    region = env.region_name
    out = [{"value": s, "label": f"{s} (gateway endpoint, free)"} for s in GATEWAY_ENDPOINTS]
    for name in lookups.endpoint_services(env):
        short = name.replace(f"com.amazonaws.{region}.", "")
        if name.startswith(f"com.amazonaws.{region}.") and short not in GATEWAY_ENDPOINTS:
            out.append({"value": short, "label": f"{short} (interface endpoint, ~${ENDPOINT_AZ_HOUR}/hour per zone)"})
    return out


def _validate_endpoint_service(env, inputs, v) -> str:
    v = str(v).strip().replace(f"com.amazonaws.{env.region_name}.", "")
    if v in GATEWAY_ENDPOINTS:
        return v
    return _choice(_endpoint_service_options(env, inputs), v, "endpoint service")


def _gateway_endpoint(i) -> bool:
    return i.get("endpoint_service") in GATEWAY_ENDPOINTS and i.get("endpoint_type", "gateway") == "gateway"


def _deletable_options(env, inputs):
    vpc = inputs.get("vpc")
    out = []
    out += [{"value": f"subnet:{s['id']}", "label": f"Subnet {s['id']} · {s['cidr']} · {s['name'] or '-'}"}
            for s in env.subnets() if s["vpc"] == vpc]
    out += [{"value": f"sg:{g['id']}", "label": f"Security group {g['id']} · {g['name']}"}
            for g in env.security_groups(vpc) if g["name"] != "default"]
    out += [{"value": f"rtb:{r['id']}", "label": f"Route table {r['id']} · {r['name'] or '-'}"}
            for r in lookups.route_tables(env, vpc) if not r["main"]]
    out += [{"value": f"acl:{a['id']}", "label": f"Network ACL {a['id']} · {a['name'] or '-'}"}
            for a in lookups.network_acls(env, vpc) if not a["default"]]
    out += [{"value": f"igw:{g['id']}", "label": f"Internet gateway {g['id']} (detach + delete)"}
            for g in lookups.internet_gateways(env) if vpc in g["vpcs"]]
    out += [{"value": f"nat:{n['id']}", "label": f"NAT gateway {n['id']} · {n['name'] or '-'}"}
            for n in lookups.nat_gateways(env) if n["vpc"] == vpc]
    out += [{"value": f"pcx:{p['id']}", "label": f"Peering {p['id']} ({p['status']})"}
            for p in lookups.peering_connections(env) if vpc in (p["requester"], p["accepter"])
            and p["status"] not in ("deleted", "rejected")]
    out += [{"value": f"eip:{e['id']}", "label": f"Elastic IP {e['ip']} (release)"} for e in lookups.elastic_ips(env)
            if not e["association"]]
    out.append({"value": f"vpc:{vpc}", "label": f"The VPC {vpc} itself (only when it is empty)"})
    return out


def _validate_name(env, inputs, v) -> str:
    v = str(v).strip()
    if not re.fullmatch(r"[\w .:/=+@-]{1,128}", v):
        raise ValueError("letters, numbers, space and _ . : / = + - @ (max 128)")
    return v


def _validate_asn(env, inputs, v) -> int:
    n = _int(v, 1, 4294967294, "ASN")
    return n


def _validate_public_ip(env, inputs, v) -> str:
    try:
        ip = ipaddress.ip_address(str(v).strip())
    except ValueError:
        raise ValueError("the public IPv4 address of your router / firewall") from None
    if ip.version != 4 or ip.is_private:
        raise ValueError("must be a public IPv4 address")
    return str(ip)


def _validate_cidr_list(env, inputs, v) -> list[str]:
    out = [cidr(x, "range") for x in ids(v)]
    if not out:
        raise ValueError("give at least one IP range")
    return out


def _validate_dns(env, inputs, v) -> list[str]:
    out = []
    for x in ids(v):
        if x == "AmazonProvidedDNS":
            out.append(x)
            continue
        try:
            out.append(str(ipaddress.ip_address(x)))
        except ValueError:
            raise ValueError(f"'{x}' is not an IP address or AmazonProvidedDNS") from None
    if not 1 <= len(out) <= 4:
        raise ValueError("1 to 4 DNS servers")
    return out


def _secondary_cidr(env, inputs, v) -> str:
    net = ipaddress.ip_network(cidr(v, "range"))
    if net.version != 4 or not 16 <= net.prefixlen <= 28:
        raise ValueError("an IPv4 range between /16 and /28")
    for c in _vpc_cidrs(env, inputs.get("vpc")):
        if c.version == 4 and c.overlaps(net):
            raise ValueError(f"{net} overlaps the VPC range {c}")
    return str(net)


def _net_notes(v: dict) -> list[str]:
    r = v.get("resource")
    if r == "nat_gateway":
        h = NAT_HOURLY + PUBLIC_IPV4_HOURLY
        return [f"COST: NAT gateway ~${h:.3f}/hour (~${h * HOURS_PER_MONTH:.0f}/month) + ${NAT_PER_GB}/GB processed, "
                "even when idle; over a $5 budget in ~4 days. Approximate us-east-1 prices; run the teardown."]
    if r == "elastic_ip":
        return [f"COST: every public IPv4 address costs ~${PUBLIC_IPV4_HOURLY}/hour (~$3.6/month), attached or not."]
    if r == "transit_gateway":
        n = len(v.get("tgw_vpcs", [])) or 2
        return [f"COST: ~${TGW_ATTACH_HOUR}/hour per VPC attachment ({n} = ~${n * TGW_ATTACH_HOUR * HOURS_PER_MONTH:.0f}"
                "/month) + $0.02/GB processed. Approximate prices; run the teardown when done."]
    if r == "vpn":
        return [f"COST: site-to-site VPN ~${VPN_HOUR}/hour (~${VPN_HOUR * HOURS_PER_MONTH:.0f}/month) + data transfer.",
                "Download the configuration for your router from the VPC console (Site-to-Site VPN > Download "
                "configuration); it contains the pre-shared keys, so Kintsugi never reads it."]
    if r == "endpoint":
        if _gateway_endpoint(v):
            return ["COST: gateway endpoints (S3, DynamoDB) are free and save NAT data charges."]
        n = len(v.get("subnets") or []) or 1
        return [f"COST: interface endpoint ~${ENDPOINT_AZ_HOUR}/hour per zone ({n} zone(s) = "
                f"~${n * ENDPOINT_AZ_HOUR * HOURS_PER_MONTH:.0f}/month) + $0.01/GB."]
    if r == "flow_logs":
        return ["COST: flow logs are billed as CloudWatch Logs / S3 data (~$0.50/GB ingested to CloudWatch)."]
    if r == "peering":
        return ["COST: peering is free; traffic across zones or regions is billed per GB."]
    if r == "delete":
        return ["Deleting fails if something still uses the resource (for example instances in a subnet); AWS "
                "then says what is in the way."]
    return ["COST: this VPC resource is free."]


def _build_net(env, v) -> ScriptDraft:
    r = v["resource"]
    vpc = v.get("vpc")
    name = v.get("name") or f"kintsugi-{r.replace('_', '-')}"
    steps: list[dict] = []
    title = f"{dict((o['value'], o['label']) for o in RESOURCES)[r].split(' (')[0]} in {vpc or env.region_name}"
    if r == "subnet":
        sid = "{{sub.Subnet.SubnetId}}"
        steps.append(aws_step("ec2", "create_subnet", {"VpcId": vpc, "CidrBlock": v["cidr"], "AvailabilityZone": v["az"],
                                                       "TagSpecifications": _tags("subnet", name)},
                              f"Create subnet {name} ({v['cidr']}, {v['az']})", save_as="sub",
                              undo=undo("ec2", "delete_subnet", {"SubnetId": sid}, f"Delete subnet {v['cidr']}")))
        if yes(v, "public"):
            steps.append(aws_step("ec2", "modify_subnet_attribute", {"SubnetId": sid, "MapPublicIpOnLaunch": {"Value": True}},
                                  "Give instances in it a public IP automatically"))
        if v.get("route_table", "none") != "none":
            steps.append(aws_step("ec2", "associate_route_table", {"RouteTableId": v["route_table"], "SubnetId": sid},
                                  f"Associate it with route table {v['route_table']}", save_as="assoc",
                                  undo=undo("ec2", "disassociate_route_table",
                                            {"AssociationId": "{{assoc.AssociationId}}"}, "Disassociate the route table")))
    elif r == "security_group":
        steps.append(aws_step("ec2", "create_security_group",
                              {"GroupName": name, "Description": v.get("description") or f"Kintsugi {name}",
                               "VpcId": vpc, "TagSpecifications": _tags("security-group", name)},
                              f"Create security group {name}", save_as="sg",
                              undo=undo("ec2", "delete_security_group", {"GroupId": "{{sg.GroupId}}"},
                                        f"Delete security group {name}")))
        perms = parse_sg_rules(v["rules"])
        steps.append(aws_step("ec2", "authorize_security_group_ingress", {"GroupId": "{{sg.GroupId}}", "IpPermissions": perms},
                              f"Inbound rules: {v['rules']}"))
        title = f"Security group {name}"
    elif r == "sg_rules":
        perms = parse_sg_rules(v["rules"])
        egress = v.get("direction") == "egress"
        add_op = "authorize_security_group_egress" if egress else "authorize_security_group_ingress"
        rm_op = "revoke_security_group_egress" if egress else "revoke_security_group_ingress"
        if v.get("rule_action", "add") == "add":
            steps.append(aws_step("ec2", add_op, {"GroupId": v["security_group"], "IpPermissions": perms},
                                  f"Add {'outbound' if egress else 'inbound'} rules to {v['security_group']}: {v['rules']}",
                                  undo=undo("ec2", rm_op, {"GroupId": v["security_group"], "IpPermissions": perms},
                                            "Remove the added rules")))
        else:
            steps.append(aws_step("ec2", rm_op, {"GroupId": v["security_group"], "IpPermissions": perms},
                                  f"Remove {'outbound' if egress else 'inbound'} rules from {v['security_group']}: "
                                  f"{v['rules']}",
                                  undo=undo("ec2", add_op, {"GroupId": v["security_group"], "IpPermissions": perms},
                                            "Add the rules back")))
        title = f"Rules of {v['security_group']}"
    elif r == "network_acl":
        acl = "{{acl.NetworkAcl.NetworkAclId}}"
        steps.append(aws_step("ec2", "create_network_acl", {"VpcId": vpc, "TagSpecifications": _tags("network-acl", name)},
                              f"Create network ACL {name}", save_as="acl",
                              undo=undo("ec2", "delete_network_acl", {"NetworkAclId": acl}, f"Delete network ACL {name}")))
        for e in parse_nacl_rules(v["nacl_rules"]):
            d = "out" if e["Egress"] else "in"
            steps.append(aws_step("ec2", "create_network_acl_entry", {"NetworkAclId": acl, **e},
                                  f"Rule {e['RuleNumber']} {d}: {e['RuleAction']} protocol {e['Protocol']} "
                                  f"{e.get('CidrBlock') or e.get('Ipv6CidrBlock')}"))
        acls = lookups.network_acls(env, vpc)
        default = next((a["id"] for a in acls if a["default"]), None)
        for n, sid in enumerate(v.get("subnets") or [], 1):
            cur = next((a["associations"][sid] for a in acls if sid in a["associations"]), None)
            if not cur:
                raise TemplateError(f"could not find the current network ACL of {sid}")
            key = f"aclassoc{n}"
            steps.append(aws_step("ec2", "replace_network_acl_association", {"AssociationId": cur, "NetworkAclId": acl},
                                  f"Use the new ACL for subnet {sid}", save_as=key,
                                  undo=undo("ec2", "replace_network_acl_association",
                                            {"AssociationId": "{{" + key + ".NewAssociationId}}", "NetworkAclId": default},
                                            f"Put subnet {sid} back on the default ACL") if default else None))
        title = f"Network ACL {name}"
    elif r == "route_table":
        rt = "{{rt.RouteTable.RouteTableId}}"
        steps.append(aws_step("ec2", "create_route_table", {"VpcId": vpc, "TagSpecifications": _tags("route-table", name)},
                              f"Create route table {name}", save_as="rt",
                              undo=undo("ec2", "delete_route_table", {"RouteTableId": rt}, f"Delete route table {name}")))
        for rp in parse_routes(v.get("routes", "")):
            dest = next(val for k, val in rp.items() if k.startswith("Destination"))
            steps.append(aws_step("ec2", "create_route", {"RouteTableId": rt, **rp}, f"Route {dest} -> "
                                                                                     f"{[x for x in rp.values()][-1]}"))
        for n, sid in enumerate(v.get("subnets") or [], 1):
            key = f"rtassoc{n}"
            steps.append(aws_step("ec2", "associate_route_table", {"RouteTableId": rt, "SubnetId": sid},
                                  f"Associate with subnet {sid}", save_as=key,
                                  undo=undo("ec2", "disassociate_route_table", {"AssociationId": "{{" + key + ".AssociationId}}"},
                                            f"Disassociate subnet {sid}")))
        title = f"Route table {name}"
    elif r == "route":
        rp = route_params(v["destination"], v["target"])
        existing = next((x for x in lookups.route_tables(env) if x["id"] == v["route_table"]), {})
        op = "replace_route" if v["destination"] in existing.get("routes", []) else "create_route"
        dest_key = next(k for k in rp if k.startswith("Destination"))
        steps.append(aws_step("ec2", op, {"RouteTableId": v["route_table"], **rp},
                              f"{'Replace' if op == 'replace_route' else 'Add'} route {v['destination']} -> {v['target']} "
                              f"in {v['route_table']}",
                              undo=undo("ec2", "delete_route", {"RouteTableId": v["route_table"], dest_key: rp[dest_key]},
                                        f"Delete route {v['destination']}") if op == "create_route" else None))
        title = f"Route {v['destination']} -> {v['target']}"
    elif r == "internet_gateway":
        igw = "{{igw.InternetGateway.InternetGatewayId}}"
        steps += [aws_step("ec2", "create_internet_gateway", {"TagSpecifications": _tags("internet-gateway", name)},
                           f"Create internet gateway {name}", save_as="igw",
                           undo=undo("ec2", "delete_internet_gateway", {"InternetGatewayId": igw}, "Delete the internet gateway")),
                  aws_step("ec2", "attach_internet_gateway", {"InternetGatewayId": igw, "VpcId": vpc}, f"Attach it to {vpc}",
                           undo=undo("ec2", "detach_internet_gateway", {"InternetGatewayId": igw, "VpcId": vpc},
                                     "Detach the internet gateway"))]
        for rt in v.get("route_tables") or []:
            steps.append(aws_step("ec2", "create_route", {"RouteTableId": rt, "DestinationCidrBlock": "0.0.0.0/0",
                                                          "GatewayId": igw},
                                  f"Route 0.0.0.0/0 in {rt} to the internet gateway (makes its subnets public)",
                                  undo=undo("ec2", "delete_route", {"RouteTableId": rt, "DestinationCidrBlock": "0.0.0.0/0"},
                                            f"Delete the internet route from {rt}")))
    elif r == "nat_gateway":
        nat = "{{nat.NatGateway.NatGatewayId}}"
        private = v.get("connectivity", "public") == "private"
        if not private:
            steps.append(aws_step("ec2", "allocate_address", {"Domain": "vpc", "TagSpecifications": _tags("elastic-ip", f"{name}-eip")},
                                  "Allocate an Elastic IP for the NAT gateway", save_as="eip",
                                  undo=undo("ec2", "release_address", {"AllocationId": "{{eip.AllocationId}}"},
                                            "Release the Elastic IP")))
        p = {"SubnetId": v["nat_subnet"], "ConnectivityType": "private" if private else "public",
             "TagSpecifications": _tags("natgateway", name)}
        if not private:
            p["AllocationId"] = "{{eip.AllocationId}}"
        steps.append(aws_step("ec2", "create_nat_gateway", p, f"Create {'private ' if private else ''}NAT gateway in "
                                                              f"{v['nat_subnet']} (waits until available)", save_as="nat",
                              wait={"waiter": "nat_gateway_available", "params": {"NatGatewayIds": [nat]}},
                              undo=undo("ec2", "delete_nat_gateway", {"NatGatewayId": nat}, "Delete the NAT gateway (waits)",
                                        wait={"waiter": "nat_gateway_deleted", "params": {"NatGatewayIds": [nat]}})))
        for rt in v.get("route_tables") or []:
            has = "0.0.0.0/0" in next((x["routes"] for x in lookups.route_tables(env) if x["id"] == rt), [])
            steps.append(aws_step("ec2", "replace_route" if has else "create_route",
                                  {"RouteTableId": rt, "DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": nat},
                                  f"Send internet traffic from {rt} through the NAT gateway",
                                  undo=None if has else undo("ec2", "delete_route",
                                                             {"RouteTableId": rt, "DestinationCidrBlock": "0.0.0.0/0"},
                                                             f"Delete the NAT route from {rt}")))
    elif r == "elastic_ip":
        a = v.get("eip_action", "allocate")
        if a == "allocate":
            steps.append(aws_step("ec2", "allocate_address", {"Domain": "vpc", "TagSpecifications": _tags("elastic-ip", name)},
                                  f"Allocate Elastic IP {name}", save_as="eip",
                                  undo=undo("ec2", "release_address", {"AllocationId": "{{eip.AllocationId}}"},
                                            "Release the Elastic IP")))
            if v.get("instance", "none") != "none":
                steps.append(aws_step("ec2", "associate_address", {"AllocationId": "{{eip.AllocationId}}",
                                                                   "InstanceId": v["instance"]},
                                      f"Attach it to {v['instance']}", save_as="eipassoc",
                                      undo=undo("ec2", "disassociate_address",
                                                {"AssociationId": "{{eipassoc.AssociationId}}"}, "Detach the Elastic IP")))
        elif a == "associate":
            steps.append(aws_step("ec2", "associate_address", {"AllocationId": v["eip"], "InstanceId": v["instance"]},
                                  f"Attach {v['eip']} to {v['instance']}", save_as="eipassoc",
                                  undo=undo("ec2", "disassociate_address", {"AssociationId": "{{eipassoc.AssociationId}}"},
                                            "Detach the Elastic IP")))
        elif a == "disassociate":
            e = next(x for x in lookups.elastic_ips(env) if x["id"] == v["eip"])
            steps.append(aws_step("ec2", "disassociate_address", {"AssociationId": e["association"]},
                                  f"Detach {e['ip']} from {e['instance']}"))
        else:
            steps.append(aws_step("ec2", "release_address", {"AllocationId": v["eip"]}, f"Release {v['eip']}"))
        title = f"Elastic IP ({a})"
    elif r == "peering":
        region = v.get("peer_region") or env.region_name
        pcx = "{{pcx.VpcPeeringConnection.VpcPeeringConnectionId}}"
        p = {"VpcId": vpc, "PeerVpcId": v["peer_vpc"], "TagSpecifications": _tags("vpc-peering-connection", name)}
        if region != env.region_name:
            p["PeerRegion"] = region
        steps.append(aws_step("ec2", "create_vpc_peering_connection", p,
                              f"Request peering {vpc} <-> {v['peer_vpc']}" + (f" ({region})" if region != env.region_name else ""),
                              save_as="pcx", undo=undo("ec2", "delete_vpc_peering_connection",
                                                       {"VpcPeeringConnectionId": pcx}, "Delete the peering connection")))
        steps.append({"kind": "wait_until", "service": "ec2", "operation": "describe_vpc_peering_connections",
                      "params": {"VpcPeeringConnectionIds": [pcx]}, "path": "VpcPeeringConnections.0.Status.Code",
                      "equals": ["pending-acceptance", "active"], "region": region,
                      "description": "Wait until the request reaches the other VPC", "timeout": 600})
        steps.append(aws_step("ec2", "accept_vpc_peering_connection", {"VpcPeeringConnectionId": pcx},
                              "Accept the peering (same account)", region=region))
        mine, theirs = _vpc(env, v).get("cidr"), _peer_cidr(env, v)
        for rt in v.get("route_tables") or []:
            steps.append(aws_step("ec2", "create_route", {"RouteTableId": rt, "DestinationCidrBlock": theirs,
                                                          "VpcPeeringConnectionId": pcx},
                                  f"Route {theirs} in {rt} through the peering",
                                  undo=undo("ec2", "delete_route", {"RouteTableId": rt, "DestinationCidrBlock": theirs},
                                            f"Delete the peering route from {rt}")))
        for rt in v.get("peer_route_tables") or []:
            steps.append(aws_step("ec2", "create_route", {"RouteTableId": rt, "DestinationCidrBlock": mine,
                                                          "VpcPeeringConnectionId": pcx},
                                  f"Route {mine} in {rt} (other VPC) through the peering", region=region,
                                  undo=undo("ec2", "delete_route", {"RouteTableId": rt, "DestinationCidrBlock": mine},
                                            f"Delete the peering route from {rt}")))
        title = f"VPC peering {vpc} <-> {v['peer_vpc']}"
    elif r == "endpoint":
        svc = v["endpoint_service"]
        p = {"VpcId": vpc, "ServiceName": f"com.amazonaws.{env.region_name}.{svc}",
             "TagSpecifications": _tags("vpc-endpoint", name)}
        if _gateway_endpoint(v):
            p.update({"VpcEndpointType": "Gateway", "RouteTableIds": v.get("route_tables") or []})
            what = f"gateway endpoint for {svc} on {len(p['RouteTableIds'])} route table(s)"
        else:
            p.update({"VpcEndpointType": "Interface", "SubnetIds": v["subnets"], "PrivateDnsEnabled": yes(v, "private_dns")})
            if v.get("security_groups"):
                p["SecurityGroupIds"] = v["security_groups"]
            what = f"interface endpoint for {svc} in {len(v['subnets'])} subnet(s)"
        steps.append(aws_step("ec2", "create_vpc_endpoint", p, f"Create {what}", save_as="vpce",
                              undo=undo("ec2", "delete_vpc_endpoints", {"VpcEndpointIds": ["{{vpce.VpcEndpoint.VpcEndpointId}}"]},
                                        "Delete the endpoint")))
        title = f"VPC endpoint for {svc}"
    elif r == "flow_logs":
        target = v.get("flow_target") or vpc
        rtype = "Subnet" if target.startswith("subnet-") else ("NetworkInterface" if target.startswith("eni-") else "VPC")
        p = {"ResourceIds": [target], "ResourceType": rtype, "TrafficType": v.get("traffic", "ALL"),
             "TagSpecifications": _tags("vpc-flow-log", name)}
        if v.get("destination", "cloudwatch") == "cloudwatch":
            group = f"/vpc/flowlogs/{target}"
            role = f"{name}-flowlogs"[:64]
            steps.append(aws_step("logs", "create_log_group", {"logGroupName": group, "tags": tag_dict(name)},
                                  f"Create log group {group}",
                                  undo=undo("logs", "delete_log_group", {"logGroupName": group}, "Delete the log group")))
            steps.append(aws_step("logs", "put_retention_policy", {"logGroupName": group,
                                                                   "retentionInDays": int(v.get("log_days", 14))},
                                  f"Keep flow logs {v.get('log_days', 14)} days"))
            steps += role_steps(role, "vpc-flow-logs.amazonaws.com", [], key="flrole", pause=1)
            doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": [
                "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"],
                "Resource": f"arn:aws:logs:{env.region_name}:{env.account_id()}:log-group:{group}:*"}]}
            steps.append(aws_step("iam", "put_role_policy", {"RoleName": role, "PolicyName": "write-flow-logs",
                                                             "PolicyDocument": json.dumps(doc)},
                                  "Allow flow logs to write ONLY to that log group",
                                  undo=undo("iam", "delete_role_policy", {"RoleName": role, "PolicyName": "write-flow-logs"},
                                            "Remove the flow logs policy"), pause_after=15))
            p.update({"LogDestinationType": "cloud-watch-logs", "LogGroupName": group,
                      "DeliverLogsPermissionArn": "{{flrole.Role.Arn}}"})
        else:
            p.update({"LogDestinationType": "s3", "LogDestination": f"arn:aws:s3:::{v['log_bucket']}/flowlogs/"})
        steps.append(aws_step("ec2", "create_flow_logs", p, f"Record {p['TrafficType']} traffic of {target}",
                              save_as="fl", undo=undo("ec2", "delete_flow_logs", {"FlowLogIds": ["{{fl.FlowLogIds.0}}"]},
                                                      "Delete the flow log")))
        title = f"Flow logs for {target}"
    elif r == "transit_gateway":
        tgw = "{{tgw.TransitGateway.TransitGatewayId}}"
        steps.append(aws_step("ec2", "create_transit_gateway",
                              {"Description": f"Kintsugi {name}", "TagSpecifications": _tags("transit-gateway", name),
                               "Options": {"AmazonSideAsn": int(v.get("asn", 64512)), "DefaultRouteTableAssociation": "enable",
                                           "DefaultRouteTablePropagation": "enable", "DnsSupport": "enable"}},
                              f"Create transit gateway {name}", save_as="tgw",
                              undo=undo("ec2", "delete_transit_gateway", {"TransitGatewayId": tgw},
                                        "Delete the transit gateway")))
        steps.append({"kind": "wait_until", "service": "ec2", "operation": "describe_transit_gateways",
                      "params": {"TransitGatewayIds": [tgw]}, "path": "TransitGateways.0.State", "equals": ["available"],
                      "description": "Wait until the transit gateway is available (a few minutes)", "timeout": 1200})
        cidrs = {}
        for n, vid in enumerate(v["tgw_vpcs"], 1):
            subs, seen = [], set()
            for s in env.subnets():
                if s["vpc"] == vid and s["az"] not in seen:
                    subs.append(s["id"])
                    seen.add(s["az"])
            if not subs:
                raise TemplateError(f"{vid} has no subnets to attach")
            key = f"tgwatt{n}"
            att = "{{" + key + ".TransitGatewayVpcAttachment.TransitGatewayAttachmentId}}"
            steps.append(aws_step("ec2", "create_transit_gateway_vpc_attachment",
                                  {"TransitGatewayId": tgw, "VpcId": vid, "SubnetIds": subs,
                                   "TagSpecifications": _tags("transit-gateway-attachment", f"{name}-{vid}")},
                                  f"Attach {vid} ({len(subs)} zone(s))", save_as=key,
                                  undo=undo("ec2", "delete_transit_gateway_vpc_attachment",
                                            {"TransitGatewayAttachmentId": att}, f"Detach {vid}")))
            steps.append({"kind": "wait_until", "service": "ec2", "operation": "describe_transit_gateway_vpc_attachments",
                          "params": {"TransitGatewayAttachmentIds": [att]},
                          "path": "TransitGatewayVpcAttachments.0.State", "equals": ["available"],
                          "description": f"Wait until {vid} is attached", "timeout": 1200})
            cidrs[vid] = next((x["cidr"] for x in lookups.vpcs(env) if x["id"] == vid), "")
        for vid in v["tgw_vpcs"]:
            others = [c for o, c in cidrs.items() if o != vid and c]
            for rt in lookups.route_tables(env, vid):
                for c in others:
                    steps.append(aws_step("ec2", "create_route", {"RouteTableId": rt["id"], "DestinationCidrBlock": c,
                                                                  "TransitGatewayId": tgw},
                                          f"Route {c} in {rt['id']} ({vid}) via the transit gateway",
                                          undo=undo("ec2", "delete_route", {"RouteTableId": rt["id"],
                                                                            "DestinationCidrBlock": c},
                                                    f"Delete route {c} from {rt['id']}")))
        title = f"Transit gateway {name} for {len(v['tgw_vpcs'])} VPCs"
    elif r == "egress_igw":
        eigw = "{{eigw.EgressOnlyInternetGateway.EgressOnlyInternetGatewayId}}"
        steps.append(aws_step("ec2", "create_egress_only_internet_gateway",
                              {"VpcId": vpc, "TagSpecifications": _tags("egress-only-internet-gateway", name)},
                              "Create an egress-only internet gateway (IPv6 outbound only)", save_as="eigw",
                              undo=undo("ec2", "delete_egress_only_internet_gateway",
                                        {"EgressOnlyInternetGatewayId": eigw}, "Delete it")))
        for rt in v.get("route_tables") or []:
            steps.append(aws_step("ec2", "create_route", {"RouteTableId": rt, "DestinationIpv6CidrBlock": "::/0",
                                                          "EgressOnlyInternetGatewayId": eigw},
                                  f"Route ::/0 in {rt} through it",
                                  undo=undo("ec2", "delete_route", {"RouteTableId": rt, "DestinationIpv6CidrBlock": "::/0"},
                                            f"Delete the IPv6 route from {rt}")))
    elif r == "cidr":
        if v.get("cidr_kind", "ipv6") == "ipv6":
            steps.append(aws_step("ec2", "associate_vpc_cidr_block", {"VpcId": vpc, "AmazonProvidedIpv6CidrBlock": True},
                                  "Add an Amazon-provided IPv6 /56 range", save_as="cidr",
                                  undo=undo("ec2", "disassociate_vpc_cidr_block",
                                            {"AssociationId": "{{cidr.Ipv6CidrBlockAssociation.AssociationId}}"},
                                            "Remove the IPv6 range")))
        else:
            steps.append(aws_step("ec2", "associate_vpc_cidr_block", {"VpcId": vpc, "CidrBlock": v["secondary_cidr"]},
                                  f"Add secondary range {v['secondary_cidr']}", save_as="cidr",
                                  undo=undo("ec2", "disassociate_vpc_cidr_block",
                                            {"AssociationId": "{{cidr.CidrBlockAssociation.AssociationId}}"},
                                            "Remove the secondary range")))
    elif r == "dhcp_options":
        cfg = [{"Key": "domain-name-servers", "Values": v["dns_servers"]}]
        if v.get("domain_name"):
            cfg.append({"Key": "domain-name", "Values": [v["domain_name"]]})
        steps.append(aws_step("ec2", "create_dhcp_options", {"DhcpConfigurations": cfg,
                                                             "TagSpecifications": _tags("dhcp-options", name)},
                              f"Create DHCP options (DNS {', '.join(v['dns_servers'])})", save_as="dhcp",
                              undo=undo("ec2", "delete_dhcp_options", {"DhcpOptionsId": "{{dhcp.DhcpOptions.DhcpOptionsId}}"},
                                        "Delete the DHCP options")))
        steps.append(aws_step("ec2", "associate_dhcp_options", {"DhcpOptionsId": "{{dhcp.DhcpOptions.DhcpOptionsId}}",
                                                                "VpcId": vpc},
                              f"Use them in {vpc} (instances pick them up on renewal)",
                              undo=undo("ec2", "associate_dhcp_options", {"DhcpOptionsId": "default", "VpcId": vpc},
                                        "Go back to the default DHCP options")))
    elif r == "vpn":
        steps += [
            aws_step("ec2", "create_customer_gateway",
                     {"Type": "ipsec.1", "PublicIp": v["router_ip"], "BgpAsn": int(v.get("bgp_asn", 65000)),
                      "TagSpecifications": _tags("customer-gateway", f"{name}-cgw")},
                     f"Register your router {v['router_ip']} as a customer gateway", save_as="cgw",
                     undo=undo("ec2", "delete_customer_gateway", {"CustomerGatewayId": "{{cgw.CustomerGateway.CustomerGatewayId}}"},
                               "Delete the customer gateway")),
            aws_step("ec2", "create_vpn_gateway", {"Type": "ipsec.1", "TagSpecifications": _tags("vpn-gateway", f"{name}-vgw")},
                     "Create a virtual private gateway", save_as="vgw",
                     undo=undo("ec2", "delete_vpn_gateway", {"VpnGatewayId": "{{vgw.VpnGateway.VpnGatewayId}}"},
                               "Delete the virtual private gateway")),
            aws_step("ec2", "attach_vpn_gateway", {"VpnGatewayId": "{{vgw.VpnGateway.VpnGatewayId}}", "VpcId": vpc},
                     f"Attach it to {vpc}",
                     undo=undo("ec2", "detach_vpn_gateway", {"VpnGatewayId": "{{vgw.VpnGateway.VpnGatewayId}}", "VpcId": vpc},
                               "Detach the virtual private gateway", pause_after=60)),
            aws_step("ec2", "create_vpn_connection",
                     {"Type": "ipsec.1", "CustomerGatewayId": "{{cgw.CustomerGateway.CustomerGatewayId}}",
                      "VpnGatewayId": "{{vgw.VpnGateway.VpnGatewayId}}", "Options": {"StaticRoutesOnly": True},
                      "TagSpecifications": _tags("vpn-connection", name)},
                     "Create the VPN connection (2 tunnels; waits until available)", save_as="vpn",
                     wait={"waiter": "vpn_connection_available",
                           "params": {"VpnConnectionIds": ["{{vpn.VpnConnection.VpnConnectionId}}"]}},
                     undo=undo("ec2", "delete_vpn_connection", {"VpnConnectionId": "{{vpn.VpnConnection.VpnConnectionId}}"},
                               "Delete the VPN connection",
                               wait={"waiter": "vpn_connection_deleted",
                                     "params": {"VpnConnectionIds": ["{{vpn.VpnConnection.VpnConnectionId}}"]}})),
        ]
        for c in v["onprem_cidrs"]:
            steps.append(aws_step("ec2", "create_vpn_connection_route",
                                  {"VpnConnectionId": "{{vpn.VpnConnection.VpnConnectionId}}", "DestinationCidrBlock": c},
                                  f"Static route {c} to your network"))
        for rt in v.get("route_tables") or []:
            steps.append(aws_step("ec2", "enable_vgw_route_propagation",
                                  {"RouteTableId": rt, "GatewayId": "{{vgw.VpnGateway.VpnGatewayId}}"},
                                  f"Propagate VPN routes into {rt}",
                                  undo=undo("ec2", "disable_vgw_route_propagation",
                                            {"RouteTableId": rt, "GatewayId": "{{vgw.VpnGateway.VpnGatewayId}}"},
                                            f"Stop propagating VPN routes into {rt}")))
        title = f"Site-to-site VPN to {v['router_ip']}"
    elif r == "prefix_list":
        entries = [{"Cidr": c, "Description": "added by Kintsugi"} for c in v["entries"]]
        steps.append(aws_step("ec2", "create_managed_prefix_list",
                              {"PrefixListName": name, "MaxEntries": max(len(entries) + 5, 10),
                               "AddressFamily": "IPv6" if ":" in entries[0]["Cidr"] else "IPv4", "Entries": entries,
                               "TagSpecifications": _tags("prefix-list", name)},
                              f"Create prefix list {name} with {len(entries)} range(s)", save_as="pl",
                              undo=undo("ec2", "delete_managed_prefix_list", {"PrefixListId": "{{pl.PrefixList.PrefixListId}}"},
                                        "Delete the prefix list")))
        title = f"Prefix list {name}"
    else:
        kind, rid = v["target_resource"].split(":", 1)
        if kind == "igw":
            steps.append(aws_step("ec2", "detach_internet_gateway", {"InternetGatewayId": rid, "VpcId": vpc},
                                  f"Detach {rid} from {vpc}"))
        op = {"subnet": ("delete_subnet", {"SubnetId": rid}), "sg": ("delete_security_group", {"GroupId": rid}),
              "rtb": ("delete_route_table", {"RouteTableId": rid}), "acl": ("delete_network_acl", {"NetworkAclId": rid}),
              "igw": ("delete_internet_gateway", {"InternetGatewayId": rid}),
              "nat": ("delete_nat_gateway", {"NatGatewayId": rid}),
              "pcx": ("delete_vpc_peering_connection", {"VpcPeeringConnectionId": rid}),
              "eip": ("release_address", {"AllocationId": rid}), "vpc": ("delete_vpc", {"VpcId": rid})}[kind]
        wait = {"waiter": "nat_gateway_deleted", "params": {"NatGatewayIds": [rid]}} if kind == "nat" else None
        steps.append(aws_step("ec2", op[0], op[1], f"Delete {rid}", wait=wait))
        title = f"Delete {rid}"
    return ScriptDraft(title=title, steps=steps, notes=_net_notes(v))


NEEDS_VPC = ("subnet", "security_group", "network_acl", "route_table", "internet_gateway", "nat_gateway", "peering",
             "endpoint", "flow_logs", "egress_igw", "cidr", "dhcp_options", "vpn", "delete", "sg_rules", "elastic_ip")

VPC_RESOURCE = Template(
    name="vpc_resource",
    description="Any VPC building block in an existing VPC: subnet, security group (+rules), network ACL, route "
                "table/route, internet/NAT/egress-only gateway, Elastic IP, peering, endpoints, flow logs, transit "
                "gateway, IPv6/secondary CIDR, DHCP options, site-to-site VPN, prefix list, deletes",
    fields=[
        FieldSpec("resource", "Which VPC resource?", "choice", must_ask=True, options=static(RESOURCES),
                  validate=pick(static(RESOURCES), "VPC resource")),
        FieldSpec("vpc", "Which VPC?", "choice", must_ask=True, options=vpc_options, validate=pick(vpc_options, "VPC"),
                  default=lambda e, i: next((o["value"] for o in vpc_options(e, i)), None),
                  relevant=lambda i: i.get("resource") in NEEDS_VPC,
                  empty_hint="No VPC in this region. First ask: 'Create a VPC with 2 public and 2 private subnets'."),
        FieldSpec("name", "Name (Name tag)?", "text", default=lambda e, i: f"kintsugi-{str(i.get('resource', 'net')).replace('_', '-')}",
                  validate=_validate_name, relevant=lambda i: i.get("resource") not in ("sg_rules", "route", "delete")),
        FieldSpec("cidr", "IP range for the subnet?", "text", must_ask=True, default=_free_subnet_default,
                  validate=_validate_subnet_cidr, relevant=_res("subnet"),
                  why="Pre-filled with the next free /24 inside the VPC; code checks overlaps."),
        FieldSpec("az", "Availability zone?", "choice", must_ask=True,
                  options=lambda e, i: [{"value": z, "label": z} for z in e.availability_zones()],
                  default=lambda e, i: (e.availability_zones() or [None])[0],
                  validate=lambda e, i, v: _choice([{"value": z, "label": z} for z in e.availability_zones()], v, "zone"),
                  relevant=_res("subnet")),
        yes_no("public", "Give instances a public IP automatically (public subnet)?", relevant=_res("subnet")),
        FieldSpec("route_table", "Route table?", "choice", default="none",
                  options=lambda e, i: _rt_options_opt(e, i) if i.get("resource") == "subnet" else _rt_options(e, i),
                  validate=lambda e, i, v: _choice(_rt_options_opt(e, i) if i.get("resource") == "subnet"
                                                   else _rt_options(e, i), v, "route table"),
                  relevant=_res("subnet", "route"), why="A public subnet needs a route table with a route to an "
                                                        "internet gateway."),
        FieldSpec("description", "Description?", "text", default="Created by Kintsugi", relevant=_res("security_group")),
        FieldSpec("security_group", "Which security group?", "choice", must_ask=True, options=_sgs_in_vpc,
                  validate=pick(_sgs_in_vpc, "security group"), relevant=_res("sg_rules")),
        choice("rule_action", "Add or remove rules?", opts(("add", "Add"), ("remove", "Remove")), default="add",
               relevant=_res("sg_rules")),
        choice("direction", "Inbound or outbound?", opts(("ingress", "Inbound"), ("egress", "Outbound")),
               default="ingress", relevant=_res("sg_rules")),
        FieldSpec("rules", "Rules? ('tcp 443 0.0.0.0/0; tcp 22 203.0.113.5/32; tcp 5432 sg-0abc; all all 10.0.0.0/16')",
                  "text", must_ask=True,
                  default=lambda e, i: "tcp 443 0.0.0.0/0; tcp 80 0.0.0.0/0" + (
                      f"; tcp 22 {e.my_ip()}/32" if e.my_ip() else ""),
                  validate=_validate_sg_rules, relevant=_res("security_group", "sg_rules"),
                  why="protocol (tcp/udp/icmp/all), port or range, source (CIDR, sg-..., pl-...). SSH from 0.0.0.0/0 is "
                      "blocked."),
        FieldSpec("nacl_rules", "ACL rules? ('100 allow tcp 80 0.0.0.0/0 in; 110 allow tcp 1024-65535 0.0.0.0/0 in; "
                                "100 allow all all 0.0.0.0/0 out')", "text", must_ask=True,
                  default="100 allow tcp 80 0.0.0.0/0 in; 110 allow tcp 443 0.0.0.0/0 in; "
                          "120 allow tcp 1024-65535 0.0.0.0/0 in; 100 allow all all 0.0.0.0/0 out",
                  validate=_validate_nacl_rules, relevant=_res("network_acl"),
                  why="ACLs are stateless: allow the return ports (1024-65535) too. Lower numbers are checked first."),
        FieldSpec("subnets", "Which subnets?", "multichoice", must_ask=True, options=_subnets_in_vpc,
                  validate=lambda e, i, v: pick_many(_subnets_in_vpc, "subnets",
                                                     0 if i.get("resource") in ("network_acl", "route_table") else 1)(e, i, v),
                  allow_empty=True,
                  default=lambda e, i: [] if i.get("resource") in ("network_acl", "route_table") else
                  [o["value"] for o in _subnets_in_vpc(e, i)][:2],
                  relevant=lambda i: i.get("resource") in ("network_acl", "route_table")
                  or (i.get("resource") == "endpoint" and not _gateway_endpoint(i))),
        FieldSpec("routes", "Routes? (optional: '0.0.0.0/0 -> igw-0abc; 10.1.0.0/16 -> pcx-0def')", "text", default="",
                  allow_empty=True, validate=_validate_routes, relevant=_res("route_table")),
        FieldSpec("destination", "Destination range?", "text", must_ask=True, default="0.0.0.0/0",
                  validate=_validate_route_dest, relevant=_res("route")),
        FieldSpec("target", "Send it to which gateway / connection?", "choice", must_ask=True, options=_target_options,
                  validate=_validate_target, allow_custom=True, relevant=_res("route"),
                  why="Pick one, or type any target ID (eni-, i-, vgw-, vpce- ...)."),
        FieldSpec("nat_subnet", "Which PUBLIC subnet should the NAT gateway live in?", "choice", must_ask=True,
                  options=lambda e, i: [o for o in _subnets_in_vpc(e, i) if "public" in o["label"]]
                  if i.get("connectivity", "public") == "public" else _subnets_in_vpc(e, i),
                  validate=lambda e, i, v: _choice(_subnets_in_vpc(e, i), v, "subnet"), relevant=_res("nat_gateway")),
        choice("connectivity", "Public NAT (internet) or private NAT (other networks only)?",
               opts(("public", "Public (internet access for private subnets)"), ("private", "Private (no internet)")),
               default="public", relevant=_res("nat_gateway")),
        FieldSpec("route_tables", "Which route tables should use it?", "multichoice", default=[],
                  options=_rt_options, validate=pick_many(_rt_options, "route tables", 0),
                  relevant=lambda i: i.get("resource") in ("internet_gateway", "nat_gateway", "peering", "egress_igw",
                                                           "vpn") or (i.get("resource") == "endpoint" and _gateway_endpoint(i)),
                  allow_empty=True),
        choice("eip_action", "What should happen with the Elastic IP?",
               opts(("allocate", "Allocate a new one (optionally attach)"), ("associate", "Attach an existing one"),
                    ("disassociate", "Detach one"), ("release", "Release (give back) one")),
               default="allocate", relevant=_res("elastic_ip")),
        FieldSpec("eip", "Which Elastic IP?", "choice", must_ask=True, options=_eip_options,
                  validate=pick(_eip_options, "Elastic IP"),
                  relevant=lambda i: i.get("resource") == "elastic_ip" and i.get("eip_action") in ("associate",
                                                                                                   "disassociate", "release")),
        FieldSpec("instance", "Attach to which instance?", "choice",
                  default=lambda e, i: "none" if i.get("eip_action", "allocate") == "allocate" else None,
                  options=lambda e, i: ([{"value": "none", "label": "Do not attach now"}]
                                        if i.get("eip_action", "allocate") == "allocate" else []) + _instances_in_vpc(e, i),
                  validate=lambda e, i, v: _choice(([{"value": "none", "label": "none"}]
                                                    if i.get("eip_action", "allocate") == "allocate" else [])
                                                   + _instances_in_vpc(e, i), v, "instance"),
                  relevant=lambda i: i.get("resource") == "elastic_ip" and i.get("eip_action", "allocate") in ("allocate",
                                                                                                               "associate")),
        FieldSpec("peer_region", "Region of the other VPC?", "choice", default=lambda e, i: e.region_name,
                  options=region_options, validate=pick(region_options, "region"), relevant=_res("peering")),
        FieldSpec("peer_vpc", "Which other VPC?", "choice", must_ask=True, options=_peer_vpc_options,
                  validate=_validate_peer, relevant=_res("peering"), empty_hint="No other VPC there."),
        FieldSpec("peer_route_tables", "Route tables in the OTHER VPC that should reach this one?", "multichoice",
                  default=[], options=_peer_rt_options, validate=pick_many(_peer_rt_options, "route tables", 0),
                  relevant=_res("peering"), allow_empty=True),
        FieldSpec("endpoint_service", "Endpoint for which AWS service?", "choice", must_ask=True, default="s3",
                  options=_endpoint_service_options, validate=_validate_endpoint_service, allow_custom=True,
                  relevant=_res("endpoint")),
        choice("endpoint_type", "S3 endpoint type?", opts(("gateway", "Gateway (free, via route tables)"),
                                                          ("interface", "Interface (private IPs, paid)")),
               default="gateway", relevant=lambda i: i.get("resource") == "endpoint" and i.get("endpoint_service") == "s3"),
        yes_no("private_dns", "Private DNS (the normal service name resolves to the endpoint)?", default="yes",
               relevant=lambda i: i.get("resource") == "endpoint" and not _gateway_endpoint(i)),
        FieldSpec("security_groups", "Security groups for the endpoint?", "multichoice", default=[],
                  options=_sgs_in_vpc, validate=pick_many(_sgs_in_vpc, "security groups", 0), allow_empty=True,
                  relevant=lambda i: i.get("resource") == "endpoint" and not _gateway_endpoint(i)),
        FieldSpec("flow_target", "Record traffic of what? (the whole VPC, or a subnet)", "choice",
                  default=lambda e, i: i.get("vpc"),
                  options=lambda e, i: [{"value": i.get("vpc"), "label": f"The whole VPC {i.get('vpc')}"}] + _subnets_in_vpc(e, i),
                  validate=lambda e, i, v: _choice([{"value": i.get("vpc"), "label": "vpc"}] + _subnets_in_vpc(e, i), v,
                                                   "VPC or subnet"), relevant=_res("flow_logs")),
        choice("traffic", "Which traffic?", opts(("ALL", "All"), ("ACCEPT", "Accepted only"), ("REJECT", "Rejected only")),
               default="ALL", relevant=_res("flow_logs")),
        choice("destination", "Send the logs to?", opts(("cloudwatch", "CloudWatch Logs (search in the console)"),
                                                        ("s3", "An S3 bucket (cheaper for large volumes)")),
               default="cloudwatch", relevant=_res("flow_logs")),
        number("log_days", "Keep the logs for how many days?", 14, 1, 3653,
               relevant=lambda i: i.get("resource") == "flow_logs" and i.get("destination", "cloudwatch") == "cloudwatch"),
        FieldSpec("log_bucket", "Which bucket?", "choice", must_ask=True,
                  options=lambda e, i: [{"value": b, "label": b} for b in lookups.buckets(e)],
                  validate=lambda e, i, v: _choice([{"value": b, "label": b} for b in lookups.buckets(e)], v, "bucket"),
                  relevant=lambda i: i.get("resource") == "flow_logs" and i.get("destination") == "s3"),
        FieldSpec("tgw_vpcs", "Which VPCs should the transit gateway connect?", "multichoice", must_ask=True,
                  options=vpc_options, validate=pick_many(vpc_options, "VPCs", 2), relevant=_res("transit_gateway")),
        number("asn", "Amazon-side BGP ASN?", 64512, 64512, 65534, relevant=_res("transit_gateway")),
        choice("cidr_kind", "Which kind of range?", opts(("ipv6", "Amazon-provided IPv6 /56"),
                                                        ("ipv4", "Secondary IPv4 range")), default="ipv6",
               relevant=_res("cidr")),
        FieldSpec("secondary_cidr", "Which IPv4 range?", "text", must_ask=True, default="100.64.0.0/16",
                  validate=_secondary_cidr, relevant=lambda i: i.get("resource") == "cidr" and i.get("cidr_kind") == "ipv4"),
        FieldSpec("dns_servers", "DNS servers? (IPs, or AmazonProvidedDNS)", "text", must_ask=True,
                  default="AmazonProvidedDNS", validate=_validate_dns, relevant=_res("dhcp_options")),
        FieldSpec("domain_name", "Domain name? (optional)", "text", default="", allow_empty=True,
                  relevant=_res("dhcp_options")),
        FieldSpec("router_ip", "Public IP of your router / firewall?", "text", must_ask=True,
                  validate=_validate_public_ip, relevant=_res("vpn")),
        FieldSpec("bgp_asn", "Your router's BGP ASN (65000 if you do not use BGP)?", "number", default=65000,
                  validate=_validate_asn, relevant=_res("vpn")),
        FieldSpec("onprem_cidrs", "Your network's IP ranges (static routes)?", "text", must_ask=True,
                  default="192.168.0.0/16", validate=_validate_cidr_list, relevant=_res("vpn")),
        FieldSpec("entries", "IP ranges in the list?", "text", must_ask=True, validate=_validate_cidr_list,
                  default=lambda e, i: f"{e.my_ip()}/32" if e.my_ip() else None, relevant=_res("prefix_list")),
        FieldSpec("target_resource", "Delete what?", "choice", must_ask=True, options=_deletable_options,
                  validate=pick(_deletable_options, "resource"), relevant=_res("delete")),
    ],
    title=lambda i: f"VPC: {str(i.get('resource', 'resource')).replace('_', ' ')}",
    build=_build_net, notes=_net_notes,
)


RECIPES = [VPC_RESOURCE]
templates.TEMPLATES.update({t.name: t for t in RECIPES})
