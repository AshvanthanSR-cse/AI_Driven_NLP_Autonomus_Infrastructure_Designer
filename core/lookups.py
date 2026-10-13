"""Read-only AWS lookups used for recipe options and validation (cached per planning call on templates.Env).

Every function takes a templates.Env and returns small, flat dicts. Nothing here writes to AWS.
"""
from core.templates import _name


def _client(env, service: str, region: str | None = None):
    return env.conn.client(service, "read", region or env.region)


def _pages(client, op: str, key: str, **kw) -> list:
    if hasattr(client, "can_paginate") and client.can_paginate(op):
        out = []
        for page in client.get_paginator(op).paginate(**kw):
            out.extend(page.get(key, []))
        return out
    return getattr(client, op)(**kw).get(key, [])


def regions(env) -> list[str]:
    return env._memo("regions", lambda: sorted(
        r["RegionName"] for r in env.ec2().describe_regions().get("Regions", [])))


def vpcs(env) -> list[dict]:
    return env._memo("vpcs", lambda: [
        {"id": v["VpcId"], "cidr": v.get("CidrBlock", ""), "name": _name(v), "default": v.get("IsDefault", False)}
        for v in env.ec2().describe_vpcs()["Vpcs"]])


def vpc_of_subnets(env, subnet_ids: list[str]) -> str | None:
    subs = {s["id"]: s for s in env.subnets()}
    return subs[subnet_ids[0]]["vpc"] if subnet_ids and subnet_ids[0] in subs else None


def all_instances(env) -> list[dict]:
    """Instances that are not terminated (for AMIs, volumes, targets)."""
    def load():
        out = []
        states = ["pending", "running", "stopping", "stopped"]
        for res in _pages(env.ec2(), "describe_instances", "Reservations",
                          Filters=[{"Name": "instance-state-name", "Values": states}]):
            for i in res["Instances"]:
                out.append({"id": i["InstanceId"], "name": _name(i), "state": i["State"]["Name"],
                            "az": i.get("Placement", {}).get("AvailabilityZone", ""), "vpc": i.get("VpcId", ""),
                            "type": i.get("InstanceType", ""), "ip": i.get("PrivateIpAddress", ""),
                            "sgs": [g["GroupId"] for g in i.get("SecurityGroups", [])]})
        return out
    return env._memo("all_instances", load)


def instance(env, iid: str) -> dict | None:
    return next((i for i in all_instances(env) if i["id"] == iid), None)


def own_amis(env) -> list[dict]:
    return env._memo("own_amis", lambda: sorted(
        ({"id": i["ImageId"], "name": i.get("Name", ""), "state": i.get("State", ""),
          "created": i.get("CreationDate", "")[:10], "root": i.get("RootDeviceName", "/dev/xvda"),
          "snapshots": [m["Ebs"]["SnapshotId"] for m in i.get("BlockDeviceMappings", [])
                        if m.get("Ebs", {}).get("SnapshotId")],
          "public": i.get("Public", False)}
         for i in env.ec2().describe_images(Owners=["self"]).get("Images", [])),
        key=lambda x: x["created"], reverse=True))


def image(env, image_id: str) -> dict | None:
    def load():
        try:
            imgs = env.ec2().describe_images(ImageIds=[image_id]).get("Images", [])
        except Exception as e:
            if "InvalidAMIID" in getattr(e, "response", {}).get("Error", {}).get("Code", ""):
                return None
            raise
        if not imgs:
            return None
        i = imgs[0]
        return {"id": i["ImageId"], "name": i.get("Name", ""), "root": i.get("RootDeviceName", "/dev/xvda"),
                "platform": i.get("PlatformDetails", ""), "arch": i.get("Architecture", "x86_64")}
    return env._memo(("image_info", image_id), load)


def volumes(env) -> list[dict]:
    def load():
        out = []
        for v in _pages(env.ec2(), "describe_volumes", "Volumes"):
            att = v.get("Attachments") or [{}]
            out.append({"id": v["VolumeId"], "name": _name(v), "size": v["Size"], "type": v["VolumeType"],
                        "az": v["AvailabilityZone"], "state": v["State"], "iops": v.get("Iops"),
                        "throughput": v.get("Throughput"), "encrypted": v.get("Encrypted", False),
                        "instance": att[0].get("InstanceId", ""), "device": att[0].get("Device", "")})
        return out
    return env._memo("volumes", load)


def volume(env, vid: str) -> dict | None:
    return next((v for v in volumes(env) if v["id"] == vid), None)


def snapshots(env) -> list[dict]:
    def load():
        out = []
        for s in _pages(env.ec2(), "describe_snapshots", "Snapshots", OwnerIds=["self"]):
            out.append({"id": s["SnapshotId"], "volume": s.get("VolumeId", ""), "size": s.get("VolumeSize", 0),
                        "state": s.get("State", ""), "tier": s.get("StorageTier", "standard"),
                        "desc": s.get("Description", "")[:60], "started": str(s.get("StartTime", ""))[:10],
                        "encrypted": s.get("Encrypted", False), "name": _name(s)})
        return sorted(out, key=lambda x: x["started"], reverse=True)
    return env._memo("snapshots", load)


def snapshot(env, sid: str) -> dict | None:
    return next((s for s in snapshots(env) if s["id"] == sid), None)


def load_balancers(env) -> list[dict]:
    def load():
        out = []
        for lb in _pages(_client(env, "elbv2"), "describe_load_balancers", "LoadBalancers"):
            out.append({"arn": lb["LoadBalancerArn"], "name": lb["LoadBalancerName"], "dns": lb.get("DNSName", ""),
                        "type": lb.get("Type", "application"), "scheme": lb.get("Scheme", ""),
                        "vpc": lb.get("VpcId", ""), "sgs": lb.get("SecurityGroups", []),
                        "zone_id": lb.get("CanonicalHostedZoneId", "")})
        return out
    return env._memo("lbs", load)


def target_groups(env) -> list[dict]:
    def load():
        out = []
        for tg in _pages(_client(env, "elbv2"), "describe_target_groups", "TargetGroups"):
            out.append({"arn": tg["TargetGroupArn"], "name": tg["TargetGroupName"], "type": tg.get("TargetType", ""),
                        "port": tg.get("Port"), "protocol": tg.get("Protocol", ""), "vpc": tg.get("VpcId", ""),
                        "lbs": tg.get("LoadBalancerArns", [])})
        return out
    return env._memo("tgs", load)


def listeners(env) -> list[dict]:
    """Listeners of every load balancer: arn, lb name, port, protocol, next free rule priority."""
    def load():
        elb = _client(env, "elbv2")
        out = []
        for lb in load_balancers(env):
            for ln in _pages(elb, "describe_listeners", "Listeners", LoadBalancerArn=lb["arn"]):
                rules = elb.describe_rules(ListenerArn=ln["ListenerArn"]).get("Rules", [])
                used = [int(r["Priority"]) for r in rules if str(r.get("Priority", "")).isdigit()]
                out.append({"arn": ln["ListenerArn"], "lb": lb["name"], "lb_type": lb["type"], "port": ln["Port"],
                            "protocol": ln.get("Protocol", ""), "vpc": lb["vpc"],
                            "next_priority": (max(used) + 1) if used else 1})
        return out
    return env._memo("listeners", load)


def launch_templates(env) -> list[dict]:
    return env._memo("lts", lambda: [
        {"id": t["LaunchTemplateId"], "name": t["LaunchTemplateName"], "latest": t.get("LatestVersionNumber"),
         "default": t.get("DefaultVersionNumber")}
        for t in _pages(env.ec2(), "describe_launch_templates", "LaunchTemplates")])


def auto_scaling_groups(env) -> list[dict]:
    def load():
        out = []
        for g in _pages(_client(env, "autoscaling"), "describe_auto_scaling_groups", "AutoScalingGroups"):
            lt = g.get("LaunchTemplate") or (g.get("MixedInstancesPolicy") or {}).get(
                "LaunchTemplate", {}).get("LaunchTemplateSpecification", {})
            out.append({"name": g["AutoScalingGroupName"], "min": g["MinSize"], "max": g["MaxSize"],
                        "desired": g["DesiredCapacity"], "lt": lt.get("LaunchTemplateName") or lt.get("LaunchTemplateId", ""),
                        "lt_id": lt.get("LaunchTemplateId", ""), "subnets": g.get("VPCZoneIdentifier", ""),
                        "instances": len(g.get("Instances", [])), "tgs": g.get("TargetGroupARNs", [])})
        return out
    return env._memo("asgs", load)


def instance_profiles(env) -> list[dict]:
    return env._memo("profiles", lambda: [
        {"name": p["InstanceProfileName"], "arn": p["Arn"], "roles": [r["RoleName"] for r in p.get("Roles", [])]}
        for p in _pages(_client(env, "iam"), "list_instance_profiles", "InstanceProfiles")])


def certificates(env, region: str | None = None) -> list[dict]:
    reg = region or env.region_name
    return env._memo(("certs", reg), lambda: [
        {"arn": c["CertificateArn"], "domain": c.get("DomainName", ""), "status": c.get("Status", "")}
        for c in _pages(_client(env, "acm", reg), "list_certificates", "CertificateSummaryList",
                        CertificateStatuses=["ISSUED"])])


def buckets(env) -> list[str]:
    return env._memo("buckets", lambda: sorted(
        b["Name"] for b in _client(env, "s3").list_buckets().get("Buckets", [])))


def lambda_functions(env) -> list[dict]:
    return env._memo("lambdas", lambda: sorted(
        ({"name": f["FunctionName"], "arn": f["FunctionArn"], "runtime": f.get("Runtime", f.get("PackageType", ""))}
         for f in _pages(_client(env, "lambda"), "list_functions", "Functions")), key=lambda x: x["name"]))


def sqs_queues(env) -> list[str]:
    return env._memo("queues", lambda: sorted(_client(env, "sqs").list_queues().get("QueueUrls", [])))


def queue_arn(env, url: str) -> str:
    parts = url.rstrip("/").split("/")
    host = parts[2].split(".")
    reg = host[1] if len(host) > 2 and host[0] == "sqs" else env.region_name
    return f"arn:aws:sqs:{reg}:{parts[-2]}:{parts[-1]}"


def sns_topics(env) -> list[str]:
    return env._memo("topics", lambda: sorted(
        t["TopicArn"] for t in _pages(_client(env, "sns"), "list_topics", "Topics")))


def ecs_clusters(env) -> list[str]:
    return env._memo("ecs_clusters", lambda: sorted(
        a.rsplit("/", 1)[-1] for a in _pages(_client(env, "ecs"), "list_clusters", "clusterArns")))


def eks_clusters(env) -> list[str]:
    return env._memo("eks_clusters", lambda: sorted(_pages(_client(env, "eks"), "list_clusters", "clusters")))


def eks_nodegroups(env, cluster: str) -> list[str]:
    return env._memo(("eks_ng", cluster), lambda: sorted(
        _pages(_client(env, "eks"), "list_nodegroups", "nodegroups", clusterName=cluster)))


def eks_cluster(env, name: str) -> dict:
    return env._memo(("eks_cluster", name), lambda: _client(env, "eks").describe_cluster(name=name)["cluster"])


def ecr_repositories(env) -> list[dict]:
    return env._memo("ecr_repos", lambda: sorted(
        ({"name": r["repositoryName"], "uri": r["repositoryUri"], "arn": r["repositoryArn"],
          "mutability": r.get("imageTagMutability", "")}
         for r in _pages(_client(env, "ecr"), "describe_repositories", "repositories")), key=lambda x: x["name"]))


def route_tables(env, vpc_id: str | None = None) -> list[dict]:
    def load():
        flt = [{"Name": "vpc-id", "Values": [vpc_id]}] if vpc_id else []
        out = []
        for rt in _pages(env.ec2(), "describe_route_tables", "RouteTables", Filters=flt):
            out.append({"id": rt["RouteTableId"], "vpc": rt["VpcId"], "name": _name(rt),
                        "main": any(a.get("Main") for a in rt.get("Associations", [])),
                        "subnets": [a["SubnetId"] for a in rt.get("Associations", []) if a.get("SubnetId")],
                        "routes": [r.get("DestinationCidrBlock") or r.get("DestinationPrefixListId", "")
                                   for r in rt.get("Routes", [])]})
        return out
    return env._memo(("rts", vpc_id), load)


def network_acls(env, vpc_id: str | None = None) -> list[dict]:
    def load():
        flt = [{"Name": "vpc-id", "Values": [vpc_id]}] if vpc_id else []
        return [{"id": a["NetworkAclId"], "vpc": a["VpcId"], "default": a.get("IsDefault", False), "name": _name(a),
                 "associations": {x["SubnetId"]: x["NetworkAclAssociationId"] for x in a.get("Associations", [])}}
                for a in _pages(env.ec2(), "describe_network_acls", "NetworkAcls", Filters=flt)]
    return env._memo(("nacls", vpc_id), load)


def internet_gateways(env) -> list[dict]:
    return env._memo("igws", lambda: [
        {"id": g["InternetGatewayId"], "name": _name(g), "vpcs": [a["VpcId"] for a in g.get("Attachments", [])]}
        for g in _pages(env.ec2(), "describe_internet_gateways", "InternetGateways")])


def nat_gateways(env) -> list[dict]:
    return env._memo("nats", lambda: [
        {"id": n["NatGatewayId"], "vpc": n.get("VpcId", ""), "subnet": n.get("SubnetId", ""), "name": _name(n),
         "state": n.get("State", "")}
        for n in _pages(env.ec2(), "describe_nat_gateways", "NatGateways",
                        Filter=[{"Name": "state", "Values": ["available", "pending"]}])])


def elastic_ips(env) -> list[dict]:
    return env._memo("eips", lambda: [
        {"id": a["AllocationId"], "ip": a.get("PublicIp", ""), "instance": a.get("InstanceId", ""),
         "association": a.get("AssociationId", ""), "name": _name(a)}
        for a in env.ec2().describe_addresses().get("Addresses", []) if a.get("AllocationId")])


def peering_connections(env) -> list[dict]:
    return env._memo("peerings", lambda: [
        {"id": p["VpcPeeringConnectionId"], "status": p.get("Status", {}).get("Code", ""),
         "requester": p.get("RequesterVpcInfo", {}).get("VpcId", ""),
         "accepter": p.get("AccepterVpcInfo", {}).get("VpcId", "")}
        for p in _pages(env.ec2(), "describe_vpc_peering_connections", "VpcPeeringConnections")])


def transit_gateways(env) -> list[dict]:
    return env._memo("tgws", lambda: [
        {"id": t["TransitGatewayId"], "state": t.get("State", ""), "name": _name(t)}
        for t in _pages(env.ec2(), "describe_transit_gateways", "TransitGateways")
        if t.get("State") not in ("deleted", "deleting")])


def endpoint_services(env) -> list[str]:
    return env._memo("endpoint_services", lambda: sorted(
        env.ec2().describe_vpc_endpoint_services().get("ServiceNames", [])))


def log_groups(env) -> list[str]:
    return env._memo("log_groups", lambda: sorted(
        g["logGroupName"] for g in _pages(_client(env, "logs"), "describe_log_groups", "logGroups")))


def glacier_vaults(env) -> list[dict]:
    return env._memo("vaults", lambda: [
        {"name": v["VaultName"], "arn": v["VaultARN"], "archives": v.get("NumberOfArchives", 0),
         "size": v.get("SizeInBytes", 0)}
        for v in _pages(_client(env, "glacier"), "list_vaults", "VaultList", accountId="-")])


def distributions(env) -> list[dict]:
    def load():
        dl = _client(env, "cloudfront").list_distributions().get("DistributionList", {})
        return [{"id": d["Id"], "domain": d["DomainName"], "enabled": d.get("Enabled", False),
                 "aliases": d.get("Aliases", {}).get("Items", []), "comment": d.get("Comment", "")}
                for d in dl.get("Items", [])]
    return env._memo("distributions", load)


def key_label(items: list[dict], fmt) -> list[dict]:
    return [{"value": v, "label": label} for v, label in (fmt(i) for i in items)]
