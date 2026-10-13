"""Container, network, storage and Lambda recipes (offline, fake AWS). Every draft is validated against the
botocore model by RecipeTest.build, so wrong parameter names fail here."""
import json
import unittest
from pathlib import Path
from unittest import mock

import yaml
from botocore.exceptions import ClientError

from core import local_steps, router, scripts, templates
from tests.fakes import FakeConn
from tests.test_compute import (ACCOUNT, FakeAcm, FakeAsg, FakeEc2Compute, FakeElb, FakeIamProfiles,
                                FakeLambdaList, FakeSns, RecipeTest)
from tests.test_recipes import FakeSts
from tests.test_templates import FakeSsm

QUEUE = f"https://sqs.us-east-1.amazonaws.com/{ACCOUNT}/jobs"


def _missing(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")


class FakeEc2Net(FakeEc2Compute):
    def describe_vpcs(self, VpcIds=None):
        vpcs = [{"VpcId": "vpc-111", "CidrBlock": "10.0.0.0/16", "Tags": [{"Key": "Name", "Value": "main"}],
                 "CidrBlockAssociationSet": [{"CidrBlock": "10.0.0.0/16", "CidrBlockState": {"State": "associated"}}]},
                {"VpcId": "vpc-222", "CidrBlock": "10.1.0.0/16", "Tags": [{"Key": "Name", "Value": "other"}]}]
        return {"Vpcs": [v for v in vpcs if not VpcIds or v["VpcId"] in VpcIds]}

    def describe_subnets(self):
        out = super().describe_subnets()
        out["Subnets"].append({"SubnetId": "subnet-other", "CidrBlock": "10.1.0.0/24", "AvailabilityZone": "us-east-1a",
                               "VpcId": "vpc-222", "MapPublicIpOnLaunch": False})
        return out

    def describe_route_tables(self, Filters=None):
        rts = [{"RouteTableId": "rtb-pub", "VpcId": "vpc-111", "Associations": [{"Main": True}],
                "Routes": [{"DestinationCidrBlock": "10.0.0.0/16"}, {"DestinationCidrBlock": "0.0.0.0/0"}]},
               {"RouteTableId": "rtb-priv", "VpcId": "vpc-111", "Associations": [{"SubnetId": "subnet-priv"}],
                "Routes": [{"DestinationCidrBlock": "10.0.0.0/16"}]},
               {"RouteTableId": "rtb-other", "VpcId": "vpc-222", "Associations": [{"Main": True}],
                "Routes": [{"DestinationCidrBlock": "10.1.0.0/16"}]}]
        vpc = (Filters or [{}])[0].get("Values", [None])[0] if Filters else None
        return {"RouteTables": [r for r in rts if not vpc or r["VpcId"] == vpc]}

    def describe_network_acls(self, Filters=None):
        return {"NetworkAcls": [{"NetworkAclId": "acl-default", "VpcId": "vpc-111", "IsDefault": True,
                                 "Associations": [{"SubnetId": "subnet-pub", "NetworkAclAssociationId": "aclassoc-1"},
                                                  {"SubnetId": "subnet-priv", "NetworkAclAssociationId": "aclassoc-2"}]}]}

    def describe_internet_gateways(self):
        return {"InternetGateways": [{"InternetGatewayId": "igw-111", "Attachments": [{"VpcId": "vpc-111"}]}]}

    def describe_nat_gateways(self, Filter=None):
        return {"NatGateways": []}

    def describe_addresses(self):
        return {"Addresses": [{"AllocationId": "eipalloc-0abc1234", "PublicIp": "3.3.3.3"}]}

    def describe_vpc_peering_connections(self):
        return {"VpcPeeringConnections": []}

    def describe_transit_gateways(self):
        return {"TransitGateways": []}

    def describe_vpc_endpoint_services(self):
        return {"ServiceNames": ["com.amazonaws.us-east-1.s3", "com.amazonaws.us-east-1.ssm",
                                 "com.amazonaws.us-east-1.ecr.api"]}


class FakeS3:
    def __init__(self):
        self.policy = None

    def list_buckets(self):
        return {"Buckets": [{"Name": "kintsugi-data"}, {"Name": "kintsugi-backup"}]}

    def get_bucket_location(self, Bucket):
        return {"LocationConstraint": None}

    def head_bucket(self, Bucket):
        raise ClientError({"Error": {"Code": "404"}, "ResponseMetadata": {"HTTPStatusCode": 404}}, "HeadBucket")

    def get_bucket_versioning(self, Bucket):
        return {"Status": "Enabled"} if Bucket == "kintsugi-backup" else {}

    def get_bucket_lifecycle_configuration(self, Bucket):
        return {"Rules": [{"ID": "old-rule", "Status": "Enabled", "Filter": {"Prefix": "tmp/"},
                           "Expiration": {"Days": 3}}]}

    def get_bucket_notification_configuration(self, Bucket):
        return {"EventBridgeConfiguration": {}}

    def get_bucket_policy(self, Bucket):
        if self.policy is None:
            raise _missing("NoSuchBucketPolicy")
        return {"Policy": self.policy}

    def get_paginator(self, op):
        objs = [{"Key": "photos/a.jpg", "Size": 1024, "StorageClass": "STANDARD"},
                {"Key": "photos/b.jpg", "Size": 2048, "StorageClass": "GLACIER"}]

        class P:
            def paginate(self, Bucket, Prefix="", **kw):
                return iter([{"Contents": [o for o in objs if o["Key"].startswith(Prefix)]}])
        return P()


class FakeSqs:
    def list_queues(self):
        return {"QueueUrls": [QUEUE]}

    def get_queue_attributes(self, QueueUrl, AttributeNames):
        return {"Attributes": {}}


class FakeSnsFull(FakeSns):
    def get_topic_attributes(self, TopicArn):
        return {"Attributes": {"Policy": json.dumps({"Version": "2012-10-17", "Statement": []})}}


class FakeLambdaFull(FakeLambdaList):
    def get_function_configuration(self, FunctionName):
        if FunctionName == "hello":
            return {"FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:hello", "MemorySize": 128,
                    "Timeout": 3, "Environment": {"Variables": {"MODE": "prod"}}}
        return super().get_function_configuration(FunctionName)

    def list_aliases(self, FunctionName):
        return {"Aliases": [{"Name": "live", "FunctionVersion": "3"}]}

    def get_alias(self, FunctionName, Name):
        if Name == "live":
            return {"Name": "live", "FunctionVersion": "3"}
        raise _missing("ResourceNotFoundException")


class FakeEcs:
    def list_clusters(self):
        return {"clusterArns": [f"arn:aws:ecs:us-east-1:{ACCOUNT}:cluster/shared"]}


class FakeEks:
    def list_clusters(self):
        return {"clusters": ["prod"]}

    def list_nodegroups(self, clusterName):
        return {"nodegroups": ["prod-nodes"]}

    def describe_nodegroup(self, clusterName, nodegroupName):
        return {"nodegroup": {"scalingConfig": {"desiredSize": 2, "minSize": 1, "maxSize": 3}}}

    def describe_cluster(self, name):
        return {"cluster": {"version": "1.31"}}

    def describe_cluster_versions(self, **kw):
        return {"clusterVersions": [{"clusterVersion": "1.32", "status": "STANDARD_SUPPORT"},
                                    {"clusterVersion": "1.33", "status": "STANDARD_SUPPORT"}]}


class FakeEcr:
    def describe_repositories(self, repositoryNames=None):
        repos = [{"repositoryName": "web", "repositoryUri": f"{ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com/web",
                  "repositoryArn": f"arn:aws:ecr:us-east-1:{ACCOUNT}:repository/web", "imageTagMutability": "MUTABLE"}]
        if repositoryNames:
            got = [r for r in repos if r["repositoryName"] in repositoryNames]
            if not got:
                raise _missing("RepositoryNotFoundException")
            return {"repositories": got}
        return {"repositories": repos}

    def describe_registry(self):
        return {"replicationConfiguration": {"rules": [{"destinations": [{"region": "eu-west-1",
                                                                          "registryId": ACCOUNT}]}]}}


class FakeGlacier:
    def list_vaults(self, accountId):
        return {"VaultList": [{"VaultName": "old-backups", "VaultARN": "arn:aws:glacier:us-east-1:1:vaults/old-backups",
                               "NumberOfArchives": 2, "SizeInBytes": 4096}]}


class FakeCloudFront:
    def list_distributions(self):
        return {"DistributionList": {"Items": [{"Id": "E2ABCDEF123456", "DomainName": "d1.cloudfront.net",
                                                "Enabled": True, "Comment": "site"}]}}


class FakeDdb:
    def list_tables(self):
        return {"TableNames": ["orders"]}

    def describe_table(self, TableName):
        return {"Table": {"LatestStreamArn": f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/orders/stream/2026",
                          "StreamSpecification": {"StreamEnabled": True}}}


class FakeWaf:
    def list_web_acls(self, Scope):
        return {"WebACLs": []}


def conn():
    return FakeConn({"ec2": FakeEc2Net(), "ssm": FakeSsm(), "sts": FakeSts(), "iam": FakeIamProfiles(),
                     "elbv2": FakeElb(), "autoscaling": FakeAsg(), "acm": FakeAcm(), "lambda": FakeLambdaFull(),
                     "sns": FakeSnsFull(), "s3": FakeS3(), "sqs": FakeSqs(), "ecs": FakeEcs(), "eks": FakeEks(),
                     "ecr": FakeEcr(), "glacier": FakeGlacier(), "cloudfront": FakeCloudFront(), "dynamodb": FakeDdb(),
                     "wafv2": FakeWaf()})


def ops(d):
    return [s.get("kind") or f"{s['service']}.{s['operation']}" for s in d.steps]


class InfraTest(RecipeTest):
    def build(self, template, inputs, c=None):
        return super().build(template, inputs, c or conn())

    def app(self):
        return self.folder("app", {"Dockerfile": "FROM nginx:alpine\nEXPOSE 8080\n", "index.html": "hi"})

    def code(self):
        return self.folder("fn", {"lambda_function.py": "def lambda_handler(e, c):\n    return 1\n"})


class TestEcs(InfraTest):
    def test_alb_autoscaling_secrets(self):
        d = self.build("ecs_fargate_service", {"app_folder": self.app(), "name": "shop", "exposure": "alb",
                                               "subnets": ["subnet-pub", "subnet-pub2"], "autoscaling": "cpu",
                                               "env_vars": "MODE=prod",
                                               "secrets": f"DB_PASSWORD=arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:db-AbCd"})
        o = ops(d)
        self.assertIn("elbv2.create_load_balancer", o)
        self.assertIn("application-autoscaling.register_scalable_target", o)
        svc = next(s for s in d.steps if s.get("operation") == "create_service")["params"]
        self.assertEqual(svc["loadBalancers"][0]["containerPort"], 8080)
        self.assertTrue(svc["deploymentConfiguration"]["deploymentCircuitBreaker"]["rollback"])
        td = next(s for s in d.steps if s.get("operation") == "register_task_definition")["params"]
        c = td["containerDefinitions"][0]
        self.assertEqual(c["environment"], [{"name": "MODE", "value": "prod"}])
        self.assertTrue(c["secrets"][0]["valueFrom"].startswith("arn:aws:secretsmanager"))
        pol = next(s for s in d.steps if s.get("operation") == "put_role_policy")["params"]
        self.assertIn("secretsmanager:GetSecretValue", pol["PolicyDocument"])
        rule = [s for s in d.steps if s.get("operation") == "authorize_security_group_ingress"
                and s["params"]["GroupId"] == "{{sg.GroupId}}"][0]
        self.assertIn("UserIdGroupPairs", rule["params"]["IpPermissions"][0])
        self.assertEqual(o[-1], "check")

    def test_secret_values_rejected(self):
        q = templates.plan("ecs_fargate_service", {"app_folder": self.app(), "env_vars": "DB_PASSWORD=hunter22"},
                           conn())
        self.assertIn("looks like a secret", next(x.error for x in q.questions if x.key == "env_vars"))

    def test_ec2_launch_type_capacity_provider(self):
        d = self.build("ecs_fargate_service", {"image_source": "image", "image_uri": "nginx:1.27", "name": "api",
                                               "launch_type": "ec2", "exposure": "private",
                                               "subnets": ["subnet-priv"]})
        o = ops(d)
        for op in ("ec2.create_launch_template", "autoscaling.create_auto_scaling_group",
                   "ecs.create_capacity_provider", "ecs.put_cluster_capacity_providers"):
            self.assertIn(op, o)
        svc = next(s for s in d.steps if s.get("operation") == "create_service")["params"]
        self.assertEqual(svc["capacityProviderStrategy"][0]["capacityProvider"], "api-cp")
        self.assertNotIn("launchType", svc)
        self.assertNotIn("command", o)

    def test_ec2_cannot_use_public_ip(self):
        q = templates.plan("ecs_fargate_service", {"image_source": "image", "image_uri": "nginx:1.27",
                                                   "launch_type": "ec2", "exposure": "public_ip"}, conn())
        self.assertIn("cannot get their own public IP", next(x.error for x in q.questions if x.key == "exposure"))

    def test_scheduled_task_in_app_timezone(self):
        d = self.build("ecs_fargate_service", {"image_source": "image", "image_uri": "nginx:1.27", "name": "job",
                                               "mode": "scheduled", "schedule": "daily 02:30",
                                               "subnets": ["subnet-pub"]})
        sched = next(s for s in d.steps if s.get("operation") == "create_schedule")["params"]
        self.assertEqual(sched["ScheduleExpression"], "cron(30 2 * * ? *)")
        self.assertEqual(sched["ScheduleExpressionTimezone"], "Asia/Kolkata")
        self.assertNotIn("ecs.create_service", ops(d))

    def test_spot_and_existing_cluster(self):
        d = self.build("ecs_fargate_service", {"image_source": "image", "image_uri": "nginx:1.27", "name": "cheap",
                                               "launch_type": "fargate_spot", "cluster": "shared",
                                               "subnets": ["subnet-pub"]})
        self.assertNotIn("ecs.create_cluster", ops(d))
        svc = next(s for s in d.steps if s.get("operation") == "create_service")["params"]
        self.assertEqual(svc["capacityProviderStrategy"][0]["capacityProvider"], "FARGATE_SPOT")


class TestEks(InfraTest):
    def base(self, **kw):
        return {"cost_ok": "yes", "name": "demo", "network": "new", "node_type": "t3.small", "nodes": 2, **kw}

    def test_helm_chart(self):
        d = self.build("eks_cluster", self.base(app_source="helm", chart="bitnami/nginx",
                                                repo_url="https://charts.bitnami.com/bitnami"))
        helm = [s for s in d.steps if s.get("tool") == "helm"]
        self.assertEqual(helm[0]["args"][:2], ["repo", "add"])
        self.assertEqual(helm[-1]["undo"]["args"][0], "uninstall")

    def test_auto_mode_and_custom_addons(self):
        d = self.build("eks_cluster", self.base(app_source="none", compute="auto", settings="custom",
                                                logs=["api"]))
        cfg = yaml.safe_load(Path(next(s for s in d.steps if s.get("tool") == "eksctl")["args"][3]).read_text())
        self.assertTrue(cfg["autoModeConfig"]["enabled"])
        self.assertNotIn("managedNodeGroups", cfg)
        self.assertEqual(cfg["metadata"]["version"], "1.33")
        d = self.build("eks_cluster", self.base(app_source="none", compute="spot", settings="custom",
                                                addons=["aws-ebs-csi-driver"]))
        cfg = yaml.safe_load(Path(next(s for s in d.steps if s.get("tool") == "eksctl")["args"][3]).read_text())
        self.assertTrue(cfg["managedNodeGroups"][0]["spot"])
        self.assertTrue(cfg["iam"]["withOIDC"])

    def test_hpa_manifest(self):
        d = self.build("eks_cluster", self.base(app_source="dockerfile", app_folder=self.app(), container_port=8080,
                                                hpa="yes"))
        app = next(s for s in d.steps if s.get("tool") == "kubectl" and s["args"][0] == "apply")
        docs = list(yaml.safe_load_all(Path(app["args"][2]).read_text()))
        self.assertEqual(docs[2]["kind"], "HorizontalPodAutoscaler")

    def test_manage_scale_addon_upgrade(self):
        d = self.build("eks_manage", {"cluster": "prod", "action": "scale", "nodegroup": "prod-nodes", "desired": 4,
                                      "max_nodes": 5})
        self.assertEqual(d.steps[0]["params"]["scalingConfig"]["desiredSize"], 4)
        self.assertEqual(d.steps[0]["undo"]["params"]["scalingConfig"]["desiredSize"], 2)
        d = self.build("eks_manage", {"cluster": "prod", "action": "addon", "addon": "metrics-server"})
        self.assertEqual(d.steps[0]["operation"], "create_addon")
        d = self.build("eks_manage", {"cluster": "prod", "action": "upgrade"})
        self.assertEqual(d.steps[0]["params"]["version"], "1.32")
        d = self.build("eks_manage", {"cluster": "prod", "action": "deploy", "app_source": "manifests",
                                      "app_folder": self.folder("k8s", {"app.yaml": "kind: Pod"})})
        self.assertEqual([s.get("tool") for s in d.steps][:2], ["aws", "kubectl"])


class TestEcr(InfraTest):
    def test_create_with_lifecycle_and_cross_account(self):
        d = self.build("ecr_repository", {"name": "api", "pull_accounts": "210987654321"})
        self.assertEqual(ops(d), ["ecr.create_repository", "ecr.put_lifecycle_policy", "ecr.set_repository_policy"])
        rules = json.loads(d.steps[1]["params"]["lifecyclePolicyText"])["rules"]
        self.assertEqual(rules[0]["selection"]["tagStatus"], "untagged")
        self.assertEqual(d.steps[0]["params"]["imageTagMutability"], "IMMUTABLE")

    def test_replication_keeps_existing_rules(self):
        d = self.build("ecr_repository", {"action": "replication", "regions": ["ap-south-1"]})
        rules = d.steps[0]["params"]["replicationConfiguration"]["rules"]
        self.assertEqual(len(rules), 2)
        self.assertEqual(len(d.steps[0]["undo"]["params"]["replicationConfiguration"]["rules"]), 1)

    def test_pull_through_and_delete(self):
        d = self.build("ecr_repository", {"action": "pull_through", "upstream": "k8s"})
        self.assertEqual(d.steps[0]["params"]["upstreamRegistryUrl"], "registry.k8s.io")
        d = self.build("ecr_repository", {"action": "delete", "repo": "web"})
        self.assertTrue(d.destructive)


class TestVpcResource(InfraTest):
    def net(self, **kw):
        return self.build("vpc_resource", {"vpc": "vpc-111", **kw})

    def test_subnet_next_free_range(self):
        d = self.net(resource="subnet", route_table="rtb-pub", public="yes")
        self.assertEqual(d.steps[0]["params"]["CidrBlock"], "10.0.3.0/24")
        self.assertEqual(ops(d), ["ec2.create_subnet", "ec2.modify_subnet_attribute", "ec2.associate_route_table"])

    def test_overlapping_subnet_rejected(self):
        q = templates.plan("vpc_resource", {"resource": "subnet", "vpc": "vpc-111", "cidr": "10.0.0.0/25"}, conn())
        self.assertIn("overlaps", next(x.error for x in q.questions if x.key == "cidr"))
        q = templates.plan("vpc_resource", {"resource": "subnet", "vpc": "vpc-111", "cidr": "192.168.0.0/24"}, conn())
        self.assertIn("not inside", next(x.error for x in q.questions if x.key == "cidr"))

    def test_security_group_rules_and_ssh_block(self):
        d = self.net(resource="security_group", rules="tcp 443 0.0.0.0/0; tcp 5432 sg-0abc12345; udp 53 10.0.0.0/16")
        perms = d.steps[1]["params"]["IpPermissions"]
        self.assertEqual(perms[1]["UserIdGroupPairs"][0]["GroupId"], "sg-0abc12345")
        q = templates.plan("vpc_resource", {"resource": "security_group", "vpc": "vpc-111",
                                            "rules": "tcp 22 0.0.0.0/0"}, conn())
        self.assertIn("SSH", next(x.error for x in q.questions if x.key == "rules"))

    def test_nacl_with_association_undo(self):
        d = self.net(resource="network_acl", subnets=["subnet-priv"])
        repl = next(s for s in d.steps if s.get("operation") == "replace_network_acl_association")
        self.assertEqual(repl["params"]["AssociationId"], "aclassoc-2")
        self.assertEqual(repl["undo"]["params"]["NetworkAclId"], "acl-default")

    def test_nat_replaces_existing_default_route(self):
        d = self.net(resource="nat_gateway", nat_subnet="subnet-pub", route_tables=["rtb-pub", "rtb-priv"])
        routes = {s["params"]["RouteTableId"]: s["operation"] for s in d.steps
                  if s.get("operation") in ("create_route", "replace_route")}
        self.assertEqual(routes, {"rtb-pub": "replace_route", "rtb-priv": "create_route"})

    def test_peering_with_routes_both_sides(self):
        d = self.net(resource="peering", peer_vpc="vpc-222", route_tables=["rtb-priv"], peer_route_tables=["rtb-other"])
        self.assertIn("wait_until", ops(d))
        routes = [s["params"]["DestinationCidrBlock"] for s in d.steps if s.get("operation") == "create_route"]
        self.assertEqual(routes, ["10.1.0.0/16", "10.0.0.0/16"])

    def test_endpoints_flow_logs_tgw(self):
        d = self.net(resource="endpoint", endpoint_service="s3", route_tables=["rtb-priv"])
        self.assertEqual(d.steps[0]["params"]["VpcEndpointType"], "Gateway")
        d = self.net(resource="endpoint", endpoint_service="ssm", subnets=["subnet-priv"])
        self.assertEqual(d.steps[0]["params"]["VpcEndpointType"], "Interface")
        d = self.net(resource="flow_logs")
        self.assertIn("iam.put_role_policy", ops(d))
        d = self.build("vpc_resource", {"resource": "transit_gateway", "tgw_vpcs": ["vpc-111", "vpc-222"]})
        self.assertEqual(ops(d).count("ec2.create_transit_gateway_vpc_attachment"), 2)
        self.assertTrue(any("COST" in n for n in d.notes))

    def test_route_eip_vpn_delete(self):
        d = self.build("vpc_resource", {"resource": "route", "vpc": "vpc-111", "route_table": "rtb-priv",
                                        "destination": "10.9.0.0/16", "target": "pcx-0abc12345"})
        self.assertEqual(d.steps[0]["params"]["VpcPeeringConnectionId"], "pcx-0abc12345")
        d = self.net(resource="elastic_ip", eip_action="allocate", instance="i-0aaaaaaaaaaaaaaa1")
        self.assertEqual(ops(d), ["ec2.allocate_address", "ec2.associate_address"])
        d = self.net(resource="vpn", router_ip="52.95.110.1", route_tables=["rtb-priv"])
        self.assertIn("ec2.create_vpn_connection", ops(d))
        d = self.net(resource="delete", target_resource="igw:igw-111")
        self.assertEqual(ops(d), ["ec2.detach_internet_gateway", "ec2.delete_internet_gateway"])
        self.assertTrue(d.destructive)

    def test_vpc_network_extras(self):
        d = self.build("vpc_network", {"name": "lab", "cidr": "10.0.0.0/16", "azs": ["us-east-1a", "us-east-1b"],
                                       "nat_gateway": "per_az", "ipv6": "yes", "flow_logs": "yes"})
        o = ops(d)
        self.assertEqual(o.count("ec2.create_nat_gateway"), 2)
        self.assertIn("ec2.create_vpc_endpoint", o)
        self.assertIn("ec2.create_flow_logs", o)
        self.assertIn("ec2.associate_vpc_cidr_block", o)


class TestS3Bucket(InfraTest):
    def test_create_with_glacier_lifecycle(self):
        d = self.build("s3_bucket", {"name": "kintsugi-archive-2026", "lifecycle": "yes", "ia_days": 30,
                                     "glacier_days": 90, "deep_archive_days": 180, "expire_days": 365})
        o = ops(d)
        self.assertEqual(o[:3], ["s3.create_bucket", "s3.put_bucket_tagging", "s3.put_public_access_block"])
        self.assertEqual(d.steps[1]["undo"]["kind"], "s3_empty")
        rule = next(s for s in d.steps if s.get("operation") == "put_bucket_lifecycle_configuration")["params"]
        trans = rule["LifecycleConfiguration"]["Rules"][0]["Transitions"]
        self.assertEqual([t["StorageClass"] for t in trans], ["STANDARD_IA", "GLACIER", "DEEP_ARCHIVE"])

    def test_lifecycle_rules_checked(self):
        q = templates.plan("s3_bucket", {"name": "kintsugi-x-2026", "lifecycle": "yes", "ia_days": 10}, conn())
        self.assertIn("30 days", next(x.error for x in q.questions if x.key == "ia_days"))
        q = templates.plan("s3_bucket", {"name": "kintsugi-x-2026", "lifecycle": "yes", "glacier_days": 90,
                                         "expire_days": 60}, conn())
        self.assertIn("after the last transition", next(x.error for x in q.questions if x.key == "expire_days"))

    def test_configure_merges_existing_rules_and_events(self):
        d = self.build("s3_bucket", {"action": "configure", "bucket": "kintsugi-data", "lifecycle": "yes",
                                     "glacier_days": 60, "notify": "sqs", "notify_target": QUEUE})
        lc = next(s for s in d.steps if s.get("operation") == "put_bucket_lifecycle_configuration")
        self.assertEqual([r["ID"] for r in lc["params"]["LifecycleConfiguration"]["Rules"]][0], "old-rule")
        self.assertEqual(lc["undo"]["params"]["LifecycleConfiguration"]["Rules"][0]["ID"], "old-rule")
        notif = next(s for s in d.steps if s.get("operation") == "put_bucket_notification_configuration")["params"]
        self.assertIn("EventBridgeConfiguration", notif["NotificationConfiguration"])
        self.assertIn("QueueConfigurations", notif["NotificationConfiguration"])
        self.assertIn("sqs.set_queue_attributes", ops(d))

    def test_replication_needs_versioned_destination(self):
        base = {"name": "kintsugi-src-2026", "settings": "custom"}
        q = templates.plan("s3_bucket", {**base, "replicate_to": "kintsugi-data"}, conn())
        self.assertIn("versioning must be ON", next(x.error for x in q.questions if x.key == "replicate_to"))
        d = self.build("s3_bucket", {**base, "replicate_to": "kintsugi-backup", "object_lock": "governance"})
        o = ops(d)
        self.assertIn("s3.put_bucket_replication", o)
        self.assertIn("s3.put_object_lock_configuration", o)
        self.assertTrue(d.steps[0]["params"]["ObjectLockEnabledForBucket"])


class TestS3ObjectsGlacier(InfraTest):
    def test_restore_from_glacier(self):
        d = self.build("s3_objects", {"bucket": "kintsugi-data", "action": "restore", "prefix": "photos/",
                                      "tier": "Bulk"})
        st = d.steps[0]
        self.assertEqual((st["kind"], st["tier"], st["days"]), ("s3_objects", "Bulk", 7))
        self.assertTrue(any("GLACIER: 1" in n for n in d.notes))

    def test_move_to_deep_archive_and_delete(self):
        d = self.build("s3_objects", {"bucket": "kintsugi-data", "action": "storage_class", "prefix": "photos/",
                                      "storage_class": "DEEP_ARCHIVE"})
        self.assertFalse(d.destructive)
        d = self.build("s3_objects", {"bucket": "kintsugi-data", "action": "delete", "prefix": "photos/"})
        self.assertTrue(d.destructive)

    def test_empty_prefix_rejected(self):
        q = templates.plan("s3_objects", {"bucket": "kintsugi-data", "action": "delete", "prefix": "nothing/"}, conn())
        self.assertIn("no objects", next(x.error for x in q.questions if x.key == "prefix"))

    def test_runtime_restore_and_storage_class(self):
        from core import aws_steps
        s3 = mock.Mock()
        s3.get_paginator.return_value.paginate.return_value = iter([{"Contents": [
            {"Key": "p/a", "StorageClass": "GLACIER"}, {"Key": "p/b", "StorageClass": "STANDARD"}]}])
        c = FakeConn({"s3": s3})
        res = aws_steps.run({"kind": "s3_objects", "bucket": "b", "prefix": "p/", "action": "restore", "days": 2,
                             "tier": "Standard"}, c, "operate", "us-east-1")
        s3.restore_object.assert_called_once()
        self.assertIn("1 object(s) restore requested", res["summary"])
        s3.get_paginator.return_value.paginate.return_value = iter([{"Contents": [
            {"Key": "p/a", "StorageClass": "GLACIER"}, {"Key": "p/b", "StorageClass": "STANDARD"}]}])
        res = aws_steps.run({"kind": "s3_objects", "bucket": "b", "prefix": "p/", "action": "storage_class",
                             "storage_class": "GLACIER_IR"}, c, "operate", "us-east-1")
        self.assertEqual(s3.copy.call_args.kwargs["ExtraArgs"]["StorageClass"], "GLACIER_IR")
        self.assertIn("restore it first", res["summary"])

    def test_upload_with_storage_class(self):
        src = self.folder("docs", {"a.txt": "x"})
        d = self.build("s3_upload", {"source": src, "bucket": "kintsugi-data", "storage_class": "DEEP_ARCHIVE"})
        up = next(s for s in d.steps if s.get("kind") == "s3_upload")
        self.assertEqual(up["storage_class"], "DEEP_ARCHIVE")
        self.assertIn("--storage-class DEEP_ARCHIVE", local_steps.render(up, "us-east-1"))

    def test_glacier_vault(self):
        d = self.build("glacier_vault", {"action": "create", "vault_name": "photos-2026"})
        self.assertEqual(d.steps[0]["undo"]["operation"], "delete_vault")
        f = self.folder("arch", {"backup.tar": "data"})
        d = self.build("glacier_vault", {"action": "upload", "vault": "old-backups", "file": f + "\\backup.tar"})
        self.assertTrue(d.steps[0]["params"]["body"].startswith("@file:"))
        self.assertEqual(d.steps[0]["undo"]["params"]["archiveId"], "{{arch.archiveId}}")
        d = self.build("glacier_vault", {"action": "inventory", "vault": "old-backups"})
        self.assertEqual(d.steps[0]["params"]["jobParameters"]["Type"], "inventory-retrieval")


class TestCloudFront(InfraTest):
    def test_private_s3_with_oac(self):
        d = self.build("cloudfront_distribution", {"origin_type": "s3", "bucket": "kintsugi-data", "spa": "yes"})
        o = ops(d)
        self.assertEqual(o, ["cloudfront.create_origin_access_control", "cloudfront.create_distribution_with_tags",
                             "s3.put_bucket_policy", "check"])
        cfg = d.steps[1]["params"]["DistributionConfigWithTags"]["DistributionConfig"]
        self.assertEqual(cfg["Origins"]["Items"][0]["OriginAccessControlId"], "{{oac.OriginAccessControl.Id}}")
        self.assertEqual(cfg["CustomErrorResponses"]["Quantity"], 2)
        self.assertEqual(d.steps[1]["undo"]["kind"], "cf_delete")
        pol = json.loads(d.steps[2]["params"]["Policy"])
        self.assertEqual(pol["Statement"][0]["Principal"], {"Service": "cloudfront.amazonaws.com"})
        self.assertFalse(scripts.makes_public(d.steps[2]))

    def test_alb_origin_and_invalidate(self):
        d = self.build("cloudfront_distribution", {"origin_type": "alb", "load_balancer": "web-1.elb.amazonaws.com"})
        cfg = d.steps[0]["params"]["DistributionConfigWithTags"]["DistributionConfig"]
        self.assertEqual(cfg["DefaultCacheBehavior"]["CachePolicyId"], "4135ea2d-6df8-44a3-9df3-4b5a84be39ad")
        self.assertEqual(cfg["Origins"]["Items"][0]["CustomOriginConfig"]["OriginProtocolPolicy"], "http-only")
        d = self.build("cloudfront_distribution", {"action": "invalidate", "distribution": "E2ABCDEF123456"})
        self.assertEqual(d.steps[0]["params"]["InvalidationBatch"]["Paths"]["Items"], ["/*"])
        d = self.build("cloudfront_distribution", {"action": "delete", "distribution": "E2ABCDEF123456"})
        self.assertTrue(d.destructive)


class TestLambdaRecipes(InfraTest):
    def test_sqs_trigger_adds_role_policy(self):
        d = self.build("lambda_function", {"name": "worker", "source_folder": self.code(), "trigger": "sqs",
                                           "trigger_queue": QUEUE})
        o = ops(d)
        self.assertEqual(o.count("iam.attach_role_policy"), 2)
        esm = next(s for s in d.steps if s.get("operation") == "create_event_source_mapping")["params"]
        self.assertEqual(esm["EventSourceArn"], f"arn:aws:sqs:us-east-1:{ACCOUNT}:jobs")

    def test_public_url_needs_confirmation(self):
        d = self.build("lambda_function", {"name": "hook", "source_folder": self.code(), "trigger": "url",
                                           "url_auth": "NONE"})
        perms = [s for s in d.steps if s.get("operation") == "add_permission"]
        self.assertEqual({p["params"]["Action"] for p in perms}, {"lambda:InvokeFunctionUrl", "lambda:InvokeFunction"})
        self.assertTrue(d.destructive)

    def test_api_s3_dynamodb_triggers(self):
        d = self.build("lambda_function", {"name": "api", "source_folder": self.code(), "trigger": "api"})
        self.assertIn("apigatewayv2.create_api", ops(d))
        perm = next(s for s in d.steps if s.get("operation") == "add_permission")["params"]
        self.assertIn("{{api.ApiId}}", perm["SourceArn"])
        d = self.build("lambda_function", {"name": "thumb", "source_folder": self.code(), "trigger": "s3",
                                           "trigger_bucket": "kintsugi-data", "trigger_suffix": ".jpg"})
        self.assertIn("s3.put_bucket_notification_configuration", ops(d))
        d = self.build("lambda_function", {"name": "ddb", "source_folder": self.code(), "trigger": "dynamodb"})
        esm = next(s for s in d.steps if s.get("operation") == "create_event_source_mapping")["params"]
        self.assertEqual(esm["StartingPosition"], "LATEST")

    def test_custom_settings_and_alias(self):
        d = self.build("lambda_function", {"name": "full", "source_folder": self.code(), "settings": "custom",
                                           "env_vars": "MODE=prod", "subnets": ["subnet-priv"],
                                           "security_groups": ["sg-web"], "alias": "yes", "provisioned": 2,
                                           "architecture": "arm64"})
        fn = next(s for s in d.steps if s.get("operation") == "create_function")["params"]
        self.assertEqual(fn["Architectures"], ["arm64"])
        self.assertEqual(fn["VpcConfig"]["SubnetIds"], ["subnet-priv"])
        self.assertIn("lambda.put_provisioned_concurrency_config", ops(d))
        self.assertIn(("iam", "attach_role_policy"), [(s.get("service"), s.get("operation")) for s in d.steps])

    def test_container_image_lambda(self):
        d = self.build("lambda_function", {"name": "img", "package": "image", "source_folder": self.app()})
        build = next(s for s in d.steps if s.get("tool") == "docker")
        self.assertIn("--provenance=false", build["args"])
        fn = next(s for s in d.steps if s.get("operation") == "create_function")["params"]
        self.assertEqual(fn["PackageType"], "Image")
        self.assertNotIn("Runtime", fn)

    def test_manage_release_canary_and_configure(self):
        d = self.build("lambda_manage", {"function": "hello", "action": "release", "shift_percent": 10})
        upd = next(s for s in d.steps if s.get("operation") == "update_alias")["params"]
        self.assertEqual(upd["RoutingConfig"]["AdditionalVersionWeights"], {"{{ver.Version}}": 0.1})
        d = self.build("lambda_manage", {"function": "hello", "action": "configure", "memory_mb": 512})
        self.assertEqual(d.steps[0]["params"]["MemorySize"], 512)
        self.assertEqual(d.steps[0]["params"]["Environment"]["Variables"], {"MODE": "prod"})
        self.assertEqual(d.steps[0]["undo"]["params"]["MemorySize"], 128)
        d = self.build("lambda_manage", {"function": "hello", "action": "trigger", "trigger": "sns",
                                         "trigger_topic": f"arn:aws:sns:us-east-1:{ACCOUNT}:alerts"})
        self.assertEqual(ops(d), ["lambda.add_permission", "sns.subscribe"])


class TestRouting(unittest.TestCase):
    CASES = {
        "create an application load balancer for my web servers": "load_balancer",
        "create an auto scaling group with cpu scaling": "auto_scaling_group",
        "create a launch template for ubuntu": "launch_template",
        "create a target group for my api": "target_group",
        "create an AMI from my web server": "ami",
        "attach a new 20 GB EBS volume to web-demo": "ebs_volume",
        "take a snapshot of my volume": "ebs_volume",
        "set up cloudfront for my bucket": "cloudfront_distribution",
        "add a lifecycle rule to move my bucket to glacier after 90 days": "s3_bucket",
        "restore my photos from glacier": "s3_objects",
        "create a glacier vault for backups": "glacier_vault",
        "add a security group that allows https": "vpc_resource",
        "create a vpc peering between my two vpcs": "vpc_resource",
        "create a vpc with 2 public subnets": "vpc_network",
        "create an ecr repository with lifecycle rules": "ecr_repository",
        "scale the node group of my eks cluster": "eks_manage",
        "create an eks cluster": "eks_cluster",
        "deploy my dockerfile on ecs fargate": "ecs_fargate_service",
        "publish a new version of lambda hello with an alias": "lambda_manage",
    }

    def test_router_picks_the_recipe(self):
        for text, recipe in self.CASES.items():
            got = router.route(text)
            self.assertEqual((got or (None, {}))[1].get("template"), recipe, text)


class TestNewStepKinds(unittest.TestCase):
    def test_validation_and_render(self):
        ok = [{"kind": "cf_delete", "distribution_id": "E2ABCDEF123456"},
              {"kind": "ami_delete", "image_id": "ami-0123abcd4567ef890"},
              {"kind": "s3_objects", "bucket": "b-1", "prefix": "x/", "action": "restore", "days": 3, "tier": "Bulk"},
              {"kind": "wait_until", "service": "ec2", "operation": "describe_transit_gateways", "params": {},
               "path": "TransitGateways.0.State", "equals": ["available"]}]
        for st in ok:
            local_steps.validate(st)
            self.assertTrue(local_steps.render(st, "us-east-1"))
        bad = [{"kind": "wait_until", "service": "ec2", "operation": "delete_vpc", "params": {}, "path": "A",
                "equals": ["x"]},
               {"kind": "s3_objects", "bucket": "b-1", "action": "explode"},
               {"kind": "ami_delete", "image_id": "nope"}]
        for st in bad:
            with self.assertRaises(local_steps.StepError):
                local_steps.validate(st)
        self.assertTrue(local_steps.is_destructive({"kind": "cf_delete", "distribution_id": "E1"}))

    def test_cf_delete_refuses_foreign_distribution(self):
        from core import aws_steps
        cf = mock.Mock()
        cf.get_distribution_config.return_value = {"DistributionConfig": {"Enabled": True}, "ETag": "E1"}
        cf.get_distribution.return_value = {"Distribution": {"ARN": "arn:aws:cloudfront::1:distribution/E2"}}
        cf.list_tags_for_resource.return_value = {"Tags": {"Items": []}}
        with self.assertRaises(local_steps.StepError):
            aws_steps.run({"kind": "cf_delete", "distribution_id": "E2ABCDEF123456"}, FakeConn({"cloudfront": cf}),
                          "operate", "us-east-1")
        cf.delete_distribution.assert_not_called()

    def test_ami_delete_removes_snapshots(self):
        from core import aws_steps
        ec2 = mock.Mock()
        ec2.describe_images.return_value = {"Images": [{"BlockDeviceMappings": [{"Ebs": {"SnapshotId": "snap-1"}}]}]}
        res = aws_steps.run({"kind": "ami_delete", "image_id": "ami-0123abcd4567ef890"}, FakeConn({"ec2": ec2}),
                            "operate", "us-east-1")
        ec2.deregister_image.assert_called_once_with(ImageId="ami-0123abcd4567ef890")
        ec2.delete_snapshot.assert_called_once_with(SnapshotId="snap-1")
        self.assertIn("1 snapshot", res["summary"])

    def test_wait_until_polls(self):
        from core import aws_steps
        ec2 = mock.Mock()
        ec2.describe_transit_gateways.side_effect = [{"TransitGateways": [{"State": "pending"}]},
                                                     {"TransitGateways": [{"State": "available"}]}]
        with mock.patch("time.sleep"):
            res = aws_steps.run({"kind": "wait_until", "service": "ec2", "operation": "describe_transit_gateways",
                                 "params": {}, "path": "TransitGateways.0.State", "equals": ["available"]},
                                FakeConn({"ec2": ec2}), "operate", "us-east-1")
        self.assertIn("available", res["summary"])


if __name__ == "__main__":
    unittest.main()
