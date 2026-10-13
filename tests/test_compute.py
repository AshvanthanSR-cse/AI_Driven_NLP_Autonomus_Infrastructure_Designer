"""Compute recipes: load balancer, target group, launch template, Auto Scaling, AMI, EBS (offline, fake AWS)."""
import unittest

from core import scripts, templates
from tests.fakes import FakeConn
from tests.test_recipes import ACCOUNT, FakeEc2, FakeIam, FakeLambda, FakeSts, RecipeTest
from tests.test_templates import FakeSsm

LB_ARN = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/web/50dc6c495c0c9188"
TG_ARN = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:targetgroup/api-tg/73e2d6bc24d8a067"


class FakeEc2Compute(FakeEc2):
    def can_paginate(self, op):
        return False

    def describe_instances(self, Filters=None):
        return {"Reservations": [{"Instances": [
            {"InstanceId": "i-0aaaaaaaaaaaaaaa1", "State": {"Name": "running"}, "VpcId": "vpc-111",
             "Placement": {"AvailabilityZone": "us-east-1a"}, "InstanceType": "t3.micro",
             "SecurityGroups": [{"GroupId": "sg-web"}], "Tags": [{"Key": "Name", "Value": "web-demo"}]}]}]}

    def describe_images(self, ImageIds=None, Owners=None):
        if Owners == ["self"]:
            return {"Images": [{"ImageId": "ami-0123abcd4567ef890", "Name": "web-golden", "State": "available",
                                "CreationDate": "2026-10-01T00:00:00Z", "RootDeviceName": "/dev/xvda",
                                "BlockDeviceMappings": [{"Ebs": {"SnapshotId": "snap-0aaa1111bbbb2222c"}}]}]}
        return {"Images": [{"ImageId": ImageIds[0], "RootDeviceName": "/dev/xvda", "Name": "al2023",
                            "Architecture": "x86_64", "PlatformDetails": "Linux/UNIX"}]}

    def describe_regions(self):
        return {"Regions": [{"RegionName": r} for r in ("us-east-1", "ap-south-1", "eu-west-1")]}

    def describe_volumes(self):
        return {"Volumes": [
            {"VolumeId": "vol-0aaa1111bbbb2222c", "Size": 8, "VolumeType": "gp3", "AvailabilityZone": "us-east-1a",
             "State": "in-use", "Attachments": [{"InstanceId": "i-0aaaaaaaaaaaaaaa1", "Device": "/dev/xvda"}]},
            {"VolumeId": "vol-0bbb2222cccc3333d", "Size": 20, "VolumeType": "gp2", "AvailabilityZone": "us-east-1a",
             "State": "available", "Attachments": []}]}

    def describe_snapshots(self, OwnerIds=None):
        return {"Snapshots": [{"SnapshotId": "snap-0aaa1111bbbb2222c", "VolumeId": "vol-0aaa1111bbbb2222c",
                               "VolumeSize": 8, "State": "completed", "StorageTier": "standard",
                               "StartTime": "2026-10-01"}]}

    def describe_launch_templates(self):
        return {"LaunchTemplates": [{"LaunchTemplateId": "lt-0abc1234def567890", "LaunchTemplateName": "web-lt",
                                     "LatestVersionNumber": 3, "DefaultVersionNumber": 1}]}

    def describe_vpcs(self):
        return {"Vpcs": [{"VpcId": "vpc-111", "CidrBlock": "10.0.0.0/16", "Tags": [{"Key": "Name", "Value": "main"}]}]}


class FakeElb:
    def describe_load_balancers(self):
        return {"LoadBalancers": [{"LoadBalancerArn": LB_ARN, "LoadBalancerName": "web", "DNSName": "web-1.elb.amazonaws.com",
                                   "Type": "application", "Scheme": "internet-facing", "VpcId": "vpc-111"}]}

    def describe_target_groups(self):
        return {"TargetGroups": [{"TargetGroupArn": TG_ARN, "TargetGroupName": "api-tg", "TargetType": "instance",
                                  "Port": 8080, "Protocol": "HTTP", "VpcId": "vpc-111", "LoadBalancerArns": [LB_ARN]}]}

    def describe_listeners(self, LoadBalancerArn):
        return {"Listeners": [{"ListenerArn": LB_ARN.replace("loadbalancer", "listener") + "/1a2b3c", "Port": 80,
                               "Protocol": "HTTP"}]}

    def describe_rules(self, ListenerArn):
        return {"Rules": [{"Priority": "default"}, {"Priority": "5"}]}


class FakeAsg:
    def describe_auto_scaling_groups(self, **kw):
        return {"AutoScalingGroups": [{"AutoScalingGroupName": "web-asg", "MinSize": 1, "MaxSize": 3,
                                       "DesiredCapacity": 2, "Instances": [{}, {}],
                                       "LaunchTemplate": {"LaunchTemplateId": "lt-0abc1234def567890",
                                                          "LaunchTemplateName": "web-lt"}}]}


class FakeIamProfiles(FakeIam):
    def list_instance_profiles(self):
        return {"InstanceProfiles": []}


class FakeAcm:
    def list_certificates(self, CertificateStatuses=None):
        return {"CertificateSummaryList": [{"CertificateArn": f"arn:aws:acm:us-east-1:{ACCOUNT}:certificate/abcd-1234",
                                            "DomainName": "shop.example.com"}]}


class FakeLambdaList(FakeLambda):
    def list_functions(self):
        return {"Functions": [{"FunctionName": "hello", "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:hello",
                               "Runtime": "python3.12"}]}


class FakeSns:
    def list_topics(self):
        return {"Topics": [{"TopicArn": f"arn:aws:sns:us-east-1:{ACCOUNT}:alerts"}]}


def conn():
    return FakeConn({"ec2": FakeEc2Compute(), "ssm": FakeSsm(), "sts": FakeSts(), "iam": FakeIamProfiles(),
                     "elbv2": FakeElb(), "autoscaling": FakeAsg(), "acm": FakeAcm(), "lambda": FakeLambdaList(),
                     "sns": FakeSns()})


def ops(d):
    return [s.get("kind") or f"{s['service']}.{s['operation']}" for s in d.steps]


class ComputeTest(RecipeTest):
    def build(self, template, inputs, c=None):
        return super().build(template, inputs, c or conn())


class TestLoadBalancer(ComputeTest):
    def test_alb_with_instance_targets_and_rules(self):
        d = self.build("load_balancer", {"name": "shop", "targets_instances": ["i-0aaaaaaaaaaaaaaa1"],
                                         "subnets": ["subnet-pub", "subnet-pub2"], "path_rules": "/api/*=api-tg"})
        o = ops(d)
        self.assertEqual(o[:3], ["ec2.create_security_group", "ec2.authorize_security_group_ingress",
                                 "elbv2.create_load_balancer"])
        self.assertIn("elbv2.create_target_group", o)
        self.assertIn("elbv2.register_targets", o)
        self.assertIn("elbv2.create_rule", o)
        self.assertEqual(o[-1], "check")
        sg_rule = [s for s in d.steps if s.get("operation") == "authorize_security_group_ingress"][-1]
        self.assertEqual(sg_rule["params"]["GroupId"], "sg-web")
        self.assertEqual(sg_rule["params"]["IpPermissions"][0]["UserIdGroupPairs"][0]["GroupId"], "{{lbsg.GroupId}}")
        lb = next(s for s in d.steps if s.get("operation") == "create_load_balancer")
        self.assertEqual(lb["undo"]["operation"], "delete_load_balancer")

    def test_https_with_redirect(self):
        d = self.build("load_balancer", {"name": "secure", "https": "yes", "subnets": ["subnet-pub", "subnet-pub2"]})
        listeners = [s["params"] for s in d.steps if s.get("operation") == "create_listener"]
        self.assertEqual([x["Port"] for x in listeners], [443, 80])
        self.assertEqual(listeners[1]["DefaultActions"][0]["Type"], "redirect")
        self.assertNotIn("check", ops(d))

    def test_alb_needs_two_zones(self):
        q = templates.plan("load_balancer", {"name": "x", "subnets": ["subnet-pub"]}, conn())
        self.assertIn("2 different availability zones", next(x.error for x in q.questions if x.key == "subnets"))

    def test_lambda_target(self):
        d = self.build("load_balancer", {"name": "fn", "target_type": "lambda", "target_lambda": "hello",
                                         "subnets": ["subnet-pub", "subnet-pub2"]})
        self.assertIn("lambda.add_permission", ops(d))
        tg = next(s for s in d.steps if s.get("operation") == "create_target_group")["params"]
        self.assertEqual(tg["TargetType"], "lambda")
        self.assertNotIn("Port", tg)

    def test_nlb(self):
        d = self.build("load_balancer", {"name": "tcp", "lb_type": "network", "port": 5432,
                                         "subnets": ["subnet-pub"]})
        lb = next(s for s in d.steps if s.get("operation") == "create_load_balancer")["params"]
        self.assertEqual(lb["Type"], "network")
        ln = next(s for s in d.steps if s.get("operation") == "create_listener")["params"]
        self.assertEqual((ln["Protocol"], ln["Port"]), ("TCP", 5432))

    def test_custom_attributes_and_deletion_protection(self):
        d = self.build("load_balancer", {"name": "c", "subnets": ["subnet-pub", "subnet-pub2"], "settings": "custom",
                                         "deletion_protection": "yes", "stickiness": "yes"})
        attrs = next(s for s in d.steps if s.get("operation") == "modify_load_balancer_attributes")
        self.assertEqual(attrs["undo"]["params"]["Attributes"][0]["Value"], "false")
        tga = next(s for s in d.steps if s.get("operation") == "modify_target_group_attributes")
        keys = {a["Key"] for a in tga["params"]["Attributes"]}
        self.assertIn("stickiness.enabled", keys)


class TestTargetGroup(ComputeTest):
    def test_with_listener_rule(self):
        listener = LB_ARN.replace("loadbalancer", "listener") + "/1a2b3c"
        d = self.build("target_group", {"name": "img", "listener": listener, "condition": "/img/*"})
        rule = next(s for s in d.steps if s.get("operation") == "create_rule")["params"]
        self.assertEqual(rule["Priority"], 6)
        self.assertEqual(rule["Conditions"][0]["PathPatternConfig"]["Values"], ["/img/*"])


class TestLaunchTemplate(ComputeTest):
    def test_create_with_nginx_and_ssm(self):
        d = self.build("launch_template", {"name": "web", "image": "amazon-linux-2023", "instance_profile": "ssm"})
        lt = next(s for s in d.steps if s.get("operation") == "create_launch_template")["params"]
        data = lt["LaunchTemplateData"]
        import base64
        self.assertIn("nginx", base64.b64decode(data["UserData"]).decode())
        self.assertEqual(data["IamInstanceProfile"], {"Name": "web-ssm"})
        self.assertEqual(data["MetadataOptions"]["HttpTokens"], "required")
        self.assertIn("iam.create_instance_profile", ops(d))

    def test_arm_mismatch_and_big_size(self):
        q = templates.plan("launch_template", {"name": "web", "image": "amazon-linux-2023", "instance_type": "m5.24xlarge"},
                           conn())
        self.assertIn("2xlarge", next(x.error for x in q.questions if x.key == "instance_type"))
        with self.assertRaises(templates.TemplateError):
            self.build("launch_template", {"name": "web", "image": "amazon-linux-2023", "instance_type": "t4g.micro"})

    def test_own_ami_and_new_version(self):
        d = self.build("launch_template", {"action": "new_version", "template": "lt-0abc1234def567890",
                                           "image": "ami-0123abcd4567ef890"})
        self.assertEqual(ops(d)[-2:], ["ec2.create_launch_template_version", "ec2.modify_launch_template"])
        self.assertEqual(d.steps[-1]["params"]["DefaultVersion"], "4")


class TestAutoScaling(ComputeTest):
    def test_create_with_new_alb_and_cpu_scaling(self):
        d = self.build("auto_scaling_group", {"name": "web", "image": "amazon-linux-2023",
                                              "subnets": ["subnet-pub", "subnet-pub2"],
                                              "scheduled": "daily 09:00 min=2 desired=2 max=4; weekdays 20:00 desired=0 min=0"})
        o = ops(d)
        self.assertLess(o.index("elbv2.create_load_balancer"), o.index("autoscaling.create_auto_scaling_group"))
        asg = next(s for s in d.steps if s.get("operation") == "create_auto_scaling_group")
        self.assertEqual(asg["params"]["TargetGroupARNs"], ["{{tg.TargetGroups.0.TargetGroupArn}}"])
        self.assertEqual(asg["undo"]["wait"]["waiter"], "group_not_exists")
        pol = next(s for s in d.steps if s.get("operation") == "put_scaling_policy")["params"]
        self.assertEqual(pol["TargetTrackingConfiguration"]["PredefinedMetricSpecification"]["PredefinedMetricType"],
                         "ASGAverageCPUUtilization")
        sched = [s["params"] for s in d.steps if s.get("operation") == "put_scheduled_update_group_action"]
        self.assertEqual(sched[0]["Recurrence"], "0 9 * * *")
        self.assertEqual(sched[1]["Recurrence"], "0 20 * * 1-5")
        sg_rule = next(s for s in d.steps if s.get("operation") == "authorize_security_group_ingress"
                       and s["params"]["GroupId"] == "{{ltsg.GroupId}}")
        pairs = [p for p in sg_rule["params"]["IpPermissions"] if p.get("UserIdGroupPairs")]
        self.assertEqual(pairs[0]["UserIdGroupPairs"][0]["GroupId"], "{{lbsg.GroupId}}")
        self.assertEqual(o[-1], "check")

    def test_requests_scaling_existing_tg_and_mixed(self):
        d = self.build("auto_scaling_group", {"name": "api", "launch_template": "lt-0abc1234def567890",
                                              "subnets": ["subnet-pub", "subnet-pub2"], "load_balancing": "existing",
                                              "target_groups": [TG_ARN], "scaling": "requests", "capacity": "mixed"})
        pol = next(s for s in d.steps if s.get("operation") == "put_scaling_policy")["params"]
        label = pol["TargetTrackingConfiguration"]["PredefinedMetricSpecification"]["ResourceLabel"]
        self.assertEqual(label, "app/web/50dc6c495c0c9188/targetgroup/api-tg/73e2d6bc24d8a067")
        asg = next(s for s in d.steps if s.get("operation") == "create_auto_scaling_group")["params"]
        self.assertIn("MixedInstancesPolicy", asg)

    def test_step_and_predictive(self):
        d = self.build("auto_scaling_group", {"name": "s", "image": "amazon-linux-2023", "load_balancing": "none",
                                              "subnets": ["subnet-pub"], "scaling": "step_cpu"})
        self.assertEqual(ops(d).count("cloudwatch.put_metric_alarm"), 2)
        d = self.build("auto_scaling_group", {"name": "p", "image": "amazon-linux-2023", "load_balancing": "none",
                                              "subnets": ["subnet-pub"], "scaling": "predictive"})
        pol = next(s for s in d.steps if s.get("operation") == "put_scaling_policy")["params"]
        self.assertEqual(pol["PolicyType"], "PredictiveScaling")

    def test_update_and_refresh(self):
        d = self.build("auto_scaling_group", {"action": "update", "group": "web-asg", "new_desired": 3,
                                              "new_max": 5, "start_refresh": "yes"})
        self.assertEqual(ops(d), ["autoscaling.update_auto_scaling_group", "autoscaling.start_instance_refresh"])
        self.assertEqual(d.steps[0]["undo"]["params"]["DesiredCapacity"], 2)

    def test_bad_sizes(self):
        q = templates.plan("auto_scaling_group", {"name": "x", "min_size": 2, "max_size": 3, "desired": 5}, conn())
        self.assertIn("between min", next(x.error for x in q.questions if x.key == "desired"))


class TestAmiEbs(ComputeTest):
    def test_create_ami_teardown_deletes_snapshots(self):
        d = self.build("ami", {"action": "create", "instance": "i-0aaaaaaaaaaaaaaa1"})
        self.assertEqual(d.steps[0]["undo"]["kind"], "ami_delete")
        self.assertFalse(d.steps[0]["params"]["NoReboot"])

    def test_share_copy_deregister(self):
        d = self.build("ami", {"action": "share", "ami": "ami-0123abcd4567ef890", "accounts": "210987654321"})
        self.assertEqual(ops(d), ["ec2.modify_image_attribute", "ec2.modify_snapshot_attribute"])
        d = self.build("ami", {"action": "copy", "ami": "ami-0123abcd4567ef890", "dest_region": "eu-west-1"})
        self.assertEqual(d.steps[0]["region"], "eu-west-1")
        d = self.build("ami", {"action": "deregister", "ami": "ami-0123abcd4567ef890"})
        self.assertTrue(d.destructive)

    def test_public_ami_blocked(self):
        with self.assertRaises(scripts.ScriptError):
            scripts.validate_step({"service": "ec2", "operation": "modify_image_attribute",
                                   "params": {"ImageId": "ami-0123abcd4567ef890",
                                              "LaunchPermission": {"Add": [{"Group": "all"}]}}})

    def test_create_and_attach_volume(self):
        d = self.build("ebs_volume", {"action": "create", "attach_to": "i-0aaaaaaaaaaaaaaa1", "size_gb": 20})
        self.assertEqual(ops(d), ["ec2.create_volume", "ec2.attach_volume"])
        self.assertEqual(d.steps[0]["params"]["AvailabilityZone"], "us-east-1a")

    def test_wrong_zone_rejected(self):
        q = templates.plan("ebs_volume", {"action": "create", "attach_to": "i-0aaaaaaaaaaaaaaa1", "az": "us-east-1b"},
                           conn())
        self.assertIn("same zone", next(x.error for x in q.questions if x.key == "az"))

    def test_modify_cannot_shrink_and_schedule(self):
        q = templates.plan("ebs_volume", {"action": "modify", "volume": "vol-0bbb2222cccc3333d", "size_gb": 10}, conn())
        self.assertIn("between 20", next(x.error for x in q.questions if x.key == "size_gb"))
        d = self.build("ebs_volume", {"action": "schedule", "time": "10:00"})
        pol = d.steps[-1]["params"]["PolicyDetails"]["Schedules"][0]["CreateRule"]
        self.assertEqual(pol["Times"], ["04:30"])

    def test_snapshot_archive_restore(self):
        for action in ("snapshot", "archive", "copy_snapshot", "delete_snapshot", "default_encryption"):
            inputs = {"action": action, "volume": "vol-0aaa1111bbbb2222c", "snapshot": "snap-0aaa1111bbbb2222c",
                      "dest_region": "eu-west-1"}
            self.build("ebs_volume", inputs)


if __name__ == "__main__":
    unittest.main()
