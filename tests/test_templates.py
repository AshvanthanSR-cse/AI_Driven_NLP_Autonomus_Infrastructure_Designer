"""Task templates: questions, live options, validation, must-ask guard, generated steps, teardown."""
import unittest
from unittest import mock

from core import scripts, templates, tools
from core.scripts import ScriptDraft
from core.templates import TaskQuestions
from core.tools import ToolContext
from tests.fakes import FakeConn


class FakeEc2Infra:
    """Read side for options + write side that returns realistic create responses."""

    def __init__(self):
        self.calls = []
        self.n = 0

    def describe_availability_zones(self, Filters=None):
        return {"AvailabilityZones": [{"ZoneName": z, "ZoneType": "availability-zone"}
                                      for z in ("us-east-1a", "us-east-1b", "us-east-1c")]}

    def describe_vpcs(self):
        return {"Vpcs": [{"VpcId": "vpc-111", "Tags": [{"Key": "Name", "Value": "main"}]}]}

    def describe_subnets(self):
        return {"Subnets": [
            {"SubnetId": "subnet-pub", "CidrBlock": "10.0.0.0/24", "AvailabilityZone": "us-east-1a",
             "VpcId": "vpc-111", "MapPublicIpOnLaunch": True},
            {"SubnetId": "subnet-priv", "CidrBlock": "10.0.2.0/24", "AvailabilityZone": "us-east-1b",
             "VpcId": "vpc-111", "MapPublicIpOnLaunch": False}]}

    def describe_security_groups(self, Filters=None):
        return {"SecurityGroups": [{"GroupId": "sg-web", "GroupName": "web", "Description": "web", "VpcId": "vpc-111"}]}

    def describe_key_pairs(self):
        return {"KeyPairs": [{"KeyName": "my-key"}]}

    def describe_images(self, ImageIds):
        return {"Images": [{"ImageId": ImageIds[0], "RootDeviceName": "/dev/xvda", "Name": "al2023"}]}

    def _id(self, prefix):
        self.n += 1
        return f"{prefix}-{self.n:04d}"

    def __getattr__(self, op):
        def call(**params):
            self.calls.append((op, params))
            ids = {"create_vpc": lambda: {"Vpc": {"VpcId": self._id("vpc")}},
                   "create_internet_gateway": lambda: {"InternetGateway": {"InternetGatewayId": self._id("igw")}},
                   "create_subnet": lambda: {"Subnet": {"SubnetId": self._id("subnet")}},
                   "create_route_table": lambda: {"RouteTable": {"RouteTableId": self._id("rtb")}},
                   "associate_route_table": lambda: {"AssociationId": self._id("rtbassoc")},
                   "allocate_address": lambda: {"AllocationId": self._id("eipalloc")},
                   "create_nat_gateway": lambda: {"NatGateway": {"NatGatewayId": self._id("nat")}}}
            return ids.get(op, lambda: {})()
        return call

    def get_waiter(self, name):
        calls = self.calls
        return mock.Mock(wait=lambda **kw: calls.append((f"wait:{name}", kw)))


class FakeSsm:
    def get_parameter(self, Name):
        return {"Parameter": {"Value": "ami-0c7d68785ec07306c"}}


def conn():
    return FakeConn({"ec2": FakeEc2Infra(), "ssm": FakeSsm()})


FULL_VPC = {"name": "lab", "public_subnets": 2, "private_subnets": 2, "cidr": "10.20.0.0/16",
            "azs": ["us-east-1a", "us-east-1b"], "nat_gateway": "yes"}


class TestVpcQuestions(unittest.TestCase):
    def test_asks_for_missing_details_with_live_options(self):
        q = templates.plan("vpc_network", {"public_subnets": 2, "private_subnets": 2}, conn(), confirmed=set())
        self.assertIsInstance(q, TaskQuestions)
        keys = [x.key for x in q.questions]
        for k in ("name", "cidr", "azs", "nat_gateway"):
            self.assertIn(k, keys)
        azq = next(x for x in q.questions if x.key == "azs")
        self.assertEqual([o["value"] for o in azq.options], ["us-east-1a", "us-east-1b", "us-east-1c"])
        self.assertEqual(azq.default, ["us-east-1a", "us-east-1b"])
        self.assertEqual(next(x for x in q.questions if x.key == "cidr").default, "10.0.0.0/16")

    def test_llm_guess_for_key_decision_is_only_a_suggestion(self):
        """The model filled cidr/nat itself: they must still be confirmed by the user."""
        guessed = {**FULL_VPC}
        confirmed = set(guessed) - templates.must_ask_keys("vpc_network")
        q = templates.plan("vpc_network", guessed, conn(), confirmed)
        self.assertIsInstance(q, TaskQuestions)
        asked = {x.key: x.default for x in q.questions}
        self.assertEqual(asked["cidr"], "10.20.0.0/16")
        self.assertIn("nat_gateway", asked)

    def test_bad_answers_come_back_with_errors(self):
        for cidr, msg in [("8.8.8.0/24", "private"), ("10.0.0.0/8", "between"), ("10.0.0.1/16", "host bits"),
                          ("10.0.0.0/24", None)]:
            q = templates.plan("vpc_network", {**FULL_VPC, "cidr": cidr}, conn())
            if msg is None:
                self.assertIsInstance(q, ScriptDraft, cidr)
                continue
            err = next(x.error for x in q.questions if x.key == "cidr")
            self.assertIn(msg, err, cidr)

    def test_nat_question_skipped_without_private_subnets(self):
        q = templates.plan("vpc_network", {"public_subnets": 2, "private_subnets": 0}, conn(), confirmed=set())
        self.assertNotIn("nat_gateway", [x.key for x in q.questions])

    def test_cidr_lists_for_subnet_counts_become_counts(self):
        """The model sent subnet CIDR lists where counts are expected: no crash, the counts are used."""
        q = templates.plan("vpc_network", {"name": "my-vpc", "public_subnets": ["10.0.1.0/24"],
                                           "private_subnets": ["10.0.2.0/24"], "cidr": "10.0.0.0/16",
                                           "azs": ["us-east-1a", "us-east-1b"]}, conn(), confirmed={"name"})
        self.assertIsInstance(q, TaskQuestions)
        self.assertEqual((q.inputs["public_subnets"], q.inputs["private_subnets"]), (1, 1))
        self.assertIn("nat_gateway", [x.key for x in q.questions])
        draft = templates.plan("vpc_network", {**FULL_VPC, "public_subnets": ["a"], "private_subnets": "1",
                                               "nat_gateway": "no"}, conn())
        self.assertIsInstance(draft, ScriptDraft)

    def test_non_numeric_count_is_asked_with_an_error(self):
        q = templates.plan("vpc_network", {**FULL_VPC, "public_subnets": "two", "private_subnets": {"n": 1}}, conn())
        errors = {x.key: x.error for x in q.questions}
        self.assertIn("whole number", errors["public_subnets"])
        self.assertIn("whole number", errors["private_subnets"])


class TestVpcScript(unittest.TestCase):
    def setUp(self):
        self.draft = templates.plan("vpc_network", FULL_VPC, conn())

    def test_steps_are_valid_aws_calls(self):
        self.assertIsInstance(self.draft, ScriptDraft)
        for st in self.draft.steps:
            scripts.validate_step(st)
            if st.get("undo"):
                scripts.check_write_allowed(st["undo"]["service"], st["undo"]["operation"], {})
        ops = [s["operation"] for s in self.draft.steps]
        self.assertEqual(ops.count("create_subnet"), 4)
        self.assertEqual(ops.count("create_route_table"), 2)
        for op in ("create_vpc", "create_internet_gateway", "attach_internet_gateway", "allocate_address",
                   "create_nat_gateway"):
            self.assertIn(op, ops)
        self.assertFalse(self.draft.destructive)

    def test_subnet_ranges_computed_by_code(self):
        cidrs = [s["params"]["CidrBlock"] for s in self.draft.steps if s["operation"] == "create_subnet"]
        self.assertEqual(cidrs, ["10.20.0.0/24", "10.20.1.0/24", "10.20.2.0/24", "10.20.3.0/24"])
        azs = [s["params"]["AvailabilityZone"] for s in self.draft.steps if s["operation"] == "create_subnet"]
        self.assertEqual(azs, ["us-east-1a", "us-east-1b", "us-east-1a", "us-east-1b"])

    def test_tags_and_cost_note(self):
        vpc = self.draft.steps[0]["params"]["TagSpecifications"][0]["Tags"]
        keys = {t["Key"] for t in vpc}
        self.assertTrue({"Name", "Project", "ExpiresAt"} <= keys)
        self.assertTrue(any("NAT gateway" in n and "/month" in n for n in self.draft.notes))
        self.assertIn("NOTE: COST", scripts.render_cli(self.draft.steps, "us-east-1", self.draft.notes))


class TestRunAndTeardown(unittest.TestCase):
    def test_placeholders_waits_and_teardown(self):
        draft = templates.plan("vpc_network", FULL_VPC, conn())
        c = conn()
        ec2 = c.clients["ec2"]
        row = {"id": 9, "title": draft.title, "request": "vpc", "risk": "operate", "destructive": False,
               "region": "us-east-1", "status": "approved", "approved_at": None, "steps": draft.steps}
        saved = {}
        with mock.patch.object(scripts, "get_script", return_value=row), \
                mock.patch.object(scripts, "_set"), mock.patch.object(scripts.audit, "log_action"), \
                mock.patch.object(scripts, "save_draft", side_effect=lambda o, r, d: saved.update(d=d) or {"id": 10}):
            res = scripts.run_script("tester", 9, c)
        self.assertTrue(res["ok"], res["log"])
        calls = dict((op, p) for op, p in ec2.calls if not op.startswith("describe"))
        self.assertEqual(calls["create_subnet"]["VpcId"], "vpc-0001")
        self.assertTrue(calls["create_nat_gateway"]["SubnetId"].startswith("subnet-"))
        self.assertIn("wait:nat_gateway_available", [op for op, _ in ec2.calls])
        self.assertIn(("ec2", "operate"), c.requested)
        td = saved["d"]
        ops = [s["operation"] for s in td.steps]
        self.assertEqual(ops[-1], "delete_vpc")
        self.assertLess(ops.index("delete_nat_gateway"), ops.index("release_address"))
        self.assertLess(ops.index("detach_internet_gateway"), ops.index("delete_internet_gateway"))
        self.assertLess(ops.index("delete_nat_gateway"), ops.index("delete_subnet"))
        self.assertTrue(td.destructive)
        self.assertNotIn("{{", str(td.steps))
        self.assertIn("Teardown script #10", res["log"])

    def test_partial_failure_still_offers_teardown(self):
        draft = templates.plan("vpc_network", {**FULL_VPC, "nat_gateway": "no"}, conn())
        c = conn()
        ec2 = c.clients["ec2"]
        original = ec2.__getattr__

        def failing(op):
            if op == "create_subnet":
                def boom(**kw):
                    raise RuntimeError("quota exceeded")
                return boom
            return original(op)
        ec2.__class__ = type("Failing", (FakeEc2Infra,), {"__getattr__": lambda self, op: failing(op)})
        row = {"id": 9, "title": draft.title, "request": "vpc", "risk": "operate", "destructive": False,
               "region": "us-east-1", "status": "approved", "approved_at": None, "steps": draft.steps}
        saved = {}
        with mock.patch.object(scripts, "get_script", return_value=row), \
                mock.patch.object(scripts, "_set"), mock.patch.object(scripts.audit, "log_action"), \
                mock.patch.object(scripts, "save_draft", side_effect=lambda o, r, d: saved.update(d=d) or {"id": 11}):
            res = scripts.run_script("tester", 9, c)
        self.assertFalse(res["ok"])
        self.assertEqual([s["operation"] for s in saved["d"].steps],
                         ["detach_internet_gateway", "delete_internet_gateway", "delete_vpc"])
        self.assertIn("clean up after the failure", res["log"])


FULL_EC2 = {"name": "web1", "purpose": "web", "os": "amazon-linux-2023", "instance_type": "t3.micro",
            "subnet_id": "subnet-pub", "security_group": "new", "admin_cidr": "203.0.113.5/32",
            "key_name": "my-key", "volume_gb": 8}


class TestEc2Template(unittest.TestCase):
    def test_questions_offer_real_subnets_and_sgs(self):
        with mock.patch.object(templates.Env, "my_ip", return_value="203.0.113.5"):
            q = templates.plan("ec2_instance", {"subnet_id": "subnet-pub"}, conn(), confirmed={"subnet_id"})
        by = {x.key: x for x in q.questions}
        self.assertNotIn("subnet_id", by)
        self.assertIn("purpose", by)
        self.assertIn("os", by)
        self.assertEqual([o["value"] for o in by["security_group"].options], ["new", "sg-web"])

    def test_admin_ip_defaults_to_my_ip_and_blocks_open_world(self):
        with mock.patch.object(templates.Env, "my_ip", return_value="203.0.113.5"):
            q = templates.plan("ec2_instance", {**FULL_EC2, "admin_cidr": None}, conn())
            self.assertEqual(next(x for x in q.questions if x.key == "admin_cidr").default, "203.0.113.5/32")
            q = templates.plan("ec2_instance", {**FULL_EC2, "admin_cidr": "0.0.0.0/0"}, conn())
            self.assertIn("too wide", next(x for x in q.questions if x.key == "admin_cidr").error)

    def test_no_subnets_explains_what_to_do(self):
        c = conn()
        c.clients["ec2"].describe_subnets = lambda: {"Subnets": []}
        q = templates.plan("ec2_instance", {}, c, confirmed=set())
        from core.prereqs import PrereqReport
        self.assertIsInstance(q, PrereqReport)
        self.assertEqual([i.key for i in q.missing], ["subnets"])
        self.assertIn("Create a VPC", q.missing[0].how)

    def test_blocks_big_instances_and_unknown_subnet(self):
        q = templates.plan("ec2_instance", {**FULL_EC2, "instance_type": "m5.24xlarge", "subnet_id": "subnet-nope"}, conn())
        errs = {x.key: x.error for x in q.questions}
        self.assertIn("blocked", errs["instance_type"])
        self.assertIn("not one of", errs["subnet_id"])

    def test_script(self):
        d = templates.plan("ec2_instance", FULL_EC2, conn())
        self.assertIsInstance(d, ScriptDraft)
        for st in d.steps:
            scripts.validate_step(st)
        ops = [s["operation"] for s in d.steps]
        self.assertEqual(ops, ["create_security_group", "authorize_security_group_ingress", "run_instances"])
        perms = d.steps[1]["params"]["IpPermissions"]
        self.assertEqual({(p["FromPort"], p["IpRanges"][0]["CidrIp"]) for p in perms},
                         {(22, "203.0.113.5/32"), (80, "0.0.0.0/0"), (443, "0.0.0.0/0")})
        run = d.steps[2]["params"]
        self.assertEqual(run["ImageId"], "ami-0c7d68785ec07306c")
        self.assertEqual(run["KeyName"], "my-key")
        self.assertEqual(run["MetadataOptions"], {"HttpTokens": "required"})
        tags = {t["Key"]: t["Value"] for t in run["TagSpecifications"][0]["Tags"]}
        self.assertEqual(tags["Env"], "demo")

    def test_windows_uses_rdp_and_30gb(self):
        d = templates.plan("ec2_instance", {**FULL_EC2, "os": "windows-2022", "volume_gb": 30, "purpose": "admin"}, conn())
        self.assertEqual(d.steps[1]["params"]["IpPermissions"][0]["FromPort"], 3389)
        q = templates.plan("ec2_instance", {**FULL_EC2, "os": "windows-2022", "volume_gb": 8}, conn())
        self.assertIn("between 30", next(x for x in q.questions if x.key == "volume_gb").error)


class TestPlanTaskTool(unittest.TestCase):
    def test_tool_returns_questions_then_script_after_answers(self):
        c = conn()
        ctx = ToolContext(conn=c, request="Create a VPC with 2 public and 2 private subnets and a NAT gateway")
        args = tools.validate_args("plan_task", {"template": "vpc_network",
                                                 "inputs": {"public_subnets": 2, "private_subnets": 2, "nat_gateway": "yes"}})
        with mock.patch.object(tools.audit, "log_action"):
            first = tools.create_script("plan_task", args, ctx)
        self.assertIn("questions", first)
        pending = first["questions"]
        ctx2 = ToolContext(conn=c, request="answers", pending_task=pending)
        args2 = tools.validate_args("plan_task", {"template": "vpc_network", "inputs": {
            "cidr": "10.20.0.0/16", "name": "lab", "azs": ["us-east-1a", "us-east-1b"], "nat_gateway": "yes"}})
        with mock.patch.object(tools.audit, "log_action"), \
                mock.patch.object(tools.scripts, "save_draft", return_value={"id": 5, "title": "t", "destructive": False, "risk": "operate"}) as save:
            second = tools.create_script("plan_task", args2, ctx2)
        self.assertEqual(second["id"], 5)
        draft = save.call_args[0][2]
        self.assertEqual(sum(s["operation"] == "create_subnet" for s in draft.steps), 4)


if __name__ == "__main__":
    unittest.main()


class TestAwsErrorText(unittest.TestCase):
    def test_clock_skew_explained(self):
        from botocore.exceptions import ClientError
        e = ClientError({"Error": {"Code": "RequestTimeTooSkewed",
                                   "Message": "The difference between the request time and the current time is too large."}},
                        "ListBuckets")
        self.assertIn("clock", templates.audit_error(e))
        e = ClientError({"Error": {"Code": "SignatureDoesNotMatch", "Message": "Signature expired: 2026..."}},
                        "GetCallerIdentity")
        self.assertIn("clock", templates.audit_error(e))

    def test_other_errors_stay_short(self):
        from botocore.exceptions import ClientError
        e = ClientError({"Error": {"Code": "SignatureDoesNotMatch", "Message": "The secret key is wrong"}}, "X")
        self.assertEqual(templates.audit_error(e), "SignatureDoesNotMatch")
        self.assertEqual(templates.audit_error(ValueError("x")), "ValueError")


class TestPlannerRelevance(unittest.TestCase):
    def test_unanswered_choice_uses_its_default_for_later_questions(self):
        from tests.test_infra_recipes import conn as infra_conn
        q = templates.plan("s3_bucket", {}, infra_conn(), confirmed=set())
        self.assertIn("name", [x.key for x in q.questions])

    def test_advanced_value_switches_settings_to_custom(self):
        from tests.test_infra_recipes import conn as infra_conn
        q = templates.plan("ecs_fargate_service", {"image_source": "image", "image_uri": "nginx:1.27",
                                                   "env_vars": "MODE=prod"}, infra_conn(), confirmed=set())
        self.assertEqual(q.inputs["settings"], "custom")
        self.assertEqual(q.inputs["env_vars"], "MODE=prod")

    def test_optional_field_takes_default_silently(self):
        q = templates.plan("vpc_network", {"name": "lab", "cidr": "10.0.0.0/16", "azs": ["us-east-1a", "us-east-1b"],
                                           "nat_gateway": "no"}, conn())
        self.assertNotIn("flow_logs", [x.key for x in getattr(q, "questions", [])])
