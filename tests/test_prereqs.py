"""Prerequisites checklist: recipes are blocked until what they need exists; any AWS service via its API model."""
import unittest

from core import prereqs, router, templates, tools
from core.prereqs import PrereqReport
from core.templates import TaskQuestions
from tests.fakes import FakeConn
from tests.test_recipes import (FakeEc2, FakeEcr, FakeIam, FakeLambda, FakeSts, NotFound, RecipeTest, _Pages,
                                conn)
from tests.test_templates import FakeSsm

DB2_LICENSES = ["bring-your-own-license", "marketplace-license"]


class FakeRds:
    def __init__(self, db2_groups=()):
        self.db2_groups = list(db2_groups)

    def get_paginator(self, op):
        assert op == "describe_db_parameter_groups"
        return _Pages([{"DBParameterGroups": [
            {"DBParameterGroupName": g, "DBParameterGroupFamily": "db2-se-11.5"} for g in self.db2_groups] + [
            {"DBParameterGroupName": "default.postgres16", "DBParameterGroupFamily": "postgres16"}]}])

    def describe_orderable_db_instance_options(self, Engine, DBInstanceClass, Vpc, MaxRecords):
        if DBInstanceClass == "db.m6i.large":
            return {"OrderableDBInstanceOptions": []}
        models = DB2_LICENSES if Engine.startswith("db2") else ["license-included"]
        return {"OrderableDBInstanceOptions": [{"LicenseModel": m} for m in models]}

    def describe_db_subnet_groups(self, DBSubnetGroupName):
        if DBSubnetGroupName != "my-db-subnets":
            raise NotFound("DBSubnetGroupNotFoundFault")
        return {"DBSubnetGroups": [{"DBSubnetGroupName": DBSubnetGroupName}]}


class NoSubnetsEc2(FakeEc2):
    def describe_subnets(self):
        return {"Subnets": []}


def rds_conn(db2_groups=(), ec2=None):
    return FakeConn({"ec2": ec2 or FakeEc2(), "ssm": FakeSsm(), "sts": FakeSts(), "iam": FakeIam(),
                     "lambda": FakeLambda(), "ecr": FakeEcr(), "rds": FakeRds(db2_groups)})


class TestRecipeGate(RecipeTest):
    def test_missing_vpc_blocks_database(self):
        r = templates.plan("database", {"engine": "postgres"}, rds_conn(ec2=NoSubnetsEc2()))
        self.assertIsInstance(r, PrereqReport)
        self.assertTrue(r.blocking)
        self.assertEqual([i.key for i in r.missing], ["subnets"])
        self.assertIn("Create a VPC", r.missing[0].how)
        text = prereqs.format_report(r.to_dict())
        self.assertIn("❌", text)
        self.assertIn("🛠", text)

    def test_dynamodb_needs_no_vpc(self):
        r = templates.plan("database", {"engine": "dynamodb"}, rds_conn(ec2=NoSubnetsEc2()))
        self.assertNotIsInstance(r, PrereqReport)

    def test_ready_checklist_shown_with_questions_and_in_script_notes(self):
        q = templates.plan("database", {"engine": "postgres"}, rds_conn(), confirmed=set())
        self.assertIsInstance(q, TaskQuestions)
        self.assertFalse(q.prerequisites["blocking"])
        self.assertEqual(q.prerequisites["items"][0]["status"], "ready")
        d = self.build("database", {"engine": "postgres"}, rds_conn())
        self.assertTrue(d.notes[0].startswith("Prerequisites checked: ✅"))

    def test_db2_byol_needs_parameter_group_first(self):
        r = templates.plan("database", {"engine": "db2-se", "license_model": "bring-your-own-license"}, rds_conn())
        self.assertIsInstance(r, PrereqReport)
        self.assertIn("IBM Customer ID", r.missing[0].title)
        self.assertIn("rds.ibm_customer_id", r.missing[0].how)

    def test_db2_byol_with_parameter_group(self):
        d = self.build("database", {"engine": "db2-se", "license_model": "bring-your-own-license"},
                       rds_conn(["db2-ibm-ids"]))
        p = d.steps[-1]["params"]
        self.assertEqual((p["Engine"], p["LicenseModel"], p["DBParameterGroupName"]),
                         ("db2-se", "bring-your-own-license", "db2-ibm-ids"))
        self.assertEqual(p["DBName"], "APPDB")
        self.assertEqual(p["DBInstanceClass"], "db.t3.small")
        self.assertEqual(d.steps[1]["params"]["IpPermissions"][0]["FromPort"], 50000)

    def test_db2_marketplace_is_a_manual_step(self):
        q = templates.plan("database", {"engine": "db2-se", "license_model": "marketplace-license"}, rds_conn(),
                           confirmed=set())
        self.assertIsInstance(q, TaskQuestions)
        manual = [i for i in q.prerequisites["items"] if i["status"] == "manual"]
        self.assertIn("Marketplace", manual[0]["title"])
        sizes = [o["value"] for o in next(x for x in q.questions if x.key == "instance_class").options]
        self.assertNotIn("db.m6i.large", sizes)

    def test_sqlserver_and_oracle(self):
        d = self.build("database", {"engine": "sqlserver-ex"}, rds_conn())
        p = d.steps[-1]["params"]
        self.assertNotIn("DBName", p)
        self.assertEqual((p["LicenseModel"], p["DBInstanceClass"]), ("license-included", "db.t3.micro"))
        d = self.build("database", {"engine": "oracle-se2", "initial_db": "orcl"}, rds_conn())
        self.assertEqual(d.steps[-1]["params"]["DBName"], "ORCL")
        self.assertEqual(d.steps[-1]["params"]["LicenseModel"], "license-included")

    def test_local_tool_missing_blocks(self):
        from unittest import mock
        with mock.patch.object(prereqs, "which", return_value=None):
            r = templates.plan("terraform_project", {}, conn())
        self.assertIsInstance(r, PrereqReport)
        self.assertIn("winget", r.missing[0].how)

    def test_check_again_continues_the_task(self):
        report = templates.plan("database", {"engine": "postgres"}, rds_conn(ec2=NoSubnetsEc2())).to_dict()
        again = prereqs.recheck("tester", rds_conn(), report)
        self.assertIn("questions", again)


class TestAnyService(unittest.TestCase):
    def test_neptune_from_api_model(self):
        r = prereqs.check_service("neptune", templates.Env(rds_conn()))
        self.assertEqual(r.operation, "create_db_cluster")
        keys = [i.key for i in r.items]
        self.assertIn("value:DBClusterIdentifier", keys)
        self.assertTrue(any(k.startswith("subnet_group:") for k in keys))
        self.assertIn("create_db_instance", r.other_operations)

    def test_service_with_recipe_uses_the_recipe_checklist(self):
        r = prereqs.check_service("rds", templates.Env(rds_conn()), engine="db2-se")
        self.assertEqual(r.template, "database")
        self.assertTrue(any(i.key == "db2_license" for i in r.items))

    def test_unknown_service(self):
        with self.assertRaises(prereqs.PrereqError):
            prereqs.check_service("notaservice", templates.Env(rds_conn()))

    def test_tool_uses_common_words(self):
        ctx = tools.ToolContext(conn=rds_conn())
        out = tools.check_prerequisites(ctx, tools.PrereqArgs(service="db2"))
        self.assertEqual(out["template"], "database")
        self.assertIn("IBM Db2", out["checklist"])

    def test_aws_write_refuses_missing_references(self):
        ctx = tools.ToolContext(conn=rds_conn())
        args = tools.AwsWriteArgs(service="rds", operation="create_db_instance", title="db", params={
            "DBInstanceIdentifier": "x", "Engine": "postgres", "DBInstanceClass": "db.t3.micro",
            "AllocatedStorage": 20, "MasterUsername": "dbadmin", "DBSubnetGroupName": "nope",
            "VpcSecurityGroupIds": ["sg-0aaaaaaaaaaaaaaa1"]})
        with self.assertRaisesRegex(tools.ToolError, "security group sg-0aaaaaaaaaaaaaaa1.*subnet group 'nope'"):
            tools.aws_write(ctx, args)
        args.params.update({"DBSubnetGroupName": "my-db-subnets", "VpcSecurityGroupIds": ["sg-web"]})
        self.assertEqual(tools.aws_write(ctx, args).steps[0]["params"]["DBSubnetGroupName"], "my-db-subnets")


class TestRouting(unittest.TestCase):
    def test_routes(self):
        cases = {
            "create a neptune graph database": ("check_prerequisites", {"service": "graph database"}),
            "what do I need to build redshift?": ("check_prerequisites", {"service": "redshift"}),
            "what are the requirements for db2?": ("check_prerequisites", {"service": "db2"}),
            "create an opensearch domain": ("check_prerequisites", {"service": "opensearch"}),
            "build an RDS Db2 database": ("plan_task", {"template": "database", "inputs": {"engine": "db2-se"}}),
            "create a vpc": ("plan_task", {"template": "vpc_network", "inputs": {}}),
        }
        for text, want in cases.items():
            with self.subTest(text=text):
                self.assertEqual(router.route(text), want)


class NoDefaultVpcEc2(FakeEc2):
    def describe_vpcs(self, Filters=None):
        if Filters:
            return {"Vpcs": []}
        return super().describe_vpcs()


class TestDefaultVpcRule(unittest.TestCase):
    def test_network_params_required_without_default_vpc(self):
        r = prereqs.check_service("neptune", templates.Env(rds_conn(ec2=NoDefaultVpcEc2())))
        group = next(i for i in r.items if i.key.startswith("subnet_group:"))
        self.assertTrue(group.required)
        self.assertIn("no default VPC", group.why)
        sg = next(i for i in r.items if i.key.startswith("security_group:"))
        self.assertFalse(sg.required)
