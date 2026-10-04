"""Scripts: write policy, botocore parameter validation, CLI rendering, confirmation, run-time guards."""
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from core import scripts
from core.scripts import ScriptDraft, ScriptError
from tests.fakes import DEMO_INSTANCES, FakeConn, FakeEc2


def step(service, operation, params, **extra):
    return {"service": service, "operation": operation, "params": params, "description": "test", **extra}


class TestWritePolicy(unittest.TestCase):
    def test_blocked(self):
        for svc, op, params in [("iam", "create_user", {}), ("organizations", "leave_organization", {}),
                                ("cloudtrail", "stop_logging", {}), ("s3", "put_bucket_policy", {}),
                                ("ec2", "describe_instances", {}),  # a read, not a write
                                ("EC2", "stop_instances", {})]:
            with self.subTest(op=f"{svc}.{op}"), self.assertRaises(ScriptError):
                scripts.check_write_allowed(svc, op, params)

    def test_open_ssh_blocked(self):
        params = {"GroupId": "sg-1", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
        with self.assertRaises(ScriptError):
            scripts.check_write_allowed("ec2", "authorize_security_group_ingress", params)
        params["IpPermissions"][0]["IpRanges"] = [{"CidrIp": "203.0.113.5/32"}]
        scripts.check_write_allowed("ec2", "authorize_security_group_ingress", params)
        web = {"GroupId": "sg-1", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
        scripts.check_write_allowed("ec2", "authorize_security_group_ingress", web)

    def test_destructive(self):
        self.assertTrue(scripts.is_destructive("terminate_instances"))
        self.assertTrue(scripts.is_destructive("delete_bucket"))
        self.assertFalse(scripts.is_destructive("stop_instances"))
        self.assertTrue(ScriptDraft("x", [step("s3", "delete_bucket", {"Bucket": "b"})]).destructive)


class TestBotocoreValidation(unittest.TestCase):
    """Made-up operations or parameters (a typical small-model mistake) are rejected before saving."""

    def test_valid(self):
        scripts.validate_step(step("ec2", "stop_instances", {"InstanceIds": ["i-0aaaaaaaaaaaaaaa1"]}))
        scripts.validate_step(step("ec2", "create_tags", {"Resources": ["i-1"], "Tags": [{"Key": "a", "Value": "b"}]}))

    def test_invalid(self):
        for st in [step("ec2", "stop_instance", {"InstanceIds": ["i-1"]}),          # no such operation
                   step("ec2", "stop_instances", {"InstanceId": "i-1"}),             # wrong parameter name
                   step("ec2", "stop_instances", {}),                                # missing required
                   step("ec2", "stop_instances", {"InstanceIds": "i-1"}),            # wrong type
                   step("notaservice", "do_things", {})]:
            with self.subTest(st=st), self.assertRaises(ScriptError):
                scripts.validate_step(st)

    def test_made_up_example_ids_rejected(self):
        for fake in ("vpc-12345678", "subnet-12345678", "eipalloc-12345678", "sg-0123456789abcdef0", "i-xxxxxxxx"):
            with self.subTest(fake=fake), self.assertRaises(ScriptError):
                scripts.validate_step(step("ec2", "create_tags", {"Resources": [fake], "Tags": [{"Key": "a", "Value": "b"}]}))
        scripts.validate_step(step("ec2", "create_tags", {"Resources": ["vpc-0a1b2c3d4e5f67890"],
                                                          "Tags": [{"Key": "a", "Value": "b"}]}))

    def test_dry_run_support(self):
        self.assertTrue(scripts.supports_dry_run(step("ec2", "stop_instances", {})))
        self.assertFalse(scripts.supports_dry_run(step("s3", "create_bucket", {})))


class TestRenderCli(unittest.TestCase):
    def test_render(self):
        text = scripts.render_cli([step("ec2", "stop_instances", {"InstanceIds": ["i-1", "i-2"], "Force": True},
                                        guard={"text": "i-1 must be tagged Env=demo"})], "ap-south-1")
        self.assertIn("aws ec2 stop-instances", text)
        self.assertIn("--instance-ids i-1 i-2", text)
        self.assertIn("--force", text)
        self.assertIn("--region ap-south-1", text)
        self.assertIn("Safety check before running: i-1 must be tagged Env=demo", text)

    def test_render_complex_value(self):
        text = scripts.render_cli([step("ec2", "create_tags",
                                        {"Resources": ["i-1"], "Tags": [{"Key": "Owner", "Value": "ash"}]})], "ap-south-1")
        self.assertIn("""--tags '[{"Key":"Owner","Value":"ash"}]'""", text)


def _row(**over):
    row = {"id": 5, "owner": "tester", "title": "Stop web-demo", "request": "stop web-demo", "risk": "operate",
           "destructive": False, "region": "ap-south-1", "status": "approved", "approved_at": None,
           "steps": [step("ec2", "stop_instances", {"InstanceIds": ["i-0aaaaaaaaaaaaaaa1"]},
                          guard={"ec2_tag": {"instance_id": "i-0aaaaaaaaaaaaaaa1", "key": "Env", "value": "demo"},
                                 "text": "x"})]}
    row.update(over)
    return row


class _Ec2WithDescribe(FakeEc2):
    def describe_instances(self, InstanceIds):
        return {"Reservations": [{"Instances": self._match([{"Name": "instance-id", "Values": InstanceIds}])}]}


class TestRunScript(unittest.TestCase):
    def setUp(self):
        self.ec2 = _Ec2WithDescribe(DEMO_INSTANCES)
        self.conn = FakeConn({"ec2": self.ec2})
        self.sets = []
        patches = [mock.patch.object(scripts, "_set", side_effect=lambda sid, **c: self.sets.append(c)),
                   mock.patch.object(scripts.audit, "log_action", return_value=None)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _run(self, row, **kw):
        with mock.patch.object(scripts, "get_script", return_value=row):
            return scripts.run_script("tester", row["id"], self.conn, **kw)

    def test_runs_with_write_identity(self):
        res = self._run(_row())
        self.assertTrue(res["ok"], res["log"])
        self.assertEqual(self.ec2.calls, [("stop", ["i-0aaaaaaaaaaaaaaa1"])])
        self.assertIn(("ec2", "operate"), self.conn.requested)
        self.assertEqual(self.sets[-1]["status"], "succeeded")

    def test_guard_blocks_untagged(self):
        row = _row()
        row["steps"][0]["params"]["InstanceIds"] = ["i-0bbbbbbbbbbbbbbb2"]
        row["steps"][0]["guard"]["ec2_tag"]["instance_id"] = "i-0bbbbbbbbbbbbbbb2"  # prod-db, no Env=demo
        res = self._run(row)
        self.assertFalse(res["ok"])
        self.assertEqual(self.ec2.calls, [])
        self.assertEqual(self.sets[-1]["status"], "failed")

    def test_destructive_needs_typed_confirmation(self):
        row = _row(destructive=True)
        with self.assertRaises(ScriptError):
            self._run(row, typed_confirmation="yes")
        self.assertEqual(self.ec2.calls, [])
        self.assertTrue(self._run(row, typed_confirmation="run script 5")["ok"])

    def test_needs_approval_before_running(self):
        for status in ("draft", "denied"):
            with self.subTest(status=status), self.assertRaises(ScriptError) as cm:
                self._run(_row(status=status))
            self.assertIn("Approve", str(cm.exception))
        self.assertEqual(self.ec2.calls, [])
        # a dry run is always allowed (it changes nothing)
        self._run(_row(status="draft"), dry_run=True)
        with mock.patch.object(scripts, "get_script", return_value=_row(status="draft")), self.assertRaises(ScriptError):
            scripts.schedule_script("tester", 5, datetime.now(timezone.utc) + timedelta(hours=1))

    def test_approve_and_deny(self):
        with mock.patch.object(scripts, "get_script", side_effect=[_row(status="draft"), _row(status="approved")]):
            scripts.approve_script("tester", 5)
        self.assertEqual(self.sets[-1]["status"], "approved")
        with mock.patch.object(scripts, "get_script", side_effect=[_row(status="approved"), _row(status="denied")]):
            scripts.deny_script("tester", 5, "wrong subnet")
        self.assertEqual(self.sets[-1]["status"], "denied")
        self.assertIn("wrong subnet", self.sets[-1]["result"])
        with mock.patch.object(scripts, "get_script", return_value=_row(status="succeeded")), self.assertRaises(ScriptError):
            scripts.deny_script("tester", 5)

    def _edit(self, text, row=None):
        row = row or _row(script_text="# NOTE: COST: cheap\n")
        with mock.patch.object(scripts, "get_script", return_value=row):
            return scripts.update_steps("tester", 5, text)

    def test_manual_edit_requires_reapproval(self):
        new = json.dumps([{"service": "ec2", "operation": "start_instances", "description": "start instead",
                           "params": {"InstanceIds": ["i-0aaaaaaaaaaaaaaa1"]}}])
        self._edit(new)
        cols = self.sets[-1]
        self.assertEqual(cols["status"], "draft")
        self.assertIsNone(cols["approved_at"])
        self.assertIn("aws ec2 start-instances", cols["script_text"])
        self.assertIn("NOTE: COST: cheap", cols["script_text"])          # notes kept
        self.assertFalse(cols["destructive"])
        delete = json.dumps([{"service": "ec2", "operation": "terminate_instances",
                              "params": {"InstanceIds": ["i-0aaaaaaaaaaaaaaa1"]}}])
        self._edit(delete)
        self.assertTrue(self.sets[-1]["destructive"])                     # now needs typed confirmation

    def test_manual_edit_is_validated(self):
        bad = [("{not json", "Not valid JSON"),
               ("[]", "at least one step"),
               ('[{"service": "iam", "operation": "create_user", "params": {"UserName": "x"}}]', "blocked"),
               ('[{"service": "ec2", "operation": "stop_instances", "params": {"InstanceId": "i-1"}}]', "Invalid parameters"),
               ('[{"service": "ec2", "operation": "create_tags", "params": {"Resources": ["vpc-12345678"], "Tags": []}}]', "made-up"),
               ('[{"service": "ec2", "operation": "delete_vpc", "params": {"VpcId": "{{vpc.Vpc.VpcId}}"}}]', "no earlier step"),
               ('[{"service": "ec2", "operation": "stop_instances", "params": {}, "shell": "rm -rf /"}]', "unknown field")]
        for text, msg in bad:
            with self.subTest(msg=msg), self.assertRaises(ScriptError) as cm:
                self._edit(text)
            self.assertIn(msg, str(cm.exception))

    def test_schedule_validation(self):
        with mock.patch.object(scripts, "get_script", return_value=_row()):
            with self.assertRaises(ScriptError):
                scripts.schedule_script("tester", 5, datetime.now(timezone.utc) - timedelta(minutes=1))
            with self.assertRaises(ScriptError):
                scripts.schedule_script("tester", 5, datetime.now() + timedelta(hours=1))  # naive time


if __name__ == "__main__":
    unittest.main()
