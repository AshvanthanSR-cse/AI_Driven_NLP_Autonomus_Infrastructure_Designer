"""Tool safety: blocklist, redaction, truncation, validation, router, approval flow, agent fallback."""
import json
import unittest
from types import SimpleNamespace
from unittest import mock

import httpx
import openai

from core import agent, audit, router, tools
from core.tools import ToolContext, ToolError
from tests.fakes import DEMO_INSTANCES, FakeConn, FakeEc2, FakeEvents, FakeScheduler


def setUpModule():
    # Never touch the real DB from unit tests.
    global _patch
    _patch = mock.patch.object(audit, "log_action", return_value=None)
    _patch.start()


def tearDownModule():
    _patch.stop()


class TestReadBlocklist(unittest.TestCase):
    def test_allowed(self):
        for svc, op in [("ec2", "describe_instances"), ("lambda", "list_functions"),
                        ("events", "list_rules"), ("scheduler", "get_schedule"), ("sts", "get_caller_identity"),
                        ("lambda", "get_function_configuration")]:
            tools.check_read_allowed(svc, op)

    def test_blocked(self):
        for svc, op in [("secretsmanager", "get_secret_value"), ("ssm", "get_parameter"),
                        ("lambda", "get_function"), ("ec2", "get_password_data"), ("s3", "get_object"),
                        ("sts", "get_session_token"), ("ecr", "get_authorization_token"),
                        ("ec2", "stop_instances"), ("s3", "delete_bucket"), ("iam", "create_user"),
                        ("EC2", "describe_instances"), ("ec2", "describe-instances")]:
            with self.subTest(op=f"{svc}.{op}"), self.assertRaises(ToolError):
                tools.check_read_allowed(svc, op)


class TestRedactAndTruncate(unittest.TestCase):
    def test_redact(self):
        data = {"Functions": [{"FunctionName": "f", "Environment": {"Variables": {"DB_URL": "postgres://x"}}}],
                "SecretAccessKey": "abc", "nested": {"password": "p", "ok": 1}}
        r = audit.redact(data)
        self.assertEqual(r["Functions"][0]["Environment"]["Variables"]["DB_URL"], audit.REDACTED)
        self.assertEqual(r["SecretAccessKey"], audit.REDACTED)
        self.assertEqual(r["nested"], {"password": audit.REDACTED, "ok": 1})
        self.assertNotIn("postgres://x", tools.to_llm_text(data))

    def test_truncate(self):
        text = tools.to_llm_text({"x": "y" * 10000}, limit=6000)
        self.assertLess(len(text), 6200)
        self.assertIn("truncated", text)


class TestValidation(unittest.TestCase):
    def test_bad_json(self):
        with self.assertRaises(ToolError):
            tools.validate_args("list_ec2_instances", "{not json")

    def test_bad_enum(self):
        with self.assertRaises(ToolError):
            tools.validate_args("list_ec2_instances", {"state": "exploded"})

    def test_bad_time(self):
        with self.assertRaises(ToolError):
            tools.validate_args("list_scheduled_lambdas", {"after_time": "noonish"})

    def test_unknown_tool(self):
        with self.assertRaises(ToolError):
            tools.validate_args("delete_everything", {})

    def test_specs_are_openai_shaped(self):
        specs = tools.openai_tool_specs()
        self.assertTrue(all(s["type"] == "function" and "parameters" in s["function"] for s in specs))
        by_name = {s["function"]["name"]: s["function"]["parameters"] for s in specs}
        # metadata titles are stripped ...
        self.assertNotIn("title", by_name["list_ec2_instances"])
        self.assertNotIn("title", by_name["list_ec2_instances"]["properties"]["state"])
        # ... but a real parameter called 'title' is kept, and every required parameter is described
        self.assertIn("title", by_name["aws_write"]["properties"])
        for name, params in by_name.items():
            for req in params.get("required", []):
                self.assertIn(req, params["properties"], f"{name}.{req}")


class TestRouter(unittest.TestCase):
    def test_routes(self):
        cases = {
            "What Lambda functions are scheduled to run after 10am?": ("list_scheduled_lambdas", {"after_time": "10am"}),
            "which lambdas have a cron trigger": ("list_scheduled_lambdas", {"after_time": "00:00"}),
            "What are the running instances?": ("list_ec2_instances", {"state": "running"}),
            "turn off instance web-demo": ("stop_instance", {"instance": "web-demo"}),
            "please stop i-0aaaaaaaaaaaaaaa1": ("stop_instance", {"instance": "i-0aaaaaaaaaaaaaaa1"}),
            "start the instance named stopped-demo": ("start_instance", {"instance": "stopped-demo"}),
            "how much did I spend in the last 7 days": ("get_cost_by_service", {"days": 7}),
            "list my s3 buckets": ("list_s3_buckets", {}),
            "show lambda functions": ("list_lambda_functions", {}),
            "cpu of instance web-demo": ("get_ec2_cpu", {"instance": "web-demo"}),
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(router.route(text), expected)

    def test_no_route(self):
        self.assertIsNone(router.route("tell me a joke"))
        self.assertIsNone(router.route("stop it"))  # stop without an instance is not routed


class TestWriteTools(unittest.TestCase):
    """Write tools only build a script draft; nothing is executed and no write identity is touched."""

    def setUp(self):
        self.ec2 = FakeEc2(DEMO_INSTANCES)
        self.conn = FakeConn({"ec2": self.ec2})
        self.ctx = ToolContext(conn=self.conn, request="stop web-demo")

    def _draft(self, name, inst):
        return tools.REGISTRY[name].func(self.ctx, tools.validate_args(name, {"instance": inst}))

    def test_stop_builds_script_without_executing(self):
        d = self._draft("stop_instance", "web-demo")
        self.assertEqual(d.title, "Stop i-0aaaaaaaaaaaaaaa1 (web-demo)")
        self.assertEqual(d.steps[0]["operation"], "stop_instances")
        self.assertEqual(d.steps[0]["guard"]["ec2_tag"]["value"], "demo")
        self.assertEqual(self.ec2.calls, [])
        self.assertNotIn(("ec2", "operate"), self.conn.requested)

    def test_requires_demo_tag(self):
        with self.assertRaises(ToolError):
            self._draft("stop_instance", "prod-db")

    def test_state_check(self):
        with self.assertRaises(ToolError):
            self._draft("stop_instance", "stopped-demo")
        self.assertEqual(self._draft("start_instance", "stopped-demo").title, "Start i-0ccccccccccccccc3 (stopped-demo)")

    def test_unknown_instance(self):
        with self.assertRaises(ToolError):
            self._draft("stop_instance", "nope")

    def test_s3_create_bucket_region_is_made_consistent(self):
        def draft(**kw):
            args = tools.validate_args("aws_write", {"title": "b", "service": "s3", "operation": "create_bucket", **kw})
            return tools.REGISTRY["aws_write"].func(self.ctx, args).steps[0]
        # the model's real mistake: location ap-south-1 but API region us-east-1
        s = draft(params={"Bucket": "b-1", "CreateBucketConfiguration": {"LocationConstraint": "ap-south-1"}},
                  region="us-east-1")
        self.assertEqual(s["region"], "ap-south-1")
        s = draft(params={"Bucket": "b-1"}, region="eu-west-1")  # no constraint: the region is added
        self.assertEqual(s["params"]["CreateBucketConfiguration"]["LocationConstraint"], s["region"])
        s = draft(params={"Bucket": "b-1"}, region="us-east-1")  # us-east-1 must have no constraint
        self.assertNotIn("CreateBucketConfiguration", s["params"])

    def test_create_script_saves_draft(self):
        with mock.patch.object(tools.scripts, "save_draft", return_value={"id": 7, "title": "t", "destructive": False, "risk": "operate"}) as save:
            saved = tools.create_script("stop_instance", tools.validate_args("stop_instance", {"instance": "web-demo"}), self.ctx)
        self.assertEqual(saved["id"], 7)
        save.assert_called_once()


def _msg(content="", calls=None):
    tc = [SimpleNamespace(id=f"c{i}", function=SimpleNamespace(name=n, arguments=a))
          for i, (n, a) in enumerate(calls or [])]
    return SimpleNamespace(content=content, tool_calls=tc or None)


class TestAgent(unittest.TestCase):
    def setUp(self):
        self.conn = FakeConn({"events": FakeEvents(), "scheduler": FakeScheduler(), "ec2": FakeEc2(DEMO_INSTANCES)})
        self.ctx = ToolContext(conn=self.conn)

    def test_model_picks_wrong_tool_is_overridden(self):
        replies = iter([_msg(calls=[("list_lambda_functions", "{}")]), _msg("Here they are (IST).")])
        with mock.patch.object(agent.llm, "chat", side_effect=lambda *a, **k: next(replies)):
            res = agent.run("What Lambda functions are scheduled to run after 10am?", self.ctx)
        self.assertEqual(res.tools_used, ["list_scheduled_lambdas"])
        self.assertTrue(res.used_fallback)

    def test_no_tool_call_uses_router(self):
        replies = iter([_msg("I think you have some instances."), _msg("You have 3 instances.")])
        with mock.patch.object(agent.llm, "chat", side_effect=lambda *a, **k: next(replies)):
            res = agent.run("list my ec2 instances", self.ctx)
        self.assertEqual(res.tools_used, ["list_ec2_instances"])
        self.assertEqual(res.text, "You have 3 instances.")

    def test_bad_args_get_one_retry(self):
        replies = iter([_msg(calls=[("list_ec2_instances", "{bad")]),
                        _msg(calls=[("list_ec2_instances", '{"state": "running"}')]),
                        _msg("done")])
        with mock.patch.object(agent.llm, "chat", side_effect=lambda *a, **k: next(replies)):
            res = agent.run("running instances?", self.ctx)
        self.assertEqual(res.tools_used, ["list_ec2_instances"])
        self.assertFalse(res.used_fallback)

    def test_write_becomes_script(self):
        replies = iter([_msg(calls=[("stop_instance", '{"instance": "web-demo"}')]), _msg("Script #3 saved.")])
        saved = {"id": 3, "title": "Stop i-0aaaaaaaaaaaaaaa1 (web-demo)", "destructive": False, "risk": "operate"}
        with mock.patch.object(agent.llm, "chat", side_effect=lambda *a, **k: next(replies)),                 mock.patch.object(tools.scripts, "save_draft", return_value=saved):
            res = agent.run("turn off web-demo", self.ctx)
        self.assertEqual(res.scripts, [saved])
        self.assertEqual(self.conn.clients["ec2"].calls, [])

    def test_max_rounds(self):
        loop = _msg(calls=[("list_s3_buckets", "{}")])
        calls = []

        def fake_chat(messages, tools_=None):
            calls.append(tools_)
            return loop if tools_ else _msg("final")
        self.conn.clients["s3"] = SimpleNamespace(list_buckets=lambda: {"Buckets": []})
        with mock.patch.object(agent.llm, "chat", side_effect=fake_chat):
            res = agent.run("buckets", self.ctx)
        self.assertEqual(len(res.tools_used), 5)
        self.assertEqual(res.text, "final")

    def test_llm_offline_answers_from_router(self):
        err = openai.APIConnectionError(request=httpx.Request("POST", "http://localhost:1234/v1"))
        with mock.patch.object(agent.llm, "chat", side_effect=err):
            res = agent.run("What Lambda functions are scheduled to run after 10am?", self.ctx)
        self.assertFalse(res.llm_available)
        self.assertIn("hello-12pm-ist", res.text)
        self.assertIn("Asia/Kolkata", res.text)


if __name__ == "__main__":
    unittest.main()
