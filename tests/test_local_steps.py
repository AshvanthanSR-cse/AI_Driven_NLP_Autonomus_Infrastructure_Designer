"""Local steps (docker / terraform / kubectl / eksctl / ansible / checks) and the runner using them."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core import local_steps, scripts, workspace
from core.local_steps import StepError
from core.scripts import ScriptDraft, ScriptError

HERE = str(Path(__file__).resolve().parent)


def cmd(tool, args, **extra):
    return {"kind": "command", "tool": tool, "args": args, "description": "t", **extra}


class TestValidation(unittest.TestCase):
    def test_allowed_commands(self):
        for st in [cmd("docker", ["build", "-t", "x:1", "."], cwd=HERE), cmd("docker", ["push", "x:1"]),
                   cmd("terraform", ["apply", "-input=false", "tfplan"], cwd=HERE),
                   cmd("kubectl", ["apply", "-f", "a.yaml", "--kubeconfig", "k"]),
                   cmd("eksctl", ["create", "cluster", "-f", "c.yaml"]),
                   cmd("aws", ["eks", "update-kubeconfig", "--name", "c"]),
                   cmd("docker", ["run", "-d", "-p", "8080:80", "-v", "D:\\site:/usr/share/nginx/html", "nginx"])]:
            with self.subTest(st=st["args"][:2]):
                local_steps.validate(st)

    def test_blocked_commands(self):
        bad = [cmd("powershell", ["-c", "whoami"]), cmd("bash", ["-c", "ls"]), cmd("python", ["x.py"]),
               cmd("aws", ["iam", "create-access-key"]),
               cmd("aws", ["s3", "rm", "s3://b", "--recursive"]),
               cmd("docker", ["login", "-p", "x"]),
               cmd("docker", ["run", "--privileged", "alpine"]),
               cmd("docker", ["run", "-v", "/:/host", "alpine"]),
               cmd("docker", ["run", "-v", "C:\\:/host", "alpine"]),
               cmd("docker", ["run", "-v", "//var/run/docker.sock:/var/run/docker.sock", "alpine"]),
               cmd("docker", ["run", "--mount", "type=bind,source=/,target=/h", "alpine"]),
               cmd("kubectl", ["exec", "-it", "pod", "--", "sh"]),
               cmd("terraform", ["apply", "-auto-approve"]),
               cmd("docker", ["build", "."], cwd="Z:\\does\\not\\exist"),
               cmd("docker", "build ."),
               {**cmd("docker", ["push", "x"]), "shell": "rm -rf /"},
               {"kind": "teleport", "description": "x"}]
        for st in bad:
            with self.subTest(st=st.get("args", st.get("kind"))), self.assertRaises(StepError):
                local_steps.validate(st)

    def test_destructive_subcommands(self):
        self.assertTrue(local_steps.is_destructive(cmd("terraform", ["destroy", "-input=false", "-auto-approve"])))
        self.assertTrue(local_steps.is_destructive(cmd("kubectl", ["delete", "-f", "x"])))
        self.assertTrue(local_steps.is_destructive(cmd("eksctl", ["delete", "cluster", "-f", "c"])))
        self.assertFalse(local_steps.is_destructive(cmd("kubectl", ["apply", "-f", "x"])))
        self.assertTrue(scripts.needs_confirmation(cmd("helm", ["uninstall", "app"])))
        self.assertTrue(ScriptDraft("x", [cmd("kubectl", ["delete", "-f", "x"])]).destructive)

    def test_ansible_and_check_steps(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "site.yml").write_text("- hosts: all\n")
            Path(d, "inventory.ini").write_text("[web]\n1.2.3.4\n")
            ok = {"kind": "ansible", "workdir": d, "playbook": "site.yml", "inventory": "inventory.ini",
                  "extra_args": ["--syntax-check"], "description": "x"}
            local_steps.validate(ok)
            for bad in ({**ok, "playbook": "../etc/passwd.yml"}, {**ok, "playbook": "missing.yml"},
                        {**ok, "extra_args": ["-e", "@/etc/shadow"]}, {**ok, "ssh_key_path": "Z:\\nokey.pem"}):
                with self.subTest(bad=bad), self.assertRaises(StepError):
                    local_steps.validate(bad)
        local_steps.validate({"kind": "check", "check": "http", "params": {"url": "http://1.2.3.4/"}})
        with self.assertRaises(StepError):
            local_steps.validate({"kind": "check", "check": "port_scan", "params": {}})
        with self.assertRaises(StepError):
            local_steps.validate({"kind": "ecr_login", "repository_uri": "evil.example.com/repo"})
        local_steps.validate({"kind": "ecr_login", "repository_uri": "123456789012.dkr.ecr.ap-south-1.amazonaws.com/app"})

    def test_scrub_hides_keys(self):
        line = "AKIAABCDEFGHIJKLMNOP secret=abcd1234efgh5678 wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY ok"
        out = local_steps.scrub(line)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", out)
        self.assertNotIn("abcd1234efgh5678", out)
        self.assertNotIn("wJalrXUtnFEMI", out)
        self.assertTrue(out.endswith("ok"))

    def test_render(self):
        self.assertIn('cd "D:\\my folder" && docker build -t x:1 .',
                      local_steps.render(cmd("docker", ["build", "-t", "x:1", "."], cwd="D:\\my folder"), "ap-south-1"))
        text = local_steps.render({"kind": "ecr_login", "repository_uri": "123456789012.dkr.ecr.ap-south-1.amazonaws.com/a"},
                                  "ap-south-1")
        self.assertIn("--password-stdin 123456789012.dkr.ecr.ap-south-1.amazonaws.com", text)


class TestProcess(unittest.TestCase):
    def test_run_process_streams_and_returns_code(self):
        seen = []
        with mock.patch.object(local_steps, "which", return_value=sys.executable):
            code, lines = local_steps.run_process(
                ["python", "-c", "import sys; print('hello'); print(sys.stdin.read()); sys.exit(3)"],
                stdin=b"from-stdin", progress=seen.append, timeout=60)
        self.assertEqual(code, 3)
        self.assertEqual(lines[:2], ["hello", "from-stdin"])
        self.assertIn("hello", seen)

    def test_missing_tool(self):
        with mock.patch.object(local_steps, "which", return_value=None), self.assertRaises(StepError) as cm:
            local_steps.run_process(["terraform", "version"])
        self.assertIn("winget install", str(cm.exception))

    def test_timeout_kills(self):
        with mock.patch.object(local_steps, "which", return_value=sys.executable), self.assertRaises(StepError):
            local_steps.run_process(["python", "-c", "import time; time.sleep(30)"], timeout=1)


class FakeConn:
    owner = "tester"

    def __init__(self):
        self.requested = []

    def client(self, service, purpose="read", region=None):
        self.requested.append((service, purpose))
        return mock.Mock()


class TestRunnerWithLocalSteps(unittest.TestCase):
    """Placeholders flow into local steps; failures stop the run; local undo goes into the teardown."""

    def setUp(self):
        self.sets, self.saved = [], []
        patches = [mock.patch.object(scripts, "_set", side_effect=lambda sid, **c: self.sets.append(c)),
                   mock.patch.object(scripts.audit, "log_action"),
                   mock.patch.object(scripts, "save_draft",
                                     side_effect=lambda o, r, d: self.saved.append(d) or {"id": 99, "title": d.title})]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _row(self, steps):
        return {"id": 7, "title": "t", "request": "r", "status": "approved", "risk": "operate", "region": "ap-south-1",
                "destructive": False, "steps": steps}

    def test_flow(self):
        steps = [cmd("terraform", ["output", "-json"], cwd=HERE, save_as="tf"),
                 cmd("kubectl", ["apply", "-f", "{{tf.json.manifest}}"],
                     undo={"kind": "command", "tool": "kubectl", "args": ["delete", "-f", "{{tf.json.manifest}}"],
                           "description": "remove the app"})]
        calls = []

        def fake_run(step, conn, purpose, region, progress=None):
            calls.append(step["args"])
            progress("working")
            out = {"stdout": "{}", "json": {"manifest": "app.yaml"}}
            return {"output": out, "summary": "ok"}

        log = []
        with mock.patch.object(scripts, "get_script", return_value=self._row(steps)), \
                mock.patch.object(local_steps, "run", side_effect=fake_run):
            res = scripts.run_script("tester", 7, FakeConn(), progress=log.append)
        self.assertTrue(res["ok"], res["log"])
        self.assertEqual(calls[1], ["apply", "-f", "app.yaml"])
        self.assertIn("working", log)
        teardown = self.saved[0]
        self.assertEqual(teardown.steps[0]["args"], ["delete", "-f", "app.yaml"])
        self.assertTrue(teardown.destructive)

    def test_failure_stops(self):
        steps = [cmd("docker", ["build", "-t", "x", "."], cwd=HERE), cmd("docker", ["push", "x"])]
        with mock.patch.object(scripts, "get_script", return_value=self._row(steps)), \
                mock.patch.object(local_steps, "run", side_effect=StepError("docker build failed (exit code 1)")) as run:
            res = scripts.run_script("tester", 7, FakeConn())
        self.assertFalse(res["ok"])
        self.assertEqual(run.call_count, 1)
        self.assertIn("docker build failed", res["log"])
        self.assertEqual(self.sets[-1]["status"], "failed")

    def test_dry_run_checks_tools_only(self):
        steps = [cmd("docker", ["build", "-t", "x", "."], cwd=HERE)]
        with mock.patch.object(scripts, "get_script", return_value=self._row(steps)), \
                mock.patch.object(local_steps, "run") as run, mock.patch.object(local_steps, "which", return_value=None):
            res = scripts.run_script("tester", 7, FakeConn(), dry_run=True)
        run.assert_not_called()
        self.assertFalse(res["ok"])
        self.assertIn("not installed: docker", res["log"])


class TestFileUpload(unittest.TestCase):
    def test_file_refs_only_from_workspace(self):
        d = workspace.new_task_dir("test")
        try:
            (d / "f.zip").write_bytes(b"PK..")
            ok = {"service": "lambda", "operation": "update_function_code", "description": "x",
                  "params": {"FunctionName": "f", "ZipFile": f"@file:{d / 'f.zip'}"}}
            scripts.validate_step(ok)
            self.assertEqual(scripts.load_files(ok["params"])["ZipFile"], b"PK..")
            self.assertIn("fileb://", scripts.render_cli([ok], "ap-south-1"))
            outside = {**ok, "params": {"FunctionName": "f", "ZipFile": "@file:C:\\Windows\\win.ini"}}
            with self.assertRaises(ScriptError):
                scripts.validate_step(outside)
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)


class TestBulkDelete(unittest.TestCase):
    def test_delete_skips_only_really_running(self):
        rows = {1: {"id": 1, "status": "draft"}, 2: {"id": 2, "status": "running"},
                3: {"id": 3, "status": "running"}}
        for r in rows.values():
            r.update(title="t", request="r", risk="operate")
        scripts._RUNNING.add(3)
        self.addCleanup(scripts._RUNNING.discard, 3)
        with mock.patch.object(scripts, "get_script", side_effect=lambda o, i: rows[i]), \
                mock.patch.object(scripts.db, "execute") as ex, mock.patch.object(scripts.audit, "log_action"):
            res = scripts.delete_scripts("tester", [1, 2, 3])
        self.assertEqual(res, {"deleted": [1, 2], "skipped": [3]})
        self.assertEqual(ex.call_count, 2)


if __name__ == "__main__":
    unittest.main()
