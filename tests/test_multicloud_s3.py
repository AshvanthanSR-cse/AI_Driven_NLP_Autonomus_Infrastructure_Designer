"""S3 upload recipe and step, chat attachments, Dockerfile-as-file, and the Azure / GCP connectors (no network)."""
import base64
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from core import agent, clouds, local_steps, recipes, scripts, templates, tools, workspace
from core.local_steps import StepError
from core.templates import TaskQuestions
from core.tools import ToolContext
from tests.test_recipes import RecipeTest, conn as recipe_conn

AZ = {"tenant_id": "11111111-1111-1111-1111-111111111111", "client_id": "22222222-2222-2222-2222-222222222222",
      "subscription_id": "33333333-3333-3333-3333-333333333333"}


class FakeS3:
    def __init__(self, existing=()):
        self.existing = set(existing)
        self.uploads = []

    def list_buckets(self):
        return {"Buckets": [{"Name": "team-docs"}, {"Name": "backups-2026"}]}

    def get_bucket_location(self, Bucket):
        return {"LocationConstraint": "ap-south-1"}

    def get_paginator(self, op):
        keys = self.existing

        class P:
            def paginate(self, Bucket, Prefix, **kw):
                return iter([{"Contents": [{"Key": k} for k in keys if k.startswith(Prefix)]}])
        return P()

    def upload_file(self, path, bucket, key, ExtraArgs=None):
        self.uploads.append((Path(path).name, bucket, key, ExtraArgs))

    def head_bucket(self, Bucket):
        from botocore.exceptions import ClientError
        code = "403" if Bucket in ("true", "taken-by-someone") else "404"
        raise ClientError({"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": int(code)}}, "HeadBucket")


def s3_conn(existing=()):
    c = recipe_conn()
    c.clients["s3"] = FakeS3(existing)
    return c


class TestS3Upload(RecipeTest):
    def test_document_to_existing_bucket(self):
        doc = self.folder("docs", {"report.pdf": "%PDF"}) + "\\report.pdf"
        c = s3_conn(existing={"reports/old.pdf"})
        d = self.build("s3_upload", {"source": doc, "bucket": "team-docs", "prefix": "reports"}, c)
        up = d.steps[-1]
        self.assertEqual((up["kind"], up["bucket"], up["region"]), ("s3_upload", "team-docs", "ap-south-1"))
        self.assertEqual(up["undo"]["params"]["Delete"]["Objects"], [{"Key": "reports/report.pdf"}])
        self.assertIn('aws s3 cp', scripts.render_cli(d.steps, "ap-south-1"))

    def test_overwrite_is_never_undone(self):
        doc = self.folder("docs", {"report.pdf": "%PDF"}) + "\\report.pdf"
        d = self.build("s3_upload", {"source": doc, "bucket": "team-docs", "prefix": "reports/"},
                       s3_conn(existing={"reports/report.pdf"}))
        self.assertNotIn("undo", d.steps[-1])
        self.assertTrue(any("OVERWRITTEN" in n for n in d.notes))

    def test_folder_to_new_bucket_skips_secrets(self):
        site = self.folder("site", {"index.html": "x", "img/a.png": "x", ".env": "SECRET=1", "key.pem": "x"})
        d = self.build("s3_upload", {"source": site, "bucket": "new", "new_bucket": "my-new-bucket-123"}, s3_conn())
        self.assertEqual([s.get("operation") or s["kind"] for s in d.steps],
                         ["create_bucket", "put_bucket_tagging", "s3_upload"])
        keys = [o["Key"] for o in d.steps[-1]["undo"]["params"]["Delete"]["Objects"]]
        self.assertEqual(sorted(keys), ["site/img/a.png", "site/index.html"])

    def test_bad_inputs(self):
        q = templates.plan("s3_upload", {"source": "Z:\\nope.pdf", "bucket": "not-my-bucket"}, s3_conn())
        errs = {x.key: x.error for x in q.questions}
        self.assertIn("not found", errs["source"])
        self.assertIn("not one of", errs["bucket"])
        key = self.folder("k", {"id_rsa": "x"}) + "\\id_rsa"
        q = templates.plan("s3_upload", {"source": key, "bucket": "team-docs"}, s3_conn())
        self.assertIn("secret file", next(x.error for x in q.questions if x.key == "source"))

    def test_new_bucket_name_must_be_a_real_free_name(self):
        doc = self.folder("docs", {"index.html": "x"}) + "\index.html"
        for bad, msg in ((True, "type a name"), ("yes", "not a bucket name"), ("taken-by-someone", "another AWS account"),
                         ("team-docs", "already have")):
            q = templates.plan("s3_upload", {"source": doc, "bucket": "new", "new_bucket": bad}, s3_conn())
            qn = next(x for x in q.questions if x.key == "new_bucket")
            self.assertIn(msg, qn.error)
            self.assertNotEqual(qn.default, True)

    def test_upload_step_runs_encrypted(self):
        site = self.folder("site", {"index.html": "<h1>", "css/a.css": "", ".env": "x"})
        s3 = FakeS3()
        c = mock.Mock(owner="t")
        c.client.return_value = s3
        res = local_steps.run({"kind": "s3_upload", "source": site, "bucket": "team-docs", "prefix": "web"},
                              c, "operate", "ap-south-1")
        keys = sorted(u[2] for u in s3.uploads)
        self.assertEqual(keys, ["web/site/css/a.css", "web/site/index.html"])
        self.assertTrue(all(u[3]["ServerSideEncryption"] == "AES256" for u in s3.uploads))
        self.assertIn("2 file(s)", res["summary"])
        with self.assertRaises(StepError):
            local_steps.validate({"kind": "s3_upload", "source": site, "bucket": "team-docs", "prefix": "../x"})


class TestAttachments(RecipeTest):
    def test_attached_dockerfile_fills_the_recipe(self):
        app = self.folder("app", {"Dockerfile": "FROM nginx\nEXPOSE 80\n"})
        att = [tools.describe_attachment(app + "\\Dockerfile")]
        self.assertEqual(att[0]["type"], "dockerfile")
        ctx = ToolContext(conn=recipe_conn(), attachments=att)
        args = tools.validate_args("plan_task", {"template": "ecs_fargate_service",
                                                 "inputs": {"app_folder": "C:\\\\made\\\\up"}})
        q = tools.plan_task(ctx, args)
        self.assertIsInstance(q, TaskQuestions)
        self.assertEqual(q.inputs["app_folder"], str(Path(app).resolve()))
        self.assertNotIn("app_folder", [x.key for x in q.questions])
        d = self.build("ecs_fargate_service", {"app_folder": app + "\\Dockerfile", "name": "web",
                                               "container_port": 80, "subnets": ["subnet-pub"]})
        build = next(s for s in d.steps if s.get("tool") == "docker")
        self.assertEqual(build["cwd"], str(Path(app).resolve()))

    def test_attachment_note_has_paths_only(self):
        doc = self.folder("d", {"secret-plan.txt": "TOP SECRET CONTENT"}) + "\\secret-plan.txt"
        note = agent.attachments_note([tools.describe_attachment(doc)])
        self.assertIn(doc, note)
        self.assertNotIn("TOP SECRET CONTENT", note)


def _rsa_key():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode()
    return k, json.dumps({"type": "service_account", "project_id": "demo-proj", "private_key": pem,
                          "client_email": "kintsugi@demo-proj.iam.gserviceaccount.com",
                          "token_uri": "https://oauth2.googleapis.com/token"})


class TestConnectors(unittest.TestCase):
    def test_azure_token_and_vms(self):
        calls = []

        def fake_http(method, url, **kw):
            calls.append((method, url, kw))
            if "login.microsoftonline.com" in url:
                assert kw["form"]["grant_type"] == "client_credentials"
                return {"access_token": "tok", "expires_in": 3600}
            if "virtualMachines?" in url:
                return {"value": [{"name": "web-1", "location": "eastus",
                                   "id": "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/web-1",
                                   "properties": {"hardwareProfile": {"vmSize": "B1s"}, "instanceView": {"statuses": [
                                       {"code": "ProvisioningState/succeeded"}, {"code": "PowerState/running"}]}}}]}
            return {"status": 202}
        c = clouds.AzureConnector(AZ, "s3cr3t-value")
        with mock.patch.object(clouds, "http", side_effect=fake_http):
            vms = c.list_vms()
            c.vm_action("web-1", "stop")
        self.assertEqual(vms[0]["state"], "running")
        self.assertEqual(vms[0]["resource_group"], "rg1")
        self.assertTrue(calls[-1][1].endswith("/virtualMachines/web-1/deallocate?api-version=2024-07-01"))
        self.assertEqual(sum("login.microsoftonline" in u for _, u, _ in calls), 1)

    def test_azure_field_checks(self):
        with self.assertRaises(clouds.CloudError):
            clouds.AzureConnector.check_fields("not-a-guid", AZ["client_id"], AZ["subscription_id"], "secretvalue")

    def test_gcp_jwt_is_signed_with_the_key(self):
        k, key_json = _rsa_key()
        seen = {}

        def fake_http(method, url, **kw):
            if url.endswith("/token"):
                seen["assertion"] = kw["form"]["assertion"]
                return {"access_token": "tok", "expires_in": 3600}
            return {"items": [{"name": "bucket-a", "location": "US"}]}
        c = clouds.GcpConnector({"project_id": "demo-proj"}, key_json)
        with mock.patch.object(clouds, "http", side_effect=fake_http):
            self.assertEqual(c.list_storage()[0]["name"], "bucket-a")
        head, claims, sig = seen["assertion"].split(".")
        pad = lambda x: x + "=" * (-len(x) % 4)
        k.public_key().verify(base64.urlsafe_b64decode(pad(sig)), f"{head}.{claims}".encode(),
                              padding.PKCS1v15(), hashes.SHA256())
        self.assertEqual(json.loads(base64.urlsafe_b64decode(pad(claims)))["iss"],
                         "kintsugi@demo-proj.iam.gserviceaccount.com")

    def test_gcp_key_validation(self):
        with self.assertRaises(clouds.CloudError):
            clouds.GcpConnector.parse_key('{"type": "authorized_user"}')
        with self.assertRaises(clouds.CloudError):
            clouds.GcpConnector.parse_key("not json")

    def test_cloud_steps_validate(self):
        local_steps.validate({"kind": "cloud", "provider": "azure", "action": "vm_stop", "params": {"vm": "web-1"}})
        for bad in ({"kind": "cloud", "provider": "oracle", "action": "vm_stop", "params": {"vm": "x"}},
                    {"kind": "cloud", "provider": "gcp", "action": "delete_project", "params": {}},
                    {"kind": "cloud", "provider": "gcp", "action": "upload", "params": {"source": "Z:\\none", "bucket": "b"}}):
            with self.subTest(bad=bad), self.assertRaises(StepError):
                local_steps.validate(bad)


if __name__ == "__main__":
    unittest.main()
