"""Public S3 static website recipe, the public-access write policy, flattened upload and s3_empty."""
import json
import unittest
from pathlib import Path
from unittest import mock

from botocore.exceptions import ClientError

from core import local_steps, recipes, router, scripts, templates, tools
from core.local_steps import StepError
from core.scripts import ScriptDraft, ScriptError
from core.templates import TaskQuestions
from core.tools import ToolContext
from tests.test_multicloud_s3 import FakeS3, s3_conn
from tests.test_recipes import RecipeTest


class FakeS3Control:
    def __init__(self, blocked=False):
        self.blocked = blocked

    def get_public_access_block(self, AccountId):
        if not self.blocked:
            raise ClientError({"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}}, "GetPublicAccessBlock")
        return {"PublicAccessBlockConfiguration": {k: True for k in recipes.BPA_KEYS}}


def site_conn(blocked=False):
    c = s3_conn()
    c.clients["s3control"] = FakeS3Control(blocked)
    return c


def ops(draft):
    return [s.get("operation") or s.get("kind") for s in draft.steps]


class TestPublicPolicy(unittest.TestCase):
    def test_public_read_policy_allowed_and_needs_confirmation(self):
        st = {"service": "s3", "operation": "put_bucket_policy", "description": "x",
              "params": {"Bucket": "my-site", "Policy": recipes.public_read_policy("my-site")}}
        scripts.validate_step(st)
        self.assertTrue(scripts.needs_confirmation(st))

    def test_public_write_policy_blocked(self):
        for action in ("s3:PutObject", "s3:*", ["s3:GetObject", "s3:DeleteObject"], "s3:ListBucket"):
            pol = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": action,
                                             "Resource": "arn:aws:s3:::my-site/*"}]})
            with self.subTest(action=action), self.assertRaises(ScriptError):
                scripts.check_write_allowed("s3", "put_bucket_policy", {"Bucket": "my-site", "Policy": pol})

    def test_private_policy_not_public(self):
        pol = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                                         "Action": "s3:PutObject", "Resource": "arn:aws:s3:::b/*"}]})
        st = {"service": "s3", "operation": "put_bucket_policy", "params": {"Bucket": "b", "Policy": pol}}
        scripts.check_write_allowed("s3", "put_bucket_policy", st["params"])
        self.assertFalse(scripts.makes_public(st))

    def test_block_public_access_off_needs_confirmation(self):
        off = {"service": "s3", "operation": "put_public_access_block",
               "params": {"Bucket": "b", "PublicAccessBlockConfiguration": recipes._bpa(False)}}
        on = {**off, "params": {"Bucket": "b", "PublicAccessBlockConfiguration": recipes._bpa(True)}}
        self.assertTrue(scripts.needs_confirmation(off))
        self.assertFalse(scripts.needs_confirmation(on))

    def test_acls_still_blocked(self):
        with self.assertRaises(ScriptError):
            scripts.check_write_allowed("s3", "put_bucket_acl", {"Bucket": "b", "ACL": "public-read"})


class TestS3Website(RecipeTest):
    def test_new_public_versioned_site(self):
        site = self.folder("mysite", {"index.html": "<h1>hi</h1>", "css/a.css": ""})
        d = self.build("s3_static_website", {"source": site, "bucket": "new", "new_bucket": "my-site-2026"},
                       site_conn())
        self.assertEqual(ops(d), ["create_bucket", "put_bucket_tagging", "put_bucket_versioning",
                                  "put_public_access_block", "put_bucket_policy", "put_bucket_website",
                                  "s3_upload", "check"])
        bpa = d.steps[3]["params"]["PublicAccessBlockConfiguration"]
        self.assertFalse(any(bpa.values()))
        self.assertEqual(d.steps[2]["params"]["VersioningConfiguration"]["Status"], "Enabled")
        up = d.steps[6]
        self.assertTrue(up["flatten"])
        self.assertEqual(up["undo"]["kind"], "s3_empty")
        self.assertIn("my-site-2026.s3-website", d.steps[7]["params"]["url"])
        self.assertTrue(ScriptDraft("x", d.steps).destructive)
        scripts.validate_steps(d.steps)

    def test_single_index_file(self):
        f = self.folder("one", {"index.html": "<h1>"}) + "\\index.html"
        d = self.build("s3_static_website", {"source": f, "bucket": "new", "new_bucket": "my-site-2027",
                                             "versioning": "no"}, site_conn())
        self.assertNotIn("put_bucket_versioning", ops(d))
        web = next(s for s in d.steps if s.get("operation") == "put_bucket_website")
        self.assertEqual(web["params"]["WebsiteConfiguration"]["IndexDocument"]["Suffix"], "index.html")

    def test_folder_without_index_rejected(self):
        site = self.folder("noindex", {"about.html": "x"})
        q = templates.plan("s3_static_website", {"source": site, "bucket": "new"}, site_conn())
        self.assertIsInstance(q, TaskQuestions)
        self.assertIn("source", [x.key for x in q.questions])

    def test_account_level_block_is_asked(self):
        site = self.folder("s", {"index.html": "x"})
        q = templates.plan("s3_static_website", {"source": site, "bucket": "new", "new_bucket": "my-site-2028"},
                           site_conn(blocked=True))
        self.assertIn("account_bpa", [x.key for x in q.questions])
        d = self.build("s3_static_website", {"source": site, "bucket": "new", "new_bucket": "my-site-2028",
                                             "account_bpa": "yes"}, site_conn(blocked=True))
        self.assertEqual((d.steps[0]["service"], d.steps[0]["operation"]), ("s3control", "put_public_access_block"))

    def test_router_and_attachment(self):
        text = ("I want to create an S3 bucket with public access and also enable bucket versioning, host a static "
                "web application using the index.html file from the attached file")
        self.assertEqual(router.route(text)[1]["template"], "s3_static_website")
        f = self.folder("att", {"index.html": "<h1>"}) + "\\index.html"
        att = [tools.describe_attachment(f)]
        q = tools.plan_task(ToolContext(conn=site_conn(), attachments=att),
                            tools.validate_args("plan_task", {"template": "s3_static_website", "inputs": {}}))
        self.assertEqual(q.inputs["source"], str(Path(f).resolve()))


class TestSteps(RecipeTest):
    def test_flatten_upload_puts_index_at_root(self):
        site = self.folder("site", {"index.html": "<h1>", "css/a.css": ""})
        s3 = FakeS3()
        c = mock.Mock(owner="t")
        c.client.return_value = s3
        local_steps.run({"kind": "s3_upload", "source": site, "bucket": "b-site", "prefix": "", "flatten": True},
                        c, "operate", "us-east-1")
        self.assertEqual(sorted(u[2] for u in s3.uploads), ["css/a.css", "index.html"])
        self.assertEqual(next(u for u in s3.uploads if u[2] == "index.html")[3]["ContentType"], "text/html")

    def test_s3_empty_only_kintsugi_buckets(self):
        s3 = mock.Mock()
        s3.get_bucket_tagging.return_value = {"TagSet": [{"Key": "CreatedBy", "Value": "someone"}]}
        c = mock.Mock(owner="t")
        c.client.return_value = s3
        with self.assertRaises(StepError):
            local_steps.run({"kind": "s3_empty", "bucket": "b-site"}, c, "operate", "us-east-1")
        s3.get_bucket_tagging.return_value = {"TagSet": [{"Key": "CreatedBy", "Value": "kintsugi"}]}
        s3.get_paginator.return_value.paginate.return_value = [
            {"Versions": [{"Key": "index.html", "VersionId": "v1"}], "DeleteMarkers": [{"Key": "a", "VersionId": "v2"}]}]
        res = local_steps.run({"kind": "s3_empty", "bucket": "b-site"}, c, "operate", "us-east-1")
        self.assertIn("2 object version", res["summary"])
        self.assertTrue(local_steps.is_destructive({"kind": "s3_empty", "bucket": "b-site"}))
