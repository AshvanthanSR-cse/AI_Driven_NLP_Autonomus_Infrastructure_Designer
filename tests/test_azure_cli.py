"""Azure CLI sign-in connections (az login): tokens from the CLI, nothing secret stored (no network, no az)."""
import json
import subprocess
import time
import unittest
from unittest import mock

from core import clouds, vault

SUB = "33333333-3333-3333-3333-333333333333"


def fake_run(responses):
    calls = []

    def run(cmd, **kw):
        calls.append(cmd[1:])
        key = " ".join(cmd[1:3])
        out = responses.get(key, {})
        if isinstance(out, Exception):
            return subprocess.CompletedProcess(cmd, 1, "", str(out))
        return subprocess.CompletedProcess(cmd, 0, json.dumps(out), "")
    return run, calls


class AzureCliTest(unittest.TestCase):
    def setUp(self):
        p = mock.patch("core.clouds.shutil.which", return_value="C:/az/az.cmd")
        p.start()
        self.addCleanup(p.stop)

    def test_subscriptions_are_listed(self):
        run, _ = fake_run({"account list": [
            {"id": SUB, "name": "Dev", "tenantId": "t", "user": {"name": "me@x.com"}, "isDefault": True},
            {"id": "x", "name": "Old", "state": "Disabled"}]})
        with mock.patch("core.clouds.subprocess.run", run):
            subs = clouds.az_subscriptions()
        self.assertEqual(subs, [{"id": SUB, "name": "Dev", "tenant_id": "t", "user": "me@x.com", "default": True}])

    def test_token_comes_from_cli_for_the_right_resource(self):
        run, calls = fake_run({"account get-access-token": {"accessToken": "tok",
                                                             "expires_on": int(time.time()) + 3000}})
        c = clouds.make_connector("azure", {"auth": "cli", "subscription_id": SUB}, "")
        self.assertIsInstance(c, clouds.AzureCliConnector)
        with mock.patch("core.clouds.subprocess.run", run):
            self.assertEqual(c._token("https://management.azure.com/.default"), "tok")
            c._token("https://management.azure.com/.default")
        self.assertEqual(len(calls), 1)
        self.assertIn("https://management.azure.com/", calls[0])
        self.assertIn(SUB, calls[0])
        self.assertEqual(calls[0][-2:], ["--output", "json"])

    def test_cli_error_is_readable_and_hides_tokens(self):
        run, _ = fake_run({"account list": RuntimeError("ERROR: Please run 'az login' to setup account. token=abc")})
        with mock.patch("core.clouds.subprocess.run", run):
            with self.assertRaises(clouds.CloudError) as e:
                clouds.az_subscriptions()
        self.assertIn("az login", str(e.exception))
        self.assertNotIn("abc", str(e.exception))

    def test_missing_cli_is_reported(self):
        with mock.patch("core.clouds.shutil.which", return_value=None):
            with self.assertRaises(clouds.CloudError) as e:
                clouds.az_run(["account", "list"])
        self.assertIn("winget install", str(e.exception))

    def test_vault_cli_fields_store_no_secret(self):
        config, secret, hint = vault._cloud_fields("azure", {"auth": "cli", "subscription_id": SUB})
        self.assertEqual((config, secret, hint), ({"auth": "cli", "subscription_id": SUB}, "", "az login"))
        with self.assertRaises(vault.VaultError):
            vault._cloud_fields("azure", {"auth": "cli", "subscription_id": "not-a-guid"})

    def test_service_principal_still_uses_client_credentials(self):
        c = clouds.make_connector("azure", {"tenant_id": "t", "client_id": "c", "subscription_id": SUB}, "s")
        self.assertIs(type(c), clouds.AzureConnector)


if __name__ == "__main__":
    unittest.main()
