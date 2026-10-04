"""Vault: encryption round trip, root rejection, input checks. No DB or AWS calls."""
import unittest
from types import SimpleNamespace
from unittest import mock

from cryptography.fernet import Fernet

from core import vault
from core.vault import VaultError

TEST_SETTINGS = SimpleNamespace(app_secret_key=Fernet.generate_key().decode(), aws_region="ap-south-1",
                                aws_read_profile="")


class _Sts:
    def __init__(self, arn):
        self.arn = arn

    def get_caller_identity(self):
        return {"Account": "123456789012", "Arn": self.arn}


class _Session:
    def __init__(self, arn):
        self.arn = arn

    def client(self, name):
        return _Sts(self.arn)


@mock.patch.object(vault, "settings", TEST_SETTINGS)
class TestVault(unittest.TestCase):
    def test_encrypt_roundtrip(self):
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        token = vault.encrypt(secret)
        self.assertNotIn(secret, token)
        self.assertEqual(vault.decrypt(token), secret)

    def test_wrong_key_fails_safely(self):
        token = vault.encrypt("x" * 40)
        other = SimpleNamespace(**{**vars(TEST_SETTINGS), "app_secret_key": Fernet.generate_key().decode()})
        with mock.patch.object(vault, "settings", other), self.assertRaises(VaultError) as cm:
            vault.decrypt(token)
        self.assertNotIn("x" * 40, str(cm.exception))

    def test_rejects_root(self):
        with self.assertRaises(VaultError):
            vault.verify_identity(_Session("arn:aws:iam::123456789012:root"))
        ident = vault.verify_identity(_Session("arn:aws:iam::123456789012:user/cloudai-readonly"))
        self.assertEqual(ident["account"], "123456789012")

    def test_key_hint(self):
        self.assertEqual(vault.key_hint("AKIAIOSFODNN7EXAMPLE"), "MPLE")

    def test_input_validation_before_any_aws_call(self):
        with mock.patch.object(vault, "_build_session") as build:
            for kwargs in [dict(purpose="admin", auth_mode="keys"),
                           dict(purpose="read", auth_mode="keys", access_key_id="bad", secret="s" * 40),
                           dict(purpose="read", auth_mode="keys", access_key_id="ASIAIOSFODNN7EXAMPLE", secret="s" * 40),
                           dict(purpose="read", auth_mode="profile"),
                           dict(purpose="read", auth_mode="assume_role", role_arn="arn:aws:iam::1:role/x")]:
                with self.subTest(kwargs=kwargs), self.assertRaises(VaultError):
                    vault.add_credential("me", "lbl", **kwargs)
            build.assert_not_called()

    def test_write_purpose_never_falls_back_to_profile(self):
        with mock.patch.object(vault.db, "fetch_one", return_value=None):
            with self.assertRaises(VaultError):
                vault.get_session("me", "operate")


if __name__ == "__main__":
    unittest.main()
