import unittest
from unittest import mock

from core import audit


class AuditRetentionTests(unittest.TestCase):
    def test_log_action_prunes_to_keep_last(self):
        with mock.patch.object(audit.db, "execute", return_value=7) as ex, \
             mock.patch.object(audit.settings.__class__, "audit_keep_last", 50, create=True):
            rid = audit.log_action(actor="a", request="r", tool_name="t", tool_args={},
                                   risk="read", approval="not_required", status="success")
        self.assertEqual(rid, 7)
        self.assertEqual(ex.call_count, 2)
        sql, params = ex.call_args_list[1].args
        self.assertIn("DELETE FROM audit_logs", sql)
        self.assertEqual(params, (50,))

    def test_prune_zero_keeps_everything(self):
        with mock.patch.object(audit.db, "execute") as ex:
            audit.prune(0)
        ex.assert_not_called()

    def test_prune_failure_never_raises(self):
        with mock.patch.object(audit.db, "execute", side_effect=RuntimeError("db down")):
            audit.prune(50)

    def test_insert_failure_skips_prune(self):
        with mock.patch.object(audit.db, "execute", side_effect=RuntimeError("db down")) as ex:
            self.assertIsNone(audit.log_action(actor="a", request="r", tool_name="t", tool_args={},
                                               risk="read", approval="not_required", status="failed"))
        self.assertEqual(ex.call_count, 1)


if __name__ == "__main__":
    unittest.main()
