"""Acceptance test 1 logic: 'What Lambda functions are scheduled to run after 10am?' (offline, fake AWS)."""
import unittest
from datetime import datetime, timezone

from core.schedules import (collect_schedules, function_name_from_arn, parse_hhmm, scheduled_lambdas)
from tests.fakes import FakeEvents, FakeScheduler

NOW = datetime(2026, 10, 3, 0, 0, tzinfo=timezone.utc)  # 05:30 IST


class TestCollect(unittest.TestCase):
    def test_collects_only_lambda_schedules(self):
        entries, warnings = collect_schedules(FakeEvents(), FakeScheduler())
        self.assertEqual(warnings, [])
        sources = {e["source"] for e in entries}
        self.assertNotIn("EventBridge rule 's3-events'", sources)      # event pattern, not a schedule
        self.assertNotIn("EventBridge rule 'sns-nightly'", sources)    # SNS target, not Lambda
        self.assertEqual(len(entries), 7)  # 5 rules (paginated) + 2 schedules
        rule_tz = {e["timezone"] for e in entries if e["source"].startswith("EventBridge rule")}
        self.assertEqual(rule_tz, {"UTC"})

    def test_universal_target_function_name(self):
        entries, _ = collect_schedules(None, FakeScheduler())
        self.assertIn("daily-report", {e["function_name"] for e in entries})

    def test_errors_become_warnings(self):
        class Broken(FakeEvents):
            def list_rules(self, NextToken=None):
                raise RuntimeError("boom")
        entries, warnings = collect_schedules(Broken(), None)
        self.assertEqual(entries, [])
        self.assertEqual(len(warnings), 1)


class TestAfterTenAm(unittest.TestCase):
    def setUp(self):
        entries, _ = collect_schedules(FakeEvents(), FakeScheduler())
        self.res = scheduled_lambdas(entries, "10:00", "Asia/Kolkata", now=NOW)

    def _times(self, bucket):
        return {r["source"]: r["next_runs_local"][0][-5:] for r in self.res[bucket]}

    def test_runs_after_ten(self):
        t = self._times("runs_after_time")
        self.assertEqual(t["EventBridge rule 'hello-10am-ist'"], "10:00")
        self.assertEqual(t["EventBridge rule 'hello-12pm-ist'"], "12:00")
        self.assertEqual(t["EventBridge Scheduler 'hello-3pm-ist'"], "15:00")
        self.assertEqual(t["EventBridge Scheduler 'report-universal'"], "18:00")

    def test_before_ten_is_separate(self):
        self.assertEqual(self._times("runs_only_before_time"), {"EventBridge rule 'hello-0830-ist'": "08:30"})

    def test_rate_and_disabled_are_notes_not_runs(self):
        self.assertEqual([r["frequency"] for r in self.res["rate_based_no_clock_time"]], ["every hour"])
        disabled = self.res["disabled_will_not_run"]
        self.assertEqual([r["source"] for r in disabled], ["EventBridge rule 'hello-disabled'"])
        names = {r["source"] for r in self.res["runs_after_time"]}
        self.assertNotIn("EventBridge rule 'hello-disabled'", names)

    def test_states_timezone(self):
        self.assertEqual(self.res["timezone"], "Asia/Kolkata")


class TestHelpers(unittest.TestCase):
    def test_parse_hhmm(self):
        self.assertEqual(parse_hhmm("10am").strftime("%H:%M"), "10:00")
        self.assertEqual(parse_hhmm("3pm").strftime("%H:%M"), "15:00")
        self.assertEqual(parse_hhmm("12am").strftime("%H:%M"), "00:00")
        self.assertEqual(parse_hhmm("14:30").strftime("%H:%M"), "14:30")
        with self.assertRaises(ValueError):
            parse_hhmm("25:00")

    def test_function_name_from_arn(self):
        self.assertEqual(function_name_from_arn("arn:aws:lambda:ap-south-1:1:function:hello"), "hello")
        self.assertEqual(function_name_from_arn("arn:aws:lambda:ap-south-1:1:function:hello:prod"), "hello")
        self.assertIsNone(function_name_from_arn("arn:aws:sns:ap-south-1:1:topic"))


if __name__ == "__main__":
    unittest.main()
