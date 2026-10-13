"""AWS cron / rate / at parsing and next-run computation (the LLM must never do this math)."""
import unittest
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from core.cron import AwsCron, CronError, describe_rate, expression_kind, parse_at, parse_rate

UTC = timezone.utc
IST = ZoneInfo("Asia/Kolkata")
START = datetime(2026, 10, 3, 0, 0, tzinfo=UTC)


class TestAwsCron(unittest.TestCase):
    def test_daily_utc_converts_to_ist(self):
        runs = AwsCron.parse("cron(30 4 * * ? *)").next_runs(START, "UTC", count=2)
        self.assertEqual(runs[0], datetime(2026, 10, 3, 4, 30, tzinfo=UTC))
        self.assertEqual(runs[0].astimezone(IST).strftime("%H:%M"), "10:00")
        self.assertEqual(runs[1] - runs[0], timedelta(days=1))

    def test_strictly_after(self):
        after = datetime(2026, 10, 3, 4, 30, tzinfo=UTC)
        runs = AwsCron.parse("cron(30 4 * * ? *)").next_runs(after, "UTC", count=1)
        self.assertEqual(runs[0], datetime(2026, 10, 4, 4, 30, tzinfo=UTC))

    def test_day_of_week_one_is_sunday(self):
        runs = AwsCron.parse("cron(0 0 ? * 1 *)").next_runs(START, "UTC", count=4)
        self.assertTrue(all(r.weekday() == 6 for r in runs))
        runs = AwsCron.parse("cron(0 0 ? * 2 *)").next_runs(START, "UTC", count=4)
        self.assertTrue(all(r.weekday() == 0 for r in runs))

    def test_weekday_names_and_range(self):
        runs = AwsCron.parse("cron(0 9 ? * MON-FRI *)").next_runs(START, "UTC", count=10)
        self.assertTrue(all(r.weekday() < 5 for r in runs))
        self.assertEqual(runs[0], datetime(2026, 10, 5, 9, 0, tzinfo=UTC))

    def test_wraparound_dow_range(self):
        runs = AwsCron.parse("cron(0 0 ? * FRI-MON *)").next_runs(START, "UTC", count=8)
        self.assertEqual({r.weekday() for r in runs}, {4, 5, 6, 0})

    def test_minute_step(self):
        c = AwsCron.parse("cron(0/15 * * * ? *)")
        self.assertEqual(c.minutes, {0, 15, 30, 45})
        self.assertEqual(AwsCron.parse("cron(*/20 * * * ? *)").minutes, {0, 20, 40})

    def test_last_day_of_month(self):
        runs = AwsCron.parse("cron(0 12 L * ? *)").next_runs(START, "UTC", count=3)
        self.assertEqual([r.date().isoformat() for r in runs], ["2026-10-31", "2026-11-30", "2026-12-31"])

    def test_last_friday(self):
        runs = AwsCron.parse("cron(0 0 ? * 6L *)").next_runs(START, "UTC", count=2)
        self.assertEqual([r.day for r in runs], [30, 27])
        self.assertTrue(all(r.weekday() == 4 for r in runs))

    def test_nth_weekday(self):
        runs = AwsCron.parse("cron(0 0 ? * 6#3 *)").next_runs(START, "UTC", count=1)
        self.assertEqual(runs[0].date().isoformat(), "2026-10-16")

    def test_nearest_weekday(self):
        runs = AwsCron.parse("cron(0 0 15W 11 ? 2026)").next_runs(START, "UTC", count=1)
        self.assertEqual(runs[0].date().isoformat(), "2026-11-16")

    def test_year_field_limits_runs(self):
        runs = AwsCron.parse("cron(0 0 1 1 ? 2027)").next_runs(START, "UTC", count=5, max_days=800)
        self.assertEqual([r.date().isoformat() for r in runs], ["2027-01-01"])

    def test_month_names(self):
        runs = AwsCron.parse("cron(0 0 1 JAN,JUL ? *)").next_runs(START, "UTC", count=2, max_days=400)
        self.assertEqual([r.month for r in runs], [1, 7])

    def test_scheduler_timezone(self):
        runs = AwsCron.parse("cron(0 15 * * ? *)").next_runs(START, "Asia/Kolkata", count=1)
        self.assertEqual(runs[0].astimezone(UTC), datetime(2026, 10, 3, 9, 30, tzinfo=UTC))

    def test_invalid_expressions(self):
        for bad in ("cron(0 0 * * * *)",
                    "cron(0 0 ? * ? *)",
                    "cron(0 0 * * ?)",
                    "cron(60 0 * * ? *)",
                    "cron(0 24 * * ? *)",
                    "cron(0 0 ? * 8 *)",
                    "cron(0 0 ? * FOO *)"):
            with self.subTest(bad=bad), self.assertRaises(CronError):
                AwsCron.parse(bad)


class TestRateAndAt(unittest.TestCase):
    def test_rate(self):
        self.assertEqual(parse_rate("rate(1 hour)"), timedelta(hours=1))
        self.assertEqual(parse_rate("rate(5 minutes)"), timedelta(minutes=5))
        self.assertEqual(describe_rate("rate(1 hour)"), "every hour")
        self.assertEqual(describe_rate("rate(2 days)"), "every 2 days")
        self.assertIsNone(parse_rate("rate(1 week)"))

    def test_at(self):
        dt = parse_at("at(2026-10-03T15:00:00)", "Asia/Kolkata")
        self.assertEqual(dt.astimezone(UTC), datetime(2026, 10, 3, 9, 30, tzinfo=UTC))

    def test_kind(self):
        self.assertEqual(expression_kind("cron(0 0 * * ? *)"), "cron")
        self.assertEqual(expression_kind("rate(1 day)"), "rate")
        self.assertEqual(expression_kind("at(2026-01-01T00:00:00)"), "at")
        self.assertEqual(expression_kind("weekly"), "unknown")


if __name__ == "__main__":
    unittest.main()
