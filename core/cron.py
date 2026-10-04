"""AWS schedule expressions: cron(...), rate(...), at(...). Pure code, no AWS calls.

AWS cron has 6 fields: minutes hours day-of-month month day-of-week year
  - day-of-week is 1-7 with 1 = SUNDAY (or SUN-SAT); one of day-of-month / day-of-week must be '?'
  - supports * ? , - / L W # and names (JAN-DEC, SUN-SAT)
EventBridge rule crons are always UTC; EventBridge Scheduler uses ScheduleExpressionTimezone.
The LLM never does this arithmetic.
"""
import calendar
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo


class CronError(ValueError):
    pass


_MONTHS = {m: i for i, m in enumerate(
    ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"], start=1)}
_DOWS = {d: i for i, d in enumerate(["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"], start=1)}


def _aws_dow(d: date) -> int:
    """Python weekday (Mon=0) -> AWS day-of-week (Sun=1 .. Sat=7)."""
    return (d.weekday() + 1) % 7 + 1


def _parse_set(field: str, lo: int, hi: int, names: dict | None = None) -> set[int]:
    """Parse a simple cron field (no L/W/#) into a set of ints."""
    result: set[int] = set()
    for part in field.split(","):
        part = part.strip().upper()
        if not part:
            raise CronError(f"empty value in '{field}'")
        step = 1
        if "/" in part:
            part, step_s = part.split("/", 1)
            if not step_s.isdigit() or int(step_s) == 0:
                raise CronError(f"bad step in '{field}'")
            step = int(step_s)
        if part in ("*", "?"):
            start, end = lo, hi
        elif "-" in part:
            a, b = part.split("-", 1)
            start, end = _value(a, names), _value(b, names)
        else:
            start = _value(part, names)
            end = hi if step > 1 else start
        if not (lo <= start <= hi and lo <= end <= hi):
            raise CronError(f"value out of range {lo}-{hi} in '{field}'")
        if start <= end:
            result.update(range(start, end + 1, step))
        else:  # wrap-around range, e.g. FRI-MON
            seq = list(range(start, hi + 1)) + list(range(lo, end + 1))
            result.update(seq[::step])
    return result


def _value(token: str, names: dict | None) -> int:
    token = token.strip().upper()
    if names and token in names:
        return names[token]
    if not token.isdigit():
        raise CronError(f"unknown value '{token}'")
    return int(token)


@dataclass
class AwsCron:
    expression: str
    minutes: set[int]
    hours: set[int]
    dom: str
    months: set[int]
    dow: str
    years: set[int] | None

    @classmethod
    def parse(cls, expr: str) -> "AwsCron":
        m = re.fullmatch(r"\s*cron\((.*)\)\s*", expr)
        body = m.group(1) if m else expr
        fields = body.split()
        if len(fields) != 6:
            raise CronError(f"AWS cron needs 6 fields (min hour dom month dow year), got {len(fields)}: '{expr}'")
        mi, hr, dom, mon, dow, yr = fields
        if (dom == "?") == (dow == "?"):
            raise CronError("exactly one of day-of-month or day-of-week must be '?'")
        c = cls(
            expression=expr.strip(),
            minutes=_parse_set(mi, 0, 59),
            hours=_parse_set(hr, 0, 23),
            dom=dom.upper(),
            months=_parse_set(mon, 1, 12, _MONTHS),
            dow=dow.upper(),
            years=None if yr in ("*", "?") else _parse_set(yr, 1970, 2199),
        )
        # Validate day fields eagerly so bad expressions fail at parse time.
        c._day_matches(date(2024, 1, 1))
        return c

    # -- day matching --------------------------------------------------------------
    def _dom_matches(self, d: date) -> bool:
        f = self.dom
        if f in ("*", "?"):
            return True
        last = calendar.monthrange(d.year, d.month)[1]
        for part in f.split(","):
            if part == "L":
                if d.day == last:
                    return True
            elif part.startswith("L-") and part[2:].isdigit():
                if d.day == last - int(part[2:]):
                    return True
            elif part == "LW":
                if d == _nearest_weekday(d.year, d.month, last):
                    return True
            elif part.endswith("W") and part[:-1].isdigit():
                target = int(part[:-1])
                if not 1 <= target <= 31:
                    raise CronError(f"bad W day '{part}'")
                if target <= last and d == _nearest_weekday(d.year, d.month, target):
                    return True
            elif d.day in _parse_set(part, 1, 31):
                return True
        return False

    def _dow_matches(self, d: date) -> bool:
        f = self.dow
        if f in ("*", "?"):
            return True
        wd = _aws_dow(d)
        last = calendar.monthrange(d.year, d.month)[1]
        for part in f.split(","):
            if "#" in part:
                a, n = part.split("#", 1)
                target, nth = _value(a, _DOWS), int(n)
                if not (1 <= target <= 7 and 1 <= nth <= 5):
                    raise CronError(f"bad '#' value '{part}'")
                if wd == target and (d.day - 1) // 7 + 1 == nth:
                    return True
            elif part.endswith("L") and len(part) > 1:
                target = _value(part[:-1], _DOWS)
                if wd == target and d.day + 7 > last:
                    return True
            elif part == "L":  # 'L' alone in day-of-week = Saturday (7)
                if wd == 7:
                    return True
            elif wd in _parse_set(part, 1, 7, _DOWS):
                return True
        return False

    def _day_matches(self, d: date) -> bool:
        if d.month not in self.months:
            return False
        if self.years is not None and d.year not in self.years:
            return False
        return self._dom_matches(d) and self._dow_matches(d)

    # -- run times -----------------------------------------------------------------
    def next_runs(self, after: datetime, tz: str = "UTC", count: int = 5, max_days: int = 400) -> list[datetime]:
        """Next `count` run times strictly after `after`, evaluated in timezone `tz` (tz-aware results)."""
        zone = ZoneInfo(tz)
        if after.tzinfo is None:
            raise ValueError("after must be timezone-aware")
        start_local = after.astimezone(zone)
        runs: list[datetime] = []
        d = start_local.date()
        for _ in range(max_days):
            if self._day_matches(d):
                for h in sorted(self.hours):
                    for m in sorted(self.minutes):
                        t = datetime(d.year, d.month, d.day, h, m, tzinfo=zone)
                        if t > start_local:
                            runs.append(t)
                            if len(runs) >= count:
                                return runs
            d += timedelta(days=1)
        return runs


def _nearest_weekday(year: int, month: int, day: int) -> date:
    """AWS 'W': nearest weekday (Mon-Fri) to the given day, never crossing into another month."""
    d = date(year, month, day)
    if d.weekday() == 5:  # Saturday
        return d - timedelta(days=1) if day > 1 else d + timedelta(days=2)
    if d.weekday() == 6:  # Sunday
        last = calendar.monthrange(year, month)[1]
        return d + timedelta(days=1) if day < last else d - timedelta(days=2)
    return d


# ---- rate(...) and at(...) -------------------------------------------------------

_RATE_RE = re.compile(r"\s*rate\(\s*(\d+)\s+(minute|minutes|hour|hours|day|days)\s*\)\s*", re.I)
_AT_RE = re.compile(r"\s*at\(\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s*\)\s*", re.I)


def parse_rate(expr: str) -> timedelta | None:
    m = _RATE_RE.fullmatch(expr)
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2).lower().rstrip("s")
    return {"minute": timedelta(minutes=n), "hour": timedelta(hours=n), "day": timedelta(days=n)}[unit]


def describe_rate(expr: str) -> str:
    m = _RATE_RE.fullmatch(expr)
    if not m:
        return expr
    n, unit = int(m.group(1)), m.group(2).lower().rstrip("s")
    return f"every {unit}" if n == 1 else f"every {n} {unit}s"


def parse_at(expr: str, tz: str = "UTC") -> datetime | None:
    m = _AT_RE.fullmatch(expr)
    if not m:
        return None
    return datetime.fromisoformat(m.group(1)).replace(tzinfo=ZoneInfo(tz))


def expression_kind(expr: str) -> str:
    e = (expr or "").strip().lower()
    for kind in ("cron", "rate", "at"):
        if e.startswith(kind + "("):
            return kind
    return "unknown"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
