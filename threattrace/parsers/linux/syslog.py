"""Linux syslog parser — handles /var/log/syslog, /var/log/messages, auth.log, etc."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser

# Standard syslog: "Jan  1 00:00:00 hostname program[pid]: message"
_SYSLOG_RE = re.compile(
    r"^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+(?P<hostname>\S+)"
    r"\s+(?P<program>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.+)$"
)

# RFC 5424: "2024-01-01T00:00:00.000000+00:00 hostname program pid - - message"
_RFC5424_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"
    r"\s+(?P<hostname>\S+)"
    r"\s+(?P<program>\S+)"
    r"\s+(?P<pid>\S+)"
    r"\s+\S+\s+\S+\s+(?P<message>.+)$"
)

_MONTH_MAP = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1
)}


def _parse_syslog_ts(month: str, day: str, time_str: str) -> "datetime | None":
    """Parse a syslog-style timestamp; returns None on any invalid value."""
    import calendar
    try:
        year = datetime.now().year
        h, m, s = map(int, time_str.split(":"))
        mon = _MONTH_MAP.get(month, 1)
        day_int = max(1, int(day))          # guard against day=0
        # Try current year, then ±1 year (handles Feb 29 in non-leap years)
        for y in (year, year - 1, year + 1):
            try:
                return datetime(y, mon, day_int, h, m, s)
            except ValueError:
                continue
        # Final fallback: clamp day to last valid day of the month
        last_day = calendar.monthrange(year, mon)[1]
        return datetime(year, mon, min(day_int, last_day), h, m, s)
    except Exception:
        return None


class SyslogParser(BaseParser):
    source_type = LogSourceType.LINUX_SYSLOG

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.rstrip("\n\r")
                    if not line.strip():
                        continue

                    m = _SYSLOG_RE.match(line)
                    if m:
                        gd = m.groupdict()
                        ts = _parse_syslog_ts(gd["month"], gd["day"], gd["time"])
                        fields = {
                            "hostname": gd["hostname"],
                            "program": gd["program"],
                            "pid": gd.get("pid", ""),
                            "message": gd["message"],
                        }
                        yield LogEvent(
                            source_type=self.source_type,
                            raw=line,
                            fields=fields,
                            timestamp=ts,
                            source_file=str(path),
                            line_number=lineno,
                        )
                        continue

                    m = _RFC5424_RE.match(line)
                    if m:
                        gd = m.groupdict()
                        ts_str = gd["timestamp"].replace("Z", "+00:00")
                        try:
                            from datetime import timezone
                            ts = datetime.fromisoformat(ts_str[:26])
                        except ValueError:
                            ts = None
                        fields = {
                            "hostname": gd["hostname"],
                            "program": gd["program"],
                            "pid": gd.get("pid", ""),
                            "message": gd["message"],
                        }
                        yield LogEvent(
                            source_type=self.source_type,
                            raw=line,
                            fields=fields,
                            timestamp=ts,
                            source_file=str(path),
                            line_number=lineno,
                        )
                        continue

                    # Fallback: unstructured line
                    yield LogEvent(
                        source_type=self.source_type,
                        raw=line,
                        fields={"message": line},
                        source_file=str(path),
                        line_number=lineno,
                    )
        except (OSError, PermissionError):
            return
