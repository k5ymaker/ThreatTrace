"""Generic plaintext log parser — yields one LogEvent per non-empty line."""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser

_TS_PATTERNS = [
    # ISO 8601
    (__import__("re").compile(
        r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    ), "%Y-%m-%dT%H:%M:%S"),
    # Syslog-style
    (__import__("re").compile(
        r"((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    ), "%b %d %H:%M:%S"),
    # US date
    (__import__("re").compile(r"(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})"), "%m/%d/%Y %H:%M:%S"),
]


def _try_parse_ts(line: str):
    from datetime import datetime
    for pattern, fmt in _TS_PATTERNS:
        m = pattern.search(line)
        if m:
            ts_str = m.group(1).replace("T", " ").rstrip("Z")
            try:
                return datetime.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass
            try:
                from datetime import datetime as dt
                import time
                return dt.fromtimestamp(
                    time.mktime(time.strptime(ts_str, fmt.replace("%Y", str(__import__("datetime").date.today().year))))
                )
            except Exception:
                pass
    return None


class PlaintextParser(BaseParser):
    source_type = LogSourceType.PLAINTEXT

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.rstrip("\n\r")
                    if not line.strip():
                        continue
                    yield LogEvent(
                        source_type=self.source_type,
                        raw=line,
                        fields={"message": line},
                        timestamp=_try_parse_ts(line),
                        source_file=str(path),
                        line_number=lineno,
                    )
        except (OSError, PermissionError):
            return
