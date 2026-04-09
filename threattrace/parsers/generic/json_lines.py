"""Generic JSON Lines parser — one JSON object per line."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser

_TS_FIELDS = ["timestamp", "ts", "time", "eventTime", "created", "@timestamp",
              "Timestamp", "date", "datetime", "log_timestamp"]


def _extract_ts(obj: dict) -> datetime | None:
    for field in _TS_FIELDS:
        val = obj.get(field)
        if val is None:
            continue
        if isinstance(val, (int, float)):
            try:
                return datetime.utcfromtimestamp(float(val))
            except (ValueError, OSError):
                pass
        if isinstance(val, str):
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.strptime(val[:26], fmt)
                except ValueError:
                    pass
    return None


def _flatten(obj: Any, prefix: str = "", sep: str = ".") -> dict:
    """Flatten nested dict to dot-notation keys (max 3 levels)."""
    result: dict = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{prefix}{sep}{k}" if prefix else k
            if isinstance(v, dict) and prefix.count(sep) < 2:
                result.update(_flatten(v, new_key, sep))
            else:
                result[new_key] = v
    return result


class JSONLinesParser(BaseParser):
    source_type = LogSourceType.JSON_LINES

    def parse(self, path: Path) -> Iterator[LogEvent]:
        # Handle both JSONL (one object per line) and JSON array files
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return

        lines = content.splitlines()
        if not lines:
            return

        # Check if it's a JSON array
        stripped = content.strip()
        if stripped.startswith("["):
            try:
                records = json.loads(stripped)
                if isinstance(records, list):
                    for lineno, record in enumerate(records, start=1):
                        if isinstance(record, dict):
                            yield self._make_event(record, str(path), lineno)
                    return
            except json.JSONDecodeError:
                pass

        # JSONL: one object per line
        for lineno, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    yield self._make_event(obj, str(path), lineno)
            except json.JSONDecodeError:
                pass

    def _make_event(self, obj: dict, source_file: str, lineno: int) -> LogEvent:
        fields = _flatten(obj)
        ts = _extract_ts(obj)
        return LogEvent(
            source_type=self.source_type,
            raw=json.dumps(obj, separators=(",", ":")),
            fields=fields,
            timestamp=ts,
            source_file=source_file,
            line_number=lineno,
        )
