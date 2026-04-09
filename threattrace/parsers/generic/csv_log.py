"""Generic CSV log parser with automatic header detection."""
from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser

_TS_COLS = {"timestamp", "time", "date", "datetime", "ts", "eventtime", "created_at"}


def _try_parse_ts(val: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                "%m/%d/%Y %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z"):
        try:
            return datetime.strptime(val[:26].strip(), fmt)
        except ValueError:
            pass
    return None


class CSVLogParser(BaseParser):
    source_type = LogSourceType.CSV_LOG

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            with open(path, encoding="utf-8", errors="replace", newline="") as fh:
                # Sniff delimiter
                sample = fh.read(4096)
                fh.seek(0)
                try:
                    dialect = csv.Sniffer().sniff(sample, delimiters=",\t|;")
                except csv.Error:
                    dialect = csv.excel
                reader = csv.DictReader(fh, dialect=dialect)
                if reader.fieldnames is None:
                    return
                ts_col = next(
                    (c for c in reader.fieldnames if c.lower() in _TS_COLS), None
                )
                for lineno, row in enumerate(reader, start=2):
                    fields = dict(row)
                    ts = None
                    if ts_col and fields.get(ts_col):
                        ts = _try_parse_ts(str(fields[ts_col]))
                    raw = ",".join(str(v) for v in row.values())
                    yield LogEvent(
                        source_type=self.source_type,
                        raw=raw,
                        fields=fields,
                        timestamp=ts,
                        source_file=str(path),
                        line_number=lineno,
                    )
        except (OSError, PermissionError, csv.Error):
            return
