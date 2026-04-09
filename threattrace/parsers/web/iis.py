"""IIS W3C Extended log parser."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser


class IISParser(BaseParser):
    source_type = LogSourceType.IIS_W3C

    def parse(self, path: Path) -> Iterator[LogEvent]:
        fields_header: list[str] = []
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.rstrip("\n\r")
                    if line.startswith("#Fields:"):
                        fields_header = line[len("#Fields:"):].strip().split()
                        continue
                    if line.startswith("#"):
                        continue
                    if not line.strip():
                        continue
                    if not fields_header:
                        continue

                    parts = line.split()
                    if len(parts) < len(fields_header):
                        parts += ["-"] * (len(fields_header) - len(parts))

                    record = dict(zip(fields_header, parts))

                    ts = None
                    if "date" in record and "time" in record:
                        try:
                            ts = datetime.strptime(
                                f"{record['date']} {record['time']}", "%Y-%m-%d %H:%M:%S"
                            )
                        except ValueError:
                            pass

                    # Normalise common field names
                    fields = {
                        "src_ip": record.get("c-ip", record.get("c-ip", "")),
                        "username": record.get("cs-username", ""),
                        "http_method": record.get("cs-method", ""),
                        "url": record.get("cs-uri-stem", "") + (
                            "?" + record.get("cs-uri-query", "")
                            if record.get("cs-uri-query", "-") != "-" else ""
                        ),
                        "status_code": record.get("sc-status", ""),
                        "bytes_sent": record.get("sc-bytes", ""),
                        "bytes_recv": record.get("cs-bytes", ""),
                        "user_agent": record.get("cs(User-Agent)", record.get("cs-user-agent", "")),
                        "server_ip": record.get("s-ip", ""),
                        "server_port": record.get("s-port", ""),
                        "time_taken_ms": record.get("time-taken", ""),
                    }
                    fields.update(record)  # keep raw IIS fields too

                    yield LogEvent(
                        source_type=self.source_type,
                        raw=line,
                        fields=fields,
                        timestamp=ts,
                        source_file=str(path),
                        line_number=lineno,
                    )
        except (OSError, PermissionError):
            return
