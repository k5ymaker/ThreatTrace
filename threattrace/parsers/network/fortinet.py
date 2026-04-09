"""Fortinet FortiGate log parser (key=value format)."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser

_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|((?:[^\s"\\]|\\.)*))')


def _parse_kv(line: str) -> dict:
    result = {}
    for m in _KV_RE.finditer(line):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3)
        result[key] = val
    return result


class FortinetParser(BaseParser):
    source_type = LogSourceType.FIREWALL_FORTINET

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.rstrip("\n\r")
                    if not line.strip():
                        continue

                    fields = _parse_kv(line)
                    ts = None
                    date_val = fields.get("date", "")
                    time_val = fields.get("time", "")
                    if date_val and time_val:
                        try:
                            ts = datetime.strptime(f"{date_val} {time_val}", "%Y-%m-%d %H:%M:%S")
                        except ValueError:
                            pass

                    # Normalise common fields
                    if "srcip" in fields:
                        fields["src_ip"] = fields["srcip"]
                    if "dstip" in fields:
                        fields["dst_ip"] = fields["dstip"]
                    if "srcport" in fields:
                        fields["src_port"] = fields["srcport"]
                    if "dstport" in fields:
                        fields["dst_port"] = fields["dstport"]
                    if "proto" in fields:
                        fields["proto"] = fields["proto"]

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
