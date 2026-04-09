"""AWS VPC Flow Log parser."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser

_DEFAULT_FIELDS = [
    "version", "account_id", "interface_id", "src_ip", "dst_ip",
    "src_port", "dst_port", "proto", "packets", "bytes",
    "start", "end", "action", "log_status",
]


class VPCFlowParser(BaseParser):
    source_type = LogSourceType.AWS_VPC_FLOW

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                header: list[str] = _DEFAULT_FIELDS[:]
                for lineno, line in enumerate(fh, start=1):
                    line = line.rstrip("\n\r")
                    if not line.strip():
                        continue

                    parts = line.split()

                    # First line may be a header
                    if lineno == 1 and parts[0].lower() in ("version", "account-id", "#version"):
                        header = [p.lower().replace("-", "_") for p in parts]
                        # Map AWS header names to canonical
                        header = [_rename(h) for h in header]
                        continue

                    fields = {}
                    for i, val in enumerate(parts):
                        key = header[i] if i < len(header) else f"field_{i}"
                        fields[key] = val if val != "-" else ""

                    ts = None
                    start_val = fields.get("start", "")
                    if start_val:
                        try:
                            ts = datetime.utcfromtimestamp(int(start_val))
                        except (ValueError, OSError):
                            pass

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


def _rename(h: str) -> str:
    _map = {
        "account_id": "account_id",
        "interface_id": "interface_id",
        "srcaddr": "src_ip",
        "dstaddr": "dst_ip",
        "srcport": "src_port",
        "dstport": "dst_port",
        "protocol": "proto",
    }
    return _map.get(h, h)
