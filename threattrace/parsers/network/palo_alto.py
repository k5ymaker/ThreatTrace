"""Palo Alto PAN-OS CSV log parser."""
from __future__ import annotations

import csv
import io
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser

# PAN-OS Traffic log CSV field order (simplified)
_TRAFFIC_FIELDS = [
    "domain", "receive_time", "serial", "type", "threat_content_type",
    "config_version", "generate_time", "src_ip", "dst_ip",
    "nat_src_ip", "nat_dst_ip", "rule_name", "src_user", "dst_user",
    "application", "virtual_system", "src_zone", "dst_zone",
    "ingress_interface", "egress_interface", "log_forwarding_profile",
    "time_logged", "session_id", "repeat_count", "src_port", "dst_port",
    "nat_src_port", "nat_dst_port", "flags", "proto", "action",
    "bytes", "bytes_sent", "bytes_recv", "packets", "start_time",
    "elapsed_time", "category", "padding", "seqno", "actionflags",
    "src_country", "dst_country", "pkts_sent", "pkts_recv",
    "session_end_reason",
]


class PaloAltoParser(BaseParser):
    source_type = LogSourceType.FIREWALL_PALO_ALTO

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            with open(path, encoding="utf-8", errors="replace", newline="") as fh:
                reader = csv.reader(fh)
                for lineno, row in enumerate(reader, start=1):
                    if not row:
                        continue
                    raw = ",".join(row)

                    if len(row) >= 6 and row[3].upper() in ("TRAFFIC", "THREAT", "SYSTEM"):
                        # Try named mapping
                        fields = {}
                        for i, val in enumerate(row):
                            if i < len(_TRAFFIC_FIELDS):
                                fields[_TRAFFIC_FIELDS[i]] = val
                            else:
                                fields[f"field_{i}"] = val
                    else:
                        fields = {f"field_{i}": v for i, v in enumerate(row)}

                    ts = None
                    for ts_key in ("receive_time", "generate_time", "start_time"):
                        val = fields.get(ts_key, "")
                        if val:
                            for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                                try:
                                    ts = datetime.strptime(val, fmt)
                                    break
                                except ValueError:
                                    pass
                            if ts:
                                break

                    fields["log_type"] = fields.get("type", "")

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
