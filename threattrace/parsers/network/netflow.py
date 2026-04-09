"""NetFlow/IPFIX parser (nfdump CSV export format)."""
from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser


class NetFlowParser(BaseParser):
    source_type = LogSourceType.NETFLOW

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            with open(path, encoding="utf-8", errors="replace", newline="") as fh:
                reader = csv.DictReader(fh)
                if reader.fieldnames is None:
                    return
                for lineno, row in enumerate(reader, start=2):
                    fields = dict(row)
                    ts = None
                    for ts_key in ("ts", "Date first seen", "date_first_seen", "start"):
                        val = fields.get(ts_key, "")
                        if val:
                            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                                try:
                                    ts = datetime.strptime(val[:19], fmt)
                                    break
                                except ValueError:
                                    pass
                            if ts:
                                break

                    # Normalise nfdump column names
                    fields.setdefault("src_ip", fields.get("Src IP Addr", fields.get("src_addr", "")))
                    fields.setdefault("dst_ip", fields.get("Dst IP Addr", fields.get("dst_addr", "")))
                    fields.setdefault("src_port", fields.get("Src Pt", fields.get("src_port", "")))
                    fields.setdefault("dst_port", fields.get("Dst Pt", fields.get("dst_port", "")))
                    fields.setdefault("proto", fields.get("Proto", fields.get("proto", "")))
                    fields.setdefault("bytes_sent", fields.get("Bytes", fields.get("bytes", "0")))

                    yield LogEvent(
                        source_type=self.source_type,
                        raw=",".join(str(v) for v in row.values()),
                        fields=fields,
                        timestamp=ts,
                        source_file=str(path),
                        line_number=lineno,
                    )
        except (OSError, PermissionError, csv.Error):
            return
