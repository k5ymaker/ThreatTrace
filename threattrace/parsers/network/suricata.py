"""Suricata EVE JSON log parser."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser
from ..generic.json_lines import _flatten, _extract_ts


class SuricataEVEParser(BaseParser):
    source_type = LogSourceType.SURICATA_EVE

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.strip()
                    if not line or not line.startswith("{"):
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    fields = _flatten(obj)

                    # Normalise key fields
                    fields.setdefault("src_ip", obj.get("src_ip", ""))
                    fields.setdefault("dst_ip", obj.get("dest_ip", ""))
                    fields.setdefault("src_port", str(obj.get("src_port", "")))
                    fields.setdefault("dst_port", str(obj.get("dest_port", "")))
                    fields.setdefault("proto", obj.get("proto", ""))
                    fields.setdefault("event_type", obj.get("event_type", ""))

                    # Alert specifics
                    alert = obj.get("alert", {})
                    if alert:
                        fields["alert_signature"] = alert.get("signature", "")
                        fields["alert_category"] = alert.get("category", "")
                        fields["alert_severity"] = str(alert.get("severity", ""))
                        fields["alert_sid"] = str(alert.get("signature_id", ""))
                        fields["mitre_technique"] = alert.get("metadata", {}).get(
                            "mitre_technique_id", [""]
                        )
                        if isinstance(fields["mitre_technique"], list):
                            fields["mitre_technique"] = (
                                fields["mitre_technique"][0]
                                if fields["mitre_technique"] else ""
                            )

                    ts = _extract_ts(obj)

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
