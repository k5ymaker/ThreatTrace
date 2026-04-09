"""Azure Activity Log and Sign-in Log parsers."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser
from ..generic.json_lines import _flatten, _extract_ts


class AzureActivityParser(BaseParser):
    source_type = LogSourceType.AZURE_ACTIVITY

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            content = path.read_text(encoding="utf-8", errors="replace").strip()
        except (OSError, PermissionError):
            return

        records: list[dict] = []
        if content.startswith("["):
            try:
                records = json.loads(content)
            except json.JSONDecodeError:
                pass
        elif content.startswith("{"):
            # May be wrapped as {"value": [...]}
            try:
                obj = json.loads(content)
                records = obj.get("value", [obj])
            except json.JSONDecodeError:
                pass
        else:
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        for lineno, record in enumerate(records, start=1):
            if not isinstance(record, dict):
                continue

            fields = _flatten(record)
            fields["operation_name"] = record.get("operationName", record.get("Operation", ""))
            fields["caller"] = record.get("caller", record.get("Caller", ""))
            fields["src_ip"] = (
                record.get("callerIpAddress") or
                record.get("ipAddress") or
                record.get("properties", {}).get("ipAddress", "")
            )
            fields["resource"] = record.get("resourceId", record.get("Resource", ""))
            fields["status"] = (
                str(record.get("status", {}).get("value", "")) or
                record.get("ResultType", "")
            )
            fields["error_code"] = record.get("errorCode", record.get("ResultDescription", ""))

            # Sign-in specific
            props = record.get("properties", {})
            if props:
                fields["username"] = props.get("userDisplayName", props.get("userPrincipalName", ""))
                fields["app_name"] = props.get("appDisplayName", "")
                fields["device_detail"] = str(props.get("deviceDetail", ""))
                fields["location"] = str(props.get("location", ""))

            ts = _extract_ts(record)

            yield LogEvent(
                source_type=self.source_type,
                raw=json.dumps(record, separators=(",", ":")),
                fields=fields,
                timestamp=ts,
                source_file=str(path),
                line_number=lineno,
            )
