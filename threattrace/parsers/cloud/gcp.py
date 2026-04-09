"""GCP Cloud Audit Log parser."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser
from ..generic.json_lines import _flatten, _extract_ts


class GCPAuditParser(BaseParser):
    source_type = LogSourceType.GCP_AUDIT

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
            proto = record.get("protoPayload", {})
            if isinstance(proto, dict):
                fields["method_name"] = proto.get("methodName", "")
                fields["resource_name"] = proto.get("resourceName", "")
                fields["service_name"] = proto.get("serviceName", "")
                auth_info = proto.get("authenticationInfo", {})
                fields["username"] = auth_info.get("principalEmail", "")
                fields["src_ip"] = proto.get("requestMetadata", {}).get("callerIp", "")

            fields["log_name"] = record.get("logName", "")
            fields["severity"] = record.get("severity", "")
            fields["project_id"] = record.get("resource", {}).get("labels", {}).get("project_id", "")

            ts = _extract_ts(record)

            yield LogEvent(
                source_type=self.source_type,
                raw=json.dumps(record, separators=(",", ":")),
                fields=fields,
                timestamp=ts,
                source_file=str(path),
                line_number=lineno,
            )
