"""AWS CloudTrail log parser."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser
from ..generic.json_lines import _flatten, _extract_ts


class CloudTrailParser(BaseParser):
    source_type = LogSourceType.AWS_CLOUDTRAIL

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return

        content = content.strip()

        # CloudTrail files are either {"Records": [...]} or JSONL
        records: list[dict] = []
        if content.startswith("{"):
            try:
                top = json.loads(content)
                if "Records" in top:
                    records = top["Records"]
                else:
                    records = [top]
            except json.JSONDecodeError:
                pass
        elif content.startswith("["):
            try:
                records = json.loads(content)
            except json.JSONDecodeError:
                pass
        else:
            # JSONL
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

            fields = _flatten(record, sep=".")

            # Normalise common CloudTrail fields
            ui = record.get("userIdentity", {})
            fields["username"] = (
                ui.get("userName") or ui.get("principalId") or ui.get("type", "")
            )
            fields["src_ip"] = record.get("sourceIPAddress", "")
            fields["event_name"] = record.get("eventName", "")
            fields["event_source"] = record.get("eventSource", "")
            fields["aws_region"] = record.get("awsRegion", "")
            fields["user_agent"] = record.get("userAgent", "")
            fields["error_code"] = record.get("errorCode", "")
            fields["error_message"] = record.get("errorMessage", "")
            fields["account_id"] = ui.get("accountId", "")
            fields["arn"] = ui.get("arn", "")
            fields["identity_type"] = ui.get("type", "")

            ts = _extract_ts(record)
            if not ts:
                et = record.get("eventTime", "")
                if et:
                    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
                        try:
                            ts = datetime.strptime(et[:19], fmt)
                            break
                        except ValueError:
                            pass

            yield LogEvent(
                source_type=self.source_type,
                raw=json.dumps(record, separators=(",", ":")),
                fields=fields,
                timestamp=ts,
                source_file=str(path),
                line_number=lineno,
            )
