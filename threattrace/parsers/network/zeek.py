"""Zeek (Bro) log parser — handles TSV and JSON formats for conn/dns/http/ssl."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser
from ..generic.json_lines import _flatten


class ZeekParser(BaseParser):
    source_type = LogSourceType.ZEEK_CONN

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except (OSError, PermissionError):
            return

        lines = content.splitlines()
        if not lines:
            return

        # Auto-detect: TSV with #separator header or JSON
        first = lines[0].strip()
        if first.startswith("{"):
            yield from self._parse_json(lines, str(path))
        else:
            yield from self._parse_tsv(lines, str(path))

    def _parse_tsv(self, lines: list[str], source_file: str) -> Iterator[LogEvent]:
        import re
        separator = "\t"
        fields_header: list[str] = []
        types_header: list[str] = []

        for lineno, line in enumerate(lines, start=1):
            if line.startswith("#separator"):
                # "#separator \x09" → tab
                sep_val = line.split(None, 1)[1] if " " in line else "\t"
                if sep_val.strip() == r"\x09":
                    separator = "\t"
                continue
            if line.startswith("#fields"):
                fields_header = line.split(separator)[1:]
                continue
            if line.startswith("#types"):
                types_header = line.split(separator)[1:]
                continue
            if line.startswith("#"):
                continue
            if not line.strip():
                continue

            parts = line.split(separator)
            if not fields_header:
                continue

            record: dict = {}
            for i, val in enumerate(parts):
                if i < len(fields_header):
                    record[fields_header[i]] = val if val != "-" else ""

            ts = None
            ts_val = record.get("ts", "")
            if ts_val:
                try:
                    ts = datetime.utcfromtimestamp(float(ts_val))
                except (ValueError, OSError):
                    pass

            # Normalise
            if "id.orig_h" in record:
                record["src_ip"] = record["id.orig_h"]
            if "id.resp_h" in record:
                record["dst_ip"] = record["id.resp_h"]
            if "id.orig_p" in record:
                record["src_port"] = record["id.orig_p"]
            if "id.resp_p" in record:
                record["dst_port"] = record["id.resp_p"]

            # Detect log type from fields
            log_type = self._detect_type(fields_header)

            yield LogEvent(
                source_type=log_type,
                raw=line,
                fields=record,
                timestamp=ts,
                source_file=source_file,
                line_number=lineno,
            )

    def _parse_json(self, lines: list[str], source_file: str) -> Iterator[LogEvent]:
        import json

        for lineno, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            fields = _flatten(obj)
            # Normalise
            if "_id.orig_h" in fields:
                fields["src_ip"] = fields["_id.orig_h"]
            if "id.orig_h" in fields:
                fields["src_ip"] = fields["id.orig_h"]
            if "id.resp_h" in fields:
                fields["dst_ip"] = fields["id.resp_h"]

            ts = None
            ts_val = obj.get("ts")
            if ts_val:
                try:
                    ts = datetime.utcfromtimestamp(float(ts_val))
                except (ValueError, TypeError):
                    pass

            log_type = self._detect_type(list(fields.keys()))

            yield LogEvent(
                source_type=log_type,
                raw=line,
                fields=fields,
                timestamp=ts,
                source_file=source_file,
                line_number=lineno,
            )

    def _detect_type(self, field_names: list[str]) -> LogSourceType:
        names_set = set(field_names)
        if "query" in names_set:
            return LogSourceType.ZEEK_DNS
        if "method" in names_set and "host" in names_set:
            return LogSourceType.ZEEK_HTTP
        if "server_name" in names_set or "cipher" in names_set:
            return LogSourceType.ZEEK_CONN
        if "orig_bytes" in names_set or "resp_bytes" in names_set:
            return LogSourceType.ZEEK_CONN
        return LogSourceType.ZEEK_CONN
