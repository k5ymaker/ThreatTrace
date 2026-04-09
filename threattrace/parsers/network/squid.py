"""Squid Proxy native log parser."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser

# Squid native: timestamp elapsed client action/code size method URL hierarchy/peer type
_SQUID_RE = re.compile(
    r'^(?P<epoch>\d{10}\.\d{3})\s+(?P<elapsed>\d+)\s+(?P<src_ip>\S+)\s+'
    r'(?P<action>[A-Z_]+)/(?P<status_code>\d{3})\s+(?P<bytes>\d+)\s+'
    r'(?P<http_method>\S+)\s+(?P<url>\S+)\s+(?P<username>\S+)\s+'
    r'(?P<hierarchy>[^/]+)/(?P<peer>\S+)\s+(?P<content_type>\S+)?'
)


class SquidParser(BaseParser):
    source_type = LogSourceType.SQUID_PROXY

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.rstrip("\n\r")
                    if not line.strip():
                        continue

                    m = _SQUID_RE.match(line)
                    if not m:
                        yield LogEvent(
                            source_type=self.source_type,
                            raw=line,
                            fields={"message": line},
                            source_file=str(path),
                            line_number=lineno,
                        )
                        continue

                    gd = m.groupdict()
                    ts = None
                    try:
                        ts = datetime.utcfromtimestamp(float(gd["epoch"]))
                    except (ValueError, OSError):
                        pass

                    username = gd.get("username", "-")
                    if username == "-":
                        username = ""

                    yield LogEvent(
                        source_type=self.source_type,
                        raw=line,
                        fields={
                            "src_ip": gd["src_ip"],
                            "username": username,
                            "http_method": gd["http_method"],
                            "url": gd["url"],
                            "status_code": int(gd["status_code"]),
                            "bytes_sent": int(gd.get("bytes", 0)),
                            "squid_action": gd.get("action", ""),
                            "content_type": gd.get("content_type", ""),
                            "elapsed_ms": int(gd.get("elapsed", 0)),
                        },
                        timestamp=ts,
                        source_file=str(path),
                        line_number=lineno,
                    )
        except (OSError, PermissionError):
            return
