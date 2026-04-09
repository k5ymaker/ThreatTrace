"""HAProxy log parser."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser

# HAProxy HTTP log format
# Feb  1 00:00:00 hostname haproxy[123]: 1.2.3.4:50000 [01/Feb/2024:00:00:00.000] frontend backend/server 0/0/0/1/1 200 1234 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"
_HAPROXY_RE = re.compile(
    r'haproxy\[\d+\]:\s+'
    r'(?P<src_ip>\S+):(?P<src_port>\d+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'(?P<frontend>\S+)\s+'
    r'(?P<backend>\S+)\s+'
    r'(?P<timers>[\d/+-]+)\s+'
    r'(?P<status_code>\d+)\s+'
    r'(?P<bytes_read>\d+)\s+'
    r'\S+\s+\S+\s+\S+\s+'
    r'[\d/]+\s+[\d/]+\s+'
    r'"(?P<request>[^"]*)"'
)


class HAProxyParser(BaseParser):
    source_type = LogSourceType.HAPROXY

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.rstrip("\n\r")
                    if not line.strip():
                        continue
                    m = _HAPROXY_RE.search(line)
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
                        ts = datetime.strptime(gd["time"][:26], "%d/%b/%Y:%H:%M:%S.%f")
                    except ValueError:
                        try:
                            ts = datetime.strptime(gd["time"][:19], "%d/%b/%Y:%H:%M:%S")
                        except ValueError:
                            pass

                    request = gd.get("request", "")
                    req_parts = request.split()
                    yield LogEvent(
                        source_type=self.source_type,
                        raw=line,
                        fields={
                            "src_ip": gd["src_ip"],
                            "src_port": gd["src_port"],
                            "frontend": gd.get("frontend", ""),
                            "backend": gd.get("backend", ""),
                            "status_code": int(gd["status_code"]),
                            "bytes_sent": int(gd.get("bytes_read", 0)),
                            "http_method": req_parts[0] if req_parts else "",
                            "url": req_parts[1] if len(req_parts) > 1 else "",
                        },
                        timestamp=ts,
                        source_file=str(path),
                        line_number=lineno,
                    )
        except (OSError, PermissionError):
            return
