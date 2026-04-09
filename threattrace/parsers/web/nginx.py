"""Nginx access and error log parsers."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser

# Nginx default combined log format
_ACCESS_RE = re.compile(
    r'^(?P<src_ip>\S+)\s+-\s+(?P<username>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<http_version>[^"]+)"\s+'
    r'(?P<status_code>\d{3})\s+(?P<bytes_sent>\d+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

# Nginx error: 2024/01/01 00:00:00 [error] 1234#5678: *1 message
_ERROR_RE = re.compile(
    r'^(?P<year>\d{4})/(?P<month>\d{2})/(?P<day>\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>\w+)\]\s+(?P<pid>\d+)#(?P<tid>\d+):\s+'
    r'(?:\*(?P<connection>\d+)\s+)?(?P<message>.+)$'
)


class NginxAccessParser(BaseParser):
    source_type = LogSourceType.NGINX_ACCESS

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.rstrip("\n\r")
                    if not line.strip():
                        continue
                    m = _ACCESS_RE.match(line)
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
                        ts = datetime.strptime(gd["time"], "%d/%b/%Y:%H:%M:%S %z")
                    except ValueError:
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
                            "http_method": gd["method"],
                            "url": gd["url"],
                            "http_version": gd.get("http_version", ""),
                            "status_code": int(gd["status_code"]),
                            "bytes_sent": int(gd.get("bytes_sent", 0) or 0),
                            "referrer": gd.get("referrer", ""),
                            "user_agent": gd.get("user_agent", ""),
                        },
                        timestamp=ts,
                        source_file=str(path),
                        line_number=lineno,
                    )
        except (OSError, PermissionError):
            return


class NginxErrorParser(BaseParser):
    source_type = LogSourceType.NGINX_ERROR

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.rstrip("\n\r")
                    if not line.strip():
                        continue
                    m = _ERROR_RE.match(line)
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
                        ts = datetime.strptime(
                            f"{gd['year']}-{gd['month']}-{gd['day']} {gd['time']}",
                            "%Y-%m-%d %H:%M:%S",
                        )
                    except ValueError:
                        pass

                    yield LogEvent(
                        source_type=self.source_type,
                        raw=line,
                        fields={
                            "level": gd.get("level", ""),
                            "pid": gd.get("pid", ""),
                            "message": gd.get("message", line),
                        },
                        timestamp=ts,
                        source_file=str(path),
                        line_number=lineno,
                    )
        except (OSError, PermissionError):
            return
