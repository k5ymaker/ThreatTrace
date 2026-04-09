"""Apache access and error log parsers."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser

# Apache Combined Log Format
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://ref" "Mozilla/5.0"
_ACCESS_RE = re.compile(
    r'^(?P<src_ip>\S+)\s+\S+\s+(?P<username>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<http_version>[^"]+)"\s+'
    r'(?P<status_code>\d{3})\s+(?P<bytes_sent>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

_ACCESS_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"

# Apache error log: [Wed Oct 11 14:32:52.123456 2000] [core:error] [pid 1234] ...
_ERROR_RE = re.compile(
    r'^\[(?P<weekday>\w+)\s+(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:.]+)\s+(?P<year>\d{4})\]\s+'
    r'\[(?P<module>[^\]]+)\]\s+'
    r'(?:\[pid (?P<pid>\d+)(?::[^\]]+)?\]\s+)?'
    r'(?:\[client (?P<src_ip>[^\]]+)\]\s+)?'
    r'(?P<message>.+)$'
)


class ApacheAccessParser(BaseParser):
    source_type = LogSourceType.APACHE_ACCESS

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
                        ts = datetime.strptime(gd["time"], _ACCESS_TS_FMT)
                    except ValueError:
                        pass

                    username = gd.get("username", "-")
                    if username == "-":
                        username = ""

                    bytes_val = gd.get("bytes_sent", "0")
                    try:
                        bytes_sent = int(bytes_val) if bytes_val != "-" else 0
                    except ValueError:
                        bytes_sent = 0

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
                            "bytes_sent": bytes_sent,
                            "referrer": gd.get("referrer", ""),
                            "user_agent": gd.get("user_agent", ""),
                        },
                        timestamp=ts,
                        source_file=str(path),
                        line_number=lineno,
                    )
        except (OSError, PermissionError):
            return


class ApacheErrorParser(BaseParser):
    source_type = LogSourceType.APACHE_ERROR

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
                        ts_str = f"{gd['day']} {gd['month']} {gd['year']} {gd['time'][:8]}"
                        ts = datetime.strptime(ts_str, "%d %b %Y %H:%M:%S")
                    except ValueError:
                        pass

                    src_ip = gd.get("src_ip", "")
                    if src_ip and ":" in src_ip:
                        # Strip port from "ip:port"
                        src_ip = src_ip.rsplit(":", 1)[0]

                    yield LogEvent(
                        source_type=self.source_type,
                        raw=line,
                        fields={
                            "module": gd.get("module", ""),
                            "pid": gd.get("pid", ""),
                            "src_ip": src_ip,
                            "message": gd.get("message", line),
                        },
                        timestamp=ts,
                        source_file=str(path),
                        line_number=lineno,
                    )
        except (OSError, PermissionError):
            return
