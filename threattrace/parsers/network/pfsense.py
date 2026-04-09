"""pfSense filterlog parser."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..linux.syslog import SyslogParser

# filterlog: rule,sub,anchor,tracker,interface,reason,action,dir,ipver,...
_FILTERLOG_RE = re.compile(r"filterlog:\s+(?P<csv>.+)$")

_FILTERLOG_FIELDS_V4 = [
    "rule_num", "sub_rule", "anchor", "tracker", "interface", "reason",
    "action", "direction", "ip_version", "tos", "ecn", "ttl", "id",
    "offset", "flags", "proto_id", "proto_text", "length",
    "src_ip", "dst_ip",
]


class PfSenseParser(SyslogParser):
    source_type = LogSourceType.FIREWALL_PFSENSE

    def parse(self, path: Path) -> Iterator[LogEvent]:
        for event in super().parse(path):
            msg = event.fields.get("message", "")
            m = _FILTERLOG_RE.search(event.raw)
            if m:
                parts = m.group("csv").split(",")
                fields = dict(event.fields)
                for i, val in enumerate(parts):
                    if i < len(_FILTERLOG_FIELDS_V4):
                        fields[_FILTERLOG_FIELDS_V4[i]] = val
                    else:
                        # ports follow src/dst IP
                        if i == len(_FILTERLOG_FIELDS_V4):
                            fields["src_port"] = val
                        elif i == len(_FILTERLOG_FIELDS_V4) + 1:
                            fields["dst_port"] = val
                event.fields = fields
            event.source_type = self.source_type
            yield event
