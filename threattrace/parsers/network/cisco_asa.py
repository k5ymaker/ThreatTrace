"""Cisco ASA syslog parser."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..linux.syslog import SyslogParser

# %ASA-5-722051: ...
_ASA_MSG_RE = re.compile(r"%ASA-(?P<severity>\d+)-(?P<msg_id>\d+):\s*(?P<message>.+)$")

# Built/Teardown connection
_CONN_RE = re.compile(
    r"(?P<action>Built|Teardown)\s+(?P<proto>\w+)\s+connection\s+\d+\s+for\s+"
    r"(?P<outside_iface>\S+):(?P<src_ip>[\d.]+)/(?P<src_port>\d+)"
    r"\s+\((?P<translated_src>[^)]+)\)"
    r"\s+to\s+(?P<inside_iface>\S+):(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)"
)
# Deny/Permit
_ACL_RE = re.compile(
    r"(?P<action>Deny|Permit)\s+(?P<proto>\w+)\s+src\s+(?P<src_iface>\S+):(?P<src_ip>[\d.]+)/(?P<src_port>\d+)"
    r"\s+dst\s+(?P<dst_iface>\S+):(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)"
)


class CiscoASAParser(SyslogParser):
    source_type = LogSourceType.FIREWALL_CISCO_ASA

    def parse(self, path: Path) -> Iterator[LogEvent]:
        for event in super().parse(path):
            msg = event.fields.get("message", "")
            m = _ASA_MSG_RE.search(event.raw)
            if m:
                gd = m.groupdict()
                event.fields["asa_severity"] = gd["severity"]
                event.fields["msg_id"] = gd["msg_id"]
                # Try to enrich with connection info
                cm = _CONN_RE.search(msg)
                if cm:
                    event.fields.update(cm.groupdict())
                else:
                    am = _ACL_RE.search(msg)
                    if am:
                        event.fields.update(am.groupdict())
            event.source_type = self.source_type
            yield event
