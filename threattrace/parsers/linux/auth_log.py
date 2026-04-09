"""Linux auth.log parser — specialized for SSH, sudo, PAM events."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from .syslog import SyslogParser

# Additional field extractors run against the message field
_SSH_ACCEPTED = re.compile(
    r"Accepted (?P<auth_method>\S+) for (?P<username>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)"
)
_SSH_FAILED = re.compile(
    r"Failed (?P<auth_method>\S+) for (?:invalid user )?(?P<username>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)"
)
_SSH_INVALID = re.compile(
    r"Invalid user (?P<username>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)"
)
_SUDO_RE = re.compile(
    r"(?P<username>\S+)\s+: TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.+)"
)
_PAM_RE = re.compile(
    r"pam_\w+\((?P<service>[^)]+)\):\s+(?P<message>.+)"
)
_USERADD_RE = re.compile(r"new user: name=(?P<username>\S+),")
_USERDEL_RE = re.compile(r"delete user '(?P<username>[^']+)'")
_PASSWD_CHANGED = re.compile(r"password changed for (?P<username>\S+)")


def _enrich_auth_fields(fields: dict) -> dict:
    msg = fields.get("message", "")
    for pattern, name in [
        (_SSH_ACCEPTED, "ssh_accepted"),
        (_SSH_FAILED, "ssh_failed"),
        (_SSH_INVALID, "ssh_invalid"),
    ]:
        m = pattern.search(msg)
        if m:
            fields.update(m.groupdict())
            fields["event_category"] = name
            return fields

    m = _SUDO_RE.search(msg)
    if m:
        fields.update(m.groupdict())
        fields["event_category"] = "sudo"
        return fields

    m = _USERADD_RE.search(msg)
    if m:
        fields.update(m.groupdict())
        fields["event_category"] = "user_add"
        return fields

    m = _USERDEL_RE.search(msg)
    if m:
        fields.update(m.groupdict())
        fields["event_category"] = "user_delete"
        return fields

    m = _PASSWD_CHANGED.search(msg)
    if m:
        fields.update(m.groupdict())
        fields["event_category"] = "password_change"
        return fields

    return fields


class AuthLogParser(SyslogParser):
    source_type = LogSourceType.LINUX_AUTH_LOG

    def parse(self, path: Path) -> Iterator[LogEvent]:
        for event in super().parse(path):
            event.fields = _enrich_auth_fields(event.fields)
            event.source_type = LogSourceType.LINUX_AUTH_LOG
            yield event
