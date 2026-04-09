"""Linux auditd log parser."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser

# type=SYSCALL msg=audit(1234567890.123:456): arch=c000003e syscall=59 ...
_AUDIT_RE = re.compile(
    r"^type=(?P<type>\S+)\s+msg=audit\((?P<epoch>\d+\.\d+):(?P<serial>\d+)\):\s*(?P<rest>.+)$"
)
_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|((?:[^\s"\\]|\\.)*))')


def _parse_kv(s: str) -> dict:
    result = {}
    for m in _KV_RE.finditer(s):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3)
        result[key] = val
    return result


_SYSCALL_MAP = {
    "59": "execve", "60": "exit", "2": "open", "257": "openat",
    "56": "clone", "57": "fork", "62": "kill", "90": "chmod",
    "92": "chown", "188": "setxattr", "161": "chroot",
}


class AuditdParser(BaseParser):
    source_type = LogSourceType.LINUX_AUDIT

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.rstrip("\n\r")
                    if not line.strip():
                        continue

                    m = _AUDIT_RE.match(line)
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
                    fields = _parse_kv(gd["rest"])
                    fields["audit_type"] = gd["type"]
                    fields["audit_serial"] = gd["serial"]

                    # Resolve syscall number to name
                    if "syscall" in fields:
                        fields["syscall_name"] = _SYSCALL_MAP.get(
                            fields["syscall"], fields["syscall"]
                        )

                    # Parse timestamp
                    try:
                        ts = datetime.utcfromtimestamp(float(gd["epoch"]))
                    except (ValueError, OSError):
                        ts = None

                    yield LogEvent(
                        source_type=self.source_type,
                        raw=line,
                        fields=fields,
                        timestamp=ts,
                        source_file=str(path),
                        line_number=lineno,
                    )
        except (OSError, PermissionError):
            return
