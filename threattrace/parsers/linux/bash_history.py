"""Linux bash history parser."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser

_TS_RE = re.compile(r"^#(\d{10})$")


class BashHistoryParser(BaseParser):
    source_type = LogSourceType.LINUX_BASH_HISTORY

    def parse(self, path: Path) -> Iterator[LogEvent]:
        from datetime import datetime

        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                pending_ts = None
                for lineno, line in enumerate(fh, start=1):
                    line = line.rstrip("\n\r")
                    if not line:
                        continue
                    m = _TS_RE.match(line)
                    if m:
                        try:
                            pending_ts = datetime.utcfromtimestamp(int(m.group(1)))
                        except (ValueError, OSError):
                            pending_ts = None
                        continue

                    # Extract command tokens
                    parts = line.split()
                    cmd = parts[0] if parts else ""
                    yield LogEvent(
                        source_type=self.source_type,
                        raw=line,
                        fields={
                            "command_line": line,
                            "command": cmd,
                            "args": " ".join(parts[1:]) if len(parts) > 1 else "",
                        },
                        timestamp=pending_ts,
                        source_file=str(path),
                        line_number=lineno,
                    )
                    pending_ts = None
        except (OSError, PermissionError):
            return
