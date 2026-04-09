"""Windows EVTX XML export parser (handles plain XML export of EVTX)."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser
from .evtx import _parse_evtx_record


class EVTXXMLParser(BaseParser):
    source_type = LogSourceType.WINDOWS_EVTX_XML

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return

        # Could be a single <Event> or wrapped in <Events>
        # Try iterative parsing
        lineno = 0
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            # Try to extract individual <Event> blocks
            import re
            for m in re.finditer(r"<Event\b.*?</Event>", content, re.DOTALL):
                lineno += 1
                event = _parse_evtx_record(m.group(0), str(path), lineno)
                if event:
                    event.source_type = self.source_type
                    yield event
            return

        tag = root.tag.split("}")[-1] if "}" in root.tag else root.tag
        if tag == "Event":
            event = _parse_evtx_record(content, str(path), 1)
            if event:
                event.source_type = self.source_type
                yield event
        else:
            # <Events> wrapper
            ns = root.tag.split("}")[0] + "}" if "}" in root.tag else ""
            for lineno, child in enumerate(root.findall(f"{ns}Event"), start=1):
                xml_str = ET.tostring(child, encoding="unicode")
                event = _parse_evtx_record(xml_str, str(path), lineno)
                if event:
                    event.source_type = self.source_type
                    yield event
