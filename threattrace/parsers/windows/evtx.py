"""Windows EVTX binary log parser using python-evtx."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Iterator

from ...models.log_event import LogEvent, LogSourceType
from ..base import BaseParser

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _parse_evtx_record(xml_str: str, source_file: str, lineno: int) -> LogEvent | None:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    system = root.find("e:System", _NS)
    event_data = root.find("e:EventData", _NS)
    user_data = root.find("e:UserData", _NS)

    fields: dict = {}

    if system is not None:
        def get_text(tag: str) -> str:
            el = system.find(f"e:{tag}", _NS)
            return el.text or "" if el is not None else ""

        def get_attrib(tag: str, attr: str) -> str:
            el = system.find(f"e:{tag}", _NS)
            return el.get(attr, "") if el is not None else ""

        fields["EventID"] = get_text("EventID") or get_attrib("EventID", "Qualifiers")
        fields["channel"] = get_text("Channel")
        fields["computer"] = get_text("Computer")
        fields["provider"] = get_attrib("Provider", "Name")
        fields["level"] = get_text("Level")
        fields["task"] = get_text("Task")
        fields["keywords"] = get_text("Keywords")
        fields["record_id"] = get_attrib("EventRecordID", "")
        if not fields["record_id"]:
            el = system.find("e:EventRecordID", _NS)
            fields["record_id"] = el.text if el is not None else ""

        ts_el = system.find("e:TimeCreated", _NS)
        ts = None
        if ts_el is not None:
            ts_str = ts_el.get("SystemTime", "")
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
                try:
                    ts = datetime.strptime(ts_str[:26], fmt)
                    break
                except ValueError:
                    pass

        security_el = system.find("e:Security", _NS)
        if security_el is not None:
            fields["username"] = security_el.get("UserID", "")

    else:
        ts = None

    # EventData — named or positional
    if event_data is not None:
        for data in event_data:
            name = data.get("Name")
            value = data.text or ""
            if name:
                fields[name] = value
            else:
                existing = fields.get("_data", [])
                existing.append(value)
                fields["_data"] = existing

    # UserData — extract from first child's children
    if user_data is not None:
        for child in user_data:
            for subchild in child:
                tag = subchild.tag.split("}")[-1] if "}" in subchild.tag else subchild.tag
                fields[tag] = subchild.text or ""

    return LogEvent(
        source_type=LogSourceType.WINDOWS_EVTX,
        raw=xml_str[:2000],
        fields=fields,
        timestamp=ts,
        source_file=source_file,
        line_number=lineno,
    )


class EVTXParser(BaseParser):
    source_type = LogSourceType.WINDOWS_EVTX

    def parse(self, path: Path) -> Iterator[LogEvent]:
        try:
            import Evtx.Evtx as evtx
            import Evtx.Views as evtx_views
        except ImportError:
            # python-evtx not installed — try XML fallback
            yield from EVTXXMLParser(source_file=str(path)).parse(path)
            return

        try:
            with evtx.Evtx(str(path)) as log:
                for lineno, record in enumerate(log.records(), start=1):
                    try:
                        xml_str = record.xml()
                    except Exception:
                        continue
                    event = _parse_evtx_record(xml_str, str(path), lineno)
                    if event:
                        yield event
        except Exception:
            return
