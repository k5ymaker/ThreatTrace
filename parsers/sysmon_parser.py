"""
Sysmon XML Log Parser
Handles individual XML records and EventLog XML format.
"""

import re
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

NS = "http://schemas.microsoft.com/win/2004/08/events/event"

SYSMON_EVENT_MAP = {
    "1":  ("Process Create",                "Process"),
    "2":  ("File Creation Time Change",     "File"),
    "3":  ("Network Connection",            "Network"),
    "5":  ("Process Terminate",             "Process"),
    "6":  ("Driver Loaded",                 "Driver"),
    "7":  ("Image Loaded",                  "Image Load"),
    "8":  ("CreateRemoteThread",            "Injection"),
    "10": ("ProcessAccess",                 "Injection"),
    "11": ("FileCreate",                    "File"),
    "12": ("Registry Key Created/Deleted",  "Registry"),
    "13": ("Registry Value Set",            "Registry"),
    "14": ("Registry Key/Value Renamed",    "Registry"),
    "15": ("FileCreateStreamHash",          "File"),
    "17": ("Pipe Created",                  "Lateral Movement"),
    "18": ("Pipe Connected",                "Lateral Movement"),
    "22": ("DNS Query",                     "Network"),
    "23": ("File Delete",                   "File"),
    "25": ("Process Tampering",             "Defense Evasion"),
}


def _parse_timestamp(ts: str) -> str:
    try:
        ts = ts.rstrip("Z").split(".")[0]
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ts


def _safe_int(val) -> Optional[int]:
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _parse_event_element(root: ET.Element) -> Optional[dict]:
    """Parse a single Event XML element."""

    def find_ns(tag):
        return root.find(f".//{{{NS}}}{tag}")

    system = root.find(f"{{{NS}}}System")
    if system is None:
        # Try without namespace
        system = root.find(".//System")

    if system is None:
        return None

    def sys_find(tag):
        el = system.find(f"{{{NS}}}{tag}")
        if el is None:
            el = system.find(tag)
        return el

    event_id_el = sys_find("EventID")
    time_el     = sys_find("TimeCreated")
    computer_el = sys_find("Computer")

    event_id = event_id_el.text.strip() if event_id_el is not None else None
    ts_raw   = time_el.get("SystemTime") if time_el is not None else None
    computer = computer_el.text if computer_el is not None else None

    # Event name / category from Sysmon ID map
    if event_id in SYSMON_EVENT_MAP:
        event_name, event_category = SYSMON_EVENT_MAP[event_id]
    else:
        event_name     = f"Sysmon Event {event_id}"
        event_category = "Sysmon"

    # EventData
    event_data = {}
    ed = root.find(f"{{{NS}}}EventData")
    if ed is None:
        ed = root.find(".//EventData")
    if ed is not None:
        for d in ed:
            name = d.get("Name")
            if name:
                event_data[name] = d.text or ""

    # Map common Sysmon fields
    source_ip    = event_data.get("SourceIp") or event_data.get("DestinationIp")
    dest_ip      = event_data.get("DestinationIp")
    source_port  = _safe_int(event_data.get("SourcePort"))
    dest_port    = _safe_int(event_data.get("DestinationPort"))
    username     = event_data.get("User")
    process_name = event_data.get("Image") or event_data.get("SourceImage")
    command_line = event_data.get("CommandLine")
    hostname     = computer
    domain       = None
    protocol     = event_data.get("Protocol")
    url          = event_data.get("QueryName")  # DNS query name

    # For network events, source is the initiator
    if event_id == "3":
        source_ip = event_data.get("SourceIp")
        dest_ip   = event_data.get("DestinationIp")

    # Username: strip DOMAIN\user
    if username and "\\" in username:
        domain, username = username.split("\\", 1)

    return {
        "timestamp":      _parse_timestamp(ts_raw) if ts_raw else None,
        "source_ip":      source_ip,
        "dest_ip":        dest_ip,
        "source_port":    source_port,
        "dest_port":      dest_port,
        "username":       username,
        "user_agent":     None,
        "method":         None,
        "url":            url,
        "status_code":    None,
        "bytes_sent":     None,
        "protocol":       protocol,
        "action":         None,
        "event_id":       event_id,
        "event_name":     event_name,
        "event_category": event_category,
        "process_name":   process_name,
        "command_line":   command_line,
        "hostname":       hostname,
        "domain":         domain,
        "log_source":     "sysmon",
        "raw":            ET.tostring(root, encoding="unicode")[:500],
    }


def _iter_events_from_file(file_path: str):
    """Yield parsed XML event elements from file."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except FileNotFoundError:
        logger.error("Sysmon parser: file not found: %s", file_path)
        return
    except Exception as e:
        logger.error("Sysmon parser: failed to open %s: %s", file_path, e)
        return

    # Try to parse as single XML document
    try:
        root = ET.fromstring(content)
        tag = root.tag.split("}")[-1] if "}" in root.tag else root.tag

        if tag == "Event":
            yield root
            return

        # EventLog or Events wrapper
        for event_el in root.iter():
            event_tag = event_el.tag.split("}")[-1] if "}" in event_el.tag else event_el.tag
            if event_tag == "Event":
                yield event_el
        return
    except ET.ParseError:
        pass

    # Try individual XML records (one per line or separated by blank lines)
    # Extract <Event ...>...</Event> blocks with regex
    pattern = re.compile(r"<Event\b[^>]*>.*?</Event>", re.DOTALL)
    for match in pattern.finditer(content):
        try:
            el = ET.fromstring(match.group())
            yield el
        except ET.ParseError as e:
            logger.debug("Sysmon parser: XML parse error in block: %s", e)
            continue


def parse(file_path: str) -> list:
    """Parse XML-formatted Sysmon logs. Returns list of normalized event dicts."""
    events = []
    for event_el in _iter_events_from_file(file_path):
        try:
            event = _parse_event_element(event_el)
            if event:
                events.append(event)
        except Exception as e:
            logger.warning("Sysmon parser: error processing event: %s", e)
            continue
    return events
