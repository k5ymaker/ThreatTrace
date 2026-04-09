"""
Active Directory / Windows Domain Controller Event Log Parser
Parses text-format XML event logs (e.g., exported from DC event viewer).
Focuses on AD-specific Event IDs.
"""

import re
import logging
import xml.etree.ElementTree as ET
from typing import Optional

logger = logging.getLogger(__name__)

NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# AD-focused event ID mapping
EVENT_ID_MAP = {
    "4768": ("Kerberos TGT Requested",              "Authentication"),
    "4769": ("Kerberos Service Ticket Requested",   "Authentication"),
    "4771": ("Kerberos Pre-Auth Failed",            "Authentication"),
    "4776": ("NTLM Auth Attempted",                 "Authentication"),
    "4662": ("Directory Service Object Access",     "Credential Access"),
    "4720": ("User Account Created",                "Account Management"),
    "4721": ("User Account Created (local)",        "Account Management"),
    "4722": ("User Account Enabled",                "Account Management"),
    "4723": ("User Account Password Changed",       "Account Management"),
    "4724": ("User Account Password Reset",         "Account Management"),
    "4725": ("User Account Disabled",               "Account Management"),
    "4726": ("User Account Deleted",                "Account Management"),
    "4728": ("Member Added to Global Group",        "Group Management"),
    "4732": ("Member Added to Local Group",         "Group Management"),
    "4740": ("Account Lockout",                     "Authentication"),
    "4756": ("Member Added to Universal Group",     "Group Management"),
    "4798": ("Local Group Enumeration",             "Discovery"),
    "4799": ("Security Group Enumeration",          "Discovery"),
    "4624": ("Successful Logon",                    "Authentication"),
    "4625": ("Failed Logon",                        "Authentication"),
    "4672": ("Special Privileges Assigned",         "Privilege"),
    "4688": ("Process Creation",                    "Process"),
    "1102": ("Security Log Cleared",                "Defense Evasion"),
}


def _parse_event_xml(xml_str: str) -> Optional[dict]:
    """Parse a single Windows XML event string into a normalized dict."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        logger.debug("AD parser: XML parse error: %s", e)
        return None

    def _find(tag):
        # Try with namespace first, then without
        el = root.find(f".//{{{NS}}}{tag}")
        if el is None:
            el = root.find(f".//{tag}")
        return el

    system = root.find(f"{{{NS}}}System") or root.find("System")
    if system is None:
        return None

    def _sys(tag):
        el = system.find(f"{{{NS}}}{tag}") or system.find(tag)
        return el

    event_id_el   = _sys("EventID")
    time_el       = _sys("TimeCreated")
    computer_el   = _sys("Computer")

    event_id  = event_id_el.text.strip() if event_id_el is not None else None
    ts_raw    = time_el.get("SystemTime") if time_el is not None else None
    computer  = computer_el.text if computer_el is not None else None

    if event_id in EVENT_ID_MAP:
        event_name, event_category = EVENT_ID_MAP[event_id]
    else:
        event_name     = f"Windows Event {event_id}"
        event_category = "Windows"

    # Collect all EventData fields
    fields = {}
    event_data_el = root.find(f"{{{NS}}}EventData") or root.find("EventData")
    if event_data_el is not None:
        for data_el in event_data_el:
            name = data_el.get("Name")
            val  = data_el.text
            if name and val:
                fields[name] = val

    # Also check UserData
    user_data_el = root.find(f"{{{NS}}}UserData") or root.find("UserData")
    if user_data_el is not None:
        for child in user_data_el.iter():
            if child.tag != user_data_el.tag and child.text:
                tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                fields.setdefault(tag, child.text)

    def _field(*names):
        for n in names:
            v = fields.get(n)
            if v and v not in ("-", "NULL", "", "0x0"):
                return v
        return None

    username  = _field("SubjectUserName", "TargetUserName", "SamAccountName")
    source_ip = _field("IpAddress", "ClientAddress")
    domain    = _field("TargetDomainName", "SubjectDomainName")
    source_port_raw = _field("IpPort")
    source_port = None
    if source_port_raw:
        try:
            source_port = int(source_port_raw)
        except (ValueError, TypeError):
            pass

    return {
        "timestamp":        ts_raw,
        "source_ip":        source_ip,
        "dest_ip":          None,
        "source_port":      source_port,
        "dest_port":        None,
        "username":         username,
        "user_agent":       None,
        "method":           None,
        "url":              None,
        "status_code":      None,
        "bytes_sent":       None,
        "protocol":         None,
        "action":           None,
        "event_id":         event_id,
        "event_name":       event_name,
        "event_category":   event_category,
        "process_name":     _field("ProcessName", "NewProcessName"),
        "command_line":     _field("CommandLine"),
        "hostname":         computer,
        "domain":           domain,
        "log_source":       "active_directory",
        "fields":           fields,
        "raw":              xml_str[:500],
    }


def parse(file_path: str) -> list:
    """Parse AD/DC XML event log file. Returns list of normalized event dicts."""
    events = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("AD parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("AD parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        content = fh.read()

    # Split on <Event boundaries to handle multiple events per file
    # Support both wrapped in <Events> root and bare sequences
    event_blocks = re.split(r'(?=<Event[\s>])', content)

    for block in event_blocks:
        block = block.strip()
        if not block or not block.startswith("<Event"):
            continue
        # Ensure it's properly closed
        if "</Event>" not in block:
            continue
        # Trim anything after the closing tag
        end_idx = block.find("</Event>") + len("</Event>")
        block = block[:end_idx]
        try:
            event = _parse_event_xml(block)
            if event:
                events.append(event)
        except Exception as e:
            logger.warning("AD parser: error processing event block: %s", e)

    return events
