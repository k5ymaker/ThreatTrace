"""
Windows EVTX Binary Log Parser
Uses python-evtx library to parse binary .evtx files.
Provides both module-level parse() and the EVTXParser class (returns LogRecord objects).
"""

import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List, Optional

logger = logging.getLogger(__name__)

# Windows XML namespace
NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Sysmon event ID -> descriptive name
SYSMON_EVENT_NAMES = {
    "1":  "Process Creation",
    "2":  "File Creation Time Changed",
    "3":  "Network Connection",
    "4":  "Sysmon Service State Changed",
    "5":  "Process Terminated",
    "6":  "Driver Loaded",
    "7":  "Image Loaded",
    "8":  "CreateRemoteThread",
    "9":  "RawAccessRead",
    "10": "ProcessAccess",
    "11": "FileCreate",
    "12": "RegistryEvent (Object create and delete)",
    "13": "RegistryEvent (Value Set)",
    "14": "RegistryEvent (Key and Value Rename)",
    "15": "FileCreateStreamHash",
    "16": "ServiceConfigurationChange",
    "17": "PipeEvent (Pipe Created)",
    "18": "PipeEvent (Pipe Connected)",
    "19": "WmiEvent (WmiEventFilter)",
    "20": "WmiEvent (WmiEventConsumer)",
    "21": "WmiEvent (WmiEventConsumerToFilter)",
    "22": "DNSEvent",
    "23": "FileDelete",
    "24": "ClipboardChange",
    "25": "ProcessTampering",
    "26": "FileDeleteDetected",
    "255": "Error",
}

# Security event ID -> descriptive name
SECURITY_EVENT_NAMES = {
    "4624":  "Successful Logon",
    "4625":  "Failed Logon",
    "4634":  "Account Logoff",
    "4648":  "Explicit Credential Use",
    "4656":  "Object Handle Requested",
    "4662":  "Directory Service Object Access",
    "4663":  "Object Access Attempt",
    "4672":  "Special Privileges Assigned",
    "4673":  "Privileged Service Called",
    "4674":  "Privileged Object Operation",
    "4688":  "Process Creation",
    "4689":  "Process Terminated",
    "4698":  "Scheduled Task Created",
    "4702":  "Scheduled Task Modified",
    "4720":  "User Account Created",
    "4722":  "User Account Enabled",
    "4723":  "Password Change Attempt",
    "4724":  "Password Reset",
    "4725":  "User Account Disabled",
    "4726":  "User Account Deleted",
    "4728":  "Member Added to Global Group",
    "4732":  "Member Added to Local Group",
    "4740":  "Account Lockout",
    "4756":  "Member Added to Universal Group",
    "4765":  "SID History Added",
    "4766":  "SID History Add Failed",
    "4768":  "Kerberos TGT Requested",
    "4769":  "Kerberos Service Ticket Requested",
    "4771":  "Kerberos Pre-Auth Failed",
    "4776":  "NTLM Auth Attempted",
    "4798":  "Local Group Enumeration",
    "4799":  "Security Group Enumeration",
    "4964":  "Special Groups Assigned to New Logon",
    "1102":  "Security Log Cleared",
    "7045":  "New Service Installed",
    "4104":  "PowerShell Script Block",
}

# Event ID -> (event_name, event_category)
EVENT_ID_MAP = {
    "4624":  ("Successful Logon",                    "Authentication"),
    "4625":  ("Failed Logon",                        "Authentication"),
    "4648":  ("Explicit Credential Use",             "Authentication"),
    "4656":  ("Object Handle Requested",             "Object Access"),
    "4662":  ("Directory Service Object Access",     "Credential Access"),
    "4663":  ("Object Access Attempt",               "Object Access"),
    "4672":  ("Special Privileges Assigned",         "Privilege"),
    "4688":  ("Process Creation",                    "Process"),
    "4689":  ("Process Terminated",                  "Process"),
    "4698":  ("Scheduled Task Created",              "Persistence"),
    "4702":  ("Scheduled Task Modified",             "Persistence"),
    "4720":  ("User Account Created",                "Account Management"),
    "4722":  ("User Account Enabled",                "Account Management"),
    "4725":  ("User Account Disabled",               "Account Management"),
    "4726":  ("User Account Deleted",                "Account Management"),
    "4728":  ("Member Added to Global Group",        "Group Management"),
    "4732":  ("Member Added to Local Group",         "Group Management"),
    "4740":  ("Account Lockout",                     "Authentication"),
    "4756":  ("Member Added to Universal Group",     "Group Management"),
    "4768":  ("Kerberos TGT Requested",              "Authentication"),
    "4769":  ("Kerberos Service Ticket Requested",   "Authentication"),
    "4771":  ("Kerberos Pre-Auth Failed",            "Authentication"),
    "4776":  ("NTLM Auth Attempted",                 "Authentication"),
    "4798":  ("Local Group Enumeration",             "Discovery"),
    "4799":  ("Security Group Enumeration",          "Discovery"),
    "1102":  ("Security Log Cleared",                "Defense Evasion"),
    "7045":  ("New Service Installed",               "Persistence"),
    "4104":  ("PowerShell Script Block",             "Execution"),
}

# EventData field -> normalized key
EVENTDATA_FIELD_MAP = {
    "SubjectUserName":      "username",
    "TargetUserName":       "username",
    "IpAddress":            "source_ip",
    "ClientAddress":        "source_ip",
    "IpPort":               "source_port",
    "ProcessName":          "process_name",
    "NewProcessName":       "process_name",
    "CommandLine":          "command_line",
    "WorkstationName":      "hostname",
    "TargetDomainName":     "domain",
    "SubjectDomainName":    "domain",
}


def _parse_timestamp(ts: str) -> str:
    """Normalize Windows event timestamp to ISO 8601 UTC."""
    try:
        ts = ts.rstrip("Z").split(".")[0]
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ts


def _safe_int(val) -> Optional[int]:
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _parse_event_xml(xml_str: str) -> Optional[dict]:
    """Parse a single Windows event XML string into a normalized dict."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        logger.debug("EVTX parser: XML parse error: %s", e)
        return None

    def find(tag):
        return root.find(f".//{{{NS}}}{tag}")

    def findall(tag):
        return root.findall(f".//{{{NS}}}{tag}")

    system = root.find(f"{{{NS}}}System")
    if system is None:
        return None

    # Extract system fields
    event_id_el   = system.find(f"{{{NS}}}EventID")
    time_el       = system.find(f"{{{NS}}}TimeCreated")
    computer_el   = system.find(f"{{{NS}}}Computer")
    channel_el    = system.find(f"{{{NS}}}Channel")
    provider_el   = system.find(f"{{{NS}}}Provider")

    event_id  = event_id_el.text.strip() if event_id_el is not None else None
    ts_raw    = time_el.get("SystemTime") if time_el is not None else None
    computer  = computer_el.text if computer_el is not None else None
    channel   = channel_el.text if channel_el is not None else None

    timestamp = _parse_timestamp(ts_raw) if ts_raw else None

    # Event name / category
    if event_id in EVENT_ID_MAP:
        event_name, event_category = EVENT_ID_MAP[event_id]
    else:
        event_name     = f"Windows Event {event_id}"
        event_category = "Windows"

    # EventData
    event_data = {}
    event_data_el = root.find(f"{{{NS}}}EventData")
    if event_data_el is not None:
        for data_el in event_data_el:
            name = data_el.get("Name")
            val  = data_el.text
            if name:
                event_data[name] = val

    # UserData fallback
    user_data_el = root.find(f"{{{NS}}}UserData")
    if user_data_el is not None:
        for child in user_data_el.iter():
            if child.tag != user_data_el.tag and child.text:
                tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                event_data.setdefault(tag, child.text)

    # Map known EventData fields to normalized keys
    source_ip    = None
    source_port  = None
    username     = None
    process_name = None
    command_line = None
    hostname     = None
    domain       = None

    for ed_key, norm_key in EVENTDATA_FIELD_MAP.items():
        val = event_data.get(ed_key)
        if val and val not in ("-", "NULL", ""):
            if norm_key == "username":
                username = username or val
            elif norm_key == "source_ip":
                source_ip = source_ip or val
            elif norm_key == "source_port":
                source_port = _safe_int(val)
            elif norm_key == "process_name":
                process_name = process_name or val
            elif norm_key == "command_line":
                command_line = command_line or val
            elif norm_key == "hostname":
                hostname = hostname or val
            elif norm_key == "domain":
                domain = domain or val

    return {
        "timestamp":      timestamp,
        "source_ip":      source_ip,
        "dest_ip":        None,
        "source_port":    source_port,
        "dest_port":      None,
        "username":       username,
        "user_agent":     None,
        "method":         None,
        "url":            None,
        "status_code":    None,
        "bytes_sent":     None,
        "protocol":       None,
        "action":         None,
        "event_id":       event_id,
        "event_name":     event_name,
        "event_category": event_category,
        "process_name":   process_name,
        "command_line":   command_line,
        "hostname":       hostname or computer,
        "domain":         domain,
        "log_source":     "windows_evtx",
        "raw":            xml_str[:500],
    }


def parse(file_path: str) -> list:
    """Parse binary Windows .evtx file. Returns list of normalized event dicts."""
    events = []
    try:
        import Evtx.Evtx as evtx
    except ImportError:
        logger.error(
            "windows_evtx_parser: python-evtx not installed. "
            "Run: pip install python-evtx"
        )
        return events

    try:
        with evtx.Evtx(file_path) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    event = _parse_event_xml(xml_str)
                    if event:
                        events.append(event)
                except Exception as e:
                    logger.warning("EVTX parser: error reading record: %s", e)
                    continue
    except FileNotFoundError:
        logger.error("EVTX parser: file not found: %s", file_path)
    except Exception as e:
        logger.error("EVTX parser: failed to open %s: %s", file_path, e)

    return events


# ---------------------------------------------------------------------------
# EVTXParser class — returns LogRecord objects for use with analytics pipeline
# ---------------------------------------------------------------------------

def _resolve_log_type(channel: Optional[str]) -> str:
    """Determine the ThreatTrace log_type from the Windows channel name."""
    if not channel:
        return "windows_evtx"
    ch_lower = channel.lower()
    if "sysmon" in ch_lower:
        return "sysmon"
    if "security" in ch_lower:
        return "windows_security"
    if "system" in ch_lower:
        return "windows_system"
    if "powershell" in ch_lower or "microsoft-windows-powershell" in ch_lower:
        return "windows_powershell"
    return "windows_evtx"


def _resolve_event_name(event_id: Optional[str], channel: Optional[str]) -> str:
    """Resolve a human-readable event name from event ID and channel."""
    if not event_id:
        return "Unknown Event"
    ch_lower = (channel or "").lower()
    if "sysmon" in ch_lower and event_id in SYSMON_EVENT_NAMES:
        return SYSMON_EVENT_NAMES[event_id]
    if event_id in SECURITY_EVENT_NAMES:
        return SECURITY_EVENT_NAMES[event_id]
    if event_id in EVENT_ID_MAP:
        return EVENT_ID_MAP[event_id][0]
    return f"Windows Event {event_id}"


def _parse_event_xml_full(xml_str: str, line_number: int = 0):
    """
    Parse a Windows event XML string into a LogRecord.
    Returns a LogRecord or None on parse failure.
    """
    # Import here to avoid circular imports at module load time
    from core.models import LogRecord

    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as exc:
        logger.debug("EVTXParser: XML parse error: %s", exc)
        return None

    def find(tag):
        return root.find(f".//{{{NS}}}{tag}")

    system = root.find(f"{{{NS}}}System")
    if system is None:
        return None

    event_id_el = system.find(f"{{{NS}}}EventID")
    time_el     = system.find(f"{{{NS}}}TimeCreated")
    computer_el = system.find(f"{{{NS}}}Computer")
    channel_el  = system.find(f"{{{NS}}}Channel")

    event_id  = event_id_el.text.strip() if event_id_el is not None else None
    ts_raw    = time_el.get("SystemTime") if time_el is not None else None
    computer  = computer_el.text if computer_el is not None else None
    channel   = channel_el.text if channel_el is not None else None

    # Parse timestamp
    ts_parsed: Optional[datetime] = None
    if ts_raw:
        try:
            ts_clean = ts_raw.rstrip("Z").split(".")[0]
            ts_parsed = datetime.strptime(ts_clean, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            pass

    log_type   = _resolve_log_type(channel)
    event_name = _resolve_event_name(event_id, channel)

    # EventData extraction
    event_data: dict = {}
    event_data_el = root.find(f"{{{NS}}}EventData")
    if event_data_el is not None:
        for data_el in event_data_el:
            name = data_el.get("Name")
            val  = data_el.text
            if name and val is not None:
                event_data[name] = val

    # UserData fallback
    user_data_el = root.find(f"{{{NS}}}UserData")
    if user_data_el is not None:
        for child in user_data_el.iter():
            if child.tag != user_data_el.tag and child.text:
                tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                event_data.setdefault(tag, child.text)

    # Normalise well-known EventData fields
    source_ip    = None
    source_port  = None
    username     = None
    process_name = None
    command_line = None
    hostname     = None

    for ed_key, norm_key in EVENTDATA_FIELD_MAP.items():
        val = event_data.get(ed_key)
        if val and val not in ("-", "NULL", ""):
            if norm_key == "username":
                username = username or val
            elif norm_key == "source_ip":
                source_ip = source_ip or val
            elif norm_key == "source_port":
                source_port = _safe_int(val)
            elif norm_key == "process_name":
                process_name = process_name or val
            elif norm_key == "command_line":
                command_line = command_line or val
            elif norm_key == "hostname":
                hostname = hostname or val

    # Build extra dict with all raw EventData fields for correlation engines
    extra = dict(event_data)
    extra["event_name"] = event_name
    extra["channel"]    = channel or ""

    return LogRecord(
        raw_line     = xml_str[:1000],
        log_type     = log_type,
        timestamp    = ts_parsed,
        source_ip    = source_ip,
        dest_ip      = None,
        source_port  = source_port,
        dest_port    = None,
        username     = username,
        action       = None,
        status_code  = None,
        bytes_transferred = None,
        uri          = None,
        user_agent   = None,
        hostname     = hostname or computer,
        process_name = process_name,
        command_line = command_line,
        event_id     = event_id,
        extra        = extra,
        line_number  = line_number,
    )


class EVTXParser:
    """
    High-level EVTX parser that returns List[LogRecord].
    Used by the analytics pipeline and ingest scripts.
    """

    def parse_file(self, file_path: str) -> "List":
        """Parse a binary .evtx file and return a list of LogRecord objects."""
        from core.models import LogRecord  # ensure import available
        records: List = []
        try:
            import Evtx.Evtx as evtx
        except ImportError:
            logger.error(
                "EVTXParser: python-evtx not installed. Run: pip install python-evtx"
            )
            return records

        try:
            with evtx.Evtx(file_path) as log:
                for idx, record in enumerate(log.records()):
                    try:
                        xml_str = record.xml()
                        lr = _parse_event_xml_full(xml_str, line_number=idx + 1)
                        if lr is not None:
                            records.append(lr)
                    except Exception as exc:
                        logger.warning("EVTXParser: record %d error: %s", idx, exc)
                        continue
        except FileNotFoundError:
            logger.error("EVTXParser: file not found: %s", file_path)
        except Exception as exc:
            logger.error("EVTXParser: failed to open %s: %s", file_path, exc)

        return records
