"""
MSSQL Audit Log Parser
Parses SQL Server audit logs in XML format or plain text.
"""

import re
import logging
import xml.etree.ElementTree as ET
from typing import Optional

logger = logging.getLogger(__name__)

# action_id -> event_name
_ACTION_MAP = {
    "BATCH STARTING":                   "SQL Batch Execute",
    "DATABASE PERMISSION CHANGED":      "SQL Permission Change",
    "DATABASE PRINCIPAL IMPERSONATION": "SQL Impersonation",
    "FAILED_LOGIN_GROUP":               "SQL Login Failed",
    "SUCCESSFUL_LOGIN_GROUP":           "SQL Login Success",
    "SCHEMA_OBJECT_ACCESS_GROUP":       "SQL Object Access",
}


def _event_name_from_action(action_id: Optional[str]) -> str:
    if not action_id:
        return "SQL Event"
    action_upper = action_id.upper().strip()
    if action_upper in _ACTION_MAP:
        return _ACTION_MAP[action_upper]
    return f"SQL Event: {action_id}"


def _parse_xml_record(el: ET.Element) -> Optional[dict]:
    """Parse a single SqlAuditRecord XML element."""
    def _attr(name: str) -> Optional[str]:
        val = el.get(name)
        return val if val not in (None, "", "NULL") else None

    action_id   = _attr("action_id")
    succeeded   = _attr("succeeded")
    action      = "success" if succeeded in ("true", "1", "True") else "failure"
    event_name  = _event_name_from_action(action_id)

    return {
        "timestamp":        _attr("event_time"),
        "source_ip":        _attr("server_ip_address"),
        "dest_ip":          None,
        "source_port":      None,
        "dest_port":        None,
        "username":         _attr("server_principal_name"),
        "user_agent":       None,
        "method":           None,
        "url":              None,
        "status_code":      None,
        "bytes_sent":       None,
        "protocol":         None,
        "action":           action,
        "event_id":         _attr("event_id"),
        "event_name":       event_name,
        "event_category":   "Database",
        "process_name":     None,
        "command_line":     _attr("statement"),
        "hostname":         None,
        "domain":           _attr("database_name"),
        "log_source":       "mssql",
        # Extra MSSQL fields
        "object_name":      _attr("object_name"),
        "session_id":       _attr("session_id"),
        "raw":              ET.tostring(el, encoding="unicode")[:500],
    }


def _parse_xml(content: str) -> list:
    """Attempt XML parse of full file content."""
    events = []
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        # Try wrapping in a root element in case it's a sequence of elements
        try:
            root = ET.fromstring(f"<root>{content}</root>")
        except ET.ParseError as e:
            logger.debug("MSSQL parser: XML parse failed: %s", e)
            return events

    # Find all SqlAuditRecord elements regardless of depth
    for el in root.iter():
        tag = el.tag.split("}")[-1] if "}" in el.tag else el.tag
        if tag.lower() in ("sqlauditrecord", "auditrecord", "record"):
            try:
                rec = _parse_xml_record(el)
                if rec:
                    events.append(rec)
            except Exception as e:
                logger.warning("MSSQL parser: error processing XML element: %s", e)

    return events


# Text log pattern: date/time  server/instance  message
_TEXT_PATTERN = re.compile(
    r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+'
    r'(?:Server|Logon|spid\d+)\s+(.+)$',
    re.IGNORECASE
)
_LOGIN_FAIL  = re.compile(r"Login failed for user '([^']+)'", re.IGNORECASE)
_LOGIN_OK    = re.compile(r"Login succeeded for user '([^']+)'", re.IGNORECASE)
_DB_CHANGE   = re.compile(r"Changed database context to '([^']+)'", re.IGNORECASE)


def _parse_text_line(line: str) -> Optional[dict]:
    m = _TEXT_PATTERN.match(line)
    if not m:
        return None
    ts, message = m.group(1), m.group(2)
    username = None
    action   = "success"
    event_name = "SQL Event"

    mf = _LOGIN_FAIL.search(message)
    ms = _LOGIN_OK.search(message)
    md = _DB_CHANGE.search(message)

    if mf:
        username   = mf.group(1)
        action     = "failure"
        event_name = "SQL Login Failed"
    elif ms:
        username   = ms.group(1)
        action     = "success"
        event_name = "SQL Login Success"
    elif md:
        event_name = "SQL Database Change"
    elif "error" in message.lower():
        action     = "failure"
        event_name = "SQL Error"

    return {
        "timestamp":        ts,
        "source_ip":        None,
        "dest_ip":          None,
        "source_port":      None,
        "dest_port":        None,
        "username":         username,
        "user_agent":       None,
        "method":           None,
        "url":              None,
        "status_code":      None,
        "bytes_sent":       None,
        "protocol":         None,
        "action":           action,
        "event_id":         None,
        "event_name":       event_name,
        "event_category":   "Database",
        "process_name":     None,
        "command_line":     message,
        "hostname":         None,
        "domain":           None,
        "log_source":       "mssql",
        "raw":              line[:500],
    }


def parse(file_path: str) -> list:
    """Parse MSSQL audit log file (XML or text). Returns normalized event dicts."""
    events = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("MSSQL parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("MSSQL parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        content = fh.read()

    # Detect XML vs text
    stripped = content.lstrip()
    if stripped.startswith("<"):
        events = _parse_xml(content)
        if events:
            return events

    # Text fallback
    for lineno, line in enumerate(content.splitlines(), 1):
        line = line.rstrip()
        if not line:
            continue
        try:
            rec = _parse_text_line(line)
            if rec:
                events.append(rec)
        except Exception as e:
            logger.warning("MSSQL parser: error on line %d: %s", lineno, e)

    return events
