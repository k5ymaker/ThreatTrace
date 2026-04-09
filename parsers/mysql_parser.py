"""
MySQL General Query Log and Error Log Parser
Detects format from first non-empty line.
"""

import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# General log: timestamp + thread_id + command + query
# Format: 2025-01-15T03:11:02.123456Z    12 Query  SELECT ...
#    or:  250115  3:11:02    12 Query  SELECT ...
_GENERAL_TS_ISO  = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+(\d+)\s+(\w+)\s*(.*)?$'
)
_GENERAL_TS_OLD  = re.compile(
    r'^(\d{6}\s+\d{1,2}:\d{2}:\d{2})\s+(\d+)\s+(\w+)\s*(.*)?$'
)
# Some versions emit only thread+cmd on continuation lines
_GENERAL_CONT    = re.compile(r'^\s+(\d+)\s+(\w+)\s*(.*)?$')

# Error log: ISO or old timestamp + [level] + message
_ERROR_TS_ISO    = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+\d+\s+\[(\w+)\]\s+(.+)$'
)
_ERROR_TS_OLD    = re.compile(
    r'^(\d{6}\s+\d{1,2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(.+)$'
)

# Extract user@host from Connect command: "user@hostname on dbname"
_CONNECT_USER    = re.compile(r'^(\S+?)@(\S+?)(?:\s+on\s+\S+)?$')

# Command -> event_name map
_CMD_MAP = {
    "Query":   "MySQL Query",
    "Connect": "MySQL Connect",
    "Quit":    "MySQL Disconnect",
    "Init":    "MySQL Database Change",
    "Field":   "MySQL Field List",
    "Ping":    "MySQL Ping",
    "Refresh": "MySQL Refresh",
    "Shutdown":"MySQL Shutdown",
}


def _event_name_from_cmd(cmd: Optional[str], message: str = "") -> str:
    if not cmd:
        return "MySQL Event"
    c = cmd.strip()
    if c in _CMD_MAP:
        return _CMD_MAP[c]
    if c.startswith("Init"):
        return "MySQL Database Change"
    return f"MySQL {c}"


def _severity_to_event(level: str, message: str) -> str:
    lvl = level.lower()
    if "error" in lvl or "Error" in message[:10]:
        return "MySQL Error"
    if "warning" in lvl or "warn" in lvl:
        return "MySQL Warning"
    if "access denied" in message.lower():
        return "MySQL Access Denied"
    return "MySQL Info"


def _detect_format(content: str) -> str:
    """Return 'general', 'error', or 'unknown'."""
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("/") or line.startswith("#"):
            continue
        if _ERROR_TS_ISO.match(line) or _ERROR_TS_OLD.match(line):
            return "error"
        if _GENERAL_TS_ISO.match(line) or _GENERAL_TS_OLD.match(line):
            return "general"
        break
    return "general"


def _parse_general_line(line: str) -> Optional[dict]:
    m = _GENERAL_TS_ISO.match(line) or _GENERAL_TS_OLD.match(line)
    if not m:
        return None

    ts, thread_id, cmd, rest = m.group(1), m.group(2), m.group(3), (m.group(4) or "").strip()

    username  = None
    source_ip = None

    if cmd == "Connect":
        # rest: "user@host on database  using TCP/IP"
        parts = rest.split(" on ")
        user_host = parts[0].strip()
        muh = _CONNECT_USER.match(user_host)
        if muh:
            username  = muh.group(1)
            source_ip = muh.group(2)

    event_name = _event_name_from_cmd(cmd, rest)

    return {
        "timestamp":        ts,
        "source_ip":        source_ip,
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
        "action":           None,
        "event_id":         None,
        "event_name":       event_name,
        "event_category":   "Database",
        "process_name":     None,
        "command_line":     rest or None,
        "hostname":         None,
        "domain":           None,
        "log_source":       "mysql",
        "thread_id":        thread_id,
        "raw":              line[:500],
    }


def _parse_error_line(line: str) -> Optional[dict]:
    m = _ERROR_TS_ISO.match(line) or _ERROR_TS_OLD.match(line)
    if not m:
        return None

    ts, level, message = m.group(1), m.group(2), m.group(3)
    event_name = _severity_to_event(level, message)

    username  = None
    source_ip = None
    # Access denied for user 'user'@'host'
    mua = re.search(r"Access denied for user '([^']+)'@'([^']+)'", message)
    if mua:
        username  = mua.group(1)
        source_ip = mua.group(2)
        event_name = "MySQL Access Denied"

    return {
        "timestamp":        ts,
        "source_ip":        source_ip,
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
        "action":           "failure" if "error" in level.lower() or "denied" in message.lower() else None,
        "event_id":         None,
        "event_name":       event_name,
        "event_category":   "Database",
        "process_name":     None,
        "command_line":     message,
        "hostname":         None,
        "domain":           None,
        "log_source":       "mysql",
        "raw":              line[:500],
    }


def parse(file_path: str) -> list:
    """Parse MySQL general query log or error log. Returns normalized event dicts."""
    events = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("MySQL parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("MySQL parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        content = fh.read()

    fmt = _detect_format(content)
    parse_line = _parse_general_line if fmt == "general" else _parse_error_line

    for lineno, line in enumerate(content.splitlines(), 1):
        line_raw = line.rstrip()
        if not line_raw:
            continue
        # Skip header/comment lines
        if line_raw.startswith("#") or line_raw.startswith("/usr") or line_raw.startswith("Tcp"):
            continue
        try:
            rec = parse_line(line_raw)
            if rec:
                events.append(rec)
        except Exception as e:
            logger.warning("MySQL parser: error on line %d: %s", lineno, e)

    return events
