"""
VPN Log Parser
Supports OpenVPN daemon logs, Cisco ASA VPN syslogs, and
GlobalProtect (Palo Alto) syslog format.
"""

import re
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# OpenVPN patterns
# --------------------------------------------------------------------------
# OpenVPN log timestamp: "Mon Jan 15 03:11:02 2025" or ISO "2025-01-15 03:11:02"
_OVPN_TS_LONG = re.compile(
    r'^(\w{3} \w{3}\s+\d+ \d{2}:\d{2}:\d{2} \d{4})\s+(.+)$'
)
_OVPN_TS_ISO  = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(.+)$'
)
_OVPN_CLIENT_IP = re.compile(
    r'from \[AF_INET\](\d+\.\d+\.\d+\.\d+):(\d+)'
)

_OVPN_EVENTS = [
    ("TCP connection established",  "VPN Connect",        "VPN"),
    ("client-instance exiting",     "VPN Disconnect",     "VPN"),
    ("AUTH_FAILED",                 "VPN Auth Failed",    "VPN"),
    ("PUSH_REQUEST",                "VPN Data Transfer",  "VPN"),
    ("Peer Connection Initiated",   "VPN Connect",        "VPN"),
    ("SIGTERM",                     "VPN Disconnect",     "VPN"),
]

# --------------------------------------------------------------------------
# Cisco ASA patterns
# --------------------------------------------------------------------------
# %ASA-6-716001: Group <grp> User <user> IP <ip> AnyConnect session started.
_ASA_HEADER = re.compile(
    r'%ASA-\d+-(\d+):\s*(.*)'
)
_ASA_USER    = re.compile(r'User <([^>]+)>')
_ASA_GROUP   = re.compile(r'Group <([^>]+)>')
_ASA_IP      = re.compile(r'IP <([^>]+)>|IP (\d+\.\d+\.\d+\.\d+)')

_ASA_EVENTS = {
    "716001": ("AnyConnect Session Started", "VPN"),
    "716002": ("AnyConnect Session Ended",   "VPN"),
    "713228": ("AnyConnect Auth Failed",     "VPN"),
    "734001": ("AnyConnect IP Assigned",     "VPN"),
    "722051": ("VPN Client Connected",       "VPN"),
    "722036": ("VPN Client Disconnected",    "VPN"),
    "713198": ("VPN Auth Failed",            "VPN"),
}

# --------------------------------------------------------------------------
# GlobalProtect (Palo Alto) syslog
# --------------------------------------------------------------------------
_GP_HEADER  = re.compile(r'type=globalprotect', re.IGNORECASE)
_GP_FIELD   = re.compile(r'(\w+)=([^ ,]+)')

_GP_SUBTYPES = {
    "portal-auth":   ("GlobalProtect Auth",         "VPN"),
    "gateway-auth":  ("GlobalProtect Connected",    "VPN"),
    "logout":        ("GlobalProtect Disconnected", "VPN"),
    "hip-report":    ("GlobalProtect HIP Report",   "VPN"),
    "connected":     ("GlobalProtect Connected",    "VPN"),
    "disconnected":  ("GlobalProtect Disconnected", "VPN"),
}

# Syslog timestamp at start of line
_SYSLOG_TS = re.compile(
    r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)'
)

RFC3164_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _normalize_ts(ts: str) -> str:
    ts = ts.strip()
    # Already ISO-ish
    if re.match(r'\d{4}-\d{2}-\d{2}', ts):
        return ts.replace(" ", "T")
    # RFC3164 "Jan 15 03:11:02"
    try:
        parts = ts.split()
        if len(parts) == 3:
            month = RFC3164_MONTHS.get(parts[0], 1)
            day   = int(parts[1])
            hms   = parts[2].split(":")
            h, m, s = int(hms[0]), int(hms[1]), int(hms[2])
            year  = datetime.utcnow().year
            d = datetime(year, month, day, h, m, s, tzinfo=timezone.utc)
            return d.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        pass
    # Long format: "Mon Jan 15 03:11:02 2025"
    try:
        d = datetime.strptime(ts, "%a %b %d %H:%M:%S %Y")
        d = d.replace(tzinfo=timezone.utc)
        return d.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        pass
    return ts


def _make_event(timestamp, event_name, event_category, source_ip=None,
                username=None, action=None, raw="") -> dict:
    return {
        "timestamp":      timestamp,
        "source_ip":      source_ip,
        "dest_ip":        None,
        "source_port":    None,
        "dest_port":      None,
        "username":       username,
        "user_agent":     None,
        "method":         None,
        "url":            None,
        "status_code":    None,
        "bytes_sent":     None,
        "protocol":       None,
        "action":         action,
        "event_id":       None,
        "event_name":     event_name,
        "event_category": event_category,
        "process_name":   None,
        "command_line":   None,
        "hostname":       None,
        "domain":         None,
        "log_source":     "vpn",
        "raw":            raw[:500],
    }


def _try_parse_openvpn(line: str) -> Optional[dict]:
    """Try to parse as OpenVPN log line."""
    ts      = None
    message = line

    m = _OVPN_TS_ISO.match(line)
    if m:
        ts, message = m.group(1), m.group(2)
    else:
        m2 = _OVPN_TS_LONG.match(line)
        if m2:
            ts, message = m2.group(1), m2.group(2)

    for pattern, event_name, category in _OVPN_EVENTS:
        if pattern in message:
            source_ip   = None
            source_port = None
            mc = _OVPN_CLIENT_IP.search(message)
            if mc:
                source_ip   = mc.group(1)
                source_port = int(mc.group(2))
            action = "failure" if "FAILED" in message or "AUTH_FAILED" in message else None
            ev = _make_event(
                _normalize_ts(ts) if ts else None,
                event_name, category, source_ip,
                action=action, raw=line
            )
            ev["source_port"] = source_port
            return ev

    return None


def _try_parse_asa(line: str) -> Optional[dict]:
    """Try to parse as Cisco ASA VPN syslog line."""
    m = _ASA_HEADER.search(line)
    if not m:
        return None

    msg_id  = m.group(1)
    message = m.group(2)

    if msg_id not in _ASA_EVENTS:
        return None

    event_name, category = _ASA_EVENTS[msg_id]

    mu = _ASA_USER.search(message)
    mi = _ASA_IP.search(message)
    username  = mu.group(1) if mu else None
    source_ip = None
    if mi:
        source_ip = mi.group(1) or mi.group(2)

    # Extract timestamp from beginning of line
    ts_m = _SYSLOG_TS.match(line)
    ts   = _normalize_ts(ts_m.group(1)) if ts_m else None

    action = "failure" if "Failed" in event_name or "Auth Failed" in event_name else "success"

    return _make_event(ts, event_name, category, source_ip, username, action, raw=line)


def _try_parse_globalprotect(line: str) -> Optional[dict]:
    """Try to parse as GlobalProtect syslog line."""
    if not _GP_HEADER.search(line):
        return None

    fields = dict(_GP_FIELD.findall(line))
    subtype   = fields.get("subtype", "").lower()
    src_ip    = fields.get("src", fields.get("private_ip", fields.get("public_ip")))
    username  = fields.get("srcuser", fields.get("user"))

    event_name, category = _GP_SUBTYPES.get(
        subtype, ("GlobalProtect Event", "VPN")
    )

    ts_m = _SYSLOG_TS.match(line)
    ts   = _normalize_ts(ts_m.group(1)) if ts_m else None

    action = "failure" if "auth" in event_name.lower() and "Disconnect" not in event_name else None

    return _make_event(ts, event_name, category, src_ip, username, action, raw=line)


def parse(file_path: str) -> list:
    """Parse VPN log file (OpenVPN/Cisco ASA/GlobalProtect). Returns normalized event dicts."""
    events = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("VPN parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("VPN parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n\r")
            if not line:
                continue
            try:
                rec = (
                    _try_parse_globalprotect(line)
                    or _try_parse_asa(line)
                    or _try_parse_openvpn(line)
                )
                if rec:
                    events.append(rec)
            except Exception as e:
                logger.warning("VPN parser: error on line %d: %s", lineno, e)

    return events
