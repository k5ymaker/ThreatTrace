"""
Multi-Vendor Firewall Log Parser
Auto-detects: Cisco ASA, Fortinet, pfSense (filterlog), Palo Alto.
"""

import re
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Cisco ASA: %ASA-level-msgid: message
CISCO_ASA_PATTERN = re.compile(
    r'%ASA-\d+-(\d+):\s*(.+)$'
)

# Cisco ASA field extraction
CISCO_IP_PATTERN = re.compile(
    r'(\d+\.\d+\.\d+\.\d+)(?:/(\d+))?'
)

# Fortinet: key=value format; signature field
FORTINET_KV = re.compile(r'(\w+)=(?:"([^"]*)"|\S+)')

# pfSense filterlog CSV detection
PFSENSE_PATTERN = re.compile(
    r'filterlog\[.*?\]:\s+(.+)$'
)

# Palo Alto: comma-separated, starts with future use or specific fields
PALO_ALTO_PATTERN = re.compile(
    r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}'
)


# ─── Cisco ASA msgid mappings ────────────────────────────────────────────────

CISCO_MSGID_MAP = {
    "106001": ("ACL Deny",                  "Firewall", "deny"),
    "106006": ("ACL Deny",                  "Firewall", "deny"),
    "106015": ("ACL Deny",                  "Firewall", "deny"),
    "106023": ("ACL Deny",                  "Firewall", "deny"),
    "106100": ("ACL Permit",                "Firewall", "permit"),
    "302013": ("TCP Connection Build",      "Firewall", "allow"),
    "302014": ("TCP Connection Teardown",   "Firewall", "allow"),
    "302015": ("UDP Connection Build",      "Firewall", "allow"),
    "302016": ("UDP Connection Teardown",   "Firewall", "allow"),
    "113005": ("AAA Authentication",        "Authentication", None),
    "113015": ("AAA Authentication",        "Authentication", None),
    "710003": ("TCP Access Denied",         "Firewall", "deny"),
}


def _safe_int(val) -> Optional[int]:
    try:
        return int(val) if val else None
    except (ValueError, TypeError):
        return None


def _parse_generic_timestamp(ts: str) -> str:
    """Try various timestamp formats and return ISO 8601."""
    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%b %d %H:%M:%S",
        "%b  %d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(ts.strip(), fmt)
            if dt.year == 1900:
                dt = dt.replace(year=datetime.utcnow().year)
            return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return ts


def _extract_cisco_ips(msg: str):
    """Extract source/dest IP and port from ASA message."""
    ips = CISCO_IP_PATTERN.findall(msg)
    src_ip = src_port = dst_ip = dst_port = None
    if len(ips) >= 1:
        src_ip   = ips[0][0]
        src_port = _safe_int(ips[0][1]) if ips[0][1] else None
    if len(ips) >= 2:
        dst_ip   = ips[1][0]
        dst_port = _safe_int(ips[1][1]) if ips[1][1] else None
    return src_ip, src_port, dst_ip, dst_port


def _parse_cisco_asa(line: str) -> Optional[dict]:
    m = CISCO_ASA_PATTERN.search(line)
    if not m:
        return None

    msgid   = m.group(1)
    message = m.group(2)

    if msgid in CISCO_MSGID_MAP:
        event_name, event_category, action = CISCO_MSGID_MAP[msgid]
    else:
        event_name     = f"ASA Event {msgid}"
        event_category = "Firewall"
        action         = None

    src_ip, src_port, dst_ip, dst_port = _extract_cisco_ips(message)

    # Try to extract protocol
    proto_m = re.search(r'\b(TCP|UDP|ICMP|GRE)\b', message, re.IGNORECASE)
    protocol = proto_m.group(1).lower() if proto_m else None

    # Extract action from message if not from mapping
    if action is None:
        if re.search(r'\b(deny|denied|block|drop)\b', message, re.IGNORECASE):
            action = "deny"
        elif re.search(r'\b(permit|allow|pass)\b', message, re.IGNORECASE):
            action = "allow"

    return {
        "timestamp":      None,
        "source_ip":      src_ip,
        "dest_ip":        dst_ip,
        "source_port":    src_port,
        "dest_port":      dst_port,
        "username":       None,
        "user_agent":     None,
        "method":         None,
        "url":            None,
        "status_code":    None,
        "bytes_sent":     None,
        "protocol":       protocol,
        "action":         action,
        "event_id":       msgid,
        "event_name":     event_name,
        "event_category": event_category,
        "process_name":   None,
        "command_line":   None,
        "hostname":       None,
        "domain":         None,
        "log_source":     "firewall_cisco_asa",
        "raw":            line,
    }


def _parse_fortinet(line: str) -> Optional[dict]:
    """Parse Fortinet key=value syslog line."""
    kv = {}
    for m in FORTINET_KV.finditer(line):
        k = m.group(1)
        v = m.group(2) if m.group(2) is not None else m.group(0).split("=", 1)[1]
        kv[k] = v

    if not kv:
        return None

    ftype   = kv.get("type", "").lower()
    subtype = kv.get("subtype", "").lower()
    action  = kv.get("action", "").lower()

    # Derive event name
    if ftype == "traffic":
        if action in ("accept", "allow", "permit"):
            event_name = "Traffic Allow"
        elif action in ("deny", "drop", "block"):
            event_name = "Traffic Deny"
        else:
            event_name = f"Traffic {action.capitalize()}"
    elif ftype == "utm" and subtype == "ips":
        event_name = "IPS Alert"
    elif ftype == "utm" and subtype == "av":
        event_name = "Antivirus Block"
    elif "vpn" in subtype or "vpn" in ftype:
        if "up" in action or "connect" in action:
            event_name = "VPN Tunnel Up"
        else:
            event_name = "VPN Tunnel Down"
    else:
        event_name = f"{ftype.capitalize()} {subtype.capitalize()}".strip()

    ts_raw = kv.get("date", "") + " " + kv.get("time", "")
    timestamp = _parse_generic_timestamp(ts_raw.strip()) if ts_raw.strip() else None

    return {
        "timestamp":      timestamp,
        "source_ip":      kv.get("srcip"),
        "dest_ip":        kv.get("dstip"),
        "source_port":    _safe_int(kv.get("srcport")),
        "dest_port":      _safe_int(kv.get("dstport")),
        "username":       kv.get("user") or kv.get("username"),
        "user_agent":     None,
        "method":         None,
        "url":            kv.get("url"),
        "status_code":    None,
        "bytes_sent":     _safe_int(kv.get("sentbyte")),
        "protocol":       kv.get("proto") or kv.get("service"),
        "action":         action if action else None,
        "event_id":       kv.get("logid"),
        "event_name":     event_name,
        "event_category": "Firewall",
        "process_name":   None,
        "command_line":   None,
        "hostname":       kv.get("devname"),
        "domain":         None,
        "log_source":     "firewall_fortinet",
        "raw":            line,
    }


def _parse_pfsense(line: str) -> Optional[dict]:
    """Parse pfSense filterlog CSV line."""
    m = PFSENSE_PATTERN.search(line)
    if not m:
        return None

    csv_data = m.group(1)
    fields   = csv_data.split(",")

    # CSV layout (simplified): rule,subrule,anchor,tracker,interface,reason,action,
    # direction,ip_version,...,proto,src,dst,[sport,dport]
    if len(fields) < 9:
        return None

    try:
        rule_num  = fields[0].strip()
        interface = fields[4].strip() if len(fields) > 4 else None
        reason    = fields[5].strip() if len(fields) > 5 else None
        action    = fields[6].strip() if len(fields) > 6 else None
        direction = fields[7].strip() if len(fields) > 7 else None
        ip_ver    = fields[8].strip() if len(fields) > 8 else None

        # IP version determines field offsets
        src_ip = dst_ip = src_port = dst_port = protocol = None
        if ip_ver == "4" and len(fields) >= 18:
            protocol = fields[16].strip()
            src_ip   = fields[18].strip() if len(fields) > 18 else None
            dst_ip   = fields[19].strip() if len(fields) > 19 else None
            src_port = _safe_int(fields[20]) if len(fields) > 20 else None
            dst_port = _safe_int(fields[21]) if len(fields) > 21 else None
        elif ip_ver == "6" and len(fields) >= 16:
            protocol = fields[14].strip() if len(fields) > 14 else None
            src_ip   = fields[15].strip() if len(fields) > 15 else None
            dst_ip   = fields[16].strip() if len(fields) > 16 else None

        if action and action.lower() == "pass":
            event_name = "Firewall Pass"
        else:
            event_name = "Firewall Block"

        return {
            "timestamp":      None,
            "source_ip":      src_ip,
            "dest_ip":        dst_ip,
            "source_port":    src_port,
            "dest_port":      dst_port,
            "username":       None,
            "user_agent":     None,
            "method":         None,
            "url":            None,
            "status_code":    None,
            "bytes_sent":     None,
            "protocol":       protocol,
            "action":         action.lower() if action else None,
            "event_id":       rule_num,
            "event_name":     event_name,
            "event_category": "Firewall",
            "process_name":   None,
            "command_line":   None,
            "hostname":       interface,
            "domain":         None,
            "log_source":     "firewall_pfsense",
            "raw":            line,
        }
    except Exception as e:
        logger.debug("pfSense parser error: %s", e)
        return None


def _parse_palo_alto(line: str) -> Optional[dict]:
    """Parse Palo Alto CSV syslog line."""
    # PA logs: FUTURE_USE,RECEIVE_TIME,SERIAL,TYPE,SUBTYPE,VERSION,GENERATE_TIME,...
    # Split on comma
    fields = line.split(",")
    if len(fields) < 7:
        return None

    # Basic PA traffic log layout (simplified)
    # Fields depend on log type; use positional heuristics
    log_type = fields[3].strip() if len(fields) > 3 else ""

    if log_type.lower() == "traffic":
        if len(fields) < 30:
            return None
        src_ip   = fields[7].strip()  if len(fields) > 7  else None
        dst_ip   = fields[8].strip()  if len(fields) > 8  else None
        src_port = _safe_int(fields[24]) if len(fields) > 24 else None
        dst_port = _safe_int(fields[25]) if len(fields) > 25 else None
        protocol = fields[29].strip() if len(fields) > 29 else None
        action   = fields[30].strip() if len(fields) > 30 else None
        event_name = "Traffic Allow" if action and "allow" in action.lower() else "Traffic Deny"
    elif log_type.lower() == "threat":
        src_ip   = fields[7].strip()  if len(fields) > 7  else None
        dst_ip   = fields[8].strip()  if len(fields) > 8  else None
        src_port = _safe_int(fields[24]) if len(fields) > 24 else None
        dst_port = _safe_int(fields[25]) if len(fields) > 25 else None
        protocol = None
        action   = None
        event_name = "Threat Detected"
    elif log_type.lower() == "url":
        src_ip     = fields[7].strip() if len(fields) > 7 else None
        dst_ip     = fields[8].strip() if len(fields) > 8 else None
        src_port   = None
        dst_port   = None
        protocol   = None
        action     = None
        event_name = "URL Filtered"
    else:
        src_ip = dst_ip = src_port = dst_port = protocol = action = None
        event_name = f"PA {log_type.capitalize()} Event"

    ts_raw    = fields[1].strip() if len(fields) > 1 else None
    timestamp = _parse_generic_timestamp(ts_raw) if ts_raw else None

    return {
        "timestamp":      timestamp,
        "source_ip":      src_ip,
        "dest_ip":        dst_ip,
        "source_port":    src_port,
        "dest_port":      dst_port,
        "username":       None,
        "user_agent":     None,
        "method":         None,
        "url":            fields[31].strip() if log_type.lower() == "url" and len(fields) > 31 else None,
        "status_code":    None,
        "bytes_sent":     None,
        "protocol":       protocol,
        "action":         action.lower() if action else None,
        "event_id":       None,
        "event_name":     event_name,
        "event_category": "Firewall",
        "process_name":   None,
        "command_line":   None,
        "hostname":       fields[4].strip() if len(fields) > 4 else None,
        "domain":         None,
        "log_source":     "firewall_palo_alto",
        "raw":            line,
    }


def _detect_and_parse(line: str) -> Optional[dict]:
    """Auto-detect firewall vendor and parse line."""
    if "%ASA-" in line:
        return _parse_cisco_asa(line)

    if "filterlog[" in line or "filterlog:" in line:
        return _parse_pfsense(line)

    # Fortinet: must have several key=value pairs including type= and subtype=
    if "type=" in line and "subtype=" in line:
        return _parse_fortinet(line)

    # Palo Alto: CSV with 4th field being a log type
    if "," in line:
        parts = line.split(",")
        if len(parts) > 4 and parts[3].strip().lower() in ("traffic", "threat", "url", "wildfire", "auth"):
            return _parse_palo_alto(line)

    return None


def parse(file_path: str) -> list:
    """Parse multi-vendor firewall logs. Returns normalized event dicts."""
    events = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("Firewall parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("Firewall parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n\r")
            if not line:
                continue
            try:
                event = _detect_and_parse(line)
                if event:
                    events.append(event)
                else:
                    logger.debug("Firewall parser: unrecognized format at line %d", lineno)
            except Exception as e:
                logger.warning("Firewall parser: error on line %d: %s", lineno, e)
                continue

    return events
