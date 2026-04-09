"""
DNS Log Parser
Supports BIND query log format and Windows DNS debug log format.
"""

import re
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# BIND named query log:
# 15-Jan-2025 03:42:17.123 client 192.168.1.1#54321 (example.com): query: example.com IN A +
# OR
# 15-Jan-2025 03:42:17.123 queries: info: client @0xabcd 192.168.1.1#54321 (example.com): query: example.com IN A + (127.0.0.1)
BIND_PATTERN = re.compile(
    r'(?P<ts>\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+'
    r'(?:queries: info: )?client\S*\s+(?P<ip>[\d.a-f:]+)#(?P<port>\d+)'
    r'.*?query: (?P<name>\S+)\s+(?P<class>\S+)\s+(?P<qtype>\S+)\s+(?P<flags>[+\-\w]*)'
)

# BIND error responses
BIND_RESPONSE = re.compile(
    r'(?P<ts>\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+'
    r'.*?(?P<response>NXDOMAIN|SERVFAIL|REFUSED|NOERROR)'
)

# Windows DNS Debug Log:
# 15/01/2025 03:42:17 AM 0F40 PACKET 00000001 UDP Rcv 192.168.1.1 0001 Q [0001 D NOERROR] A (7)example(3)com(0)
WIN_DNS_PATTERN = re.compile(
    r'(?P<date>\d{1,2}/\d{1,2}/\d{4})\s+(?P<time>\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?)\s+'
    r'\S+\s+PACKET\s+\S+\s+(?P<proto>UDP|TCP)\s+(?:Snd|Rcv)\s+'
    r'(?P<ip>[\d.a-f:]+)\s+\S+\s+(?P<dir>[QR])\s+\[(?P<flags>[^\]]+)\]\s+'
    r'(?P<qtype>\S+)\s+(?P<name>.+)$'
)

BIND_DATE_FORMAT = "%d-%b-%Y %H:%M:%S"

QTYPE_EVENT_MAP = {
    "A":    ("DNS A Query",               "DNS"),
    "AAAA": ("DNS AAAA Query",            "DNS"),
    "MX":   ("DNS MX Query",              "DNS"),
    "TXT":  ("DNS TXT Query",             "DNS"),
    "PTR":  ("DNS Reverse Lookup (PTR)",  "DNS"),
    "SRV":  ("DNS SRV Query",             "DNS"),
    "NS":   ("DNS NS Query",              "DNS"),
    "CNAME":("DNS CNAME Query",           "DNS"),
    "SOA":  ("DNS SOA Query",             "DNS"),
    "ANY":  ("DNS ANY Query",             "DNS"),
}


def _safe_int(val) -> Optional[int]:
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _parse_bind_timestamp(ts: str) -> str:
    try:
        ts_clean = ts.split(".")[0]
        dt = datetime.strptime(ts_clean, BIND_DATE_FORMAT)
        return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ts


def _parse_win_dns_timestamp(date: str, time: str) -> str:
    try:
        raw = f"{date} {time.strip()}"
        for fmt in ("%m/%d/%Y %I:%M:%S %p", "%d/%m/%Y %I:%M:%S %p",
                    "%m/%d/%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
            try:
                dt = datetime.strptime(raw, fmt)
                return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                continue
    except Exception:
        pass
    return f"{date}T{time}Z"


def _classify_qtype(qtype: str, response_code: str = None) -> tuple:
    """Return (event_name, event_category) for a DNS query type."""
    if response_code:
        rc = response_code.upper()
        if "NXDOMAIN" in rc:
            return ("DNS NXDOMAIN Response", "DNS")
        if "SERVFAIL" in rc:
            return ("DNS SERVFAIL Response", "DNS")

    qt = qtype.upper()
    if qt in QTYPE_EVENT_MAP:
        return QTYPE_EVENT_MAP[qt]
    return ("DNS Query", "DNS")


def _decode_win_dns_name(encoded: str) -> str:
    """Decode Windows DNS packet name format: (7)example(3)com(0)"""
    try:
        parts = re.findall(r'\((\d+)\)([^(]*)', encoded)
        labels = [p[1].strip() for p in parts if p[1].strip() and p[0] != "0"]
        if labels:
            return ".".join(labels)
    except Exception:
        pass
    return encoded.strip()


def parse(file_path: str) -> list:
    """Parse BIND or Windows DNS debug log. Returns normalized event dicts."""
    events = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("DNS parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("DNS parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n\r")
            if not line:
                continue

            event = None

            # Try BIND format
            m = BIND_PATTERN.search(line)
            if m:
                ts_raw   = m.group("ts")
                src_ip   = m.group("ip")
                src_port = _safe_int(m.group("port"))
                qname    = m.group("name")
                qtype    = m.group("qtype")
                flags    = m.group("flags")

                # Check for NXDOMAIN in flags
                response_code = None
                if "NXDOMAIN" in line:
                    response_code = "NXDOMAIN"
                elif "SERVFAIL" in line:
                    response_code = "SERVFAIL"

                event_name, event_category = _classify_qtype(qtype, response_code)

                event = {
                    "timestamp":      _parse_bind_timestamp(ts_raw),
                    "source_ip":      src_ip,
                    "dest_ip":        None,
                    "source_port":    src_port,
                    "dest_port":      53,
                    "username":       None,
                    "user_agent":     None,
                    "method":         None,
                    "url":            qname,
                    "status_code":    None,
                    "bytes_sent":     None,
                    "protocol":       "udp",
                    "action":         None,
                    "event_id":       None,
                    "event_name":     event_name,
                    "event_category": event_category,
                    "process_name":   None,
                    "command_line":   None,
                    "hostname":       None,
                    "domain":         qname,
                    "log_source":     "dns",
                    "raw":            line,
                }

            else:
                # Try Windows DNS debug format
                wm = WIN_DNS_PATTERN.search(line)
                if wm:
                    date_str  = wm.group("date")
                    time_str  = wm.group("time")
                    proto     = wm.group("proto").lower()
                    src_ip    = wm.group("ip")
                    direction = wm.group("dir")
                    qtype     = wm.group("qtype")
                    raw_name  = wm.group("name")
                    flags     = wm.group("flags")

                    qname = _decode_win_dns_name(raw_name)

                    response_code = None
                    if "NXDOMAIN" in flags:
                        response_code = "NXDOMAIN"
                    elif "SERVFAIL" in flags:
                        response_code = "SERVFAIL"

                    event_name, event_category = _classify_qtype(qtype, response_code)

                    event = {
                        "timestamp":      _parse_win_dns_timestamp(date_str, time_str),
                        "source_ip":      src_ip if direction == "R" else None,
                        "dest_ip":        None,
                        "source_port":    None,
                        "dest_port":      53,
                        "username":       None,
                        "user_agent":     None,
                        "method":         None,
                        "url":            qname,
                        "status_code":    None,
                        "bytes_sent":     None,
                        "protocol":       proto,
                        "action":         None,
                        "event_id":       None,
                        "event_name":     event_name,
                        "event_category": event_category,
                        "process_name":   None,
                        "command_line":   None,
                        "hostname":       None,
                        "domain":         qname,
                        "log_source":     "dns",
                        "raw":            line,
                    }

            if event:
                events.append(event)
            else:
                logger.debug("DNS parser: no match at line %d", lineno)

    return events
