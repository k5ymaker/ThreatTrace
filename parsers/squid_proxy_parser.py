"""
Squid Proxy Log Parser
Native Squid access log format:
  timestamp duration client_ip result/status bytes method url username hierarchy/code content_type
"""

import re
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Squid native log pattern
# 1234567890.123   1234 192.168.1.1 TCP_MISS/200 1234 GET http://example.com/ user DIRECT/1.2.3.4 text/html
SQUID_PATTERN = re.compile(
    r'^(\d+\.\d+)\s+(\d+)\s+(\S+)\s+(\S+)/(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)/(\S+)\s+(\S+)'
)

# Simpler fallback
SQUID_BASIC = re.compile(
    r'^(\d+\.\d+)\s+(\d+)\s+(\S+)\s+(\S+)/(\d+)\s+(\d+)\s+(\S+)\s+(\S+)'
)

RESULT_CODE_EVENT_MAP = {
    "TCP_DENIED":       ("Proxy Auth Failure",          "Proxy",  "deny"),
    "TCP_HIT":          ("Proxy Cache Hit",              "Proxy",  "allow"),
    "TCP_MEM_HIT":      ("Proxy Cache Hit",              "Proxy",  "allow"),
    "TCP_MISS":         ("Proxy Request Allowed",        "Proxy",  "allow"),
    "TCP_TUNNEL":       ("Proxy CONNECT (HTTPS Tunnel)", "Proxy",  "allow"),
    "TCP_REFRESH_HIT":  ("Proxy Cache Hit",              "Proxy",  "allow"),
    "TCP_REFRESH_MISS": ("Proxy Request Allowed",        "Proxy",  "allow"),
    "NONE":             ("Proxy Request",                "Proxy",  None),
}

METHOD_CONNECT_EVENT = ("Proxy CONNECT (HTTPS Tunnel)", "Proxy", "allow")


def _safe_int(val) -> Optional[int]:
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _parse_timestamp(epoch_str: str) -> str:
    try:
        ts = float(epoch_str)
        dt = datetime.utcfromtimestamp(ts).replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return epoch_str


def _classify(result_code: str, status_code: int, method: str) -> tuple:
    """Return (event_name, event_category, action)."""
    # CONNECT method = HTTPS tunnel
    if method and method.upper() == "CONNECT":
        return METHOD_CONNECT_EVENT

    # TCP_DENIED or 407 = auth failure
    if "DENIED" in result_code.upper() or status_code == 407:
        return ("Proxy Auth Failure", "Proxy", "deny")

    # 403 = denied
    if status_code == 403:
        return ("Proxy Request Denied", "Proxy", "deny")

    # Result code mapping
    rc = result_code.upper().split("/")[0] if "/" in result_code else result_code.upper()
    if rc in RESULT_CODE_EVENT_MAP:
        return RESULT_CODE_EVENT_MAP[rc]

    # HTTP status based
    if status_code and 200 <= status_code < 300:
        return ("Proxy Request Allowed", "Proxy", "allow")
    if status_code and status_code in (401, 403, 407):
        return ("Proxy Request Denied", "Proxy", "deny")

    return ("Proxy Request", "Proxy", None)


def parse(file_path: str) -> list:
    """Parse Squid native access log. Returns normalized event dicts."""
    events = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("Squid parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("Squid parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n\r")
            if not line or line.startswith("#"):
                continue

            try:
                m = SQUID_PATTERN.match(line)
                if m:
                    ts_epoch    = m.group(1)
                    duration    = m.group(2)
                    client_ip   = m.group(3)
                    result_code = m.group(4)
                    status_str  = m.group(5)
                    bytes_str   = m.group(6)
                    method      = m.group(7)
                    url         = m.group(8)
                    username    = m.group(9)
                    hier_code   = m.group(10)
                    peer_host   = m.group(11)
                    content_type= m.group(12)
                else:
                    m2 = SQUID_BASIC.match(line)
                    if not m2:
                        logger.debug("Squid parser: no match at line %d", lineno)
                        continue
                    ts_epoch    = m2.group(1)
                    duration    = m2.group(2)
                    client_ip   = m2.group(3)
                    result_code = m2.group(4)
                    status_str  = m2.group(5)
                    bytes_str   = m2.group(6)
                    method      = m2.group(7)
                    url         = m2.group(8)
                    username    = None
                    peer_host   = None
                    content_type= None

                status_code = _safe_int(status_str)
                event_name, event_category, action = _classify(result_code, status_code, method)

                # Extract destination port from URL
                dest_port = None
                if url:
                    port_m = re.search(r':(\d+)(?:/|$)', url.split("//")[-1].split("/")[0])
                    if port_m:
                        dest_port = _safe_int(port_m.group(1))
                    elif method and method.upper() == "CONNECT":
                        dest_port = 443

                events.append({
                    "timestamp":      _parse_timestamp(ts_epoch),
                    "source_ip":      client_ip,
                    "dest_ip":        peer_host if peer_host and peer_host != "-" else None,
                    "source_port":    None,
                    "dest_port":      dest_port,
                    "username":       username if username and username != "-" else None,
                    "user_agent":     None,
                    "method":         method,
                    "url":            url,
                    "status_code":    status_code,
                    "bytes_sent":     _safe_int(bytes_str),
                    "protocol":       "http",
                    "action":         action,
                    "event_id":       None,
                    "event_name":     event_name,
                    "event_category": event_category,
                    "process_name":   None,
                    "command_line":   None,
                    "hostname":       None,
                    "domain":         None,
                    "log_source":     "squid_proxy",
                    "raw":            line,
                })
            except Exception as e:
                logger.warning("Squid parser: error on line %d: %s", lineno, e)
                continue

    return events
