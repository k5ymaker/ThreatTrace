"""
SSH Log Parser
Dedicated parser for sshd events from auth.log / secure.
Subset of linux_auth_parser, focusing exclusively on sshd lines with
additional SSH-specific pattern detection.
"""

import re
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Same syslog header as auth parser
HEADER_PATTERN = re.compile(
    r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?: (.+)$'
)

RFC3164_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

SSH_IP_PORT  = re.compile(r'from (\d+\.\d+\.\d+\.\d+|[\da-f:]+) port (\d+)')
SSH_IP_ONLY  = re.compile(r'from (\d+\.\d+\.\d+\.\d+|[\da-f:]+)')
SSH_USER     = re.compile(r'(?:for(?: invalid user)?|user) (\S+)')
INV_USER     = re.compile(r'Invalid user (\S+)')
CONN_FROM    = re.compile(r'Connection from (\d+\.\d+\.\d+\.\d+|[\da-f:]+) port (\d+)')
DISC_FROM    = re.compile(r'Received disconnect from (\d+\.\d+\.\d+\.\d+|[\da-f:]+) port (\d+)')
BAD_PROTO_IP = re.compile(r'Bad protocol version identification.*from (\d+\.\d+\.\d+\.\d+|[\da-f:]+)')
NO_IDENT_IP  = re.compile(r'Did not receive identification string from (\d+\.\d+\.\d+\.\d+|[\da-f:]+)')


def _parse_timestamp(ts: str) -> str:
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
    return ts


def _classify_ssh(message: str) -> tuple:
    """
    Returns (event_name, username, source_ip, source_port, protocol).
    """
    username    = None
    source_ip   = None
    source_port = None
    protocol    = "SSH2" if "ssh2" in message.lower() else None

    # Extract IP and port
    m_ip = SSH_IP_PORT.search(message)
    if m_ip:
        source_ip   = m_ip.group(1)
        source_port = int(m_ip.group(2))
    else:
        m_ip2 = SSH_IP_ONLY.search(message)
        if m_ip2:
            source_ip = m_ip2.group(1)

    # Extract user
    inv = INV_USER.search(message)
    if inv:
        username = inv.group(1)
    else:
        mu = SSH_USER.search(message)
        if mu:
            username = mu.group(1)

    # Classify event
    if "Accepted password" in message:
        return ("SSH Accepted Password",              username, source_ip, source_port, protocol)
    if "Failed password" in message:
        return ("SSH Failed Password",                username, source_ip, source_port, protocol)
    if "Invalid user" in message:
        return ("SSH Invalid User Attempt",           username, source_ip, source_port, protocol)
    if "Accepted publickey" in message:
        return ("SSH Public Key Accepted",            username, source_ip, source_port, protocol)
    if "Accepted keyboard-interactive" in message:
        return ("SSH Keyboard-Interactive Auth",      username, source_ip, source_port, protocol)
    if "Connection closed" in message:
        return ("SSH Connection Closed",              username, source_ip, source_port, protocol)
    if "Disconnecting: Too many authentication failures" in message:
        return ("SSH Max Auth Exceeded",              username, source_ip, source_port, protocol)
    if "error: maximum authentication attempts exceeded" in message.lower():
        return ("SSH Max Auth Tries Exceeded",        username, source_ip, source_port, protocol)
    if "Too many authentication failures" in message:
        return ("SSH Max Auth Exceeded",              username, source_ip, source_port, protocol)

    m_recv = DISC_FROM.search(message)
    if m_recv or "Received disconnect" in message:
        if m_recv:
            source_ip   = m_recv.group(1)
            source_port = int(m_recv.group(2))
        return ("SSH Client Disconnect",              username, source_ip, source_port, protocol)

    m_conn = CONN_FROM.search(message)
    if m_conn or "Connection from" in message:
        if m_conn:
            source_ip   = m_conn.group(1)
            source_port = int(m_conn.group(2))
        return ("SSH Connection Established",         username, source_ip, source_port, protocol)

    m_noid = NO_IDENT_IP.search(message)
    if m_noid or "Did not receive identification string" in message:
        if m_noid:
            source_ip = m_noid.group(1)
        return ("SSH Scanner Detected",               username, source_ip, source_port, protocol)

    m_badp = BAD_PROTO_IP.search(message)
    if m_badp or "Bad protocol version identification" in message:
        if m_badp:
            source_ip = m_badp.group(1)
        return ("SSH Protocol Error",                 username, source_ip, source_port, protocol)

    if "session opened" in message.lower():
        return ("SSH Session Opened",                 username, source_ip, source_port, protocol)
    if "session closed" in message.lower():
        return ("SSH Session Closed",                 username, source_ip, source_port, protocol)
    if "PAM" in message:
        return ("SSH PAM Event",                      username, source_ip, source_port, protocol)

    return ("SSH Event",                              username, source_ip, source_port, protocol)


def parse(file_path: str) -> list:
    """Parse SSH log file (auth.log/secure). Returns normalized event dicts for sshd lines only."""
    events = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("SSH parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("SSH parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n\r")
            if not line:
                continue

            m = HEADER_PATTERN.match(line)
            if not m:
                continue

            try:
                ts_raw  = m.group(1)
                host    = m.group(2)
                process = m.group(3)
                message = m.group(5)

                # Only process sshd lines
                if "sshd" not in process.lower():
                    continue

                event_name, username, source_ip, source_port, protocol = _classify_ssh(message)
                timestamp = _parse_timestamp(ts_raw)

                events.append({
                    "timestamp":      timestamp,
                    "source_ip":      source_ip,
                    "dest_ip":        None,
                    "source_port":    source_port,
                    "dest_port":      22,
                    "username":       username,
                    "user_agent":     None,
                    "method":         None,
                    "url":            None,
                    "status_code":    None,
                    "bytes_sent":     None,
                    "protocol":       protocol,
                    "action":         None,
                    "event_id":       None,
                    "event_name":     event_name,
                    "event_category": "Authentication",
                    "process_name":   process,
                    "command_line":   None,
                    "hostname":       host,
                    "domain":         None,
                    "log_source":     "ssh",
                    "raw":            line,
                })
            except Exception as e:
                logger.warning("SSH parser: error on line %d: %s", lineno, e)

    return events
