"""
Linux Auth Log Parser
Parses /var/log/auth.log and /var/log/secure.
Detects SSH, sudo, PAM, login, and session events.
"""

import re
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Header: "Jan 15 03:42:17 hostname process[pid]: message"
HEADER_PATTERN = re.compile(
    r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?: (.+)$'
)

RFC3164_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# SSH field extraction patterns
SSH_IP_PORT = re.compile(r'from (\d+\.\d+\.\d+\.\d+|[\da-f:]+) port (\d+)')
SSH_USER    = re.compile(r'(?:for|user) (\S+)')
SUDO_CMDLINE= re.compile(r'COMMAND=(.+)$')
SUDO_USER   = re.compile(r'^(\S+)\s+:')
SESSION_USER= re.compile(r'session (?:opened|closed) for user (\S+)')
SU_USER     = re.compile(r"Successful su for (\S+)|su: \(to (\S+)\)")
PAM_USER    = re.compile(r'user=(\S+)')


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


def _classify(process: str, message: str) -> tuple:
    """
    Returns (event_name, event_category, username, source_ip, source_port).
    """
    proc = process.lower().rstrip(":")
    msg  = message

    username    = None
    source_ip   = None
    source_port = None

    # SSH events
    if "sshd" in proc:
        m_ip = SSH_IP_PORT.search(msg)
        if m_ip:
            source_ip   = m_ip.group(1)
            source_port = int(m_ip.group(2))

        m_user = SSH_USER.search(msg)
        if m_user:
            username = m_user.group(1)

        # Invalid user has slightly different pattern
        inv_user = re.search(r'Invalid user (\S+)', msg)
        if inv_user:
            username = inv_user.group(1)

        if "Accepted password" in msg:
            return ("SSH Accepted Password",          "Authentication", username, source_ip, source_port)
        if "Failed password" in msg:
            return ("SSH Failed Password",            "Authentication", username, source_ip, source_port)
        if "Invalid user" in msg:
            return ("SSH Invalid User Attempt",       "Authentication", username, source_ip, source_port)
        if "Accepted publickey" in msg:
            return ("SSH Public Key Accepted",        "Authentication", username, source_ip, source_port)
        if "Connection closed" in msg:
            return ("SSH Connection Closed",          "Authentication", username, source_ip, source_port)
        if "error: maximum authentication" in msg.lower():
            return ("SSH Max Auth Tries Exceeded",    "Authentication", username, source_ip, source_port)
        return ("SSH Event",                          "Authentication", username, source_ip, source_port)

    # sudo events
    if proc == "sudo" or proc.startswith("sudo"):
        m_user = SUDO_USER.match(msg)
        if m_user:
            username = m_user.group(1)
        if "COMMAND=" in msg:
            return ("Sudo Command Executed",          "Privilege Escalation", username, None, None)
        if "auth failure" in msg.lower() or "authentication failure" in msg.lower():
            return ("Sudo Authentication Failure",    "Privilege Escalation", username, None, None)
        return ("Sudo Event",                         "Privilege Escalation", username, None, None)

    # PAM events
    if "pam_unix" in proc or "pam" in proc:
        m_user = PAM_USER.search(msg)
        if m_user:
            username = m_user.group(1)
        if "authentication failure" in msg.lower():
            return ("PAM Authentication Failure",     "Authentication", username, None, None)
        if "session opened" in msg.lower():
            m_su = SESSION_USER.search(msg)
            if m_su:
                username = m_su.group(1)
            return ("User Login (local)",             "Session", username, None, None)
        if "session closed" in msg.lower():
            m_su = SESSION_USER.search(msg)
            if m_su:
                username = m_su.group(1)
            return ("User Logout (local)",            "Session", username, None, None)
        return ("PAM Event",                          "Authentication", username, None, None)

    # login / gdm events
    if proc in ("login", "gdm", "gdm3", "gdm-password"):
        if "session opened" in msg.lower() or "logged in" in msg.lower():
            m_su = SESSION_USER.search(msg)
            if m_su:
                username = m_su.group(1)
            return ("User Login (local)",             "Session", username, None, None)
        if "session closed" in msg.lower():
            m_su = SESSION_USER.search(msg)
            if m_su:
                username = m_su.group(1)
            return ("User Logout (local)",            "Session", username, None, None)

    # session opened / closed (systemd-logind, etc.)
    if "session opened" in msg.lower():
        m_su = SESSION_USER.search(msg)
        if m_su:
            username = m_su.group(1)
        return ("User Login (local)",                 "Session", username, None, None)
    if "session closed" in msg.lower():
        m_su = SESSION_USER.search(msg)
        if m_su:
            username = m_su.group(1)
        return ("User Logout (local)",                "Session", username, None, None)

    # su
    if proc == "su":
        m_su = SU_USER.search(msg)
        if m_su:
            username = m_su.group(1) or m_su.group(2)
        return ("Switch User (su)",                   "Privilege Escalation", username, None, None)

    return ("Auth Event",                             "Authentication", username, source_ip, source_port)


def parse(file_path: str) -> list:
    """Parse Linux auth.log / secure log. Returns normalized event dicts."""
    events = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("Auth parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("Auth parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n\r")
            if not line:
                continue

            m = HEADER_PATTERN.match(line)
            if not m:
                logger.debug("Auth parser: no match at line %d", lineno)
                continue

            try:
                ts_raw  = m.group(1)
                host    = m.group(2)
                process = m.group(3)
                message = m.group(5)

                event_name, event_category, username, source_ip, source_port = _classify(process, message)
                timestamp = _parse_timestamp(ts_raw)

                events.append({
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
                    "event_id":       None,
                    "event_name":     event_name,
                    "event_category": event_category,
                    "process_name":   process,
                    "command_line":   None,
                    "hostname":       host,
                    "domain":         None,
                    "log_source":     "linux_auth",
                    "raw":            line,
                })
            except Exception as e:
                logger.warning("Auth parser: error on line %d: %s", lineno, e)
                continue

    return events
