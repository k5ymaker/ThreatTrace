"""
Linux Syslog Parser
Supports RFC3164 and RFC5424 syslog formats.
"""

import re
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# RFC3164: Jan 15 03:42:17 hostname process[pid]: message
RFC3164_PATTERN = re.compile(
    r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\w[\w/-]*)(?:\[(\d+)\])?: (.+)$'
)

# RFC5424: <priority>1 timestamp hostname app-name procid msgid structured-data msg
RFC5424_PATTERN = re.compile(
    r'^<\d+>1 (\S+) (\S+) (\S+) (\S+) .+ (.+)$'
)

# RFC3164 timestamp has no year; assume current year
RFC3164_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_rfc3164_timestamp(ts: str) -> str:
    """Convert 'Jan 15 03:42:17' to ISO 8601."""
    try:
        from datetime import datetime as dt_cls
        parts = ts.split()
        if len(parts) == 3:
            month = RFC3164_MONTHS.get(parts[0], 1)
            day   = int(parts[1])
            hms   = parts[2].split(":")
            h, m, s = int(hms[0]), int(hms[1]), int(hms[2])
            year  = datetime.utcnow().year
            d = dt_cls(year, month, day, h, m, s, tzinfo=timezone.utc)
            return d.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        pass
    return ts


def _parse_rfc5424_timestamp(ts: str) -> str:
    """Convert RFC5424 timestamp to ISO 8601 UTC."""
    try:
        ts = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ts


def _classify_event(process: str, message: str) -> tuple:
    """Return (event_name, event_category) from process and message."""
    proc_lower = process.lower()
    msg_lower  = message.lower()

    if "kernel" in proc_lower and "oom" in msg_lower:
        return ("Kernel OOM Kill", "System")
    if proc_lower in ("cron", "crond") or "cron" in proc_lower:
        return ("Cron Job Executed", "System")
    if "systemd" in proc_lower:
        if "started" in msg_lower:
            return ("Service Started", "System")
        if "stopped" in msg_lower or "stopping" in msg_lower:
            return ("Service Stopped", "System")
    if "su:" in message or proc_lower == "su":
        return ("User Switch (su)", "System")
    return ("Syslog Event", "System")


def parse(file_path: str) -> list:
    """Parse syslog file (RFC3164 or RFC5424). Returns normalized event dicts."""
    events = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("Syslog parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("Syslog parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n\r")
            if not line:
                continue

            event = None

            # Try RFC3164
            m3164 = RFC3164_PATTERN.match(line)
            if m3164:
                ts_raw  = m3164.group(1)
                host    = m3164.group(2)
                process = m3164.group(3)
                pid     = m3164.group(4)
                message = m3164.group(5)

                event_name, event_category = _classify_event(process, message)
                timestamp = _parse_rfc3164_timestamp(ts_raw)

                event = {
                    "timestamp":      timestamp,
                    "source_ip":      None,
                    "dest_ip":        None,
                    "source_port":    None,
                    "dest_port":      None,
                    "username":       None,
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
                    "log_source":     "linux_syslog",
                    "raw":            line,
                }

            else:
                # Try RFC5424
                m5424 = RFC5424_PATTERN.match(line)
                if m5424:
                    ts_raw  = m5424.group(1)
                    host    = m5424.group(2)
                    app     = m5424.group(3)
                    procid  = m5424.group(4)
                    message = m5424.group(5)

                    event_name, event_category = _classify_event(app, message)
                    timestamp = _parse_rfc5424_timestamp(ts_raw)

                    event = {
                        "timestamp":      timestamp,
                        "source_ip":      None,
                        "dest_ip":        None,
                        "source_port":    None,
                        "dest_port":      None,
                        "username":       None,
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
                        "process_name":   app if app != "-" else None,
                        "command_line":   None,
                        "hostname":       host if host != "-" else None,
                        "domain":         None,
                        "log_source":     "linux_syslog",
                        "raw":            line,
                    }
                else:
                    logger.debug("Syslog parser: no match at line %d", lineno)
                    continue

            if event:
                events.append(event)

    return events
