"""
Apache Access Log Parser
Supports Combined Log Format and Common Log Format.
Handles both plain text and .gz compressed files.
"""

import re
import gzip
import logging
import warnings
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

LOG_PATTERN = re.compile(
    r'^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\S+)'
    r'(?: "([^"]*)" "([^"]*)")?'
)

# Apache date format: 15/Jan/2025:03:42:17 +0000
APACHE_DATE_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_timestamp(raw_ts: str) -> str:
    """Convert Apache timestamp to ISO 8601 UTC."""
    try:
        dt = datetime.strptime(raw_ts, APACHE_DATE_FORMAT)
        dt_utc = dt.astimezone(timezone.utc)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return raw_ts


def _safe_int(val: str) -> Optional[int]:
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _open_file(file_path: str):
    """Open plain or gzip-compressed file, returning lines as strings."""
    if file_path.endswith(".gz"):
        return gzip.open(file_path, "rt", encoding="utf-8", errors="replace")
    return open(file_path, "r", encoding="utf-8", errors="replace")


def _make_event(
    source_ip, username, timestamp_raw, method, url, protocol,
    status_code, bytes_sent, referer, user_agent, raw_line
) -> dict:
    status = _safe_int(status_code)
    event_name = f"HTTP {method} {status_code}"
    return {
        "timestamp":      _parse_timestamp(timestamp_raw),
        "source_ip":      source_ip if source_ip != "-" else None,
        "dest_ip":        None,
        "source_port":    None,
        "dest_port":      None,
        "username":       username if username != "-" else None,
        "user_agent":     user_agent if user_agent and user_agent != "-" else None,
        "method":         method,
        "url":            url,
        "status_code":    status,
        "bytes_sent":     _safe_int(bytes_sent),
        "protocol":       protocol,
        "action":         None,
        "event_id":       None,
        "event_name":     event_name,
        "event_category": "Web Request",
        "process_name":   None,
        "command_line":   None,
        "hostname":       None,
        "domain":         None,
        "log_source":     "apache",
        "raw":            raw_line,
    }


def parse(file_path: str) -> list:
    """Parse Apache access log file. Returns list of normalized event dicts."""
    events = []
    try:
        fh = _open_file(file_path)
    except FileNotFoundError:
        logger.error("Apache parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("Apache parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n\r")
            if not line:
                continue
            # Skip multiline error log entries (start with [) gracefully
            if line.startswith("["):
                continue
            m = LOG_PATTERN.match(line)
            if not m:
                logger.debug("Apache parser: no match at line %d: %s", lineno, line[:120])
                continue
            try:
                source_ip    = m.group(1)
                username     = m.group(2)
                timestamp_raw= m.group(3)
                method       = m.group(4)
                url          = m.group(5)
                protocol     = m.group(6)
                status_code  = m.group(7)
                bytes_sent   = m.group(8)
                referer      = m.group(9)
                user_agent   = m.group(10)

                events.append(_make_event(
                    source_ip, username, timestamp_raw, method, url, protocol,
                    status_code, bytes_sent, referer, user_agent, line
                ))
            except Exception as e:
                logger.warning("Apache parser: error processing line %d: %s", lineno, e)
                continue

    return events
