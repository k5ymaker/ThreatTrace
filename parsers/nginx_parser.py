"""
Nginx Access Log Parser
Supports both default combined format and JSON-formatted nginx logs.
Auto-detects format from first non-empty line.
"""

import re
import json
import gzip
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Combined Log Format (same as Apache)
LOG_PATTERN = re.compile(
    r'^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\S+)'
    r'(?: "([^"]*)" "([^"]*)")?'
)

NGINX_DATE_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_timestamp(raw_ts: str) -> str:
    """Convert nginx timestamp to ISO 8601 UTC."""
    try:
        dt = datetime.strptime(raw_ts, NGINX_DATE_FORMAT)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        # Try ISO format (JSON logs)
        try:
            raw_ts = raw_ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(raw_ts)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return raw_ts


def _safe_int(val) -> Optional[int]:
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _open_file(file_path: str):
    if file_path.endswith(".gz"):
        return gzip.open(file_path, "rt", encoding="utf-8", errors="replace")
    return open(file_path, "r", encoding="utf-8", errors="replace")


def _parse_json_line(line: str, raw: str) -> Optional[dict]:
    """Parse JSON-format nginx log line."""
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    # Handle various nginx JSON field names
    time_local  = obj.get("time_local") or obj.get("time_iso8601") or obj.get("time") or ""
    remote_addr = obj.get("remote_addr") or obj.get("client") or None
    remote_user = obj.get("remote_user") or None
    request     = obj.get("request") or ""
    status      = obj.get("status") or obj.get("response_code") or None
    body_bytes  = obj.get("body_bytes_sent") or obj.get("bytes_sent") or None
    http_referer= obj.get("http_referer") or obj.get("referer") or None
    http_ua     = obj.get("http_user_agent") or obj.get("user_agent") or None

    # upstream fields
    upstream_addr        = obj.get("upstream_addr")
    upstream_status      = obj.get("upstream_status")
    upstream_response_time = obj.get("upstream_response_time")

    method = url = protocol = None
    if request:
        parts = request.split(" ", 2)
        if len(parts) == 3:
            method, url, protocol = parts
        elif len(parts) == 2:
            method, url = parts

    if not method:
        method = obj.get("method") or obj.get("verb")
    if not url:
        url = obj.get("uri") or obj.get("path")

    status_int = _safe_int(status)
    event_name = f"HTTP {method or 'UNKNOWN'} {status or 'UNKNOWN'}"

    return {
        "timestamp":      _parse_timestamp(time_local),
        "source_ip":      remote_addr,
        "dest_ip":        upstream_addr,
        "source_port":    None,
        "dest_port":      None,
        "username":       remote_user if remote_user and remote_user != "-" else None,
        "user_agent":     http_ua if http_ua and http_ua != "-" else None,
        "method":         method,
        "url":            url,
        "status_code":    status_int,
        "bytes_sent":     _safe_int(body_bytes),
        "protocol":       protocol,
        "action":         None,
        "event_id":       None,
        "event_name":     event_name,
        "event_category": "Web Request",
        "process_name":   None,
        "command_line":   None,
        "hostname":       obj.get("host") or obj.get("server_name"),
        "domain":         None,
        "log_source":     "nginx",
        "raw":            raw,
    }


def _parse_combined_line(line: str) -> Optional[dict]:
    """Parse combined-format nginx log line."""
    m = LOG_PATTERN.match(line)
    if not m:
        return None

    source_ip     = m.group(1)
    username      = m.group(2)
    timestamp_raw = m.group(3)
    method        = m.group(4)
    url           = m.group(5)
    protocol      = m.group(6)
    status_code   = m.group(7)
    bytes_sent    = m.group(8)
    user_agent    = m.group(10)

    status_int = _safe_int(status_code)
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
        "status_code":    status_int,
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
        "log_source":     "nginx",
        "raw":            line,
    }


def _detect_json(line: str) -> bool:
    """Return True if the line looks like JSON."""
    stripped = line.strip()
    return stripped.startswith("{") or stripped.startswith("[")


def parse(file_path: str) -> list:
    """Parse nginx access log. Auto-detects combined vs JSON format."""
    events = []
    try:
        fh = _open_file(file_path)
    except FileNotFoundError:
        logger.error("Nginx parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("Nginx parser: failed to open %s: %s", file_path, e)
        return events

    json_mode = None  # None = not yet decided

    with fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n\r")
            if not line:
                continue

            # Auto-detect format from first meaningful line
            if json_mode is None:
                json_mode = _detect_json(line)

            try:
                if json_mode:
                    event = _parse_json_line(line, line)
                    if event is None:
                        # Fallback to combined
                        event = _parse_combined_line(line)
                else:
                    event = _parse_combined_line(line)
                    if event is None:
                        # Try JSON fallback
                        event = _parse_json_line(line, line)

                if event:
                    events.append(event)
                else:
                    logger.debug("Nginx parser: no match at line %d", lineno)
            except Exception as e:
                logger.warning("Nginx parser: error on line %d: %s", lineno, e)
                continue

    return events
