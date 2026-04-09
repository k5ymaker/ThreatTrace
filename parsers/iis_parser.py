"""
IIS W3C Extended Log Format Parser
Dynamically reads #Fields header to map columns.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Mapping from W3C field names to normalized event keys
W3C_FIELD_MAP = {
    "date":             "date",
    "time":             "time",
    "s-ip":             "dest_ip",
    "cs-method":        "method",
    "cs-uri-stem":      "url_stem",
    "cs-uri-query":     "url_query",
    "s-port":           "dest_port",
    "cs-username":      "username",
    "c-ip":             "source_ip",
    "cs(user-agent)":   "user_agent",
    "cs(referer)":      "referer",
    "sc-status":        "status_code",
    "sc-substatus":     "sc_substatus",
    "sc-win32-status":  "sc_win32_status",
    "sc-bytes":         "bytes_sent",
    "cs-bytes":         "bytes_recv",
    "time-taken":       "time_taken",
    "s-sitename":       "sitename",
    "s-computername":   "hostname",
    "cs-host":          "host_header",
    "cs-version":       "protocol",
}


def _safe_int(val: str) -> Optional[int]:
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _parse_timestamp(date_str: str, time_str: str) -> str:
    """Combine IIS date and time fields into ISO 8601 UTC."""
    try:
        raw = f"{date_str} {time_str}"
        dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return f"{date_str}T{time_str}Z"


def parse(file_path: str) -> list:
    """Parse IIS W3C Extended Log Format file."""
    events = []
    fields = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("IIS parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("IIS parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n\r")
            if not line:
                continue

            # Comment lines
            if line.startswith("#"):
                if line.lower().startswith("#fields:"):
                    # Parse fields header
                    raw_fields = line[len("#fields:"):].strip().split()
                    fields = [f.lower() for f in raw_fields]
                # Skip #Version, #Software, #Date lines
                continue

            if not fields:
                logger.debug("IIS parser: no #Fields header yet at line %d", lineno)
                continue

            parts = line.split(" ")
            if len(parts) != len(fields):
                logger.debug(
                    "IIS parser: field count mismatch at line %d "
                    "(expected %d, got %d)", lineno, len(fields), len(parts)
                )
                continue

            try:
                row = dict(zip(fields, parts))

                # Build normalized record
                mapped = {}
                for w3c_key, norm_key in W3C_FIELD_MAP.items():
                    if w3c_key in row:
                        mapped[norm_key] = row[w3c_key]

                # Timestamp
                date_val = mapped.get("date", "")
                time_val = mapped.get("time", "")
                timestamp = _parse_timestamp(date_val, time_val) if date_val and time_val else None

                method      = mapped.get("method")
                url_stem    = mapped.get("url_stem", "")
                url_query   = mapped.get("url_query", "")
                url         = url_stem + ("?" + url_query if url_query and url_query != "-" else "")
                status_code = _safe_int(mapped.get("status_code"))
                username    = mapped.get("username")
                source_ip   = mapped.get("source_ip")
                dest_ip     = mapped.get("dest_ip")
                dest_port   = _safe_int(mapped.get("dest_port"))
                user_agent  = mapped.get("user_agent")
                bytes_sent  = _safe_int(mapped.get("bytes_sent"))
                hostname    = mapped.get("hostname")
                protocol    = mapped.get("protocol")

                event_name = f"IIS {method or 'UNKNOWN'} {status_code or 'UNKNOWN'}"

                events.append({
                    "timestamp":      timestamp,
                    "source_ip":      source_ip if source_ip and source_ip != "-" else None,
                    "dest_ip":        dest_ip if dest_ip and dest_ip != "-" else None,
                    "source_port":    None,
                    "dest_port":      dest_port,
                    "username":       username if username and username != "-" else None,
                    "user_agent":     user_agent if user_agent and user_agent != "-" else None,
                    "method":         method if method and method != "-" else None,
                    "url":            url if url else None,
                    "status_code":    status_code,
                    "bytes_sent":     bytes_sent,
                    "protocol":       protocol if protocol and protocol != "-" else None,
                    "action":         None,
                    "event_id":       None,
                    "event_name":     event_name,
                    "event_category": "Web Request",
                    "process_name":   None,
                    "command_line":   None,
                    "hostname":       hostname if hostname and hostname != "-" else None,
                    "domain":         None,
                    "log_source":     "iis",
                    "raw":            line,
                })
            except Exception as e:
                logger.warning("IIS parser: error on line %d: %s", lineno, e)
                continue

    return events
