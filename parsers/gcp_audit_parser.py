"""
GCP Cloud Audit Log Parser
Parses GCP Cloud Audit Log JSON (array or newline-delimited JSON).
"""

import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _get_nested(d, *keys, default=None):
    """Safely traverse nested dict keys."""
    cur = d
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def _normalize_record(rec: dict) -> dict:
    """Convert a single GCP audit log record to a normalized event dict."""
    proto = rec.get("protoPayload") or {}
    resource = rec.get("resource") or {}
    resource_labels = resource.get("labels") or {}

    event_name    = proto.get("methodName")
    domain        = proto.get("serviceName")
    username      = _get_nested(proto, "authenticationInfo", "principalEmail")
    source_ip     = _get_nested(proto, "requestMetadata", "callerIp")
    user_agent    = _get_nested(proto, "requestMetadata", "callerUserAgent")
    status_code   = _get_nested(proto, "status", "code")
    event_category = resource.get("type", "GCP")

    # action: success if status code is 0 or absent
    if status_code is None or status_code == 0:
        action = "success"
    else:
        action = "failure"

    return {
        "timestamp":        rec.get("timestamp"),
        "source_ip":        source_ip,
        "dest_ip":          None,
        "source_port":      None,
        "dest_port":        None,
        "username":         username,
        "user_agent":       user_agent,
        "method":           None,
        "url":              None,
        "status_code":      status_code,
        "bytes_sent":       None,
        "protocol":         None,
        "action":           action,
        "event_id":         rec.get("insertId"),
        "event_name":       event_name,
        "event_category":   event_category,
        "process_name":     None,
        "command_line":     None,
        "hostname":         None,
        "domain":           domain,
        "log_source":       "gcp_audit",
        # Extra GCP fields
        "log_name":         rec.get("logName"),
        "severity":         rec.get("severity"),
        "resource_labels":  resource_labels,
        "authorization_info": proto.get("authorizationInfo"),
        "raw":              json.dumps(rec)[:500],
    }


def parse(file_path: str) -> list:
    """Parse GCP Cloud Audit Log file. Returns list of normalized event dicts."""
    events = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("GCP Audit parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("GCP Audit parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        content = fh.read()

    # Try full JSON first
    try:
        data = json.loads(content)
        records = data if isinstance(data, list) else [data]
        for rec in records:
            try:
                events.append(_normalize_record(rec))
            except Exception as e:
                logger.warning("GCP Audit parser: error processing record: %s", e)
        return events
    except json.JSONDecodeError:
        pass

    # Fall back to newline-delimited JSON
    for lineno, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            events.append(_normalize_record(rec))
        except json.JSONDecodeError:
            logger.debug("GCP Audit parser: skipping non-JSON line %d", lineno)
        except Exception as e:
            logger.warning("GCP Audit parser: error on line %d: %s", lineno, e)

    return events
