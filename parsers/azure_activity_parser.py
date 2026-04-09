"""
Azure Activity Log Parser
Parses Azure Activity Log JSON (array or newline-delimited JSON).
"""

import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _get_nested(d: dict, *keys, default=None):
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
    """Convert a single Azure activity log record to a normalized event dict."""
    # event_name: prefer localizedValue, fall back to value
    op = rec.get("operationName") or {}
    if isinstance(op, dict):
        event_name = op.get("localizedValue") or op.get("value")
    else:
        event_name = str(op)

    # event_category from resourceType
    resource_type = rec.get("resourceType")
    if isinstance(resource_type, dict):
        event_category = resource_type.get("localizedValue") or resource_type.get("value") or "Azure"
    else:
        event_category = str(resource_type) if resource_type else "Azure"

    # action from status.value
    status = rec.get("status") or {}
    if isinstance(status, dict):
        action = (status.get("value") or "").lower()
    else:
        action = str(status).lower() if status else None

    # source IP - try callerIpAddress first, then identity claims
    source_ip = rec.get("callerIpAddress")
    if not source_ip:
        source_ip = _get_nested(rec, "identity", "claims", "ipaddr")

    # username - prefer caller field
    username = rec.get("caller")

    properties = rec.get("properties") or {}

    return {
        "timestamp":        rec.get("time"),
        "source_ip":        source_ip,
        "dest_ip":          None,
        "source_port":      None,
        "dest_port":        None,
        "username":         username,
        "user_agent":       None,
        "method":           None,
        "url":              None,
        "status_code":      None,
        "bytes_sent":       None,
        "protocol":         None,
        "action":           action,
        "event_id":         rec.get("eventDataId"),
        "event_name":       event_name,
        "event_category":   event_category,
        "process_name":     None,
        "command_line":     None,
        "hostname":         None,
        "domain":           None,
        "log_source":       "azure_activity",
        # Extra Azure fields
        "resource_id":      rec.get("resourceId"),
        "tenant_id":        rec.get("tenantId"),
        "subscription_id":  rec.get("subscriptionId"),
        "properties":       properties,
        "raw":              json.dumps(rec)[:500],
    }


def parse(file_path: str) -> list:
    """Parse Azure Activity Log file. Returns list of normalized event dicts."""
    events = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("Azure Activity parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("Azure Activity parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        content = fh.read()

    # Try full JSON first (array format)
    try:
        data = json.loads(content)
        records = data if isinstance(data, list) else [data]
        for rec in records:
            try:
                events.append(_normalize_record(rec))
            except Exception as e:
                logger.warning("Azure Activity parser: error processing record: %s", e)
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
            logger.debug("Azure Activity parser: skipping non-JSON line %d", lineno)
        except Exception as e:
            logger.warning("Azure Activity parser: error on line %d: %s", lineno, e)

    return events
