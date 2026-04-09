"""
Okta System Log Parser
Parses Okta System Log JSON (array or newline-delimited JSON).
"""

import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# eventType prefix -> event_category
_CATEGORY_MAP = {
    "user":   "User",
    "app":    "Application",
    "system": "System",
    "policy": "Policy",
    "group":  "Group",
}


def _event_category(event_type: Optional[str]) -> str:
    if not event_type:
        return "Okta"
    for prefix, cat in _CATEGORY_MAP.items():
        if event_type.startswith(prefix):
            return cat
    return "Okta"


def _get_nested(d, *keys, default=None):
    cur = d
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def _normalize_record(rec: dict) -> dict:
    """Convert a single Okta system log event to a normalized event dict."""
    event_type = rec.get("eventType")
    actor      = rec.get("actor") or {}
    client     = rec.get("client") or {}
    outcome    = rec.get("outcome") or {}

    username   = actor.get("alternateId") or actor.get("displayName")
    source_ip  = _get_nested(client, "ipAddress")
    user_agent = _get_nested(client, "userAgent", "rawUserAgent")
    action     = outcome.get("result")
    severity   = rec.get("severity")

    return {
        "timestamp":        rec.get("published"),
        "source_ip":        source_ip,
        "dest_ip":          None,
        "source_port":      None,
        "dest_port":        None,
        "username":         username,
        "user_agent":       user_agent,
        "method":           None,
        "url":              None,
        "status_code":      None,
        "bytes_sent":       None,
        "protocol":         None,
        "action":           action,
        "event_id":         rec.get("uuid"),
        "event_name":       event_type,
        "event_category":   _event_category(event_type),
        "process_name":     None,
        "command_line":     None,
        "hostname":         None,
        "domain":           None,
        "log_source":       "okta",
        # Extra Okta fields
        "display_message":  rec.get("displayMessage"),
        "severity":         severity,
        "actor_name":       actor.get("displayName"),
        "outcome_reason":   outcome.get("reason"),
        "target":           rec.get("target"),
        "auth_context":     rec.get("authenticationContext"),
        "security_context": rec.get("securityContext"),
        "raw":              json.dumps(rec)[:500],
    }


def parse(file_path: str) -> list:
    """Parse Okta System Log file. Returns list of normalized event dicts."""
    events = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("Okta parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("Okta parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        content = fh.read()

    # Try full JSON array first
    try:
        data = json.loads(content)
        records = data if isinstance(data, list) else [data]
        for rec in records:
            try:
                events.append(_normalize_record(rec))
            except Exception as e:
                logger.warning("Okta parser: error processing record: %s", e)
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
            logger.debug("Okta parser: skipping non-JSON line %d", lineno)
        except Exception as e:
            logger.warning("Okta parser: error on line %d: %s", lineno, e)

    return events
