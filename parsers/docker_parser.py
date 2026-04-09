"""
Docker Log Parser
Supports Docker daemon JSON logs and docker events text format.
"""

import re
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Docker daemon JSON log format
# {"log": "...", "stream": "stdout", "time": "2025-01-15T03:11:02.123456789Z"}
# --------------------------------------------------------------------------

_CONTAINER_EVENTS = [
    ("container create",   "Container Created"),
    ("container start",    "Container Started"),
    ("container stop",     "Container Stopped"),
    ("container kill",     "Container Stopped"),
    ("container remove",   "Container Removed"),
    ("container die",      "Container Stopped"),
    ("container restart",  "Container Restarted"),
    ("container pause",    "Container Paused"),
    ("container unpause",  "Container Resumed"),
    ("exec_create",        "Container Exec"),
    ("exec_start",         "Container Exec"),
    ("pull",               "Image Pulled"),
    ("push",               "Image Pushed"),
    ("create network",     "Network Created"),
    ("connect network",    "Network Connected"),
    ("disconnect network", "Network Disconnected"),
    ("mount",              "Volume Mounted"),
    ("create volume",      "Volume Created"),
    ("destroy volume",     "Volume Destroyed"),
]


def _event_name_from_log(log_line: str) -> str:
    ll = log_line.lower()
    for pattern, name in _CONTAINER_EVENTS:
        if pattern in ll:
            return name
    return "Docker Event"


def _parse_json_log_line(line: str) -> Optional[dict]:
    """Parse a Docker daemon JSON log line."""
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None

    if not isinstance(rec, dict):
        return None

    log_text  = rec.get("log", "")
    timestamp = rec.get("time")
    stream    = rec.get("stream", "stdout")

    if not log_text:
        return None

    event_name = _event_name_from_log(log_text)

    return {
        "timestamp":        timestamp,
        "source_ip":        None,
        "dest_ip":          None,
        "source_port":      None,
        "dest_port":        None,
        "username":         None,
        "user_agent":       None,
        "method":           None,
        "url":              None,
        "status_code":      None,
        "bytes_sent":       None,
        "protocol":         None,
        "action":           None,
        "event_id":         None,
        "event_name":       event_name,
        "event_category":   "Container",
        "process_name":     None,
        "command_line":     log_text.strip(),
        "hostname":         None,
        "domain":           None,
        "log_source":       "docker",
        "stream":           stream,
        "raw":              line[:500],
    }


# --------------------------------------------------------------------------
# Docker events text format
# 2025-01-15T03:11:02.123456789Z container start abc123def456 (image=ubuntu:20.04, name=mycontainer)
# --------------------------------------------------------------------------
_DOCKER_EVENT_LINE = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z?)\s+'
    r'(\w+)\s+'             # type (container, image, network, volume)
    r'(\w+)\s+'             # action
    r'([a-f0-9]{12,64})\s+' # id
    r'\((.+)\)$'            # attributes
)

# Also handle simpler format: timestamp  type  action  id  (attrs)
_DOCKER_EVENT_SIMPLE = re.compile(
    r'^(\S+)\s+(\w+)\s+(\w+)\s+(\S+)'
)


def _action_to_event_name(event_type: str, action: str) -> str:
    key = f"{event_type} {action}".lower()
    for pattern, name in _CONTAINER_EVENTS:
        if key == pattern or action.lower() in pattern:
            return name
    return f"Docker {event_type.title()} {action.title()}"


def _parse_docker_event_line(line: str) -> Optional[dict]:
    """Parse docker events text format."""
    m = _DOCKER_EVENT_LINE.match(line)
    if not m:
        return None

    timestamp    = m.group(1)
    event_type   = m.group(2)
    action       = m.group(3)
    container_id = m.group(4)
    attrs_raw    = m.group(5)

    # Parse attributes: key=value pairs
    attrs = {}
    for pair in re.findall(r'(\w+)=([^,)]+)', attrs_raw):
        attrs[pair[0]] = pair[1].strip()

    image      = attrs.get("image")
    event_name = _action_to_event_name(event_type, action)

    return {
        "timestamp":        timestamp,
        "source_ip":        None,
        "dest_ip":          None,
        "source_port":      None,
        "dest_port":        None,
        "username":         None,
        "user_agent":       None,
        "method":           None,
        "url":              None,
        "status_code":      None,
        "bytes_sent":       None,
        "protocol":         None,
        "action":           action,
        "event_id":         container_id,
        "event_name":       event_name,
        "event_category":   "Container",
        "process_name":     None,
        "command_line":     None,
        "hostname":         None,
        "domain":           None,
        "log_source":       "docker",
        "container_id":     container_id,
        "image":            image,
        "container_name":   attrs.get("name"),
        "event_type":       event_type,
        "raw":              line[:500],
    }


def parse(file_path: str) -> list:
    """Parse Docker log file (JSON daemon logs or events text). Returns normalized event dicts."""
    events = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("Docker parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("Docker parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n\r")
            if not line:
                continue
            try:
                # Try JSON format first
                rec = _parse_json_log_line(line)
                if rec is None:
                    # Try docker events text format
                    rec = _parse_docker_event_line(line)
                if rec:
                    events.append(rec)
            except Exception as e:
                logger.warning("Docker parser: error on line %d: %s", lineno, e)

    return events
