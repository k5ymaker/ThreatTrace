"""
Kubernetes API Server Audit Log Parser
Parses Kubernetes audit log JSON (one JSON object per line).
"""

import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# (verb, resource) pattern -> event_name
# Checked in order; first match wins.
_EVENT_RULES = [
    # Secret access
    ({"get", "list", "watch"},  "secrets",                  "K8s Secret Accessed"),
    # Pod operations
    ({"create"},                "pods",                     "K8s Pod Created"),
    ({"delete", "deletecollection"}, "pods",                "K8s Pod Deleted"),
    # ConfigMap changes
    ({"update", "patch"},       "configmaps",               "K8s ConfigMap Modified"),
    # RBAC changes
    ({"create", "update", "patch"}, "clusterrolebindings",  "K8s RBAC Change"),
    ({"create", "update", "patch"}, "rolebindings",         "K8s RBAC Change"),
    # Exec into pod
    ({"create"},                "pods/exec",                "K8s Exec into Pod"),
    # Service account token
    ({"create"},                "serviceaccounts/token",    "K8s Service Account Token Request"),
    # Node operations
    ({"get", "list"},           "nodes",                    "K8s Node Enumeration"),
    # Namespace operations
    ({"create"},                "namespaces",               "K8s Namespace Created"),
    ({"delete"},                "namespaces",               "K8s Namespace Deleted"),
    # Deployment operations
    ({"create"},                "deployments",              "K8s Deployment Created"),
    ({"delete"},                "deployments",              "K8s Deployment Deleted"),
    # DaemonSet
    ({"create"},                "daemonsets",               "K8s DaemonSet Created"),
    # Service
    ({"create"},                "services",                 "K8s Service Created"),
    # PersistentVolume
    ({"create"},                "persistentvolumes",        "K8s PersistentVolume Created"),
]


def _determine_event_name(verb: str, resource: str, status_code: Optional[int]) -> str:
    """Determine event name from verb, resource and status code."""
    # Auth failures override everything
    if status_code in (401, 403):
        return "K8s API Auth Failure"

    verb_lower     = (verb or "").lower()
    resource_lower = (resource or "").lower()

    for verbs_set, res_pattern, event_name in _EVENT_RULES:
        if verb_lower in verbs_set and resource_lower == res_pattern:
            return event_name

    # Default
    verb_title    = verb_lower.title() if verb_lower else "Unknown"
    resource_title = resource_lower.title() if resource_lower else "Resource"
    return f"K8s {verb_title} {resource_title}"


def _normalize_record(rec: dict) -> dict:
    """Convert a single K8s audit log record to normalized event dict."""
    obj_ref    = rec.get("objectRef") or {}
    user       = rec.get("user") or {}
    resp       = rec.get("responseStatus") or {}

    verb       = rec.get("verb")
    resource   = obj_ref.get("resource")
    namespace  = obj_ref.get("namespace")
    username   = user.get("username")
    user_agent = rec.get("userAgent")
    source_ips = rec.get("sourceIPs") or []
    source_ip  = source_ips[0] if source_ips else None
    status_code_raw = resp.get("code")
    try:
        status_code = int(status_code_raw) if status_code_raw is not None else None
    except (ValueError, TypeError):
        status_code = None

    method     = rec.get("requestURI", "").split("?")[0] if rec.get("requestURI") else None
    event_name = _determine_event_name(verb, resource, status_code)
    action     = "failure" if status_code and status_code >= 400 else "success"

    return {
        "timestamp":        rec.get("requestReceivedTimestamp") or rec.get("stageTimestamp"),
        "source_ip":        source_ip,
        "dest_ip":          None,
        "source_port":      None,
        "dest_port":        None,
        "username":         username,
        "user_agent":       user_agent,
        "method":           verb,
        "url":              rec.get("requestURI"),
        "status_code":      status_code,
        "bytes_sent":       None,
        "protocol":         None,
        "action":           action,
        "event_id":         rec.get("auditID"),
        "event_name":       event_name,
        "event_category":   "Kubernetes",
        "process_name":     None,
        "command_line":     None,
        "hostname":         None,
        "domain":           resource,
        "log_source":       "k8s",
        # Extra K8s fields
        "namespace":        namespace,
        "resource":         resource,
        "verb":             verb,
        "object_name":      obj_ref.get("name"),
        "api_version":      obj_ref.get("apiVersion"),
        "user_groups":      user.get("groups"),
        "stage":            rec.get("stage"),
        "request_object":   rec.get("requestObject"),
        "response_object":  rec.get("responseObject"),
        "raw":              json.dumps(rec)[:500],
    }


def parse(file_path: str) -> list:
    """Parse Kubernetes API server audit log. Returns list of normalized event dicts."""
    events = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("K8s parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("K8s parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                events.append(_normalize_record(rec))
            except json.JSONDecodeError:
                logger.debug("K8s parser: skipping non-JSON line %d", lineno)
            except Exception as e:
                logger.warning("K8s parser: error on line %d: %s", lineno, e)

    return events
