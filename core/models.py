"""
core/models.py — Shared data models for ThreatTrace.

Every module imports from here — no inline dicts passed between layers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Core data-classes
# ---------------------------------------------------------------------------

@dataclass
class LogRecord:
    """Normalised representation of a single log event from any source."""

    raw_line: str
    log_type: str
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    username: Optional[str] = None
    action: Optional[str] = None
    status_code: Optional[int] = None
    bytes_transferred: Optional[int] = None
    uri: Optional[str] = None
    user_agent: Optional[str] = None
    hostname: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    event_id: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)
    line_number: int = 0


@dataclass
class Alert:
    """A single detection finding from YARA, Sigma, or a statistical module."""

    rule_name: str
    rule_type: str           # "YARA" | "SIGMA" | "STATISTICAL"
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: str          # HIGH | MEDIUM | LOW
    description: str
    mitre_tactic: str
    mitre_technique: str
    matched_line: str
    line_number: int
    timestamp: Optional[datetime]
    iocs: List[str]
    recommended_action: str
    log_type: str


@dataclass
class StatResult:
    """Output of a single analytics module run."""

    module: str              # "baseline" | "frequency" | "beaconing" | "topn" | "timeline"
    log_type: str
    title: str
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW | INFO
    description: str
    data: Dict[str, Any]     # Module-specific structured output
    anomalies: List[Dict]    # Flagged anomalous records
    generated_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict."""

        def _default(obj: Any) -> Any:
            if isinstance(obj, datetime):
                return obj.isoformat()
            return str(obj)

        import json
        raw = asdict(self)
        # Round-trip through JSON to coerce all non-serialisable nested types
        return json.loads(json.dumps(raw, default=_default))


@dataclass
class AnalysisReport:
    """Top-level container for a completed ThreatTrace analysis run."""

    log_type: str
    log_source_path: str
    total_lines: int
    parsed_lines: int
    skipped_lines: int
    analysis_duration_seconds: float
    alerts: List[Alert]
    stat_results: List[StatResult]
    generated_at: datetime
    analyst_notes: str = ""


# ---------------------------------------------------------------------------
# dict → LogRecord conversion
# ---------------------------------------------------------------------------

_KNOWN_KEYS: frozenset = frozenset({
    "raw", "raw_line", "log_type", "timestamp",
    "source_ip", "src_ip", "client_ip", "remote_addr", "ip", "remote_host",
    "dest_ip", "dst_ip", "destination_ip", "server_ip",
    "source_port", "src_port", "sport",
    "dest_port", "dst_port", "dport", "port",
    "username", "user", "user_name", "account_name", "subject_user",
    "subject_username", "target_user", "login",
    "action", "method", "request_method",
    "status_code", "status", "http_status", "sc_status",
    "bytes_transferred", "bytes", "size", "bytes_sent",
    "content_length", "cs_bytes", "sc_bytes", "body_bytes_sent",
    "uri", "url", "path", "request_path", "cs_uri_stem", "request",
    "user_agent", "ua", "cs_user_agent", "http_user_agent", "agent",
    "hostname", "host", "computer_name", "workstation", "machine",
    "process_name", "process", "comm", "image_name", "image",
    "command_line", "cmdline", "CommandLine", "cmd",
    "event_id", "EventID", "id", "event_id_str",
    "line_number", "source_file", "source_type", "fields",
})

_TS_FORMATS: Tuple[str, ...] = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",   # Apache CLF
)

_RE_EPOCH_10 = re.compile(r"^\d{10}$")
_RE_EPOCH_13 = re.compile(r"^\d{13}$")


def _int_or_none(val: Any) -> Optional[int]:
    if val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _parse_ts(raw: Any) -> Optional[datetime]:
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return raw
    s = str(raw).strip()
    # Unix epoch (seconds)
    if _RE_EPOCH_10.match(s):
        try:
            return datetime.fromtimestamp(int(s), tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            pass
    # Unix epoch (milliseconds)
    if _RE_EPOCH_13.match(s):
        try:
            return datetime.fromtimestamp(int(s) / 1000, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            pass
    s_clean = s.replace("Z", "+00:00")
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(s_clean, fmt)
        except ValueError:
            pass
    # dateutil fallback
    try:
        from dateutil import parser as _dp
        return _dp.parse(s)
    except Exception:
        pass
    return None


def dict_to_log_record(event: Dict[str, Any], idx: int = 0) -> LogRecord:
    """
    Convert a normalised event dict produced by core.parser_router into a LogRecord.

    Handles all field-name variants emitted by the 24 parser classes.
    """
    g = event.get  # shorthand

    raw = g("raw") or g("raw_line") or ""
    log_type = g("log_type") or "unknown"

    # Timestamp
    ts = _parse_ts(g("timestamp"))

    # IP addresses
    src_ip: Optional[str] = (
        g("source_ip") or g("src_ip") or g("client_ip") or
        g("remote_addr") or g("remote_host") or g("ip")
    )
    dst_ip: Optional[str] = (
        g("dest_ip") or g("dst_ip") or
        g("destination_ip") or g("server_ip")
    )

    # Ports
    src_port = _int_or_none(g("source_port") or g("src_port") or g("sport"))
    dst_port = _int_or_none(g("dest_port") or g("dst_port") or g("dport") or g("port"))

    # Username
    username: Optional[str] = (
        g("username") or g("user") or g("user_name") or
        g("account_name") or g("subject_user") or
        g("subject_username") or g("target_user") or g("login")
    )

    # Action / method
    action: Optional[str] = g("action") or g("method") or g("request_method")

    # HTTP / status
    status = _int_or_none(g("status_code") or g("status") or g("http_status") or g("sc_status"))

    # Bytes
    bytes_val = _int_or_none(
        g("bytes_transferred") or g("bytes") or g("size") or
        g("bytes_sent") or g("content_length") or
        g("cs_bytes") or g("sc_bytes") or g("body_bytes_sent")
    )

    # URI
    uri: Optional[str] = (
        g("uri") or g("url") or g("path") or
        g("request_path") or g("cs_uri_stem") or g("request")
    )

    # User-Agent
    ua: Optional[str] = (
        g("user_agent") or g("ua") or
        g("cs_user_agent") or g("http_user_agent") or g("agent")
    )

    # Hostname
    hostname: Optional[str] = (
        g("hostname") or g("host") or
        g("computer_name") or g("workstation") or g("machine")
    )

    # Process
    process: Optional[str] = (
        g("process_name") or g("process") or
        g("comm") or g("image_name") or g("image")
    )

    # Command line
    cmdline: Optional[str] = g("command_line") or g("cmdline") or g("CommandLine") or g("cmd")

    # Event ID
    eid = g("event_id") or g("EventID") or g("id") or g("event_id_str")
    event_id: Optional[str] = str(eid) if eid is not None else None

    # Flatten nested "fields" dict into extra
    extra: Dict[str, Any] = {}
    nested = g("fields")
    if isinstance(nested, dict):
        extra.update(nested)
    for k, v in event.items():
        if k not in _KNOWN_KEYS and v is not None:
            extra[k] = v

    return LogRecord(
        raw_line=str(raw),
        log_type=log_type,
        timestamp=ts,
        source_ip=src_ip or None,
        dest_ip=dst_ip or None,
        source_port=src_port,
        dest_port=dst_port,
        username=username or None,
        action=action or None,
        status_code=status,
        bytes_transferred=bytes_val,
        uri=uri or None,
        user_agent=ua or None,
        hostname=hostname or None,
        process_name=process or None,
        command_line=cmdline or None,
        event_id=event_id,
        extra=extra,
        line_number=_int_or_none(g("line_number")) or idx,
    )
