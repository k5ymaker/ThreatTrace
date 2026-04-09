"""
analytics/topn.py — Top-N Reporter

Generates ranked frequency tables for all key dimensions per log type.
Also buckets events into time windows and ranks busiest periods.
Flags any single value that accounts for > highlight_threshold_pct of all events.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.models import LogRecord, StatResult

# ---------------------------------------------------------------------------
# Optional dependencies
# ---------------------------------------------------------------------------
try:
    import numpy as np
    _NP = True
except ImportError:
    _NP = False


# ---------------------------------------------------------------------------
# Field configuration
# ---------------------------------------------------------------------------

# (field_label, extractor)
_FIELD_CONFIG: Dict[str, List[Tuple[str, Callable]]] = {
    "apache": [
        ("source_ip",   lambda r: r.source_ip),
        ("uri",         lambda r: r.uri),
        ("user_agent",  lambda r: r.user_agent),
        ("status_code", lambda r: str(r.status_code) if r.status_code else None),
        ("method",      lambda r: r.action),
        ("referrer",    lambda r: r.extra.get("referrer") or r.extra.get("referer")),
    ],
    "nginx": [
        ("source_ip",   lambda r: r.source_ip),
        ("uri",         lambda r: r.uri),
        ("user_agent",  lambda r: r.user_agent),
        ("status_code", lambda r: str(r.status_code) if r.status_code else None),
        ("method",      lambda r: r.action),
    ],
    "iis": [
        ("source_ip",   lambda r: r.source_ip),
        ("uri",         lambda r: r.uri),
        ("user_agent",  lambda r: r.user_agent),
        ("status_code", lambda r: str(r.status_code) if r.status_code else None),
        ("method",      lambda r: r.action),
        ("username",    lambda r: r.username),
    ],
    "windows_evtx": [
        ("event_id",      lambda r: r.event_id),
        ("username",      lambda r: r.username),
        ("source_ip",     lambda r: r.source_ip),
        ("hostname",      lambda r: r.hostname),
        ("logon_type",    lambda r: str(r.extra.get("logon_type", "")) or None),
        ("process_name",  lambda r: r.process_name),
    ],
    "sysmon": [
        ("process_name",   lambda r: r.process_name),
        ("parent_process", lambda r: r.extra.get("parent_process") or r.extra.get("parent_image")),
        ("event_id",       lambda r: r.event_id),
        ("username",       lambda r: r.username),
        ("dest_ip",        lambda r: r.dest_ip),
        ("hostname",       lambda r: r.hostname),
    ],
    "auth_log": [
        ("username",   lambda r: r.username),
        ("source_ip",  lambda r: r.source_ip),
        ("action",     lambda r: r.action),
        ("hostname",   lambda r: r.hostname),
    ],
    "ssh": [
        ("username",   lambda r: r.username),
        ("source_ip",  lambda r: r.source_ip),
        ("action",     lambda r: r.action),
    ],
    "auditd": [
        ("username",     lambda r: r.username),
        ("process_name", lambda r: r.process_name),
        ("action",       lambda r: r.action),
        ("source_ip",    lambda r: r.source_ip),
        ("event_id",     lambda r: r.event_id),
    ],
    "cisco_asa": [
        ("source_ip",  lambda r: r.source_ip),
        ("dest_ip",    lambda r: r.dest_ip),
        ("dest_port",  lambda r: str(r.dest_port) if r.dest_port else None),
        ("action",     lambda r: r.action),
        ("protocol",   lambda r: r.extra.get("protocol")),
    ],
    "fortinet": [
        ("source_ip",  lambda r: r.source_ip),
        ("dest_ip",    lambda r: r.dest_ip),
        ("dest_port",  lambda r: str(r.dest_port) if r.dest_port else None),
        ("action",     lambda r: r.action),
    ],
    "palo_alto": [
        ("source_ip",  lambda r: r.source_ip),
        ("dest_ip",    lambda r: r.dest_ip),
        ("dest_port",  lambda r: str(r.dest_port) if r.dest_port else None),
        ("action",     lambda r: r.action),
    ],
    "pfsense": [
        ("source_ip",  lambda r: r.source_ip),
        ("dest_ip",    lambda r: r.dest_ip),
        ("dest_port",  lambda r: str(r.dest_port) if r.dest_port else None),
        ("action",     lambda r: r.action),
    ],
    "squid": [
        ("source_ip",     lambda r: r.source_ip),
        ("dest_ip",       lambda r: r.dest_ip),
        ("uri",           lambda r: r.uri),
        ("status_code",   lambda r: str(r.status_code) if r.status_code else None),
    ],
    "suricata": [
        ("source_ip",   lambda r: r.source_ip),
        ("dest_ip",     lambda r: r.dest_ip),
        ("dest_port",   lambda r: str(r.dest_port) if r.dest_port else None),
        ("action",      lambda r: r.action),
        ("event_id",    lambda r: r.event_id),
    ],
    "dns_bind": [
        ("source_ip",   lambda r: r.source_ip),
        ("uri",         lambda r: r.uri),
        ("action",      lambda r: r.action),
        ("status_code", lambda r: str(r.status_code) if r.status_code else None),
    ],
    "cloudtrail": [
        ("action",    lambda r: r.action),
        ("username",  lambda r: r.username),
        ("source_ip", lambda r: r.source_ip),
        ("hostname",  lambda r: r.hostname),
        ("error",     lambda r: r.extra.get("error_code") or r.extra.get("errorCode")),
        ("region",    lambda r: r.extra.get("aws_region") or r.extra.get("awsRegion")),
    ],
    "azure_activity": [
        ("action",      lambda r: r.action),
        ("username",    lambda r: r.username),
        ("source_ip",   lambda r: r.source_ip),
        ("resource",    lambda r: r.extra.get("resource_type") or r.extra.get("resourceType")),
    ],
    "gcp_audit": [
        ("action",    lambda r: r.action),
        ("username",  lambda r: r.username),
        ("source_ip", lambda r: r.source_ip),
    ],
}

_DEFAULT_FIELDS: List[Tuple[str, Callable]] = [
    ("source_ip",   lambda r: r.source_ip),
    ("username",    lambda r: r.username),
    ("action",      lambda r: r.action),
    ("dest_port",   lambda r: str(r.dest_port) if r.dest_port else None),
    ("status_code", lambda r: str(r.status_code) if r.status_code else None),
    ("event_id",    lambda r: r.event_id),
]

# Time-bucket sizes: (label, seconds_per_bucket)
_TIME_BUCKETS: List[Tuple[str, int]] = [
    ("1min",  60),
    ("5min",  300),
    ("1hour", 3600),
    ("1day",  86400),
]


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

class TopNReporter:
    """
    Ranked frequency tables + time-window analysis for every log type.
    """

    DEFAULT_CONFIG: Dict[str, Any] = {
        "top_n":                   10,
        "highlight_threshold_pct": 30.0,
        "include_percentage":      True,
        "include_cumulative_pct":  True,
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.cfg = {**self.DEFAULT_CONFIG, **(config or {})}

    # ------------------------------------------------------------------
    def run(self, records: List[LogRecord], log_type: str) -> StatResult:
        now = datetime.now(timezone.utc)

        if not records:
            return self._empty(log_type, now)

        total = len(records)
        fields = _FIELD_CONFIG.get(log_type, _DEFAULT_FIELDS)
        top_n  = self.cfg["top_n"]
        thresh = self.cfg["highlight_threshold_pct"]

        tables: Dict[str, List[Dict]] = {}
        flagged_any = False
        dominant_ip = ""
        dominant_uri = ""
        peak_hour = ""
        peak_hour_count = 0

        for field_name, extractor in fields:
            values: List[str] = []
            for r in records:
                try:
                    v = extractor(r)
                    if v is not None:
                        values.append(str(v))
                except Exception:
                    pass

            if not values:
                continue

            freq = Counter(values)
            ranked = freq.most_common(top_n)

            rows: List[Dict] = []
            cum = 0.0
            for rank, (val, cnt) in enumerate(ranked, 1):
                pct = cnt / total * 100
                cum += pct
                flagged = pct >= thresh
                if flagged:
                    flagged_any = True
                rows.append({
                    "rank":           rank,
                    "value":          val,
                    "count":          cnt,
                    "percentage":     round(pct, 2),
                    "cumulative_pct": round(cum, 2),
                    "flagged":        flagged,
                })

                # Track summary metrics
                if field_name in ("source_ip",) and rank == 1:
                    dominant_ip = val
                if field_name in ("uri", "url") and rank == 1:
                    dominant_uri = val

            tables[field_name] = rows

        # Time windows
        time_windows = self._build_time_windows(records, total)
        if time_windows.get("1hour"):
            top_window = time_windows["1hour"][0] if time_windows["1hour"] else {}
            peak_hour = top_window.get("window_start", "")
            peak_hour_count = top_window.get("event_count", 0)

        data: Dict[str, Any] = {
            "tables":       tables,
            "time_windows": time_windows,
            "summary": {
                "dominant_source_ip": dominant_ip,
                "dominant_uri":       dominant_uri,
                "peak_hour":          peak_hour,
                "peak_hour_count":    peak_hour_count,
            },
        }

        n_flagged = sum(
            sum(1 for row in rows if row.get("flagged"))
            for rows in tables.values()
        )
        severity = "HIGH" if flagged_any else "MEDIUM" if tables else "INFO"
        desc = (
            f"{len(tables)} dimension(s) ranked. "
            + (f"{n_flagged} value(s) exceed {thresh:.0f}% dominance threshold." if n_flagged else "")
            + (f" Peak hour: {peak_hour} ({peak_hour_count:,} events)." if peak_hour else "")
        )

        # Build anomaly list from flagged rows
        anomalies: List[Dict] = []
        for fname, rows in tables.items():
            for row in rows:
                if row.get("flagged"):
                    anomalies.append({
                        "field":      fname,
                        "value":      row["value"],
                        "count":      row["count"],
                        "percentage": row["percentage"],
                    })

        return StatResult(
            module="topn",
            log_type=log_type,
            title=f"Top-N Reporter — {log_type}",
            severity=severity,
            description=desc,
            data=data,
            anomalies=anomalies[:30],
            generated_at=now,
        )

    # ------------------------------------------------------------------
    def _build_time_windows(
        self, records: List[LogRecord], total: int
    ) -> Dict[str, List[Dict]]:
        """
        Bucket records by time and rank the busiest windows per bucket size.
        """
        result: Dict[str, List[Dict]] = {}
        timed = [r for r in records if r.timestamp is not None]
        if len(timed) < 2:
            return result

        timed.sort(key=lambda r: r.timestamp)  # type: ignore[arg-type]

        # Compute per-bucket mean for anomaly scoring
        for label, secs in _TIME_BUCKETS:
            bucket_td = timedelta(seconds=secs)
            buckets: Dict[datetime, int] = defaultdict(int)
            for r in timed:
                ts = r.timestamp  # type: ignore[union-attr]
                # Floor to bucket boundary
                epoch = ts.timestamp()
                floored = datetime.fromtimestamp(
                    int(epoch // secs) * secs, tz=ts.tzinfo
                )
                buckets[floored] += 1

            if not buckets:
                continue

            counts = list(buckets.values())
            mean_c = sum(counts) / len(counts)
            std_c  = _stddev(counts)

            sorted_buckets = sorted(buckets.items(), key=lambda x: x[1], reverse=True)
            rows: List[Dict] = []
            for rank, (window_start, cnt) in enumerate(sorted_buckets[:20], 1):
                window_end = window_start + bucket_td
                z = (cnt - mean_c) / std_c if std_c > 0 else 0.0
                anomaly_score = min(max(z / 10.0, 0.0), 1.0)
                rows.append({
                    "window_start":  window_start.isoformat(),
                    "window_end":    window_end.isoformat(),
                    "event_count":   cnt,
                    "rank":          rank,
                    "anomaly_score": round(anomaly_score, 3),
                })
            result[label] = rows

        return result

    def _empty(self, log_type: str, now: datetime) -> StatResult:
        return StatResult(
            module="topn",
            log_type=log_type,
            title=f"Top-N Reporter — {log_type}",
            severity="INFO",
            description="No records to analyse.",
            data={"tables": {}, "time_windows": {}, "summary": {
                "dominant_source_ip": "",
                "dominant_uri": "",
                "peak_hour": "",
                "peak_hour_count": 0,
            }},
            anomalies=[],
            generated_at=now,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stddev(values: List[float]) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return math.sqrt(sum((v - mean) ** 2 for v in values) / n)
