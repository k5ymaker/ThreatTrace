"""
analytics/baseline.py — Baseline Profiler

Learns "normal" behaviour from the first 70 % of log records (by timestamp),
then flags records in the remaining 30 % that deviate more than
deviation_threshold_sigma standard deviations from the baseline.

Dimensions profiled are configurable per log type and cover both:
  - Per-record fields   (bytes_transferred, status_code, …)
  - Aggregate series    (IP requests/hour, user logins/hour, events/hour, …)
"""
from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Tuple

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
# Dimension definition
# ---------------------------------------------------------------------------

class Dimension(NamedTuple):
    name: str
    # Returns a list of (value, record_index) pairs from a record list.
    # For aggregate dims the record_index is -1 (no single owning record).
    extractor: Callable[[List[LogRecord]], List[Tuple[float, int]]]
    description: str


# ---------------------------------------------------------------------------
# Extractor helpers
# ---------------------------------------------------------------------------

def _per_record(
    attr: str,
    transform: Optional[Callable[[Any], float]] = None,
) -> Callable[[List[LogRecord]], List[Tuple[float, int]]]:
    """Build an extractor for a direct LogRecord attribute."""
    def _extract(records: List[LogRecord]) -> List[Tuple[float, int]]:
        out: List[Tuple[float, int]] = []
        for i, r in enumerate(records):
            raw = getattr(r, attr, None)
            if raw is None:
                continue
            try:
                val = float(raw) if transform is None else transform(raw)
                out.append((val, i))
            except (TypeError, ValueError):
                pass
        return out
    return _extract


def _hourly_ip_rate(
    records: List[LogRecord],
) -> List[Tuple[float, int]]:
    """
    For each (hour_bucket, source_ip) pair, return the request count.
    Used for apache/nginx/proxy to detect IP request-rate anomalies.
    """
    buckets: Dict[Tuple[str, str], int] = defaultdict(int)
    for r in records:
        if r.timestamp is None or not r.source_ip:
            continue
        hour = r.timestamp.strftime("%Y-%m-%dT%H")
        buckets[(hour, r.source_ip)] += 1
    return [(float(v), -1) for v in buckets.values()]


def _hourly_user_logins(
    records: List[LogRecord],
) -> List[Tuple[float, int]]:
    """
    Return per-(hour, username) login counts for auth-type logs.
    """
    buckets: Dict[Tuple[str, str], int] = defaultdict(int)
    for r in records:
        if r.timestamp is None or not r.username:
            continue
        hour = r.timestamp.strftime("%Y-%m-%dT%H")
        buckets[(hour, r.username)] += 1
    return [(float(v), -1) for v in buckets.values()]


def _hourly_events(
    records: List[LogRecord],
) -> List[Tuple[float, int]]:
    """Global events-per-hour series."""
    buckets: Dict[str, int] = defaultdict(int)
    for r in records:
        if r.timestamp is None:
            continue
        buckets[r.timestamp.strftime("%Y-%m-%dT%H")] += 1
    return [(float(v), -1) for v in buckets.values()]


def _ip_failure_rate(
    records: List[LogRecord],
) -> List[Tuple[float, int]]:
    """
    Per-IP ratio of failed/total events.
    A 'failure' is: status_code in 4xx/5xx for HTTP,
    or action containing 'fail'/'deny'/'block'/'drop' for auth/firewall.
    """
    totals: Dict[str, int] = defaultdict(int)
    fails: Dict[str, int] = defaultdict(int)
    for r in records:
        if not r.source_ip:
            continue
        totals[r.source_ip] += 1
        sc = r.status_code or 0
        act = (r.action or "").lower()
        if sc >= 400 or any(k in act for k in ("fail", "deny", "block", "drop", "error")):
            fails[r.source_ip] += 1
    return [
        (fails[ip] / totals[ip], -1)
        for ip in totals
        if totals[ip] > 0
    ]


def _session_bytes(
    records: List[LogRecord],
) -> List[Tuple[float, int]]:
    """Per-(src_ip, dst_ip) total bytes transferred — firewall/proxy dimension."""
    pairs: Dict[Tuple[str, str], float] = defaultdict(float)
    for r in records:
        if r.bytes_transferred is not None and r.source_ip and r.dest_ip:
            pairs[(r.source_ip, r.dest_ip)] += r.bytes_transferred
    return [(v, -1) for v in pairs.values()]


def _user_event_diversity(
    records: List[LogRecord],
) -> List[Tuple[float, int]]:
    """Number of unique event_ids per user (Windows/Sysmon dimension)."""
    user_events: Dict[str, set] = defaultdict(set)
    for r in records:
        if r.username and r.event_id:
            user_events[r.username].add(r.event_id)
    return [(float(len(v)), -1) for v in user_events.values()]


# ---------------------------------------------------------------------------
# Dimension registry: log_type → list of Dimensions
# ---------------------------------------------------------------------------

_DIM_REGISTRY: Dict[str, List[Dimension]] = {
    "apache": [
        Dimension("bytes_transferred",   _per_record("bytes_transferred"), "HTTP response size per request"),
        Dimension("status_code",         _per_record("status_code"),        "HTTP status code per request"),
        Dimension("requests_per_hour_per_ip", _hourly_ip_rate,              "Requests/hour per source IP"),
        Dimension("ip_failure_rate",     _ip_failure_rate,                  "4xx/5xx failure ratio per IP"),
        Dimension("events_per_hour",     _hourly_events,                    "Global events per hour"),
    ],
    "nginx": [
        Dimension("bytes_transferred",   _per_record("bytes_transferred"), "HTTP response size per request"),
        Dimension("status_code",         _per_record("status_code"),        "HTTP status code"),
        Dimension("requests_per_hour_per_ip", _hourly_ip_rate,              "Requests/hour per source IP"),
        Dimension("ip_failure_rate",     _ip_failure_rate,                  "4xx/5xx failure ratio per IP"),
        Dimension("events_per_hour",     _hourly_events,                    "Global events per hour"),
    ],
    "iis": [
        Dimension("bytes_transferred",   _per_record("bytes_transferred"), "Response bytes"),
        Dimension("status_code",         _per_record("status_code"),        "HTTP status code"),
        Dimension("requests_per_hour_per_ip", _hourly_ip_rate,              "Requests/hour per source IP"),
        Dimension("events_per_hour",     _hourly_events,                    "Global events per hour"),
    ],
    "auth_log": [
        Dimension("logins_per_hour_per_user", _hourly_user_logins,          "Logins/hour per user"),
        Dimension("ip_failure_rate",     _ip_failure_rate,                   "Auth failure ratio per IP"),
        Dimension("events_per_hour",     _hourly_events,                     "Global events per hour"),
    ],
    "ssh": [
        Dimension("logins_per_hour_per_user", _hourly_user_logins,          "SSH logins/hour per user"),
        Dimension("ip_failure_rate",     _ip_failure_rate,                   "SSH failure ratio per IP"),
        Dimension("events_per_hour",     _hourly_events,                     "Events per hour"),
    ],
    "windows_evtx": [
        Dimension("logins_per_hour_per_user", _hourly_user_logins,          "Logons/hour per user"),
        Dimension("ip_failure_rate",     _ip_failure_rate,                   "Failure ratio per IP"),
        Dimension("user_event_diversity", _user_event_diversity,             "Unique EventIDs per user"),
        Dimension("events_per_hour",     _hourly_events,                     "Global events per hour"),
    ],
    "sysmon": [
        Dimension("logins_per_hour_per_user", _hourly_user_logins,          "Logins/hour per user"),
        Dimension("user_event_diversity", _user_event_diversity,             "Unique EventIDs per user"),
        Dimension("events_per_hour",     _hourly_events,                     "Events per hour"),
    ],
    "auditd": [
        Dimension("events_per_hour",     _hourly_events,                     "Audit events per hour"),
        Dimension("logins_per_hour_per_user", _hourly_user_logins,          "Logins/hour per user"),
    ],
    "cisco_asa": [
        Dimension("bytes_transferred",   _per_record("bytes_transferred"),  "Session bytes"),
        Dimension("session_bytes_per_pair", _session_bytes,                  "Bytes per src-dst pair"),
        Dimension("events_per_hour",     _hourly_events,                     "Events per hour"),
        Dimension("ip_failure_rate",     _ip_failure_rate,                   "Deny ratio per IP"),
    ],
    "fortinet": [
        Dimension("bytes_transferred",   _per_record("bytes_transferred"),  "Session bytes"),
        Dimension("session_bytes_per_pair", _session_bytes,                  "Bytes per src-dst pair"),
        Dimension("events_per_hour",     _hourly_events,                     "Events per hour"),
    ],
    "palo_alto": [
        Dimension("bytes_transferred",   _per_record("bytes_transferred"),  "Session bytes"),
        Dimension("session_bytes_per_pair", _session_bytes,                  "Bytes per src-dst pair"),
        Dimension("events_per_hour",     _hourly_events,                     "Events per hour"),
    ],
    "squid": [
        Dimension("bytes_transferred",   _per_record("bytes_transferred"),  "Outbound bytes"),
        Dimension("requests_per_hour_per_ip", _hourly_ip_rate,              "Requests/hour per IP"),
        Dimension("events_per_hour",     _hourly_events,                     "Events per hour"),
    ],
    "cloudtrail": [
        Dimension("logins_per_hour_per_user", _hourly_user_logins,          "API calls/hour per IAM user"),
        Dimension("ip_failure_rate",     _ip_failure_rate,                   "API error ratio per IP"),
        Dimension("events_per_hour",     _hourly_events,                     "API calls per hour"),
    ],
    "azure_activity": [
        Dimension("logins_per_hour_per_user", _hourly_user_logins,          "Ops/hour per user"),
        Dimension("events_per_hour",     _hourly_events,                     "Operations per hour"),
    ],
    "gcp_audit": [
        Dimension("logins_per_hour_per_user", _hourly_user_logins,          "API calls/hour per principal"),
        Dimension("events_per_hour",     _hourly_events,                     "Audit events per hour"),
    ],
    "dns_bind": [
        Dimension("requests_per_hour_per_ip", _hourly_ip_rate,              "DNS queries/hour per IP"),
        Dimension("events_per_hour",     _hourly_events,                     "Global queries per hour"),
    ],
    "syslog": [
        Dimension("events_per_hour",     _hourly_events,                     "Events per hour"),
    ],
}

# Fallback for unmapped log types
_DEFAULT_DIMS: List[Dimension] = [
    Dimension("events_per_hour", _hourly_events, "Events per hour"),
    Dimension("ip_failure_rate", _ip_failure_rate, "Failure ratio per IP"),
]


# ---------------------------------------------------------------------------
# Statistics helpers
# ---------------------------------------------------------------------------

def _profile(values: List[float]) -> Dict[str, float]:
    """Compute descriptive statistics for a list of float values."""
    n = len(values)
    if n == 0:
        return {"mean": 0.0, "std_dev": 0.0, "min": 0.0, "max": 0.0, "p95": 0.0, "p99": 0.0}

    if _NP:
        arr = np.array(values, dtype=float)
        return {
            "mean":    float(arr.mean()),
            "std_dev": float(arr.std()),
            "min":     float(arr.min()),
            "max":     float(arr.max()),
            "p95":     float(np.percentile(arr, 95)),
            "p99":     float(np.percentile(arr, 99)),
        }

    # Pure-Python fallback
    s = sorted(values)
    mean = sum(s) / n
    variance = sum((x - mean) ** 2 for x in s) / n
    std_dev = math.sqrt(variance)

    def _pct(p: float) -> float:
        idx = int(math.ceil(p / 100 * n)) - 1
        return s[max(0, min(idx, n - 1))]

    return {
        "mean":    mean,
        "std_dev": std_dev,
        "min":     s[0],
        "max":     s[-1],
        "p95":     _pct(95),
        "p99":     _pct(99),
    }


def _zscore(value: float, mean: float, std: float) -> float:
    if std == 0.0:
        return 0.0
    return (value - mean) / std


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

class BaselineProfiler:
    """
    Learns normal behaviour from the first training_pct of records
    (by timestamp), then flags deviations in the remainder.

    Minimum records: at least min_records total before any profiling runs.
    """

    DEFAULT_CONFIG: Dict[str, Any] = {
        "training_pct": 0.70,
        "min_records": 100,
        "deviation_threshold_sigma": 2.5,
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.cfg = {**self.DEFAULT_CONFIG, **(config or {})}

    # ------------------------------------------------------------------
    def run(self, records: List[LogRecord], log_type: str) -> StatResult:
        """Run baseline profiling and return a StatResult."""
        now = datetime.now(timezone.utc)

        if len(records) < self.cfg["min_records"]:
            return self._empty_result(log_type, now, len(records))

        # Sort by timestamp (records without timestamps go last)
        timed = [r for r in records if r.timestamp is not None]
        untimed = [r for r in records if r.timestamp is None]
        timed.sort(key=lambda r: r.timestamp)  # type: ignore[arg-type]
        sorted_records = timed + untimed

        split = int(len(sorted_records) * self.cfg["training_pct"])
        split = max(split, 1)
        training = sorted_records[:split]
        test = sorted_records[split:]

        if not test:
            return self._empty_result(log_type, now, len(records))

        # Training window
        t_start = training[0].timestamp if training[0].timestamp else None
        t_end = training[-1].timestamp if training[-1].timestamp else None

        dims = _DIM_REGISTRY.get(log_type, _DEFAULT_DIMS)

        dimension_profiles: Dict[str, Dict[str, float]] = {}
        all_deviations: List[Dict[str, Any]] = []
        sigma_threshold = self.cfg["deviation_threshold_sigma"]

        for dim in dims:
            train_vals_raw = dim.extractor(training)
            if not train_vals_raw:
                continue
            train_vals = [v for v, _ in train_vals_raw]
            if len(train_vals) < 3:
                continue

            prof = _profile(train_vals)
            dimension_profiles[dim.name] = prof

            # Test — per-record dimensions
            test_vals_raw = dim.extractor(test)
            for val, rec_idx in test_vals_raw:
                z = _zscore(val, prof["mean"], prof["std_dev"])
                if abs(z) > sigma_threshold:
                    entry: Dict[str, Any] = {
                        "dimension":       dim.name,
                        "observed_value":  round(val, 4),
                        "baseline_mean":   round(prof["mean"], 4),
                        "sigma_distance":  round(abs(z), 2),
                    }
                    if rec_idx >= 0 and rec_idx < len(test):
                        r = test[rec_idx]
                        entry["record_index"] = split + rec_idx
                        entry["timestamp"] = (
                            r.timestamp.isoformat() if r.timestamp else ""
                        )
                        entry["source_ip"]  = r.source_ip or ""
                        entry["username"]   = r.username or ""
                        entry["raw_line"]   = r.raw_line[:200]
                    else:
                        entry["record_index"] = -1
                        entry["timestamp"] = ""
                        entry["source_ip"]  = ""
                        entry["username"]   = ""
                        entry["raw_line"]   = "(aggregate)"
                    all_deviations.append(entry)

        # Sort deviations by sigma distance descending
        all_deviations.sort(key=lambda d: d["sigma_distance"], reverse=True)

        severity = _severity_from_deviations(all_deviations)

        data: Dict[str, Any] = {
            "baseline_summary": {
                "training_records":  len(training),
                "test_records":      len(test),
                "dimensions_profiled": [d.name for d in dims if d.name in dimension_profiles],
                "training_window": {
                    "start": t_start.isoformat() if t_start else "",
                    "end":   t_end.isoformat()   if t_end   else "",
                },
            },
            "dimension_profiles": dimension_profiles,
            "deviations_detected": all_deviations[:200],  # cap for serialisation
        }

        n_dev = len(all_deviations)
        desc = (
            f"{n_dev} deviation(s) detected across "
            f"{len(dimension_profiles)} dimension(s). "
            f"Training: {len(training):,} records, Test: {len(test):,} records."
        )

        return StatResult(
            module="baseline",
            log_type=log_type,
            title=f"Baseline Profiler — {log_type}",
            severity=severity,
            description=desc,
            data=data,
            anomalies=all_deviations[:50],
            generated_at=now,
        )

    # ------------------------------------------------------------------
    def _empty_result(
        self, log_type: str, now: datetime, n: int
    ) -> StatResult:
        return StatResult(
            module="baseline",
            log_type=log_type,
            title=f"Baseline Profiler — {log_type}",
            severity="INFO",
            description=(
                f"Insufficient data for baseline profiling "
                f"({n} records < {self.cfg['min_records']} minimum)."
            ),
            data={
                "baseline_summary": {
                    "training_records": 0, "test_records": 0,
                    "dimensions_profiled": [], "training_window": {},
                },
                "dimension_profiles": {},
                "deviations_detected": [],
            },
            anomalies=[],
            generated_at=now,
        )


# ---------------------------------------------------------------------------
# Severity helper
# ---------------------------------------------------------------------------

def _severity_from_deviations(devs: List[Dict]) -> str:
    if not devs:
        return "INFO"
    max_sigma = max(d.get("sigma_distance", 0) for d in devs)
    n = len(devs)
    if max_sigma >= 100 or n >= 50:
        return "CRITICAL"
    if max_sigma >= 20 or n >= 20:
        return "HIGH"
    if max_sigma >= 5 or n >= 5:
        return "MEDIUM"
    return "LOW"
