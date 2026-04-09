"""
analytics/frequency.py — Frequency Analysis

Counts all discrete field values across the full dataset and surfaces statistical
outliers using two complementary methods:

  Z-score  — values whose frequency is > z_threshold std-deviations above the mean
  IQR      — values below Q1 - 1.5×IQR (rare/stealthy) or above Q3 + 1.5×IQR (high)

Both methods run in parallel; results are merged and deduplicated.
"""
from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.models import LogRecord, StatResult

# ---------------------------------------------------------------------------
# Optional scientific libraries
# ---------------------------------------------------------------------------
try:
    import numpy as np
    _NP = True
except ImportError:
    _NP = False

try:
    from scipy.stats import iqr as _scipy_iqr
    _SCIPY = True
except ImportError:
    _SCIPY = False


# ---------------------------------------------------------------------------
# Field configuration per log type
# ---------------------------------------------------------------------------

# Each entry: (field_name, extractor_lambda)
_FIELD_CONFIG: Dict[str, List[Tuple[str, Any]]] = {
    "apache": [
        ("source_ip",   lambda r: r.source_ip),
        ("uri",         lambda r: r.uri),
        ("status_code", lambda r: str(r.status_code) if r.status_code else None),
        ("user_agent",  lambda r: r.user_agent),
        ("bytes",       lambda r: str(_bucket_bytes(r.bytes_transferred))),
        ("method",      lambda r: r.action),
    ],
    "nginx": [
        ("source_ip",   lambda r: r.source_ip),
        ("uri",         lambda r: r.uri),
        ("status_code", lambda r: str(r.status_code) if r.status_code else None),
        ("user_agent",  lambda r: r.user_agent),
        ("bytes",       lambda r: str(_bucket_bytes(r.bytes_transferred))),
        ("method",      lambda r: r.action),
    ],
    "iis": [
        ("source_ip",   lambda r: r.source_ip),
        ("uri",         lambda r: r.uri),
        ("status_code", lambda r: str(r.status_code) if r.status_code else None),
        ("user_agent",  lambda r: r.user_agent),
        ("method",      lambda r: r.action),
    ],
    "windows_evtx": [
        ("event_id",    lambda r: r.event_id),
        ("username",    lambda r: r.username),
        ("source_ip",   lambda r: r.source_ip),
        ("hostname",    lambda r: r.hostname),
        ("logon_type",  lambda r: str(r.extra.get("logon_type", "")) or None),
    ],
    "sysmon": [
        ("process_name", lambda r: r.process_name),
        ("event_id",     lambda r: r.event_id),
        ("username",     lambda r: r.username),
        ("dest_ip",      lambda r: r.dest_ip),
        ("hostname",     lambda r: r.hostname),
    ],
    "auth_log": [
        ("username",    lambda r: r.username),
        ("source_ip",   lambda r: r.source_ip),
        ("action",      lambda r: r.action),
        ("hostname",    lambda r: r.hostname),
    ],
    "ssh": [
        ("username",    lambda r: r.username),
        ("source_ip",   lambda r: r.source_ip),
        ("action",      lambda r: r.action),
    ],
    "auditd": [
        ("username",    lambda r: r.username),
        ("process_name", lambda r: r.process_name),
        ("action",      lambda r: r.action),
        ("source_ip",   lambda r: r.source_ip),
    ],
    "cisco_asa": [
        ("source_ip",   lambda r: r.source_ip),
        ("dest_ip",     lambda r: r.dest_ip),
        ("dest_port",   lambda r: str(r.dest_port) if r.dest_port else None),
        ("action",      lambda r: r.action),
        ("protocol",    lambda r: r.extra.get("protocol")),
    ],
    "fortinet": [
        ("source_ip",   lambda r: r.source_ip),
        ("dest_ip",     lambda r: r.dest_ip),
        ("dest_port",   lambda r: str(r.dest_port) if r.dest_port else None),
        ("action",      lambda r: r.action),
    ],
    "palo_alto": [
        ("source_ip",   lambda r: r.source_ip),
        ("dest_ip",     lambda r: r.dest_ip),
        ("dest_port",   lambda r: str(r.dest_port) if r.dest_port else None),
        ("action",      lambda r: r.action),
    ],
    "pfsense": [
        ("source_ip",   lambda r: r.source_ip),
        ("dest_ip",     lambda r: r.dest_ip),
        ("dest_port",   lambda r: str(r.dest_port) if r.dest_port else None),
        ("action",      lambda r: r.action),
    ],
    "squid": [
        ("source_ip",   lambda r: r.source_ip),
        ("dest_ip",     lambda r: r.dest_ip),
        ("uri",         lambda r: r.uri),
        ("status_code", lambda r: str(r.status_code) if r.status_code else None),
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
        ("uri",         lambda r: r.uri),            # query name in uri field
        ("action",      lambda r: r.action),          # query type
        ("status_code", lambda r: str(r.status_code) if r.status_code else None),
    ],
    "cloudtrail": [
        ("action",      lambda r: r.action),          # eventName
        ("username",    lambda r: r.username),
        ("source_ip",   lambda r: r.source_ip),
        ("hostname",    lambda r: r.hostname),
        ("status_code", lambda r: str(r.status_code) if r.status_code else None),
    ],
    "azure_activity": [
        ("action",      lambda r: r.action),
        ("username",    lambda r: r.username),
        ("source_ip",   lambda r: r.source_ip),
    ],
    "gcp_audit": [
        ("action",      lambda r: r.action),
        ("username",    lambda r: r.username),
        ("source_ip",   lambda r: r.source_ip),
    ],
}

_DEFAULT_FIELDS: List[Tuple[str, Any]] = [
    ("source_ip",   lambda r: r.source_ip),
    ("username",    lambda r: r.username),
    ("action",      lambda r: r.action),
    ("dest_port",   lambda r: str(r.dest_port) if r.dest_port else None),
    ("status_code", lambda r: str(r.status_code) if r.status_code else None),
]


def _bucket_bytes(b: Optional[int]) -> Optional[str]:
    """Bucket bytes into human ranges for frequency analysis."""
    if b is None:
        return None
    if b < 1_000:
        return "<1KB"
    if b < 10_000:
        return "1KB-10KB"
    if b < 100_000:
        return "10KB-100KB"
    if b < 1_000_000:
        return "100KB-1MB"
    return ">1MB"


# ---------------------------------------------------------------------------
# Statistics helpers
# ---------------------------------------------------------------------------

def _compute_stats(
    freq: Dict[str, int],
) -> Tuple[float, float, float, float, float]:
    """Return (mean, std, Q1, Q3, IQR) of the frequency values."""
    counts = list(freq.values())
    n = len(counts)
    if n == 0:
        return 0.0, 0.0, 0.0, 0.0, 0.0

    if _NP:
        arr = np.array(counts, dtype=float)
        mean = float(arr.mean())
        std  = float(arr.std())
        q1   = float(np.percentile(arr, 25))
        q3   = float(np.percentile(arr, 75))
        return mean, std, q1, q3, q3 - q1

    s = sorted(counts)
    mean = sum(s) / n
    variance = sum((x - mean) ** 2 for x in s) / n
    std = math.sqrt(variance)

    def _pct(p: float) -> float:
        idx = int(math.ceil(p / 100 * n)) - 1
        return float(s[max(0, min(idx, n - 1))])

    q1 = _pct(25)
    q3 = _pct(75)
    return mean, std, q1, q3, q3 - q1


def _zscore(count: int, mean: float, std: float) -> float:
    if std == 0.0:
        return 0.0
    return (count - mean) / std


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

class FrequencyAnalyzer:
    """
    Counts field values and surfaces both high-frequency (scanning/brute-force)
    and low-frequency (stealthy/rare) anomalies via Z-score and IQR.
    """

    DEFAULT_CONFIG: Dict[str, Any] = {
        "z_threshold":        3.0,
        "iqr_multiplier":     1.5,
        "top_n":              10,
        "min_unique_values":  5,
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.cfg = {**self.DEFAULT_CONFIG, **(config or {})}

    # ------------------------------------------------------------------
    def run(self, records: List[LogRecord], log_type: str) -> StatResult:
        now = datetime.now(timezone.utc)

        if not records:
            return self._empty(log_type, now)

        fields = _FIELD_CONFIG.get(log_type, _DEFAULT_FIELDS)
        field_frequencies: Dict[str, Any] = {}
        total_outliers = 0
        most_anomalous_field = ""
        max_z = 0.0

        for field_name, extractor in fields:
            values = []
            for r in records:
                try:
                    v = extractor(r)
                    if v is not None:
                        values.append(str(v))
                except Exception:
                    pass

            if not values:
                continue

            freq: Dict[str, int] = dict(Counter(values))
            n_unique = len(freq)

            if n_unique < self.cfg["min_unique_values"]:
                continue

            mean, std, q1, q3, iqr = _compute_stats(freq)
            z_thresh = self.cfg["z_threshold"]
            iqr_mult = self.cfg["iqr_multiplier"]
            total = sum(freq.values())

            # Top-N
            top = sorted(freq.items(), key=lambda x: x[1], reverse=True)
            top_values = [
                {
                    "value": val,
                    "count": cnt,
                    "pct": round(cnt / total * 100, 2),
                }
                for val, cnt in top[: self.cfg["top_n"]]
            ]

            # High-frequency outliers (Z-score)
            high_freq: List[Dict] = []
            # Low-frequency outliers (IQR)
            low_freq: List[Dict] = []

            iqr_high_thresh = q3 + iqr_mult * iqr
            iqr_low_thresh  = q1 - iqr_mult * iqr

            for val, cnt in freq.items():
                z = _zscore(cnt, mean, std)
                if z > z_thresh:
                    high_freq.append({"value": val, "count": cnt, "z_score": round(z, 2)})
                    if z > max_z:
                        max_z = z
                        most_anomalous_field = field_name
                if iqr > 0 and cnt <= max(1, iqr_low_thresh):
                    low_freq.append({
                        "value": val,
                        "count": cnt,
                        "iqr_score": round((iqr_low_thresh - cnt) / iqr, 2) if iqr > 0 else 0.0,
                    })
                elif iqr > 0 and cnt >= iqr_high_thresh and z <= z_thresh:
                    # IQR high but not already in z-score list
                    high_freq.append({
                        "value": val,
                        "count": cnt,
                        "z_score": round(z, 2),
                    })

            high_freq.sort(key=lambda x: x["count"], reverse=True)
            low_freq.sort(key=lambda x: x["count"])

            total_outliers += len(high_freq) + len(low_freq)

            field_frequencies[field_name] = {
                "total_unique_values": n_unique,
                "mean_frequency":      round(mean, 3),
                "std_dev":             round(std, 3),
                "Q1":                  round(q1, 3),
                "Q3":                  round(q3, 3),
                "IQR":                 round(iqr, 3),
                "top_values":          top_values,
                "high_freq_outliers":  high_freq[:20],
                "low_freq_outliers":   low_freq[:20],
            }

        severity = _severity_from_outliers(total_outliers, max_z)

        # Build flat anomaly list
        anomalies: List[Dict] = []
        for fname, fd in field_frequencies.items():
            for item in fd.get("high_freq_outliers", []):
                anomalies.append({
                    "field":   fname,
                    "value":   item["value"],
                    "count":   item["count"],
                    "z_score": item.get("z_score", 0),
                    "type":    "HIGH_FREQUENCY",
                })
            for item in fd.get("low_freq_outliers", [])[:5]:
                anomalies.append({
                    "field":  fname,
                    "value":  item["value"],
                    "count":  item["count"],
                    "type":   "LOW_FREQUENCY",
                })
        anomalies.sort(key=lambda a: a.get("z_score", 0) or a.get("count", 0), reverse=True)

        data: Dict[str, Any] = {
            "field_frequencies": field_frequencies,
            "summary": {
                "total_fields_analyzed": len(field_frequencies),
                "total_outliers_found":  total_outliers,
                "most_anomalous_field":  most_anomalous_field,
            },
        }

        desc = (
            f"{len(field_frequencies)} field(s) analysed, "
            f"{total_outliers} outlier(s) found."
            + (f" Most anomalous: {most_anomalous_field} (z={max_z:.1f})." if most_anomalous_field else "")
        )

        return StatResult(
            module="frequency",
            log_type=log_type,
            title=f"Frequency Analysis — {log_type}",
            severity=severity,
            description=desc,
            data=data,
            anomalies=anomalies[:50],
            generated_at=now,
        )

    def _empty(self, log_type: str, now: datetime) -> StatResult:
        return StatResult(
            module="frequency",
            log_type=log_type,
            title=f"Frequency Analysis — {log_type}",
            severity="INFO",
            description="No records to analyse.",
            data={"field_frequencies": {}, "summary": {
                "total_fields_analyzed": 0,
                "total_outliers_found":  0,
                "most_anomalous_field":  "",
            }},
            anomalies=[],
            generated_at=now,
        )


def _severity_from_outliers(n: int, max_z: float) -> str:
    if max_z >= 500 or n >= 30:
        return "CRITICAL"
    if max_z >= 50 or n >= 10:
        return "HIGH"
    if max_z >= 5 or n >= 3:
        return "MEDIUM"
    if n >= 1:
        return "LOW"
    return "INFO"
