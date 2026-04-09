"""
analytics/beaconing.py — Beaconing Detector

Identifies C2 (Command & Control) callback patterns by detecting periodically
regular connections from the same source to the same destination.

Three complementary algorithms, any two of which must trigger:

  1. Jitter Score  — Coefficient of Variation (CV = std/mean) of inter-arrival
                     time deltas. Low CV indicates machine-like regularity.
  2. Autocorrelation — Lag-1 autocorr of the delta series. High value indicates
                       a persistent periodic pattern.
  3. FFT Periodicity — Dominant frequency peak in the delta series via FFT.
                       A sharp peak indicates strict periodic beaconing.
"""
from __future__ import annotations

import math
from collections import defaultdict
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


# ---------------------------------------------------------------------------
# Log types where beaconing detection is applicable
# ---------------------------------------------------------------------------
_APPLICABLE_LOG_TYPES = frozenset({
    "squid", "proxy", "cisco_asa", "fortinet", "palo_alto", "pfsense",
    "suricata", "zeek", "dns_bind", "sysmon", "cloudtrail",
    "apache", "nginx", "iis",  # can also exhibit beaconing
})


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

class BeaconingDetector:
    """
    For each unique (src_ip, dst) pair with >= min_connections, compute the
    inter-arrival time delta series and apply three algorithms.
    A pair is flagged if >= 2 algorithms score above their thresholds.
    """

    DEFAULT_CONFIG: Dict[str, Any] = {
        "min_connections":           8,
        "cv_threshold":              0.35,   # CV below this = suspicious
        "autocorr_threshold":        0.70,   # regularity score above this = suspicious
        "fft_peak_prominence":       0.35,   # FFT peak prominence threshold
        "max_beacon_interval_hrs":   24,
        "min_beacon_interval_secs":  5,
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.cfg = {**self.DEFAULT_CONFIG, **(config or {})}

    # ------------------------------------------------------------------
    def run(self, records: List[LogRecord], log_type: str) -> StatResult:
        now = datetime.now(timezone.utc)

        timed = [r for r in records if r.timestamp is not None]
        if len(timed) < self.cfg["min_connections"]:
            return self._empty(log_type, now, 0, 0)

        # Build connection groups keyed by (src_ip, dst)
        groups: Dict[Tuple[str, str], List[LogRecord]] = defaultdict(list)
        for r in timed:
            src = r.source_ip or ""
            dst = _dst_key(r)
            if src and dst:
                groups[(src, dst)].append(r)

        total_pairs = len(groups)
        beacon_candidates: List[Dict[str, Any]] = []

        min_conn   = self.cfg["min_connections"]
        min_iv_s   = self.cfg["min_beacon_interval_secs"]
        max_iv_hrs = self.cfg["max_beacon_interval_hrs"]

        for (src, dst), recs in groups.items():
            if len(recs) < min_conn:
                continue

            recs.sort(key=lambda r: r.timestamp)  # type: ignore[arg-type]
            timestamps = [r.timestamp for r in recs]  # type: ignore[union-attr]

            deltas = [
                (timestamps[i + 1] - timestamps[i]).total_seconds()
                for i in range(len(timestamps) - 1)
            ]
            if not deltas:
                continue

            # Filter nonsensical deltas
            deltas = [d for d in deltas if min_iv_s <= d <= max_iv_hrs * 3600]
            if len(deltas) < self.cfg["min_connections"] - 1:
                continue

            mean_iv = sum(deltas) / len(deltas)
            if mean_iv <= 0:
                continue

            # Method 1 — Jitter (CV)
            cv = self._jitter_cv(deltas)
            jitter_hit = cv < self.cfg["cv_threshold"]

            # Method 2 — Autocorrelation
            ac = self._autocorr(deltas)
            autocorr_hit = ac >= self.cfg["autocorr_threshold"]

            # Method 3 — FFT
            fft_hit, fft_period = self._fft_period(deltas)

            methods_flagged = []
            if jitter_hit:
                methods_flagged.append("jitter")
            if autocorr_hit:
                methods_flagged.append("autocorr")
            if fft_hit:
                methods_flagged.append("fft")

            if len(methods_flagged) < 2:
                continue

            # Composite beacon score (0–1)
            beacon_score = self._beacon_score(cv, ac, fft_hit, len(methods_flagged))

            # Byte consistency
            bytes_list = [
                r.bytes_transferred
                for r in recs
                if r.bytes_transferred is not None
            ]
            avg_bytes = sum(bytes_list) / len(bytes_list) if bytes_list else 0.0
            consistent_payload = False
            if len(bytes_list) >= 5:
                b_cv = self._jitter_cv([float(b) for b in bytes_list])
                consistent_payload = b_cv < 0.25

            # Severity
            severity = _beacon_severity(beacon_score)

            first_ts = timestamps[0]
            last_ts  = timestamps[-1]
            span_hrs = (last_ts - first_ts).total_seconds() / 3600

            std_iv = self._stddev(deltas)

            beacon_candidates.append({
                "src_ip":                  src,
                "dst_ip_or_domain":        dst,
                "total_connections":       len(recs),
                "time_span_hours":         round(span_hrs, 2),
                "mean_interval_seconds":   round(mean_iv, 2),
                "std_dev_seconds":         round(std_iv, 2),
                "jitter_cv":               round(cv, 4),
                "autocorrelation_score":   round(ac, 4),
                "fft_dominant_period_seconds": round(fft_period, 2),
                "methods_flagged":         methods_flagged,
                "beacon_score":            round(beacon_score, 3),
                "severity":                severity,
                "first_seen":              first_ts.isoformat(),
                "last_seen":               last_ts.isoformat(),
                "sample_intervals_seconds": [round(d, 1) for d in deltas[:20]],
                "consistent_payload_size": consistent_payload,
                "avg_bytes":               round(avg_bytes, 1),
            })

        # Sort by beacon score descending
        beacon_candidates.sort(key=lambda b: b["beacon_score"], reverse=True)

        highest = (
            f'{beacon_candidates[0]["src_ip"]} → {beacon_candidates[0]["dst_ip_or_domain"]}'
            if beacon_candidates else ""
        )

        data: Dict[str, Any] = {
            "beacon_candidates": beacon_candidates,
            "summary": {
                "total_pairs_analyzed":     total_pairs,
                "beacon_candidates_count":  len(beacon_candidates),
                "highest_confidence_beacon": highest,
            },
        }

        n = len(beacon_candidates)
        max_score = beacon_candidates[0]["beacon_score"] if beacon_candidates else 0.0
        severity = _beacon_severity(max_score) if n > 0 else "INFO"
        desc = (
            f"{n} beaconing candidate(s) found across {total_pairs} pair(s) analysed."
            + (f" Highest confidence: {highest} (score={max_score:.3f})." if n else "")
        )

        return StatResult(
            module="beaconing",
            log_type=log_type,
            title=f"Beaconing Detector — {log_type}",
            severity=severity,
            description=desc,
            data=data,
            anomalies=[
                {
                    "src_ip":       b["src_ip"],
                    "dst":          b["dst_ip_or_domain"],
                    "score":        b["beacon_score"],
                    "interval_sec": b["mean_interval_seconds"],
                    "connections":  b["total_connections"],
                    "methods":      b["methods_flagged"],
                    "severity":     b["severity"],
                }
                for b in beacon_candidates[:20]
            ],
            generated_at=now,
        )

    # ------------------------------------------------------------------
    # Algorithm implementations
    # ------------------------------------------------------------------

    def _jitter_cv(self, deltas: List[float]) -> float:
        """Coefficient of Variation = std / mean. Lower → more regular."""
        n = len(deltas)
        if n < 2:
            return 1.0
        mean = sum(deltas) / n
        if mean == 0:
            return 0.0
        variance = sum((d - mean) ** 2 for d in deltas) / n
        std = math.sqrt(variance)
        return std / mean

    def _stddev(self, deltas: List[float]) -> float:
        n = len(deltas)
        if n < 2:
            return 0.0
        mean = sum(deltas) / n
        return math.sqrt(sum((d - mean) ** 2 for d in deltas) / n)

    def _autocorr(self, deltas: List[float]) -> float:
        """
        Regularity score based on the residuals of timestamps relative to
        a perfect periodic signal (timestamp_i - i * mean_interval).

        A perfectly periodic beacon has near-zero residuals; their std
        normalised by mean_interval gives a score in [0, 1].
        Low value = highly regular = suspicious.
        We invert so that HIGH value = suspicious (consistent with threshold).
        """
        n = len(deltas)
        if n < 3:
            return 0.0

        mean_iv = sum(deltas) / n
        if mean_iv <= 0:
            return 0.0

        # Reconstruct cumulative timestamps, compute residual from ideal grid
        cum = 0.0
        residuals: List[float] = []
        for d in deltas:
            cum += d
            ideal = (len(residuals) + 1) * mean_iv
            residuals.append(abs(cum - ideal))

        r_mean = sum(residuals) / n if n > 0 else 0.0
        r_std  = math.sqrt(sum((r - r_mean) ** 2 for r in residuals) / n)

        # Coefficient of variation of residuals relative to mean interval
        # Low = high periodicity; invert to get 0→bad, 1→perfect beacon
        normalised_drift = r_std / mean_iv
        regularity = max(0.0, 1.0 - normalised_drift)
        return regularity

    def _fft_period(self, deltas: List[float]) -> Tuple[bool, float]:
        """
        Apply FFT to a time-binned presence signal derived from timestamps.
        Returns (is_periodic, dominant_period_seconds).
        Requires numpy; returns (False, 0.0) without it.
        """
        if not _NP or len(deltas) < 8:
            return False, 0.0

        mean_iv = sum(deltas) / len(deltas)

        # Reconstruct cumulative timestamps relative to t=0
        times: List[float] = [0.0]
        for d in deltas:
            times.append(times[-1] + d)

        # Bin into uniform time windows of size mean_iv/4 (4 bins per expected period)
        bin_size = max(mean_iv / 4.0, 1.0)
        total_time = times[-1]
        n_bins = max(int(total_time / bin_size) + 1, 16)
        counts = np.zeros(n_bins, dtype=float)
        for t in times:
            idx = min(int(t / bin_size), n_bins - 1)
            counts[idx] += 1.0

        fft = np.abs(np.fft.rfft(counts))
        if len(fft) < 2:
            return False, 0.0

        fft[0] = 0.0   # remove DC
        total_power = float(fft.sum())
        if total_power == 0.0:
            return False, 0.0

        peak_idx = int(np.argmax(fft[1:])) + 1
        prominence = float(fft[peak_idx]) / total_power
        is_periodic = prominence >= self.cfg["fft_peak_prominence"]

        # Convert bin frequency back to period in seconds
        freq_hz = peak_idx / (n_bins * bin_size)
        dominant_period = 1.0 / freq_hz if freq_hz > 0 else 0.0

        return is_periodic, dominant_period

    def _beacon_score(
        self,
        cv: float,
        ac: float,
        fft_hit: bool,
        methods_hit: int,
    ) -> float:
        """
        Composite beacon score in [0, 1].
        Weighted average of method signals.
        """
        # Jitter contribution: lower CV → higher score
        cv_score = max(0.0, 1.0 - cv / self.cfg["cv_threshold"])
        # Autocorr contribution: higher AC → higher score
        ac_norm  = max(0.0, (ac - self.cfg["autocorr_threshold"]) / (1.0 - self.cfg["autocorr_threshold"] + 1e-9))
        fft_score = 1.0 if fft_hit else 0.0
        # Weighted
        raw = 0.40 * cv_score + 0.35 * ac_norm + 0.25 * fft_score
        # Penalise single-method hits (already filtered upstream, but keep guard)
        if methods_hit == 2:
            raw *= 0.85
        return min(raw, 1.0)

    def _empty(
        self,
        log_type: str,
        now: datetime,
        total_pairs: int,
        n_candidates: int,
    ) -> StatResult:
        return StatResult(
            module="beaconing",
            log_type=log_type,
            title=f"Beaconing Detector — {log_type}",
            severity="INFO",
            description="Insufficient timed records for beaconing analysis.",
            data={
                "beacon_candidates": [],
                "summary": {
                    "total_pairs_analyzed":     total_pairs,
                    "beacon_candidates_count":  n_candidates,
                    "highest_confidence_beacon": "",
                },
            },
            anomalies=[],
            generated_at=now,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dst_key(r: LogRecord) -> str:
    """
    Return a destination key for the (src, dst) pair.
    Prefer URI domain for HTTP logs; fall back to dest_ip:dest_port.
    """
    if r.uri:
        # Extract hostname from URI
        import re
        m = re.search(r"https?://([^/]+)", r.uri)
        if m:
            return m.group(1)
    if r.dest_ip:
        if r.dest_port:
            return f"{r.dest_ip}:{r.dest_port}"
        return r.dest_ip
    # DNS: use the queried domain (stored in uri or extra)
    domain = r.extra.get("query_name") or r.extra.get("domain")
    if domain:
        return str(domain)
    return ""


def _beacon_severity(score: float) -> str:
    if score >= 0.90:
        return "CRITICAL"
    if score >= 0.75:
        return "HIGH"
    if score >= 0.55:
        return "MEDIUM"
    return "LOW"
