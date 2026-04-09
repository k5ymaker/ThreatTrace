"""
extractor/engine.py — High-level IOC extraction engine.

ExtractorEngine orchestrates the full extraction pipeline:
  1. Build a LineIndexer from files or pre-loaded records.
  2. Wrap every found IOC in an ExtractionResult with risk scoring.
  3. Expose pivot() to drill into a single entity.

Public API:
    ExtractionResult  — dataclass for a single extracted IOC
    PivotResult       — dataclass for a pivot drill-down
    ExtractorEngine   — main class

    engine.load_from_files(paths, filter_private=True)
    engine.load_from_records(records, source_label="", filter_private=True)
    engine.extract(entity_types=None) → list[ExtractionResult]
    engine.pivot(entity_type, value)  → PivotResult
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from extractor.line_indexer import LineIndexer
from extractor.context_discoverer import ContextDiscoverer
from extractor.patterns import PATTERNS


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ExtractionResult:
    """
    Represents a single extracted IOC and its context.

    Attributes
    ----------
    entity_type   : IOC category (e.g. "ipv4", "md5", "url").
    value         : The extracted IOC value.
    occurrences   : Number of log lines this IOC appeared on.
    first_seen    : Earliest timestamp parsed from those lines (or None).
    last_seen     : Latest timestamp parsed from those lines (or None).
    sources       : Distinct source file paths (or labels) that contained it.
    sample_lines  : Up to 5 representative (lineno, raw_line) tuples.
    risk_score    : Float 0.0–1.0 heuristic risk score.
    risk_factors  : Human-readable list of scoring reasons.
    context       : Co-occurring IOC types → [(value, count), …] mapping.
    """
    entity_type:  str
    value:        str
    occurrences:  int                           = 0
    first_seen:   Optional[datetime]            = None
    last_seen:    Optional[datetime]            = None
    sources:      List[str]                     = field(default_factory=list)
    sample_lines: List[Tuple[int, str]]         = field(default_factory=list)
    risk_score:   float                         = 0.0
    risk_factors: List[str]                     = field(default_factory=list)
    context:      Dict[str, List[Tuple[str, int]]] = field(default_factory=dict)


@dataclass
class PivotResult:
    """
    Aggregated context for a single pivoted entity.

    Attributes
    ----------
    entity_type     : IOC category.
    value           : The pivoted entity value.
    total_lines     : Total log lines that mention this entity.
    first_seen      : Earliest timestamp.
    last_seen       : Latest timestamp.
    sources         : Distinct source file paths.
    all_lines       : All (lineno, raw_line) tuples from the index.
    co_occurring    : Co-occurring IOCs grouped by type.
    risk_score      : Same scoring as ExtractionResult.
    risk_factors    : Human-readable scoring reasons.
    """
    entity_type:  str
    value:        str
    total_lines:  int                           = 0
    first_seen:   Optional[datetime]            = None
    last_seen:    Optional[datetime]            = None
    sources:      List[str]                     = field(default_factory=list)
    all_lines:    List[Tuple[int, str]]         = field(default_factory=list)
    co_occurring: Dict[str, List[Tuple[str, int]]] = field(default_factory=dict)
    risk_score:   float                         = 0.0
    risk_factors: List[str]                     = field(default_factory=list)


# ---------------------------------------------------------------------------
# Risk-scoring heuristics
# ---------------------------------------------------------------------------

# Base risk weights per IOC type (0.0–1.0 starting contribution)
_TYPE_BASE_RISK: Dict[str, float] = {
    "aws_key":    0.90,
    "jwt":        0.70,
    "sha256":     0.55,
    "sha1":       0.50,
    "md5":        0.45,
    "ipv4":       0.30,
    "ipv6":       0.30,
    "url":        0.35,
    "email":      0.20,
    "domain":     0.25,
    "cve":        0.60,
    "username":   0.20,
    "user_agent": 0.10,
    "mac":        0.15,
    "win_path":   0.20,
    "unix_path":  0.15,
}

# Known malicious / suspicious keywords that boost risk
_SUSPICIOUS_KEYWORDS = frozenset({
    "mimikatz", "meterpreter", "cobalt", "powersploit", "bloodhound",
    "exploit", "shellcode", "payload", "beacon", "c2", "botnet",
    "ransomware", "cryptolocker", "wannacry", "notpetya", "ryuk",
    "passwd", "shadow", "ntds.dit", "sam", "lsass",
    "wget", "curl", "base64", "powershell", "cmd.exe", "wscript",
    "cscript", "regsvr32", "mshta", "rundll32",
    "admin", "administrator", "root", "system",
    "/etc/passwd", "/etc/shadow",
    "eval(", "exec(", "os.system",
    "drop table", "union select", "1=1", "--",  # SQLi fragments
    "<script", "onerror=", "javascript:",        # XSS fragments
})

# TLDs commonly abused in phishing / malware infrastructure
_SUSPICIOUS_TLDS = frozenset({
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".download", ".stream", ".win", ".party", ".loan",
})


def _score(
    entity_type: str,
    value: str,
    occurrences: int,
    has_timestamps: bool,
    total_line_count: int,
    freq_mean: Optional[float] = None,
    freq_sigma: Optional[float] = None,
) -> Tuple[float, List[str]]:
    """
    Additive heuristic risk scorer. Returns (score: float, factors: list[str]).
    Score is capped at 1.0.

    Heuristics applied:
    - Base risk by entity type
    - High occurrence count (absolute)
    - Statistical rarity / frequency spike (if freq_mean / freq_sigma provided)
    - Suspicious keyword match in value
    - Suspicious TLD (for domain / url / email)
    - AWS key / JWT detected (inherently high risk)
    - CVE detected
    - No timestamps found (may indicate log tampering)
    """
    score   = _TYPE_BASE_RISK.get(entity_type, 0.10)
    factors: List[str] = [f"Base risk for type={entity_type} ({score:.2f})"]

    val_lc = value.lower()

    # Suspicious keyword in value
    matched_kw = next((kw for kw in _SUSPICIOUS_KEYWORDS if kw in val_lc), None)
    if matched_kw:
        score   += 0.20
        factors.append(f"Suspicious keyword in value: '{matched_kw}' (+0.20)")

    # Suspicious TLD
    for tld in _SUSPICIOUS_TLDS:
        if val_lc.endswith(tld) or tld in val_lc:
            score   += 0.15
            factors.append(f"Suspicious TLD '{tld}' (+0.15)")
            break

    # High absolute occurrence count — IOC that appears on many lines
    if total_line_count > 0 and occurrences > 1:
        pct = occurrences / total_line_count
        if pct >= 0.10:
            score   += 0.15
            factors.append(f"High occurrence rate ({pct*100:.1f}% of lines) (+0.15)")
        elif occurrences >= 20:
            score   += 0.10
            factors.append(f"High absolute count ({occurrences} hits) (+0.10)")

    # Statistical anomaly — z-score from frequency analytics if available
    if freq_mean is not None and freq_sigma is not None and freq_sigma > 0:
        z = (occurrences - freq_mean) / freq_sigma
        if z >= 3.0:
            score   += 0.20
            factors.append(f"Statistical frequency spike (z={z:.1f}) (+0.20)")
        elif z >= 2.0:
            score   += 0.10
            factors.append(f"Above-average frequency (z={z:.1f}) (+0.10)")

    # No timestamps — possible log tampering / synthetic logs
    if not has_timestamps:
        score   += 0.05
        factors.append("No timestamps detected on matched lines (+0.05)")

    return min(score, 1.0), factors


# ---------------------------------------------------------------------------
# ExtractorEngine
# ---------------------------------------------------------------------------

class ExtractorEngine:
    """
    Orchestrates IOC extraction from files or pre-loaded log records.

    Usage (from files)::

        engine = ExtractorEngine()
        engine.load_from_files(["/var/log/auth.log"])
        results = engine.extract()

    Usage (from records — e.g. post-analysis)::

        engine = ExtractorEngine()
        engine.load_from_records(all_events, source_label="auth.log")
        results = engine.extract()
    """

    def __init__(self) -> None:
        self._indexer:   Optional[LineIndexer]      = None
        self._discoverer: Optional[ContextDiscoverer] = None
        self._source_label: str = ""

    # ------------------------------------------------------------------
    # Loaders
    # ------------------------------------------------------------------

    def load_from_files(
        self,
        paths: Iterable[Union[str, Path]],
        filter_private: bool = True,
    ) -> "ExtractorEngine":
        """
        Build the index by scanning *paths* on disk.

        Parameters
        ----------
        paths          : Iterable of file paths.
        filter_private : Skip RFC-1918 / loopback IPv4 (default: True).
        """
        self._indexer = LineIndexer().build(paths, filter_private=filter_private)
        self._discoverer = ContextDiscoverer(self._indexer)
        self._source_label = ", ".join(str(p) for p in paths)
        return self

    def load_from_records(
        self,
        records: Iterable[Any],
        source_label: str = "",
        filter_private: bool = True,
    ) -> "ExtractorEngine":
        """
        Build the index from a list of log record objects or raw strings.

        Accepts:
          - Objects with a ``.raw_line`` attribute (core.models.LogRecord)
          - Plain strings
          - Dicts with a ``"raw"`` or ``"raw_line"`` key

        Parameters
        ----------
        records        : Iterable of record objects / strings / dicts.
        source_label   : Label stored in source_map (e.g. filename).
        filter_private : Skip RFC-1918 / loopback IPv4 (default: True).
        """
        def _to_str(r: Any) -> str:
            if isinstance(r, str):
                return r
            if isinstance(r, dict):
                return r.get("raw_line") or r.get("raw") or str(r)
            if hasattr(r, "raw_line"):
                return r.raw_line or ""
            return str(r)

        lines = (_to_str(rec) for rec in records)
        self._source_label = source_label
        self._indexer = LineIndexer().build_from_lines(
            lines,
            source_label=source_label,
            filter_private=filter_private,
        )
        self._discoverer = ContextDiscoverer(self._indexer)
        return self

    # ------------------------------------------------------------------
    # Extraction
    # ------------------------------------------------------------------

    def extract(
        self,
        entity_types: Optional[List[str]] = None,
    ) -> List[ExtractionResult]:
        """
        Return a list of :class:`ExtractionResult` objects, one per unique IOC.

        Parameters
        ----------
        entity_types : If provided, only return results for the named types.
                       Defaults to all 16 types.

        Returns
        -------
        List sorted by (risk_score desc, occurrences desc).
        """
        if self._indexer is None:
            return []

        allowed = frozenset(entity_types) if entity_types else frozenset(PATTERNS)
        total_lines = len(self._indexer.raw_lines)

        # Compute per-type occurrence stats for z-score scoring
        type_freq: Dict[str, List[int]] = {}
        for (et, _val), hits in self._indexer.index.items():
            if et not in type_freq:
                type_freq[et] = []
            type_freq[et].append(len(hits))

        type_stats: Dict[str, Tuple[float, float]] = {}  # et → (mean, sigma)
        for et, counts in type_freq.items():
            n    = len(counts)
            mean = sum(counts) / n
            sigma = math.sqrt(sum((c - mean) ** 2 for c in counts) / n) if n > 1 else 0.0
            type_stats[et] = (mean, sigma)

        # Also try to import analytics frequency stats (optional)
        freq_mean_ext: Optional[float]  = None
        freq_sigma_ext: Optional[float] = None
        try:
            from analytics.frequency import _compute_stats  # type: ignore
            # If available, we could pass external stats; keep as None for now
        except (ImportError, AttributeError):
            pass

        results: List[ExtractionResult] = []

        for (entity_type, value), hits in self._indexer.index.items():
            if entity_type not in allowed:
                continue

            timestamps = [
                ts for ts in self._indexer.timestamps.get((entity_type, value), [])
                if ts is not None
            ]
            sources = list(dict.fromkeys(
                self._indexer.source_map.get((entity_type, value), [])
            ))

            first_seen = min(timestamps) if timestamps else None
            last_seen  = max(timestamps) if timestamps else None

            sample = hits[:5]

            mean_et, sigma_et = type_stats.get(entity_type, (0.0, 0.0))
            risk, factors = _score(
                entity_type   = entity_type,
                value         = value,
                occurrences   = len(hits),
                has_timestamps= bool(timestamps),
                total_line_count = total_lines,
                freq_mean     = mean_et,
                freq_sigma    = sigma_et,
            )

            context = (
                self._discoverer.discover(entity_type, value)
                if self._discoverer else {}
            )

            results.append(ExtractionResult(
                entity_type  = entity_type,
                value        = value,
                occurrences  = len(hits),
                first_seen   = first_seen,
                last_seen    = last_seen,
                sources      = sources,
                sample_lines = sample,
                risk_score   = risk,
                risk_factors = factors,
                context      = context,
            ))

        results.sort(key=lambda r: (r.risk_score, r.occurrences), reverse=True)
        return results

    # ------------------------------------------------------------------
    # Pivot
    # ------------------------------------------------------------------

    def pivot(
        self,
        entity_type: str,
        value: str,
    ) -> Optional[PivotResult]:
        """
        Drill into a single entity and return enriched context.

        Returns
        -------
        :class:`PivotResult` or ``None`` if the entity is not in the index.
        """
        if self._indexer is None:
            return None

        hits = self._indexer.get_lines(entity_type, value)
        if not hits:
            return None

        timestamps = [
            ts for ts in self._indexer.timestamps.get((entity_type, value), [])
            if ts is not None
        ]
        sources = list(dict.fromkeys(
            self._indexer.source_map.get((entity_type, value), [])
        ))

        co_occurring = (
            self._discoverer.discover(entity_type, value)
            if self._discoverer else {}
        )

        total_lines = len(self._indexer.raw_lines)
        mean_et, sigma_et = (0.0, 0.0)
        type_counts = [
            len(v) for (et, _), v in self._indexer.index.items()
            if et == entity_type
        ]
        if type_counts:
            n     = len(type_counts)
            mean_et = sum(type_counts) / n
            sigma_et = math.sqrt(sum((c - mean_et)**2 for c in type_counts) / n) if n > 1 else 0.0

        risk, factors = _score(
            entity_type      = entity_type,
            value            = value,
            occurrences      = len(hits),
            has_timestamps   = bool(timestamps),
            total_line_count = total_lines,
            freq_mean        = mean_et,
            freq_sigma       = sigma_et,
        )

        return PivotResult(
            entity_type  = entity_type,
            value        = value,
            total_lines  = len(hits),
            first_seen   = min(timestamps) if timestamps else None,
            last_seen    = max(timestamps) if timestamps else None,
            sources      = sources,
            all_lines    = hits,
            co_occurring = co_occurring,
            risk_score   = risk,
            risk_factors = factors,
        )

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @property
    def indexer(self) -> Optional[LineIndexer]:
        """Expose the underlying LineIndexer (read-only)."""
        return self._indexer

    def summary(self) -> Dict[str, int]:
        """Return {entity_type: unique_count} summary dict."""
        if self._indexer is None:
            return {}
        counts: Dict[str, int] = {}
        for (et, _val) in self._indexer.index:
            counts[et] = counts.get(et, 0) + 1
        return dict(sorted(counts.items()))
