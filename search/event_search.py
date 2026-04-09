"""search/event_search.py — Structured search and filtering over Alert/StatResult objects."""
from __future__ import annotations

import ipaddress
import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("threattrace.search")


# ---------------------------------------------------------------------------
# PivotResult / AttackChain dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PivotResult:
    """Aggregated view of all activity for a single IP or username."""
    entity_type: str
    entity_value: str
    total_events: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    unique_rules: List[str] = field(default_factory=list)
    severity_breakdown: Dict[str, int] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    log_sources: List[str] = field(default_factory=list)
    top_alerts: List[Any] = field(default_factory=list)


@dataclass
class AttackChain:
    """A reconstructed multi-stage attack chain."""
    chain_id: str
    stages: List[Dict[str, Any]] = field(default_factory=list)
    kill_chain_score: float = 0.0
    duration_seconds: int = 0
    log_sources: List[str] = field(default_factory=list)
    primary_actor_ip: str = ""


# ---------------------------------------------------------------------------
# EventSearchEngine
# ---------------------------------------------------------------------------

class EventSearchEngine:
    """Structured search, filtering, and pivot analysis over detection alerts."""

    def __init__(
        self,
        alerts: List[Any],
        stat_results: List[Any],
        log_records: List[Any],
    ) -> None:
        """Initialise with alerts, stat results, and raw log records."""
        self.alerts = list(alerts) if alerts else []
        self.stat_results = list(stat_results) if stat_results else []
        self.log_records = list(log_records) if log_records else []

        # Build internal indices
        self._by_ip: Dict[str, List[Any]] = defaultdict(list)
        self._by_user: Dict[str, List[Any]] = defaultdict(list)
        self._by_rule: Dict[str, List[Any]] = defaultdict(list)
        self._by_severity: Dict[str, List[Any]] = defaultdict(list)
        self._by_mitre: Dict[str, List[Any]] = defaultdict(list)
        self._by_log_type: Dict[str, List[Any]] = defaultdict(list)

        for alert in self.alerts:
            src_ip = str(getattr(alert, "source_ip", "") or getattr(alert, "log_source", "") or "")
            username = str(getattr(alert, "username", "") or "")
            rule = str(getattr(alert, "rule_name", "") or "")
            sev = str(getattr(alert, "severity", "") or "").upper()
            tactic = str(getattr(alert, "mitre_tactic", "") or "")
            lt = str(getattr(alert, "log_type", "") or getattr(alert, "log_source", "") or "")

            if src_ip:
                self._by_ip[src_ip].append(alert)
            if username:
                self._by_user[username].append(alert)
            if rule:
                self._by_rule[rule].append(alert)
            if sev:
                self._by_severity[sev].append(alert)
            if tactic:
                self._by_mitre[tactic].append(alert)
            if lt:
                self._by_log_type[lt].append(alert)

        # Timeline (sorted by timestamp ascending)
        def _alert_ts(a: Any) -> datetime:
            ts = getattr(a, "timestamp", None)
            if isinstance(ts, datetime):
                return ts
            return datetime.min.replace(tzinfo=timezone.utc)

        self._timeline: List[Any] = sorted(self.alerts, key=_alert_ts)

    # ------------------------------------------------------------------
    # Filter
    # ------------------------------------------------------------------

    def filter(
        self,
        event_type: Optional[str] = None,
        severity: Optional[List[str]] = None,
        from_time: Optional[datetime] = None,
        to_time: Optional[datetime] = None,
        src_ip: Optional[str] = None,
        username: Optional[str] = None,
        log_type: Optional[str] = None,
        mitre_tactic: Optional[str] = None,
        mitre_technique: Optional[str] = None,
        ioc: Optional[str] = None,
        deduplicate: bool = False,
    ) -> List[Any]:
        """Filter alerts with AND logic across all provided parameters."""
        results = list(self.alerts)

        if event_type:
            pattern = event_type.lower()
            results = [
                a for a in results
                if pattern in str(getattr(a, "rule_name", "") or "").lower()
            ]

        if severity:
            sev_set = {s.upper() for s in severity}
            results = [
                a for a in results
                if str(getattr(a, "severity", "") or "").upper() in sev_set
            ]

        if from_time:
            def _ts_gte(a: Any) -> bool:
                ts = getattr(a, "timestamp", None)
                if not isinstance(ts, datetime):
                    return True
                # make comparable (strip/add tz)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                ft = from_time
                if ft.tzinfo is None:
                    ft = ft.replace(tzinfo=timezone.utc)
                return ts >= ft
            results = [a for a in results if _ts_gte(a)]

        if to_time:
            def _ts_lte(a: Any) -> bool:
                ts = getattr(a, "timestamp", None)
                if not isinstance(ts, datetime):
                    return True
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                tt = to_time
                if tt.tzinfo is None:
                    tt = tt.replace(tzinfo=timezone.utc)
                return ts <= tt
            results = [a for a in results if _ts_lte(a)]

        if src_ip:
            try:
                net = ipaddress.ip_network(src_ip, strict=False)
                def _ip_match(a: Any) -> bool:
                    ip_str = getattr(a, "source_ip", None) or getattr(a, "log_source", None) or ""
                    if not ip_str:
                        return False
                    try:
                        return ipaddress.ip_address(ip_str.split(":")[0]) in net
                    except ValueError:
                        return ip_str == src_ip
                results = [a for a in results if _ip_match(a)]
            except ValueError:
                # Not a valid CIDR — do exact match
                results = [
                    a for a in results
                    if (getattr(a, "source_ip", "") or "") == src_ip
                ]

        if username:
            uname = username.lower()
            results = [
                a for a in results
                if uname in str(getattr(a, "username", "") or "").lower()
            ]

        if log_type:
            lt_lower = log_type.lower()
            results = [
                a for a in results
                if lt_lower in str(
                    getattr(a, "log_type", "") or getattr(a, "log_source", "") or ""
                ).lower()
            ]

        if mitre_tactic:
            tactic_lower = mitre_tactic.lower()
            results = [
                a for a in results
                if tactic_lower in str(getattr(a, "mitre_tactic", "") or "").lower()
            ]

        if mitre_technique:
            tech_lower = mitre_technique.lower()
            results = [
                a for a in results
                if tech_lower in str(getattr(a, "mitre_technique", "") or "").lower()
            ]

        if ioc:
            ioc_lower = ioc.lower()
            def _ioc_match(a: Any) -> bool:
                iocs = getattr(a, "iocs", None) or []
                if any(ioc_lower in str(i).lower() for i in iocs):
                    return True
                return ioc_lower in str(getattr(a, "matched_line", "") or "").lower()
            results = [a for a in results if _ioc_match(a)]

        if deduplicate:
            results = self._deduplicate(results)

        # Sort by timestamp descending
        def _ts_sort(a: Any) -> datetime:
            ts = getattr(a, "timestamp", None)
            if isinstance(ts, datetime):
                if ts.tzinfo is None:
                    return ts.replace(tzinfo=timezone.utc)
                return ts
            return datetime.min.replace(tzinfo=timezone.utc)

        results.sort(key=_ts_sort, reverse=True)
        return results

    def _deduplicate(self, alerts: List[Any]) -> List[Any]:
        """Collapse alerts with same rule_name + source_ip within 60-second windows."""
        seen: Dict[Tuple[str, str], datetime] = {}
        deduped: List[Any] = []
        for alert in alerts:
            rule = str(getattr(alert, "rule_name", "") or "")
            src_ip = str(getattr(alert, "source_ip", "") or "")
            key = (rule, src_ip)
            ts = getattr(alert, "timestamp", None)
            if not isinstance(ts, datetime):
                deduped.append(alert)
                continue
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if key in seen:
                delta = abs((ts - seen[key]).total_seconds())
                if delta <= 60:
                    # Collapse: bump count in extra dict
                    if hasattr(alert, "extra") and isinstance(getattr(alert, "extra", None), dict):
                        alert.extra["count"] = alert.extra.get("count", 1) + 1
                    continue
            seen[key] = ts
            deduped.append(alert)
        return deduped

    # ------------------------------------------------------------------
    # Pivot analysis
    # ------------------------------------------------------------------

    def pivot_by_ip(self, ip: str) -> PivotResult:
        """Build a comprehensive view of all activity for a specific IP address."""
        matched = [
            a for a in self.alerts
            if (getattr(a, "source_ip", "") or "") == ip
        ]
        log_recs = [
            r for r in self.log_records
            if (getattr(r, "source_ip", "") or "") == ip
        ]
        return self._build_pivot("ip", ip, matched, log_recs)

    def pivot_by_user(self, username: str) -> PivotResult:
        """Build a comprehensive view of all activity for a specific username."""
        uname = username.lower()
        matched = [
            a for a in self.alerts
            if uname in str(getattr(a, "username", "") or "").lower()
        ]
        log_recs = [
            r for r in self.log_records
            if uname in str(getattr(r, "username", "") or "").lower()
        ]
        return self._build_pivot("user", username, matched, log_recs)

    def _build_pivot(
        self,
        entity_type: str,
        entity_value: str,
        matched_alerts: List[Any],
        matched_records: List[Any],
    ) -> PivotResult:
        """Construct a PivotResult from matched alerts and records."""
        from collections import Counter

        timestamps = [
            getattr(a, "timestamp", None)
            for a in matched_alerts
            if isinstance(getattr(a, "timestamp", None), datetime)
        ]
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None

        rules = list({str(getattr(a, "rule_name", "") or "") for a in matched_alerts if getattr(a, "rule_name", None)})
        sev_counter: Counter = Counter(
            str(getattr(a, "severity", "") or "").upper()
            for a in matched_alerts
        )
        mitre = list({str(getattr(a, "mitre_technique", "") or "") for a in matched_alerts if getattr(a, "mitre_technique", None)})
        sources = list({
            str(getattr(a, "log_type", "") or getattr(a, "log_source", "") or "")
            for a in matched_alerts
            if getattr(a, "log_type", None) or getattr(a, "log_source", None)
        })

        # Top 10 by severity sort
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "INFORMATIONAL": 5}
        top_alerts = sorted(
            matched_alerts,
            key=lambda a: sev_order.get(str(getattr(a, "severity", "") or "").upper(), 99),
        )[:10]

        return PivotResult(
            entity_type=entity_type,
            entity_value=entity_value,
            total_events=len(matched_alerts) + len(matched_records),
            first_seen=first_seen,
            last_seen=last_seen,
            unique_rules=rules,
            severity_breakdown=dict(sev_counter),
            mitre_techniques=mitre,
            log_sources=sources,
            top_alerts=top_alerts,
        )

    # ------------------------------------------------------------------
    # Attack chain
    # ------------------------------------------------------------------

    def get_attack_chain(self, chain_id: str) -> AttackChain:
        """Reconstruct an attack chain from stat_results timeline data."""
        chain_alerts: List[Any] = []
        for sr in self.stat_results:
            data = getattr(sr, "data", {}) or {}
            if chain_id in str(data):
                anom = getattr(sr, "anomalies", []) or []
                chain_alerts.extend(anom)

        # Also grab alerts whose description/rule_name mentions the chain_id
        for alert in self.alerts:
            if chain_id in str(getattr(alert, "rule_name", "") or ""):
                chain_alerts.append(alert)
            elif chain_id in str(getattr(alert, "description", "") or ""):
                chain_alerts.append(alert)

        if not chain_alerts:
            return AttackChain(chain_id=chain_id, stages=[], kill_chain_score=0.0)

        timestamps = [
            getattr(a, "timestamp", None)
            for a in chain_alerts
            if isinstance(getattr(a, "timestamp", None), datetime)
        ]
        duration = 0
        if len(timestamps) >= 2:
            duration = int((max(timestamps) - min(timestamps)).total_seconds())

        stages_map: Dict[str, List[Any]] = defaultdict(list)
        for a in chain_alerts:
            stage = str(getattr(a, "mitre_tactic", "") or "Unknown")
            stages_map[stage].append(a)

        stages = [
            {"stage": s, "alerts": alerts_list}
            for s, alerts_list in stages_map.items()
        ]

        sources = list({
            str(getattr(a, "log_type", "") or getattr(a, "log_source", "") or "")
            for a in chain_alerts
        })

        ips: Dict[str, int] = defaultdict(int)
        for a in chain_alerts:
            ip = str(getattr(a, "source_ip", "") or "")
            if ip:
                ips[ip] += 1
        primary_ip = max(ips, key=lambda k: ips[k]) if ips else ""

        score = min(1.0, len(stages) / max(len(stages_map), 1))

        return AttackChain(
            chain_id=chain_id,
            stages=stages,
            kill_chain_score=score,
            duration_seconds=duration,
            log_sources=sources,
            primary_actor_ip=primary_ip,
        )

    # ------------------------------------------------------------------
    # Heatmap
    # ------------------------------------------------------------------

    def get_event_heatmap(self, bucket: str = "hour") -> Dict[str, Dict[str, int]]:
        """Return nested dict {rule_name: {time_bucket: count}} for heatmap rendering."""
        heatmap: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        fmt_map = {"hour": "%Y-%m-%d %H:00", "minute": "%Y-%m-%d %H:%M", "day": "%Y-%m-%d"}
        fmt = fmt_map.get(bucket, "%Y-%m-%d %H:00")

        for alert in self.alerts:
            rule = str(getattr(alert, "rule_name", "") or "unknown")
            ts = getattr(alert, "timestamp", None)
            if isinstance(ts, datetime):
                bucket_key = ts.strftime(fmt)
            else:
                bucket_key = "unknown"
            heatmap[rule][bucket_key] += 1

        return {k: dict(v) for k, v in heatmap.items()}

    # ------------------------------------------------------------------
    # IOC search
    # ------------------------------------------------------------------

    def search_by_ioc(self, ioc: str) -> List[Any]:
        """Search Alert.iocs and LogRecord.raw_line for an IOC string."""
        ioc_lower = ioc.lower()
        seen_ids: set = set()
        results: List[Any] = []

        for alert in self.alerts:
            iocs = getattr(alert, "iocs", None) or []
            matched_line = str(getattr(alert, "matched_line", "") or "")
            if (
                any(ioc_lower in str(i).lower() for i in iocs)
                or ioc_lower in matched_line.lower()
            ):
                aid = id(alert)
                if aid not in seen_ids:
                    seen_ids.add(aid)
                    results.append(alert)

        for record in self.log_records:
            raw = str(getattr(record, "raw_line", "") or "")
            if ioc_lower in raw.lower():
                rid = id(record)
                if rid not in seen_ids:
                    seen_ids.add(rid)
                    results.append(record)

        def _ts_key(obj: Any) -> datetime:
            ts = getattr(obj, "timestamp", None)
            if isinstance(ts, datetime):
                return ts
            return datetime.min

        results.sort(key=_ts_key)
        return results

    # ------------------------------------------------------------------
    # Severity timeline
    # ------------------------------------------------------------------

    def get_severity_timeline(
        self,
        from_time: Optional[datetime] = None,
        to_time: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Return hourly severity counts for sparkline rendering."""
        from collections import Counter

        buckets: Dict[Tuple[str, str], int] = defaultdict(int)

        for alert in self.alerts:
            ts = getattr(alert, "timestamp", None)
            if not isinstance(ts, datetime):
                continue
            if from_time and ts < from_time:
                continue
            if to_time and ts > to_time:
                continue
            hour_key = ts.strftime("%Y-%m-%d %H:00")
            sev = str(getattr(alert, "severity", "") or "INFO").upper()
            buckets[(hour_key, sev)] += 1

        result: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for (hour, sev), cnt in buckets.items():
            result[hour][sev] += cnt

        timeline = []
        for hour in sorted(result.keys()):
            for sev, cnt in result[hour].items():
                timeline.append({"timestamp": hour, "severity": sev, "count": cnt})

        return timeline

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_filtered(
        self,
        alerts: List[Any],
        output_path: str,
        format: str = "json",
    ) -> None:
        """Export filtered alerts to JSON or CSV."""
        from rich.console import Console
        from rich.panel import Panel
        import pandas as pd

        console = Console()
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            data = []
            for a in alerts:
                if hasattr(a, "to_dict"):
                    data.append(a.to_dict())
                else:
                    data.append({
                        "rule_name": str(getattr(a, "rule_name", "") or ""),
                        "severity": str(getattr(a, "severity", "") or ""),
                        "timestamp": str(getattr(a, "timestamp", "") or ""),
                        "description": str(getattr(a, "description", "") or ""),
                    })
            out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        elif format == "csv":
            rows = []
            for a in alerts:
                if hasattr(a, "to_dict"):
                    rows.append(a.to_dict())
                else:
                    rows.append({
                        "rule_name": str(getattr(a, "rule_name", "") or ""),
                        "severity": str(getattr(a, "severity", "") or ""),
                        "timestamp": str(getattr(a, "timestamp", "") or ""),
                    })
            df = pd.DataFrame(rows)
            df.to_csv(str(out), index=False)

        console.print(Panel(
            f"[green]Exported {len(alerts):,} results → {out}[/green]",
            title="Export Complete",
            border_style="green",
        ))
