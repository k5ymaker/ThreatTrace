"""
analytics/orchestrator.py — Analytics Orchestrator

Entry point for the full analytics pipeline. Converts raw event dicts to
LogRecord objects, runs all five analytics modules, renders Rich terminal
output, and returns the merged StatResult list.

Usage
-----
from analytics.orchestrator import AnalyticsOrchestrator

results = AnalyticsOrchestrator().run_all(
    events=all_events,        # List[Dict] from parser_router
    log_type="apache",
    all_sources=None,         # Optional Dict[str, List[Dict]] for timeline
)
"""
from __future__ import annotations

import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from core.models import LogRecord, StatResult, dict_to_log_record
from analytics.baseline import BaselineProfiler
from analytics.frequency import FrequencyAnalyzer
from analytics.beaconing import BeaconingDetector
from analytics.topn import TopNReporter
from analytics.timeline import TimelineBuilder

console = Console()

# ---------------------------------------------------------------------------
# Severity coloring
# ---------------------------------------------------------------------------
_SEV_COLOUR: Dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "INFO":     "dim",
}

_MODULE_ICONS: Dict[str, str] = {
    "baseline":    "📊",
    "frequency":   "📈",
    "beaconing":   "📡",
    "topn":        "🏆",
    "timeline":    "⏱",
    "correlation": "🔗",
}

# Log types that should trigger the Windows privilege escalation correlation engine
_WINDOWS_LOG_TYPES: frozenset = frozenset({
    "windows_security", "sysmon", "windows_event",
    "windows_evtx", "windows_system", "windows_powershell",
})


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class AnalyticsOrchestrator:
    """
    Runs all five analytics modules and aggregates results into a
    List[StatResult].  Modules run sequentially by default; pass
    parallel=True to use a ThreadPoolExecutor.
    """

    def __init__(
        self,
        baseline_cfg:  Optional[Dict[str, Any]] = None,
        frequency_cfg: Optional[Dict[str, Any]] = None,
        beaconing_cfg: Optional[Dict[str, Any]] = None,
        topn_cfg:      Optional[Dict[str, Any]] = None,
        timeline_cfg:  Optional[Dict[str, Any]] = None,
    ) -> None:
        self._baseline_cfg  = baseline_cfg
        self._frequency_cfg = frequency_cfg
        self._beaconing_cfg = beaconing_cfg
        self._topn_cfg      = topn_cfg
        self._timeline_cfg  = timeline_cfg

    # ------------------------------------------------------------------
    def run_all(
        self,
        events: List[Dict[str, Any]],
        log_type: str,
        all_sources: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        modules: Optional[List[str]] = None,
        parallel: bool = False,
    ) -> List[StatResult]:
        """
        Convert events → LogRecord, run selected modules, return results.

        Parameters
        ----------
        events      : flat list of event dicts from parser_router
        log_type    : detected log type string
        all_sources : optional {log_type: [event_dicts]} for timeline module
        modules     : subset of ["baseline","frequency","beaconing","topn","timeline"]
                      (default: all five)
        parallel    : run non-timeline modules concurrently
        """
        if modules is None:
            modules = ["baseline", "frequency", "beaconing", "topn", "timeline"]

        records = self._convert(events)

        # Build multi-source records for timeline
        all_records: Dict[str, List[LogRecord]] = {log_type: records}
        if all_sources:
            for lt, evs in all_sources.items():
                if lt != log_type:
                    all_records[lt] = self._convert(evs)

        results: List[StatResult] = []

        if parallel and len(modules) > 1:
            results = self._run_parallel(records, log_type, all_records, modules)
        else:
            results = self._run_sequential(records, log_type, all_records, modules)

        # Run Windows privilege-escalation correlation engine for Windows log types
        if log_type in _WINDOWS_LOG_TYPES:
            corr_result = self._run_privesc_correlation(records, log_type)
            if corr_result is not None:
                results.append(corr_result)

        return results

    # ------------------------------------------------------------------
    def _convert(self, events: List[Dict[str, Any]]) -> List[LogRecord]:
        """Convert a list of event dicts to LogRecord objects."""
        records: List[LogRecord] = []
        for i, ev in enumerate(events):
            try:
                records.append(dict_to_log_record(ev, idx=i))
            except Exception:
                pass
        return records

    # ------------------------------------------------------------------
    def _run_sequential(
        self,
        records: List[LogRecord],
        log_type: str,
        all_records: Dict[str, List[LogRecord]],
        modules: List[str],
    ) -> List[StatResult]:
        results: List[StatResult] = []
        for name in modules:
            r = self._run_one(name, records, log_type, all_records)
            if r is not None:
                results.append(r)
        return results

    def _run_parallel(
        self,
        records: List[LogRecord],
        log_type: str,
        all_records: Dict[str, List[LogRecord]],
        modules: List[str],
    ) -> List[StatResult]:
        results: List[StatResult] = []
        # Timeline always runs last (needs all sources)
        non_tl = [m for m in modules if m != "timeline"]
        tl     = [m for m in modules if m == "timeline"]

        with ThreadPoolExecutor(max_workers=min(4, len(non_tl))) as ex:
            futures = {
                ex.submit(self._run_one, name, records, log_type, all_records): name
                for name in non_tl
            }
            for fut in as_completed(futures):
                r = fut.result()
                if r is not None:
                    results.append(r)

        for name in tl:
            r = self._run_one(name, records, log_type, all_records)
            if r is not None:
                results.append(r)

        # Sort by canonical module order
        _order = {"baseline": 0, "frequency": 1, "beaconing": 2, "topn": 3, "timeline": 4}
        results.sort(key=lambda r: _order.get(r.module, 9))
        return results

    # ------------------------------------------------------------------
    def _run_one(
        self,
        name: str,
        records: List[LogRecord],
        log_type: str,
        all_records: Dict[str, List[LogRecord]],
    ) -> Optional[StatResult]:
        try:
            if name == "baseline":
                return BaselineProfiler(self._baseline_cfg).run(records, log_type)
            if name == "frequency":
                return FrequencyAnalyzer(self._frequency_cfg).run(records, log_type)
            if name == "beaconing":
                return BeaconingDetector(self._beaconing_cfg).run(records, log_type)
            if name == "topn":
                return TopNReporter(self._topn_cfg).run(records, log_type)
            if name == "timeline":
                return TimelineBuilder(self._timeline_cfg).run(all_records)
        except Exception as exc:
            console.print(
                f"[yellow]Analytics warning:[/yellow] module '{name}' failed — "
                f"{type(exc).__name__}: {exc}"
            )
            if console.is_terminal:
                traceback.print_exc()
        return None

    # ------------------------------------------------------------------
    def _run_privesc_correlation(
        self,
        records: List[LogRecord],
        log_type: str,
    ) -> Optional[StatResult]:
        """Run the Windows privilege-escalation correlation engine."""
        try:
            from analytics.correlations.privesc_chains import PrivEscCorrelationEngine
        except ImportError:
            return None

        try:
            corr_engine = PrivEscCorrelationEngine()
            corr_alerts = corr_engine.evaluate(records)

            severity = (
                "CRITICAL" if any(a.severity == "CRITICAL" for a in corr_alerts)
                else "HIGH"  if any(a.severity == "HIGH"     for a in corr_alerts)
                else "INFO"
            )

            return StatResult(
                module="correlation",
                log_type=log_type,
                title="Privilege Escalation — Attack Chain Correlation",
                severity=severity,
                description=(
                    f"{len(corr_alerts)} attack chain(s) detected "
                    f"across {len(records)} records."
                ),
                data={
                    "chains": [
                        {
                            "chain_id":       a.rule_name,
                            "attack_name":    a.rule_name,
                            "mitre_technique": a.mitre_technique,
                            "severity":       a.severity,
                            "description":    a.description,
                            "iocs":           a.iocs,
                            "recommendation": a.recommended_action,
                            "matched_events": a.matched_line[:500] if a.matched_line else "",
                            "timestamp":      a.timestamp.isoformat() if a.timestamp else "",
                        }
                        for a in corr_alerts
                    ],
                    "total_chains":   len(corr_alerts),
                    "records_scanned": len(records),
                },
                anomalies=[
                    {
                        "rule":      a.rule_name,
                        "severity":  a.severity,
                        "technique": a.mitre_technique,
                        "iocs":      a.iocs,
                    }
                    for a in corr_alerts
                ],
                generated_at=datetime.now(timezone.utc),
            )
        except Exception as exc:
            console.print(
                f"[yellow]Correlation warning:[/yellow] PrivEsc engine failed — "
                f"{type(exc).__name__}: {exc}"
            )
            return None


# ---------------------------------------------------------------------------
# Terminal renderer
# ---------------------------------------------------------------------------

def render_analytics_terminal(results: List[StatResult]) -> None:
    """
    Print a Rich-formatted summary of all StatResult objects to the terminal.
    Called after the main detection pipeline output.
    """
    if not results:
        return

    console.print()
    console.rule("[bold cyan]  Analytics Results  [/bold cyan]", style="cyan")

    for result in results:
        _render_one(result)

    console.print()


def _render_one(result: StatResult) -> None:
    icon = _MODULE_ICONS.get(result.module, "•")
    sev_colour = _SEV_COLOUR.get(result.severity, "white")
    sev_badge = f"[{sev_colour}]{result.severity}[/{sev_colour}]"

    # Header panel
    header = (
        f"{icon}  [bold]{result.title}[/bold]\n"
        f"[dim]{result.description}[/dim]   {sev_badge}"
    )
    console.print(Panel(header, border_style="cyan", padding=(0, 1)))

    mod = result.module

    if mod == "baseline":
        _render_baseline(result)
    elif mod == "frequency":
        _render_frequency(result)
    elif mod == "beaconing":
        _render_beaconing(result)
    elif mod == "topn":
        _render_topn(result)
    elif mod == "timeline":
        _render_timeline(result)
    elif mod == "correlation":
        _render_correlation(result)


# ---------------------------------------------------------------------------
# Per-module renderers
# ---------------------------------------------------------------------------

def _render_baseline(r: StatResult) -> None:
    devs = r.data.get("deviations_detected", [])
    if not devs:
        console.print("[dim]  No deviations detected.[/dim]\n")
        return

    t = Table(
        box=box.SIMPLE_HEAVY, show_header=True,
        header_style="bold cyan", border_style="cyan",
        title=f"Top Baseline Deviations (showing {min(10, len(devs))} of {len(devs)})",
    )
    t.add_column("Dimension",      style="cyan",       min_width=28)
    t.add_column("Observed",       style="bold white",  min_width=12, justify="right")
    t.add_column("Baseline Mean",  style="dim",         min_width=12, justify="right")
    t.add_column("σ Distance",     style="bold yellow", min_width=10, justify="right")
    t.add_column("Source IP",      style="dim",         min_width=15)
    t.add_column("Timestamp",      style="dim",         min_width=19)

    for d in devs[:10]:
        sigma = d.get("sigma_distance", 0)
        colour = "bold red" if sigma >= 100 else "red" if sigma >= 20 else "yellow"
        t.add_row(
            d.get("dimension", ""),
            f"{d.get('observed_value', 0):,.2f}",
            f"{d.get('baseline_mean', 0):,.2f}",
            f"[{colour}]{sigma:.1f}σ[/{colour}]",
            d.get("source_ip", ""),
            d.get("timestamp", "")[:19],
        )
    console.print(t)
    console.print()


def _render_frequency(r: StatResult) -> None:
    ff = r.data.get("field_frequencies", {})
    if not ff:
        console.print("[dim]  No frequency data.[/dim]\n")
        return

    for field_name, fd in ff.items():
        high = fd.get("high_freq_outliers", [])
        low  = fd.get("low_freq_outliers", [])
        if not high and not low:
            continue

        console.print(
            f"  [bold cyan]FIELD: {field_name}[/bold cyan]"
            f"  [dim]({fd.get('total_unique_values', 0)} unique · "
            f"mean={fd.get('mean_frequency', 0):.1f} · "
            f"IQR={fd.get('Q1', 0):.0f}–{fd.get('Q3', 0):.0f})[/dim]"
        )
        if high:
            t = Table(box=box.MINIMAL, show_header=True, header_style="bold red")
            t.add_column("Value",   style="bold white", min_width=80 if field_name == "user_agent" else 30)
            t.add_column("Count",   justify="right")
            t.add_column("Z-Score", justify="right", style="red")
            for item in high[:5]:
                # Show full string for user_agent field; truncate others
                val = str(item["value"])
                val_display = val if field_name == "user_agent" else val[:50]
                t.add_row(
                    val_display,
                    f"{item['count']:,}",
                    f"{item.get('z_score', 0):.1f}",
                )
            console.print("  [bold red]HIGH-FREQ OUTLIERS[/bold red]")
            console.print(t)
        if low:
            console.print("  [yellow]LOW-FREQ OUTLIERS[/yellow]")
            for item in low[:3]:
                console.print(f"  [dim]  {item['value']}  (count: {item['count']})[/dim]")
        console.print()


def _render_beaconing(r: StatResult) -> None:
    candidates = r.data.get("beacon_candidates", [])
    if not candidates:
        console.print("[dim]  No beaconing candidates detected.[/dim]\n")
        return

    for idx, b in enumerate(candidates[:5], 1):
        score = b.get("beacon_score", 0)
        sev = b.get("severity", "LOW")
        colour = _SEV_COLOUR.get(sev, "white")
        methods = ", ".join(b.get("methods_flagged", []))

        t = Table(box=box.SIMPLE, show_header=False, border_style=colour, padding=(0, 1))
        t.add_column("K", style="dim",       width=20)
        t.add_column("V", style="bold white")
        t.add_row("Source",       b.get("src_ip", ""))
        t.add_row("Destination",  b.get("dst_ip_or_domain", ""))
        t.add_row("Connections",  f"{b.get('total_connections', 0):,}  over {b.get('time_span_hours', 0):.1f}h")
        t.add_row("Interval",     f"{b.get('mean_interval_seconds', 0):.1f}s mean  ± {b.get('std_dev_seconds', 0):.1f}s")
        t.add_row("Jitter CV",    f"{b.get('jitter_cv', 0):.3f}  {'✓' if b.get('jitter_cv', 1) < 0.35 else '✗'}")
        t.add_row("Autocorr",     f"{b.get('autocorrelation_score', 0):.3f}  {'✓' if b.get('autocorrelation_score', 0) >= 0.75 else '✗'}")
        t.add_row("Methods Hit",  methods)
        t.add_row("Score",        f"[{colour}]{score:.3f}  {sev}[/{colour}]")
        t.add_row("First Seen",   b.get("first_seen", "")[:19])
        t.add_row("Last Seen",    b.get("last_seen",  "")[:19])

        console.print(Panel(
            t,
            title=f"[{colour}]BEACON #{idx}[/{colour}]",
            border_style=colour,
        ))
    console.print()


def _render_topn(r: StatResult) -> None:
    tables = r.data.get("tables", {})
    if not tables:
        console.print("[dim]  No Top-N data.[/dim]\n")
        return

    for field_name, rows in list(tables.items())[:4]:
        if not rows:
            continue
        t = Table(
            box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan",
            title=f"Top {len(rows)} — {field_name}",
        )
        val_col_width = 80 if field_name == "user_agent" else 30
        t.add_column("#",      width=4,  justify="right")
        t.add_column("Value",  min_width=val_col_width, style="bold white")
        t.add_column("Count",  min_width=8,  justify="right")
        t.add_column("%",      min_width=7,  justify="right")
        t.add_column("Cum%",   min_width=7,  justify="right")

        for row in rows[:10]:
            flag = "⚠  " if row.get("flagged") else ""
            raw_val = str(row["value"])
            # Show full string for user_agent; truncate other fields to 60 chars
            display_val = raw_val if field_name == "user_agent" else raw_val[:60]
            val_str = f"[bold yellow]{flag}{display_val}[/bold yellow]" if row.get("flagged") else display_val
            t.add_row(
                str(row["rank"]),
                val_str,
                f"{row['count']:,}",
                f"{row['percentage']:.1f}%",
                f"{row['cumulative_pct']:.1f}%",
            )
        console.print(t)

    # Peak time window
    windows = r.data.get("time_windows", {}).get("1hour", [])
    if windows:
        top_w = windows[0]
        console.print(
            f"  [bold cyan]Peak hour:[/bold cyan] "
            f"{top_w.get('window_start', '')[:16]} → "
            f"{top_w.get('event_count', 0):,} events  "
            f"[dim](anomaly score: {top_w.get('anomaly_score', 0):.2f})[/dim]"
        )
    console.print()


def _render_timeline(r: StatResult) -> None:
    chains = r.data.get("attack_chains", [])
    summary = r.data.get("summary", {})

    console.print(
        f"  [bold cyan]Events correlated:[/bold cyan] "
        f"{summary.get('total_events_correlated', 0):,}  │  "
        f"[bold cyan]Attack chains:[/bold cyan] "
        f"{summary.get('attack_chains_identified', 0)}  │  "
        f"[bold cyan]Timespan:[/bold cyan] "
        f"{summary.get('total_timespan_hours', 0):.1f}h"
    )

    if not chains:
        console.print("[dim]  No multi-stage attack chains identified.[/dim]\n")
        return

    for chain in chains[:3]:
        completeness = chain.get("kill_chain_completeness_pct", 0)
        colour = "bold red" if completeness >= 50 else "red" if completeness >= 25 else "yellow"
        stages = " → ".join(chain.get("stages_observed", []))

        t = Table(box=box.SIMPLE, show_header=False, border_style=colour, padding=(0, 1))
        t.add_column("K", width=22, style="dim")
        t.add_column("V", style="bold white")
        t.add_row("Chain ID",       chain.get("chain_id", ""))
        t.add_row("Pivot",          f"{chain.get('pivot_type', '')} = {chain.get('pivot_value', '')}")
        t.add_row("Events",         str(chain.get("events_count", 0)))
        t.add_row("Duration",       f"{chain.get('duration_hours', 0):.2f}h")
        t.add_row("Stages",         stages[:80])
        t.add_row("Kill Chain",     f"[{colour}]{completeness:.0f}%[/{colour}]")
        t.add_row("Log Sources",    ", ".join(chain.get("log_sources_involved", [])))

        console.print(Panel(
            t,
            title=f"[{colour}]CHAIN: {chain.get('pivot_value', '')}[/{colour}]",
            border_style=colour,
        ))

    console.print()


def _render_correlation(r: StatResult) -> None:
    """Render Windows privilege-escalation correlation results."""
    chains = r.data.get("chains", [])
    total = r.data.get("total_chains", 0)
    scanned = r.data.get("records_scanned", 0)

    console.print(
        f"  [bold cyan]Records scanned:[/bold cyan] {scanned:,}  │  "
        f"[bold cyan]Chains detected:[/bold cyan] {total}"
    )

    if not chains:
        console.print(
            "[dim]  No privilege escalation attack chains detected.[/dim]\n"
        )
        return

    for c in chains:
        sev = c.get("severity", "HIGH")
        colour = _SEV_COLOUR.get(sev, "white")
        iocs_str = ", ".join(c.get("iocs", [])[:8]) or "—"
        ts = c.get("timestamp", "")[:19]

        t = Table(
            box=box.SIMPLE, show_header=False,
            border_style=colour, padding=(0, 1),
        )
        t.add_column("K", style="dim",       width=22)
        t.add_column("V", style="bold white", overflow="fold")

        t.add_row("Attack",       c.get("attack_name",    ""))
        t.add_row("Technique",    c.get("mitre_technique",""))
        t.add_row("Severity",     f"[{colour}]{sev}[/{colour}]")
        t.add_row("Timestamp",    ts)
        t.add_row("Description",  c.get("description", "")[:120])
        t.add_row("IOCs",         iocs_str)
        t.add_row("Action",       c.get("recommendation", "")[:110])

        console.print(Panel(
            t,
            title=f"[{colour}]⚠  PRIVESC CHAIN DETECTED[/{colour}]",
            border_style=colour,
        ))

    console.print()
