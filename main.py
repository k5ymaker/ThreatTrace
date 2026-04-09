"""
main.py — ThreatTrace v2.0 entry point.

MODE A — Click CLI (non-interactive):
    python main.py --path /var/log/apache2/access.log
    python main.py --path /var/log/ --recursive
    python main.py --path /logs/windows_events.evtx --output /reports/
    python main.py --path /logs/ --analyst "Jane Doe" --tlp RED --format both

MODE B — Interactive (no args):
    python main.py

Run from the project root directory.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path so local packages resolve correctly
# ---------------------------------------------------------------------------
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

console = Console()

# ---------------------------------------------------------------------------
# Large-file streaming thresholds
# ---------------------------------------------------------------------------
# Files larger than this are processed in chunks to avoid OOM on 3GB+ logs.
_LARGE_FILE_BYTES: int = 200 * 1024 * 1024    # 200 MB
_DEFAULT_CHUNK_SIZE: int = 50_000              # events per batch
# Analytics modules only see up to this many events (representative sample).
_ANALYTICS_SAMPLE_CAP: int = 200_000

# ---------------------------------------------------------------------------
# Lazy imports — avoids slow startup when only --help is invoked
# ---------------------------------------------------------------------------

def _import_file_handler():
    from core.file_handler import load_files
    return load_files


def _import_auto_detector():
    from core.auto_detector import detect_deep
    return detect_deep


def _import_parser_router():
    from core.parser_router import parse_files
    return parse_files


def _import_menu():
    from core.menu import (
        run_interactive_menu,
        run_analysis_progress,
        show_analysis_complete_banner,
        print_static_banner,
        print_banner,
    )
    return run_interactive_menu, run_analysis_progress, show_analysis_complete_banner, print_static_banner, print_banner


def _import_analytics():
    """
    Lazy import for the analytics orchestrator + renderer.
    Returns (run_analytics, render_analytics) callables, or (None, None) stubs
    if dependencies are unavailable.
    """
    try:
        from analytics.orchestrator import AnalyticsOrchestrator, render_analytics_terminal

        def run_analytics(
            events: list,
            log_type: str,
            modules: list,
        ) -> list:
            return AnalyticsOrchestrator().run_all(
                events=events,
                log_type=log_type,
                modules=modules,
            )

        return run_analytics, render_analytics_terminal
    except Exception as exc:  # noqa: BLE001
        console.print(f"[dim yellow]Analytics unavailable: {exc}[/dim yellow]")

        def _noop_run(*_a, **_kw) -> list:
            return []

        def _noop_render(*_a, **_kw) -> None:
            pass

        return _noop_run, _noop_render


def _import_detection_engine():
    """
    Try to import the detection engine.
    Returns a callable run_analysis(events, log_type) or a no-op stub.
    """
    try:
        from threattrace.detectors.sigma_engine import SigmaEngine
        from threattrace.detectors.yara_engine import YaraEngine

        rules_root = Path(_ROOT) / "rules"

        sigma_engine = SigmaEngine(rules_root / "sigma")
        yara_engine  = YaraEngine(rules_root / "yara")

        def run_analysis(events: List[Dict[str, Any]], log_type: str) -> Dict[str, Any]:
            sigma_hits = sigma_engine.run(events)
            yara_hits  = yara_engine.run(events)
            return {
                "log_type":    log_type,
                "total_events": len(events),
                "sigma_hits":  sigma_hits,
                "yara_hits":   yara_hits,
                "events":      events,
            }

        return run_analysis
    except Exception:  # noqa: BLE001
        def run_analysis_stub(events: List[Dict[str, Any]], log_type: str) -> Dict[str, Any]:
            return {
                "log_type":     log_type,
                "total_events": len(events),
                "sigma_hits":   [],
                "yara_hits":    [],
                "events":       events,
            }
        return run_analysis_stub


def _import_report_builder():
    """
    Try to import the report builder.
    Returns a callable generate_reports(results, output_dir, fmt) or stub.
    """
    try:
        from core.report_builder import save_report

        def generate_reports(
            results: Dict[str, Any],
            output_dir: str,
            fmt: str,
        ) -> List[str]:
            analyst = results.get("analyst", "N/A")
            tlp = f"TLP:{results.get('tlp', 'AMBER')}"
            # save_report returns the primary path string
            saved = save_report(
                results,
                output_dir=output_dir,
                format_=fmt,
                events=results.get("events"),
                analyst=analyst,
                tlp=tlp,
            )
            return [saved] if saved else []

        return generate_reports
    except Exception:  # noqa: BLE001
        import json
        import datetime

        def generate_reports_stub(
            results: Dict[str, Any],
            output_dir: str,
            fmt: str,
        ) -> List[str]:
            out_dir = Path(output_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            ts  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            paths = []

            if fmt in ("json", "both"):
                json_path = out_dir / f"threattrace_report_{ts}.json"
                exportable = {
                    k: v for k, v in results.items()
                    if k != "events"  # skip raw events to keep file small
                }
                exportable["total_events"] = results.get("total_events", 0)
                json_path.write_text(
                    json.dumps(exportable, indent=2, default=str),
                    encoding="utf-8",
                )
                paths.append(str(json_path))

            if fmt in ("html", "both"):
                html_path = out_dir / f"threattrace_report_{ts}.html"
                sigma_count = len(results.get("sigma_hits", []))
                yara_count  = len(results.get("yara_hits", []))
                html_path.write_text(
                    f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ThreatTrace Report — {results.get('log_type','unknown')}</title>
  <style>
    body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2em; }}
    h1   {{ color: #58a6ff; }}
    h2   {{ color: #79c0ff; border-bottom: 1px solid #30363d; padding-bottom: .3em; }}
    table{{ border-collapse: collapse; width: 100%; }}
    th,td{{ border: 1px solid #30363d; padding: .4em .8em; text-align: left; }}
    th   {{ background: #161b22; color: #f0f6fc; }}
    .crit{{ color: #ff7b72; }}
    .high{{ color: #f85149; }}
    .med {{ color: #e3b341; }}
    .low {{ color: #56d364; }}
  </style>
</head>
<body>
  <h1>ThreatTrace Report</h1>
  <p><strong>Log Type:</strong> {results.get('log_type','unknown')}<br>
     <strong>Total Events:</strong> {results.get('total_events',0)}<br>
     <strong>Sigma Hits:</strong> {sigma_count}<br>
     <strong>YARA Hits:</strong> {yara_count}</p>
  <h2>Summary</h2>
  <p>Analysis complete. {sigma_count + yara_count} detection(s) fired.</p>
</body>
</html>""",
                    encoding="utf-8",
                )
                paths.append(str(html_path))

            return paths

        return generate_reports_stub


# ---------------------------------------------------------------------------
# Terminal summary printer
# ---------------------------------------------------------------------------

def _print_summary(results: Dict[str, Any], report_paths: List[str]) -> None:
    total      = results.get("total_events", 0)
    findings   = results.get("findings", [])
    sev        = results.get("findings_by_severity", {})
    risk       = results.get("overall_risk", "INFORMATIONAL")
    # legacy keys (old engine)
    sigma_hits = results.get("sigma_hits", [])
    yara_hits  = results.get("yara_hits", [])
    # prefer new findings count, fall back to old sigma+yara counts
    total_hits = len(findings) if findings else len(sigma_hits) + len(yara_hits)

    summary = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
        title="[bold cyan]  ThreatTrace Analysis Summary  [/bold cyan]",
        title_style="bold cyan",
        expand=False,
    )
    summary.add_column("Metric",  style="dim",       min_width=28)
    summary.add_column("Value",   style="bold white", min_width=14, justify="right")

    summary.add_row("Total Events Parsed", str(total))
    summary.add_row("Total Findings",      f"[yellow]{total_hits}[/yellow]")
    if sev:
        crit = sev.get("CRITICAL", 0)
        high = sev.get("HIGH", 0)
        med  = sev.get("MEDIUM", 0)
        if crit:
            summary.add_row("  Critical", f"[bold red]{crit}[/bold red]")
        if high:
            summary.add_row("  High",     f"[red]{high}[/red]")
        if med:
            summary.add_row("  Medium",   f"[yellow]{med}[/yellow]")
    summary.add_row("Overall Risk",        f"[bold]{risk}[/bold]")
    summary.add_row("Reports Generated",   str(len(report_paths)))

    console.print()
    console.print(summary)
    console.print()

    if report_paths:
        console.print("[bold cyan]ThreatTrace ›[/bold cyan] Reports saved:")
        for rp in report_paths:
            console.print(f"  [green]{rp}[/green]")
        console.print()


# ---------------------------------------------------------------------------
# Streaming helper for large files
# ---------------------------------------------------------------------------

def _parse_and_detect_streaming(
    file_descriptors: List[Dict[str, Any]],
    log_type: str,
    run_analysis_fn,
    chunk_size: int,
    total_bytes: int,
) -> tuple:
    """
    Stream-parse large files in chunks to avoid out-of-memory on 3 GB+ logs.

    Returns ``(sample_events, merged_results)`` where:
      - ``sample_events``  — up to _ANALYTICS_SAMPLE_CAP events for analytics
      - ``merged_results`` — detection findings accumulated across all chunks

    Detection is run on *every* chunk so nothing is missed.
    Analytics / reporting operate on the representative sample.
    """
    from core.parser_router import stream_file_chunked
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
    )

    all_findings:   List[Dict[str, Any]] = []
    all_sigma_hits: List[Any] = []
    all_yara_hits:  List[Any] = []
    sample_events:  List[Dict[str, Any]] = []
    total_events    = 0
    mb_processed    = 0.0

    mb_total = total_bytes / (1024 * 1024)
    console.print(
        f"[bold cyan]ThreatTrace ›[/bold cyan] "
        f"[yellow]Large file detected ({mb_total:.0f} MB) — enabling streaming mode.[/yellow]"
    )
    console.print(
        f"[bold cyan]ThreatTrace ›[/bold cyan] "
        f"[dim]Chunk size: {chunk_size:,} events · "
        f"Analytics sample cap: {_ANALYTICS_SAMPLE_CAP:,} events[/dim]"
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=28),
        TextColumn("[dim]{task.fields[ev]} events · {task.fields[mb]} MB read"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as prog:
        task_id = prog.add_task(
            "Streaming…",
            total=None,
            ev="0",
            mb="0.0",
        )

        for descriptor in file_descriptors:
            for chunk in stream_file_chunked(descriptor, log_type, chunk_size):
                if not chunk:
                    continue

                # Detection — runs on every chunk
                chunk_result = run_analysis_fn(chunk, log_type)
                all_findings.extend(chunk_result.get("findings", []))
                all_sigma_hits.extend(chunk_result.get("sigma_hits", []))
                all_yara_hits.extend(chunk_result.get("yara_hits", []))

                # Sample — keep up to _ANALYTICS_SAMPLE_CAP
                remaining = _ANALYTICS_SAMPLE_CAP - len(sample_events)
                if remaining > 0:
                    sample_events.extend(chunk[:remaining])

                # Progress
                total_events += len(chunk)
                mb_processed += sum(
                    len(str(e.get("raw", ""))) for e in chunk
                ) / (1024 * 1024)
                prog.update(
                    task_id,
                    ev=f"{total_events:,}",
                    mb=f"{mb_processed:.1f}",
                )

    # Severity breakdown and risk score from accumulated findings
    sev_counts: Dict[str, int] = {}
    for f in all_findings:
        sev = str(f.get("severity", "INFORMATIONAL")).upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    if sev_counts.get("CRITICAL", 0):
        risk = "CRITICAL"
    elif sev_counts.get("HIGH", 0):
        risk = "HIGH"
    elif sev_counts.get("MEDIUM", 0):
        risk = "MEDIUM"
    elif sev_counts.get("LOW", 0) or all_findings:
        risk = "LOW"
    else:
        risk = "INFORMATIONAL"

    console.print(
        f"[bold cyan]ThreatTrace ›[/bold cyan] Parsed "
        f"[bold]{total_events:,}[/bold] event(s) "
        f"[dim](streaming mode)[/dim]"
    )
    if len(sample_events) < total_events:
        console.print(
            f"[dim yellow]  ⚠  Analytics and report use a representative sample "
            f"of {len(sample_events):,} events "
            f"({len(sample_events) * 100 // max(total_events, 1)}% of total).[/dim yellow]"
        )

    merged: Dict[str, Any] = {
        "log_type":             log_type,
        "total_events":         total_events,
        "findings":             all_findings,
        "sigma_hits":           all_sigma_hits,
        "yara_hits":            all_yara_hits,
        "events":               sample_events,
        "findings_by_severity": sev_counts,
        "overall_risk":         risk,
    }
    return sample_events, merged


# ---------------------------------------------------------------------------
# Core analysis pipeline
# ---------------------------------------------------------------------------

def _run_analysis_pipeline(
    path: str,
    log_type: str,
    recursive: bool,
    output_dir: str,
    output_format: str,
    analyst: str,
    tlp: str,
    analytics_modules: Optional[List[str]] = None,
    chunk_size: int = _DEFAULT_CHUNK_SIZE,
    silent_summary: bool = False,
) -> Optional[List[str]]:
    """
    Full analysis pipeline:
      1. Load file(s)
      2. Auto-detect or use provided log_type
      3. Parse events
      4. Run detection engine
      5. Run analytics modules (baseline/frequency/beaconing/topn/timeline)
      6. Generate reports
      7. Print summary
    """
    load_files    = _import_file_handler()
    detect        = _import_auto_detector()
    parse_files   = _import_parser_router()
    run_analysis  = _import_detection_engine()
    gen_reports   = _import_report_builder()

    if analytics_modules is None:
        analytics_modules = ["baseline", "frequency", "beaconing", "topn", "timeline"]
    run_analytics, render_analytics = _import_analytics()

    # 1. Load
    try:
        file_descriptors = load_files(path, recursive=recursive)
    except FileNotFoundError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(1)

    if not file_descriptors:
        console.print("[yellow]No log files found at the specified path.[/yellow]")
        sys.exit(0)

    # 2. Detect / confirm log type
    resolved_log_type = log_type
    detection_meta: dict = {}
    if log_type == "auto" or not log_type:
        first_path = file_descriptors[0]["path"]
        detection  = detect(first_path)
        resolved_log_type = detection["log_type"]
        detection_meta = detection
        tier      = detection.get("tier", "UNKNOWN")
        structure = detection.get("structure", "")
        ruleset   = detection.get("ruleset", {})
        tier_colours = {
            "CONFIRMED": "bold green",
            "LIKELY":    "green",
            "POSSIBLE":  "yellow",
            "FALLBACK":  "dim yellow",
        }
        colour = tier_colours.get(tier, "white")
        console.print(
            f"[bold cyan]ThreatTrace ›[/bold cyan] "
            f"Log type: [{colour}]{resolved_log_type}[/{colour}] "
            f"[dim](tier: {tier}, structure: {structure})[/dim]"
        )
        if ruleset:
            sigma_cats = ", ".join(ruleset.get("sigma", ["generic"]))
            yara_cats  = ", ".join(ruleset.get("yara",  ["generic"]))
            console.print(
                f"[bold cyan]ThreatTrace ›[/bold cyan] "
                f"[dim]Deep analysis rules: Sigma [{sigma_cats}] · YARA [{yara_cats}][/dim]"
            )

    # 3 + 4. Parse + Detect
    # For files > _LARGE_FILE_BYTES, use chunk-streaming to avoid OOM.
    total_bytes = sum(fd.get("size_bytes", 0) for fd in file_descriptors)

    if total_bytes > _LARGE_FILE_BYTES:
        all_events, results = _parse_and_detect_streaming(
            file_descriptors,
            resolved_log_type,
            run_analysis,
            chunk_size,
            total_bytes,
        )
    else:
        all_events = parse_files(file_descriptors, resolved_log_type)
        console.print(
            f"[bold cyan]ThreatTrace ›[/bold cyan] Parsed "
            f"[bold]{len(all_events)}[/bold] event(s)."
        )
        results = run_analysis(all_events, resolved_log_type)
        results["events"] = all_events

    results["analyst"]        = analyst
    results["tlp"]            = tlp
    results["detection_meta"] = detection_meta   # tier, structure, ruleset, signals

    # 5. Analytics modules
    stat_results = []
    if analytics_modules and all_events:
        console.print(
            f"[bold cyan]ThreatTrace ›[/bold cyan] "
            f"[dim]Running analytics: {', '.join(analytics_modules)}[/dim]"
        )
        stat_results = run_analytics(
            events=all_events,
            log_type=resolved_log_type,
            modules=analytics_modules,
        )
        results["stat_results"] = [s.to_dict() for s in stat_results]
        render_analytics(stat_results)

    # 6. Report
    report_paths = gen_reports(results, output_dir, output_format)

    # 7. Summary (suppressed in interactive mode — unified report handles display)
    if not silent_summary:
        _print_summary(results, report_paths)

    # Persist for post-analysis search menu
    _last_scan_state["all_events"] = all_events
    _last_scan_state["results"]    = results

    return report_paths


# ---------------------------------------------------------------------------
# MODE A — Click CLI
# ---------------------------------------------------------------------------

@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--path", "-p",
    default=None,
    metavar="PATH",
    help="File or directory path to analyse.",
)
@click.option(
    "--recursive", "-r",
    is_flag=True,
    default=False,
    help="Recurse into sub-directories (only when --path is a directory).",
)
@click.option(
    "--type", "-t",
    "log_type",
    default="auto",
    metavar="TYPE",
    help=(
        "Force log type (e.g. apache, nginx, cloudtrail). "
        "Defaults to auto-detect."
    ),
)
@click.option(
    "--output", "-o",
    "output_dir",
    default="./threattrace_reports",
    metavar="DIR",
    help="Output directory for reports (default: ./threattrace_reports/).",
)
@click.option(
    "--format", "-f",
    "output_format",
    default="html",
    type=click.Choice(["html", "json", "both"], case_sensitive=False),
    help="Report format: html | json | both (default: html).",
)
@click.option(
    "--analyst",
    default="Unknown Analyst",
    metavar="NAME",
    help="Analyst name embedded in the report header.",
)
@click.option(
    "--tlp",
    default="AMBER",
    type=click.Choice(["WHITE", "GREEN", "AMBER", "RED"], case_sensitive=False),
    help="TLP classification for the report (default: AMBER).",
)
@click.option(
    "--no-analytics",
    "skip_analytics",
    is_flag=True,
    default=False,
    help="Skip all analytics modules (faster; detection-engine only).",
)
@click.option(
    "--no-baseline",   is_flag=True, default=False, hidden=True)
@click.option(
    "--no-beaconing",  is_flag=True, default=False, hidden=True)
@click.option(
    "--no-frequency",  is_flag=True, default=False, hidden=True)
@click.option(
    "--no-topn",       is_flag=True, default=False, hidden=True)
@click.option(
    "--no-timeline",   is_flag=True, default=False, hidden=True)
@click.option(
    "--stats-only",
    is_flag=True,
    default=False,
    help="Run analytics modules only; skip YARA/Sigma detection engine.",
)
@click.option(
    "--chunk-size",
    "chunk_size",
    default=_DEFAULT_CHUNK_SIZE,
    metavar="N",
    help=(
        f"Events per batch when streaming large files (default: {_DEFAULT_CHUNK_SIZE:,}). "
        "Lower values reduce peak memory usage."
    ),
    hidden=False,
)
def cli(
    path: Optional[str],
    recursive: bool,
    log_type: str,
    output_dir: str,
    output_format: str,
    analyst: str,
    tlp: str,
    skip_analytics: bool,
    no_baseline: bool,
    no_beaconing: bool,
    no_frequency: bool,
    no_topn: bool,
    no_timeline: bool,
    stats_only: bool,
    chunk_size: int,
) -> None:
    """
    ThreatTrace v2.0 — Cybersecurity Log Analysis & Threat Detection.

    Run without arguments to launch the interactive menu.
    """
    if path is None:
        # No --path supplied → fall through to interactive mode
        _run_interactive()
        return

    # Build analytics module list
    if skip_analytics:
        analytics_modules: Optional[List[str]] = []
    else:
        _all = ["baseline", "frequency", "beaconing", "topn", "timeline"]
        _skip = set()
        if no_baseline:  _skip.add("baseline")
        if no_beaconing: _skip.add("beaconing")
        if no_frequency: _skip.add("frequency")
        if no_topn:      _skip.add("topn")
        if no_timeline:  _skip.add("timeline")
        analytics_modules = [m for m in _all if m not in _skip]

    # Print banner for CLI mode too
    try:
        from core.menu import print_banner
        print_banner()
    except Exception:  # noqa: BLE001
        pass

    _run_analysis_pipeline(
        path=path,
        log_type=log_type,
        recursive=recursive,
        output_dir=output_dir,
        output_format=output_format.lower(),
        analyst=analyst,
        tlp=tlp.upper(),
        analytics_modules=analytics_modules,
        chunk_size=chunk_size,
    )


# ---------------------------------------------------------------------------
# Module-level scan state (populated after each pipeline run)
# ---------------------------------------------------------------------------

_last_scan_state: Dict[str, Any] = {}
_main_menu_banner_shown: bool = False   # static banner only on first visit


def _quit_app() -> None:
    """Print goodbye panel and exit the process."""
    console.print(
        Panel(
            "[bold cyan]Thank you for using ThreatTrace.[/bold cyan]\n"
            "[dim]Stay vigilant.[/dim]",
            border_style="cyan",
            padding=(1, 4),
        )
    )
    raise SystemExit(0)


# ---------------------------------------------------------------------------
# IOC Extractor UI helpers
# ---------------------------------------------------------------------------

def _ioc_risk_colour(score: float) -> str:
    """Return a Rich colour string for a 0–1 risk score."""
    if score >= 0.80:
        return "bold red"
    if score >= 0.60:
        return "red"
    if score >= 0.40:
        return "yellow"
    if score >= 0.20:
        return "cyan"
    return "dim white"


def _ioc_type_icon(entity_type: str) -> str:
    """Return a short icon/label for display in the results table."""
    _ICONS = {
        "ipv4":       "🌐 IPv4",
        "ipv6":       "🌐 IPv6",
        "domain":     "🔗 Domain",
        "url":        "🔗 URL",
        "email":      "✉  Email",
        "mac":        "🖧  MAC",
        "md5":        "#  MD5",
        "sha1":       "#  SHA1",
        "sha256":     "#  SHA256",
        "cve":        "⚠  CVE",
        "win_path":   "📁 WinPath",
        "unix_path":  "📁 UnixPath",
        "username":   "👤 Username",
        "user_agent": "🖥  UserAgent",
        "aws_key":    "🔑 AWSKey",
        "jwt":        "🔑 JWT",
    }
    return _ICONS.get(entity_type, entity_type)


def _show_ioc_results_panel(results: list, engine) -> None:
    """
    Display extraction results in a Rich table, then offer pivot / export flow.

    Parameters
    ----------
    results : list[ExtractionResult] from ExtractorEngine.extract()
    engine  : The ExtractorEngine instance (for pivot())
    """
    from rich.prompt import Prompt, Confirm
    from rich.text import Text

    if not results:
        console.print(
            Panel(
                "[yellow]No IOCs found in the provided input.[/yellow]\n"
                "[dim]Try a different file or data source.[/dim]",
                border_style="yellow",
                padding=(0, 2),
            )
        )
        return

    # ── summary counts ────────────────────────────────────────────────────
    from collections import Counter
    type_counts = Counter(r.entity_type for r in results)

    summary_tbl = Table(
        title="[bold bright_cyan]IOC Extraction Summary[/bold bright_cyan]",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style="bold white on #1e293b",
        expand=False,
    )
    summary_tbl.add_column("IOC Type",    style="cyan",        min_width=14)
    summary_tbl.add_column("Unique",      style="bold white",  justify="right", min_width=8)
    summary_tbl.add_column("Total Hits",  style="dim",         justify="right", min_width=10)
    summary_tbl.add_column("Top Risk",    min_width=8,         justify="right")

    # Group results by type
    by_type: Dict[str, list] = {}
    for r in results:
        by_type.setdefault(r.entity_type, []).append(r)

    for et in sorted(by_type, key=lambda t: -max(r.risk_score for r in by_type[t])):
        grp        = by_type[et]
        unique     = len(grp)
        total_hits = sum(r.occurrences for r in grp)
        top_risk   = max(r.risk_score for r in grp)
        risk_col   = _ioc_risk_colour(top_risk)
        summary_tbl.add_row(
            _ioc_type_icon(et),
            str(unique),
            str(total_hits),
            f"[{risk_col}]{top_risk:.2f}[/{risk_col}]",
        )

    console.print(summary_tbl)
    console.print()

    # ── top-N results table (up to 50) ───────────────────────────────────
    detail_tbl = Table(
        title=(
            f"[bold cyan]Top {min(len(results), 50)} IOCs[/bold cyan]  "
            f"[dim](sorted by risk · {len(results)} total)[/dim]"
        ),
        box=box.SIMPLE_HEAVY,
        border_style="dim",
        show_header=True,
        header_style="bold white on #1e293b",
        show_lines=False,
    )
    detail_tbl.add_column("#",          style="dim",         width=4,  justify="right")
    detail_tbl.add_column("Type",       style="cyan",        min_width=11)
    detail_tbl.add_column("Value",      style="bold white",  min_width=28, overflow="fold")
    detail_tbl.add_column("Count",      style="dim",         width=7,  justify="right")
    detail_tbl.add_column("Risk",       min_width=6,         justify="right")
    detail_tbl.add_column("First Seen", style="dim",         min_width=12)

    for idx, r in enumerate(results[:50], start=1):
        risk_col = _ioc_risk_colour(r.risk_score)
        first_ts = r.first_seen.strftime("%Y-%m-%d %H:%M") if r.first_seen else "—"
        detail_tbl.add_row(
            str(idx),
            _ioc_type_icon(r.entity_type),
            r.value,
            str(r.occurrences),
            f"[{risk_col}]{r.risk_score:.2f}[/{risk_col}]",
            first_ts,
        )

    console.print(detail_tbl)
    console.print()

    # ── post-results action loop ──────────────────────────────────────────
    while True:
        console.print(
            Panel(
                "  [bold white]1[/bold white]  [cyan]›[/cyan] Pivot — drill into a specific IOC\n"
                "  [bold white]2[/bold white]  [cyan]›[/cyan] Export results  "
                "[dim](CSV · TXT · JSON)[/dim]\n"
                "  [bold white]3[/bold white]  [cyan]›[/cyan] Back\n"
                "  [bold white]4[/bold white]  [cyan]›[/cyan] Exit ThreatTrace",
                border_style="cyan",
                padding=(0, 2),
            )
        )
        try:
            sub = Prompt.ask(
                "[bold cyan]IOC ›[/bold cyan] Choose",
                choices=["1", "2", "3", "4"],
                default="3",
                show_choices=False,
            ).strip()
        except (KeyboardInterrupt, EOFError):
            sub = "3"

        if sub == "1":
            _ioc_pivot_flow(results, engine)
        elif sub == "2":
            _ioc_export_flow(results)
        elif sub == "4":
            _quit_app()
        else:
            return


def _ioc_pivot_flow(results: list, engine) -> None:
    """Prompt for an IOC number and display its pivot context."""
    from rich.prompt import Prompt
    from rich.text import Text

    try:
        raw = Prompt.ask(
            "[bold cyan]IOC ›[/bold cyan] Enter IOC # to pivot  "
            "[dim](1–{} or b=back)[/dim]".format(min(len(results), 50))
        ).strip()
    except (KeyboardInterrupt, EOFError):
        return
    if raw.lower() == "b":
        return
    try:
        idx = int(raw) - 1
        if not (0 <= idx < min(len(results), 50)):
            raise ValueError
    except ValueError:
        console.print("  [red]✗  Invalid selection.[/red]")
        return

    chosen = results[idx]
    pivot  = engine.pivot(chosen.entity_type, chosen.value)
    if pivot is None:
        console.print("  [yellow]No pivot data available.[/yellow]")
        return

    # ── pivot detail panel ────────────────────────────────────────────
    risk_col = _ioc_risk_colour(pivot.risk_score)
    console.print(
        Panel(
            f"[bold bright_cyan]Pivot: {_ioc_type_icon(pivot.entity_type)}[/bold bright_cyan]  "
            f"[bold white]{pivot.value}[/bold white]\n\n"
            f"  [dim]Risk score :[/dim]  [{risk_col}]{pivot.risk_score:.3f}[/{risk_col}]\n"
            f"  [dim]Total lines:[/dim]  {pivot.total_lines}\n"
            f"  [dim]First seen :[/dim]  "
            f"{pivot.first_seen.isoformat() if pivot.first_seen else '—'}\n"
            f"  [dim]Last seen  :[/dim]  "
            f"{pivot.last_seen.isoformat() if pivot.last_seen else '—'}\n"
            f"  [dim]Sources    :[/dim]  {'; '.join(pivot.sources[:3]) or '—'}",
            border_style=risk_col,
            padding=(0, 2),
            title=f"[bold]Pivot Detail[/bold]",
            title_align="left",
        )
    )

    # Risk factors
    if pivot.risk_factors:
        console.print("  [bold dim]Risk factors:[/bold dim]")
        for f in pivot.risk_factors:
            console.print(f"    [dim]•[/dim] {f}")
        console.print()

    # Co-occurring IOCs
    if pivot.co_occurring:
        co_tbl = Table(
            title="[bold cyan]Co-occurring IOCs[/bold cyan]",
            box=box.SIMPLE_HEAVY,
            border_style="dim",
            header_style="bold white on #1e293b",
        )
        co_tbl.add_column("Type",  style="cyan",       min_width=12)
        co_tbl.add_column("Value", style="bold white",  min_width=28, overflow="fold")
        co_tbl.add_column("Lines", style="dim",         width=7, justify="right")
        for co_type, pairs in sorted(pivot.co_occurring.items()):
            for co_val, count in pairs[:5]:
                co_tbl.add_row(_ioc_type_icon(co_type), co_val, str(count))
        console.print(co_tbl)
        console.print()

    # Sample lines
    if pivot.all_lines:
        console.print("  [bold dim]Sample log lines:[/bold dim]")
        for lineno, raw in pivot.all_lines[:5]:
            console.print(f"  [dim]{lineno:>6}[/dim]  {raw[:120]}")
        if len(pivot.all_lines) > 5:
            console.print(f"  [dim]  … and {len(pivot.all_lines) - 5} more lines[/dim]")
        console.print()

        # ── download all related log lines ────────────────────────────────
        try:
            dl = Prompt.ask(
                f"  [bold cyan]›[/bold cyan] Download all [bold white]{len(pivot.all_lines)}[/bold white]"
                f" log lines for this IOC?  [dim](y/n)[/dim]",
                choices=["y", "n"],
                default="n",
                show_choices=False,
            )
        except (KeyboardInterrupt, EOFError):
            dl = "n"

        if dl == "y":
            import datetime as _dt, re as _re
            ts        = _dt.datetime.now().strftime("%H%M%S")
            safe_val  = _re.sub(r"[^\w\-.]", "_", pivot.value)[:48]
            default_p = str(Path.cwd() / f"ioc_{pivot.entity_type}_{safe_val}_{ts}.txt")
            try:
                out_path = Prompt.ask(
                    "  [bold cyan]›[/bold cyan] Save to",
                    default=default_p,
                ).strip()
            except (KeyboardInterrupt, EOFError):
                out_path = default_p

            try:
                out = Path(out_path)
                out.parent.mkdir(parents=True, exist_ok=True)
                with out.open("w", encoding="utf-8") as fh:
                    fh.write(
                        f"# ThreatTrace — IOC Log Export\n"
                        f"# Type  : {pivot.entity_type}\n"
                        f"# Value : {pivot.value}\n"
                        f"# Lines : {len(pivot.all_lines)}\n"
                        f"# Risk  : {pivot.risk_score:.3f}\n"
                        f"# Exported: {_dt.datetime.now().isoformat()}\n\n"
                    )
                    for lineno, raw_line in pivot.all_lines:
                        fh.write(f"{lineno:>8}: {raw_line}\n")
                console.print(
                    f"  [green]✔[/green]  Saved [bold white]{len(pivot.all_lines)}[/bold white]"
                    f" lines → [bright_white]{out}[/bright_white]\n"
                )
            except (OSError, PermissionError) as exc:
                console.print(f"  [red]✗  Export failed:[/red] {exc}\n")


def _ioc_export_flow(results: list) -> None:
    """Prompt for export format and output path, then write the file."""
    from rich.prompt import Prompt
    import datetime as _dt

    from extractor.exporters import ExportManager

    console.print(
        Panel(
            "  [bold white]1[/bold white]  CSV   [dim](Excel-compatible)[/dim]\n"
            "  [bold white]2[/bold white]  TXT   [dim](human-readable report)[/dim]\n"
            "  [bold white]3[/bold white]  JSON  [dim](structured data)[/dim]\n"
            "  [bold white]b[/bold white]  Back",
            border_style="cyan",
            padding=(0, 2),
            title="[bold]Export Format[/bold]",
            title_align="left",
        )
    )
    try:
        fmt_choice = Prompt.ask(
            "[bold cyan]IOC ›[/bold cyan] Format",
            choices=["1", "2", "3", "b"],
            default="1",
            show_choices=False,
        ).strip()
    except (KeyboardInterrupt, EOFError):
        return
    if fmt_choice.lower() == "b":
        return

    ext_map    = {"1": "csv", "2": "txt", "3": "json"}
    ext        = ext_map[fmt_choice]
    ts         = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    default_out = str(Path.cwd() / f"ioc_results_{ts}.{ext}")

    try:
        out_raw = Prompt.ask(
            "[bold cyan]IOC ›[/bold cyan] Save to",
            default=default_out,
        ).strip()
    except (KeyboardInterrupt, EOFError):
        console.print("[dim]Export cancelled.[/dim]")
        return

    mgr = ExportManager(results)
    try:
        if fmt_choice == "1":
            out_path = mgr.export_csv(out_raw)
        elif fmt_choice == "2":
            out_path = mgr.export_txt(out_raw)
        else:
            out_path = mgr.export_json(out_raw)
        console.print(
            f"  [green]✔[/green]  Exported [bold]{len(results)}[/bold] IOC(s) "
            f"→ [bright_white]{out_path}[/bright_white]\n"
        )
    except (OSError, PermissionError) as exc:
        console.print(f"  [red]✗  Export failed:[/red] {exc}")


def _run_ioc_extractor_from_file(filepath: str) -> None:
    """
    Touchpoint 1: Extract IOCs from a file chosen by the user or passed in.

    Shows a progress spinner, builds the index, then delegates to
    _show_ioc_results_panel().
    """
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from extractor import ExtractorEngine

    fname = Path(filepath).name
    console.print(
        Panel(
            f"[bold bright_cyan]  ◆  IOC Extractor  ◆[/bold bright_cyan]\n"
            f"[dim]Scanning:[/dim] [bold white]{fname}[/bold white]",
            border_style="bright_cyan",
            padding=(0, 2),
        )
    )

    engine = ExtractorEngine()

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        console=console,
        transient=True,
    ) as prog:
        prog.add_task("Extracting IOCs…", total=None)
        try:
            engine.load_from_files([filepath])
        except Exception as exc:  # noqa: BLE001
            console.print(f"  [red]✗  Failed to scan file:[/red] {exc}")
            return

    results = engine.extract()
    _show_ioc_results_panel(results, engine)


def _run_ioc_extractor_from_records(records: list, source_label: str = "") -> None:
    """
    Touchpoint 2: Extract IOCs from already-parsed log records (post-analysis).

    Parameters
    ----------
    records      : List of LogRecord objects or raw line strings.
    source_label : Human-readable label (e.g. filename) shown in the header.
    """
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from extractor import ExtractorEngine

    label = source_label or "scanned data"
    console.print(
        Panel(
            f"[bold bright_cyan]  ◆  IOC Extractor  ◆[/bold bright_cyan]\n"
            f"[dim]Source:[/dim] [bold white]{label}[/bold white]  "
            f"[dim]({len(records):,} records)[/dim]",
            border_style="bright_cyan",
            padding=(0, 2),
        )
    )

    engine = ExtractorEngine()

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        console=console,
        transient=True,
    ) as prog:
        prog.add_task("Extracting IOCs…", total=None)
        try:
            engine.load_from_records(records, source_label=source_label)
        except Exception as exc:  # noqa: BLE001
            console.print(f"  [red]✗  Failed to process records:[/red] {exc}")
            return

    results = engine.extract()
    _show_ioc_results_panel(results, engine)


# ---------------------------------------------------------------------------
# Simple keyword search
# ---------------------------------------------------------------------------

def _run_simple_search(filepath: Optional[str] = None) -> None:
    """
    Interactive keyword search against a log file.

    If *filepath* is None the user is prompted for a path.
    Loops until the user exits so multiple keywords can be tried.
    """
    import time
    from rich.live import Live
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich.columns import Columns
    from rich.align import Align

    # ── animated entry ───────────────────────────────────────────────────────
    BAR_W   = 36
    TITLE   = "◆  Log File Search  ◆"
    PHASES  = [
        ("[cyan]", "Initializing engine…"),
        ("[bold cyan]", "Loading pattern library…"),
        ("[bold bright_cyan]", "Ready"),
    ]
    phase_len = BAR_W // len(PHASES)

    with Live(console=console, refresh_per_second=30, transient=True) as live:
        for step in range(BAR_W + 1):
            filled  = "█" * step
            empty   = "░" * (BAR_W - step)
            pct     = int(step / BAR_W * 100)
            p_idx   = min(step * len(PHASES) // (BAR_W + 1), len(PHASES) - 1)
            col, lbl = PHASES[p_idx]
            bar_line = f"  {col}{filled}[/]{col.rstrip(']')} on #0a0a0a]{empty}[/]  [dim]{pct:>3}%[/dim]  {col}{lbl}[/]"
            content  = (
                f"\n  [bold bright_cyan]{TITLE}[/bold bright_cyan]\n\n"
                f"{bar_line}\n"
            )
            live.update(
                Panel(content, border_style="bright_cyan", padding=(0, 1),
                      title="[dim cyan]ThreatTrace[/dim cyan]", title_align="left")
            )
            time.sleep(0.018)

        # flash "Ready" green for a moment
        ready_bar = f"  [bold green]{'█' * BAR_W}[/bold green]  [bold green]✔  Ready[/bold green]"
        live.update(
            Panel(
                f"\n  [bold bright_cyan]{TITLE}[/bold bright_cyan]\n\n{ready_bar}\n",
                border_style="green", padding=(0, 1),
                title="[dim cyan]ThreatTrace[/dim cyan]", title_align="left",
            )
        )
        time.sleep(0.35)

    # ── static search panel ──────────────────────────────────────────────────
    ops_grid = (
        "  [bold cyan]AND[/bold cyan]  [dim]both terms present[/dim]        "
        "[bold cyan]OR[/bold cyan]   [dim]either term present[/dim]\n"
        "  [bold cyan]NOT[/bold cyan]  [dim]term must be absent[/dim]        "
        "[bold cyan]XOR[/bold cyan]  [dim]exactly one term present[/dim]\n"
        "  [bold cyan]( )[/bold cyan]  [dim]group sub-expressions[/dim]"
    )
    console.print(
        Panel(
            f"[bold bright_cyan]  ◆  Log File Search  ◆[/bold bright_cyan]\n"
            f"  [dim]Search any log or text file — keyword, IP, hash, boolean expression[/dim]\n\n"
            f"[bold white on #0d1117]  Boolean Operators[/bold white on #0d1117]\n"
            f"{ops_grid}\n\n"
            f"  [dim]Navigation:[/dim]  "
            f"[bold white]b[/bold white][dim]=back[/dim]   "
            f"[bold white]q[/bold white][dim]=exit[/dim]",
            border_style="bright_cyan",
            padding=(0, 2),
            title="[bold bright_cyan]ThreatTrace[/bold bright_cyan]",
            title_align="left",
            subtitle="[dim]v · boolean · IOC-aware[/dim]",
            subtitle_align="right",
        )
    )
    console.print()

    # ── resolve file ─────────────────────────────────────────────────────────
    if filepath is None:
        while True:
            try:
                raw = Prompt.ask(
                    "[bold cyan]ThreatTrace ›[/bold cyan] Path to log file "
                    "[dim](b=main menu  q=exit)[/dim]"
                ).strip()
            except (KeyboardInterrupt, EOFError):
                raw = "b"
            if raw.lower() == "b":
                return
            if raw.lower() == "q":
                _quit_app()
            expanded = os.path.expandvars(os.path.expanduser(raw))
            if Path(expanded).is_file():
                filepath = expanded
                console.print(
                    f"  [bright_green]✔[/bright_green]  [dim]{filepath}[/dim]\n"
                )
                break
            console.print(f"  [red]✗  File not found:[/red] [dim]{expanded}[/dim]")
    else:
        console.print(
            f"  [dim]File:[/dim] [bold white]{filepath}[/bold white]\n"
        )

    # ── offer IOC extraction before search ───────────────────────────────────
    console.print(
        "  [dim]Options:[/dim]  "
        "[bold white]S[/bold white] [dim]= search (default)[/dim]   "
        "[bold white]E[/bold white] [dim]= Extract IOCs from this file[/dim]   "
        "[bold white]b[/bold white] [dim]= back[/dim]"
    )
    try:
        pre_choice = Prompt.ask(
            "[bold cyan]ThreatTrace ›[/bold cyan] Action",
            default="s",
        ).strip().lower()
    except (KeyboardInterrupt, EOFError):
        pre_choice = "b"
    if pre_choice == "b":
        return
    if pre_choice == "e":
        _run_ioc_extractor_from_file(filepath)
        return

    # ── search loop ──────────────────────────────────────────────────────────
    while True:
        try:
            keyword = Prompt.ask(
                "[bold cyan]Search ›[/bold cyan] Query "
                "[dim](b=back  q=exit  ·  boolean: term AND term  OR  NOT term  XOR  (group))[/dim]"
            ).strip()
        except (KeyboardInterrupt, EOFError):
            keyword = "b"

        if keyword.lower() == "b":
            return
        if keyword.lower() == "q":
            _quit_app()
        if not keyword:
            continue

        # ── boolean vs simple detection ───────────────────────────────────
        boolean_mode   = False
        bool_ast       = None
        bool_keywords: List[str] = []

        try:
            from search.boolean_eval import (
                is_boolean_query, parse_expr, extract_variables, eval_node,
            )
            if is_boolean_query(keyword):
                bool_ast      = parse_expr(keyword)   # raises ValueError on bad syntax
                bool_keywords = extract_variables(keyword)
                boolean_mode  = True
        except ValueError as _parse_err:
            console.print(
                f"  [red]✗  Boolean syntax error:[/red] {_parse_err}\n"
                f"  [dim]Tip: use  term AND term  OR  NOT term  XOR  (group)[/dim]\n"
            )
            continue
        except ImportError:
            pass   # boolean_eval not available — fall back to simple

        # ── scan file ─────────────────────────────────────────────────────
        # Each match is (lineno, raw_text, hit_keywords_for_this_line)
        matches: List[tuple] = []
        try:
            with open(filepath, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    raw = line.rstrip("\n\r")
                    if boolean_mode and bool_ast is not None:
                        line_lc = raw.lower()
                        env     = {kw: kw.lower() in line_lc for kw in bool_keywords}
                        try:
                            hit = eval_node(bool_ast, env)
                        except ValueError:
                            hit = False
                        if hit:
                            hit_kws = [kw for kw, present in env.items() if present]
                            matches.append((lineno, raw, hit_kws))
                    else:
                        if keyword.lower() in raw.lower():
                            matches.append((lineno, raw, [keyword]))
        except (OSError, PermissionError) as exc:
            console.print(f"[red]Cannot read file:[/red] {exc}")
            continue

        if not matches:
            mode_label = "boolean expression" if boolean_mode else "keyword"
            console.print(
                f"  [yellow]No matches for {mode_label}[/yellow] "
                f"[bold]{keyword!r}[/bold]  "
                f"[dim]in {Path(filepath).name}[/dim]\n"
            )
            continue

        # ── display results table ─────────────────────────────────────────
        mode_badge = (
            "[bold magenta]BOOLEAN[/bold magenta]"
            if boolean_mode else
            "[bold cyan]KEYWORD[/bold cyan]"
        )
        tbl = Table(
            title=(
                f"[bold cyan]{len(matches)} "
                f"match{'es' if len(matches) != 1 else ''}[/bold cyan]  "
                f"{mode_badge}  "
                f"[bold white]{keyword!r}[/bold white]  "
                f"[dim]in {Path(filepath).name}[/dim]"
            ),
            show_header=True,
            header_style="bold white on #1e293b",
            border_style="dim",
            show_lines=False,
            box=box.SIMPLE_HEAVY,
        )
        tbl.add_column("Line",    style="bold cyan", width=7, justify="right")
        tbl.add_column("Content", style="white")

        for lineno, text, hit_kws in matches[:500]:
            # Build a Rich Text cell with all hit keywords highlighted.
            # We do a single left-to-right pass, marking every occurrence of
            # every hit keyword (case-insensitive) in the order they appear.
            cell     = Text()
            text_lc  = text.lower()
            pos      = 0
            # Collect all (start, end) spans for every hit keyword
            spans: List[tuple] = []
            for kw in hit_kws:
                kw_lc = kw.lower()
                klen  = len(kw_lc)
                if not kw_lc:
                    continue
                idx = 0
                while True:
                    found = text_lc.find(kw_lc, idx)
                    if found == -1:
                        break
                    spans.append((found, found + klen))
                    idx = found + klen

            if spans:
                # Merge overlapping/adjacent spans, then render
                spans.sort()
                merged: List[tuple] = []
                for start, end in spans:
                    if merged and start <= merged[-1][1]:
                        merged[-1] = (merged[-1][0], max(merged[-1][1], end))
                    else:
                        merged.append([start, end])
                for start, end in merged:
                    if pos < start:
                        cell.append(text[pos:start])
                    cell.append(text[start:end], style="bold yellow on #1a1a00")
                    pos = end
            cell.append(text[pos:])   # remainder (or full text if no spans)
            tbl.add_row(str(lineno), cell)

        if len(matches) > 500:
            tbl.caption = (
                f"[dim](showing first 500 of {len(matches):,} matches)[/dim]"
            )

        console.print(tbl)
        console.print()

        # ── post-results sub-menu ─────────────────────────────────────────
        console.print(
            Panel(
                f"  [bold bright_cyan]◆  Search Complete[/bold bright_cyan]  "
                f"[dim]— {len(matches):,} match{'es' if len(matches) != 1 else ''} found[/dim]\n\n"
                "  [bold white]1[/bold white]  [cyan]›[/cyan] Search again          "
                "[dim]new keyword or expression[/dim]\n"
                "  [bold white]2[/bold white]  [cyan]›[/cyan] Export results        "
                "[dim]save matches to file[/dim]\n"
                "  [bold white]3[/bold white]  [cyan]›[/cyan] Back to main menu\n"
                "  [bold white]4[/bold white]  [cyan]›[/cyan] Exit ThreatTrace",
                border_style="bright_cyan",
                padding=(0, 2),
                title="[bold bright_cyan]ThreatTrace[/bold bright_cyan]",
                title_align="left",
            )
        )
        try:
            sub = Prompt.ask(
                "[bold cyan]ThreatTrace ›[/bold cyan] Choose",
                choices=["1", "2", "3", "4"],
                default="1",
                show_choices=False,
            ).strip()
        except (KeyboardInterrupt, EOFError):
            sub = "3"

        if sub == "2":
            _export_search_results(filepath, keyword, matches)
        elif sub == "3":
            return
        elif sub == "4":
            _quit_app()
        # sub == "1" → loop back for another keyword

        console.print()


def _export_search_results(
    filepath: str,
    keyword: str,
    matches: List[tuple],
) -> None:
    """Write search matches to a timestamped text file beside the source file."""
    import datetime as _dt
    from rich.prompt import Prompt

    ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_kw = "".join(c if c.isalnum() else "_" for c in keyword)[:40]
    default_out = str(Path(filepath).parent / f"search_{safe_kw}_{ts}.txt")

    try:
        out_raw = Prompt.ask(
            "[bold cyan]ThreatTrace ›[/bold cyan] Save to",
            default=default_out,
        ).strip()
    except (KeyboardInterrupt, EOFError):
        console.print("[dim]Export cancelled.[/dim]")
        return

    out_path = Path(os.path.expandvars(os.path.expanduser(out_raw)))
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(f"# ThreatTrace Search Results\n")
            fh.write(f"# File   : {filepath}\n")
            fh.write(f"# Keyword: {keyword}\n")
            fh.write(f"# Matches: {len(matches)}\n")
            fh.write(f"# Exported: {_dt.datetime.now().isoformat()}\n\n")
            for lineno, text, *_ in matches:   # *_ tolerates 2- or 3-tuple
                fh.write(f"{lineno:>8}  {text}\n")
        console.print(
            f"  [green]✔[/green]  Saved [bold]{len(matches)}[/bold] "
            f"line(s) → [bright_white]{out_path}[/bright_white]\n"
        )
    except (OSError, PermissionError) as exc:
        console.print(f"[red]Export failed:[/red] {exc}")


# ---------------------------------------------------------------------------
# Unified analysis + IOC report
# ---------------------------------------------------------------------------

_SEV_COLOUR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "INFO":     "dim",
}


def _display_unified_report(
    results: Dict[str, Any],
    ioc_results: list,
    report_paths: List[str],
    filepath: str,
) -> None:
    """
    Render a combined terminal report:
      • Scan metadata header
      • Detection findings table
      • Analytics stat summary
      • IOC extraction summary
      • Saved report paths
    """
    from rich.text import Text
    from pathlib import Path as _Path
    import datetime

    # ── header panel ─────────────────────────────────────────────────────────
    risk       = results.get("overall_risk", "INFORMATIONAL")
    risk_col   = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                  "LOW": "green"}.get(risk, "dim")
    log_type   = results.get("log_type", "auto")
    analyst    = results.get("analyst", "—")
    tlp        = results.get("tlp", "AMBER")
    total_ev   = results.get("total_events", 0)
    fname      = _Path(filepath).name if filepath else "—"
    findings   = results.get("findings", [])
    ts_now     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    header_lines = (
        f"  [bold bright_cyan]◆  ThreatTrace Analysis Report  ◆[/bold bright_cyan]\n\n"
        f"  [dim]File      :[/dim]  [bold white]{fname}[/bold white]\n"
        f"  [dim]Log Type  :[/dim]  [cyan]{log_type}[/cyan]\n"
        f"  [dim]Analyst   :[/dim]  [white]{analyst}[/white]\n"
        f"  [dim]TLP       :[/dim]  [yellow]{tlp}[/yellow]\n"
        f"  [dim]Timestamp :[/dim]  [dim]{ts_now}[/dim]\n"
        f"  [dim]Events    :[/dim]  [white]{total_ev:,}[/white]\n"
        f"  [dim]Risk Level:[/dim]  [{risk_col}]{risk}[/{risk_col}]"
    )
    console.print()
    console.print(
        Panel(
            header_lines,
            border_style="bright_cyan",
            padding=(0, 2),
            title="[bold bright_cyan]ThreatTrace[/bold bright_cyan]",
            title_align="left",
        )
    )
    console.print()

    # ── detection findings table ──────────────────────────────────────────────
    if findings:
        det_tbl = Table(
            title=f"[bold cyan]Detection Findings[/bold cyan]  [dim]({len(findings)} total)[/dim]",
            box=box.ROUNDED,
            border_style="cyan",
            show_header=True,
            header_style="bold white on #1e293b",
            show_lines=False,
            expand=True,
        )
        det_tbl.add_column("#",          style="dim",         width=5,  justify="right")
        det_tbl.add_column("Rule",       style="bold white",  min_width=28)
        det_tbl.add_column("Sev",        min_width=9)
        det_tbl.add_column("Type",       style="dim cyan",    min_width=7)
        det_tbl.add_column("Tactic",     style="cyan",        min_width=16)
        det_tbl.add_column("Technique",  style="dim",         min_width=10)
        det_tbl.add_column("IPs",        style="dim",         min_width=15, overflow="fold")
        det_tbl.add_column("Users",      style="dim",         min_width=12, overflow="fold")
        det_tbl.add_column("Count",      style="dim",         width=7, justify="right")

        # Sort: CRITICAL first, then HIGH, MEDIUM, LOW, INFO
        _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: _sev_order.get(f.get("severity", "INFO"), 9),
        )

        for i, f in enumerate(sorted_findings[:30], 1):
            sev      = f.get("severity", "—")
            sev_col  = _SEV_COLOUR.get(sev, "white")
            indics   = f.get("indicators", {})
            ips      = ", ".join(indics.get("ips", [])[:3])
            users    = ", ".join(indics.get("usernames", [])[:3])
            det_tbl.add_row(
                str(i),
                f.get("rule_name", "—"),
                f"[{sev_col}]{sev}[/{sev_col}]",
                f.get("rule_type", "—"),
                f.get("mitre_tactic", "—") or "—",
                f.get("mitre_technique", "—") or "—",
                ips or "—",
                users or "—",
                str(f.get("count", 0)),
            )
        console.print(det_tbl)
        if len(findings) > 30:
            console.print(
                f"  [dim]… {len(findings) - 30} more findings in saved report[/dim]"
            )
        console.print()
    else:
        console.print(
            Panel(
                "[green]✔  No detections triggered.[/green]\n"
                "[dim]No Sigma or YARA rules matched.[/dim]",
                border_style="green",
                padding=(0, 2),
            )
        )
        console.print()

    # ── analytics summary ─────────────────────────────────────────────────────
    stat_results = results.get("stat_results", [])
    if stat_results:
        ana_tbl = Table(
            title="[bold cyan]Analytics Summary[/bold cyan]",
            box=box.SIMPLE_HEAVY,
            border_style="dim",
            show_header=True,
            header_style="bold white",
            expand=False,
        )
        ana_tbl.add_column("Module",   style="cyan",       min_width=16)
        ana_tbl.add_column("Insight",  style="bold white", min_width=40)
        ana_tbl.add_column("Value",    style="dim",        min_width=20, overflow="fold")

        for s in stat_results[:15]:
            if isinstance(s, dict):
                module  = s.get("module", "—")
                insight = s.get("insight", s.get("label", "—"))
                value   = str(s.get("value", s.get("count", "—")))
                ana_tbl.add_row(module, insight, value)

        console.print(ana_tbl)
        console.print()

    # ── IOC extraction summary ────────────────────────────────────────────────
    if ioc_results:
        from collections import Counter
        type_counts = Counter(r.entity_type for r in ioc_results)

        ioc_sum_tbl = Table(
            title="[bold bright_cyan]IOC Extraction Summary[/bold bright_cyan]"
                  f"  [dim]({len(ioc_results)} unique IOCs)[/dim]",
            box=box.ROUNDED,
            border_style="cyan",
            show_header=True,
            header_style="bold white on #1e293b",
            expand=False,
        )
        ioc_sum_tbl.add_column("IOC Type",   style="cyan",       min_width=14)
        ioc_sum_tbl.add_column("Unique",     style="bold white", justify="right", min_width=8)
        ioc_sum_tbl.add_column("Total Hits", style="dim",        justify="right", min_width=10)
        ioc_sum_tbl.add_column("Top Risk",   min_width=8,        justify="right")

        by_type: Dict[str, list] = {}
        for r in ioc_results:
            by_type.setdefault(r.entity_type, []).append(r)

        for et in sorted(by_type, key=lambda t: -max(r.risk_score for r in by_type[t])):
            grp      = by_type[et]
            unique   = len(grp)
            tot_hits = sum(r.occurrences for r in grp)
            top_risk = max(r.risk_score for r in grp)
            rc       = _ioc_risk_colour(top_risk)
            ioc_sum_tbl.add_row(
                _ioc_type_icon(et),
                str(unique),
                str(tot_hits),
                f"[{rc}]{top_risk:.2f}[/{rc}]",
            )
        console.print(ioc_sum_tbl)
        console.print()

        # Top 10 IOCs by risk
        top10 = sorted(ioc_results, key=lambda r: -r.risk_score)[:10]
        top_tbl = Table(
            title="[bold cyan]Top 10 IOCs by Risk[/bold cyan]",
            box=box.SIMPLE_HEAVY,
            border_style="dim",
            show_header=True,
            header_style="bold white on #1e293b",
            show_lines=False,
        )
        top_tbl.add_column("#",     style="dim",        width=4,  justify="right")
        top_tbl.add_column("Type",  style="cyan",       min_width=11)
        top_tbl.add_column("Value", style="bold white", min_width=32, overflow="fold")
        top_tbl.add_column("Count", style="dim",        width=7,  justify="right")
        top_tbl.add_column("Risk",  min_width=6,        justify="right")

        for i, r in enumerate(top10, 1):
            rc = _ioc_risk_colour(r.risk_score)
            top_tbl.add_row(
                str(i),
                _ioc_type_icon(r.entity_type),
                r.value,
                str(r.occurrences),
                f"[{rc}]{r.risk_score:.2f}[/{rc}]",
            )
        console.print(top_tbl)
        console.print()
    else:
        console.print(
            Panel(
                "[dim]No IOCs extracted from this log source.[/dim]",
                border_style="dim",
                padding=(0, 2),
            )
        )
        console.print()

    # ── saved report paths ────────────────────────────────────────────────────
    if report_paths:
        console.print("[bold cyan]ThreatTrace ›[/bold cyan] Reports saved:")
        for rp in report_paths:
            console.print(f"  [green]{rp}[/green]")
        console.print()


# ---------------------------------------------------------------------------
# Post-analysis menu
# ---------------------------------------------------------------------------

def _post_analysis_menu() -> str:
    """
    Display a post-analysis action menu and return the chosen action:
      "search"   — search the last scanned file
      "previous" — go back to analysis wizard (re-analyze)
      "menu"     — return to the main menu
      "exit"     — quit ThreatTrace
    """
    from rich.prompt import Prompt

    console.print(
        Panel(
            "[bold bright_cyan]  ◆  Analysis Complete  ◆[/bold bright_cyan]\n\n"
            "  [bold white]1[/bold white]  [cyan]›[/cyan] Search this log file  "
            "[dim](keyword · IP · hash · boolean)[/dim]\n"
            "  [bold white]2[/bold white]  [cyan]›[/cyan] Re-analyze / Previous menu  "
            "[dim](back to analysis wizard)[/dim]\n"
            "  [bold white]3[/bold white]  [cyan]›[/cyan] Main Menu  "
            "[dim](return to main menu)[/dim]\n"
            "  [bold white]4[/bold white]  [cyan]›[/cyan] Exit ThreatTrace",
            border_style="bright_cyan",
            padding=(0, 2),
            title="[bold bright_cyan]ThreatTrace[/bold bright_cyan]",
            title_align="left",
        )
    )

    while True:
        try:
            choice = Prompt.ask(
                "[bold cyan]ThreatTrace ›[/bold cyan] Choose",
                choices=["1", "2", "3", "4"],
                default="3",
                show_choices=False,
            )
        except (KeyboardInterrupt, EOFError):
            choice = "4"

        if choice == "1":
            return "search"
        elif choice == "2":
            return "previous"
        elif choice == "3":
            return "menu"
        else:
            return "exit"


# ---------------------------------------------------------------------------
# Top-level main menu
# ---------------------------------------------------------------------------

def _show_main_menu() -> str:
    """
    Display the ThreatTrace main menu and return the chosen action:
      "analyze" — run analysis pipeline
      "search"  — search a log file by keyword
      "exit"    — quit
    """
    global _main_menu_banner_shown
    from rich.prompt import Prompt

    if not _main_menu_banner_shown:
        _, _, _, print_static_banner, _ = _import_menu()
        print_static_banner()
        _main_menu_banner_shown = True

    console.print(
        Panel(
            "[bold bright_cyan]  ◆  Main Menu  ◆[/bold bright_cyan]\n\n"
            "  [bold white]1[/bold white]  [cyan]›[/cyan] Analyze Log File  "
            "[dim](YARA · Sigma · Analytics)[/dim]\n"
            "  [bold white]2[/bold white]  [cyan]›[/cyan] Search Log File   "
            "[dim](keyword · IP · hash · username)[/dim]\n"
            "  [bold white]3[/bold white]  [cyan]›[/cyan] Exit ThreatTrace",
            border_style="bright_cyan",
            padding=(0, 2),
            title="[bold bright_cyan]ThreatTrace[/bold bright_cyan]",
            title_align="left",
        )
    )

    while True:
        try:
            choice = Prompt.ask(
                "[bold cyan]ThreatTrace ›[/bold cyan] Choose",
                choices=["1", "2", "3"],
                default="1",
                show_choices=False,
            )
        except (KeyboardInterrupt, EOFError):
            choice = "3"

        if choice == "1":
            return "analyze"
        elif choice == "2":
            return "search"
        else:
            return "exit"


# ---------------------------------------------------------------------------
# MODE B — Interactive
# ---------------------------------------------------------------------------

def _run_interactive() -> None:
    """
    Persistent interactive loop with a top-level main menu:
      1 → Analyze  2 → Search  3 → Exit
    """
    run_interactive_menu, run_analysis_progress, show_analysis_complete_banner, \
        _, print_banner = _import_menu()

    # Animated banner plays exactly once at startup
    print_banner()

    while True:
        # ── top-level main menu ──────────────────────────────────────────
        top_action = _show_main_menu()

        if top_action == "exit":
            _quit_app()

        if top_action == "search":
            _run_simple_search()
            continue

        # ── top_action == "analyze" ──────────────────────────────────────
        try:
            session = run_interactive_menu()
        except KeyboardInterrupt:
            # User cancelled analysis wizard → back to main menu
            continue

        # Show staged progress bar
        file_display = Path(session["path"]).name
        run_analysis_progress(file_display)

        # Run real pipeline (silent_summary=True: unified report handles display)
        report_paths = _run_analysis_pipeline(
            path=session["path"],
            log_type=session["log_type"],
            recursive=False,
            output_dir=session["output_dir"],
            output_format=session["output_format"],
            analyst=session["analyst"],
            tlp="AMBER",
            analytics_modules=["baseline", "frequency", "beaconing", "topn", "timeline"],
            silent_summary=True,
        )

        # Store scanned file path for post-analysis search
        _last_scan_state["filepath"] = session["path"]

        # ── Auto-run IOC extractor ───────────────────────────────────────────
        ioc_results = []
        try:
            from extractor import ExtractorEngine
            all_ev  = _last_scan_state.get("all_events", [])
            src_lbl = Path(session["path"]).name
            if all_ev:
                _ioc_engine = ExtractorEngine()
                _ioc_engine.load_from_records(all_ev, source_label=src_lbl)
            else:
                _ioc_engine = ExtractorEngine()
                _ioc_engine.load_from_files([session["path"]])
            ioc_results = _ioc_engine.extract()
            _last_scan_state["ioc_results"] = ioc_results
            _last_scan_state["ioc_engine"]  = _ioc_engine
        except Exception as _exc:
            console.print(f"[yellow]IOC extraction skipped:[/yellow] {_exc}")
            _last_scan_state["ioc_results"] = []
            _last_scan_state["ioc_engine"]  = None

        # ── Unified terminal report ──────────────────────────────────────────
        _display_unified_report(
            results=_last_scan_state.get("results", {}),
            ioc_results=ioc_results,
            report_paths=report_paths or [],
            filepath=session["path"],
        )

        # ── post-analysis menu ───────────────────────────────────────────────
        while True:
            action = _post_analysis_menu()
            if action == "search":
                last_file = _last_scan_state.get("filepath")
                _run_simple_search(filepath=last_file)
                continue
            elif action == "previous":
                # Break inner loop → re-enter analysis wizard
                break
            elif action == "exit":
                _quit_app()
            else:
                # "menu" → break inner loop AND outer while → back to top menu
                break


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Determine run mode and dispatch accordingly.

    If no CLI arguments are provided (sys.argv == [script_name]),
    launch interactive mode directly without going through Click
    (avoids the --help prompt).
    """
    # If no args at all, go straight to interactive mode
    # (print_banner is called inside run_interactive_menu — no duplicate needed)
    if len(sys.argv) == 1:
        _run_interactive()
    else:
        cli()


if __name__ == "__main__":
    main()
