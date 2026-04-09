"""Main analysis orchestrator — wires TUI, parsers, detection engines, and reporter."""
from __future__ import annotations

import socket
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.live import Live
from rich.panel import Panel
from rich.progress import (BarColumn, MofNCompleteColumn, Progress,
                            SpinnerColumn, TaskProgressColumn, TextColumn,
                            TimeElapsedColumn)
from rich.table import Table

from .detectors import SigmaEngine, YARAEngine
from .fingerprint import AutoDetector
from .models.finding import Severity
from .models.log_event import LOG_SOURCE_LABELS, LogSourceType
from .models.report import AnalysisReport
from .parsers import get_parser
from .reports import ReportGenerator
from .tui.console import console, print_banner, severity_badge
from .tui.menu import pick_log_source

_RULES_BASE = Path(__file__).parent.parent / "rules"


class ThreatTraceApp:
    def __init__(
        self,
        files: list[str],
        log_type: Optional[str] = None,
        rules_dir: Optional[str] = None,
        verbose: bool = False,
        quiet: bool = False,
        no_tui: bool = False,
        output: Optional[str] = None,
        fmt: str = "table",
        options: Optional[dict] = None,
    ) -> None:
        self.input_paths = [Path(f) for f in files]
        self.forced_type = log_type
        self.rules_dir = Path(rules_dir) if rules_dir else _RULES_BASE
        self.verbose = verbose
        self.quiet = quiet
        self.no_tui = no_tui
        self.output = output
        self.fmt = fmt
        self.options: dict = options or {}
        # Search engines — populated during run() if search phase executes
        self._keyword_engine = None
        self._event_engine = None
        self._name_detector = None
        self._name_results: list = []

    def run(self) -> AnalysisReport:
        if not self.quiet:
            print_banner()

        # Resolve all input files (expand directories)
        all_files = self._resolve_files()
        if not all_files:
            console.print("[red]No readable files found.[/red]")
            raise SystemExit(1)

        # Determine log source type
        source_type = self._resolve_log_type(all_files)

        # Load detection engines
        yara_rules_dir = self.rules_dir / "yara"
        sigma_rules_dir = self.rules_dir / "sigma"

        if not self.quiet:
            console.print(f"[dim]Loading detection rules from {self.rules_dir}...[/dim]")

        yara_engine = YARAEngine(yara_rules_dir) if yara_rules_dir.exists() else None
        sigma_engine = SigmaEngine(sigma_rules_dir) if sigma_rules_dir.exists() else None

        # Initialise report
        report = AnalysisReport(
            generated_at=datetime.utcnow(),
            analyst_host=socket.gethostname(),
            input_files=[str(p) for p in all_files],
            log_source=source_type,
        )

        start_time = time.time()

        # Scan
        self._scan_files(all_files, source_type, yara_engine, sigma_engine, report)

        report.elapsed_seconds = time.time() - start_time

        # Persist to global state so the interactive shell can access it
        try:
            from .tui import state
            state.last_report = report
        except Exception:
            pass

        # --- SEARCH & EVENT NAME DETECTION PHASE ---
        if not self.options.get("no_search", False):
            self._run_search_phase(report)

        # Display results
        if not self.quiet:
            self._display_results(report)

        # Write report if requested
        if self.output and self.fmt != "table":
            gen = ReportGenerator(self.output, self.fmt)
            out_path = gen.write(report)
            if not self.quiet:
                console.print(f"\n[green]Report written to:[/green] {out_path}")

        return report

    def _resolve_files(self) -> list[Path]:
        result: list[Path] = []
        for p in self.input_paths:
            if p.is_dir():
                for ext in ["*.log", "*.txt", "*.json", "*.evtx", "*.xml", "*.csv"]:
                    result.extend(sorted(p.rglob(ext)))
            elif p.is_file():
                result.append(p)
        return result

    def _resolve_log_type(self, files: list[Path]) -> LogSourceType:
        if self.forced_type:
            try:
                return LogSourceType(self.forced_type)
            except ValueError:
                console.print(f"[yellow]Unknown log type '{self.forced_type}' — auto-detecting.[/yellow]")

        detector = AutoDetector()
        candidates = detector.detect(files[0])
        best, confidence = candidates[0]

        if not self.quiet:
            console.print(
                f"[dim]Auto-detected:[/dim] [bold]{LOG_SOURCE_LABELS.get(best, best.value)}[/bold] "
                f"([green]{confidence:.0%} confidence[/green])"
            )

        if self.no_tui or confidence >= 0.75:
            return best

        # Show interactive menu for confirmation
        return pick_log_source(candidates if confidence >= 0.4 else None)

    def _scan_files(
        self,
        files: list[Path],
        source_type: LogSourceType,
        yara_engine: Optional[YARAEngine],
        sigma_engine: Optional[SigmaEngine],
        report: AnalysisReport,
    ) -> None:
        parser = get_parser(source_type)

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        )

        file_task = progress.add_task("[cyan]Scanning files...", total=len(files))

        with progress:
            for file_path in files:
                progress.update(file_task, description=f"[cyan]Scanning[/cyan] {file_path.name}")
                parser.source_file = str(file_path)

                try:
                    for event in parser.parse(file_path):
                        report.total_events += 1

                        findings: list = []

                        if yara_engine:
                            try:
                                findings.extend(yara_engine.scan_event(event))
                            except Exception:
                                pass

                        if sigma_engine:
                            try:
                                findings.extend(sigma_engine.scan_event(event))
                            except Exception:
                                pass

                        for f in findings:
                            report.add_finding(f)
                            if not self.quiet:
                                self._print_finding_inline(f)

                except Exception as e:
                    report.parse_errors += 1
                    if self.verbose:
                        console.print(f"[red]Parse error in {file_path}: {e}[/red]")

                progress.advance(file_task)

    def _print_finding_inline(self, finding) -> None:
        """Print a finding as it is discovered."""
        ts = finding.timestamp.strftime("%Y-%m-%d %H:%M:%S") if finding.timestamp else "          "
        badge = severity_badge(finding.severity)
        engine = f"[dim][{finding.engine.upper()}][/dim]"
        mitre = ""
        if finding.mitre_technique:
            mitre = f" [dim]{finding.mitre_technique}[/dim]"
        console.print(
            f"{ts}  {badge}  {engine} {finding.rule_name}{mitre}  "
            f"[dim]{finding.source_file}:{finding.line_number}[/dim]"
        )
        if self.verbose and finding.matched_fields:
            for k, v in list(finding.matched_fields.items())[:3]:
                console.print(f"           [dim]{k}[/dim] → [italic]{v[:80]}[/italic]")

    def _display_results(self, report: AnalysisReport) -> None:
        """Print final summary table."""
        console.print()

        # Summary panel
        summary_grid = Table.grid(padding=(0, 2))
        summary_grid.add_column()
        summary_grid.add_column()
        summary_grid.add_row("[dim]Log source:[/dim]", LOG_SOURCE_LABELS.get(report.log_source, report.log_source.value))
        summary_grid.add_row("[dim]Events parsed:[/dim]", f"{report.total_events:,}")
        summary_grid.add_row("[dim]Parse errors:[/dim]", str(report.parse_errors))
        summary_grid.add_row("[dim]Elapsed:[/dim]", f"{report.elapsed_seconds:.1f}s")
        summary_grid.add_row("[dim]Findings:[/dim]", str(len(report.findings)))

        sev_parts = []
        for sev in Severity:
            count = report.severity_counts.get(sev.value, 0)
            if count:
                sev_parts.append(f"[{sev.rich_style}]{sev.value}: {count}[/{sev.rich_style}]")
        summary_grid.add_row("[dim]Breakdown:[/dim]", "  ".join(sev_parts) or "[green]Clean[/green]")

        console.print(Panel(summary_grid, title="[bold]Scan Summary[/bold]", border_style="blue"))

        if not report.findings:
            console.print("\n[bold green]No threats detected.[/bold green]\n")
            return

        # Findings table
        table = Table(
            title=f"[bold red]Findings ({len(report.findings)})[/bold red]",
            show_header=True,
            header_style="bold white on #1e293b",
            border_style="dim",
            show_lines=True,
        )
        table.add_column("Timestamp", style="dim", width=19)
        table.add_column("Severity", width=10)
        table.add_column("Engine", width=6)
        table.add_column("Rule", min_width=30)
        table.add_column("MITRE ATT&CK", width=25)
        table.add_column("Source", style="dim", width=25)

        for f in report.sorted_findings():
            ts = f.timestamp.strftime("%Y-%m-%d %H:%M:%S") if f.timestamp else "—"
            sev_str = f"[{f.severity.rich_style}]{f.severity.value}[/{f.severity.rich_style}]"
            engine_str = f"[cyan]{f.engine.upper()}[/cyan]"
            mitre = ""
            if f.mitre_tactic:
                mitre = f.mitre_tactic
            if f.mitre_technique:
                mitre += f"\n[dim]{f.mitre_technique}[/dim]"
            source = f"{Path(f.source_file).name}:{f.line_number}" if f.source_file else "—"

            table.add_row(ts, sev_str, engine_str, f.rule_name, mitre, source)

        console.print(table)
        console.print()

    def _run_search_phase(self, report) -> None:
        """Build search engines from the completed report and handle CLI search options."""
        from search.keyword_search import KeywordSearchEngine
        from search.event_search import EventSearchEngine
        from search.event_name_detector import EventNameDetector

        # Build minimal LogRecord-like objects from findings for the search engines
        log_records: list = []
        for f in report.findings:
            # Use Finding as a duck-typed LogRecord — both have .timestamp, .raw_line, etc.
            # Adapt field names so EventSearchEngine indices work correctly
            f.source_ip = getattr(f, "source_ip", None) or getattr(f, "log_source", None) or ""
            f.username = getattr(f, "username", None) or ""
            log_records.append(f)

        # Event name detection on findings (use raw_line attribute)
        name_detector = EventNameDetector(
            rules_dir=str(self.rules_dir),
            templates_path="data/event_templates.json",
            drain_threshold=0.4,
        )
        if report.findings:
            self._name_results = name_detector.detect_batch(
                report.findings,
                show_progress=not self.quiet,
            )
            for finding, result in zip(report.findings, self._name_results):
                finding.matched_fields = finding.matched_fields or {}
                finding.matched_fields["event_name"] = result.event_name
                finding.matched_fields["canonical_name"] = result.canonical_name or ""
                finding.matched_fields["mitre_auto"] = result.mitre_technique or ""
                finding.matched_fields["rarity_score"] = str(result.rarity_score)

        # Build search engines
        self._keyword_engine = KeywordSearchEngine(
            index_dir="search/search_index",
            records=report.findings,
        )
        self._event_engine = EventSearchEngine(
            alerts=report.findings,
            stat_results=[],
            log_records=log_records,
        )
        self._name_detector = name_detector

        # Store in global state for interactive shell
        try:
            from .tui import state
            state.keyword_engine = self._keyword_engine
            state.event_engine = self._event_engine
            state.name_detector = self._name_detector
            state.name_results = self._name_results
        except Exception:
            pass

        # Handle CLI search flags
        if self.options.get("search"):
            search_fields = (
                [self.options["search_field"]]
                if self.options.get("search_field") else None
            )
            results = self._keyword_engine.search(
                self.options["search"],
                fields=search_fields,
            )
            export_path = self.options.get("export_search", "search_results.json")
            self._keyword_engine.export_results(results, export_path)

        if self.options.get("pivot_ip"):
            pivot = self._event_engine.pivot_by_ip(self.options["pivot_ip"])
            self._display_pivot(pivot)

        if self.options.get("pivot_user"):
            pivot = self._event_engine.pivot_by_user(self.options["pivot_user"])
            self._display_pivot(pivot)

        if self.options.get("ioc"):
            results = self._event_engine.search_by_ioc(self.options["ioc"])
            console.print(
                Panel(
                    f"[bold]IOC Search:[/bold] {self.options['ioc']}  "
                    f"→  [cyan]{len(results)}[/cyan] matches",
                    border_style="yellow",
                )
            )

    def _display_pivot(self, pivot) -> None:
        """Print pivot analysis result to the terminal."""
        from rich.columns import Columns

        summary_grid = Table.grid(padding=(0, 2))
        summary_grid.add_column(style="dim")
        summary_grid.add_column()
        summary_grid.add_row("Entity", f"[bold]{pivot.entity_value}[/bold]")
        summary_grid.add_row("Type", pivot.entity_type)
        summary_grid.add_row("Total Events", str(pivot.total_events))
        fs = pivot.first_seen.strftime("%Y-%m-%d %H:%M:%S") if pivot.first_seen else "—"
        ls = pivot.last_seen.strftime("%Y-%m-%d %H:%M:%S") if pivot.last_seen else "—"
        summary_grid.add_row("First Seen", fs)
        summary_grid.add_row("Last Seen", ls)
        summary_grid.add_row("Log Sources", ", ".join(pivot.log_sources) or "—")
        summary_grid.add_row(
            "MITRE Techniques", ", ".join(pivot.mitre_techniques[:5]) or "—"
        )

        rules_table = Table(show_header=False, box=None)
        rules_table.add_column("Rule", style="cyan")
        for rule in pivot.unique_rules[:10]:
            rules_table.add_row(rule)

        console.print(Panel(
            Columns([summary_grid, rules_table]),
            title=f"[bold]Pivot: {pivot.entity_value}[/bold]",
            border_style="blue",
        ))
