"""Scan sub-menu — handles file/directory scanning with log type selection."""
from __future__ import annotations

from pathlib import Path

from rich import box
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from .console import console
from ..models.log_event import LOG_SOURCE_LABELS, LogSourceType
import threattrace.tui.state as state


def show_scan_menu(auto: bool = True, directory: bool = False) -> None:
    """
    Interactive scan sub-menu.

    Parameters
    ----------
    auto:       If True, auto-detect the log type after path is entered.
    directory:  If True, prompt for a directory path instead of a file.
    """
    while True:
        console.print()
        table = Table(
            title="SCAN & ANALYZE",
            box=box.ROUNDED,
            show_header=False,
            border_style="bright_cyan",
            title_style="bold white",
            expand=False,
            padding=(0, 1),
        )
        table.add_column("Key", style="bold bright_cyan", no_wrap=True, min_width=5)
        table.add_column("Option", style="white", min_width=60)

        if auto and not directory:
            table.add_row("[1]", "Scan File  [dim]— enter path, auto-detect log type[/dim]")
            table.add_row("[2]", "Scan File  [dim]— enter path, choose log type manually[/dim]")
            table.add_row("[3]", "Scan Directory  [dim]— auto-detect, scan all log files[/dim]")
        elif not auto:
            table.add_row("[1]", "Select Log Type First, then scan file")
            table.add_row("[2]", "Select Log Type First, then scan directory")
        else:
            table.add_row("[1]", "Scan Directory  [dim]— auto-detect log type per file[/dim]")
            table.add_row("[2]", "Scan Directory  [dim]— choose one log type for all files[/dim]")

        table.add_section()
        table.add_row("[0]", "[dim]Back to Main Menu[/dim]")
        console.print(table)
        console.print()

        choice = Prompt.ask(
            "[bold bright_cyan]Select option[/bold bright_cyan]",
            show_choices=False,
        ).strip().lower()

        if choice == "0":
            break
        elif choice == "1":
            if auto and not directory:
                _run_scan_file(force_type=False)
            elif not auto:
                _run_scan_file(force_type=True)
            else:
                _run_scan_dir(force_type=False)
        elif choice == "2":
            if auto and not directory:
                _run_scan_file(force_type=True)
            elif not auto:
                _run_scan_dir(force_type=True)
            else:
                _run_scan_dir(force_type=True)
        elif choice == "3" and auto and not directory:
            _run_scan_dir(force_type=False)
        else:
            console.print("[red]  Invalid option.[/red]")


def _prompt_path(label: str, must_exist: bool = True) -> Path | None:
    """Prompt user for a file or directory path."""
    while True:
        val = Prompt.ask(f"[bold cyan]  {label}[/bold cyan]").strip()
        if not val:
            return None
        p = Path(val).expanduser()
        if must_exist and not p.exists():
            console.print(f"[red]  Path does not exist: {p}[/red]")
            continue
        return p


def _prompt_log_type() -> LogSourceType | None:
    """Let the user select a log source type from a compact menu."""
    console.print()
    # Build a compact numbered list
    all_types = list(LogSourceType)
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
        border_style="yellow",
        expand=False,
        padding=(0, 1),
    )
    table.add_column("#", style="bold yellow", width=4, justify="right")
    table.add_column("Type ID", style="cyan", min_width=22)
    table.add_column("Description", style="dim")

    for i, lst in enumerate(all_types, start=1):
        table.add_row(str(i), lst.value, LOG_SOURCE_LABELS.get(lst, ""))

    console.print(table)
    console.print()

    while True:
        raw = Prompt.ask("[bold yellow]  Enter number (or 0 to cancel)[/bold yellow]").strip()
        if raw == "0" or not raw:
            return None
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(all_types):
                return all_types[idx]
        except ValueError:
            pass
        console.print(f"[red]  Enter a number between 1 and {len(all_types)}.[/red]")


def _run_scan_file(force_type: bool = False) -> None:
    """Prompt for a file path and run a scan."""
    path = _prompt_path("Enter file path")
    if path is None:
        return

    log_type = None
    if force_type:
        log_type_obj = _prompt_log_type()
        if log_type_obj is None:
            return
        log_type = log_type_obj.value

    _execute_scan([str(path)], log_type=log_type, no_tui=True)


def _run_scan_dir(force_type: bool = False) -> None:
    """Prompt for a directory path and run a scan."""
    path = _prompt_path("Enter directory path")
    if path is None:
        return
    if not path.is_dir():
        console.print("[red]  Path is not a directory.[/red]")
        return

    log_type = None
    if force_type:
        log_type_obj = _prompt_log_type()
        if log_type_obj is None:
            return
        log_type = log_type_obj.value

    _execute_scan([str(path)], log_type=log_type, no_tui=True)


def _execute_scan(
    files: list[str],
    log_type: str | None = None,
    no_tui: bool = True,
) -> None:
    """Execute a scan and store results in global state."""
    from ..app import ThreatTraceApp

    console.print()
    app = ThreatTraceApp(
        files=files,
        log_type=log_type,
        no_tui=no_tui,
        verbose=False,
        quiet=False,
    )
    try:
        report = app.run()
        state.last_report = report

        if report.findings:
            console.print()
            export = Prompt.ask(
                "[bold cyan]  Export report?[/bold cyan]",
                choices=["y", "n"],
                default="n",
            )
            if export == "y":
                _export_report_prompt(report)
        else:
            console.print("\n[bold green]  No threats detected.[/bold green]")

    except Exception as e:
        console.print(f"\n[red]  Scan error: {e}[/red]")

    console.print()
    Prompt.ask("[dim]  Press Enter to return[/dim]", default="")


def _export_report_prompt(report) -> None:
    from datetime import datetime
    from ..reports import ReportGenerator

    fmt = Prompt.ask(
        "[bold cyan]  Format[/bold cyan]",
        choices=["json", "html", "all"],
        default="html",
    )
    default = f"threattrace_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
    out = Prompt.ask("[bold cyan]  Output path[/bold cyan]", default=default).strip()
    gen = ReportGenerator(out, fmt)
    path = gen.write(report)
    console.print(f"\n[bold green]  Saved:[/bold green] {path}")
