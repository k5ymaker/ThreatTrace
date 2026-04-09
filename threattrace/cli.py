"""ThreatTrace CLI entry point."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click

from . import __version__


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version")
@click.argument("files", nargs=-1, type=click.Path(exists=True))
@click.option(
    "--type", "-t", "log_type",
    default=None,
    metavar="TYPE",
    help="Force log source type (e.g. apache_access, windows_evtx). Skip auto-detection.",
)
@click.option(
    "--output", "-o",
    default=None,
    metavar="PATH",
    help="Output path for report file.",
)
@click.option(
    "--format", "-f", "fmt",
    default="table",
    type=click.Choice(["table", "json", "html", "all"], case_sensitive=False),
    show_default=True,
    help="Output format. 'table' prints to terminal only.",
)
@click.option(
    "--rules", "-r",
    default=None,
    metavar="DIR",
    help="Path to custom rules directory (default: <install>/rules).",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Show matched field values for each finding.",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    help="Suppress all output except findings (useful for piping).",
)
@click.option(
    "--no-tui",
    is_flag=True,
    help="Skip interactive menu — always use auto-detected log type.",
)
@click.option(
    "--list-types",
    is_flag=True,
    help="List all supported log source types and exit.",
)
@click.option(
    "--search",
    default=None,
    metavar="QUERY",
    help="Keyword search query (Boolean supported, e.g. 'src_ip:10.0.0.1 AND NOT uri:favicon').",
)
@click.option(
    "--search-field",
    default=None,
    metavar="FIELD",
    help="Specific field to search (uri/username/src_ip/etc).",
)
@click.option(
    "--event-type",
    default=None,
    metavar="NAME",
    help="Filter results by event type name (partial match on rule name).",
)
@click.option(
    "--severity",
    "severity_filter",
    default=None,
    metavar="LEVELS",
    help="Comma-separated severity filter (e.g. CRITICAL,HIGH).",
)
@click.option(
    "--from-time",
    default=None,
    metavar="DATETIME",
    help="Start time filter: YYYY-MM-DD HH:MM.",
)
@click.option(
    "--to-time",
    default=None,
    metavar="DATETIME",
    help="End time filter: YYYY-MM-DD HH:MM.",
)
@click.option(
    "--pivot-ip",
    default=None,
    metavar="IP",
    help="Pivot analysis for a specific IP address.",
)
@click.option(
    "--pivot-user",
    default=None,
    metavar="USER",
    help="Pivot analysis for a specific username.",
)
@click.option(
    "--ioc",
    default=None,
    metavar="IOC",
    help="Search all events for a specific IOC (IP, domain, hash).",
)
@click.option(
    "--export-search",
    default=None,
    metavar="PATH",
    help="Path to export search results (JSON or CSV).",
)
@click.option(
    "--no-search",
    is_flag=True,
    help="Skip search module entirely.",
)
def main(
    files: tuple[str, ...],
    log_type: Optional[str],
    output: Optional[str],
    fmt: str,
    rules: Optional[str],
    verbose: bool,
    quiet: bool,
    no_tui: bool,
    list_types: bool,
    search: Optional[str],
    search_field: Optional[str],
    event_type: Optional[str],
    severity_filter: Optional[str],
    from_time: Optional[str],
    to_time: Optional[str],
    pivot_ip: Optional[str],
    pivot_user: Optional[str],
    ioc: Optional[str],
    export_search: Optional[str],
    no_search: bool,
) -> None:
    """ThreatTrace — Cybersecurity log analysis with YARA + Sigma detection.

    Provide one or more FILE paths (or a directory) to scan.
    If no files are provided, the interactive log type menu will be shown.

    \b
    Examples:
      threattrace /var/log/auth.log
      threattrace -t apache_access /var/log/apache2/access.log -o report.html -f html
      threattrace /logs/ --no-tui --quiet -o findings.json -f json
    """
    if list_types:
        _print_log_types()
        return

    if fmt != "table" and output is None:
        click.echo(
            "Warning: --format requires --output to write a file. "
            "Defaulting to terminal table output.",
            err=True,
        )
        fmt = "table"

    if not files:
        if no_tui:
            click.echo("Error: no files provided. Pass at least one FILE argument.", err=True)
            sys.exit(1)
        # Show interactive menu without a file — ask for file path
        from .tui.console import console
        from rich.prompt import Prompt
        path_str = Prompt.ask("[bold cyan]Enter path to log file or directory[/bold cyan]")
        if not path_str or not Path(path_str).exists():
            console.print("[red]Path does not exist.[/red]")
            sys.exit(1)
        files = (path_str,)

    from .app import ThreatTraceApp
    app = ThreatTraceApp(
        files=list(files),
        log_type=log_type,
        rules_dir=rules,
        verbose=verbose,
        quiet=quiet,
        no_tui=no_tui,
        output=output,
        fmt=fmt,
        options={
            "search": search,
            "search_field": search_field,
            "event_type": event_type,
            "severity_filter": severity_filter,
            "from_time": from_time,
            "to_time": to_time,
            "pivot_ip": pivot_ip,
            "pivot_user": pivot_user,
            "ioc": ioc,
            "export_search": export_search,
            "no_search": no_search,
        },
    )
    app.run()


def _print_log_types() -> None:
    from rich.table import Table
    from .models.log_event import LOG_SOURCE_LABELS, LogSourceType
    from .tui.console import console

    table = Table(title="Supported Log Source Types", show_header=True, header_style="bold")
    table.add_column("Type ID", style="cyan")
    table.add_column("Description")

    for lst in LogSourceType:
        table.add_row(lst.value, LOG_SOURCE_LABELS.get(lst, ""))

    console.print(table)
