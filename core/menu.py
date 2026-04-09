"""
core/menu.py — ThreatTrace animated terminal menu.

Interactive analysis flow:
  Step 1  — Animated banner + startup sequence
  Step 2  — Log source selection (colour-coded by category)
  Step 3  — Path input + validation
  Step 4  — Output format selection
  Step 5  — Output directory + analyst name
  Step 6  — Session summary + confirm
  Step 7  — Staged analysis progress bar
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.style import Style
from rich.table import Table
from rich.text import Text

console = Console()

# ---------------------------------------------------------------------------
# Colour scheme
# ---------------------------------------------------------------------------
BRAND_CYAN   = "bright_cyan"
BRAND_BLUE   = "bright_blue"
BRAND_GREEN  = "bright_green"
BRAND_YELLOW = "bright_yellow"
BRAND_RED    = "bright_red"
BRAND_MAGENTA = "bright_magenta"
BRAND_WHITE  = "bright_white"
DIM          = "dim"

# Category colours for log source table
CAT_COLORS = {
    "Web":       "bright_cyan",
    "Windows":   "bright_yellow",
    "Linux":     "bright_green",
    "Network":   "bright_magenta",
    "Cloud":     "bright_blue",
    "Auth":      "bright_red",
    "Container": "cyan",
    "Auto":      "bold bright_white",
}

CAT_ICONS = {
    "Web":       "🌐",
    "Windows":   "🪟",
    "Linux":     "🐧",
    "Network":   "🔌",
    "Cloud":     "☁️",
    "Auth":      "🔑",
    "Container": "🐳",
    "Auto":      "⚡",
}

# ---------------------------------------------------------------------------
# Log sources
# ---------------------------------------------------------------------------
LOG_SOURCES = [
    # (display_label, log_type, category)
    ("Apache Access Log",         "apache",         "Web"),
    ("Nginx Access Log",          "nginx",          "Web"),
    ("IIS Access Log",            "iis",            "Web"),
    ("Sysmon (XML / EVTX)",       "sysmon",         "Windows"),
    ("Windows Event Log (.evtx)", "windows_evtx",   "Windows"),
    ("Linux Syslog",              "syslog",         "Linux"),
    ("Linux Auth Log",            "auth_log",       "Linux"),
    ("Linux Auditd Log",          "auditd",         "Linux"),
    ("Cisco ASA Firewall",        "cisco_asa",      "Network"),
    ("Fortinet FortiGate",        "fortinet",       "Network"),
    ("pfSense Firewall",          "pfsense",        "Network"),
    ("Palo Alto Networks",        "palo_alto",      "Network"),
    ("DNS / BIND Log",            "dns_bind",       "Network"),
    ("Suricata EVE JSON",         "suricata",       "Network"),
    ("Zeek Logs",                 "zeek",           "Network"),
    ("AWS CloudTrail",            "cloudtrail",     "Cloud"),
    ("Azure Activity Log",        "azure_activity", "Cloud"),
    ("GCP Audit Log",             "gcp_audit",      "Cloud"),
    ("Okta System Log",           "okta",           "Auth"),
    ("Squid Proxy Log",           "squid",          "Network"),
    ("SSH Log",                   "ssh",            "Auth"),
    ("Docker Container Log",      "docker",         "Container"),
    ("Kubernetes (k8s) Log",      "k8s",            "Container"),
    ("Auto-Detect",               "auto",           "Auto"),
]

OUTPUT_FORMATS = {"1": "html", "2": "json", "3": "both"}
DEFAULT_OUTPUT_DIR = "./threattrace_reports"

ANALYSIS_STAGES = [
    ("Parsing {filename}",         0.15),
    ("Building Event Matrix",      0.20),
    ("Running YARA Rules",         0.20),
    ("Running Sigma Rules",        0.20),
    ("Running Correlation Engine", 0.15),
    ("Generating Report",          0.10),
]

# ---------------------------------------------------------------------------
# ASCII banner frames  (used for typewriter animation)
# ---------------------------------------------------------------------------
_BANNER_LINES = [
    r"  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗",
    r"     ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝",
    r"     ██║   ███████║██████╔╝█████╗  ███████║   ██║   ",
    r"     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ",
    r"     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ",
    r"     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ",
    r"",
    r"  ████████╗██████╗  █████╗  ██████╗███████╗",
    r"     ██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝",
    r"     ██║   ██████╔╝███████║██║     █████╗  ",
    r"     ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ",
    r"     ██║   ██║  ██║██║  ██║╚██████╗███████╗",
    r"     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝",
]

_LINE_STYLES = [
    "bold bright_cyan",
    "bold cyan",
    "bold bright_blue",
    "bold blue",
    "bold bright_cyan",
    "bold cyan",
    "",
    "bold bright_magenta",
    "bold magenta",
    "bold bright_blue",
    "bold blue",
    "bold bright_magenta",
    "bold magenta",
]

_TAGLINE = "  Cybersecurity Log Intelligence  ·  YARA + Sigma  ·  NIST SP 800-61"
_VERSION = "  v2.0  |  TLP:AMBER  |  Powered by ThreatTrace Engine"

_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


# ---------------------------------------------------------------------------
# Banner helpers
# ---------------------------------------------------------------------------

def _build_banner_text(revealed_lines: int = len(_BANNER_LINES)) -> Text:
    t = Text()
    for i, line in enumerate(_BANNER_LINES[:revealed_lines]):
        style = _LINE_STYLES[i] if i < len(_LINE_STYLES) else "white"
        t.append(line + "\n", style=style)
    return t


def _build_full_banner_panel(spinner_char: str = "") -> Panel:
    banner = _build_banner_text()
    banner.append("\n")
    banner.append(_TAGLINE + "\n", style="bold bright_white")
    banner.append(_VERSION, style="dim white")
    if spinner_char:
        banner.append(f"  {spinner_char}", style="bright_cyan")

    return Panel(
        banner,
        border_style="bright_cyan",
        padding=(1, 3),
        subtitle=(
            "[dim cyan]  ◆  Threat Intelligence Platform  ◆  [/dim cyan]"
        ),
    )


def print_static_banner() -> None:
    """Print the final banner panel instantly, with no animation."""
    console.print(_build_full_banner_panel())
    console.print()


def print_banner() -> None:
    """
    Animated banner: typewriter reveal then a brief spinner,
    then leave the final static banner on screen.
    """
    # Phase 1 — typewriter: reveal lines one by one
    with Live(console=console, refresh_per_second=30, transient=True) as live:
        for n in range(1, len(_BANNER_LINES) + 1):
            t = _build_banner_text(n)
            live.update(Panel(t, border_style="bright_cyan", padding=(1, 3)))
            time.sleep(0.045)

    # Phase 2 — spinner while "booting"
    boot_msgs = [
        "Loading detection rules…",
        "Initialising YARA engine…",
        "Initialising Sigma engine…",
        "Ready.",
    ]
    with Live(console=console, refresh_per_second=20, transient=True) as live:
        frame_idx = 0
        for msg in boot_msgs:
            for _ in range(12):
                spin = _SPINNER_FRAMES[frame_idx % len(_SPINNER_FRAMES)]
                t = _build_banner_text()
                t.append(f"\n  {spin} [dim]{msg}[/dim]", style="bright_cyan")
                live.update(Panel(t, border_style="bright_cyan", padding=(1, 3)))
                time.sleep(0.04)
                frame_idx += 1

    # Phase 3 — static final banner
    console.print(_build_full_banner_panel())
    console.print()


# ---------------------------------------------------------------------------
# Log source table  (two-column, colour-coded by category)
# ---------------------------------------------------------------------------

def _make_half_table(entries: list) -> Table:
    """
    One half of the log source list — clean bordered table with row lines.
    entries: list of (num, (label, key, cat))
    """
    t = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold bright_white",
        border_style="bright_cyan",
        show_lines=False,
        padding=(0, 1),
        expand=True,
    )
    t.add_column("#", style="bold bright_yellow", justify="right", width=3, no_wrap=True)
    t.add_column("Log Source", min_width=22, no_wrap=True)
    t.add_column("Category", width=11, no_wrap=True)

    for num, (label, _key, cat) in entries:
        color = CAT_COLORS.get(cat, "white")
        icon  = CAT_ICONS.get(cat, "")
        if cat == "Auto":
            label_cell = Text(f"{icon}  {label}", style="bold bright_white")
        else:
            label_cell = Text(f"{icon}  {label}", style=color)
        t.add_row(
            Text(str(num), style="bold bright_yellow"),
            label_cell,
            Text(f"[{cat}]", style=f"dim {color}"),
        )
    return t


def _build_source_grid() -> Table:
    """
    Outer 2-column table that holds the two half-tables side by side.
    Uses a borderless container so only the inner tables show their borders.
    """
    mid = (len(LOG_SOURCES) + 1) // 2
    left_t  = _make_half_table(list(enumerate(LOG_SOURCES[:mid],  start=1)))
    right_t = _make_half_table(list(enumerate(LOG_SOURCES[mid:], start=mid + 1)))

    grid = Table.grid(padding=(0, 2))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(left_t, right_t)
    return grid


def select_log_source() -> str:
    """Display coloured log source menu and return selected log_type."""
    console.print(
        Panel(
            _build_source_grid(),
            title="[bold bright_cyan]  ◆  Select Log Source  ◆  [/bold bright_cyan]",
            border_style="bright_cyan",
            padding=(1, 2),
        )
    )

    # Category legend
    legend_parts = []
    for cat, color in CAT_COLORS.items():
        icon = CAT_ICONS.get(cat, "")
        legend_parts.append(Text(f" {icon} {cat}  ", style=color))
    legend = Text()
    for p in legend_parts:
        legend.append_text(p)
    console.print(Align.center(legend))
    console.print()

    valid = [str(i) for i in range(1, len(LOG_SOURCES) + 1)]
    while True:
        choice = Prompt.ask(
            f"[bold bright_cyan]ThreatTrace ›[/bold bright_cyan] "
            f"[bright_white]Enter number[/bright_white]",
            default=str(len(LOG_SOURCES)),
        ).strip()
        if choice in valid:
            label, log_type, cat = LOG_SOURCES[int(choice) - 1]
            color = CAT_COLORS.get(cat, "white")
            console.print(
                f"  [dim]Selected:[/dim] [{color}]{label}[/{color}]  "
                f"[dim cyan]({log_type})[/dim cyan]\n"
            )
            return log_type
        console.print(
            f"  [red]✗  Invalid choice. Enter 1–{len(LOG_SOURCES)}.[/red]"
        )


# ---------------------------------------------------------------------------
# Path input
# ---------------------------------------------------------------------------

def prompt_path() -> str:
    while True:
        raw = Prompt.ask(
            "[bold bright_cyan]ThreatTrace ›[/bold bright_cyan] "
            "[bright_white]Path to log file or directory[/bright_white]"
        ).strip()
        expanded = os.path.expandvars(os.path.expanduser(raw))
        if Path(expanded).exists():
            console.print(
                f"  [bright_green]✔[/bright_green]  [dim]{expanded}[/dim]\n"
            )
            return expanded
        console.print(
            f"  [red]✗  Not found:[/red] [dim]{expanded}[/dim]\n"
        )


# ---------------------------------------------------------------------------
# Output format
# ---------------------------------------------------------------------------

def select_output_format() -> str:
    fmt_table = Table(
        box=box.ROUNDED,
        show_header=False,
        border_style="bright_magenta",
        padding=(0, 2),
        expand=False,
    )
    fmt_table.add_column("#",       style="bold bright_yellow", width=4, justify="right")
    fmt_table.add_column("Format",  min_width=36)

    fmt_table.add_row("1", Text("🌐  HTML   ", style="bright_cyan") +
                           Text("Interactive browser report", style="dim"))
    fmt_table.add_row("2", Text("{}  JSON   ", style="bright_yellow") +
                           Text("Machine-readable output",   style="dim"))
    fmt_table.add_row("3", Text("◈   Both  ", style="bright_green") +
                           Text("HTML + JSON combined",      style="dim"))

    console.print(
        Panel(
            fmt_table,
            title="[bold bright_magenta]  ◆  Output Format  ◆  [/bold bright_magenta]",
            border_style="bright_magenta",
            padding=(1, 1),
        )
    )
    while True:
        choice = Prompt.ask(
            "[bold bright_cyan]ThreatTrace ›[/bold bright_cyan] "
            "[bright_white]Format[/bright_white]",
            default="1",
        ).strip()
        if choice in OUTPUT_FORMATS:
            fmt = OUTPUT_FORMATS[choice]
            console.print(
                f"  [bright_green]✔[/bright_green]  Format: "
                f"[bold bright_green]{fmt.upper()}[/bold bright_green]\n"
            )
            return fmt
        console.print("  [red]✗  Please enter 1, 2, or 3.[/red]")


# ---------------------------------------------------------------------------
# Output directory + analyst
# ---------------------------------------------------------------------------

def prompt_output_dir() -> str:
    raw = Prompt.ask(
        "[bold bright_cyan]ThreatTrace ›[/bold bright_cyan] "
        "[bright_white]Output directory[/bright_white]",
        default=DEFAULT_OUTPUT_DIR,
    ).strip()
    expanded = os.path.expandvars(os.path.expanduser(raw))
    Path(expanded).mkdir(parents=True, exist_ok=True)
    console.print(
        f"  [bright_green]✔[/bright_green]  Reports → "
        f"[bright_green]{Path(expanded).resolve()}[/bright_green]\n"
    )
    return expanded


def prompt_analyst() -> str:
    name = Prompt.ask(
        "[bold bright_cyan]ThreatTrace ›[/bold bright_cyan] "
        "[bright_white]Analyst name[/bright_white]",
        default="Unknown Analyst",
    ).strip()
    return name or "Unknown Analyst"


# ---------------------------------------------------------------------------
# Analysis progress bar
# ---------------------------------------------------------------------------

_STAGE_COLORS = [
    "bright_cyan",
    "bright_blue",
    "bright_magenta",
    "bright_yellow",
    "bright_green",
    "bright_cyan",
]


def run_analysis_progress(filename: str) -> None:
    """Animated staged progress bar for the analysis pipeline."""
    total_weight = sum(w for _, w in ANALYSIS_STAGES)

    console.print()
    with Progress(
        SpinnerColumn(spinner_name="dots2", style="bright_cyan"),
        TextColumn(
            "[progress.description]{task.description}",
            table_column=None,
        ),
        BarColumn(bar_width=38, style="bright_blue", complete_style="bright_cyan"),
        TaskProgressColumn(style="bright_yellow"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task(
            f"[bright_cyan]Parsing {filename}…[/bright_cyan]",
            total=100,
        )
        completed = 0.0
        for (stage_label, weight), color in zip(ANALYSIS_STAGES, _STAGE_COLORS):
            label = stage_label.format(filename=filename)
            progress.update(
                task,
                description=f"[{color}]  ◆  {label}…[/{color}]",
            )
            step_pct = weight / total_weight * 100
            steps = max(1, int(step_pct * 2))
            for _ in range(steps):
                time.sleep(0.025)
                inc = step_pct / steps
                completed = min(completed + inc, 100)
                progress.update(task, completed=completed)

        progress.update(
            task,
            description=f"[bright_cyan]  ◆  Starting analysis engines…[/bright_cyan]",
            completed=100,
        )

    console.print()


def show_analysis_complete_banner(report_paths: Optional[List[str]] = None) -> None:
    """
    Display the '✔ Analysis Complete' banner.

    Must be called AFTER the real analysis pipeline has fully finished
    (parsing, detection, analytics, and report generation all complete).

    Parameters
    ----------
    report_paths : list of str, optional
        Paths of generated report files to show beneath the banner.
    """
    done = Panel(
        Align.center(
            Text("✔  Analysis Complete", style="bold bright_green")
            + Text("  —  Report generated successfully", style="dim green")
        ),
        border_style="bright_green",
        padding=(0, 4),
    )
    console.print(done)
    if report_paths:
        for p in report_paths:
            console.print(
                f"  [bright_green]✔[/bright_green]  "
                f"[dim]Report →[/dim] [bright_white]{p}[/bright_white]"
            )
    console.print()


# ---------------------------------------------------------------------------
# Session summary + confirm
# ---------------------------------------------------------------------------

def _build_summary_panel(session: Dict) -> Panel:
    t = Table(
        box=box.SIMPLE,
        show_header=False,
        show_edge=False,
        padding=(0, 1),
        expand=False,
    )
    t.add_column("Key",   style="dim", width=16)
    t.add_column("Value", style="bold bright_white")

    rows = [
        ("Log type",   session["log_type"]),
        ("Path",       str(session["path"])[:72]),
        ("Output dir", str(Path(session["output_dir"]).resolve())[:72]),
        ("Format",     session["output_format"].upper()),
        ("Analyst",    session["analyst"]),
    ]
    for k, v in rows:
        t.add_row(
            Text(k, style="dim bright_cyan"),
            Text(v, style="bright_white"),
        )

    return Panel(
        t,
        title="[bold bright_yellow]  ◆  Session Summary  ◆  [/bold bright_yellow]",
        border_style="bright_yellow",
        padding=(1, 2),
    )


# ---------------------------------------------------------------------------
# Main interactive flow
# ---------------------------------------------------------------------------

def run_interactive_menu() -> Dict[str, Any]:
    """
    Execute the full interactive menu flow.

    Returns a session dict:
        log_type, path, output_dir, output_format, analyst
    """
    print_static_banner()

    console.print(Rule(style="bright_cyan"))
    console.print()

    log_type   = select_log_source()
    path       = prompt_path()
    output_fmt = select_output_format()
    output_dir = prompt_output_dir()
    analyst    = prompt_analyst()

    session: Dict[str, Any] = {
        "log_type":      log_type,
        "path":          path,
        "output_dir":    output_dir,
        "output_format": output_fmt,
        "analyst":       analyst,
    }

    console.print(_build_summary_panel(session))
    console.print()

    if not Confirm.ask(
        "[bold bright_cyan]ThreatTrace ›[/bold bright_cyan] "
        "[bright_white]Start analysis?[/bright_white]",
        default=True,
    ):
        console.print(
            "\n  [bright_yellow]✗  Analysis cancelled.[/bright_yellow]\n"
        )
        raise KeyboardInterrupt("User cancelled")

    console.print()
    return session
