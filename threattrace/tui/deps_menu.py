"""Dependency status sub-menu — check tool availability and rule health."""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

from rich import box
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from .console import console

_RULES_DIR = Path(__file__).parent.parent.parent / "rules"


def show_deps_menu() -> None:
    """Dependency Manager sub-menu."""
    while True:
        console.print()
        table = Table(
            title="DEPENDENCY STATUS",
            box=box.ROUNDED,
            show_header=False,
            border_style="bright_white",
            title_style="bold white",
            expand=False,
            padding=(0, 1),
        )
        table.add_column("Key", style="bold bright_white", no_wrap=True, min_width=5)
        table.add_column("Option", style="white", min_width=55)

        table.add_row("[1]", "Check Python Libraries")
        table.add_row("[2]", "Check YARA Rule Files")
        table.add_row("[3]", "Check Sigma Rule Files")
        table.add_row("[4]", "Full System Check")
        table.add_section()
        table.add_row("[0]", "[dim]Back to Main Menu[/dim]")
        console.print(table)
        console.print()

        choice = Prompt.ask(
            "[bold bright_white]Select option[/bold bright_white]",
            show_choices=False,
        ).strip()

        if choice == "0":
            break
        elif choice == "1":
            _check_libraries()
        elif choice == "2":
            _check_yara_rules()
        elif choice == "3":
            _check_sigma_rules()
        elif choice == "4":
            _check_libraries()
            _check_yara_rules()
            _check_sigma_rules()
            Prompt.ask("[dim]  Press Enter to return[/dim]", default="")
        else:
            console.print("[red]  Invalid option.[/red]")


def _check_libraries() -> None:
    """Check all required and optional Python library dependencies."""
    _LIBS = [
        ("rich",          True,  "Terminal UI — required"),
        ("click",         True,  "CLI interface — required"),
        ("yaml",          True,  "Sigma rule parsing — required"),
        ("jinja2",        True,  "HTML report generation — required"),
        ("yara",          False, "YARA detection engine — optional (pip install yara-python)"),
        ("Evtx",          False, "Windows EVTX parsing — optional (pip install python-evtx)"),
    ]

    table = Table(
        title="[bold white]Python Library Status[/bold white]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on grey23",
        border_style="bright_white",
        expand=False,
        show_lines=True,
    )
    table.add_column("Library", style="bold", min_width=20)
    table.add_column("Status", min_width=12)
    table.add_column("Version", style="dim", min_width=12)
    table.add_column("Notes", style="dim")

    for lib, required, note in _LIBS:
        try:
            mod = importlib.import_module(lib)
            version = getattr(mod, "__version__", getattr(mod, "YARA_VERSION", "—"))
            status = "[bold green]  INSTALLED[/bold green]"
        except ImportError:
            version = "—"
            if required:
                status = "[bold red]  MISSING[/bold red]"
            else:
                status = "[bold yellow]  NOT FOUND[/bold yellow]"
        table.add_row(lib, status, str(version), note)

    console.print()
    console.print(table)
    console.print()
    Prompt.ask("[dim]  Press Enter to return[/dim]", default="")


def _check_yara_rules() -> None:
    """Check YARA rule files for existence and count."""
    yara_dir = _RULES_DIR / "yara"
    if not yara_dir.exists():
        console.print("[red]  YARA rules directory not found.[/red]")
        return

    table = Table(
        title="[bold white]YARA Rule Files[/bold white]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on grey23",
        border_style="yellow",
        expand=False,
        show_lines=True,
    )
    table.add_column("Category", style="bold yellow", min_width=16)
    table.add_column("File", style="cyan", min_width=30)
    table.add_column("Rules", justify="right", min_width=6)
    table.add_column("Status", min_width=12)

    import re
    total_rules = 0
    total_files = 0

    for yar in sorted(yara_dir.rglob("*.yar")):
        cat = yar.parent.name
        try:
            content = yar.read_text(encoding="utf-8", errors="replace")
            rule_count = len(re.findall(r"^rule\s+\w+", content, re.MULTILINE))
            total_rules += rule_count
            total_files += 1

            # Quick syntax validation via yara if available
            status = "[bold green]OK[/bold green]"
            try:
                import yara
                yara.compile(filepath=str(yar))
            except ImportError:
                status = "[bold yellow]UNVERIFIED[/bold yellow]"
            except Exception as e:
                status = f"[bold red]ERROR: {str(e)[:30]}[/bold red]"

            table.add_row(cat, yar.name, str(rule_count), status)
        except Exception as e:
            table.add_row(cat, yar.name, "?", f"[red]READ ERROR: {e}[/red]")

    table.add_section()
    table.add_row(
        "[bold]Total[/bold]",
        f"[dim]{total_files} files[/dim]",
        f"[bold]{total_rules}[/bold]",
        "",
    )

    console.print()
    console.print(table)
    console.print()
    Prompt.ask("[dim]  Press Enter to return[/dim]", default="")


def _check_sigma_rules() -> None:
    """Check Sigma rule files and report load status."""
    sigma_dir = _RULES_DIR / "sigma"
    if not sigma_dir.exists():
        console.print("[red]  Sigma rules directory not found.[/red]")
        return

    from ..detectors.sigma_engine import SigmaEngine, _load_sigma_rule
    import yaml

    table = Table(
        title="[bold white]Sigma Rule Files[/bold white]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on grey23",
        border_style="yellow",
        expand=False,
        show_lines=True,
    )
    table.add_column("Category", style="bold yellow", min_width=12)
    table.add_column("File", style="cyan", min_width=36)
    table.add_column("Rules", justify="right", min_width=6)
    table.add_column("Status", min_width=10)

    total_rules = 0
    total_files = 0

    for rf in sorted(sigma_dir.rglob("*.yml")):
        cat = rf.parent.name
        try:
            content = rf.read_text(encoding="utf-8", errors="replace")
            docs = list(yaml.safe_load_all(content))
            loaded = sum(1 for d in docs if _load_sigma_rule(d) is not None)
            total_rules += loaded
            total_files += 1
            status = "[bold green]OK[/bold green]" if loaded > 0 else "[bold yellow]EMPTY[/bold yellow]"
            table.add_row(cat, rf.name, str(loaded), status)
        except Exception as e:
            table.add_row(cat, rf.name, "?", f"[red]{str(e)[:30]}[/red]")

    table.add_section()
    table.add_row(
        "[bold]Total[/bold]",
        f"[dim]{total_files} files[/dim]",
        f"[bold]{total_rules}[/bold]",
        "",
    )

    console.print()
    console.print(table)
    console.print()
    Prompt.ask("[dim]  Press Enter to return[/dim]", default="")
