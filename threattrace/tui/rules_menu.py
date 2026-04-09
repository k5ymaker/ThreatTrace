"""Rules browser sub-menu — browse YARA and Sigma rules by category."""
from __future__ import annotations

from pathlib import Path

from rich import box
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from .console import console

_RULES_DIR = Path(__file__).parent.parent.parent / "rules"


def show_rules_menu(engine_filter: str | None = None) -> None:
    """
    Rules browser sub-menu.

    Parameters
    ----------
    engine_filter: "yara" | "sigma" | None (show both)
    """
    while True:
        console.print()
        table = Table(
            title="RULE BROWSER",
            box=box.ROUNDED,
            show_header=False,
            border_style="yellow",
            title_style="bold white",
            expand=False,
            padding=(0, 1),
        )
        table.add_column("Key", style="bold yellow", no_wrap=True, min_width=5)
        table.add_column("Option", style="white", min_width=60)

        if engine_filter is None or engine_filter == "yara":
            table.add_row("[1]", "YARA Rules  [dim]— browse by category[/dim]")
        if engine_filter is None or engine_filter == "sigma":
            table.add_row("[2]", "Sigma Rules  [dim]— browse by MITRE tactic or category[/dim]")
        if engine_filter is None:
            table.add_row("[3]", "All Rules Summary  [dim]— counts by severity[/dim]")
        table.add_section()
        table.add_row("[0]", "[dim]Back to Main Menu[/dim]")
        console.print(table)
        console.print()

        choice = Prompt.ask(
            "[bold yellow]Select option[/bold yellow]",
            show_choices=False,
        ).strip().lower()

        if choice == "0":
            break
        elif choice == "1" and (engine_filter is None or engine_filter == "yara"):
            _show_yara_browser()
        elif choice == "2" and (engine_filter is None or engine_filter == "sigma"):
            _show_sigma_browser()
        elif choice == "3" and engine_filter is None:
            _show_rules_summary()
        else:
            console.print("[red]  Invalid option.[/red]")


def _show_yara_browser() -> None:
    """Browse YARA rules organized by file/category."""
    yara_dir = _RULES_DIR / "yara"
    if not yara_dir.exists():
        console.print("[red]  YARA rules directory not found.[/red]")
        Prompt.ask("[dim]  Press Enter to return[/dim]", default="")
        return

    # Collect all .yar files grouped by subdirectory
    categories: dict[str, list[Path]] = {}
    for yar in sorted(yara_dir.rglob("*.yar")):
        cat = yar.parent.name
        categories.setdefault(cat, []).append(yar)

    while True:
        console.print()
        table = Table(
            title="YARA RULES — CATEGORIES",
            box=box.ROUNDED,
            show_header=False,
            border_style="yellow",
            title_style="bold white",
            expand=False,
            padding=(0, 1),
        )
        table.add_column("Key", style="bold yellow", min_width=5)
        table.add_column("Category", style="white", min_width=20)
        table.add_column("Files", style="dim", min_width=6, justify="right")

        cat_list = sorted(categories)
        for i, cat in enumerate(cat_list, start=1):
            table.add_row(f"[{i}]", cat.upper(), str(len(categories[cat])))
        table.add_section()
        table.add_row("[0]", "[dim]Back[/dim]", "")
        console.print(table)
        console.print()

        choice = Prompt.ask(
            "[bold yellow]  Select category[/bold yellow]",
            show_choices=False,
        ).strip()

        if choice == "0":
            break

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(cat_list):
                _display_yara_rules_in_category(cat_list[idx], categories[cat_list[idx]])
            else:
                console.print("[red]  Invalid choice.[/red]")
        except ValueError:
            console.print("[red]  Enter a number.[/red]")


def _display_yara_rules_in_category(cat: str, yar_files: list[Path]) -> None:
    """Parse and display rules from YARA files in a category."""
    import re

    rule_re = re.compile(
        r"rule\s+(?P<name>\w+)\s*\{[^}]*?meta:[^}]*?description\s*=\s*\"(?P<desc>[^\"]+)\"[^}]*?"
        r"severity\s*=\s*\"(?P<sev>[^\"]+)\"[^}]*?mitre_technique\s*=\s*\"(?P<tech>[^\"]+)\"",
        re.DOTALL | re.IGNORECASE,
    )

    table = Table(
        title=f"YARA — {cat.upper()}",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on grey23",
        border_style="yellow",
        expand=True,
        show_lines=True,
    )
    table.add_column("Rule Name", style="bold cyan", min_width=30)
    table.add_column("Severity", min_width=10)
    table.add_column("MITRE", style="dim", min_width=10)
    table.add_column("Description", style="dim")

    _SEV_STYLES = {
        "critical": "bold red",
        "high": "bold yellow",
        "medium": "bold dark_orange",
        "low": "bold cyan",
        "info": "bold blue",
    }

    for yar in yar_files:
        content = yar.read_text(encoding="utf-8", errors="replace")
        found_any = False
        for m in rule_re.finditer(content):
            found_any = True
            sev = m.group("sev").lower()
            sev_style = _SEV_STYLES.get(sev, "white")
            table.add_row(
                m.group("name"),
                f"[{sev_style}]{sev.upper()}[/{sev_style}]",
                m.group("tech"),
                m.group("desc"),
            )
        if not found_any:
            # Simpler fallback: just show rule names
            for nm in re.findall(r"^rule\s+(\w+)", content, re.MULTILINE):
                table.add_row(nm, "—", "—", f"[dim]{yar.name}[/dim]")

    console.print()
    console.print(table)
    console.print()
    Prompt.ask("[dim]  Press Enter to return[/dim]", default="")


def _show_sigma_browser() -> None:
    """Browse Sigma rules organized by category/tactic."""
    from ..detectors.sigma_engine import SigmaEngine

    sigma_dir = _RULES_DIR / "sigma"
    if not sigma_dir.exists():
        console.print("[red]  Sigma rules directory not found.[/red]")
        Prompt.ask("[dim]  Press Enter to return[/dim]", default="")
        return

    engine = SigmaEngine(sigma_dir)
    rules = engine._rules

    while True:
        console.print()
        table = Table(
            title="SIGMA RULES — FILTER BY",
            box=box.ROUNDED,
            show_header=False,
            border_style="yellow",
            title_style="bold white",
            expand=False,
            padding=(0, 1),
        )
        table.add_column("Key", style="bold yellow", min_width=5)
        table.add_column("Option", style="white", min_width=50)

        table.add_row("[1]", f"All Rules  [dim]({len(rules)} total)[/dim]")
        table.add_row("[2]", "Filter by Tactic")
        table.add_row("[3]", "Filter by Severity")
        table.add_row("[4]", "Filter by Log Source")
        table.add_section()
        table.add_row("[0]", "[dim]Back[/dim]")
        console.print(table)
        console.print()

        choice = Prompt.ask(
            "[bold yellow]  Select filter[/bold yellow]",
            show_choices=False,
        ).strip()

        if choice == "0":
            break
        elif choice == "1":
            _display_sigma_rules(rules, "All Sigma Rules")
        elif choice == "2":
            _sigma_filter_tactic(rules)
        elif choice == "3":
            _sigma_filter_severity(rules)
        elif choice == "4":
            _sigma_filter_logsource(rules)
        else:
            console.print("[red]  Invalid option.[/red]")


def _display_sigma_rules(rules: list, title: str = "Sigma Rules") -> None:
    from ..models.finding import Severity

    table = Table(
        title=f"[bold white]{title}[/bold white]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on grey23",
        border_style="yellow",
        expand=True,
        show_lines=True,
    )
    table.add_column("Rule", style="bold white", min_width=36)
    table.add_column("Severity", min_width=10)
    table.add_column("Tactic", style="dim", min_width=22)
    table.add_column("Technique", style="dim cyan", min_width=10)
    table.add_column("Log Source", style="dim", min_width=16)

    for rule in sorted(rules, key=lambda r: r.severity.sort_order):
        sev_style = rule.severity.rich_style
        tactic = rule.mitre_tactics[0] if rule.mitre_tactics else "—"
        tech = rule.mitre_techniques[0] if rule.mitre_techniques else "—"
        ls = f"{rule.logsource.get('product', '')} / {rule.logsource.get('service', '')}".strip(" /") or rule._logsource_key
        table.add_row(
            rule.title,
            f"[{sev_style}]{rule.severity.value}[/{sev_style}]",
            tactic,
            tech,
            ls,
        )

    console.print()
    console.print(table)
    console.print()
    Prompt.ask("[dim]  Press Enter to return[/dim]", default="")


def _sigma_filter_tactic(rules: list) -> None:
    from collections import Counter
    tactics = Counter()
    for r in rules:
        for t in r.mitre_tactics:
            tactics[t] += 1
    if not tactics:
        console.print("[yellow]  No tactic information available.[/yellow]")
        return

    tactic_list = sorted(tactics)
    console.print()
    for i, t in enumerate(tactic_list, start=1):
        console.print(f"  [bold yellow][{i}][/bold yellow] {t}  [dim]({tactics[t]} rules)[/dim]")
    console.print()

    choice = Prompt.ask("[bold yellow]  Select tactic number[/bold yellow]").strip()
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(tactic_list):
            selected = tactic_list[idx]
            filtered = [r for r in rules if selected in r.mitre_tactics]
            _display_sigma_rules(filtered, f"Sigma Rules — {selected}")
    except ValueError:
        pass


def _sigma_filter_severity(rules: list) -> None:
    from ..models.finding import Severity

    console.print()
    for i, sev in enumerate(Severity, start=1):
        count = sum(1 for r in rules if r.severity == sev)
        console.print(
            f"  [bold yellow][{i}][/bold yellow] [{sev.rich_style}]{sev.value}[/{sev.rich_style}]  [dim]({count} rules)[/dim]"
        )
    console.print()

    choice = Prompt.ask("[bold yellow]  Select severity number[/bold yellow]").strip()
    try:
        sev_list = list(Severity)
        idx = int(choice) - 1
        if 0 <= idx < len(sev_list):
            selected = sev_list[idx]
            filtered = [r for r in rules if r.severity == selected]
            _display_sigma_rules(filtered, f"Sigma Rules — {selected.value}")
    except ValueError:
        pass


def _sigma_filter_logsource(rules: list) -> None:
    from collections import Counter
    sources = Counter(r._logsource_key for r in rules)
    src_list = sorted(sources)

    console.print()
    for i, s in enumerate(src_list, start=1):
        console.print(f"  [bold yellow][{i}][/bold yellow] {s}  [dim]({sources[s]} rules)[/dim]")
    console.print()

    choice = Prompt.ask("[bold yellow]  Select log source number[/bold yellow]").strip()
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(src_list):
            selected = src_list[idx]
            filtered = [r for r in rules if r._logsource_key == selected]
            _display_sigma_rules(filtered, f"Sigma Rules — {selected}")
    except ValueError:
        pass


def _show_rules_summary() -> None:
    """Show a summary of all loaded rules with counts by engine and severity."""
    from ..detectors.sigma_engine import SigmaEngine
    from ..models.finding import Severity
    import re

    sigma_dir = _RULES_DIR / "sigma"
    yara_dir = _RULES_DIR / "yara"

    sigma_rules: list = []
    if sigma_dir.exists():
        engine = SigmaEngine(sigma_dir)
        sigma_rules = engine._rules

    yara_count = 0
    yara_by_sev: dict[str, int] = {}
    if yara_dir.exists():
        rule_re = re.compile(r'severity\s*=\s*"(\w+)"', re.IGNORECASE)
        for yar in yara_dir.rglob("*.yar"):
            content = yar.read_text(encoding="utf-8", errors="replace")
            for m in re.finditer(r"^rule\s+\w+", content, re.MULTILINE):
                yara_count += 1
            for m in rule_re.finditer(content):
                sev = m.group(1).upper()
                yara_by_sev[sev] = yara_by_sev.get(sev, 0) + 1

    table = Table(
        title="[bold white]Detection Rules Summary[/bold white]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on grey23",
        border_style="yellow",
        expand=False,
        show_lines=True,
    )
    table.add_column("Engine", style="bold", min_width=12)
    table.add_column("Total", justify="right", style="bold", min_width=8)
    for sev in Severity:
        table.add_column(sev.value, justify="right", min_width=8, style=sev.rich_style)

    sigma_by_sev: dict[str, int] = {}
    for r in sigma_rules:
        sigma_by_sev[r.severity.value] = sigma_by_sev.get(r.severity.value, 0) + 1

    sigma_row = ["Sigma (YAML)", str(len(sigma_rules))]
    for sev in Severity:
        sigma_row.append(str(sigma_by_sev.get(sev.value, 0)))
    table.add_row(*sigma_row)

    yara_row = ["YARA", str(yara_count)]
    for sev in Severity:
        yara_row.append(str(yara_by_sev.get(sev.value, 0)))
    table.add_row(*yara_row)

    total_row = ["Total", str(len(sigma_rules) + yara_count)]
    combined = {}
    for d in (sigma_by_sev, yara_by_sev):
        for k, v in d.items():
            combined[k] = combined.get(k, 0) + v
    for sev in Severity:
        total_row.append(str(combined.get(sev.value, 0)))
    table.add_row(*total_row)

    console.print()
    console.print(table)
    console.print()
    Prompt.ask("[dim]  Press Enter to return[/dim]", default="")
