"""Interactive TUI menu for log source selection and search."""
from __future__ import annotations

from rich.columns import Columns
from rich.panel import Panel
from rich.prompt import IntPrompt, Prompt
from rich.table import Table

from ..models.log_event import LOG_SOURCE_LABELS, LogSourceType
from .console import console

# Menu categories with their log source types
MENU_CATEGORIES: list[tuple[str, list[LogSourceType]]] = [
    ("Web Servers", [
        LogSourceType.APACHE_ACCESS,
        LogSourceType.APACHE_ERROR,
        LogSourceType.NGINX_ACCESS,
        LogSourceType.NGINX_ERROR,
        LogSourceType.IIS_W3C,
        LogSourceType.HAPROXY,
    ]),
    ("OS — Windows", [
        LogSourceType.WINDOWS_EVTX,
        LogSourceType.WINDOWS_EVTX_XML,
        LogSourceType.WINDOWS_SYSMON,
        LogSourceType.WINDOWS_POWERSHELL,
    ]),
    ("OS — Linux/Unix", [
        LogSourceType.LINUX_SYSLOG,
        LogSourceType.LINUX_AUTH_LOG,
        LogSourceType.LINUX_KERN_LOG,
        LogSourceType.LINUX_AUDIT,
        LogSourceType.LINUX_CRON,
        LogSourceType.LINUX_BASH_HISTORY,
    ]),
    ("Network Devices", [
        LogSourceType.FIREWALL_CISCO_ASA,
        LogSourceType.FIREWALL_PALO_ALTO,
        LogSourceType.FIREWALL_FORTINET,
        LogSourceType.FIREWALL_PFSENSE,
        LogSourceType.ZEEK_CONN,
        LogSourceType.ZEEK_DNS,
        LogSourceType.ZEEK_HTTP,
        LogSourceType.SURICATA_EVE,
        LogSourceType.NETFLOW,
    ]),
    ("Proxy & DNS", [
        LogSourceType.SQUID_PROXY,
        LogSourceType.DNS_BIND,
        LogSourceType.DNS_WINDOWS,
    ]),
    ("Authentication & IAM", [
        LogSourceType.ACTIVE_DIRECTORY,
        LogSourceType.RADIUS,
        LogSourceType.LDAP,
    ]),
    ("Cloud Platforms", [
        LogSourceType.AWS_CLOUDTRAIL,
        LogSourceType.AWS_VPC_FLOW,
        LogSourceType.AZURE_ACTIVITY,
        LogSourceType.AZURE_SIGNIN,
        LogSourceType.GCP_AUDIT,
    ]),
    ("Email Systems", [
        LogSourceType.POSTFIX,
        LogSourceType.EXCHANGE,
    ]),
    ("Endpoint Security / EDR", [
        LogSourceType.CROWDSTRIKE,
        LogSourceType.CARBON_BLACK,
        LogSourceType.OSQUERY,
    ]),
    ("Databases", [
        LogSourceType.MYSQL,
        LogSourceType.POSTGRESQL,
        LogSourceType.MSSQL,
    ]),
    ("Containers & K8s", [
        LogSourceType.DOCKER,
        LogSourceType.KUBERNETES,
    ]),
    ("SaaS / Identity", [
        LogSourceType.OKTA,
        LogSourceType.GOOGLE_WORKSPACE,
    ]),
    ("VPN / Remote Access", [
        LogSourceType.OPENVPN,
        LogSourceType.CISCO_ANYCONNECT,
        LogSourceType.GLOBALPROTECT,
    ]),
    ("Generic", [
        LogSourceType.JSON_LINES,
        LogSourceType.CSV_LOG,
        LogSourceType.PLAINTEXT,
    ]),
]


def show_search_menu() -> None:
    """Launch the interactive search menu if search engines are available."""
    from . import state

    if state.keyword_engine is None or state.event_engine is None:
        console.print(
            Panel(
                "[yellow]No search index available — run a scan first.[/yellow]",
                border_style="yellow",
            )
        )
        return

    try:
        from ..tui.search_menu import SearchMenu
        menu = SearchMenu(
            console=console,
            keyword_engine=state.keyword_engine,
            event_engine=state.event_engine,
            name_detector=state.name_detector,
        )
        menu._name_results = state.name_results or []
        menu.show()
    except ImportError as exc:
        console.print(f"[red]Search menu unavailable: {exc}[/red]")


def pick_log_source(
    candidates: list[tuple[LogSourceType, float]] | None = None,
) -> LogSourceType:
    """
    Display an interactive menu and return the selected LogSourceType.

    If *candidates* is provided (from auto-detection), the top matches are
    shown first so the user can confirm quickly.
    """
    # Build flat index list: [(number, LogSourceType), ...]
    numbered: list[LogSourceType] = []

    if candidates:
        console.print(
            Panel(
                "[bold yellow]Auto-detection candidates[/bold yellow]\n"
                "The following log types were detected — select one or choose manually below.",
                border_style="yellow",
                padding=(0, 2),
            )
        )
        cand_table = Table(show_header=True, header_style="bold", box=None)
        cand_table.add_column("#", style="bold cyan", width=4)
        cand_table.add_column("Log Type", style="white")
        cand_table.add_column("Confidence", justify="right")
        for lst, (ltype, conf) in enumerate(candidates[:5], start=1):
            cand_table.add_row(
                str(lst),
                LOG_SOURCE_LABELS.get(ltype, ltype.value),
                f"[green]{conf:.0%}[/green]",
            )
            numbered.append(ltype)
        console.print(cand_table)
        console.print()

    console.print(
        Panel(
            "[bold white]Select Log Source Type[/bold white]",
            border_style="blue",
            padding=(0, 2),
        )
    )

    offset = len(numbered)
    cat_offset = offset  # where category headers start

    # Build category tables side-by-side to save vertical space
    col_width = 50
    for cat_name, sources in MENU_CATEGORIES:
        tbl = Table(
            title=f"[bold magenta]{cat_name}[/bold magenta]",
            show_header=False,
            box=None,
            padding=(0, 1),
            min_width=col_width,
        )
        tbl.add_column("#", style="bold cyan", width=4)
        tbl.add_column("Log Type", style="white")
        for lst in sources:
            n = len(numbered) + 1
            numbered.append(lst)
            tbl.add_row(str(n), LOG_SOURCE_LABELS.get(lst, lst.value))
        console.print(tbl)

    console.print()

    while True:
        choice = IntPrompt.ask(
            "[bold cyan]Enter number[/bold cyan]",
            default=1 if candidates else None,
        )
        if 1 <= choice <= len(numbered):
            selected = numbered[choice - 1]
            console.print(
                f"[bold green]Selected:[/bold green] {LOG_SOURCE_LABELS.get(selected, selected.value)}\n"
            )
            return selected
        console.print(f"[red]Invalid choice — enter a number between 1 and {len(numbered)}.[/red]")
