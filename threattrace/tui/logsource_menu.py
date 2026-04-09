"""Log source types reference sub-menu."""
from __future__ import annotations

from rich import box
from rich.prompt import Prompt
from rich.table import Table

from .console import console
from ..models.log_event import LOG_SOURCE_LABELS, LogSourceType

# Category groupings for the reference table
_CATEGORIES: list[tuple[str, list[LogSourceType]]] = [
    ("Web Servers", [
        LogSourceType.APACHE_ACCESS, LogSourceType.APACHE_ERROR,
        LogSourceType.NGINX_ACCESS, LogSourceType.NGINX_ERROR,
        LogSourceType.IIS_W3C, LogSourceType.HAPROXY,
    ]),
    ("OS — Windows", [
        LogSourceType.WINDOWS_EVTX, LogSourceType.WINDOWS_EVTX_XML,
        LogSourceType.WINDOWS_SYSMON, LogSourceType.WINDOWS_POWERSHELL,
    ]),
    ("OS — Linux/Unix", [
        LogSourceType.LINUX_SYSLOG, LogSourceType.LINUX_AUTH_LOG,
        LogSourceType.LINUX_KERN_LOG, LogSourceType.LINUX_AUDIT,
        LogSourceType.LINUX_CRON, LogSourceType.LINUX_BASH_HISTORY,
    ]),
    ("Network / Firewall", [
        LogSourceType.FIREWALL_CISCO_ASA, LogSourceType.FIREWALL_PALO_ALTO,
        LogSourceType.FIREWALL_FORTINET, LogSourceType.FIREWALL_PFSENSE,
        LogSourceType.ZEEK_CONN, LogSourceType.ZEEK_DNS, LogSourceType.ZEEK_HTTP,
        LogSourceType.SURICATA_EVE, LogSourceType.NETFLOW,
    ]),
    ("Proxy & DNS", [
        LogSourceType.SQUID_PROXY, LogSourceType.DNS_BIND, LogSourceType.DNS_WINDOWS,
    ]),
    ("Authentication & IAM", [
        LogSourceType.ACTIVE_DIRECTORY, LogSourceType.RADIUS, LogSourceType.LDAP,
    ]),
    ("Cloud Platforms", [
        LogSourceType.AWS_CLOUDTRAIL, LogSourceType.AWS_VPC_FLOW,
        LogSourceType.AZURE_ACTIVITY, LogSourceType.AZURE_SIGNIN,
        LogSourceType.GCP_AUDIT,
    ]),
    ("Email", [
        LogSourceType.POSTFIX, LogSourceType.EXCHANGE,
    ]),
    ("Endpoint / EDR", [
        LogSourceType.CROWDSTRIKE, LogSourceType.CARBON_BLACK, LogSourceType.OSQUERY,
    ]),
    ("Databases", [
        LogSourceType.MYSQL, LogSourceType.POSTGRESQL, LogSourceType.MSSQL,
    ]),
    ("Containers & K8s", [
        LogSourceType.DOCKER, LogSourceType.KUBERNETES,
    ]),
    ("SaaS / Identity", [
        LogSourceType.OKTA, LogSourceType.GOOGLE_WORKSPACE,
    ]),
    ("VPN / Remote Access", [
        LogSourceType.OPENVPN, LogSourceType.CISCO_ANYCONNECT, LogSourceType.GLOBALPROTECT,
    ]),
    ("Generic", [
        LogSourceType.JSON_LINES, LogSourceType.CSV_LOG, LogSourceType.PLAINTEXT,
    ]),
]


def show_logsource_menu() -> None:
    """Display log source reference and optionally filter by category."""
    while True:
        console.print()
        cat_table = Table(
            title="LOG SOURCE TYPES",
            box=box.ROUNDED,
            show_header=False,
            border_style="bright_magenta",
            title_style="bold white",
            expand=False,
            padding=(0, 1),
        )
        cat_table.add_column("Key", style="bold bright_magenta", min_width=5)
        cat_table.add_column("Category", style="white", min_width=28)
        cat_table.add_column("Count", style="dim", min_width=6, justify="right")

        for i, (cat_name, sources) in enumerate(_CATEGORIES, start=1):
            cat_table.add_row(f"[{i}]", cat_name, str(len(sources)))
        cat_table.add_row("[A]", "All log source types", str(sum(len(s) for _, s in _CATEGORIES)))
        cat_table.add_section()
        cat_table.add_row("[0]", "[dim]Back to Main Menu[/dim]", "")
        console.print(cat_table)
        console.print()

        choice = Prompt.ask(
            "[bold bright_magenta]  Select category[/bold bright_magenta]",
            show_choices=False,
        ).strip().lower()

        if choice == "0":
            break
        elif choice == "a":
            _display_all_types()
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(_CATEGORIES):
                    cat_name, sources = _CATEGORIES[idx]
                    _display_category(cat_name, sources)
                else:
                    console.print("[red]  Invalid choice.[/red]")
            except ValueError:
                console.print("[red]  Enter a number or 'A'.[/red]")


def _display_category(cat_name: str, sources: list[LogSourceType]) -> None:
    table = Table(
        title=f"[bold white]{cat_name}[/bold white]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on grey23",
        border_style="bright_magenta",
        expand=False,
        show_lines=True,
    )
    table.add_column("Type ID  [dim](use with -t / --type)[/dim]", style="bold cyan", min_width=26)
    table.add_column("Description", style="white")

    for lst in sources:
        table.add_row(lst.value, LOG_SOURCE_LABELS.get(lst, ""))

    console.print()
    console.print(table)
    console.print()
    Prompt.ask("[dim]  Press Enter to return[/dim]", default="")


def _display_all_types() -> None:
    table = Table(
        title="[bold white]All Supported Log Source Types[/bold white]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on grey23",
        border_style="bright_magenta",
        expand=True,
        show_lines=False,
    )
    table.add_column("Type ID", style="bold cyan", min_width=24)
    table.add_column("Description", style="white")
    table.add_column("Category", style="dim", min_width=20)

    # Build reverse lookup: type → category
    type_to_cat: dict[LogSourceType, str] = {}
    for cat_name, sources in _CATEGORIES:
        for s in sources:
            type_to_cat[s] = cat_name

    for lst in LogSourceType:
        table.add_row(
            lst.value,
            LOG_SOURCE_LABELS.get(lst, ""),
            type_to_cat.get(lst, "Generic"),
        )

    console.print()
    console.print(table)
    console.print()
    Prompt.ask("[dim]  Press Enter to return[/dim]", default="")
