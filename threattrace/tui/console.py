"""Shared Rich console and display helpers."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ..models.finding import Severity

console = Console(highlight=False)

BANNER = r"""
 _______ _                    _  _______
|__   __| |                  | ||__   __|
   | |  | |__  _ __ ___  __ _| |   | |_ __ __ _  ___ ___
   | |  | '_ \| '__/ _ \/ _` | |   | | '__/ _` |/ __/ _ \
   | |  | | | | | |  __/ (_| | |   | | | | (_| | (_|  __/
   |_|  |_| |_|_|  \___|\__,_|_|   |_|_|  \__,_|\___\___|
"""


def print_banner() -> None:
    """Print the ThreatTrace ASCII banner."""
    text = Text(BANNER, style="bold red")
    console.print(text)
    console.print(
        Panel(
            "[bold white]Cybersecurity Log Analysis Tool[/bold white]  |  "
            "[dim]YARA + Sigma Detection Engine[/dim]  |  "
            "[dim]MITRE ATT&CK Mapped[/dim]",
            border_style="red",
            padding=(0, 2),
        )
    )
    console.print()


def severity_style(sev: Severity | str) -> str:
    """Return Rich markup style for a severity level."""
    if isinstance(sev, str):
        sev = Severity.from_str(sev)
    return sev.rich_style


def severity_badge(sev: Severity | str) -> str:
    """Return a Rich markup string that renders as a colored badge."""
    if isinstance(sev, str):
        sev = Severity.from_str(sev)
    style = severity_style(sev)
    return f"[{style}]{sev.value:8s}[/{style}]"
