"""threattrace/tui/search_menu.py — Interactive Rich TUI for keyword/event/pivot search."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

logger = logging.getLogger("threattrace.search")

# Severity colour scheme matching existing TUI conventions
_SEV_STYLES: Dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "orange1",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "green",
    "INFORMATIONAL": "green",
}


class SearchMenu:
    """Interactive Rich TUI for all search capabilities."""

    def __init__(
        self,
        console: Console,
        keyword_engine: Any,
        event_engine: Any,
        name_detector: Any,
    ) -> None:
        """Store all search engines for use by sub-menus."""
        self.console = console
        self.keyword_engine = keyword_engine
        self.event_engine = event_engine
        self.name_detector = name_detector
        self._name_results: List[Any] = []

    # ------------------------------------------------------------------
    # Main menu
    # ------------------------------------------------------------------

    def show(self) -> None:
        """Display the main search menu and loop until the user exits."""
        while True:
            self.console.print()
            menu_table = Table(
                title="ThreatTrace Search",
                box=box.ROUNDED,
                show_header=False,
                border_style="bright_cyan",
                title_style="bold white",
                expand=False,
                padding=(0, 1),
            )
            menu_table.add_column("Key", style="bold bright_cyan", no_wrap=True, min_width=4)
            menu_table.add_column("Option", style="white", min_width=50)

            menu_table.add_row("[1]", "Keyword Search  [dim]— Boolean, field-scoped, fuzzy[/dim]")
            menu_table.add_row("[2]", "Event Search & Filter  [dim]— severity, time, IP, MITRE[/dim]")
            menu_table.add_row("[3]", "IP / User Pivot  [dim]— activity summary for entity[/dim]")
            menu_table.add_row("[4]", "Event Frequency Heatmap  [dim]— rules × time buckets[/dim]")
            menu_table.add_row("[5]", "Attack Chain Drill-Down  [dim]— kill-chain stages[/dim]")
            menu_table.add_row("[6]", "Unknown Event Explorer  [dim]— rare / novel events[/dim]")
            menu_table.add_row("[7]", "IOC Search  [dim]— IP, domain, username, hash[/dim]")
            menu_table.add_section()
            menu_table.add_row("[0]", "[dim]Back to Main Menu[/dim]")

            self.console.print(menu_table)
            self.console.print()

            choice = Prompt.ask(
                "[bold bright_cyan]Select option[/bold bright_cyan]",
                show_choices=False,
            ).strip()

            if choice == "0":
                return
            elif choice == "1":
                self._show_keyword_search()
            elif choice == "2":
                self._show_event_search()
            elif choice == "3":
                self._show_pivot()
            elif choice == "4":
                self._show_heatmap()
            elif choice == "5":
                self._show_attack_chain()
            elif choice == "6":
                self._show_unknown_events()
            elif choice == "7":
                self._show_ioc_search()
            else:
                self.console.print("[red]Invalid option — enter 0–7.[/red]")

    # ------------------------------------------------------------------
    # [1] Keyword search
    # ------------------------------------------------------------------

    def _show_keyword_search(self) -> None:
        """Prompt for a Boolean keyword query and display results."""
        self.console.print()
        self.console.print(Panel("Keyword Search", border_style="bright_cyan", padding=(0, 2)))

        query_str = Prompt.ask(
            "Enter search query [dim](Boolean, e.g. src_ip:10.0.0.1 AND NOT uri:favicon)[/dim]"
        ).strip()
        if not query_str:
            return

        fields_raw = Prompt.ask(
            "Search fields [dim](comma-separated, ENTER for all)[/dim]",
            default="",
        ).strip()
        fields: Optional[List[str]] = (
            [f.strip() for f in fields_raw.split(",") if f.strip()]
            if fields_raw else None
        )

        fuzzy_str = Prompt.ask("Fuzzy matching?", choices=["y", "n"], default="n")
        fuzzy = fuzzy_str.lower() == "y"

        ctx_raw = Prompt.ask("Context lines", default="0").strip()
        try:
            context_lines = int(ctx_raw)
        except ValueError:
            context_lines = 0

        self.console.print("\n[dim]Searching…[/dim]")

        results = self.keyword_engine.search(query_str, fields=fields, limit=200, fuzzy=fuzzy)

        if context_lines > 0:
            grep_results = self.keyword_engine.raw_grep(
                query_str, context_lines=context_lines
            )
            # Merge, preferring Whoosh results; append grep-only results
            existing_ids = {r.event_id for r in results}
            for gr in grep_results:
                if gr.event_id not in existing_ids:
                    results.append(gr)

        if not results:
            self.console.print(Panel(
                f"[yellow]No matches for query: {query_str}[/yellow]",
                border_style="yellow",
            ))
            return

        highlighted = self.keyword_engine.highlight_results(results, query_str)

        table = Table(
            title=f"Keyword Search Results — {len(results)} matches",
            show_header=True,
            header_style="bold white on #1e293b",
            border_style="dim",
            show_lines=True,
            box=box.SIMPLE,
        )
        table.add_column("#", style="dim", width=4, no_wrap=True)
        table.add_column("Timestamp", style="dim", width=19)
        table.add_column("Log Type", width=14)
        table.add_column("Source IP", width=15)
        table.add_column("Score", width=6, justify="right")
        table.add_column("Matched Line", min_width=40)

        for i, (result, hl_text) in enumerate(zip(results[:200], highlighted), start=1):
            ts = result.timestamp.strftime("%Y-%m-%d %H:%M:%S") if result.timestamp else "—"
            src_rec = result.source_record
            src_ip = str(getattr(src_rec, "source_ip", "") or "") if src_rec else ""
            table.add_row(
                str(i),
                ts,
                result.log_type or "—",
                src_ip or "—",
                f"{result.score:.2f}",
                hl_text,
            )

        self.console.print(table)

        export_yn = Prompt.ask("Export results?", choices=["y", "n"], default="n")
        if export_yn == "y":
            out_path = Prompt.ask("Output path", default="search_results.json")
            fmt = Prompt.ask("Format", choices=["json", "csv"], default="json")
            self.keyword_engine.export_results(results, out_path, format=fmt)

    # ------------------------------------------------------------------
    # [2] Event search & filter
    # ------------------------------------------------------------------

    def _show_event_search(self) -> None:
        """Prompt for structured filters and display matching alerts."""
        self.console.print()
        self.console.print(Panel("Event Search & Filter", border_style="bright_cyan", padding=(0, 2)))
        self.console.print("[dim]Press ENTER to skip any filter.[/dim]\n")

        event_type = Prompt.ask("Event type (partial match on rule name)", default="").strip() or None
        severity_raw = Prompt.ask("Severity [CRITICAL/HIGH/MEDIUM/LOW/INFO, comma-separated]", default="").strip()
        severity = [s.strip().upper() for s in severity_raw.split(",") if s.strip()] or None

        from_raw = Prompt.ask("From time [YYYY-MM-DD HH:MM]", default="").strip()
        to_raw = Prompt.ask("To time [YYYY-MM-DD HH:MM]", default="").strip()

        import click as _click

        def _parse_dt(s: str) -> Optional[datetime]:
            if not s:
                return None
            for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
                try:
                    return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
            raise _click.BadParameter(f"Invalid datetime: {s!r} — use YYYY-MM-DD HH:MM")

        try:
            from_time = _parse_dt(from_raw)
            to_time = _parse_dt(to_raw)
        except Exception as exc:
            self.console.print(f"[red]{exc}[/red]")
            return

        src_ip = Prompt.ask("Source IP or CIDR", default="").strip() or None
        username = Prompt.ask("Username", default="").strip() or None
        log_type = Prompt.ask("Log type", default="").strip() or None
        mitre_tactic = Prompt.ask("MITRE tactic", default="").strip() or None
        mitre_technique = Prompt.ask("MITRE technique (T-code)", default="").strip() or None
        ioc = Prompt.ask("IOC (IP/domain/hash)", default="").strip() or None
        dedup_str = Prompt.ask("Deduplicate?", choices=["y", "n"], default="n")
        deduplicate = dedup_str == "y"

        self.console.print("\n[dim]Filtering…[/dim]")

        alerts = self.event_engine.filter(
            event_type=event_type,
            severity=severity,
            from_time=from_time,
            to_time=to_time,
            src_ip=src_ip,
            username=username,
            log_type=log_type,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            ioc=ioc,
            deduplicate=deduplicate,
        )

        if not alerts:
            self.console.print(Panel("[yellow]No alerts matched the given filters.[/yellow]", border_style="yellow"))
            return

        table = Table(
            title=f"Event Search Results — {len(alerts)} alerts",
            show_header=True,
            header_style="bold white on #1e293b",
            border_style="dim",
            show_lines=True,
            box=box.SIMPLE,
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Timestamp", style="dim", width=19)
        table.add_column("Severity", width=10)
        table.add_column("Rule Name", min_width=28)
        table.add_column("Src IP", width=15)
        table.add_column("MITRE", width=20)
        table.add_column("Description", min_width=30)

        for i, alert in enumerate(alerts[:500], start=1):
            ts = ""
            ts_val = getattr(alert, "timestamp", None)
            if isinstance(ts_val, datetime):
                ts = ts_val.strftime("%Y-%m-%d %H:%M:%S")
            sev = str(getattr(alert, "severity", "") or "").upper()
            sev_style = _SEV_STYLES.get(sev, "white")
            sev_text = Text(sev, style=sev_style)
            src_ip_val = str(getattr(alert, "source_ip", "") or getattr(alert, "log_source", "") or "—")
            mitre = str(getattr(alert, "mitre_tactic", "") or "")
            tech = str(getattr(alert, "mitre_technique", "") or "")
            if tech:
                mitre = f"{mitre}\n[dim]{tech}[/dim]" if mitre else tech
            desc = str(getattr(alert, "description", "") or "")[:80]
            table.add_row(
                str(i),
                ts or "—",
                sev_text,
                str(getattr(alert, "rule_name", "") or "—"),
                src_ip_val,
                mitre or "—",
                desc or "—",
            )

        self.console.print(table)
        self.console.print(
            Panel(f"[dim]Total: {len(alerts)} alerts matched[/dim]", border_style="dim")
        )

    # ------------------------------------------------------------------
    # [3] IP / User pivot
    # ------------------------------------------------------------------

    def _show_pivot(self) -> None:
        """Prompt for entity type and value, then display a pivot summary."""
        self.console.print()
        self.console.print(Panel("IP / User Pivot", border_style="bright_cyan", padding=(0, 2)))

        pivot_type = Prompt.ask(
            "Pivot by [1=IP  2=Username]",
            choices=["1", "2"],
            default="1",
            show_choices=False,
        ).strip()

        if pivot_type == "1":
            entity = Prompt.ask("IP address").strip()
            if not entity:
                return
            pivot = self.event_engine.pivot_by_ip(entity)
        else:
            entity = Prompt.ask("Username").strip()
            if not entity:
                return
            pivot = self.event_engine.pivot_by_user(entity)

        # Layout: summary + rules side by side
        from rich.columns import Columns

        # Summary panel
        summary_table = Table(box=None, show_header=False, padding=(0, 1))
        summary_table.add_column("Field", style="dim")
        summary_table.add_column("Value", style="white")
        summary_table.add_row("Entity", f"[bold]{pivot.entity_value}[/bold]")
        summary_table.add_row("Total Events", str(pivot.total_events))
        fs = pivot.first_seen.strftime("%Y-%m-%d %H:%M:%S") if pivot.first_seen else "—"
        ls = pivot.last_seen.strftime("%Y-%m-%d %H:%M:%S") if pivot.last_seen else "—"
        summary_table.add_row("First Seen", fs)
        summary_table.add_row("Last Seen", ls)
        summary_table.add_row("Log Sources", ", ".join(pivot.log_sources) or "—")

        # Top rules table
        rules_table = Table(
            title="Top Rules Triggered",
            box=box.SIMPLE,
            show_header=True,
            header_style="bold",
            border_style="dim",
        )
        rules_table.add_column("Rule Name", min_width=30)
        for rule in pivot.unique_rules[:10]:
            rules_table.add_row(rule)

        self.console.print()
        self.console.print(Columns([
            Panel(summary_table, title="Entity Summary", border_style="blue"),
            Panel(rules_table, title="Rules", border_style="blue"),
        ]))

        # Severity breakdown bar
        if pivot.severity_breakdown:
            self.console.print("\n[bold]Severity Breakdown:[/bold]")
            sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            for sev in sev_order:
                count = pivot.severity_breakdown.get(sev, 0)
                if count:
                    style = _SEV_STYLES.get(sev, "white")
                    bar = "█" * min(count, 40)
                    self.console.print(
                        f"  [{style}]{sev:10s}[/{style}]  [{style}]{bar}[/{style}] {count}"
                    )

        # MITRE badges
        if pivot.mitre_techniques:
            techniques_str = "  ".join(
                f"[bold cyan]{t}[/bold cyan]" for t in pivot.mitre_techniques[:10]
            )
            self.console.print(f"\n[bold]MITRE Techniques:[/bold] {techniques_str}")

    # ------------------------------------------------------------------
    # [4] Heatmap
    # ------------------------------------------------------------------

    def _show_heatmap(self) -> None:
        """Render an event frequency heatmap (rules × time buckets)."""
        self.console.print()
        self.console.print(Panel("Event Frequency Heatmap", border_style="bright_cyan", padding=(0, 2)))

        heatmap = self.event_engine.get_event_heatmap(bucket="hour")
        if not heatmap:
            self.console.print(Panel("[yellow]No events to display in heatmap.[/yellow]", border_style="yellow"))
            return

        # Top 10 rules by total count
        rule_totals = {rule: sum(counts.values()) for rule, counts in heatmap.items()}
        top_rules = sorted(rule_totals, key=lambda r: rule_totals[r], reverse=True)[:10]

        # Collect all time buckets across top rules, last 24 distinct hours
        all_buckets: set = set()
        for rule in top_rules:
            all_buckets.update(heatmap[rule].keys())
        sorted_buckets = sorted(all_buckets)[-24:]

        table = Table(
            title="Event Heatmap  (top 10 rules × last 24 hours)",
            show_header=True,
            header_style="bold white",
            border_style="dim",
            box=box.SIMPLE,
        )
        table.add_column("Rule", min_width=28, no_wrap=True)
        for bucket in sorted_buckets:
            # Show just HH:00 to save width
            label = bucket[-5:] if len(bucket) >= 5 else bucket
            table.add_column(label, width=5, justify="center")

        def _cell(count: int) -> Text:
            if count == 0:
                return Text("  0 ", style="dim white")
            elif count <= 5:
                return Text(f" {count:2d} ", style="green")
            elif count <= 20:
                return Text(f" {count:2d} ", style="yellow")
            elif count <= 100:
                return Text(f" {count:2d} ", style="orange1")
            else:
                return Text(f"{min(count, 999):3d}+", style="bold red")

        for rule in top_rules:
            row_cells = [Text(rule[:28], style="white")]
            for bucket in sorted_buckets:
                count = heatmap[rule].get(bucket, 0)
                row_cells.append(_cell(count))
            table.add_row(*row_cells)

        self.console.print(Panel(table, border_style="blue"))

    # ------------------------------------------------------------------
    # [5] Attack chain drill-down
    # ------------------------------------------------------------------

    def _show_attack_chain(self) -> None:
        """List available attack chains and drill into kill-chain stages."""
        self.console.print()
        self.console.print(Panel("Attack Chain Drill-Down", border_style="bright_cyan", padding=(0, 2)))

        # Collect chain IDs from stat_results
        chain_ids: List[str] = []
        for sr in (self.event_engine.stat_results or []):
            data = getattr(sr, "data", {}) or {}
            for key in data:
                if re.match(r'PRIVESC-\d+|CHAIN-\d+|ATK-\d+', str(key)):
                    chain_ids.append(str(key))

        # Also scan alert rule names for chain-like patterns
        for alert in (self.event_engine.alerts or []):
            hits = re.findall(r'PRIVESC-\d{3}|CHAIN-\d{3}|ATK-\d{3}', str(getattr(alert, "rule_name", "") or ""))
            chain_ids.extend(hits)

        chain_ids = list(dict.fromkeys(chain_ids))  # deduplicate, preserve order

        if chain_ids:
            list_table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
            list_table.add_column("#", width=4, style="dim")
            list_table.add_column("Chain ID", style="cyan")
            for i, cid in enumerate(chain_ids, 1):
                list_table.add_row(str(i), cid)
            self.console.print(list_table)

        chain_id = Prompt.ask("Enter Chain ID (e.g. PRIVESC-001) or type directly").strip()
        if not chain_id:
            return

        chain = self.event_engine.get_attack_chain(chain_id)

        self.console.print(Panel(
            f"[bold]{chain.chain_id}[/bold]  "
            f"Kill-chain score: [cyan]{chain.kill_chain_score:.0%}[/cyan]  "
            f"Duration: [dim]{chain.duration_seconds}s[/dim]  "
            f"Primary IP: [yellow]{chain.primary_actor_ip or 'unknown'}[/yellow]",
            title="Attack Chain",
            border_style="red",
        ))

        if not chain.stages:
            self.console.print("[dim]No stages found for this chain ID.[/dim]")
            return

        for stage_info in chain.stages:
            stage_name = str(stage_info.get("stage", "Unknown"))
            stage_alerts = stage_info.get("alerts", [])
            stage_table = Table(
                show_header=True,
                header_style="bold",
                box=box.SIMPLE,
                border_style="dim",
            )
            stage_table.add_column("Rule", min_width=28)
            stage_table.add_column("Severity", width=10)
            stage_table.add_column("Timestamp", width=20)
            for a in stage_alerts[:20]:
                sev = str(getattr(a, "severity", "") or "").upper()
                sev_style = _SEV_STYLES.get(sev, "white")
                ts = ""
                ts_val = getattr(a, "timestamp", None)
                if isinstance(ts_val, datetime):
                    ts = ts_val.strftime("%Y-%m-%d %H:%M:%S")
                stage_table.add_row(
                    str(getattr(a, "rule_name", "") or "—"),
                    Text(sev, style=sev_style),
                    ts or "—",
                )
            self.console.print(Panel(
                stage_table,
                title=f"Stage: {stage_name}",
                border_style="yellow",
                subtitle=f"[dim]{len(stage_alerts)} alerts[/dim]",
            ))

    # ------------------------------------------------------------------
    # [6] Unknown event explorer
    # ------------------------------------------------------------------

    def _show_unknown_events(self) -> None:
        """Show events the detector could not classify, sorted by rarity."""
        self.console.print()
        self.console.print(Panel("Unknown Event Explorer", border_style="bright_cyan", padding=(0, 2)))

        if not self._name_results:
            self.console.print(Panel(
                "[yellow]No event name results available — run analysis first.[/yellow]",
                border_style="yellow",
            ))
            return

        unknown = self.name_detector.get_unknown_events(self._name_results)

        if not unknown:
            self.console.print(Panel(
                "[green]All events were successfully classified. No unknowns.[/green]",
                border_style="green",
            ))
            return

        table = Table(
            title=f"Unknown Events — {len(unknown)} unclassified",
            show_header=True,
            header_style="bold white on #1e293b",
            border_style="dim",
            show_lines=True,
            box=box.SIMPLE,
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Rarity", width=8, justify="right")
        table.add_column("Template", min_width=35)
        table.add_column("Log Type", width=14)
        table.add_column("Raw Line", min_width=40)
        table.add_column("Auto-Promoted", width=13, justify="center")

        for i, result in enumerate(unknown[:100], start=1):
            raw = str(getattr(result.record, "raw_line", "") or "")[:80]
            log_type = str(getattr(result.record, "log_type", "") or "—")
            promoted_text = Text("YES", style="bold red") if result.auto_promoted else Text("no", style="dim")
            table.add_row(
                str(i),
                f"{result.rarity_score:.3f}",
                result.template[:50],
                log_type,
                raw,
                promoted_text,
            )

        self.console.print(table)

        flag_raw = Prompt.ask(
            "Flag an event as known? Enter # (or ENTER to skip)",
            default="",
        ).strip()

        if flag_raw:
            try:
                idx = int(flag_raw) - 1
                if 0 <= idx < len(unknown):
                    result = unknown[idx]
                    canonical = Prompt.ask(
                        f"Canonical name for template '{result.template[:40]}'"
                    ).strip()
                    if canonical:
                        # Lazy import: only needed when user flags an event
                        from threattrace.detection import canonical_name_map as _cnm  # noqa: F401
                        CANONICAL_NAME_MAP_KEY = result.template[:60].lower()
                        self.console.print(
                            f"[green]Flagged: '{CANONICAL_NAME_MAP_KEY}' → '{canonical}'[/green]\n"
                            "[dim]Note: persist to config.yaml manually to survive restarts.[/dim]"
                        )
            except (ValueError, IndexError):
                pass

    # ------------------------------------------------------------------
    # [7] IOC search
    # ------------------------------------------------------------------

    def _show_ioc_search(self) -> None:
        """Search all events for a specific IOC (IP, domain, username, hash)."""
        self.console.print()
        self.console.print(Panel("IOC Search", border_style="bright_cyan", padding=(0, 2)))

        ioc = Prompt.ask("Enter IOC (IP, domain, username, hash)").strip()
        if not ioc:
            return

        self.console.print("\n[dim]Searching alerts and raw log lines…[/dim]")

        alert_results = self.event_engine.search_by_ioc(ioc)
        grep_results = self.keyword_engine.raw_grep(ioc)

        # Merge: tag each with source
        merged: List[Dict[str, Any]] = []
        for a in alert_results:
            merged.append({"obj": a, "source": "Alert"})
        alert_rawlines = {str(getattr(a, "matched_line", "") or "") for a in alert_results}
        for sr in grep_results:
            if sr.matched_line not in alert_rawlines:
                merged.append({"obj": sr, "source": "Raw Match"})

        if not merged:
            self.console.print(Panel(
                f"[yellow]No matches found for IOC: {ioc}[/yellow]",
                border_style="yellow",
            ))
            return

        def _ts_key(item: Dict) -> datetime:
            obj = item["obj"]
            ts = getattr(obj, "timestamp", None)
            if isinstance(ts, datetime):
                return ts
            return datetime.min.replace(tzinfo=timezone.utc)

        merged.sort(key=_ts_key)

        table = Table(
            title=f"IOC Search: '{ioc}' — {len(merged)} results",
            show_header=True,
            header_style="bold white on #1e293b",
            border_style="dim",
            show_lines=True,
            box=box.SIMPLE,
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Source", width=11)
        table.add_column("Timestamp", style="dim", width=19)
        table.add_column("Type / Rule", width=24)
        table.add_column("Matched Line", min_width=40)

        for i, item in enumerate(merged[:200], start=1):
            obj = item["obj"]
            src = item["source"]
            ts_val = getattr(obj, "timestamp", None)
            ts = ts_val.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts_val, datetime) else "—"

            if src == "Alert":
                rule = str(getattr(obj, "rule_name", "") or "—")
                line = str(getattr(obj, "matched_line", "") or "")[:80]
                src_text = Text("Alert", style="bold red")
            else:
                rule = str(getattr(obj, "log_type", "") or "—")
                line = str(getattr(obj, "matched_line", "") or "")[:80]
                src_text = Text("Raw", style="dim cyan")

            # Highlight the IOC in the line
            hl = Text(line)
            hl.highlight_words([ioc], style="bold yellow")

            table.add_row(str(i), src_text, ts, rule, hl)

        self.console.print(table)
