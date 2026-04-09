"""search/keyword_search.py — Full-text + field-scoped keyword search engine."""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

import rich.text

if TYPE_CHECKING:
    from core.models import LogRecord

logger = logging.getLogger("threattrace.search")

# ---------------------------------------------------------------------------
# SearchResult dataclass
# ---------------------------------------------------------------------------

@dataclass
class SearchResult:
    """A single search result with context and metadata."""
    event_id: str
    log_type: str
    timestamp: Optional[datetime]
    matched_line: str
    matched_fields: List[str]
    score: float
    context_before: List[str] = field(default_factory=list)
    context_after: List[str] = field(default_factory=list)
    source_record: Any = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict."""
        return {
            "event_id": self.event_id,
            "log_type": self.log_type,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "matched_line": self.matched_line,
            "matched_fields": self.matched_fields,
            "score": self.score,
            "context_before": self.context_before,
            "context_after": self.context_after,
        }


# ---------------------------------------------------------------------------
# Whoosh schema (lazy — only imported when Whoosh is available)
# ---------------------------------------------------------------------------

def _build_whoosh_schema():
    """Build and return a Whoosh schema. Returns None if Whoosh unavailable."""
    try:
        from whoosh.fields import (
            Schema, ID, TEXT, KEYWORD, DATETIME, NUMERIC,
        )
        from whoosh.analysis import StemmingAnalyzer
        return Schema(
            event_id=ID(stored=True, unique=True),
            raw=TEXT(stored=True, analyzer=StemmingAnalyzer()),
            uri=TEXT(stored=True),
            username=KEYWORD(stored=True, commas=True),
            src_ip=ID(stored=True),
            dst_ip=ID(stored=True),
            user_agent=TEXT(stored=True),
            message=TEXT(stored=True),
            log_type=KEYWORD(stored=True),
            hostname=KEYWORD(stored=True),
            action=TEXT(stored=True),
            timestamp=DATETIME(stored=True),
            severity=KEYWORD(stored=True),
            line_number=NUMERIC(stored=True),
        )
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# KeywordSearchEngine
# ---------------------------------------------------------------------------

class KeywordSearchEngine:
    """Full-text and field-scoped keyword search over LogRecord objects."""

    def __init__(
        self,
        index_dir: str = "search/search_index",
        records: Optional[List[Any]] = None,
    ) -> None:
        """Initialise search engine; optionally index records immediately."""
        self._index_dir = Path(index_dir)
        self._records: List[Any] = []
        self._whoosh_index = None
        self._schema = _build_whoosh_schema()

        if records:
            self.build_index(records)

    # ------------------------------------------------------------------
    # Index management
    # ------------------------------------------------------------------

    def build_index(self, records: List[Any]) -> None:
        """Build or rebuild the Whoosh full-text index from LogRecord list."""
        from rich.console import Console
        from rich.panel import Panel
        from rich.progress import track

        console = Console()
        self._records = list(records)

        if not self._schema:
            console.print(
                Panel(
                    "[yellow]Whoosh not installed — using in-memory search only.[/yellow]",
                    title="Search Engine",
                    border_style="yellow",
                )
            )
            return

        try:
            from whoosh import index as whoosh_index
            from whoosh.writing import AsyncWriter

            self._index_dir.mkdir(parents=True, exist_ok=True)

            if whoosh_index.exists_in(str(self._index_dir)):
                ix = whoosh_index.open_dir(str(self._index_dir))
            else:
                ix = whoosh_index.create_in(str(self._index_dir), self._schema)

            self._whoosh_index = ix
            writer = AsyncWriter(ix)

            for record in track(records, description="Indexing events…"):
                line_no = getattr(record, "line_number", 0) or 0
                log_type = getattr(record, "log_type", "unknown") or "unknown"
                event_id = f"evt_{line_no}_{log_type}"
                ts = getattr(record, "timestamp", None)
                writer.update_document(
                    event_id=event_id,
                    raw=getattr(record, "raw_line", "") or "",
                    uri=getattr(record, "uri", "") or "",
                    username=getattr(record, "username", "") or "",
                    src_ip=getattr(record, "source_ip", "") or "",
                    dst_ip=getattr(record, "dest_ip", "") or "",
                    user_agent=getattr(record, "user_agent", "") or "",
                    message=getattr(record, "raw_line", "") or "",
                    log_type=log_type,
                    hostname=getattr(record, "hostname", "") or "",
                    action=getattr(record, "action", "") or "",
                    timestamp=ts if isinstance(ts, datetime) else None,
                    severity="",
                    line_number=line_no,
                )

            writer.commit()
            console.print(
                Panel(
                    f"[green]Search Index Built — {len(records):,} events indexed[/green]",
                    title="Search Engine",
                    border_style="green",
                )
            )

        except Exception as exc:
            logger.warning("Whoosh indexing failed: %s — using in-memory fallback", exc)
            self._whoosh_index = None

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search(
        self,
        query_str: str,
        fields: Optional[List[str]] = None,
        limit: int = 100,
        fuzzy: bool = False,
    ) -> List[SearchResult]:
        """Search indexed events; falls back to raw_grep if index unavailable."""
        if not self._whoosh_index or not self._schema:
            logger.info("No Whoosh index available — using raw_grep fallback")
            return self.raw_grep(query_str)

        try:
            from whoosh.qparser import MultifieldParser
            from whoosh.query import FuzzyTerm

            all_fields = [
                "raw", "uri", "username", "src_ip", "dst_ip",
                "user_agent", "message", "log_type", "hostname", "action",
            ]
            search_fields = fields if fields else all_fields

            with self._whoosh_index.searcher() as searcher:
                parser = MultifieldParser(search_fields, schema=self._whoosh_index.schema)
                if fuzzy:
                    # Monkey-patch the default term class for fuzzy matching
                    parser.termclass = FuzzyTerm
                try:
                    parsed_q = parser.parse(query_str)
                except Exception:
                    parsed_q = parser.parse(re.sub(r'[^\w\s:*"\'()&|!]', " ", query_str))

                hits = searcher.search(parsed_q, limit=limit)
                results: List[SearchResult] = []

                # Build a lookup from event_id back to LogRecord
                record_by_id: Dict[str, Any] = {}
                for rec in self._records:
                    ln = getattr(rec, "line_number", 0) or 0
                    lt = getattr(rec, "log_type", "unknown") or "unknown"
                    eid = f"evt_{ln}_{lt}"
                    record_by_id[eid] = rec

                for hit in hits:
                    eid = hit.get("event_id", "")
                    source_rec = record_by_id.get(eid)
                    matched_fields_list = [
                        f for f in search_fields
                        if hit.get(f) and query_str.lower() in str(hit.get(f, "")).lower()
                    ]
                    ts_val = hit.get("timestamp")
                    results.append(SearchResult(
                        event_id=eid,
                        log_type=hit.get("log_type", ""),
                        timestamp=ts_val if isinstance(ts_val, datetime) else None,
                        matched_line=hit.get("raw", ""),
                        matched_fields=matched_fields_list or ["raw"],
                        score=float(hit.score) if hit.score else 1.0,
                        source_record=source_rec,
                    ))

                return results

        except Exception as exc:
            logger.warning("Whoosh search error: %s — falling back to raw_grep", exc)
            from rich.console import Console
            Console().print(f"  [yellow]Search index error: {exc} — using grep fallback.[/yellow]")
            return self.raw_grep(query_str)

    def raw_grep(
        self,
        pattern: str,
        records: Optional[List[Any]] = None,
        context_lines: int = 0,
    ) -> List[SearchResult]:
        """Grep-style regex search over raw_line of LogRecord list."""
        target = records if records is not None else self._records
        if not target:
            from rich.console import Console
            from rich.panel import Panel
            Console().print(Panel(
                "[yellow]No records loaded — raw_grep returned empty.[/yellow]",
                border_style="yellow",
            ))
            return []

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            logger.warning("Invalid regex pattern '%s': %s", pattern, exc)
            regex = re.compile(re.escape(pattern), re.IGNORECASE)

        results: List[SearchResult] = []
        for idx, record in enumerate(target):
            raw = getattr(record, "raw_line", "") or ""
            if not regex.search(raw):
                continue

            before: List[str] = []
            after: List[str] = []
            if context_lines > 0:
                start = max(0, idx - context_lines)
                end = min(len(target), idx + context_lines + 1)
                before = [
                    getattr(target[i], "raw_line", "") or ""
                    for i in range(start, idx)
                ]
                after = [
                    getattr(target[i], "raw_line", "") or ""
                    for i in range(idx + 1, end)
                ]

            ln = getattr(record, "line_number", idx) or idx
            lt = getattr(record, "log_type", "unknown") or "unknown"
            ts = getattr(record, "timestamp", None)
            results.append(SearchResult(
                event_id=f"evt_{ln}_{lt}",
                log_type=lt,
                timestamp=ts if isinstance(ts, datetime) else None,
                matched_line=raw,
                matched_fields=["raw"],
                score=1.0,
                context_before=before,
                context_after=after,
                source_record=record,
            ))

        return results

    # ------------------------------------------------------------------
    # Rendering / export
    # ------------------------------------------------------------------

    def highlight_results(
        self,
        results: List[SearchResult],
        query_str: str,
    ) -> List[rich.text.Text]:
        """Return Rich Text objects with query keywords highlighted."""
        keywords = [
            w for w in re.split(r'\s+|(?:AND|OR|NOT)', query_str)
            if w and not w.upper() in ("AND", "OR", "NOT")
            and not re.match(r'^\w+:', w)
        ]
        highlighted: List[rich.text.Text] = []
        for result in results:
            text = rich.text.Text(result.matched_line[:200])
            if keywords:
                text.highlight_words(keywords, style="bold yellow")
            highlighted.append(text)
        return highlighted

    def export_results(
        self,
        results: List[SearchResult],
        output_path: str,
        format: str = "json",
    ) -> None:
        """Export search results to JSON or CSV."""
        from rich.console import Console
        from rich.panel import Panel
        import pandas as pd

        console = Console()
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            data = [r.to_dict() for r in results]
            out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        elif format == "csv":
            df = pd.DataFrame([r.to_dict() for r in results])
            df.to_csv(str(out), index=False)
        else:
            logger.warning("Unknown export format '%s' — defaulting to json", format)
            data = [r.to_dict() for r in results]
            out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

        console.print(Panel(
            f"[green]Exported {len(results):,} results → {out}[/green]",
            title="Export Complete",
            border_style="green",
        ))
