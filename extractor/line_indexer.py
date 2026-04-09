"""
extractor/line_indexer.py — Single-pass IOC → line index builder.

LineIndexer scans one or more log files (or a list of pre-loaded raw lines)
in a **single forward pass** and builds an inverted index from each
(entity_type, value) pair to every line that contained it.

Public API:
    LineIndexer.build(files, filter_private=True)
        Build index from a list of file paths (str or Path).

    LineIndexer.build_from_lines(lines, source_label="", filter_private=True)
        Build index from an iterable of raw string lines.

    LineIndexer.get_lines(entity_type, value) → list[tuple[int, str]]
        Return [(lineno, raw_line), …] for all occurrences.

Attributes after build:
    index       — dict[(entity_type, value), list[(lineno, raw_line)]]
    timestamps  — dict[(entity_type, value), list[datetime|None]]
    source_map  — dict[(entity_type, value), list[str]]  (file paths)
    raw_lines   — list[(lineno, raw_line, source_path)]  (all lines scanned)
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from extractor.patterns import (
    PATTERNS,
    GROUP1_PATTERNS,
    PRIVATE_IP_RE,
    TS_PATTERNS,
    refang,
)


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

_LineRef  = Tuple[int, str]            # (lineno, raw_line)
_IndexKey = Tuple[str, str]            # (entity_type, value)


# ---------------------------------------------------------------------------
# Timestamp extraction helper
# ---------------------------------------------------------------------------

def _extract_timestamp(line: str) -> Optional[datetime]:
    """
    Try each TS_PATTERNS prefix against *line* and parse whatever matches.
    Returns a naive or tz-aware datetime, or None if no timestamp is found.
    """
    for pat in TS_PATTERNS:
        m = pat.match(line.strip())
        if not m:
            continue
        raw_ts = m.group(0)
        # Try a battery of strptime formats
        fmts = [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%b %d %H:%M:%S",
            "%b  %d %H:%M:%S",
        ]
        for fmt in fmts:
            try:
                return datetime.strptime(raw_ts.rstrip("Z").strip(), fmt)
            except ValueError:
                continue
        # Numeric epoch
        try:
            ts_val = float(raw_ts)
            return datetime.utcfromtimestamp(ts_val)
        except (ValueError, OverflowError, OSError):
            pass
    return None


# ---------------------------------------------------------------------------
# LineIndexer
# ---------------------------------------------------------------------------

class LineIndexer:
    """
    Single-pass IOC → line inverted index.

    Usage::

        idx = LineIndexer()
        idx.build(["/var/log/auth.log", "/var/log/syslog"])
        lines = idx.get_lines("ipv4", "203.0.113.5")
    """

    def __init__(self) -> None:
        # (entity_type, value) → [(lineno, raw_line), …]
        self.index:      Dict[_IndexKey, List[_LineRef]] = defaultdict(list)
        # (entity_type, value) → [datetime|None, …]
        self.timestamps: Dict[_IndexKey, List[Optional[datetime]]] = defaultdict(list)
        # (entity_type, value) → [source_path, …]
        self.source_map: Dict[_IndexKey, List[str]] = defaultdict(list)
        # All lines scanned: [(lineno, raw_line, source_path), …]
        self.raw_lines:  List[Tuple[int, str, str]] = []

    # ------------------------------------------------------------------
    # Public build methods
    # ------------------------------------------------------------------

    def build(
        self,
        files: Iterable[Union[str, Path]],
        filter_private: bool = True,
    ) -> "LineIndexer":
        """
        Scan each file in *files* in a single forward pass.

        Parameters
        ----------
        files          : Iterable of file paths (str or pathlib.Path).
        filter_private : If True, skip RFC-1918 / loopback IPv4 addresses
                         (applied at index time, not query time).
        """
        self._reset()
        for file_path in files:
            file_path = str(file_path)
            try:
                with open(file_path, encoding="utf-8", errors="replace") as fh:
                    for lineno, raw in enumerate(fh, start=1):
                        self._process_line(
                            lineno=lineno,
                            raw=raw.rstrip("\n\r"),
                            source=file_path,
                            filter_private=filter_private,
                        )
            except (OSError, PermissionError):
                # Skip unreadable files silently; caller can check raw_lines
                continue
        return self

    def build_from_lines(
        self,
        lines: Iterable[str],
        source_label: str = "",
        filter_private: bool = True,
    ) -> "LineIndexer":
        """
        Build index from an iterable of raw log lines (no file I/O).

        Parameters
        ----------
        lines          : Iterable of raw string lines.
        source_label   : Arbitrary label stored in source_map (e.g. filename).
        filter_private : Same semantics as in ``build()``.
        """
        self._reset()
        for lineno, raw in enumerate(lines, start=1):
            self._process_line(
                lineno=lineno,
                raw=raw.rstrip("\n\r"),
                source=source_label,
                filter_private=filter_private,
            )
        return self

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_lines(
        self,
        entity_type: str,
        value: str,
    ) -> List[_LineRef]:
        """
        Return ``[(lineno, raw_line), …]`` for every occurrence of
        *(entity_type, value)* in the index.

        The look-up is case-sensitive for hashes/keys and case-insensitive
        for everything else.
        """
        key = (entity_type, value)
        if key in self.index:
            return self.index[key]
        # Case-insensitive fallback
        val_lc = value.lower()
        for (et, v), refs in self.index.items():
            if et == entity_type and v.lower() == val_lc:
                return refs
        return []

    def all_entities(self) -> List[Tuple[str, str]]:
        """Return all (entity_type, value) keys in the index."""
        return list(self.index.keys())

    def entities_of_type(self, entity_type: str) -> List[str]:
        """Return all unique values for a given entity_type."""
        return [v for (et, v) in self.index if et == entity_type]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _reset(self) -> None:
        self.index.clear()
        self.timestamps.clear()
        self.source_map.clear()
        self.raw_lines.clear()

    def _process_line(
        self,
        lineno: int,
        raw: str,
        source: str,
        filter_private: bool,
    ) -> None:
        """Extract IOCs from *raw* and add to the index."""
        self.raw_lines.append((lineno, raw, source))

        # Refang the line before matching
        line = refang(raw)
        ts   = _extract_timestamp(line)

        for entity_type, pattern in PATTERNS.items():
            for m in pattern.finditer(line):
                # Capture group 1 for username / user_agent; else full match
                if entity_type in GROUP1_PATTERNS:
                    value = m.group(1).strip() if m.lastindex and m.group(1) else m.group(0)
                else:
                    value = m.group(0)

                # Normalise value
                value = value.strip().rstrip(".,;:'\")")

                if not value:
                    continue

                # Private IP filter
                if filter_private and entity_type == "ipv4":
                    if PRIVATE_IP_RE.match(value):
                        continue

                key = (entity_type, value)
                self.index[key].append((lineno, raw))
                self.timestamps[key].append(ts)
                self.source_map[key].append(source)
