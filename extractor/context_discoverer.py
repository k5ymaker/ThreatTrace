"""
extractor/context_discoverer.py — Contextual co-occurrence discovery.

ContextDiscoverer walks the LineIndexer index and, for a given
(entity_type, value) pivot entity, returns every *other* IOC that
appeared on the same lines — giving the analyst a quick "what else was
on those lines?" view.

Public API:
    ContextDiscoverer(indexer: LineIndexer)
    .discover(entity_type, value) → dict[str, list[tuple[str, int]]]

Return structure::

    {
        "ipv4":       [("203.0.113.5", 3), ("198.51.100.2", 1)],
        "domain":     [("evil.example.com", 2)],
        "username":   [("root", 1)],
        ...
    }

Each inner list is ``(value, occurrence_count)`` sorted by count descending.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Tuple

from extractor.line_indexer import LineIndexer


class ContextDiscoverer:
    """
    Discovers IOCs that co-occur with a pivot entity on the same log lines.

    Parameters
    ----------
    indexer : A fully built :class:`LineIndexer` instance.
    """

    def __init__(self, indexer: LineIndexer) -> None:
        self._indexer = indexer

        # Pre-build a reverse map: lineno → list[(entity_type, value)]
        # keyed by (source, lineno) to handle multi-file scenarios.
        self._line_to_entities: Dict[Tuple[str, int], List[Tuple[str, str]]] = (
            defaultdict(list)
        )
        self._build_reverse_map()

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def discover(
        self,
        entity_type: str,
        value: str,
    ) -> Dict[str, List[Tuple[str, int]]]:
        """
        Return co-occurring IOCs for the pivot entity *(entity_type, value)*.

        Parameters
        ----------
        entity_type : One of the 16 IOC types (e.g. ``"ipv4"``).
        value       : The entity value (e.g. ``"203.0.113.5"``).

        Returns
        -------
        dict mapping entity_type → [(value, count), …] sorted by count desc.
        Empty dict if the pivot entity is not in the index.
        """
        pivot_lines = self._indexer.get_lines(entity_type, value)
        if not pivot_lines:
            return {}

        # Resolve which (source, lineno) keys correspond to pivot hits
        # We need source information; fall back to lineno-only if unavailable.
        pivot_keys: set[Tuple[str, int]] = set()
        for lineno, raw in pivot_lines:
            # source_map stores per-hit sources in insertion order
            key_idx = self._get_hit_indices(entity_type, value)
            for (src, ln) in key_idx:
                if ln == lineno:
                    pivot_keys.add((src, lineno))
            # Ensure at least lineno-based key is covered
            pivot_keys.add(("", lineno))

        # Accumulate co-occurring entities
        # Use a counter: (co_type, co_value) → count
        co_counts: Dict[Tuple[str, str], int] = defaultdict(int)

        for pk in pivot_keys:
            for (co_type, co_value) in self._line_to_entities.get(pk, []):
                # Skip the pivot entity itself
                if co_type == entity_type and co_value == value:
                    continue
                co_counts[(co_type, co_value)] += 1

        # Structure result: entity_type → [(value, count), …] sorted desc
        result: Dict[str, List[Tuple[str, int]]] = defaultdict(list)
        for (co_type, co_value), count in co_counts.items():
            result[co_type].append((co_value, count))

        for co_type in result:
            result[co_type].sort(key=lambda x: x[1], reverse=True)

        return dict(result)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_reverse_map(self) -> None:
        """Build line → [(entity_type, value)] reverse index."""
        for (et, val), hits in self._indexer.index.items():
            sources = self._indexer.source_map.get((et, val), [])
            for idx, (lineno, _raw) in enumerate(hits):
                src = sources[idx] if idx < len(sources) else ""
                # Store under both (src, lineno) and ("", lineno) for easy lookup
                self._line_to_entities[(src, lineno)].append((et, val))
                if src:
                    self._line_to_entities[("", lineno)].append((et, val))

    def _get_hit_indices(
        self,
        entity_type: str,
        value: str,
    ) -> List[Tuple[str, int]]:
        """
        Return [(source_path, lineno), …] for every hit of
        *(entity_type, value)* in the index.
        """
        key     = (entity_type, value)
        hits    = self._indexer.index.get(key, [])
        sources = self._indexer.source_map.get(key, [])
        result  = []
        for i, (lineno, _raw) in enumerate(hits):
            src = sources[i] if i < len(sources) else ""
            result.append((src, lineno))
        return result
