"""
extractor/exporters.py — Export IOC extraction results to CSV, TXT, JSON.

Export formats:
  CSV  — utf-8-sig (Excel-compatible BOM); columns: type, value, occurrences,
          first_seen, last_seen, sources, risk_score, risk_factors, sample_line
  TXT  — utf-8; plain human-readable report with section headers
  JSON — utf-8; structured list of result dicts

Filename collision policy:
  If the requested path already exists, a ``_HHMMSS`` suffix is inserted
  before the extension.

Public API:
    ExportManager(results: list[ExtractionResult])
    .export_csv(path)  → Path
    .export_txt(path)  → Path
    .export_json(path) → Path
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Union

from extractor.engine import ExtractionResult


class ExportManager:
    """
    Writes :class:`ExtractionResult` lists to disk in the requested format.

    Parameters
    ----------
    results : List of :class:`ExtractionResult` instances to export.
    """

    def __init__(self, results: List[ExtractionResult]) -> None:
        self._results = results

    # ------------------------------------------------------------------
    # Public export methods
    # ------------------------------------------------------------------

    def export_csv(self, path: Union[str, Path]) -> Path:
        """
        Write results to *path* as CSV (utf-8-sig, Excel-compatible).

        Columns: type, value, occurrences, first_seen, last_seen,
                 sources, risk_score, risk_factors, sample_line
        """
        out = self._resolve_path(path)
        out.parent.mkdir(parents=True, exist_ok=True)

        with open(out, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh)
            writer.writerow([
                "type", "value", "occurrences",
                "first_seen", "last_seen", "sources",
                "risk_score", "risk_factors", "sample_line",
            ])
            for r in self._results:
                sample = r.sample_lines[0][1] if r.sample_lines else ""
                writer.writerow([
                    r.entity_type,
                    r.value,
                    r.occurrences,
                    r.first_seen.isoformat() if r.first_seen else "",
                    r.last_seen.isoformat()  if r.last_seen  else "",
                    "; ".join(r.sources),
                    f"{r.risk_score:.3f}",
                    " | ".join(r.risk_factors),
                    sample[:200],
                ])
        return out

    def export_txt(self, path: Union[str, Path]) -> Path:
        """
        Write results to *path* as a plain-text human-readable report (utf-8).
        """
        out = self._resolve_path(path)
        out.parent.mkdir(parents=True, exist_ok=True)

        now = datetime.now().isoformat(timespec="seconds")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("=" * 72 + "\n")
            fh.write("  ThreatTrace — Context-Aware IOC Extractor Report\n")
            fh.write(f"  Generated : {now}\n")
            fh.write(f"  Total IOCs : {len(self._results)}\n")
            fh.write("=" * 72 + "\n\n")

            # Group by entity_type for readability
            by_type: dict[str, list[ExtractionResult]] = {}
            for r in self._results:
                by_type.setdefault(r.entity_type, []).append(r)

            for et in sorted(by_type):
                group = by_type[et]
                fh.write(f"\n{'─' * 72}\n")
                fh.write(f"  {et.upper()}  ({len(group)} unique)\n")
                fh.write(f"{'─' * 72}\n")
                for r in group:
                    fh.write(f"\n  Value     : {r.value}\n")
                    fh.write(f"  Count     : {r.occurrences}\n")
                    fh.write(f"  Risk      : {r.risk_score:.3f}  "
                             f"({', '.join(r.risk_factors[:2])})\n")
                    if r.first_seen:
                        fh.write(f"  First     : {r.first_seen.isoformat()}\n")
                    if r.last_seen and r.last_seen != r.first_seen:
                        fh.write(f"  Last      : {r.last_seen.isoformat()}\n")
                    if r.sources:
                        fh.write(f"  Sources   : {'; '.join(r.sources[:3])}\n")
                    if r.sample_lines:
                        ln, raw = r.sample_lines[0]
                        fh.write(f"  Sample    : [line {ln}] {raw[:120]}\n")
                    if r.context:
                        co_summary = ", ".join(
                            f"{cet}({len(cvals)})"
                            for cet, cvals in r.context.items()
                        )
                        fh.write(f"  Context   : {co_summary}\n")

            fh.write(f"\n{'=' * 72}\n")
            fh.write("  End of Report\n")
            fh.write(f"{'=' * 72}\n")
        return out

    def export_json(self, path: Union[str, Path]) -> Path:
        """
        Write results to *path* as JSON (utf-8).

        Each result is serialised to a dict.  datetimes → ISO-8601 strings.
        """
        out = self._resolve_path(path)
        out.parent.mkdir(parents=True, exist_ok=True)

        def _dt(d: Optional[datetime]) -> Optional[str]:
            return d.isoformat() if d else None

        data = {
            "generated":  datetime.now().isoformat(timespec="seconds"),
            "total_iocs": len(self._results),
            "results": [
                {
                    "type":         r.entity_type,
                    "value":        r.value,
                    "occurrences":  r.occurrences,
                    "first_seen":   _dt(r.first_seen),
                    "last_seen":    _dt(r.last_seen),
                    "sources":      r.sources,
                    "risk_score":   round(r.risk_score, 4),
                    "risk_factors": r.risk_factors,
                    "sample_lines": [
                        {"lineno": ln, "raw": raw}
                        for ln, raw in r.sample_lines
                    ],
                    "context": {
                        et: [{"value": v, "count": c} for v, c in pairs]
                        for et, pairs in r.context.items()
                    },
                }
                for r in self._results
            ],
        }

        with open(out, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        return out

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_path(self, path: Union[str, Path]) -> Path:
        """
        If *path* already exists on disk, insert a ``_HHMMSS`` suffix
        before the file extension and return the new path.

        Example::
            ioc_results.csv → ioc_results_143022.csv
        """
        p = Path(os.path.expandvars(os.path.expanduser(str(path))))
        if not p.exists():
            return p
        ts   = datetime.now().strftime("%H%M%S")
        stem = p.stem
        return p.parent / f"{stem}_{ts}{p.suffix}"
