"""Global TUI state — stores the last scan report for export/re-display."""
from __future__ import annotations

from typing import TYPE_CHECKING, Optional, Any, List

if TYPE_CHECKING:
    from ..models.report import AnalysisReport

# Stores the most recently completed scan report
last_report: Optional["AnalysisReport"] = None

# Search engines populated after each scan (used by SearchMenu)
keyword_engine: Optional[Any] = None
event_engine: Optional[Any] = None
name_detector: Optional[Any] = None
name_results: List[Any] = []
