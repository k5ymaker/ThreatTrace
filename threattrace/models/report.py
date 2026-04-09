"""AnalysisReport – aggregates all findings from a scan session."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .finding import Finding, Severity
from .log_event import LogSourceType


@dataclass
class AnalysisReport:
    generated_at: datetime
    analyst_host: str
    input_files: list[str]
    log_source: LogSourceType
    total_events: int = 0
    parse_errors: int = 0
    elapsed_seconds: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)
        self.severity_counts[f.severity.value] = (
            self.severity_counts.get(f.severity.value, 0) + 1
        )

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity.sort_order)

    @property
    def critical_count(self) -> int:
        return self.severity_counts.get(Severity.CRITICAL.value, 0)

    @property
    def high_count(self) -> int:
        return self.severity_counts.get(Severity.HIGH.value, 0)

    @property
    def medium_count(self) -> int:
        return self.severity_counts.get(Severity.MEDIUM.value, 0)

    @property
    def low_count(self) -> int:
        return self.severity_counts.get(Severity.LOW.value, 0)

    @property
    def info_count(self) -> int:
        return self.severity_counts.get(Severity.INFO.value, 0)

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at.isoformat(),
            "analyst_host": self.analyst_host,
            "input_files": self.input_files,
            "log_source": self.log_source.value,
            "total_events": self.total_events,
            "parse_errors": self.parse_errors,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "summary": {
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
