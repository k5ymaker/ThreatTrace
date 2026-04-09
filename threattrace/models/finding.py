"""Finding data model – a single detection result."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rich_style(self) -> str:
        return {
            "CRITICAL": "bold red",
            "HIGH": "bold yellow",
            "MEDIUM": "bold dark_orange",
            "LOW": "bold cyan",
            "INFO": "bold blue",
        }[self.value]

    @property
    def sort_order(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[self.value]

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        try:
            return cls(s.upper())
        except ValueError:
            return cls.MEDIUM


@dataclass
class Finding:
    # Identity
    rule_id: str
    rule_name: str
    engine: str  # "yara" | "sigma"
    severity: Severity

    # Context
    log_source: str
    matched_fields: dict[str, str]
    raw_line: str

    # Timing
    timestamp: Optional[datetime] = None

    # MITRE ATT&CK
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None

    # Metadata
    description: str = ""
    references: list[str] = field(default_factory=list)
    false_positive_notes: str = ""

    # File context
    source_file: str = ""
    line_number: int = 0

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "engine": self.engine,
            "severity": self.severity.value,
            "log_source": self.log_source,
            "matched_fields": self.matched_fields,
            "raw_line": self.raw_line[:500],
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "description": self.description,
            "references": self.references,
            "false_positive_notes": self.false_positive_notes,
            "source_file": self.source_file,
            "line_number": self.line_number,
        }
