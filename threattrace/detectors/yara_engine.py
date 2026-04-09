"""YARA detection engine — compiles rules and matches against raw log content."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator

from ..models.finding import Finding, Severity
from ..models.log_event import LogEvent

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


class YARAEngine:
    """Loads and runs YARA rules against raw log content."""

    def __init__(self, rules_dir: Path) -> None:
        self.rules_dir = rules_dir
        self._rules = None
        self._load_rules()

    def _load_rules(self) -> None:
        try:
            import yara
        except ImportError:
            logger.warning("yara-python not installed — YARA detection disabled")
            return

        yar_files = list(self.rules_dir.rglob("*.yar")) + list(self.rules_dir.rglob("*.yara"))
        if not yar_files:
            logger.warning("No YARA rule files found in %s", self.rules_dir)
            return

        filepaths: dict[str, str] = {}
        for yar in yar_files:
            namespace = str(yar.relative_to(self.rules_dir)).replace("/", "_").replace("\\", "_")
            filepaths[namespace] = str(yar)

        try:
            self._rules = yara.compile(filepaths=filepaths)
            logger.debug("Compiled %d YARA rule files", len(yar_files))
        except yara.SyntaxError as e:
            # Try compiling one by one to identify broken files
            logger.error("YARA compilation error: %s — trying per-file fallback", e)
            good: dict[str, str] = {}
            for ns, fp in filepaths.items():
                try:
                    yara.compile(filepath=fp)
                    good[ns] = fp
                except yara.SyntaxError as e2:
                    logger.error("Skipping broken rule file %s: %s", fp, e2)
            if good:
                try:
                    self._rules = yara.compile(filepaths=good)
                except Exception as e3:
                    logger.error("YARA compilation failed: %s", e3)

    def scan_event(self, event: LogEvent) -> list[Finding]:
        """Scan a single LogEvent's raw content with all YARA rules."""
        if self._rules is None:
            return []

        findings: list[Finding] = []
        try:
            matches = self._rules.match(data=event.raw.encode("utf-8", errors="replace"))
        except Exception as e:
            logger.debug("YARA scan error: %s", e)
            return []

        for match in matches:
            findings.append(self._match_to_finding(match, event))

        return findings

    def scan_raw(self, data: bytes | str, source_file: str = "") -> list[dict]:
        """Scan raw bytes/string and return raw match dicts (for bulk scanning)."""
        if self._rules is None:
            return []
        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")
        try:
            matches = self._rules.match(data=data)
        except Exception:
            return []
        return [
            {
                "rule": m.rule,
                "namespace": m.namespace,
                "tags": m.tags,
                "meta": dict(m.meta),
                "strings": [
                    {"identifier": s.identifier, "offset": s.instances[0].offset if s.instances else 0,
                     "matched": s.instances[0].matched_data.decode("utf-8", errors="replace") if s.instances else ""}
                    for s in m.strings
                ],
            }
            for m in matches
        ]

    def _match_to_finding(self, match, event: LogEvent) -> Finding:
        meta = dict(match.meta)
        severity = _SEVERITY_MAP.get(
            str(meta.get("severity", "medium")).lower(), Severity.MEDIUM
        )

        # Collect matched strings
        matched_fields: dict[str, str] = {}
        for string in match.strings:
            identifier = string.identifier
            for instance in string.instances:
                matched_fields[identifier] = instance.matched_data.decode("utf-8", errors="replace")[:200]

        ref = meta.get("reference", meta.get("ref", ""))
        references = [ref] if ref else []

        return Finding(
            rule_id=f"yara:{match.namespace}:{match.rule}",
            rule_name=match.rule,
            engine="yara",
            severity=severity,
            log_source=event.source_type.value,
            matched_fields=matched_fields,
            raw_line=event.raw[:500],
            timestamp=event.timestamp,
            mitre_tactic=meta.get("mitre_tactic", ""),
            mitre_technique=meta.get("mitre_technique", ""),
            description=meta.get("description", ""),
            references=references,
            false_positive_notes=str(meta.get("false_positives", "")),
            source_file=event.source_file,
            line_number=event.line_number,
        )
