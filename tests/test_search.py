"""
tests/test_search.py — Unit tests for search package modules.

Run with:
    pytest tests/test_search.py -v
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Helpers — minimal mock LogRecord / Alert so tests don't need core.models
# ---------------------------------------------------------------------------

class _MockLogRecord:
    def __init__(self, raw_line: str, log_type: str = "test",
                 timestamp: Optional[datetime] = None,
                 source_ip: str = "", username: str = "",
                 line_number: int = 1):
        self.raw_line = raw_line
        self.log_type = log_type
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.username = username
        self.line_number = line_number
        self.dest_ip = None
        self.uri = None
        self.user_agent = None
        self.hostname = None
        self.action = None


class _MockAlert:
    def __init__(self, rule_name: str, severity: str = "HIGH",
                 timestamp: Optional[datetime] = None,
                 source_ip: str = "", username: str = "",
                 mitre_tactic: str = "", mitre_technique: str = "",
                 log_type: str = "test", iocs: Optional[List[str]] = None,
                 matched_line: str = "", description: str = ""):
        self.rule_name = rule_name
        self.severity = severity
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.username = username
        self.mitre_tactic = mitre_tactic
        self.mitre_technique = mitre_technique
        self.log_type = log_type
        self.iocs = iocs or []
        self.matched_line = matched_line
        self.description = description
        self.extra: Dict[str, Any] = {}


class _MockStatResult:
    def __init__(self, module: str = "timeline", data: Optional[dict] = None):
        self.module = module
        self.data = data or {}
        self.anomalies: List[Any] = []
        self.title = "test"
        self.severity = "INFO"
        self.log_type = "test"


# ---------------------------------------------------------------------------
# KeywordSearchEngine tests
# ---------------------------------------------------------------------------

class TestKeywordSearchEngine:
    """Tests for KeywordSearchEngine.raw_grep()."""

    def _make_engine(self, records: List[_MockLogRecord]):
        from search.keyword_search import KeywordSearchEngine
        engine = KeywordSearchEngine(index_dir="/tmp/tt_test_index")
        engine._records = records
        return engine

    def test_raw_grep_match(self):
        """raw_grep returns results for matching pattern."""
        records = [
            _MockLogRecord("Failed password for root from 10.0.0.1"),
            _MockLogRecord("Accepted publickey for admin"),
            _MockLogRecord("Connection closed by 192.168.1.1"),
        ]
        engine = self._make_engine(records)
        results = engine.raw_grep("Failed password")
        assert len(results) == 1
        assert "Failed password" in results[0].matched_line

    def test_raw_grep_no_match(self):
        """raw_grep returns empty list when no line matches."""
        records = [
            _MockLogRecord("Accepted publickey for admin"),
            _MockLogRecord("Connection closed by 192.168.1.1"),
        ]
        engine = self._make_engine(records)
        results = engine.raw_grep("mimikatz")
        assert results == []

    def test_raw_grep_case_insensitive(self):
        """raw_grep is case-insensitive."""
        records = [_MockLogRecord("FAILED PASSWORD for root")]
        engine = self._make_engine(records)
        assert len(engine.raw_grep("failed password")) == 1

    def test_raw_grep_multiple_matches(self):
        """raw_grep returns all matching lines."""
        records = [
            _MockLogRecord("Failed password for user1 from 1.2.3.4"),
            _MockLogRecord("Failed password for user2 from 5.6.7.8"),
            _MockLogRecord("Accepted publickey for admin"),
        ]
        engine = self._make_engine(records)
        results = engine.raw_grep("Failed password")
        assert len(results) == 2

    def test_raw_grep_context_lines(self):
        """raw_grep returns surrounding context lines when context_lines > 0."""
        records = [
            _MockLogRecord("line before"),
            _MockLogRecord("target line with keyword"),
            _MockLogRecord("line after"),
        ]
        engine = self._make_engine(records)
        results = engine.raw_grep("keyword", context_lines=1)
        assert len(results) == 1
        assert len(results[0].context_before) == 1
        assert len(results[0].context_after) == 1

    def test_raw_grep_empty_records(self):
        """raw_grep on empty records returns empty list."""
        engine = self._make_engine([])
        results = engine.raw_grep("anything")
        assert results == []

    def test_highlight_results_returns_rich_text(self):
        """highlight_results returns a Rich Text object per result."""
        import rich.text
        records = [_MockLogRecord("Failed password for root")]
        engine = self._make_engine(records)
        results = engine.raw_grep("Failed")
        highlighted = engine.highlight_results(results, "Failed")
        assert len(highlighted) == 1
        assert isinstance(highlighted[0], rich.text.Text)


# ---------------------------------------------------------------------------
# EventSearchEngine tests
# ---------------------------------------------------------------------------

class TestEventSearchEngine:
    """Tests for EventSearchEngine.filter()."""

    def _make_engine(self, alerts=None, stat_results=None, log_records=None):
        from search.event_search import EventSearchEngine
        return EventSearchEngine(
            alerts=alerts or [],
            stat_results=stat_results or [],
            log_records=log_records or [],
        )

    def test_filter_by_severity(self):
        """filter() returns only alerts matching the given severities."""
        t = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        alerts = [
            _MockAlert("rule_A", severity="CRITICAL", timestamp=t),
            _MockAlert("rule_B", severity="HIGH", timestamp=t),
            _MockAlert("rule_C", severity="LOW", timestamp=t),
        ]
        engine = self._make_engine(alerts)
        results = engine.filter(severity=["CRITICAL"])
        assert len(results) == 1
        assert results[0].rule_name == "rule_A"

    def test_filter_by_multiple_severities(self):
        """filter() handles comma-list of severities."""
        t = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        alerts = [
            _MockAlert("rule_A", severity="CRITICAL", timestamp=t),
            _MockAlert("rule_B", severity="HIGH", timestamp=t),
            _MockAlert("rule_C", severity="LOW", timestamp=t),
        ]
        engine = self._make_engine(alerts)
        results = engine.filter(severity=["CRITICAL", "HIGH"])
        assert len(results) == 2

    def test_filter_by_time_range(self):
        """filter() respects from_time and to_time."""
        t0 = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2024, 1, 1, 14, 0, 0, tzinfo=timezone.utc)
        alerts = [
            _MockAlert("early", timestamp=t0),
            _MockAlert("middle", timestamp=t1),
            _MockAlert("late", timestamp=t2),
        ]
        engine = self._make_engine(alerts)
        results = engine.filter(
            from_time=datetime(2024, 1, 1, 11, 0, 0, tzinfo=timezone.utc),
            to_time=datetime(2024, 1, 1, 13, 0, 0, tzinfo=timezone.utc),
        )
        assert len(results) == 1
        assert results[0].rule_name == "middle"

    def test_filter_by_event_type(self):
        """filter() does partial case-insensitive match on rule_name."""
        t = datetime(2024, 1, 1, tzinfo=timezone.utc)
        alerts = [
            _MockAlert("BruteForce_SSH", timestamp=t),
            _MockAlert("SQLInjection_Web", timestamp=t),
        ]
        engine = self._make_engine(alerts)
        results = engine.filter(event_type="brute")
        assert len(results) == 1
        assert "BruteForce" in results[0].rule_name

    def test_filter_empty_returns_all(self):
        """filter() with no arguments returns all alerts."""
        t = datetime(2024, 1, 1, tzinfo=timezone.utc)
        alerts = [_MockAlert(f"rule_{i}", timestamp=t) for i in range(5)]
        engine = self._make_engine(alerts)
        assert len(engine.filter()) == 5

    def test_filter_deduplicate(self):
        """filter() with deduplicate=True collapses same rule/IP within 60s."""
        t0 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        alerts = [
            _MockAlert("BruteForce", source_ip="1.2.3.4", timestamp=t0),
            _MockAlert("BruteForce", source_ip="1.2.3.4", timestamp=t0 + timedelta(seconds=10)),
            _MockAlert("BruteForce", source_ip="1.2.3.4", timestamp=t0 + timedelta(seconds=70)),
        ]
        engine = self._make_engine(alerts)
        results = engine.filter(deduplicate=True)
        # First two within 60s window → collapsed; third is outside → kept
        assert len(results) == 2


# ---------------------------------------------------------------------------
# EventNameDetector tests
# ---------------------------------------------------------------------------

class TestEventNameDetector:
    """Tests for EventNameDetector helper methods."""

    def _make_detector(self):
        from search.event_name_detector import EventNameDetector
        return EventNameDetector(
            rules_dir="detection/rules",
            templates_path="/tmp/tt_test_templates.json",
        )

    def test_canonicalize_known_key(self):
        """_canonicalize returns canonical name for known substring."""
        from search.event_name_detector import EventNameDetector
        d = EventNameDetector(
            rules_dir="detection/rules",
            templates_path="/tmp/tt_test_templates.json",
        )
        assert d._canonicalize("authentication failure for user") == "AUTH_FAILURE"
        assert d._canonicalize("Failed password for root") == "AUTH_FAILURE"
        assert d._canonicalize("Accepted password for admin") == "AUTH_SUCCESS"

    def test_canonicalize_unknown_returns_none(self):
        """_canonicalize returns None when no key matches."""
        from search.event_name_detector import EventNameDetector
        d = EventNameDetector(
            rules_dir="detection/rules",
            templates_path="/tmp/tt_test_templates.json",
        )
        result = d._canonicalize("completely unrelated log line with no matches xyz999")
        assert result is None

    def test_infer_mitre_sudo(self):
        """_infer_mitre returns correct tactic/technique for 'sudo'."""
        from search.event_name_detector import EventNameDetector
        d = EventNameDetector(
            rules_dir="detection/rules",
            templates_path="/tmp/tt_test_templates.json",
        )
        tactic, technique = d._infer_mitre("user ran sudo -i to become root")
        assert tactic == "Privilege Escalation"
        assert technique == "T1548.003"

    def test_infer_mitre_mimikatz(self):
        """_infer_mitre detects mimikatz credential dumping."""
        from search.event_name_detector import EventNameDetector
        d = EventNameDetector(
            rules_dir="detection/rules",
            templates_path="/tmp/tt_test_templates.json",
        )
        tactic, technique = d._infer_mitre("process mimikatz.exe started")
        assert tactic == "Credential Access"
        assert technique == "T1003"

    def test_infer_mitre_no_match(self):
        """_infer_mitre returns (None, None) when no keyword matches."""
        from search.event_name_detector import EventNameDetector
        d = EventNameDetector(
            rules_dir="detection/rules",
            templates_path="/tmp/tt_test_templates.json",
        )
        tactic, technique = d._infer_mitre("2024-01-01 12:00:00 INFO heartbeat ok")
        assert tactic is None
        assert technique is None

    def test_canonicalize_all_canonical_map_keys(self):
        """_canonicalize covers every key in CANONICAL_NAME_MAP."""
        from search.event_name_detector import EventNameDetector, CANONICAL_NAME_MAP
        d = EventNameDetector(
            rules_dir="detection/rules",
            templates_path="/tmp/tt_test_templates.json",
        )
        for key, expected_value in CANONICAL_NAME_MAP.items():
            result = d._canonicalize(f"some prefix {key} some suffix")
            assert result == expected_value, (
                f"Expected '{expected_value}' for key '{key}', got '{result}'"
            )

    def test_infer_mitre_covers_all_keywords(self):
        """_infer_mitre covers every key in MITRE_KEYWORD_MAP."""
        from search.event_name_detector import EventNameDetector, MITRE_KEYWORD_MAP
        d = EventNameDetector(
            rules_dir="detection/rules",
            templates_path="/tmp/tt_test_templates.json",
        )
        for keyword, (expected_tactic, expected_technique) in MITRE_KEYWORD_MAP.items():
            tactic, technique = d._infer_mitre(f"event contains {keyword} inside line")
            assert tactic == expected_tactic, f"Keyword '{keyword}' tactic mismatch"
            assert technique == expected_technique, f"Keyword '{keyword}' technique mismatch"


# ---------------------------------------------------------------------------
# PivotResult field correctness
# ---------------------------------------------------------------------------

class TestPivotResult:
    """Test PivotResult field correctness for a mock Alert list."""

    def test_pivot_by_ip_fields(self):
        """pivot_by_ip returns correct aggregated fields."""
        from search.event_search import EventSearchEngine

        t0 = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2024, 1, 1, 11, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        alerts = [
            _MockAlert("BruteForce_SSH", severity="HIGH",
                       source_ip="10.0.0.1", timestamp=t0,
                       mitre_technique="T1110", log_type="ssh"),
            _MockAlert("CredentialStuffing", severity="CRITICAL",
                       source_ip="10.0.0.1", timestamp=t1,
                       mitre_technique="T1110", log_type="ssh"),
            _MockAlert("PortScan", severity="MEDIUM",
                       source_ip="10.0.0.2", timestamp=t2,
                       mitre_technique="T1046", log_type="network"),
        ]

        engine = EventSearchEngine(alerts=alerts, stat_results=[], log_records=[])
        pivot = engine.pivot_by_ip("10.0.0.1")

        assert pivot.entity_type == "ip"
        assert pivot.entity_value == "10.0.0.1"
        assert pivot.total_events == 2
        assert pivot.first_seen == t0
        assert pivot.last_seen == t1
        assert set(pivot.unique_rules) == {"BruteForce_SSH", "CredentialStuffing"}
        assert pivot.severity_breakdown.get("HIGH", 0) == 1
        assert pivot.severity_breakdown.get("CRITICAL", 0) == 1
        assert "T1110" in pivot.mitre_techniques
        assert len(pivot.top_alerts) <= 10

    def test_pivot_by_user_fields(self):
        """pivot_by_user aggregates by username correctly."""
        from search.event_search import EventSearchEngine

        t0 = datetime(2024, 1, 1, tzinfo=timezone.utc)
        alerts = [
            _MockAlert("AuthFail", severity="HIGH",
                       username="alice", timestamp=t0, log_type="auth"),
            _MockAlert("AuthFail", severity="HIGH",
                       username="alice", timestamp=t0, log_type="auth"),
            _MockAlert("AuthFail", severity="HIGH",
                       username="bob", timestamp=t0, log_type="auth"),
        ]
        engine = EventSearchEngine(alerts=alerts, stat_results=[], log_records=[])
        pivot = engine.pivot_by_user("alice")
        assert pivot.entity_type == "user"
        assert pivot.total_events == 2
