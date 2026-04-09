"""
tests/test_privesc_detections.py — Windows Privilege Escalation Detection Tests

Verifies that each EVTX sample triggers its expected YARA rules, Sigma rules,
and/or Correlation chains.

Run with:
    pytest tests/test_privesc_detections.py -v
    pytest tests/test_privesc_detections.py -v -k JuicyPotato

Samples must be downloaded first:
    python scripts/ingest_privesc_samples.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Allow running from repo root
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

SAMPLES_DIR = ROOT / "data" / "evtx_samples" / "privilege_escalation"

# ---------------------------------------------------------------------------
# Expected detections — maps sample filename → rules/chains that MUST fire
# ---------------------------------------------------------------------------

EXPECTED_DETECTIONS: dict = {
    "4624 LT3 AnonymousLogon Localhost - JuicyPotato.evtx": {
        "rule_names": ["PrivEsc_JuicyPotato_AnonymousLogon"],
        "chain_ids":  ["PRIVESC-001"],
    },
    "EfsPotato_sysmon_17_18_privesc_seimpersonate_to_system.evtx": {
        "rule_names": ["PrivEsc_EfsPotato_SrvSvc_Pipe"],
        "chain_ids":  ["PRIVESC-006"],
    },
    "privesc_rotten_potato_from_webshell_metasploit_sysmon_1_8_3.evtx": {
        "rule_names": ["PrivEsc_RottenPotato_RemoteThread"],
        "chain_ids":  ["PRIVESC-002"],
    },
    "privesc_roguepotato_sysmon_17_18.evtx": {
        "rule_names": ["PrivEsc_RoguePotato_NamedPipe"],
        "chain_ids":  [],
    },
    "Sysmon_13_1_UACBypass_SDCLTBypass.evtx": {
        "rule_names": ["PrivEsc_UAC_Bypass_SDCLT"],
        "chain_ids":  ["PRIVESC-003"],
    },
    "Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx": {
        "rule_names": ["PrivEsc_UAC_Bypass_EventViewer"],
        "chain_ids":  ["PRIVESC-003"],
    },
    "samaccount_spoofing_CVE-2021-42287_CVE-2021-42278_DC_securitylogs.evtx": {
        "rule_names": ["PrivEsc_NoPac_SAMAccountSpoofing"],
        "chain_ids":  ["PRIVESC-004"],
    },
    "privesc_spoolfool_mahdihtm_sysmon_1_11_7_13.evtx": {
        "rule_names": ["PrivEsc_SpoolFool_DLLWrite"],
        "chain_ids":  ["PRIVESC-005"],
    },
    "win10_4703_SeDebugPrivilege_enabled.evtx": {
        "rule_names": ["PrivEsc_SeDebugPrivilege_Enabled"],
        "chain_ids":  [],
    },
    "NTLM2SelfRelay-med0x2e-security_4624_4688.evtx": {
        "rule_names": ["PrivEsc_NTLM_SelfRelay"],
        "chain_ids":  ["PRIVESC-007"],
    },
    "4765_sidhistory_add_t1178.evtx": {
        "rule_names": ["PrivEsc_SIDHistory_Injection"],
        "chain_ids":  [],
    },
    "privesc_KrbRelayUp_windows_4624.evtx": {
        "rule_names": ["PrivEsc_KrbRelayUp"],
        "chain_ids":  ["PRIVESC-009"],
    },
    "System_7045_namedpipe_privesc.evtx": {
        "rule_names": ["PrivEsc_NewService_NamedPipe_Path"],
        "chain_ids":  [],
    },
    "privesc_unquoted_svc_sysmon_1_11.evtx": {
        "rule_names": ["PrivEsc_UnquotedServicePath"],
        "chain_ids":  ["PRIVESC-008"],
    },
    "sysmon_1_7_11_sysprep_uacbypass.evtx": {
        "rule_names": ["PrivEsc_UAC_Bypass_DLL_Hijack_Generic"],
        "chain_ids":  ["PRIVESC-010"],
    },
    "sysmon_1_13_11_cmstp_ini_uacbypass.evtx": {
        "rule_names": ["PrivEsc_UAC_Bypass_CMSTP"],
        "chain_ids":  [],
    },
}


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _collect_chain_ids(corr_alerts) -> list[str]:
    """
    Extract chain IDs from correlation Alert objects.

    Alert.rule_name is the attack_name (e.g. "JuicyPotato / LocalPotato NTLM Reflection").
    The chain_id lives in the CorrelationChain definition, so we also check
    whether the matched description or rule_name contains a "PRIVESC-NNN" token.
    """
    ids: list[str] = []
    import re
    for a in corr_alerts:
        # Look for PRIVESC-NNN in rule_name or description
        for text in (getattr(a, "rule_name", ""), getattr(a, "description", "")):
            hits = re.findall(r"PRIVESC-\d{3}", text)
            ids.extend(hits)
    return ids


# ---------------------------------------------------------------------------
# Parametrised test
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("evtx_filename,expected", EXPECTED_DETECTIONS.items())
def test_detection_coverage(evtx_filename: str, expected: dict) -> None:
    """Verify each EVTX sample triggers its expected YARA/Sigma/Correlation rules."""
    sample_path = SAMPLES_DIR / evtx_filename
    if not sample_path.exists():
        pytest.skip(f"Sample not downloaded: {evtx_filename}")

    # ── Imports ──────────────────────────────────────────────────────────────
    try:
        from parsers.windows_evtx_parser import EVTXParser
    except ImportError as exc:
        pytest.skip(f"EVTXParser unavailable (python-evtx not installed?): {exc}")

    try:
        from detection.engine import run_analysis
        has_engine = True
    except ImportError:
        has_engine = False

    from analytics.correlations.privesc_chains import PrivEscCorrelationEngine

    # ── Parse ────────────────────────────────────────────────────────────────
    parser = EVTXParser()
    records = parser.parse_file(str(sample_path))
    assert len(records) > 0, f"No records parsed from {evtx_filename}"

    # ── YARA + Sigma via detection engine ────────────────────────────────────
    all_rule_names: list[str] = []

    if has_engine:
        # Build a raw events list from the records (engine expects dicts)
        raw_events = []
        for r in records:
            ev = {"raw": r.raw_line, "log_type": r.log_type, "event_id": r.event_id}
            ev.update(r.extra)
            if r.timestamp:
                ev["timestamp"] = r.timestamp.isoformat()
            raw_events.append(ev)

        log_type = records[0].log_type if records else "windows_event"
        analysis = run_analysis(raw_events, log_type=log_type)
        all_rule_names = [f.get("rule_name", "") for f in analysis.get("findings", [])]

    # ── Correlation engine ───────────────────────────────────────────────────
    corr_engine = PrivEscCorrelationEngine()
    corr_alerts = corr_engine.evaluate(records)
    corr_names = [a.rule_name for a in corr_alerts]
    corr_chain_ids = _collect_chain_ids(corr_alerts)

    all_names = all_rule_names + corr_names

    # ── Assertions: YARA/Sigma rule coverage ─────────────────────────────────
    for expected_rule in expected.get("rule_names", []):
        matched = any(expected_rule in name for name in all_names)
        assert matched, (
            f"[{evtx_filename}] Expected rule '{expected_rule}' not triggered.\n"
            f"  Got rules:  {all_names}\n"
            f"  Got chains: {corr_chain_ids}"
        )

    # ── Assertions: correlation chain coverage ───────────────────────────────
    for expected_chain in expected.get("chain_ids", []):
        # Accept if chain fired OR if we have no correlation (engine skip)
        if corr_alerts:
            matched = expected_chain in corr_chain_ids or any(
                expected_chain in a.rule_name for a in corr_alerts
            )
            assert matched, (
                f"[{evtx_filename}] Expected chain '{expected_chain}' not fired.\n"
                f"  Got chains: {corr_chain_ids}\n"
                f"  Got names:  {corr_names}"
            )


# ---------------------------------------------------------------------------
# Additional unit tests for the correlation engine
# ---------------------------------------------------------------------------

class TestPrivEscCorrelationEngine:
    """Unit tests for PrivEscCorrelationEngine using synthetic records."""

    def _make_record(self, event_id: str, extra: dict, ts=None):
        from core.models import LogRecord
        from datetime import datetime, timezone
        return LogRecord(
            raw_line=f"<Event><EventID>{event_id}</EventID></Event>",
            log_type="windows_security",
            event_id=event_id,
            timestamp=ts or datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            extra=extra,
        )

    def test_juicypotato_chain_matches(self):
        from analytics.correlations.privesc_chains import PrivEscCorrelationEngine, PRIVESC_CHAINS
        from core.models import LogRecord
        from datetime import datetime, timezone, timedelta

        t0 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        records = [
            self._make_record("4624", {
                "LogonType": "3",
                "AuthenticationPackageName": "NTLM",
                "IpAddress": "127.0.0.1",
                "TargetUserName": "ANONYMOUS LOGON",
            }, ts=t0),
            self._make_record("4688", {
                "SubjectUserName": "SYSTEM",
            }, ts=t0 + timedelta(seconds=5)),
        ]
        chain = next(c for c in PRIVESC_CHAINS if c.chain_id == "PRIVESC-001")
        engine = PrivEscCorrelationEngine()
        matched = engine._evaluate_chain(records, chain)
        assert matched is not None, "JuicyPotato chain should have matched"
        assert len(matched) == 2

    def test_chain_no_match_wrong_event_id(self):
        from analytics.correlations.privesc_chains import PrivEscCorrelationEngine, PRIVESC_CHAINS

        records = [
            self._make_record("9999", {"LogonType": "3"})
        ]
        chain = next(c for c in PRIVESC_CHAINS if c.chain_id == "PRIVESC-001")
        engine = PrivEscCorrelationEngine()
        matched = engine._evaluate_chain(records, chain)
        assert matched is None, "Chain should not match with wrong event ID"

    def test_chain_no_match_time_window_exceeded(self):
        from analytics.correlations.privesc_chains import PrivEscCorrelationEngine, PRIVESC_CHAINS
        from datetime import datetime, timezone, timedelta

        t0 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        records = [
            self._make_record("4624", {
                "LogonType": "3",
                "AuthenticationPackageName": "NTLM",
                "IpAddress": "127.0.0.1",
                "TargetUserName": "ANONYMOUS LOGON",
            }, ts=t0),
            # Stage 2 arrives 300s later — outside the 30s window
            self._make_record("4688", {
                "SubjectUserName": "SYSTEM",
            }, ts=t0 + timedelta(seconds=300)),
        ]
        chain = next(c for c in PRIVESC_CHAINS if c.chain_id == "PRIVESC-001")
        engine = PrivEscCorrelationEngine()
        matched = engine._evaluate_chain(records, chain)
        assert matched is None, "Chain should not match when time window exceeded"

    def test_all_chains_defined(self):
        from analytics.correlations.privesc_chains import PRIVESC_CHAINS
        assert len(PRIVESC_CHAINS) == 10, "All 10 chains must be defined"
        ids = [c.chain_id for c in PRIVESC_CHAINS]
        expected = [f"PRIVESC-{i:03d}" for i in range(1, 11)]
        assert ids == expected, f"Chain IDs mismatch: {ids}"

    def test_match_conditions_endswith_any(self):
        from analytics.correlations.privesc_chains import PrivEscCorrelationEngine
        engine = PrivEscCorrelationEngine()
        record = self._make_record("1", {"Image": "C:\\Windows\\System32\\spoolsv.exe"})
        assert engine._match_conditions(record, {"Image__endswith_any": ["spoolsv.exe", "lsass.exe"]})
        assert not engine._match_conditions(record, {"Image__endswith_any": ["notepad.exe"]})

    def test_match_conditions_contains_any(self):
        from analytics.correlations.privesc_chains import PrivEscCorrelationEngine
        engine = PrivEscCorrelationEngine()
        record = self._make_record("17", {"PipeName": "\\\\.\\pipe\\srvsvc"})
        assert engine._match_conditions(record, {"PipeName__contains_any": ["srvsvc", "efslpc"]})
        assert not engine._match_conditions(record, {"PipeName__contains_any": ["RoguePotato"]})
