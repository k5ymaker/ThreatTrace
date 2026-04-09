"""
analytics/correlations/privesc_chains.py — Windows Privilege Escalation Correlation Engine

Defines CorrelationChain objects for 10 multi-stage privilege escalation attack patterns
and a PrivEscCorrelationEngine that matches ordered event sequences against a list of
LogRecord objects within configurable time windows.

Usage
-----
from analytics.correlations.privesc_chains import PrivEscCorrelationEngine

engine = PrivEscCorrelationEngine()
alerts = engine.evaluate(records)   # records: List[LogRecord]
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.models import Alert, LogRecord


# ---------------------------------------------------------------------------
# UACME method fingerprint reference
# ---------------------------------------------------------------------------

UACME_METHOD_FINGERPRINTS: Dict[int, Dict[str, str]] = {
    22: {"binary": "wusa.exe",          "technique": "CAB expansion to system32"},
    23: {"binary": "pkgmgr.exe",        "technique": "INF file auto-elevation"},
    30: {"binary": "InetMgr.exe",       "technique": "COM object elevation"},
    32: {"binary": "msiexec.exe",       "technique": "MSI transform auto-elevation"},
    33: {"binary": "SndVol.exe",        "technique": "DLL hijack CRYPTBASE.dll"},
    34: {"binary": "NewDev.dll",        "technique": "rundll32 via auto-elevation"},
    36: {"technique": "File Create in Protected Directory"},
    37: {"technique": "File Create via Junction"},
    38: {"binary": "wscript.exe",       "technique": "WSH INF execution"},
    39: {"binary": "cmstp.exe",         "technique": "COM surrogate elevation"},
    41: {"binary": "ClipRenew.exe",     "technique": "Task hijack"},
    43: {"binary": "atbroker.exe",      "technique": "Registry class hijack"},
    45: {"binary": "dccw.exe",          "technique": "HKCU hijack → auto-elevate"},
    53: {"binary": "ntoskrnl.exe",      "technique": "PEB elevation flag manipulation"},
    54: {"binary": "consent.exe",       "technique": "AppInfo bypass"},
    56: {"binary": "IFileOperation",    "technique": "COM object file move to system32"},
    58: {"binary": "mmc.exe",           "technique": "HKCU class hijack for snap-in"},
    59: {"binary": "wsreset.exe",       "technique": "AppX class store hijack"},
    63: {"technique": "COM elevation moniker abuse"},
    64: {"binary": "msiexec.exe",       "technique": "MSI with elevated install"},
}


# ---------------------------------------------------------------------------
# CorrelationChain dataclass
# ---------------------------------------------------------------------------

@dataclass
class CorrelationChain:
    """
    Describes a multi-stage attack that spans several log events in order.

    required_stages is an ordered list of dicts.  Each dict may contain:
      - "event_id"              : str  — EventID to match (required)
      - "conditions"            : dict — field → value / operator conditions (optional)
      - "follows_within_seconds": int  — max seconds after previous stage (optional)

    Condition key format:  <field_name>__<op>   (op defaults to "eq")
    Operators: eq, contains, endswith, endswith_any, contains_any
    """
    chain_id: str
    attack_name: str
    mitre_technique: str
    description: str
    required_stages: List[Dict[str, Any]]
    time_window_seconds: int
    severity: str


# ---------------------------------------------------------------------------
# Privilege Escalation Correlation Chains
# ---------------------------------------------------------------------------

PRIVESC_CHAINS: List[CorrelationChain] = [

    # ── PRIVESC-001 ─────────────────────────────────────────────────────────
    CorrelationChain(
        chain_id="PRIVESC-001",
        attack_name="JuicyPotato / LocalPotato NTLM Reflection",
        mitre_technique="T1134.001",
        description=(
            "Stage 1: Anonymous NTLM logon from localhost (4624, LogonType=3, NTLM, 127.0.0.1). "
            "Stage 2: SYSTEM-level process creation immediately after. "
            "Indicates token captured via DCOM/OXID NTLM reflection."
        ),
        required_stages=[
            {
                "event_id": "4624",
                "conditions": {
                    "LogonType":                   "3",
                    "AuthenticationPackageName":   "NTLM",
                    "IpAddress":                   "127.0.0.1",
                    "TargetUserName__contains":    "ANONYMOUS LOGON",
                },
            },
            {
                "event_id": "4688",
                "conditions": {"SubjectUserName": "SYSTEM"},
                "follows_within_seconds": 30,
            },
        ],
        time_window_seconds=30,
        severity="CRITICAL",
    ),

    # ── PRIVESC-002 ─────────────────────────────────────────────────────────
    CorrelationChain(
        chain_id="PRIVESC-002",
        attack_name="RottenPotato from Webshell",
        mitre_technique="T1134.001",
        description=(
            "Stage 1: Sysmon 3 - Network connection from w3wp.exe to localhost. "
            "Stage 2: Sysmon 8 - CreateRemoteThread from w3wp.exe into SYSTEM process. "
            "Stage 3: Sysmon 1 - New SYSTEM process spawned."
        ),
        required_stages=[
            {
                "event_id": "3",
                "conditions": {
                    "Image__endswith":    "w3wp.exe",
                    "DestinationIp":      "127.0.0.1",
                },
            },
            {
                "event_id": "8",
                "conditions": {"SourceImage__endswith": "w3wp.exe"},
                "follows_within_seconds": 60,
            },
            {
                "event_id": "1",
                "conditions": {"User__contains": "SYSTEM"},
                "follows_within_seconds": 30,
            },
        ],
        time_window_seconds=120,
        severity="CRITICAL",
    ),

    # ── PRIVESC-003 ─────────────────────────────────────────────────────────
    CorrelationChain(
        chain_id="PRIVESC-003",
        attack_name="UAC Bypass via Registry Class Hijack",
        mitre_technique="T1548.002",
        description=(
            "Stage 1: Sysmon 13 - HKCU\\Software\\Classes registry value set. "
            "Stage 2: Sysmon 1 - Auto-elevated binary spawned (eventvwr, sdclt, wsreset…). "
            "Stage 3: Sysmon 1 - High-integrity child process spawned."
        ),
        required_stages=[
            {
                "event_id": "13",
                "conditions": {
                    "TargetObject__contains": "HKCU\\Software\\Classes",
                },
            },
            {
                "event_id": "1",
                "conditions": {
                    "Image__endswith_any": [
                        "eventvwr.exe", "sdclt.exe", "wsreset.exe",
                        "fodhelper.exe", "perfmon.exe", "CompMgmtLauncher.exe",
                        "changepk.exe",
                    ],
                },
                "follows_within_seconds": 10,
            },
            {
                "event_id": "1",
                "conditions": {"IntegrityLevel": "High"},
                "follows_within_seconds": 10,
            },
        ],
        time_window_seconds=30,
        severity="HIGH",
    ),

    # ── PRIVESC-004 ─────────────────────────────────────────────────────────
    CorrelationChain(
        chain_id="PRIVESC-004",
        attack_name="noPac / SAMAccountName Spoofing",
        mitre_technique="T1558",
        description=(
            "Stage 1: EventID 4781 - Computer account renamed to match DC name. "
            "Stage 2: EventID 4768 - TGT requested for the renamed account. "
            "Stage 3: EventID 4781 - Account renamed back. "
            "Indicates noPac CVE-2021-42278/42287 exploitation."
        ),
        required_stages=[
            {
                "event_id": "4781",
                "conditions": {"OldTargetUserName__endswith": "$"},
            },
            {
                "event_id": "4768",
                "follows_within_seconds": 60,
            },
            {
                "event_id": "4781",
                "follows_within_seconds": 120,
            },
        ],
        time_window_seconds=180,
        severity="CRITICAL",
    ),

    # ── PRIVESC-005 ─────────────────────────────────────────────────────────
    CorrelationChain(
        chain_id="PRIVESC-005",
        attack_name="SpoolFool / PrintNightmare DLL Injection",
        mitre_technique="T1574.010",
        description=(
            "Stage 1: Sysmon 11 - spoolsv.exe creates a .dll file. "
            "Stage 2: Sysmon 7  - spoolsv.exe loads the newly created DLL. "
            "Stage 3: Sysmon 1  - Unexpected child process spawned by spoolsv.exe."
        ),
        required_stages=[
            {
                "event_id": "11",
                "conditions": {
                    "Image__endswith":          "spoolsv.exe",
                    "TargetFilename__endswith": ".dll",
                },
            },
            {
                "event_id": "7",
                "conditions": {"Image__endswith": "spoolsv.exe"},
                "follows_within_seconds": 30,
            },
            {
                "event_id": "1",
                "conditions": {"ParentImage__endswith": "spoolsv.exe"},
                "follows_within_seconds": 30,
            },
        ],
        time_window_seconds=60,
        severity="CRITICAL",
    ),

    # ── PRIVESC-006 ─────────────────────────────────────────────────────────
    CorrelationChain(
        chain_id="PRIVESC-006",
        attack_name="SeImpersonate via Named Pipe (EfsPotato/Generic)",
        mitre_technique="T1134.001",
        description=(
            "Stage 1: Sysmon 17 - Named pipe created with a well-known IPC name. "
            "Stage 2: Sysmon 18 - Pipe connection (SYSTEM service connects). "
            "Stage 3: Sysmon 1  - New process spawned as SYSTEM."
        ),
        required_stages=[
            {
                "event_id": "17",
                "conditions": {
                    "PipeName__contains_any": [
                        "srvsvc", "efslpc", "lsarpc", "spoolss", "epmapper",
                    ],
                },
            },
            {
                "event_id": "18",
                "follows_within_seconds": 10,
            },
            {
                "event_id": "1",
                "conditions": {"User__contains": "SYSTEM"},
                "follows_within_seconds": 30,
            },
        ],
        time_window_seconds=60,
        severity="CRITICAL",
    ),

    # ── PRIVESC-007 ─────────────────────────────────────────────────────────
    CorrelationChain(
        chain_id="PRIVESC-007",
        attack_name="NTLM Self-Relay (RogueWinRM / NTLM2SelfRelay)",
        mitre_technique="T1557.001",
        description=(
            "Stage 1: EventID 4624 - NTLM logon from 127.0.0.1 (LogonType 3 or 9). "
            "Stage 2: EventID 4688 - SYSTEM-level cmd/powershell spawned within 30 s."
        ),
        required_stages=[
            {
                "event_id": "4624",
                "conditions": {
                    "AuthenticationPackageName": "NTLM",
                    "IpAddress":                 "127.0.0.1",
                },
            },
            {
                "event_id": "4688",
                "conditions": {
                    "SubjectUserName":           "SYSTEM",
                    "NewProcessName__endswith_any": ["cmd.exe", "powershell.exe"],
                },
                "follows_within_seconds": 30,
            },
        ],
        time_window_seconds=30,
        severity="CRITICAL",
    ),

    # ── PRIVESC-008 ─────────────────────────────────────────────────────────
    CorrelationChain(
        chain_id="PRIVESC-008",
        attack_name="Unquoted Service Path Execution",
        mitre_technique="T1574.009",
        description=(
            "Stage 1: Sysmon 11 - Executable created in an unquoted service path dir. "
            "Stage 2: EventID 7045 - Service starts and executes the planted binary."
        ),
        required_stages=[
            {
                "event_id": "11",
                "conditions": {
                    "TargetFilename__contains":  "C:\\Program Files",
                    "TargetFilename__endswith":  ".exe",
                },
            },
            {
                "event_id": "7045",
                "follows_within_seconds": 300,
            },
        ],
        time_window_seconds=300,
        severity="HIGH",
    ),

    # ── PRIVESC-009 ─────────────────────────────────────────────────────────
    CorrelationChain(
        chain_id="PRIVESC-009",
        attack_name="KrbRelayUp RBCD Kerberos Relay",
        mitre_technique="T1558",
        description=(
            "Stage 1: EventID 4624 - Kerberos logon from localhost LogonType=9 (S4U2Self). "
            "Stage 2: EventID 4688 - SYSTEM process spawned on the same host."
        ),
        required_stages=[
            {
                "event_id": "4624",
                "conditions": {
                    "AuthenticationPackageName": "Kerberos",
                    "IpAddress":                 "127.0.0.1",
                    "LogonType":                 "9",
                },
            },
            {
                "event_id": "4688",
                "conditions": {"SubjectUserName": "SYSTEM"},
                "follows_within_seconds": 60,
            },
        ],
        time_window_seconds=60,
        severity="CRITICAL",
    ),

    # ── PRIVESC-010 ─────────────────────────────────────────────────────────
    CorrelationChain(
        chain_id="PRIVESC-010",
        attack_name="UACME DLL Hijack - Auto-Elevated Binary",
        mitre_technique="T1548.002",
        description=(
            "Stage 1: Sysmon 11 - DLL written to temp/user-writable path. "
            "Stage 2: Sysmon 7  - Auto-elevated binary loads the DLL "
            "(sysprep, migwiz, cliconfg, mcx2prov, SndVol…). "
            "Leads to a high-integrity process."
        ),
        required_stages=[
            {
                "event_id": "11",
                "conditions": {
                    "TargetFilename__endswith_any": [
                        "CRYPTBASE.dll", "CRYPTSP.dll", "ntwdblib.dll",
                        "AUTHZ.dll", "ActionQueue.dll",
                    ],
                },
            },
            {
                "event_id": "7",
                "conditions": {
                    "Image__endswith_any": [
                        "sysprep.exe", "migwiz.exe", "cliconfg.exe",
                        "mcx2prov.exe", "SndVol.exe",
                    ],
                },
                "follows_within_seconds": 15,
            },
        ],
        time_window_seconds=30,
        severity="HIGH",
    ),
]


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------

_RECOMMENDATIONS: Dict[str, str] = {
    "PRIVESC-001": (
        "Isolate host immediately. Investigate DCOM/COM server abuse. "
        "Check for new SYSTEM processes created after the anonymous logon."
    ),
    "PRIVESC-002": (
        "Investigate w3wp.exe process tree. Check for uploaded files on the web server. "
        "Isolate IIS host and audit application code for web shells."
    ),
    "PRIVESC-003": (
        "Audit HKCU\\Software\\Classes modifications. "
        "Review history of auto-elevated binary execution. "
        "Consider restricting HKCU write access for high-risk binaries."
    ),
    "PRIVESC-004": (
        "Reset the affected machine account password. "
        "Audit DC sAMAccountName changes (Event 4781). "
        "Rotate Kerberos keys (krbtgt × 2) to invalidate forged tickets."
    ),
    "PRIVESC-005": (
        "Stop Print Spooler service on affected hosts. "
        "Apply PrintNightmare/SpoolFool patches. "
        "Audit spoolsv.exe DLL load events and block unsigned driver installs."
    ),
    "PRIVESC-006": (
        "Block named pipe impersonation at the system level. "
        "Audit service accounts with SeImpersonatePrivilege. "
        "Consider removing SeImpersonatePrivilege from IIS/SQL service accounts."
    ),
    "PRIVESC-007": (
        "Block local NTLM authentication to loopback addresses. "
        "Enforce Extended Protection for Authentication (EPA) on WinRM/IIS. "
        "Enable SMB signing to prevent relay."
    ),
    "PRIVESC-008": (
        "Audit all service binary paths for unquoted paths. "
        "Remove write access from service path directories for non-admin users. "
        "Use sc qc to enumerate and remediate unquoted paths."
    ),
    "PRIVESC-009": (
        "Audit Kerberos RBCD delegations (msDS-AllowedToActOnBehalfOfOtherIdentity). "
        "Remove unexpected RBCD entries. "
        "Enable Protected Users security group for privileged accounts."
    ),
    "PRIVESC-010": (
        "Audit DLL loads in auto-elevated binaries. "
        "Restrict write access to directories searched by these binaries. "
        "Enable DLL safe-search mode and binary-signed DLL enforcement."
    ),
}


# ---------------------------------------------------------------------------
# PrivEscCorrelationEngine
# ---------------------------------------------------------------------------

class PrivEscCorrelationEngine:
    """
    Evaluates PRIVESC_CHAINS against an ordered list of LogRecord objects.

    For each chain, the engine steps through required_stages in order, searching
    forward from the current position.  Each stage must be found within
    ``follows_within_seconds`` of the previous one.  If all stages match, an
    Alert is emitted.
    """

    def evaluate(
        self,
        records: List[LogRecord],
        chain_list: Optional[List[CorrelationChain]] = None,
    ) -> List[Alert]:
        """Run all chains against *records* and return matched Alert objects."""
        chains = chain_list if chain_list is not None else PRIVESC_CHAINS
        alerts: List[Alert] = []
        for chain in chains:
            matched = self._evaluate_chain(records, chain)
            if matched:
                alerts.append(self._build_alert(chain, matched))
        return alerts

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evaluate_chain(
        self,
        records: List[LogRecord],
        chain: CorrelationChain,
    ) -> Optional[List[LogRecord]]:
        """
        Walk through required_stages in order.  Returns the list of matched
        LogRecord objects if every stage is satisfied, else None.
        """
        matched_records: List[LogRecord] = []
        search_from: int = 0

        for stage in chain.required_stages:
            found: Optional[LogRecord] = None

            window_start: Optional[datetime] = (
                matched_records[-1].timestamp
                if matched_records and matched_records[-1].timestamp
                else None
            )
            max_delta = stage.get("follows_within_seconds", chain.time_window_seconds)

            for i, record in enumerate(records[search_from:], start=search_from):
                # Filter by event_id first (cheap string compare)
                if record.event_id != stage["event_id"]:
                    continue

                # Check time window relative to previous stage
                if window_start and record.timestamp:
                    delta = (record.timestamp - window_start).total_seconds()
                    if delta < 0 or delta > max_delta:
                        continue

                # Check all field conditions
                if self._match_conditions(record, stage.get("conditions", {})):
                    found = record
                    search_from = i + 1
                    break

            if found is None:
                return None
            matched_records.append(found)

        return matched_records

    def _match_conditions(
        self,
        record: LogRecord,
        conditions: Dict[str, Any],
    ) -> bool:
        """
        Evaluate all key/value conditions against a LogRecord.

        Key format: ``<field_name>`` (eq) or ``<field_name>__<op>``.
        Operators: eq, contains, endswith, endswith_any, contains_any.
        Field resolution: record.extra first, then LogRecord attributes.
        """
        for key, value in conditions.items():
            parts = key.split("__")
            field_name = parts[0]
            op = parts[1] if len(parts) > 1 else "eq"

            # Resolve field value: extra dict takes priority, then dataclass attrs
            rec_val = str(
                record.extra.get(field_name)
                or getattr(record, field_name, None)
                or ""
            )

            if op == "eq":
                if rec_val != value:
                    return False
            elif op == "contains":
                if value.lower() not in rec_val.lower():
                    return False
            elif op == "endswith":
                if not rec_val.lower().endswith(value.lower()):
                    return False
            elif op == "endswith_any":
                if not any(rec_val.lower().endswith(v.lower()) for v in value):
                    return False
            elif op == "contains_any":
                if not any(v.lower() in rec_val.lower() for v in value):
                    return False
            # Unknown ops are treated as pass-through
        return True

    def _build_alert(
        self,
        chain: CorrelationChain,
        matched_records: List[LogRecord],
    ) -> Alert:
        """Construct an Alert from a successfully matched correlation chain."""
        first = matched_records[0]
        return Alert(
            rule_name=chain.attack_name,
            rule_type="CORRELATION",
            severity=chain.severity,
            confidence="HIGH",
            description=chain.description,
            mitre_tactic="Privilege Escalation",
            mitre_technique=chain.mitre_technique,
            matched_line="\n".join(r.raw_line[:200] for r in matched_records),
            line_number=first.line_number,
            timestamp=first.timestamp,
            iocs=self._extract_iocs(matched_records),
            recommended_action=_RECOMMENDATIONS.get(
                chain.chain_id,
                "Investigate immediately and escalate to the IR team.",
            ),
            log_type="windows_event",
        )

    def _extract_iocs(self, records: List[LogRecord]) -> List[str]:
        """Collect unique source IPs, usernames, process names, and hostnames."""
        iocs: set = set()
        for r in records:
            for val in (r.source_ip, r.username, r.process_name, r.hostname):
                if val:
                    iocs.add(val)
        return sorted(iocs)
