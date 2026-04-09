"""
analytics/timeline.py — Attack Timeline Builder

Reconstructs a chronological sequence of events across all analysed log
sources. Groups related events by shared pivots (src_ip, username, hostname)
and maps each event to a Cyber Kill Chain stage and MITRE ATT&CK technique.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple, Callable

from core.models import LogRecord, StatResult

# ---------------------------------------------------------------------------
# Kill Chain stage definitions
# ---------------------------------------------------------------------------
# 13 canonical stages for completeness percentage calculation
ALL_STAGES: List[str] = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "C2",
    "Exfiltration",
    "Impact",
]

# ---------------------------------------------------------------------------
# Scanner / attack-tool user-agent patterns
# ---------------------------------------------------------------------------
_SCANNER_UA_PATTERNS = re.compile(
    r"(?i)sqlmap|nikto|nmap|masscan|nessus|openvas|burpsuite|"
    r"zgrab|gobuster|dirbuster|wfuzz|hydra|medusa|metasploit|"
    r"nuclei|acunetix|w3af|zap|whatweb|python-requests|go-http|"
    r"curl/|wget/|libwww|sipscan|scanner|crawler|spider|bot",
)

# ---------------------------------------------------------------------------
# Command patterns indicating execution/privilege escalation
# ---------------------------------------------------------------------------
_EXEC_PATTERNS = re.compile(
    r"(?i)bash\s+-[ic]|/bin/sh|/bin/bash|cmd\.exe|powershell|"
    r"python\s+-c|perl\s+-e|ruby\s+-e|php\s+-r|nc\s+-[el]|"
    r"netcat|mkfifo|/dev/tcp|bash -i|sh -i",
)
_PRIV_ESC_PATTERNS = re.compile(
    r"(?i)sudo\s+bash|sudo\s+su|sudo\s+-s|sudo\s+-i|"
    r"chmod\s+[47][0-9][0-9]\s+/|chown\s+root|"
    r"seDebugPrivilege|impersonat|token|"
    r"useradd|adduser|net\s+user\s+/add|"
    r"setuid|suid|set\s*/p\s+=%",
)
_PERSISTENCE_PATTERNS = re.compile(
    r"(?i)crontab|/etc/cron|at\.allow|/etc/init\.d|"
    r"systemctl\s+enable|rc\.local|"
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|"
    r"schtasks|taskschd|New-ScheduledTask|"
    r"sc\s+create|services\.msc|"
    r"~/.bashrc|~/.profile|~/.bash_profile",
)
_DEFENSE_EVASION = re.compile(
    r"(?i)wevtutil\s+cl|Clear-EventLog|clearev|"
    r"certutil\s+-decode|"
    r"timestomp|touch\s+-t|"
    r"net\s+stop|sc\s+stop|taskkill|pkill|"
    r"disable.*antivirus|Set-MpPreference|"
    r"IEX|invoke-expression|FromBase64String|"
    r"regsvr32|rundll32|mshta|wscript|cscript",
)
_CREDENTIAL_PATTERNS = re.compile(
    r"(?i)mimikatz|sekurlsa|lsass\.exe|sam\.hive|ntds\.dit|"
    r"vssadmin|shadow\s+copy|"
    r"/etc/shadow|/etc/passwd|"
    r"crackmapexec|impacket|secretsdump|"
    r"procdump.*lsass|task.*lsass",
)
_DISCOVERY_PATTERNS = re.compile(
    r"(?i)net\s+user\s*/domain|net\s+group|"
    r"whoami\s*/all|id\s*;|"
    r"nslookup|dig\s+|host\s+|"
    r"arp\s+-a|ipconfig\s*/all|ifconfig|"
    r"netstat\s+-[an]|ss\s+-[an]|"
    r"Get-ADUser|Get-ADGroup|enum4linux|ldapsearch",
)
_LATERAL_PATTERNS = re.compile(
    r"(?i)psexec|wmiexec|dcom|"
    r"xfreerdp|rdesktop|mstsc|"
    r"ssh\s+-[lp]|scp\s+-|rsync|"
    r"pass-the-hash|pth-|"
    r"Invoke-WMI|WMI.*exec|"
    r"net\s+use\s+\\\\",
)
_COLLECTION_PATTERNS = re.compile(
    r"(?i)tar\s+-c|zip\s+-r|7z\s+a|rar\s+a|"
    r"certutil.*-encode|"
    r"copy.*\\\\.+\\|xcopy|robocopy|"
    r"clip\.exe|xclip|xdotool",
)
_WEBSHELL_PATTERNS = re.compile(
    r"(?i)(?:GET|POST)\s+/.+\.php\?(?:cmd|exec|shell|c=|run=|pass=|file=|id=)|"
    r"shell\.php|cmd\.php|c99\.php|r57\.php|b374k|weevely|"
    r"/uploads?/.*\.php|/tmp/.*\.php",
)
_EXFIL_PATTERNS = re.compile(
    r"(?i)paste\.ee|pastebin\.com|"
    r"drive\.google|dropbox\.com|"
    r"mega\.nz|transfer\.sh|"
    r"curl\s+-d\s+@|wget\s+--post-file|"
    r"ftp\s+-u|sftp\s+-b",
)
_C2_DOMAINS = re.compile(
    r"(?i)\.top/|\.xyz/|\.bit/|\.cc/|\.io/update|"
    r"update-cdn\.|cdn-update\.|check-in\.|"
    r"beacon\.|c2\.|command\.|\bc&c\b",
)


# ---------------------------------------------------------------------------
# Kill chain rule set
# Format: (stage, mitre_technique, test_fn)
# Rules are tested in order; first match wins.
# ---------------------------------------------------------------------------

KillChainRule = Tuple[str, str, Callable[[LogRecord], bool]]

def _is_scanner(r: LogRecord) -> bool:
    ua = r.user_agent or ""
    return bool(_SCANNER_UA_PATTERNS.search(ua))

def _is_web_exploit(r: LogRecord) -> bool:
    if r.status_code == 500:
        line = (r.uri or "") + (r.raw_line or "")
        return bool(re.search(r"(?i)(?:'|--|UNION|SELECT|<script|onerror=|../|%2e%2e)", line))
    return False

def _is_brute_force(r: LogRecord) -> bool:
    act = (r.action or "").lower()
    return bool(
        r.status_code in (401, 403) or
        re.search(r"(?i)fail|invalid|incorrect|denied", r.raw_line or "") and
        "password" in (r.raw_line or "").lower()
    )

def _is_priv_esc(r: LogRecord) -> bool:
    line = (r.command_line or "") + (r.raw_line or "")
    return bool(_PRIV_ESC_PATTERNS.search(line))

def _is_exec(r: LogRecord) -> bool:
    line = (r.command_line or "") + (r.raw_line or "")
    return bool(_EXEC_PATTERNS.search(line))

def _is_webshell(r: LogRecord) -> bool:
    line = (r.uri or "") + (r.raw_line or "")
    return bool(_WEBSHELL_PATTERNS.search(line))

def _is_persistence(r: LogRecord) -> bool:
    line = (r.command_line or "") + (r.raw_line or "")
    return bool(_PERSISTENCE_PATTERNS.search(line))

def _is_defense_evasion(r: LogRecord) -> bool:
    line = (r.command_line or "") + (r.raw_line or "")
    return bool(_DEFENSE_EVASION.search(line))

def _is_credential(r: LogRecord) -> bool:
    line = (r.command_line or "") + (r.raw_line or "")
    return bool(_CREDENTIAL_PATTERNS.search(line))

def _is_discovery(r: LogRecord) -> bool:
    line = (r.command_line or "") + (r.raw_line or "")
    return bool(_DISCOVERY_PATTERNS.search(line))

def _is_lateral(r: LogRecord) -> bool:
    line = (r.command_line or "") + (r.raw_line or "")
    return bool(_LATERAL_PATTERNS.search(line))

def _is_collection(r: LogRecord) -> bool:
    line = (r.command_line or "") + (r.raw_line or "")
    return bool(_COLLECTION_PATTERNS.search(line))

def _is_c2(r: LogRecord) -> bool:
    uri = (r.uri or "").lower()
    return bool(_C2_DOMAINS.search(uri))

def _is_exfil(r: LogRecord) -> bool:
    line = (r.uri or "") + (r.raw_line or "")
    if bool(_EXFIL_PATTERNS.search(line)):
        return True
    # Large outbound POST
    if (r.action or "").upper() == "POST" and (r.bytes_transferred or 0) > 1_000_000:
        return True
    return False

def _is_impact(r: LogRecord) -> bool:
    line = (r.command_line or "") + (r.raw_line or "").lower()
    return bool(re.search(
        r"(?i)ransom|encrypt|\.locked|\.crypt|vssadmin.*delete|"
        r"bcdedit.*recoveryenabled|wbadmin.*delete|mkfs\.|dd\s+if=|shred\s",
        line,
    ))

def _is_port_scan(r: LogRecord) -> bool:
    # Many different dest ports from same source in a short time is scored in beaconing
    # Here flag SYN-style resets or explicit port-scan UA patterns
    line = r.raw_line or ""
    return bool(re.search(r"(?i)SYN_SENT|RST|portscan|port.scan|scan", line))

def _is_auth_success_after_failure(r: LogRecord) -> bool:
    act = (r.action or "").lower()
    return bool(re.search(r"(?i)accepted|success|logged in", act))

# Ordered rule list: first match wins
_KC_RULES: List[KillChainRule] = [
    # Reconnaissance
    ("Reconnaissance",       "T1595.002", _is_scanner),
    ("Reconnaissance",       "T1046",     _is_port_scan),
    # Initial Access
    ("Initial Access",       "T1190",     _is_web_exploit),
    ("Initial Access",       "T1110.001", _is_brute_force),
    ("Initial Access",       "T1078",     _is_auth_success_after_failure),
    # Execution
    ("Execution",            "T1505.003", _is_webshell),
    ("Execution",            "T1059",     _is_exec),
    # Persistence
    ("Persistence",          "T1053",     _is_persistence),
    # Privilege Escalation
    ("Privilege Escalation", "T1548.003", _is_priv_esc),
    # Defense Evasion
    ("Defense Evasion",      "T1070",     _is_defense_evasion),
    # Credential Access
    ("Credential Access",    "T1003",     _is_credential),
    # Discovery
    ("Discovery",            "T1087",     _is_discovery),
    # Lateral Movement
    ("Lateral Movement",     "T1021",     _is_lateral),
    # Collection
    ("Collection",           "T1560",     _is_collection),
    # C2
    ("C2",                   "T1071.001", _is_c2),
    # Exfiltration
    ("Exfiltration",         "T1048.003", _is_exfil),
    # Impact
    ("Impact",               "T1486",     _is_impact),
]

def _assign_kill_chain(r: LogRecord) -> Tuple[str, str]:
    """Return (kill_chain_stage, mitre_technique). Falls back to 'Other'."""
    for stage, technique, test in _KC_RULES:
        try:
            if test(r):
                return stage, technique
        except Exception:
            pass
    return "Other", "T0000"


def _severity_for_stage(stage: str) -> str:
    _sev = {
        "Reconnaissance":       "LOW",
        "Initial Access":       "HIGH",
        "Execution":            "HIGH",
        "Persistence":          "HIGH",
        "Privilege Escalation": "CRITICAL",
        "Defense Evasion":      "HIGH",
        "Credential Access":    "CRITICAL",
        "Discovery":            "MEDIUM",
        "Lateral Movement":     "CRITICAL",
        "Collection":           "HIGH",
        "C2":                   "CRITICAL",
        "Exfiltration":         "CRITICAL",
        "Impact":               "CRITICAL",
    }
    return _sev.get(stage, "INFO")


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

class TimelineBuilder:
    """
    Accepts a dict of {log_type: List[LogRecord]} (or a single list).
    Correlates events across all sources by shared pivots and builds
    a global kill-chain annotated timeline with attack chains.
    """

    DEFAULT_CONFIG: Dict[str, Any] = {
        "dedup_window_seconds":        2,
        "pivot_fields":                ["source_ip", "username", "hostname"],
        "min_events_for_chain":        3,
        "time_gap_threshold_minutes":  30,
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.cfg = {**self.DEFAULT_CONFIG, **(config or {})}

    # ------------------------------------------------------------------
    def run(
        self,
        all_sources: Dict[str, List[LogRecord]],
    ) -> StatResult:
        now = datetime.now(timezone.utc)

        if not all_sources:
            return self._empty(now)

        # Flatten all records with their source tag
        flat: List[Tuple[LogRecord, str]] = []
        for lt, recs in all_sources.items():
            for r in recs:
                flat.append((r, lt))

        if not flat:
            return self._empty(now)

        # Sort by timestamp; records without timestamp go last
        timed = [(r, lt) for r, lt in flat if r.timestamp is not None]
        untimed = [(r, lt) for r, lt in flat if r.timestamp is None]
        timed.sort(key=lambda x: x[0].timestamp)  # type: ignore[union-attr]
        sorted_flat = timed + untimed

        # Deduplication within dedup_window_seconds
        dedup_secs = self.cfg["dedup_window_seconds"]
        sorted_flat = self._dedup(sorted_flat, dedup_secs)

        # Build global timeline
        global_timeline: List[Dict[str, Any]] = []
        for seq, (r, lt) in enumerate(sorted_flat, 1):
            stage, technique = _assign_kill_chain(r)
            pivot_vals: Dict[str, str] = {}
            for pf in self.cfg["pivot_fields"]:
                v = getattr(r, pf, None)
                if v:
                    pivot_vals[pf] = str(v)

            entry: Dict[str, Any] = {
                "seq":             seq,
                "timestamp":       r.timestamp.isoformat() if r.timestamp else "",
                "log_type":        lt,
                "kill_chain_stage": stage,
                "mitre_technique": technique,
                "pivot_values":    pivot_vals,
                "description":     self._describe(r, stage),
                "severity":        _severity_for_stage(stage),
                "raw_line":        r.raw_line[:200],
                "line_number":     r.line_number,
            }
            global_timeline.append(entry)

        # Build attack chains
        attack_chains = self._build_chains(global_timeline, sorted_flat)

        # Summary
        log_sources = sorted(set(lt for _, lt in sorted_flat))
        earliest = global_timeline[0]["timestamp"] if global_timeline else ""
        latest   = global_timeline[-1]["timestamp"] if global_timeline else ""
        if earliest and latest:
            try:
                e = datetime.fromisoformat(earliest.replace("Z", "+00:00"))
                l = datetime.fromisoformat(latest.replace("Z", "+00:00"))
                span_hrs = (l - e).total_seconds() / 3600
            except (ValueError, TypeError):
                span_hrs = 0.0
        else:
            span_hrs = 0.0

        most_complete = (
            max(attack_chains, key=lambda c: c["kill_chain_completeness_pct"])
            ["pivot_value"]
            if attack_chains else ""
        )

        data: Dict[str, Any] = {
            "global_timeline":  global_timeline[:500],    # cap for serialisation
            "attack_chains":    attack_chains,
            "summary": {
                "total_events_correlated":    len(global_timeline),
                "attack_chains_identified":   len(attack_chains),
                "most_complete_chain_pivot":  most_complete,
                "log_sources_analyzed":       log_sources,
                "earliest_event":             earliest,
                "latest_event":               latest,
                "total_timespan_hours":       round(span_hrs, 2),
            },
        }

        n_chains = len(attack_chains)
        max_completeness = (
            max(c["kill_chain_completeness_pct"] for c in attack_chains)
            if attack_chains else 0.0
        )

        if max_completeness >= 50:
            severity = "CRITICAL"
        elif n_chains >= 3:
            severity = "HIGH"
        elif n_chains >= 1:
            severity = "MEDIUM"
        elif global_timeline:
            severity = "LOW"
        else:
            severity = "INFO"

        desc = (
            f"{len(global_timeline):,} event(s) correlated across "
            f"{len(log_sources)} source(s). "
            f"{n_chains} attack chain(s) identified."
            + (f" Most complete chain: {most_complete} ({max_completeness:.0f}%)." if most_complete else "")
        )

        return StatResult(
            module="timeline",
            log_type=", ".join(log_sources),
            title="Attack Timeline",
            severity=severity,
            description=desc,
            data=data,
            anomalies=[
                {
                    "chain_id":     c["chain_id"],
                    "pivot_value":  c["pivot_value"],
                    "stages":       c["stages_observed"],
                    "completeness": c["kill_chain_completeness_pct"],
                    "duration_hrs": c["duration_hours"],
                }
                for c in attack_chains[:10]
            ],
            generated_at=now,
        )

    # ------------------------------------------------------------------
    def _dedup(
        self,
        items: List[Tuple[LogRecord, str]],
        window_secs: int,
    ) -> List[Tuple[LogRecord, str]]:
        """
        Remove near-duplicate events within dedup_window_seconds that have the
        same (log_type, source_ip, event_id) tuple.
        """
        seen: Dict[str, datetime] = {}
        out: List[Tuple[LogRecord, str]] = []
        for r, lt in items:
            key = f"{lt}:{r.source_ip}:{r.event_id}:{r.username}"
            ts = r.timestamp
            if ts is None:
                out.append((r, lt))
                continue
            last = seen.get(key)
            if last is None or (ts - last).total_seconds() > window_secs:
                seen[key] = ts
                out.append((r, lt))
        return out

    # ------------------------------------------------------------------
    def _build_chains(
        self,
        timeline: List[Dict[str, Any]],
        sorted_flat: List[Tuple[LogRecord, str]],
    ) -> List[Dict[str, Any]]:
        """
        Group timeline events by shared pivot values and build attack chains
        for pivot groups with >= min_events_for_chain events.
        """
        pivot_fields = self.cfg["pivot_fields"]
        min_events = self.cfg["min_events_for_chain"]

        # Group timeline entry indices by (pivot_field, pivot_value)
        groups: Dict[Tuple[str, str], List[int]] = defaultdict(list)
        for i, entry in enumerate(timeline):
            for pf, pv in entry.get("pivot_values", {}).items():
                if pv and pf in pivot_fields:
                    groups[(pf, pv)].append(i)

        chains: List[Dict[str, Any]] = []
        seen_chains: set = set()

        for (pf, pv), indices in groups.items():
            if len(indices) < min_events:
                continue

            # Deduplicate chains that cover the same set of events
            chain_key = frozenset(indices[:50])
            if chain_key in seen_chains:
                continue
            seen_chains.add(chain_key)

            chain_events = [timeline[i] for i in indices]
            stages_seen = list(dict.fromkeys(
                e["kill_chain_stage"] for e in chain_events
                if e["kill_chain_stage"] != "Other"
            ))
            completeness = len(set(stages_seen) & set(ALL_STAGES)) / len(ALL_STAGES) * 100

            timestamps = [e["timestamp"] for e in chain_events if e.get("timestamp")]
            first_ts = timestamps[0] if timestamps else ""
            last_ts  = timestamps[-1] if timestamps else ""
            duration_hrs = 0.0
            if first_ts and last_ts:
                try:
                    d0 = datetime.fromisoformat(first_ts.replace("Z", "+00:00"))
                    d1 = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
                    duration_hrs = (d1 - d0).total_seconds() / 3600
                except (ValueError, TypeError):
                    pass

            log_sources = list(dict.fromkeys(e["log_type"] for e in chain_events))
            chain_id = "CHAIN-" + hashlib.sha1(
                f"{pf}:{pv}:{first_ts}".encode()
            ).hexdigest()[:6].upper()

            chains.append({
                "chain_id":                  chain_id,
                "pivot_type":                pf,
                "pivot_value":               pv,
                "events_count":              len(chain_events),
                "stages_observed":           stages_seen,
                "kill_chain_completeness_pct": round(completeness, 1),
                "first_event":               first_ts,
                "last_event":                last_ts,
                "duration_hours":            round(duration_hrs, 2),
                "log_sources_involved":      log_sources,
                "events":                    chain_events[:50],   # cap
            })

        # Sort by kill_chain_completeness_pct descending
        chains.sort(key=lambda c: c["kill_chain_completeness_pct"], reverse=True)
        return chains

    # ------------------------------------------------------------------
    def _describe(self, r: LogRecord, stage: str) -> str:
        """Generate a human-readable one-liner for the timeline entry."""
        parts: List[str] = []
        if r.source_ip:
            parts.append(f"src={r.source_ip}")
        if r.username:
            parts.append(f"user={r.username}")
        if r.uri:
            parts.append(f"uri={r.uri[:80]}")
        if r.action:
            parts.append(f"action={r.action}")
        if r.status_code:
            parts.append(f"status={r.status_code}")
        if r.bytes_transferred and r.bytes_transferred > 0:
            parts.append(f"bytes={_fmt_bytes(r.bytes_transferred)}")
        if r.command_line:
            parts.append(f"cmd={r.command_line[:80]}")
        base = " | ".join(parts) if parts else r.raw_line[:120]
        return f"[{stage}] {base}"

    def _empty(self, now: datetime) -> StatResult:
        return StatResult(
            module="timeline",
            log_type="unknown",
            title="Attack Timeline",
            severity="INFO",
            description="No records available for timeline construction.",
            data={
                "global_timeline": [],
                "attack_chains": [],
                "summary": {
                    "total_events_correlated": 0,
                    "attack_chains_identified": 0,
                    "most_complete_chain_pivot": "",
                    "log_sources_analyzed": [],
                    "earliest_event": "",
                    "latest_event": "",
                    "total_timespan_hours": 0.0,
                },
            },
            anomalies=[],
            generated_at=now,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n //= 1024
    return f"{n}PB"
