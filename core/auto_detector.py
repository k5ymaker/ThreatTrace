"""
core/auto_detector.py — ThreatTrace log-type auto-detection engine.

Fingerprints an unknown log file using a multi-phase approach:

  Phase 1 — Extension shortcut   (.evtx → windows_evtx immediately)
  Phase 2 — Signature matching   (~90 weighted regex/keyword/json_key patterns)
  Phase 3 — Structural analysis  (JSON-lines, XML, CEF, syslog, key=value, W3C…)
  Phase 4 — Semantic analysis    (security keyword domains when nothing else fires)

Confidence tiers:
  CONFIRMED  ≥ 80 %   — signature or structural match is definitive
  LIKELY     50–79%   — strong structural + semantic signals
  POSSIBLE   20–49%   — weak signals, best-effort guess
  FALLBACK    < 20%   — structural guess only, rules chosen conservatively

Returns:
    {
        "log_type":   str,     # e.g. "apache", "auth_log", "generic_kv" …
        "confidence": float,   # 0.0 – 1.0
        "tier":       str,     # "CONFIRMED" | "LIKELY" | "POSSIBLE" | "FALLBACK"
        "structure":  str,     # detected format: "json_lines", "syslog_rfc3164" …
        "signals":    list     # human-readable evidence strings
    }
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console

console = Console()

# ---------------------------------------------------------------------------
# Magic bytes / extension sentinels
# ---------------------------------------------------------------------------
EVTX_MAGIC = b"ElfFile\x00"

# ---------------------------------------------------------------------------
# Signature definitions
# (log_type, weight, pattern_type, pattern)
# ---------------------------------------------------------------------------
_SIGNATURES: List[Tuple[str, float, str, Any]] = [
    # ---- Apache / Nginx (CLF / combined log format) ----------------------
    (
        "apache", 0.9, "regex",
        re.compile(
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\S+\s+\S+\s+\[.+?\]'
            r'\s+"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+'
        ),
    ),
    ("nginx", 0.6, "keyword", "upstream"),
    ("nginx", 0.6, "keyword", "upstream_addr"),
    ("nginx", 0.5, "keyword", "ngx_"),
    (
        "nginx", 0.8, "regex",
        re.compile(
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\S+\s+\S+\s+\[.+?\]'
            r'\s+"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+'
        ),
    ),
    # ---- IIS ---------------------------------------------------------------
    ("iis", 1.0, "keyword", "#Software: Microsoft Internet Information Services"),
    ("iis", 0.8, "keyword", "#Fields:"),
    ("iis", 0.7, "regex",   re.compile(r"^#Software:\s+Microsoft")),
    # ---- Sysmon (XML event log) -------------------------------------------
    ("sysmon", 1.0, "keyword", "<Channel>Microsoft-Windows-Sysmon</Channel>"),
    ("sysmon", 0.8, "keyword", "Microsoft-Windows-Sysmon/Operational"),
    ("sysmon", 0.6, "keyword", "EventID>1<"),
    ("sysmon", 0.6, "keyword", "<EventID>"),
    # ---- Syslog (generic) -------------------------------------------------
    (
        "syslog", 0.9, "regex",
        re.compile(r"^\w{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\w+[\[:]"),
    ),
    # ---- Auth log -----------------------------------------------------------
    ("auth_log", 0.9, "keyword", "sshd["),
    ("auth_log", 0.8, "keyword", "sudo:"),
    ("auth_log", 0.8, "keyword", "pam_unix("),
    ("auth_log", 0.7, "keyword", "login["),
    # ---- Auditd -----------------------------------------------------------
    ("auditd", 1.0, "keyword", "type=SYSCALL"),
    ("auditd", 1.0, "keyword", "type=EXECVE"),
    ("auditd", 0.8, "regex",   re.compile(r"^type=\w+\s+msg=audit\(")),
    # ---- Cisco ASA --------------------------------------------------------
    ("cisco_asa", 1.0, "keyword", "%ASA-"),
    ("cisco_asa", 1.0, "keyword", "%PIX-"),
    ("cisco_asa", 0.7, "regex",   re.compile(r"%(?:ASA|PIX|FWSM)-\d+-\d+:")),
    # ---- Fortinet FortiGate -----------------------------------------------
    ("fortinet", 0.9, "keyword", "logid="),
    ("fortinet", 0.7, "keyword", "subtype="),
    ("fortinet", 0.7, "keyword", "action="),
    ("fortinet", 0.8, "regex",   re.compile(r'\btype=\S+\s+subtype=\S+')),
    # ---- pfSense ----------------------------------------------------------
    ("pfsense", 1.0, "keyword", "filterlog:"),
    ("pfsense", 0.7, "keyword", "pfsense"),
    # ---- Palo Alto Networks -----------------------------------------------
    ("palo_alto", 0.9, "keyword", "TRAFFIC,"),
    ("palo_alto", 0.9, "keyword", "THREAT,"),
    ("palo_alto", 0.8, "regex",   re.compile(r"^\d+,\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2},")),
    # ---- DNS BIND ---------------------------------------------------------
    ("dns_bind", 1.0, "keyword", "named["),
    ("dns_bind", 0.9, "keyword", "query:"),
    ("dns_bind", 0.7, "regex",   re.compile(r"named\[\d+\].*query:")),
    # ---- AWS CloudTrail ---------------------------------------------------
    ("cloudtrail", 0.9, "json_key", ("eventVersion", "eventSource", "awsRegion")),
    ("cloudtrail", 0.8, "json_key", ("Records",)),
    # ---- Azure Activity Log -----------------------------------------------
    ("azure_activity", 0.9, "json_key", ("operationName", "resourceId")),
    ("azure_activity", 0.7, "json_key", ("tenantId",)),
    ("azure_activity", 0.7, "json_key", ("subscriptionId",)),
    # ---- GCP Audit --------------------------------------------------------
    ("gcp_audit", 1.0, "json_key", ("protoPayload", "logName", "resource")),
    ("gcp_audit", 0.7, "json_key", ("insertId",)),
    # ---- Okta System Log --------------------------------------------------
    ("okta", 1.0, "json_key", ("actor", "target", "outcome", "eventType")),
    ("okta", 0.8, "json_key", ("legacyEventType",)),
    # ---- Squid proxy ------------------------------------------------------
    (
        "squid", 1.0, "regex",
        re.compile(r"^\d{10}\.\d{3}\s+\d+\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
    ),
    # ---- Postfix ----------------------------------------------------------
    ("postfix", 1.0, "keyword", "postfix/"),
    ("postfix", 0.7, "keyword", "postfix/smtpd"),
    # ---- SSH (standalone, not full auth.log) ------------------------------
    ("ssh", 0.9, "keyword", "sshd["),
    ("ssh", 0.7, "keyword", "Accepted publickey"),
    ("ssh", 0.7, "keyword", "Failed password"),
    ("ssh", 0.6, "keyword", "Disconnected from"),
    # ---- Docker -----------------------------------------------------------
    ("docker", 0.9, "keyword", "container_id="),
    ("docker", 0.9, "keyword", "container_name="),
    ("docker", 0.8, "json_key", ("log", "stream", "time")),
    # ---- Kubernetes -------------------------------------------------------
    ("k8s",    1.0, "keyword",  '"kubernetes"'),
    ("k8s",    0.8, "keyword",  "namespace_name"),
    ("k8s",    0.8, "json_key", ("kubernetes", "log")),
    ("k8s",    0.7, "keyword",  "pod_name"),
    # ---- MSSQL ------------------------------------------------------------
    ("mssql",  0.9, "keyword", "SQL Server"),
    ("mssql",  0.8, "keyword", "spid"),
    ("mssql",  0.7, "regex",   re.compile(r"Login\s+(?:failed|succeeded)\s+for\s+user")),
    # ---- MySQL ------------------------------------------------------------
    ("mysql",  0.9, "keyword", "mysqld["),
    ("mysql",  0.8, "keyword", "InnoDB:"),
    ("mysql",  0.7, "regex",   re.compile(r"Access denied for user")),
    # ---- Suricata EVE JSON ------------------------------------------------
    ("suricata", 1.0, "json_key", ("event_type", "src_ip", "dest_ip")),
    ("suricata", 0.9, "json_key", ("alert", "flow_id")),
    ("suricata", 0.8, "keyword",  '"event_type"'),
    # ---- Zeek (Bro) -------------------------------------------------------
    ("zeek",   1.0, "keyword",  "#separator"),
    ("zeek",   0.9, "keyword",  "#path\tconn"),
    ("zeek",   0.8, "regex",    re.compile(r"^#fields\s+")),
    # ---- VPN (generic syslog-based) --------------------------------------
    ("vpn",    0.8, "keyword",  "vpn"),
    ("vpn",    0.7, "keyword",  "VPNC"),
    ("vpn",    0.7, "keyword",  "remote_access"),
    # ---- Email (generic SMTP) --------------------------------------------
    ("email",  0.9, "keyword",  "RCPT TO:"),
    ("email",  0.9, "keyword",  "MAIL FROM:"),
    ("email",  0.7, "keyword",  "SMTP"),
    # ---- Windows EVTX XML (exported) -------------------------------------
    ("windows_evtx_xml", 1.0, "keyword", "<Events>"),
    ("windows_evtx_xml", 0.9, "keyword", "<Event xmlns="),
    ("windows_evtx_xml", 0.8, "keyword", "<System><Provider Name="),
]

_SAMPLE_LINES = 100  # increased for better semantic analysis
_SAMPLE_BYTES = 8192  # read this many bytes for structural analysis


# ---------------------------------------------------------------------------
# Ruleset mapping — maps any log_type (known or structural) to the
# recommended Sigma and YARA rule directories/tags for deep analysis.
# ---------------------------------------------------------------------------
_RULESET_MAP: Dict[str, Dict[str, List[str]]] = {
    # Web
    "apache":            {"sigma": ["web"],                         "yara": ["web"]},
    "nginx":             {"sigma": ["web"],                         "yara": ["web"]},
    "iis":               {"sigma": ["web", "windows"],              "yara": ["web", "windows"]},
    # Windows
    "windows_evtx":      {"sigma": ["windows"],                     "yara": ["windows"]},
    "windows_evtx_xml":  {"sigma": ["windows"],                     "yara": ["windows"]},
    "sysmon":            {"sigma": ["windows", "sysmon"],           "yara": ["windows"]},
    # Linux
    "syslog":            {"sigma": ["linux"],                       "yara": ["linux"]},
    "auth_log":          {"sigma": ["linux", "auth"],               "yara": ["linux"]},
    "auditd":            {"sigma": ["linux", "audit"],              "yara": ["linux"]},
    "ssh":               {"sigma": ["linux", "auth"],               "yara": ["linux"]},
    # Network
    "cisco_asa":         {"sigma": ["network", "firewall"],         "yara": ["network"]},
    "fortinet":          {"sigma": ["network", "firewall"],         "yara": ["network"]},
    "pfsense":           {"sigma": ["network", "firewall"],         "yara": ["network"]},
    "palo_alto":         {"sigma": ["network", "firewall"],         "yara": ["network"]},
    "squid":             {"sigma": ["network", "proxy"],            "yara": ["network"]},
    "suricata":          {"sigma": ["network", "ids"],              "yara": ["network"]},
    "zeek":              {"sigma": ["network"],                     "yara": ["network"]},
    "dns_bind":          {"sigma": ["network", "dns"],              "yara": ["network"]},
    "vpn":               {"sigma": ["network", "auth"],             "yara": ["network"]},
    # Cloud
    "cloudtrail":        {"sigma": ["cloud", "aws"],                "yara": ["cloud"]},
    "azure_activity":    {"sigma": ["cloud", "azure"],              "yara": ["cloud"]},
    "gcp_audit":         {"sigma": ["cloud", "gcp"],                "yara": ["cloud"]},
    "okta":              {"sigma": ["cloud", "auth"],               "yara": ["cloud"]},
    # Auth
    "postfix":           {"sigma": ["linux", "email"],              "yara": ["linux"]},
    "email":             {"sigma": ["linux", "email"],              "yara": ["linux"]},
    # Containers
    "docker":            {"sigma": ["linux", "container"],          "yara": ["linux"]},
    "k8s":               {"sigma": ["linux", "container"],          "yara": ["linux"]},
    # Databases
    "mssql":             {"sigma": ["windows", "database"],         "yara": ["windows"]},
    "mysql":             {"sigma": ["linux", "database"],           "yara": ["linux"]},
    # Structural fallbacks (no known signature matched)
    "generic_json":      {"sigma": ["generic"],                     "yara": ["generic"]},
    "generic_xml":       {"sigma": ["windows", "generic"],          "yara": ["windows", "generic"]},
    "generic_cef":       {"sigma": ["network", "generic"],          "yara": ["network"]},
    "generic_leef":      {"sigma": ["network", "generic"],          "yara": ["network"]},
    "generic_syslog":    {"sigma": ["linux", "generic"],            "yara": ["linux"]},
    "generic_kv":        {"sigma": ["generic"],                     "yara": ["generic"]},
    "generic_w3c":       {"sigma": ["web", "windows"],              "yara": ["web"]},
    "generic_csv":       {"sigma": ["generic"],                     "yara": ["generic"]},
    "unknown":           {"sigma": ["generic"],                     "yara": ["generic"]},
}

# ---------------------------------------------------------------------------
# Semantic keyword groups — used when structural analysis still can't decide
# ---------------------------------------------------------------------------
_SEMANTIC_GROUPS: List[Tuple[str, float, List[str]]] = [
    # (candidate_type, per-hit weight, keywords)
    ("auth_log",     0.4, [
        "sshd", "Failed password", "Accepted password", "Invalid user",
        "authentication failure", "pam_unix", "sudo", "su:", "login:",
        "useradd", "userdel", "passwd", "account locked",
    ]),
    ("apache",       0.4, [
        '"GET /', '"POST /', '"PUT /', '"DELETE /', "HTTP/1.1", "HTTP/2.0",
        "200 ", "301 ", "302 ", "403 ", "404 ", "500 ",
        "Mozilla/5.0", "User-Agent", "Referer:",
    ]),
    ("cloudtrail",   0.5, [
        "amazonaws.com", "aws:", "arn:aws:", "AssumeRole", "ConsoleLogin",
        "PutObject", "GetObject", "CreateInstance", "DescribeInstances",
        "eventSource", "eventName", "awsRegion", "userIdentity",
    ]),
    ("azure_activity", 0.5, [
        "microsoft.com", "azure", "Management", "operationName",
        "resourceGroup", "subscriptionId", "tenantId", "Microsoft.",
    ]),
    ("gcp_audit",    0.5, [
        "googleapis.com", "protoPayload", "logName", "projects/",
        "cloud.google.com", "serviceAccountName", "GCP",
    ]),
    ("windows_evtx_xml", 0.5, [
        "EventID", "EventRecord", "Security", "System", "Application",
        "Logon", "Logoff", "AccountName", "SubjectUserName",
        "SYSTEM32", "ntdll.dll", "lsass", "winlogon",
    ]),
    ("cisco_asa",    0.5, [
        "%ASA", "%PIX", "FWSM", "Built inbound", "Built outbound",
        "Teardown TCP", "access-list", "Deny", "permit",
    ]),
    ("suricata",     0.5, [
        "event_type", "alert", "flow_id", "src_ip", "dest_ip",
        "proto", "app_proto", "community_id", "signature",
    ]),
    ("dns_bind",     0.4, [
        "query:", "NOERROR", "NXDOMAIN", "IN A ", "IN AAAA",
        "named", "REFUSED", "SERVFAIL", "client @",
    ]),
    ("firewall",     0.3, [
        "ALLOW", "DENY", "BLOCK", "DROP", "ACCEPT", "REJECT",
        "SRC=", "DST=", "PROTO=", "DPT=", "SPT=",
        "IN=", "OUT=", "LEN=", "TCP ", "UDP ",
    ]),
    ("mysql",        0.4, [
        "SELECT", "INSERT INTO", "UPDATE ", "DELETE FROM",
        "Access denied for user", "InnoDB", "Query_time",
        "mysqld", "Aborted connection",
    ]),
    ("mssql",        0.4, [
        "SQL Server", "Login failed for user", "spid", "MSSQL",
        "Deadlock", "sqlserver", "xp_cmdshell", "sa ",
    ]),
    ("k8s",          0.5, [
        "kubernetes", "namespace", "pod_name", "container_id",
        "node_name", "kube-system", "kubectl", "apiserver",
    ]),
    ("docker",       0.4, [
        "container_id", "container_name", "docker", "image_name",
        "/var/lib/docker", "containerd", "runc",
    ]),
    ("postfix",      0.4, [
        "postfix/smtpd", "postfix/smtp", "RCPT TO", "MAIL FROM",
        "reject:", "milter", "queue_id", "relay=",
    ]),
    ("auditd",       0.5, [
        "type=SYSCALL", "type=EXECVE", "type=PROCTITLE", "type=PATH",
        "msg=audit(", "auid=", "uid=", "gid=", "pid=", "comm=",
        "exe=", "key=", "res=success", "res=failed",
    ]),
]


# ---------------------------------------------------------------------------
# Structural format classifiers
# ---------------------------------------------------------------------------

# RFC3164: "Mon DD HH:MM:SS hostname process[pid]:"
_RE_SYSLOG_3164 = re.compile(
    r"^\w{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\w+[\[:]"
)
# RFC5424: "<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID"
_RE_SYSLOG_5424 = re.compile(
    r"^<\d{1,3}>\d+\s+\d{4}-\d{2}-\d{2}T"
)
# CEF: "CEF:0|Vendor|Product|..."
_RE_CEF = re.compile(r"^CEF:\d+\|")
# LEEF: "LEEF:1.0|Vendor|Product|..."
_RE_LEEF = re.compile(r"^LEEF:\d+\.\d+\|")
# W3C Extended Log Format header
_RE_W3C = re.compile(r"^#(?:Version|Fields|Software|Date):")
# Apache CLF / combined: IP - - [timestamp] "METHOD
_RE_CLF = re.compile(
    r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\S+\s+\S+\s+\[.+?\]\s+"'
)
# Key=value pairs (at least 3 k=v pairs)
_RE_KV = re.compile(r"(?:\w[\w\-\.]*=\S+\s+){2,}")
# Zeek TSV header
_RE_ZEEK = re.compile(r"^#(?:separator|path|fields|types)")
# Pure ISO timestamp at start of line (many generic logs)
_RE_ISO_TS = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")


def _classify_structure(lines: List[str]) -> Tuple[str, float, List[str]]:
    """
    Analyse the structural format of *lines*.

    Returns (structure_name, confidence_boost, signals).

    structure_name is one of:
        json_lines, json_array, xml, cef, leef,
        syslog_rfc5424, syslog_rfc3164, zeek_tsv,
        w3c_extended, clf, key_value, csv, plaintext
    """
    if not lines:
        return "plaintext", 0.0, []

    signals: List[str] = []

    # ---- JSON -------------------------------------------------------
    json_count = 0
    for line in lines[:20]:
        if line.startswith("{") and _try_parse_json(line):
            json_count += 1
    if json_count >= max(1, len(lines[:20]) // 2):
        conf = min(json_count / max(len(lines[:20]), 1), 1.0)
        signals.append(f"JSON-lines: {json_count}/{min(len(lines), 20)} lines parsed as JSON objects")
        return "json_lines", conf * 0.9, signals

    # JSON array
    full_text = "\n".join(lines[:5])
    if lines[0].startswith("["):
        try:
            obj = json.loads(full_text + "]")  # may be partial
            if isinstance(obj, list):
                signals.append("JSON array structure detected")
                return "json_array", 0.8, signals
        except Exception:
            pass

    # ---- XML -------------------------------------------------------
    xml_count = sum(1 for l in lines[:20] if "<" in l and ">" in l and "</" in l)
    if xml_count >= 3 or (lines[0].startswith("<?xml") or lines[0].startswith("<Events")):
        signals.append(f"XML structure: {xml_count} lines with XML tags")
        return "xml", min(xml_count / 5.0, 1.0) * 0.85, signals

    # ---- CEF -------------------------------------------------------
    cef_count = sum(1 for l in lines[:20] if _RE_CEF.match(l))
    if cef_count >= 1:
        signals.append(f"CEF format: {cef_count} lines match CEF:N| prefix")
        return "cef", min(cef_count / 3.0, 1.0) * 0.9, signals

    # ---- LEEF -------------------------------------------------------
    leef_count = sum(1 for l in lines[:20] if _RE_LEEF.match(l))
    if leef_count >= 1:
        signals.append(f"LEEF format: {leef_count} lines match LEEF:N.N| prefix")
        return "leef", min(leef_count / 3.0, 1.0) * 0.9, signals

    # ---- Zeek TSV --------------------------------------------------
    zeek_count = sum(1 for l in lines[:10] if _RE_ZEEK.match(l))
    if zeek_count >= 2:
        signals.append(f"Zeek TSV: {zeek_count} header comment lines")
        return "zeek_tsv", 0.9, signals

    # ---- W3C Extended ----------------------------------------------
    w3c_count = sum(1 for l in lines[:10] if _RE_W3C.match(l))
    if w3c_count >= 2:
        signals.append(f"W3C Extended Log: {w3c_count} header directives")
        return "w3c_extended", min(w3c_count / 3.0, 1.0) * 0.85, signals

    # ---- Syslog RFC5424 -------------------------------------------
    s5424_count = sum(1 for l in lines[:20] if _RE_SYSLOG_5424.match(l))
    if s5424_count >= 2:
        signals.append(f"Syslog RFC5424: {s5424_count} lines match structured format")
        return "syslog_rfc5424", min(s5424_count / 5.0, 1.0) * 0.85, signals

    # ---- Syslog RFC3164 -------------------------------------------
    s3164_count = sum(1 for l in lines[:20] if _RE_SYSLOG_3164.match(l))
    if s3164_count >= 3:
        signals.append(f"Syslog RFC3164: {s3164_count} lines match BSD syslog format")
        return "syslog_rfc3164", min(s3164_count / 5.0, 1.0) * 0.8, signals

    # ---- Apache CLF -----------------------------------------------
    clf_count = sum(1 for l in lines[:20] if _RE_CLF.match(l))
    if clf_count >= 3:
        signals.append(f"Apache CLF: {clf_count} lines match Combined Log Format")
        return "clf", min(clf_count / 5.0, 1.0) * 0.85, signals

    # ---- Key=Value ------------------------------------------------
    kv_count = sum(1 for l in lines[:20] if _RE_KV.search(l))
    if kv_count >= 4:
        signals.append(f"Key=Value format: {kv_count} lines with multiple k=v pairs")
        return "key_value", min(kv_count / 8.0, 1.0) * 0.7, signals

    # ---- CSV -------------------------------------------------------
    # Check if first non-comment line has consistent delimiter counts
    data_lines = [l for l in lines[:10] if not l.startswith("#")]
    if len(data_lines) >= 3:
        for delim in (",", "\t", ";"):
            counts = [l.count(delim) for l in data_lines[:5]]
            if min(counts) >= 3 and max(counts) - min(counts) <= 2:
                signals.append(f"CSV/delimited: consistent '{delim}' separators ({counts[0]} per line)")
                return "csv", 0.6, signals

    # ---- ISO timestamp lines (generic structured log) ---------------
    iso_count = sum(1 for l in lines[:20] if _RE_ISO_TS.match(l))
    if iso_count >= 4:
        signals.append(f"ISO-timestamp lines: {iso_count} lines start with timestamp")
        return "iso_timestamp", 0.5, signals

    signals.append("No structured format detected — treating as plaintext")
    return "plaintext", 0.1, signals


def _scan_semantics(lines: List[str]) -> List[Tuple[str, float, List[str]]]:
    """
    Score each semantic group against *lines*.

    Returns a list of (candidate_type, score, signals) sorted descending by score.
    """
    full_text = "\n".join(lines)
    results: List[Tuple[str, float, List[str]]] = []

    for candidate, weight, keywords in _SEMANTIC_GROUPS:
        hits = [kw for kw in keywords if kw in full_text]
        if hits:
            score = min(len(hits) * weight, 1.5)   # cap at 1.5 raw
            signals = [f"Semantic keyword '{kw}'" for kw in hits[:5]]
            if len(hits) > 5:
                signals.append(f"… and {len(hits) - 5} more keyword(s)")
            results.append((candidate, score, signals))

    results.sort(key=lambda x: x[1], reverse=True)
    return results


def _structure_to_logtype(structure: str, semantic_type: Optional[str]) -> str:
    """
    Map a structural format + optional semantic best-guess to a log_type.
    """
    # If semantic analysis has a confident result, prefer it
    if semantic_type and semantic_type not in ("firewall",):
        return semantic_type

    _map = {
        "json_lines":    "generic_json",
        "json_array":    "generic_json",
        "xml":           "generic_xml",
        "cef":           "generic_cef",
        "leef":          "generic_leef",
        "syslog_rfc5424": "syslog",
        "syslog_rfc3164": "syslog",
        "zeek_tsv":      "zeek",
        "w3c_extended":  "iis",   # W3C is almost always IIS
        "clf":           "apache",
        "key_value":     "generic_kv",
        "csv":           "generic_csv",
        "iso_timestamp": "syslog",
        "plaintext":     "unknown",
    }
    if semantic_type == "firewall":
        return "cisco_asa"  # generic firewall fallback to broadest rules

    return _map.get(structure, "unknown")


def _confidence_tier(confidence: float) -> str:
    if confidence >= 0.80:
        return "CONFIRMED"
    if confidence >= 0.50:
        return "LIKELY"
    if confidence >= 0.20:
        return "POSSIBLE"
    return "FALLBACK"


# ---------------------------------------------------------------------------
# Internal helpers (unchanged)
# ---------------------------------------------------------------------------

def _read_sample(path: Path, n: int) -> List[str]:
    """Return up to *n* non-empty lines from the beginning of *path*."""
    lines: List[str] = []
    try:
        with open(path, "r", errors="replace") as fh:
            for raw in fh:
                stripped = raw.strip()
                if stripped:
                    lines.append(stripped)
                    if len(lines) >= n:
                        break
    except OSError:
        pass
    return lines


def _check_pattern(lines: List[str], pattern_type: str, pattern: Any) -> bool:
    if pattern_type == "regex":
        return any(pattern.search(line) for line in lines)
    if pattern_type == "keyword":
        return any(pattern in line for line in lines)
    if pattern_type == "json_key":
        required_keys: Tuple[str, ...] = pattern
        for line in lines:
            obj = _try_parse_json(line)
            if obj is None:
                continue
            if "Records" in obj and isinstance(obj["Records"], list) and obj["Records"]:
                obj = obj["Records"][0]
            if all(k in obj for k in required_keys):
                return True
        return False
    return False


def _try_parse_json(text: str) -> Optional[Dict[str, Any]]:
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except (json.JSONDecodeError, ValueError):
        pass
    return None


def _describe(pattern_type: str, pattern: Any, weight: float) -> str:
    if pattern_type == "regex":
        return f"Regex match (w={weight:.1f}): {pattern.pattern[:60]}"
    if pattern_type == "keyword":
        return f"Keyword match (w={weight:.1f}): '{pattern}'"
    if pattern_type == "json_key":
        keys = ", ".join(pattern)
        return f"JSON keys present (w={weight:.1f}): {keys}"
    return f"Match (w={weight:.1f})"


def _print_result(log_type: str, confidence: float, tier: str, structure: str = "") -> None:
    pct = int(confidence * 100)
    tier_colours = {
        "CONFIRMED": "bold green",
        "LIKELY":    "green",
        "POSSIBLE":  "yellow",
        "FALLBACK":  "dim yellow",
    }
    colour = tier_colours.get(tier, "white")
    struct_hint = f" [dim](structure: {structure})[/dim]" if structure and structure not in ("plaintext", "") else ""

    if log_type == "unknown":
        console.print(
            "[bold cyan]ThreatTrace Auto-Detector:[/bold cyan] "
            "[yellow]Could not identify log type[/yellow] "
            "(confidence: 0%)"
        )
    else:
        console.print(
            f"[bold cyan]ThreatTrace Auto-Detector:[/bold cyan] "
            f"Identified [{colour}]{log_type}[/{colour}] "
            f"(confidence: [bold]{pct}%[/bold] — [{colour}]{tier}[/{colour}])"
            f"{struct_hint}"
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_ruleset_for_type(log_type: str) -> Dict[str, List[str]]:
    """
    Return the recommended Sigma and YARA rule subdirectories/tags for
    *log_type*.

    Usage
    -----
    ruleset = get_ruleset_for_type("auth_log")
    # → {"sigma": ["linux", "auth"], "yara": ["linux"]}

    The detection engine can use these to load only the rules relevant to
    the detected log type, enabling fast and targeted deep analysis.
    """
    return _RULESET_MAP.get(log_type, _RULESET_MAP["unknown"])


def detect(file_path: str) -> Dict[str, Any]:
    """
    Fingerprint the log type of *file_path*.

    Backward-compatible wrapper around detect_deep().

    Returns
    -------
    {
        "log_type":   str,
        "confidence": float,   # 0.0 – 1.0
        "tier":       str,     # CONFIRMED | LIKELY | POSSIBLE | FALLBACK
        "structure":  str,     # detected format
        "signals":    list[str]
    }
    """
    return detect_deep(file_path)


def detect_deep(file_path: str) -> Dict[str, Any]:
    """
    Multi-phase log type detection — always returns a usable log_type.

    Phase 1: Extension / magic bytes (immediate, high-confidence)
    Phase 2: Signature matching (regex / keyword / JSON keys)
    Phase 3: Structural analysis (format shape classification)
    Phase 4: Semantic keyword analysis (domain inference)

    Never returns log_type "unknown" without also providing a structural
    fallback type and the recommended ruleset for deep analysis.
    """
    path = Path(file_path)

    # ------------------------------------------------------------------
    # Phase 1 — Extension / magic bytes
    # ------------------------------------------------------------------
    if path.suffix.lower() == ".evtx":
        try:
            with open(path, "rb") as fh:
                magic = fh.read(8)
            if magic == EVTX_MAGIC:
                result = {
                    "log_type":   "windows_evtx",
                    "confidence": 1.0,
                    "tier":       "CONFIRMED",
                    "structure":  "evtx_binary",
                    "signals":    ["EVTX magic bytes (ElfFile\\x00)", "Extension .evtx"],
                    "ruleset":    get_ruleset_for_type("windows_evtx"),
                }
                _print_result("windows_evtx", 1.0, "CONFIRMED", "evtx_binary")
                return result
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Phase 2 — Read sample lines
    # ------------------------------------------------------------------
    sample_lines = _read_sample(path, _SAMPLE_LINES)

    if not sample_lines:
        result = {
            "log_type":   "unknown",
            "confidence": 0.0,
            "tier":       "FALLBACK",
            "structure":  "empty",
            "signals":    ["File is empty or unreadable"],
            "ruleset":    get_ruleset_for_type("unknown"),
        }
        _print_result("unknown", 0.0, "FALLBACK")
        return result

    # ------------------------------------------------------------------
    # Phase 2 — Signature scoring
    # ------------------------------------------------------------------
    scores: Dict[str, float] = {}
    evidence: Dict[str, List[str]] = {}

    for log_type, weight, pattern_type, pattern in _SIGNATURES:
        hit = _check_pattern(sample_lines, pattern_type, pattern)
        if hit:
            scores[log_type] = scores.get(log_type, 0.0) + weight
            evidence.setdefault(log_type, []).append(
                _describe(pattern_type, pattern, weight)
            )

    # Disambiguation rules
    if "nginx" in scores and "apache" in scores:
        nginx_specific = sum(
            w for lt, w, pt, pat in _SIGNATURES
            if lt == "nginx" and pt == "keyword"
        )
        if scores["nginx"] - scores["apache"] < nginx_specific * 0.5:
            del scores["nginx"]
            evidence.pop("nginx", None)

    if "auth_log" in scores and "ssh" in scores:
        del scores["ssh"]
        evidence.pop("ssh", None)

    if "auth_log" in scores and "syslog" in scores:
        del scores["syslog"]
        evidence.pop("syslog", None)

    # ------------------------------------------------------------------
    # Phase 3 — Structural analysis (runs regardless of signature score)
    # ------------------------------------------------------------------
    structure, struct_conf, struct_signals = _classify_structure(sample_lines)

    # ------------------------------------------------------------------
    # Phase 4 — Semantic analysis (runs when signature confidence < 0.5)
    # ------------------------------------------------------------------
    semantic_results = _scan_semantics(sample_lines)
    semantic_type: Optional[str] = None
    semantic_signals: List[str] = []
    semantic_score: float = 0.0

    if semantic_results:
        best_sem = semantic_results[0]
        semantic_type  = best_sem[0]
        semantic_score = best_sem[1]
        semantic_signals = best_sem[2]

    # ------------------------------------------------------------------
    # Decide winner
    # ------------------------------------------------------------------
    all_signals: List[str] = []

    if scores:
        best_type  = max(scores, key=lambda t: scores[t])
        raw_score  = scores[best_type]
        confidence = min(raw_score / 2.0, 1.0)
        all_signals = evidence.get(best_type, [])

        # Boost confidence slightly when structural analysis agrees
        struct_map = {
            "json_lines":     {"cloudtrail", "azure_activity", "gcp_audit", "okta", "docker", "k8s", "suricata"},
            "xml":            {"sysmon", "windows_evtx_xml"},
            "syslog_rfc3164": {"syslog", "auth_log", "postfix", "dns_bind"},
            "zeek_tsv":       {"zeek"},
            "w3c_extended":   {"iis"},
            "clf":            {"apache", "nginx"},
            "key_value":      {"auditd", "fortinet"},
            "cef":            {"cisco_asa"},
            "leef":           {"cisco_asa"},
        }
        if structure in struct_map and best_type in struct_map[structure]:
            confidence = min(confidence + 0.10, 1.0)
            all_signals.append(f"Structural confirmation: {structure}")
        else:
            all_signals.extend(struct_signals[:2])

    else:
        # No signature matched — rely on structural + semantic
        all_signals.extend(struct_signals)

        if semantic_score >= 0.6 and semantic_type:
            # Semantic analysis has a plausible answer
            best_type  = semantic_type
            confidence = min(struct_conf + (semantic_score * 0.3), 0.75)
            all_signals.extend(semantic_signals)
        elif struct_conf >= 0.5:
            # Trust the structural format even without semantic signals
            best_type  = _structure_to_logtype(structure, None)
            confidence = struct_conf
        elif semantic_type:
            best_type  = semantic_type
            confidence = max(struct_conf, semantic_score * 0.25)
            all_signals.extend(semantic_signals)
        else:
            # Last resort
            best_type  = "unknown"
            confidence = 0.0

    tier = _confidence_tier(confidence)

    # Attach ruleset so caller can immediately start analysis
    ruleset = get_ruleset_for_type(best_type)

    # Add ruleset info to signals for transparency
    if tier in ("POSSIBLE", "FALLBACK") and best_type != "unknown":
        all_signals.append(
            f"Deep analysis will use rules: sigma={ruleset['sigma']}, yara={ruleset['yara']}"
        )

    _print_result(best_type, round(confidence, 3), tier, structure)

    # When confidence is low, print an extra advisory
    if tier in ("POSSIBLE", "FALLBACK") and best_type != "unknown":
        console.print(
            f"[bold cyan]ThreatTrace Auto-Detector:[/bold cyan] "
            f"[dim]Best structural guess: [yellow]{structure}[/yellow] — "
            f"initiating broad deep analysis with {ruleset['sigma']} Sigma + "
            f"{ruleset['yara']} YARA rules[/dim]"
        )
    elif best_type == "unknown":
        console.print(
            "[bold cyan]ThreatTrace Auto-Detector:[/bold cyan] "
            "[yellow]Format unrecognised. Running generic deep analysis across all rule categories.[/yellow]"
        )
        best_type = "generic_kv"   # broadest parse; never return raw "unknown" to the pipeline
        ruleset   = get_ruleset_for_type("generic_kv")

    return {
        "log_type":   best_type,
        "confidence": round(confidence, 3),
        "tier":       tier,
        "structure":  structure,
        "signals":    all_signals,
        "ruleset":    ruleset,
    }
