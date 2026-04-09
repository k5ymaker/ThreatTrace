"""Custom Sigma rule evaluator — parses YAML Sigma rules and evaluates against LogEvent fields."""
from __future__ import annotations

import base64
import fnmatch
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import yaml

from ..models.finding import Finding, Severity
from ..models.log_event import LogEvent, LogSourceType

logger = logging.getLogger(__name__)

# MITRE ATT&CK tactic tag → display name
TACTIC_MAP: dict[str, str] = {
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "reconnaissance": "Reconnaissance",
    "resource_development": "Resource Development",
}

# Sigma logsource → set of compatible LogSourceType values
LOGSOURCE_COMPAT: dict[str, set[LogSourceType]] = {
    # Windows
    "windows/security": {LogSourceType.WINDOWS_EVTX, LogSourceType.WINDOWS_EVTX_XML},
    "windows/system": {LogSourceType.WINDOWS_EVTX, LogSourceType.WINDOWS_EVTX_XML},
    "windows/application": {LogSourceType.WINDOWS_EVTX, LogSourceType.WINDOWS_EVTX_XML},
    "windows/sysmon": {LogSourceType.WINDOWS_EVTX, LogSourceType.WINDOWS_EVTX_XML, LogSourceType.WINDOWS_SYSMON},
    "windows/powershell": {LogSourceType.WINDOWS_EVTX, LogSourceType.WINDOWS_EVTX_XML, LogSourceType.WINDOWS_POWERSHELL},
    "windows": {LogSourceType.WINDOWS_EVTX, LogSourceType.WINDOWS_EVTX_XML, LogSourceType.WINDOWS_SYSMON, LogSourceType.WINDOWS_POWERSHELL},
    "process_creation/windows": {LogSourceType.WINDOWS_EVTX, LogSourceType.WINDOWS_EVTX_XML, LogSourceType.WINDOWS_SYSMON},
    # Linux
    "linux/auth": {LogSourceType.LINUX_AUTH_LOG, LogSourceType.LINUX_SYSLOG},
    "linux/syslog": {LogSourceType.LINUX_SYSLOG},
    "linux/audit": {LogSourceType.LINUX_AUDIT},
    "linux/cron": {LogSourceType.LINUX_CRON, LogSourceType.LINUX_SYSLOG},
    "linux": {LogSourceType.LINUX_AUTH_LOG, LogSourceType.LINUX_SYSLOG, LogSourceType.LINUX_AUDIT, LogSourceType.LINUX_KERN_LOG, LogSourceType.LINUX_CRON},
    # Web
    "web/apache": {LogSourceType.APACHE_ACCESS, LogSourceType.APACHE_ERROR},
    "web/nginx": {LogSourceType.NGINX_ACCESS, LogSourceType.NGINX_ERROR},
    "web/iis": {LogSourceType.IIS_W3C},
    "web": {LogSourceType.APACHE_ACCESS, LogSourceType.APACHE_ERROR, LogSourceType.NGINX_ACCESS, LogSourceType.NGINX_ERROR, LogSourceType.IIS_W3C, LogSourceType.HAPROXY},
    "webserver": {LogSourceType.APACHE_ACCESS, LogSourceType.APACHE_ERROR, LogSourceType.NGINX_ACCESS, LogSourceType.NGINX_ERROR, LogSourceType.IIS_W3C},
    # Network
    "network/firewall": {LogSourceType.FIREWALL_CISCO_ASA, LogSourceType.FIREWALL_PALO_ALTO, LogSourceType.FIREWALL_FORTINET, LogSourceType.FIREWALL_PFSENSE},
    "network/dns": {LogSourceType.DNS_BIND, LogSourceType.DNS_WINDOWS, LogSourceType.ZEEK_DNS},
    "network": {LogSourceType.FIREWALL_CISCO_ASA, LogSourceType.FIREWALL_PALO_ALTO, LogSourceType.ZEEK_CONN, LogSourceType.ZEEK_DNS, LogSourceType.SURICATA_EVE, LogSourceType.NETFLOW},
    # Cloud (keys match Sigma logsource product/service combinations)
    "cloud/aws": {LogSourceType.AWS_CLOUDTRAIL, LogSourceType.AWS_VPC_FLOW},
    "aws/cloudtrail": {LogSourceType.AWS_CLOUDTRAIL},
    "aws/s3": {LogSourceType.AWS_CLOUDTRAIL},
    "aws/vpc_flow": {LogSourceType.AWS_VPC_FLOW},
    "aws": {LogSourceType.AWS_CLOUDTRAIL, LogSourceType.AWS_VPC_FLOW},
    "cloud/azure": {LogSourceType.AZURE_ACTIVITY, LogSourceType.AZURE_SIGNIN},
    "azure/activity": {LogSourceType.AZURE_ACTIVITY},
    "azure/signin": {LogSourceType.AZURE_SIGNIN},
    "azure": {LogSourceType.AZURE_ACTIVITY, LogSourceType.AZURE_SIGNIN},
    "cloud/gcp": {LogSourceType.GCP_AUDIT},
    "gcp/audit": {LogSourceType.GCP_AUDIT},
    "gcp": {LogSourceType.GCP_AUDIT},
    "cloud": {LogSourceType.AWS_CLOUDTRAIL, LogSourceType.AWS_VPC_FLOW, LogSourceType.AZURE_ACTIVITY, LogSourceType.AZURE_SIGNIN, LogSourceType.GCP_AUDIT},
    # Network vendors
    "cisco/asa": {LogSourceType.FIREWALL_CISCO_ASA},
    "palo-alto/firewall": {LogSourceType.FIREWALL_PALO_ALTO},
    "suricata": {LogSourceType.SURICATA_EVE},
    "zeek/dns": {LogSourceType.ZEEK_DNS},
    "zeek/conn": {LogSourceType.ZEEK_CONN},
    "zeek": {LogSourceType.ZEEK_CONN, LogSourceType.ZEEK_DNS, LogSourceType.ZEEK_HTTP},
    # Catch-all
    "any": set(LogSourceType),
    "_all": set(LogSourceType),
}


@dataclass
class SigmaRule:
    rule_id: str
    title: str
    status: str
    severity: Severity
    description: str
    references: list[str]
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    logsource: dict
    detection: dict
    false_positives: list[str]
    _logsource_key: str = ""  # computed


def _parse_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    """Extract MITRE tactics and techniques from Sigma tags."""
    tactics: list[str] = []
    techniques: list[str] = []
    for tag in tags:
        if not tag.startswith("attack."):
            continue
        part = tag[len("attack."):]
        if part.startswith("t") and len(part) >= 5 and part[1:].replace(".", "").isdigit():
            techniques.append(part.upper())
        else:
            display = TACTIC_MAP.get(part, part.replace("_", " ").title())
            if display not in tactics:
                tactics.append(display)
    return tactics, techniques


def _logsource_key(logsource: dict) -> str:
    product = logsource.get("product", "").lower()
    service = logsource.get("service", "").lower()
    category = logsource.get("category", "").lower()

    if product and service:
        return f"{product}/{service}"
    if category and product:
        return f"{category}/{product}"
    if product:
        return product
    if category:
        return category
    if service:
        return service
    return "_all"


def _load_sigma_rule(doc: dict) -> SigmaRule | None:
    if not isinstance(doc, dict):
        return None
    detection = doc.get("detection")
    if not detection:
        return None

    tags = doc.get("tags", [])
    tactics, techniques = _parse_tags(tags)

    level = doc.get("level", "medium")
    severity = Severity.from_str(level)

    ls = doc.get("logsource", {})
    ls_key = _logsource_key(ls)

    return SigmaRule(
        rule_id=doc.get("id", doc.get("title", "unknown")),
        title=doc.get("title", "Unknown Rule"),
        status=doc.get("status", "experimental"),
        severity=severity,
        description=doc.get("description", ""),
        references=doc.get("references", []),
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        logsource=ls,
        detection=detection,
        false_positives=doc.get("falsepositives", []),
        _logsource_key=ls_key,
    )


class FieldMatcher:
    """Evaluates a single Sigma detection field specification against event fields."""

    # Pre-compile common patterns
    _b64_re = re.compile(r"^[A-Za-z0-9+/]{4,}={0,2}$")

    def match_field_value(self, event_val: str, rule_val: Any, modifiers: list[str]) -> bool:
        """Test whether event_val matches rule_val given the list of modifiers."""
        if not isinstance(event_val, str):
            event_val = str(event_val)
        if not isinstance(rule_val, (str, int, float, bool)):
            rule_val = str(rule_val)
        else:
            rule_val = str(rule_val)

        if "base64" in modifiers:
            try:
                event_val = base64.b64decode(event_val + "==").decode("utf-8", errors="replace")
            except Exception:
                pass

        if "re" in modifiers or "regex" in modifiers:
            try:
                return bool(re.search(rule_val, event_val, re.IGNORECASE))
            except re.error:
                return False

        if "windash" in modifiers:
            # Normalize Windows argument dashes
            rule_val = rule_val.replace("-", "[-/]").replace("/", "[-/]")
            try:
                return bool(re.search(rule_val, event_val, re.IGNORECASE))
            except re.error:
                pass

        if "cidr" in modifiers:
            try:
                network = ipaddress.ip_network(rule_val, strict=False)
                addr = ipaddress.ip_address(event_val.split("/")[0])
                return addr in network
            except ValueError:
                return False

        # Case-insensitive comparison by default
        ev_lower = event_val.lower()
        rv_lower = rule_val.lower()

        if "startswith" in modifiers:
            return ev_lower.startswith(rv_lower)
        if "endswith" in modifiers:
            return ev_lower.endswith(rv_lower)
        if "contains" in modifiers:
            return rv_lower in ev_lower

        # Default: exact match (case-insensitive)
        return ev_lower == rv_lower

    def match_field(
        self, event_fields: dict, field_spec: str, value_spec: Any
    ) -> tuple[bool, str]:
        """
        Evaluate one field specification.
        Returns (matched: bool, matched_value: str).

        field_spec examples:
          "CommandLine|contains"
          "EventID"
          "Message|contains|all"
        """
        parts = field_spec.split("|")
        field_name = parts[0]
        modifiers = [p.lower() for p in parts[1:]]

        # Fetch value from event (case-insensitive field lookup)
        event_val = self._get_field(event_fields, field_name)
        if event_val is None:
            return False, ""

        require_all = "all" in modifiers
        effective_modifiers = [m for m in modifiers if m != "all"]

        values = value_spec if isinstance(value_spec, list) else [value_spec]
        # Remove 'all' from the effective modifiers list since it controls AND/OR
        matched_vals: list[str] = []

        for v in values:
            if v is None:
                continue
            if self.match_field_value(str(event_val), v, effective_modifiers):
                matched_vals.append(str(v))

        if require_all:
            if len(matched_vals) == len([v for v in values if v is not None]):
                return True, "; ".join(matched_vals)
            return False, ""

        if matched_vals:
            return True, matched_vals[0]

        return False, ""

    @staticmethod
    def _get_field(fields: dict, name: str) -> Any:
        """Case-insensitive field lookup."""
        if name in fields:
            return fields[name]
        name_lower = name.lower()
        for k, v in fields.items():
            if k.lower() == name_lower:
                return v
        return None


class SelectionEvaluator:
    """Evaluates a named selection block from the detection dict."""

    def __init__(self) -> None:
        self._matcher = FieldMatcher()

    def evaluate(
        self, selection: Any, event_fields: dict
    ) -> tuple[bool, dict[str, str]]:
        """
        Returns (matched, {field: matched_value}).

        A selection can be:
          - dict: all field conditions must match (AND)
          - list of dicts: any dict in list must fully match (OR across items)
          - list of strings: any string must appear somewhere in event values (keyword search)
        """
        if isinstance(selection, list):
            # Could be list of dicts (OR) or list of strings (keyword match)
            if selection and isinstance(selection[0], dict):
                for item in selection:
                    matched, evidence = self.evaluate(item, event_fields)
                    if matched:
                        return True, evidence
                return False, {}
            else:
                # Keyword search across all field values
                all_values = " ".join(str(v) for v in event_fields.values()).lower()
                for kw in selection:
                    if str(kw).lower() in all_values:
                        return True, {"_keyword": str(kw)}
                return False, {}

        if isinstance(selection, dict):
            evidence: dict[str, str] = {}
            for field_spec, value_spec in selection.items():
                matched, val = self._matcher.match_field(event_fields, field_spec, value_spec)
                if not matched:
                    return False, {}
                evidence[field_spec] = val
            return True, evidence

        # Scalar: keyword search
        kw = str(selection).lower()
        all_values = " ".join(str(v) for v in event_fields.values()).lower()
        if kw in all_values:
            return True, {"_keyword": str(selection)}
        return False, {}


class ConditionParser:
    """
    Parses and evaluates a Sigma condition string against resolved selection results.

    Supported syntax:
      - identifier
      - not <expr>
      - <expr> and <expr>
      - <expr> or <expr>
      - ( <expr> )
      - 1 of <pattern>
      - all of <pattern>
      - <n> of <pattern>  (n is an integer)
    """

    def __init__(self, selection_results: dict[str, tuple[bool, dict]]) -> None:
        self.selections = selection_results

    def evaluate(self, condition: str) -> tuple[bool, dict[str, str]]:
        condition = condition.strip()
        tokens = self._tokenize(condition)
        result, evidence, _ = self._parse_expr(tokens, 0)
        return result, evidence

    def _tokenize(self, s: str) -> list[str]:
        import re as _re
        token_re = _re.compile(
            r"\b(?:not|and|or|of|all|them)\b"
            r"|\d+(?=\s+of)"
            r"|[()]"
            r"|[^\s()]+",
            re.IGNORECASE,
        )
        return token_re.findall(s)

    def _parse_expr(
        self, tokens: list[str], pos: int, min_prec: int = 0
    ) -> tuple[bool, dict, int]:
        """Recursive descent with operator precedence (not > and > or)."""
        result, evidence, pos = self._parse_unary(tokens, pos)

        while pos < len(tokens):
            op = tokens[pos].lower()
            if op == "and" and 2 >= min_prec:
                pos += 1
                right, right_ev, pos = self._parse_unary(tokens, pos)
                if result and right:
                    evidence.update(right_ev)
                    result = True
                else:
                    result = False
                    evidence = {}
            elif op == "or" and 1 >= min_prec:
                pos += 1
                right, right_ev, pos = self._parse_unary(tokens, pos)
                if result:
                    pass  # keep existing evidence
                elif right:
                    result = True
                    evidence = right_ev
                # else stays False
            else:
                break

        return result, evidence, pos

    def _parse_unary(
        self, tokens: list[str], pos: int
    ) -> tuple[bool, dict, int]:
        if pos >= len(tokens):
            return False, {}, pos

        tok = tokens[pos]

        if tok.lower() == "not":
            pos += 1
            inner, ev, pos = self._parse_unary(tokens, pos)
            return not inner, {}, pos

        if tok == "(":
            pos += 1
            result, evidence, pos = self._parse_expr(tokens, pos)
            if pos < len(tokens) and tokens[pos] == ")":
                pos += 1
            return result, evidence, pos

        # "1 of X", "all of X", "N of X"
        if tok.lower() == "all" and pos + 1 < len(tokens) and tokens[pos + 1].lower() == "of":
            pos += 2
            pattern = tokens[pos] if pos < len(tokens) else ""
            pos += 1
            matches = self._expand_pattern(pattern)
            all_ok = all(self.selections.get(m, (False, {}))[0] for m in matches)
            ev: dict = {}
            if all_ok:
                for m in matches:
                    ev.update(self.selections.get(m, (False, {}))[1])
            return all_ok, ev, pos

        if tok.isdigit() and pos + 1 < len(tokens) and tokens[pos + 1].lower() == "of":
            n = int(tok)
            pos += 2
            pattern = tokens[pos] if pos < len(tokens) else ""
            pos += 1
            matches = self._expand_pattern(pattern)
            count = sum(1 for m in matches if self.selections.get(m, (False, {}))[0])
            if count >= n:
                ev = {}
                for m in matches:
                    ok, sel_ev = self.selections.get(m, (False, {}))
                    if ok:
                        ev.update(sel_ev)
                return True, ev, pos
            return False, {}, pos

        # Plain identifier — look up selection result
        result, evidence = self.selections.get(tok, (False, {}))
        return result, dict(evidence), pos + 1

    def _expand_pattern(self, pattern: str) -> list[str]:
        """Expand wildcard pattern like 'selection_*' or 'them' against known selection names."""
        if pattern == "them":
            return list(self.selections.keys())
        return [k for k in self.selections if fnmatch.fnmatch(k, pattern)]


class SigmaEngine:
    """Loads Sigma YAML rule files and evaluates events."""

    def __init__(self, rules_dir: Path) -> None:
        self.rules_dir = rules_dir
        self._rules: list[SigmaRule] = []
        self._sel_evaluator = SelectionEvaluator()
        self._load_rules()

    def _load_rules(self) -> None:
        rule_files = list(self.rules_dir.rglob("*.yml")) + list(self.rules_dir.rglob("*.yaml"))
        for rf in rule_files:
            try:
                content = rf.read_text(encoding="utf-8", errors="replace")
                docs = list(yaml.safe_load_all(content))
                for doc in docs:
                    rule = _load_sigma_rule(doc)
                    if rule:
                        self._rules.append(rule)
            except Exception as e:
                logger.debug("Failed to load Sigma rule %s: %s", rf, e)
        logger.debug("Loaded %d Sigma rules", len(self._rules))

    def scan_event(self, event: LogEvent) -> list[Finding]:
        """Evaluate all applicable Sigma rules against a LogEvent."""
        findings: list[Finding] = []
        for rule in self._rules:
            if not self._logsource_matches(rule, event):
                continue
            matched, evidence = self._evaluate_rule(rule, event.fields)
            if matched:
                findings.append(self._make_finding(rule, evidence, event))
        return findings

    def _logsource_matches(self, rule: SigmaRule, event: LogEvent) -> bool:
        """Check whether the rule's logsource is compatible with the event source type."""
        ls_key = rule._logsource_key
        compatible = LOGSOURCE_COMPAT.get(ls_key)
        if compatible is None:
            # Partial match — check if any key prefix matches
            for k, v in LOGSOURCE_COMPAT.items():
                if ls_key.startswith(k) or k.startswith(ls_key.split("/")[0]):
                    compatible = v
                    break
        if compatible is None:
            return False
        return event.source_type in compatible or LogSourceType.UNKNOWN in compatible

    def _evaluate_rule(
        self, rule: SigmaRule, event_fields: dict
    ) -> tuple[bool, dict[str, str]]:
        detection = rule.detection

        # Resolve each named selection
        selection_results: dict[str, tuple[bool, dict]] = {}
        for name, spec in detection.items():
            if name == "condition":
                continue
            matched, evidence = self._sel_evaluator.evaluate(spec, event_fields)
            selection_results[name] = (matched, evidence)

        # Evaluate condition string
        condition = detection.get("condition", "selection")
        if isinstance(condition, list):
            condition = " or ".join(str(c) for c in condition)

        parser = ConditionParser(selection_results)
        matched, evidence = parser.evaluate(str(condition))
        return matched, evidence

    def _make_finding(
        self, rule: SigmaRule, evidence: dict[str, str], event: LogEvent
    ) -> Finding:
        tactic = rule.mitre_tactics[0] if rule.mitre_tactics else ""
        technique = rule.mitre_techniques[0] if rule.mitre_techniques else ""

        return Finding(
            rule_id=f"sigma:{rule.rule_id}",
            rule_name=rule.title,
            engine="sigma",
            severity=rule.severity,
            log_source=event.source_type.value,
            matched_fields={k: str(v)[:200] for k, v in evidence.items()},
            raw_line=event.raw[:500],
            timestamp=event.timestamp,
            mitre_tactic=tactic,
            mitre_technique=technique,
            description=rule.description,
            references=list(rule.references),
            false_positive_notes="; ".join(rule.false_positives),
            source_file=event.source_file,
            line_number=event.line_number,
        )
