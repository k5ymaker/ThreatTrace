"""
ThreatTrace Sigma Rule Scanner
Loads YAML Sigma rules from detection/rules/sigma/ and evaluates them against
normalised event dicts.
"""

import logging
import re
import fnmatch
import warnings
from pathlib import Path
from collections import defaultdict
from typing import Any, Optional

logger = logging.getLogger(__name__)

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    warnings.warn(
        "PyYAML is not installed. Sigma scanning will be disabled. "
        "Install with: pip install pyyaml",
        RuntimeWarning,
        stacklevel=2,
    )

_RULES_DIR = Path(__file__).parent / "rules" / "sigma"
_rules_count = 0

# ---------------------------------------------------------------------------
# Field name mapping: Sigma → normalised event dict key
# ---------------------------------------------------------------------------
FIELD_MAP: dict[str, str] = {
    # HTTP/Web
    "cs-uri-query": "url",
    "cs-uri-stem": "url",
    "http.url": "url",
    "c-uri": "url",
    "url": "url",
    "http.method": "method",
    "cs-method": "method",
    "method": "method",
    "cs-username": "username",
    "sc-status": "status_code",
    "http.status": "status_code",
    "status_code": "status_code",
    "http.user_agent": "user_agent",
    "cs(User-Agent)": "user_agent",
    "user_agent": "user_agent",
    # Windows
    "EventID": "event_id",
    "event_id": "event_id",
    "LogonType": "fields.LogonType",
    "AuthenticationPackageName": "fields.AuthenticationPackageName",
    "WorkstationName": "fields.WorkstationName",
    "TargetComputerName": "fields.TargetComputerName",
    "IpAddress": "source_ip",
    "CommandLine": "command_line",
    "NewProcessName": "process_name",
    "TargetImage": "fields.TargetImage",
    "GrantedAccess": "fields.GrantedAccess",
    "TaskContent": "fields.TaskContent",
    "ImagePath": "fields.ImagePath",
    "ServiceName": "fields.ServiceName",
    "TicketEncryptionType": "fields.TicketEncryptionType",
    "AccessMask": "fields.AccessMask",
    "Properties": "fields.Properties",
    # Linux
    "message": "raw",
    "msg": "raw",
    "exe": "process_name",
    "comm": "process_name",
    "type": "fields.type",
    "syscall": "fields.syscall",
    "path": "fields.path",
    "uid": "fields.uid",
    # Cloud
    "eventName": "event_name",
    "eventSource": "fields.eventSource",
    "userIdentity.type": "fields.userIdentity_type",
    "sourceIPAddress": "source_ip",
    "methodName": "fields.methodName",
    "operationName": "event_name",
    "resultType": "fields.resultType",
    "riskLevelDuringSignIn": "fields.riskLevel",
    # Generic
    "source_ip": "source_ip",
    "dest_ip": "dest_ip",
    "action": "action",
    "hostname": "hostname",
    "bytes_sent": "bytes_sent",
    "query_name": "fields.query_name",
    "query_type": "fields.query_type",
}


def _get_event_field(event: dict, sigma_field: str) -> Any:
    """
    Resolve a Sigma field name to its value in the normalised event dict.
    Supports dotted paths into a nested "fields" sub-dict.
    """
    mapped = FIELD_MAP.get(sigma_field, sigma_field)
    if mapped.startswith("fields."):
        sub_key = mapped[len("fields."):]
        return event.get("fields", {}).get(sub_key)
    return event.get(mapped)


def _val_as_str(val: Any) -> str:
    """Coerce a field value to string for comparison."""
    if val is None:
        return ""
    return str(val)


def _wildcard_match(pattern: str, value: str) -> bool:
    """Match using fnmatch-style wildcards (* and ?)."""
    return fnmatch.fnmatch(value.lower(), pattern.lower())


def _apply_modifier(modifier: str, field_val: str, test_val: str) -> bool:
    """Apply a single Sigma modifier to field_val vs test_val."""
    if modifier == "contains":
        return test_val.lower() in field_val.lower()
    if modifier == "startswith":
        return field_val.lower().startswith(test_val.lower())
    if modifier == "endswith":
        return field_val.lower().endswith(test_val.lower())
    if modifier == "re":
        try:
            return bool(re.search(test_val, field_val, re.IGNORECASE))
        except re.error:
            return False
    # Default: exact / wildcard
    if "*" in test_val or "?" in test_val:
        return _wildcard_match(test_val, field_val)
    return field_val.lower() == test_val.lower()


def _parse_field_key(key: str) -> tuple[str, list[str]]:
    """
    Split 'field|mod1|mod2' into (field_name, [mod1, mod2]).
    """
    parts = key.split("|")
    return parts[0], parts[1:]


class SigmaEvaluator:
    """Evaluates Sigma rules against normalised event lists."""

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def evaluate(self, rule: dict, events: list[dict]) -> list[dict]:
        """Evaluate a single Sigma rule against all events, return matching events."""
        detection = rule.get("detection", {})
        if not detection:
            return []

        condition_str = str(detection.get("condition", "selection"))

        # Build selection name -> matching event list
        selections: dict[str, list[dict]] = {}
        for key, val in detection.items():
            if key == "condition":
                continue
            # Each key in detection (other than condition) is a selection name
            selections[key] = [e for e in events if self._match_selection_block(val, e)]

        # Evaluate the condition expression
        return self._evaluate_condition(condition_str, selections, events)

    # -----------------------------------------------------------------------
    # Selection matching
    # -----------------------------------------------------------------------

    def _match_selection_block(self, block: Any, event: dict) -> bool:
        """
        A block can be:
          - dict  → all keys must match (AND)
          - list  → any element must match (OR)
          - str   → raw value match against "raw" / "event_name"
        """
        if isinstance(block, dict):
            return self._match_detection(block, event)
        if isinstance(block, list):
            return any(self._match_selection_block(item, event) for item in block)
        if isinstance(block, str):
            raw = _val_as_str(event.get("raw", ""))
            return block.lower() in raw.lower()
        return False

    def _match_detection(self, detection: dict, event: dict) -> bool:
        """
        Evaluate a detection dict (one selection group) against one event.
        All top-level keys must match (AND semantics within a dict).
        """
        for key, val in detection.items():
            field_name, modifiers = _parse_field_key(key)
            field_val = _val_as_str(_get_event_field(event, field_name))

            if not modifiers:
                # Plain value or list of values (OR)
                if not self._plain_match(field_val, val):
                    return False
            elif "all" in modifiers:
                # field|contains|all: [list] — all must match
                sub_mod = [m for m in modifiers if m != "all"]
                primary_mod = sub_mod[0] if sub_mod else "contains"
                values = val if isinstance(val, list) else [val]
                if not all(_apply_modifier(primary_mod, field_val, str(v)) for v in values):
                    return False
            elif "any" in modifiers:
                # field|contains|any: [list] — any must match
                sub_mod = [m for m in modifiers if m != "any"]
                primary_mod = sub_mod[0] if sub_mod else "contains"
                values = val if isinstance(val, list) else [val]
                if not any(_apply_modifier(primary_mod, field_val, str(v)) for v in values):
                    return False
            else:
                # Single modifier
                primary_mod = modifiers[0]
                if not self._modifier_match(primary_mod, field_val, val):
                    return False
        return True

    def _plain_match(self, field_val: str, val: Any) -> bool:
        """Exact match (with wildcard support) against a value or list of values (OR)."""
        if isinstance(val, list):
            return any(self._plain_match(field_val, v) for v in val)
        test_val = str(val)
        if "*" in test_val or "?" in test_val:
            return _wildcard_match(test_val, field_val)
        return field_val.lower() == test_val.lower()

    def _modifier_match(self, modifier: str, field_val: str, val: Any) -> bool:
        """Apply modifier to a value or list of values (OR over list)."""
        if isinstance(val, list):
            return any(_apply_modifier(modifier, field_val, str(v)) for v in val)
        return _apply_modifier(modifier, field_val, str(val))

    # -----------------------------------------------------------------------
    # Condition evaluation
    # -----------------------------------------------------------------------

    def _evaluate_condition(
        self, condition: str, selections: dict[str, list[dict]], events: list[dict]
    ) -> list[dict]:
        """
        Parse and evaluate the Sigma condition string.
        Supported forms:
          selection
          all of them
          1 of them
          1 of selection_*
          all of selection_*
          selection and not filter
          selection1 or selection2
          selection1 and selection2
          count() by field > N  (aggregation)
        Returns list of matching events.
        """
        cond = condition.strip()

        # --- count() aggregation ---
        count_match = re.match(
            r"count\(\s*\)\s*(?:by\s+(\w+)\s+)?([><=!]+)\s*(\d+)", cond, re.IGNORECASE
        )
        if count_match:
            group_field = count_match.group(1)
            operator = count_match.group(2)
            threshold = int(count_match.group(3))
            sel_events = selections.get("selection", events)
            return self._count_aggregation(sel_events, group_field, operator, threshold)

        # --- "all of them" / "1 of them" ---
        if re.fullmatch(r"all\s+of\s+them", cond, re.IGNORECASE):
            result = list(events)
            for sel_events in selections.values():
                sel_set = {id(e) for e in sel_events}
                result = [e for e in result if id(e) in sel_set]
            return result

        num_match = re.fullmatch(r"(\d+)\s+of\s+them", cond, re.IGNORECASE)
        if num_match:
            n = int(num_match.group(1))
            return self._n_of_selections(list(selections.values()), n, events)

        # --- "N of selection_*" / "all of selection_*" ---
        n_of_pattern = re.fullmatch(
            r"(\d+|all)\s+of\s+([\w\*]+)", cond, re.IGNORECASE
        )
        if n_of_pattern:
            quantifier = n_of_pattern.group(1).lower()
            pattern = n_of_pattern.group(2)
            matched_sels = [
                v for k, v in selections.items()
                if fnmatch.fnmatch(k.lower(), pattern.lower())
            ]
            if quantifier == "all":
                result = list(events)
                for sel_events in matched_sels:
                    sel_set = {id(e) for e in sel_events}
                    result = [e for e in result if id(e) in sel_set]
                return result
            return self._n_of_selections(matched_sels, int(quantifier), events)

        # --- Tokenised boolean expression ---
        return self._eval_bool_expr(cond, selections, events)

    def _count_aggregation(
        self,
        events: list[dict],
        group_field: Optional[str],
        operator: str,
        threshold: int,
    ) -> list[dict]:
        """Return events where count (optionally grouped) satisfies the threshold."""
        if group_field:
            groups: dict[str, list[dict]] = defaultdict(list)
            for e in events:
                key = _val_as_str(_get_event_field(e, group_field))
                groups[key].append(e)
            result = []
            for grp_events in groups.values():
                if self._compare(len(grp_events), operator, threshold):
                    result.extend(grp_events)
            return result
        if self._compare(len(events), operator, threshold):
            return events
        return []

    @staticmethod
    def _compare(count: int, operator: str, threshold: int) -> bool:
        ops = {">": count > threshold, ">=": count >= threshold,
               "<": count < threshold, "<=": count <= threshold,
               "=": count == threshold, "==": count == threshold,
               "!=": count != threshold}
        return ops.get(operator, False)

    def _n_of_selections(
        self, sel_lists: list[list[dict]], n: int, events: list[dict]
    ) -> list[dict]:
        """Return events that appear in at least n of the given selection lists."""
        from collections import Counter
        id_counts: Counter = Counter()
        id_to_event: dict[int, dict] = {}
        for sel in sel_lists:
            for e in sel:
                id_counts[id(e)] += 1
                id_to_event[id(e)] = e
        return [id_to_event[eid] for eid, cnt in id_counts.items() if cnt >= n]

    def _eval_bool_expr(
        self, expr: str, selections: dict[str, list[dict]], events: list[dict]
    ) -> list[dict]:
        """
        Simple recursive descent for boolean expressions:
        Supports: AND, OR, NOT, parentheses, selection names.
        """
        expr = expr.strip()

        # Strip outer parentheses
        if expr.startswith("(") and expr.endswith(")"):
            inner = expr[1:-1].strip()
            # Ensure the parens are matched around the whole expr
            depth = 0
            balanced_at = -1
            for i, ch in enumerate(inner):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                if depth < 0:
                    balanced_at = i
                    break
            if balanced_at == -1:
                return self._eval_bool_expr(inner, selections, events)

        # Split on OR (lowest precedence)
        or_parts = self._split_on_keyword(expr, "or")
        if len(or_parts) > 1:
            result_set: set[int] = set()
            id_to_event: dict[int, dict] = {}
            for part in or_parts:
                for e in self._eval_bool_expr(part.strip(), selections, events):
                    result_set.add(id(e))
                    id_to_event[id(e)] = e
            return [id_to_event[eid] for eid in result_set]

        # Split on AND
        and_parts = self._split_on_keyword(expr, "and")
        if len(and_parts) > 1:
            result = list(events)
            for part in and_parts:
                part = part.strip()
                negate = False
                if part.lower().startswith("not "):
                    negate = True
                    part = part[4:].strip()
                part_events = self._eval_bool_expr(part, selections, events)
                part_ids = {id(e) for e in part_events}
                if negate:
                    result = [e for e in result if id(e) not in part_ids]
                else:
                    result = [e for e in result if id(e) in part_ids]
            return result

        # NOT prefix
        if expr.lower().startswith("not "):
            sub = expr[4:].strip()
            sub_events = self._eval_bool_expr(sub, selections, events)
            sub_ids = {id(e) for e in sub_events}
            return [e for e in events if id(e) not in sub_ids]

        # Base case: selection name
        name = expr.strip()
        if name in selections:
            return selections[name]

        # Wildcard selection name (e.g. selection_*)
        matched = []
        for k, v in selections.items():
            if fnmatch.fnmatch(k.lower(), name.lower()):
                matched.extend(v)
        return matched

    @staticmethod
    def _split_on_keyword(expr: str, keyword: str) -> list[str]:
        """
        Split expr on a boolean keyword (and/or) that is not inside parentheses.
        Comparison is case-insensitive.
        """
        parts = []
        depth = 0
        current = []
        kw = keyword.lower()
        kw_len = len(kw)
        i = 0
        tokens = expr.split()
        reconstructed = " ".join(tokens)
        chars = reconstructed + " "
        i = 0
        n = len(chars)
        buf = []
        while i < n:
            ch = chars[i]
            if ch == "(":
                depth += 1
                buf.append(ch)
                i += 1
            elif ch == ")":
                depth -= 1
                buf.append(ch)
                i += 1
            elif depth == 0:
                # Check if we have the keyword here (surrounded by spaces/start/end)
                remaining = chars[i:]
                kw_padded = kw + " "
                if remaining.lower().startswith(kw_padded):
                    parts.append("".join(buf).strip())
                    buf = []
                    i += len(kw_padded)
                else:
                    buf.append(ch)
                    i += 1
            else:
                buf.append(ch)
                i += 1
        last = "".join(buf).strip()
        if last:
            parts.append(last)
        return parts if len(parts) > 1 else [expr]


# ---------------------------------------------------------------------------
# Module-level scan state
# ---------------------------------------------------------------------------
_loaded_rules: list[dict] = []
_rules_loaded = False


def _load_rules() -> list[dict]:
    global _loaded_rules, _rules_loaded, _rules_count
    if _rules_loaded:
        return _loaded_rules

    if not YAML_AVAILABLE:
        _rules_loaded = True
        return []

    if not _RULES_DIR.exists():
        logger.warning("Sigma rules directory does not exist: %s", _RULES_DIR)
        _rules_loaded = True
        return []

    rules = []
    for yfile in sorted(_RULES_DIR.rglob("*.yml")):
        try:
            with open(yfile, "r", encoding="utf-8") as fh:
                docs = list(yaml.safe_load_all(fh))
            for doc in docs:
                if isinstance(doc, dict) and "detection" in doc:
                    rules.append(doc)
        except Exception as exc:
            logger.warning("Sigma: failed to load %s — %s", yfile.name, exc)

    _loaded_rules = rules
    _rules_count = len(rules)
    _rules_loaded = True
    logger.info("Sigma: loaded %d rules.", len(rules))
    return rules


def get_rules_count() -> int:
    _load_rules()
    return _rules_count


def _build_finding(rule: dict, matched_events: list[dict], finding_index: int) -> dict:
    """Convert a Sigma rule + matched events into a standardised finding dict."""
    tags = rule.get("tags", []) or []
    mitre_tactic = ""
    mitre_technique = ""
    for tag in tags:
        tag = str(tag)
        if tag.startswith("attack.t"):
            mitre_technique = tag.replace("attack.", "").upper()
        elif tag.startswith("attack."):
            mitre_tactic = tag.replace("attack.", "").replace("_", " ").title()

    level = str(rule.get("level", "medium")).upper()
    severity_map = {
        "CRITICAL": "CRITICAL", "HIGH": "HIGH",
        "MEDIUM": "MEDIUM", "LOW": "LOW", "INFORMATIONAL": "INFO",
    }
    severity = severity_map.get(level, "MEDIUM")

    timestamps = sorted(
        set(e.get("timestamp", "") for e in matched_events if e.get("timestamp", ""))
    )
    first_seen = timestamps[0] if timestamps else ""
    last_seen = timestamps[-1] if timestamps else ""

    ips = list(dict.fromkeys(e.get("source_ip", "") for e in matched_events if e.get("source_ip")))
    usernames = list(dict.fromkeys(e.get("username", "") for e in matched_events if e.get("username")))
    user_agents = list(dict.fromkeys(e.get("user_agent", "") for e in matched_events if e.get("user_agent")))
    urls = list(dict.fromkeys(e.get("url", "") for e in matched_events if e.get("url")))
    commands = list(dict.fromkeys(e.get("command_line", "") for e in matched_events if e.get("command_line")))
    file_paths = list(dict.fromkeys(
        e.get("process_name", "") for e in matched_events
        if e.get("process_name") and ("/" in e.get("process_name", "") or "\\" in e.get("process_name", ""))
    ))

    return {
        "finding_id": f"TT-F-{finding_index:03d}",
        "rule_name": rule.get("title", rule.get("name", "Unknown Sigma Rule")),
        "rule_type": "SIGMA",
        "severity": severity,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "description": rule.get("description", ""),
        "matched_events": matched_events,
        "count": len(matched_events),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "indicators": {
            "ips": ips,
            "usernames": usernames,
            "user_agents": user_agents,
            "urls": urls,
            "commands": commands,
            "file_paths": file_paths,
        },
    }


def scan(events: list[dict], log_type: str = "") -> list[dict]:
    """
    Main entry point for Sigma scanning.
    Returns a list of finding dicts.
    """
    rules = _load_rules()
    if not rules:
        return []

    evaluator = SigmaEvaluator()
    findings: list[dict] = []
    idx = 1

    for rule in rules:
        try:
            matched = evaluator.evaluate(rule, events)
        except Exception as exc:
            logger.warning(
                "Sigma: error evaluating rule '%s' — %s",
                rule.get("title", "unknown"),
                exc,
            )
            matched = []

        if matched:
            findings.append(_build_finding(rule, matched, idx))
            idx += 1

    return findings
