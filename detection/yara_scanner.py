"""
ThreatTrace YARA Scanner
Discovers and compiles .yar rules, scans raw file content and individual event raw fields.
"""

import logging
import warnings
from pathlib import Path
from collections import defaultdict
from typing import Optional

logger = logging.getLogger(__name__)

# Module-level state
_compiled_rules = None
_rules_count = 0
_RULES_DIR = Path(__file__).parent / "rules" / "yara"

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    warnings.warn(
        "yara-python is not installed. YARA scanning will be disabled. "
        "Install with: pip install yara-python",
        RuntimeWarning,
        stacklevel=2,
    )


def _discover_rule_files() -> list[Path]:
    """Return all .yar files under the rules/yara directory."""
    if not _RULES_DIR.exists():
        logger.warning("YARA rules directory does not exist: %s", _RULES_DIR)
        return []
    return sorted(_RULES_DIR.rglob("*.yar"))


def _compile_rules() -> Optional["yara.Rules"]:
    """
    Attempt to compile all .yar files together; fall back to per-file compilation
    and collect all that succeed.
    """
    global _compiled_rules, _rules_count

    if not YARA_AVAILABLE:
        return None

    rule_files = _discover_rule_files()
    if not rule_files:
        logger.info("No YARA rule files found in %s", _RULES_DIR)
        _rules_count = 0
        return None

    # Attempt combined compilation first
    filepaths = {f"ns_{i}": str(f) for i, f in enumerate(rule_files)}
    try:
        compiled = yara.compile(filepaths=filepaths)
        _rules_count = len(rule_files)
        logger.info("YARA: compiled %d rule files successfully.", len(rule_files))
        return compiled
    except yara.SyntaxError as exc:
        logger.warning("YARA combined compilation failed (%s). Falling back to per-file.", exc)

    # Per-file fallback
    good_rules: list["yara.Rules"] = []
    for f in rule_files:
        try:
            r = yara.compile(filepath=str(f))
            good_rules.append(r)
        except yara.SyntaxError as e:
            logger.warning("YARA: skipping %s — %s", f.name, e)

    if not good_rules:
        logger.error("YARA: all rule files failed to compile.")
        _rules_count = 0
        return None

    _rules_count = len(good_rules)
    logger.info("YARA: compiled %d/%d rule files (per-file fallback).", len(good_rules), len(rule_files))

    # Wrap list in a simple container that mimics yara.Rules.match()
    class _MultiRules:
        def __init__(self, rules_list):
            self._rules = rules_list

        def match(self, data: bytes) -> list:
            matches = []
            for r in self._rules:
                try:
                    matches.extend(r.match(data=data))
                except Exception:
                    pass
            return matches

    return _MultiRules(good_rules)


def _get_compiled() -> Optional[object]:
    global _compiled_rules
    if _compiled_rules is None:
        _compiled_rules = _compile_rules()
    return _compiled_rules


def get_rules_count() -> int:
    """Return the number of rule files that were successfully compiled."""
    _get_compiled()  # ensure compilation has happened
    return _rules_count


def _extract_meta(match) -> dict:
    """Pull meta fields from a YARA match object."""
    meta = getattr(match, "meta", {}) or {}
    return {
        "severity": str(meta.get("severity", "HIGH")).upper(),
        "mitre_tactic": str(meta.get("mitre_tactic", "")),
        "mitre_technique": str(meta.get("mitre_technique", "")),
        "description": str(meta.get("description", match.rule)),
    }


def _build_finding(
    rule_name: str,
    meta: dict,
    matched_events: list[dict],
    finding_index: int,
) -> dict:
    """Build a standardised finding dict from matched events."""
    timestamps = []
    ips, usernames, user_agents, urls, commands, file_paths = [], [], [], [], [], []

    for ev in matched_events:
        ts = ev.get("timestamp", "")
        if ts:
            timestamps.append(ts)
        ip = ev.get("source_ip", "")
        if ip and ip not in ips:
            ips.append(ip)
        usr = ev.get("username", "")
        if usr and usr not in usernames:
            usernames.append(usr)
        ua = ev.get("user_agent", "")
        if ua and ua not in user_agents:
            user_agents.append(ua)
        url = ev.get("url", "")
        if url and url not in urls:
            urls.append(url)
        cmd = ev.get("command_line", "")
        if cmd and cmd not in commands:
            commands.append(cmd)
        # file paths heuristic: process_name that looks like a path
        proc = ev.get("process_name", "")
        if proc and ("/" in proc or "\\" in proc) and proc not in file_paths:
            file_paths.append(proc)

    timestamps_sorted = sorted(set(timestamps))
    first_seen = timestamps_sorted[0] if timestamps_sorted else ""
    last_seen = timestamps_sorted[-1] if timestamps_sorted else ""

    return {
        "finding_id": f"TT-F-{finding_index:03d}",
        "rule_name": rule_name,
        "rule_type": "YARA",
        "severity": meta["severity"],
        "mitre_tactic": meta["mitre_tactic"],
        "mitre_technique": meta["mitre_technique"],
        "description": meta["description"],
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


def scan(events: list[dict], log_type: str = "", raw_file_content: bytes = b"") -> list[dict]:
    """
    Main entry point for YARA scanning.

    Scans:
      (a) raw_file_content as a whole (if provided)
      (b) each event's "raw" field as a UTF-8 encoded byte string

    Returns a list of finding dicts.
    """
    if not YARA_AVAILABLE:
        return []

    rules = _get_compiled()
    if rules is None:
        return []

    # ------- (a) Whole-file scan -------
    file_hits: dict[str, list] = defaultdict(list)  # rule_name -> [match]
    if raw_file_content:
        try:
            matches = rules.match(data=raw_file_content)
            for m in matches:
                file_hits[m.rule].append(m)
        except Exception as exc:
            logger.warning("YARA whole-file scan error: %s", exc)

    # ------- (b) Per-event scan -------
    # rule_name -> list of events that triggered it
    event_hits: dict[str, list[dict]] = defaultdict(list)
    meta_cache: dict[str, dict] = {}

    for event in events:
        raw = event.get("raw", "")
        if not raw:
            continue
        try:
            data = raw.encode("utf-8", errors="replace")
            matches = rules.match(data=data)
            for m in matches:
                rname = m.rule
                if rname not in meta_cache:
                    meta_cache[rname] = _extract_meta(m)
                event_hits[rname].append(event)
        except Exception as exc:
            logger.debug("YARA event scan error: %s", exc)

    # Also record meta from whole-file hits
    for rname, match_list in file_hits.items():
        if rname not in meta_cache and match_list:
            meta_cache[rname] = _extract_meta(match_list[0])

    # ------- Build findings -------
    findings: list[dict] = []
    all_rule_names = set(file_hits.keys()) | set(event_hits.keys())
    idx = 1
    for rname in sorted(all_rule_names):
        matched_events = event_hits.get(rname, [])
        meta = meta_cache.get(rname, {
            "severity": "HIGH",
            "mitre_tactic": "",
            "mitre_technique": "",
            "description": rname,
        })
        # If the whole-file scan matched but no individual events did, create a
        # synthetic event entry so there is always something in matched_events.
        if not matched_events and rname in file_hits:
            matched_events = [{"raw": "[whole-file match]", "event_name": rname}]

        findings.append(_build_finding(rname, meta, matched_events, idx))
        idx += 1

    return findings
