"""search/event_name_detector.py — Automated event name detection via Drain3 + MITRE mapping."""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("threattrace.search")

# ---------------------------------------------------------------------------
# MITRE ATT&CK keyword map
# ---------------------------------------------------------------------------
MITRE_KEYWORD_MAP: Dict[str, Tuple[str, str]] = {
    "sudo":               ("Privilege Escalation", "T1548.003"),
    "UNION SELECT":       ("Initial Access",        "T1190"),
    "Failed password":    ("Credential Access",     "T1110"),
    "Accepted password":  ("Valid Accounts",        "T1078"),
    "useradd":            ("Persistence",           "T1136.001"),
    "crontab":            ("Persistence",           "T1053.003"),
    "wget":               ("Command and Control",   "T1105"),
    "curl":               ("Command and Control",   "T1105"),
    "base64":             ("Defense Evasion",       "T1140"),
    "mimikatz":           ("Credential Access",     "T1003"),
    "powershell -enc":    ("Defense Evasion",       "T1027"),
    "/etc/shadow":        ("Credential Access",     "T1003.008"),
    "net user":           ("Discovery",             "T1087.001"),
    "whoami":             ("Discovery",             "T1033"),
    "iptables":           ("Defense Evasion",       "T1562.004"),
    "chmod 777":          ("Privilege Escalation",  "T1222"),
    "nc -e":              ("Command and Control",   "T1059"),
    "reverse shell":      ("Command and Control",   "T1059"),
    "CreateRemoteThread": ("Execution",             "T1055"),
    "S3":                 ("Exfiltration",          "T1537"),
}

# ---------------------------------------------------------------------------
# Canonical name map
# ---------------------------------------------------------------------------
CANONICAL_NAME_MAP: Dict[str, str] = {
    "authentication failure": "AUTH_FAILURE",
    "logon failure":          "AUTH_FAILURE",
    "failed password":        "AUTH_FAILURE",
    "invalid user":           "AUTH_INVALID_USER",
    "accepted password":      "AUTH_SUCCESS",
    "new session":            "SESSION_START",
    "session closed":         "SESSION_END",
    "connection refused":     "CONN_REFUSED",
    "port scan":              "NETWORK_PORTSCAN",
    "sql injection":          "WEB_SQLI",
    "web shell":              "WEB_SHELL",
    "privilege escalation":   "PRIV_ESC",
    "brute force":            "BRUTE_FORCE",
    "data exfiltration":      "DATA_EXFIL",
    "c2 beaconing":           "C2_BEACON",
    "ransomware":             "RANSOMWARE",
}


# ---------------------------------------------------------------------------
# EventNameResult dataclass
# ---------------------------------------------------------------------------

@dataclass
class EventNameResult:
    """Result of auto-naming a single log event."""
    record: Any
    template: str
    event_name: str
    canonical_name: Optional[str]
    confidence: str               # "CONFIRMED" | "INFERRED" | "UNKNOWN"
    matched_rule: Optional[str]
    mitre_tactic: Optional[str]
    mitre_technique: Optional[str]
    rarity_score: float
    auto_promoted: bool = False


# ---------------------------------------------------------------------------
# EventNameDetector
# ---------------------------------------------------------------------------

class EventNameDetector:
    """Assign human-readable names to raw log events using Drain3 + MITRE mapping."""

    def __init__(
        self,
        rules_dir: str = "detection/rules",
        templates_path: str = "data/event_templates.json",
        drain_threshold: float = 0.4,
        drain_depth: int = 4,
    ) -> None:
        """Initialise Drain3, load YARA/Sigma rule names, and restore saved templates."""
        self._rules_dir = Path(rules_dir)
        self._templates_path = Path(templates_path)
        self._drain_threshold = drain_threshold
        self._drain_depth = drain_depth
        self._total_events = 0

        # Initialise Drain3
        self._miner = self._init_drain()

        # Load rule/title vocabularies
        self._yara_rule_names: Set[str] = self._load_yara_names()
        self._sigma_titles: List[str] = self._load_sigma_titles()

        # Load or initialise template vocab
        self._template_vocab: Dict[str, Any] = self._load_template_vocab()

    def _init_drain(self):
        """Initialise Drain3 TemplateMiner with graceful degradation."""
        try:
            from drain3 import TemplateMiner
            from drain3.template_miner_config import TemplateMinerConfig

            config = TemplateMinerConfig()
            config.drain_sim_th = self._drain_threshold
            config.drain_depth = self._drain_depth
            config.profiling_enabled = False

            miner = TemplateMiner(config=config)
            logger.info("Drain3 TemplateMiner initialised")
            return miner
        except ImportError:
            logger.warning("drain3 not installed — using simple tokenisation fallback")
            return None

    def _load_yara_names(self) -> Set[str]:
        """Extract YARA rule names from .yar files in rules_dir."""
        names: Set[str] = set()
        yara_dir = self._rules_dir / "yara"
        if not yara_dir.exists():
            # try sibling detection/rules/yara pattern
            yara_dir = self._rules_dir.parent / "yara"
        rule_re = re.compile(r'^\s*rule\s+(\w+)')
        for yar in yara_dir.rglob("*.yar") if yara_dir.exists() else []:
            try:
                for line in yar.read_text(encoding="utf-8", errors="replace").splitlines():
                    m = rule_re.match(line)
                    if m:
                        names.add(m.group(1))
            except OSError:
                pass
        return names

    def _load_sigma_titles(self) -> List[str]:
        """Extract Sigma rule titles from .yml files in rules_dir."""
        titles: List[str] = []
        sigma_dir = self._rules_dir / "sigma"
        title_re = re.compile(r'^title:\s*(.+)$', re.IGNORECASE)
        for yml in sigma_dir.rglob("*.yml") if sigma_dir.exists() else []:
            try:
                for line in yml.read_text(encoding="utf-8", errors="replace").splitlines():
                    m = title_re.match(line)
                    if m:
                        titles.append(m.group(1).strip())
                        break
            except OSError:
                pass
        return titles

    def _load_template_vocab(self) -> Dict[str, Any]:
        """Load or create the template vocabulary JSON file."""
        if self._templates_path.exists():
            try:
                raw = self._templates_path.read_text(encoding="utf-8")
                return json.loads(raw)
            except (json.JSONDecodeError, OSError):
                pass
        return {"templates": [], "version": "1.0"}

    def _save_template_vocab(self) -> None:
        """Persist the template vocabulary to disk."""
        try:
            self._templates_path.parent.mkdir(parents=True, exist_ok=True)
            self._templates_path.write_text(
                json.dumps(self._template_vocab, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("Could not save template vocab: %s", exc)

    # ------------------------------------------------------------------
    # Core detection
    # ------------------------------------------------------------------

    def detect(self, record: Any) -> EventNameResult:
        """Assign a human-readable name to a single LogRecord."""
        raw_line = str(getattr(record, "raw_line", "") or "")
        self._total_events += 1

        # Layer 1: Drain3 template mining
        template, rarity_score, cluster_size = self._mine_template(raw_line)

        # Layer 2: Match to YARA/Sigma rule names
        matched_rule = self._match_to_rule(template, record)

        # Layer 3: Canonical name lookup
        canonical_name = self._canonicalize(template)

        # MITRE inference
        mitre_tactic, mitre_technique = self._infer_mitre(raw_line)

        # Determine confidence
        if matched_rule:
            confidence = "CONFIRMED"
        elif canonical_name:
            confidence = "INFERRED"
        else:
            confidence = "UNKNOWN"

        # Derive human-readable event name
        if matched_rule:
            # Convert snake_case rule name to title case words
            event_name = " ".join(
                w.capitalize() for w in matched_rule.replace("_", " ").split()
            )
        elif canonical_name:
            event_name = canonical_name.replace("_", " ").title()
        else:
            # Best-effort from template
            clean = re.sub(r'<\*+>', '', template).strip()
            event_name = clean[:80] if clean else "Unknown Event"

        # Auto-promote on extreme rarity
        auto_promoted = rarity_score > 0.95

        return EventNameResult(
            record=record,
            template=template,
            event_name=event_name,
            canonical_name=canonical_name,
            confidence=confidence,
            matched_rule=matched_rule,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            rarity_score=rarity_score,
            auto_promoted=auto_promoted,
        )

    def _mine_template(self, raw_line: str) -> Tuple[str, float, int]:
        """Run Drain3 template mining; fall back to simple tokenisation."""
        if self._miner is not None:
            try:
                result = self._miner.add_log_message(raw_line)
                cluster = result.get("cluster") if isinstance(result, dict) else result
                if cluster is not None:
                    size = getattr(cluster, "size", 1) or 1
                    template = cluster.get_template() if hasattr(cluster, "get_template") else raw_line
                    # Rarity: infrequent clusters score near 1.0
                    rarity = max(0.0, min(1.0, 1.0 - (size / max(self._total_events, 1))))
                    return template, rarity, size
            except Exception as exc:
                logger.debug("Drain3 mining error: %s", exc)

        # Simple fallback: tokenise and build pseudo-template
        tokens = raw_line.split()
        pseudo_tokens = []
        for tok in tokens[:20]:
            if re.match(r'^[\d.:/]+$', tok):
                pseudo_tokens.append("<*>")
            else:
                pseudo_tokens.append(tok)
        template = " ".join(pseudo_tokens)
        return template, 0.5, 1

    def _match_to_rule(self, template: str, record: Any) -> Optional[str]:
        """Match template against known YARA/Sigma rule names."""
        template_lower = template.lower()
        # Remove Drain variable placeholders
        tokens = set(re.sub(r'<\*+>', '', template_lower).split())
        tokens = {t for t in tokens if len(t) > 2}

        best_rule: Optional[str] = None
        best_overlap = 0

        # Check YARA rule names
        for rule_name in self._yara_rule_names:
            rule_keywords = set(
                w.lower() for w in re.split(r'[_\s]+', rule_name) if len(w) > 2
            )
            overlap = len(tokens & rule_keywords)
            if overlap > best_overlap:
                best_overlap = overlap
                best_rule = rule_name

        # Check Sigma titles
        for title in self._sigma_titles:
            title_keywords = set(
                w.lower() for w in re.split(r'[\s\-_]+', title) if len(w) > 2
            )
            overlap = len(tokens & title_keywords)
            if overlap > best_overlap:
                best_overlap = overlap
                best_rule = title

        if best_overlap >= 2:
            return best_rule
        return None

    def _canonicalize(self, template: str) -> Optional[str]:
        """Map template to a canonical event name via CANONICAL_NAME_MAP."""
        template_lower = template.lower()
        for key, value in CANONICAL_NAME_MAP.items():
            if key in template_lower:
                return value
        return None

    def _infer_mitre(self, raw_line: str) -> Tuple[Optional[str], Optional[str]]:
        """Infer MITRE ATT&CK tactic and technique from raw log line."""
        raw_lower = raw_line.lower()
        for keyword, (tactic, technique) in MITRE_KEYWORD_MAP.items():
            if keyword.lower() in raw_lower:
                return tactic, technique
        return None, None

    # ------------------------------------------------------------------
    # Batch processing
    # ------------------------------------------------------------------

    def detect_batch(
        self,
        records: List[Any],
        show_progress: bool = True,
    ) -> List[EventNameResult]:
        """Detect event names for a list of records and persist templates."""
        if not records:
            from rich.console import Console
            from rich.panel import Panel
            Console().print(Panel(
                "[yellow]detect_batch: empty records list — returning empty results.[/yellow]",
                border_style="yellow",
            ))
            return []

        results: List[EventNameResult] = []

        if show_progress:
            from rich.progress import track
            iter_records = track(records, description="Naming events…")
        else:
            iter_records = records  # type: ignore[assignment]

        for record in iter_records:
            results.append(self.detect(record))

        # Update template vocab
        if self._miner is not None:
            try:
                clusters = list(self._miner.drain.clusters)
                self._template_vocab["templates"] = [
                    {
                        "template": c.get_template() if hasattr(c, "get_template") else str(c),
                        "size": getattr(c, "size", 0),
                    }
                    for c in clusters
                ]
            except Exception:
                pass

        self._save_template_vocab()
        return results

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    def get_unknown_events(self, results: List[EventNameResult]) -> List[EventNameResult]:
        """Return only UNKNOWN-confidence results sorted by rarity descending."""
        unknown = [r for r in results if r.confidence == "UNKNOWN"]
        unknown.sort(key=lambda r: r.rarity_score, reverse=True)
        return unknown

    def get_vocabulary_summary(self) -> Dict[str, Any]:
        """Return a summary of the current template vocabulary."""
        templates = self._template_vocab.get("templates", [])
        return {
            "total_templates": len(templates),
            "confirmed": sum(
                1 for t in templates
                if self._match_to_rule(t.get("template", ""), None) is not None
            ),
            "inferred": 0,  # Would require re-running canonicalize on each
            "unknown": 0,
            "top_10_templates": [
                t.get("template", "") for t in
                sorted(templates, key=lambda x: x.get("size", 0), reverse=True)[:10]
            ],
        }
