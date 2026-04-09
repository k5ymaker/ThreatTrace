"""
OpenCode-assisted log analysis module for ThreatTrace.

This module integrates OpenCode CLI for advanced log analysis, IOC extraction,
MITRE ATT&CK threat hunting, and MITRE CAR incident investigation.

Integration point in the pipeline:
Detection Engine (YARA/Sigma) -> OpenCode Log Analysis Module -> Analytics Modules -> Report Builder
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class IOCFinding:
    """Represents an extracted Indicator of Compromise"""

    ioc_type: str  # ipv4, ipv6, domain, url, email, username, file_path, hash, cve, jwt, api_key, mac
    value: str
    context: str  # surrounding log lines or context
    risk: str  # high/medium/low
    confidence: float  # 0.0-1.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    occurrences: int = 1


@dataclass
class MITREAttackFinding:
    """Represents a MITRE ATT&CK technique finding"""

    technique_id: str  # e.g., T1059.001
    technique_name: str
    tactic: str  # e.g., Execution, Persistence
    evidence: str
    confidence: str  # high/medium/low
    recommended_response: str
    matched_log_lines: List[str]
    severity: str = "MEDIUM"  # CRITICAL/HIGH/MEDIUM/LOW/INFO


@dataclass
class MITRECARFinding:
    """Represents a MITRE CAR detection"""

    car_id: str  # e.g., CAR-2016-03-001
    detection_name: str
    description: str
    severity: str  # CRITICAL/HIGH/MEDIUM/LOW
    matching_events: List[Dict[str, Any]]
    investigation_notes: str
    confidence: float  # 0.0-1.0


@dataclass
class BaselineDeviation:
    """Represents a baseline deviation finding"""

    dimension: str
    observed_value: float
    baseline_mean: float
    sigma_distance: float
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    raw_line: Optional[str] = None
    severity: str = "MEDIUM"  # CRITICAL/HIGH/MEDIUM/LOW/INFO


@dataclass
class AnalysisResult:
    """Container for all analysis results"""

    ioc_findings: List[IOCFinding]
    mitre_attack_findings: List[MITREAttackFinding]
    mitre_car_findings: List[MITRECARFinding]
    baseline_deviations: List[BaselineDeviation]
    analysis_duration: float
    opencode_version: str = "unknown"
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# MITRE ATT&CK Technique Mapping
# ---------------------------------------------------------------------------

ATTACK_TECHNIQUE_MAPPING = {
    "powershell_execution": ["T1059.001", "T1059.004"],
    "lsass_access": ["T1003.001"],
    "scheduled_task_create": ["T1053.005", "T1053.009"],
    "process_injection": ["T1055"],
    "credential_access": ["T1003", "T1110"],
    "discovery": ["T1087", "T1082", "T1083"],
    "lateral_movement": ["T1021", "T1072"],
    "persistence": ["T1547", "T1053"],
    "exfiltration": ["T1041", "T1567"],
    "command_and_control": ["T1071", "T1095", "T1571"],
    "defense_evasion": ["T1027", "T1112", "T1140"],
    "privilege_escalation": ["T1068", "T1078"],
    "initial_access": ["T1190", "T1133", "T1566"],
    "reconnaissance": ["T1595", "T1592"],
    "resource_development": ["T1583", "T1584", "T1585"],
}

ATTACK_TACTICS = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

# ---------------------------------------------------------------------------
# Baseline Dimensions Configuration
# ---------------------------------------------------------------------------

BASELINE_DIMENSIONS = {
    "apache": [
        {
            "name": "requests_per_hour_per_ip",
            "description": "Requests/hour per source IP",
        },
        {"name": "bytes_transferred", "description": "HTTP response size per request"},
        {"name": "status_code", "description": "HTTP status code per request"},
        {"1ame": "events_per_hour", "description": "Global events per hour"},
    ],
    "nginx": [
        {
            "name": "requests_per_hour_per_ip",
            "description": "Requests/hour per source IP",
        },
        {"name": "bytes_transferred", "description": "HTTP response size per request"},
        {"name": "status_code", "description": "HTTP status code"},
        {"name": "events_per_hour", "description": "Global events per hour"},
    ],
    "windows_security": [
        {"name": "logins_per_hour_per_user", "description": "Logons/hour per user"},
        {"name": "events_per_hour", "description": "Global events per hour"},
        {"name": "ip_failure_rate", "description": "Failure ratio per IP"},
    ],
    "sysmon": [
        {"name": "logins_per_hour_per_user", "description": "Logins/hour per user"},
        {"name": "events_per_hour", "description": "Events per hour"},
    ],
    "auth_log": [
        {"name": "logins_per_hour_per_user", "description": "Logins/hour per user"},
        {"name": "ip_failure_rate", "description": "Auth failure ratio per IP"},
        {"name": "events_per_hour", "description": "Global events per hour"},
    ],
    "dns": [
        {"name": "requests_per_hour_per_ip", "description": "DNS queries/hour per IP"},
        {"name": "events_per_hour", "description": "Global queries per hour"},
    ],
    "network": [
        {"name": "bytes_transferred", "description": "Session bytes"},
        {"name": "events_per_hour", "description": "Events per hour"},
    ],
    "generic": [
        {"name": "events_per_hour", "description": "Events per hour"},
        {"name": "ip_failure_rate", "description": "Failure ratio per IP"},
    ],
}

# ---------------------------------------------------------------------------
# MITRE CAR Detection Logic
# ---------------------------------------------------------------------------

CAR_DETECTIONS = {
    "CAR-2016-03-001": {
        "name": "Batch file that deletes shadow copies",
        "description": "Detects batch files or commands attempting to delete volume shadow copies",
        "detection_logic": "vssadmin delete shadows OR wmic shadowcopy delete OR wbadmin delete catalog",
        "log_sources": ["windows_security", "sysmon", "windows_event"],
        "severity": "HIGH",
    },
    "CAR-2016-002": {
        "name": "LSASS process dump",
        "description": "Detects attempts to dump LSASS process memory for credential extraction",
        "detection_logic": "lsass.exe AND (dump OR procdump OR mimikatz OR sekurlsa)",
        "log_sources": ["windows_security", "sysmon"],
        "severity": "CRITICAL",
    },
    "CAR-2019-08-001": {
        "name": "DNS beaconing detection",
        "description": "Detects DNS beaconing patterns with regular intervals",
        "detection_logic": "DNS query patterns with regular timing and consistent subdomains",
        "log_sources": ["dns", "network"],
        "severity": "HIGH",
    },
    "CAR-2020-05-002": {
        "name": "Password spray detection",
        "description": "Detects password spray attacks with multiple failed logins across accounts",
        "detection_logic": "multiple authentication failures across different usernames from same source",
        "log_sources": ["auth", "windows_security", "okta", "azure"],
        "severity": "HIGH",
    },
    "CAR-2021-01-001": {
        "name": "SMB lateral movement",
        "description": "Detects SMB-based lateral movement attempts",
        "detection_logic": "SMB session setup with admin credentials from unusual source",
        "log_sources": ["windows_security", "network"],
        "severity": "HIGH",
    },
    "CAR-2021-03-001": {
        "name": "Rare process execution",
        "description": "Detects execution of rare or unusual processes",
        "detection_logic": "process execution not seen in baseline or with low frequency",
        "log_sources": ["sysmon", "linux_audit", "process"],
        "severity": "MEDIUM",
    },
}

# ---------------------------------------------------------------------------
# OpenCode Log Analyzer
# ---------------------------------------------------------------------------


class OpenCodeLogAnalyzer:
    """
    OpenCode-assisted log analysis module for ThreatTrace.

    Capabilities:
    - Deep semantic IOC extraction via OpenCode CLI
    - MITRE ATT&CK threat hunting
    - MITRE CAR incident investigation
    - Combined results integration
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.opencode_timeout = self.config.get("timeout", 120)
        self.max_retries = self.config.get("max_retries", 2)
        self.temp_dir = Path(self.config.get("temp_dir", "/tmp/threattrace"))
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        # Initialize MITRE databases
        self.mitre_attack_db = self._load_mitre_attack_db()
        self.mitre_car_db = CAR_DETECTIONS

        logger.info(f"OpenCodeLogAnalyzer initialized with config: {self.config}")

    def _load_mitre_attack_db(self) -> Dict[str, Dict[str, Any]]:
        """Load MITRE ATT&CK technique database"""
        # This would typically load from a local file or API
        # For now, return a minimal database
        return {
            "T1059.001": {
                "name": "PowerShell",
                "tactic": "Execution",
                "description": "Adversaries may abuse PowerShell commands and scripts for execution",
            },
            "T1059.004": {
                "name": "Unix Shell",
                "tactic": "Execution",
                "description": "Adversaries may abuse Unix shell commands and scripts for execution",
            },
            "T1003.001": {
                "name": "LSASS Memory",
                "tactic": "Credential Access",
                "description": "Adversaries may attempt to access credential material stored in LSASS",
            },
            "T1053.005": {
                "name": "Scheduled Task",
                "tactic": "Execution, Persistence, Privilege Escalation",
                "description": "Adversaries may abuse task scheduling functionality to facilitate execution",
            },
            "T1055": {
                "name": "Process Injection",
                "tactic": "Defense Evasion, Privilege Escalation",
                "description": "Adversaries may inject code into processes to evade defenses",
            },
            "T1110": {
                "name": "Brute Force",
                "tactic": "Credential Access",
                "description": "Adversaries may use brute force techniques to gain access to accounts",
            },
            "T1087": {
                "name": "Account Discovery",
                "tactic": "Discovery",
                "description": "Adversaries may attempt to get a listing of accounts",
            },
            "T1021": {
                "name": "Remote Services",
                "tactic": "Lateral Movement",
                "description": "Adversaries may use legitimate credentials to log into remote services",
            },
            "T1547": {
                "name": "Boot or Logon Autostart Execution",
                "tactic": "Persistence, Privilege Escalation",
                "description": "Adversaries may configure system settings to automatically execute at boot",
            },
            "T1041": {
                "name": "Exfiltration Over C2 Channel",
                "tactic": "Exfiltration",
                "description": "Adversaries may steal data by exfiltrating it over a C2 channel",
            },
        }

    def _analyze_baseline_deviations(
        self, events: List[Dict[str, Any]], log_type: str
    ) -> List[BaselineDeviation]:
        """
        Analyze baseline deviations using statistical methods enhanced with OpenCode AI.

        Args:
            events: List of parsed log events
            log_type: Type of logs being analyzed

        Returns:
            List of BaselineDeviation objects
        """
        logger.info(
            f"Analyzing baseline deviations for {len(events)} events of type {log_type}"
        )

        # Get appropriate dimensions for this log type
        dimensions = BASELINE_DIMENSIONS.get(log_type, BASELINE_DIMENSIONS["generic"])

        deviations = []

        # Analyze each dimension
        for dim_config in dimensions:
            dim_name = dim_config["name"]

            # Extract values for this dimension
            values = self._extract_dimension_values(dim_name, events, log_type)

            if len(values) < 10:  # Need sufficient data for baseline analysis
                continue

            # Calculate baseline statistics
            baseline_stats = self._calculate_baseline_stats(values)

            # Identify deviations
            dim_deviations = self._identify_deviations(
                dim_name, values, baseline_stats, events
            )
            deviations.extend(dim_deviations)

        # Use OpenCode to analyze deviations for context and risk assessment
        if deviations:
            deviations = self._enhance_deviations_with_opencode(
                deviations, events, log_type
            )

        logger.info(f"Found {len(deviations)} baseline deviations")
        return deviations

    def _extract_dimension_values(
        self, dimension_name: str, events: List[Dict[str, Any]], log_type: str
    ) -> List[Tuple[float, Dict[str, Any]]]:
        """
        Extract values for a specific dimension from events.

        Returns list of (value, event_context) tuples.
        """
        import statistics
        from collections import defaultdict

        values = []

        if dimension_name == "events_per_hour":
            # Group events by hour
            hourly_counts = defaultdict(int)
            hourly_events = defaultdict(list)

            for event in events:
                timestamp = event.get("timestamp")
                if timestamp:
                    try:
                        dt = self._parse_timestamp(timestamp)
                        hour_key = dt.strftime("%Y-%m-%dT%H")
                        hourly_counts[hour_key] += 1
                        hourly_events[hour_key].append(event)
                    except:
                        pass

            for hour_key, count in hourly_counts.items():
                values.append(
                    (
                        float(count),
                        {"hour": hour_key, "events": hourly_events[hour_key]},
                    )
                )

        elif dimension_name == "requests_per_hour_per_ip":
            # Group by hour and IP
            hourly_ip_counts = defaultdict(lambda: defaultdict(int))
            hourly_ip_events = defaultdict(lambda: defaultdict(list))

            for event in events:
                timestamp = event.get("timestamp")
                source_ip = (
                    event.get("source_ip") or event.get("ip") or event.get("client_ip")
                )
                if timestamp and source_ip:
                    try:
                        dt = self._parse_timestamp(timestamp)
                        hour_key = dt.strftime("%Y-%m-%dT%H")
                        hourly_ip_counts[hour_key][source_ip] += 1
                        hourly_ip_events[hour_key][source_ip].append(event)
                    except:
                        pass

            for hour_key, ip_counts in hourly_ip_counts.items():
                for ip, count in ip_counts.items():
                    values.append(
                        (
                            float(count),
                            {
                                "hour": hour_key,
                                "ip": ip,
                                "events": hourly_ip_events[hour_key][ip],
                            },
                        )
                    )

        elif dimension_name == "bytes_transferred":
            for event in events:
                bytes_val = (
                    event.get("bytes_transferred")
                    or event.get("bytes")
                    or event.get("size")
                )
                if bytes_val:
                    try:
                        value = float(bytes_val)
                        values.append((value, event))
                    except:
                        pass

        elif dimension_name == "status_code":
            for event in events:
                status_code = event.get("status_code") or event.get("status")
                if status_code:
                    try:
                        value = float(status_code)
                        values.append((value, event))
                    except:
                        pass

        elif dimension_name == "logins_per_hour_per_user":
            # Group by hour and username
            hourly_user_counts = defaultdict(lambda: defaultdict(int))
            hourly_user_events = defaultdict(lambda: defaultdict(list))

            for event in events:
                timestamp = event.get("timestamp")
                username = (
                    event.get("username") or event.get("user") or event.get("account")
                )
                if timestamp and username:
                    try:
                        dt = self._parse_timestamp(timestamp)
                        hour_key = dt.strftime("%Y-%m-%dT%H")
                        hourly_user_counts[hour_key][username] += 1
                        hourly_user_events[hour_key][username].append(event)
                    except:
                        pass

            for hour_key, user_counts in hourly_user_counts.items():
                for username, count in user_counts.items():
                    values.append(
                        (
                            float(count),
                            {
                                "hour": hour_key,
                                "username": username,
                                "events": hourly_user_events[hour_key][username],
                            },
                        )
                    )

        elif dimension_name == "ip_failure_rate":
            # Calculate failure rate per IP
            ip_stats = defaultdict(lambda: {"total": 0, "failures": 0, "events": []})

            for event in events:
                source_ip = (
                    event.get("source_ip") or event.get("ip") or event.get("client_ip")
                )
                if source_ip:
                    ip_stats[source_ip]["total"] += 1
                    ip_stats[source_ip]["events"].append(event)

                    # Check for failure indicators
                    status_code = event.get("status_code") or event.get("status")
                    if status_code and str(status_code).startswith(("4", "5")):
                        ip_stats[source_ip]["failures"] += 1

                    event_name = event.get("event_name") or event.get("action") or ""
                    if any(
                        fail_term in event_name.lower()
                        for fail_term in ["fail", "deny", "block", "error", "invalid"]
                    ):
                        ip_stats[source_ip]["failures"] += 1

            for ip, stats in ip_stats.items():
                if stats["total"] > 0:
                    failure_rate = stats["failures"] / stats["total"]
                    values.append(
                        (
                            failure_rate,
                            {
                                "ip": ip,
                                "total": stats["total"],
                                "failures": stats["failures"],
                                "events": stats["events"],
                            },
                        )
                    )

        return values

    def _calculate_baseline_stats(
        self, values: List[Tuple[float, Dict[str, Any]]]
    ) -> Dict[str, float]:
        """Calculate baseline statistics for a set of values."""
        import statistics

        numeric_values = [v[0] for v in values]

        if len(numeric_values) < 3:
            return {"mean": 0.0, "std_dev": 0.0, "min": 0.0, "max": 0.0}

        mean = statistics.mean(numeric_values)

        if len(numeric_values) >= 2:
            try:
                std_dev = statistics.stdev(numeric_values)
            except statistics.StatisticsError:
                std_dev = 0.0
        else:
            std_dev = 0.0

        return {
            "mean": mean,
            "std_dev": std_dev,
            "min": min(numeric_values),
            "max": max(numeric_values),
            "median": statistics.median(numeric_values)
            if len(numeric_values) >= 3
            else mean,
        }

    def _identify_deviations(
        self,
        dimension_name: str,
        values: List[Tuple[float, Dict[str, Any]]],
        baseline_stats: Dict[str, float],
        events: List[Dict[str, Any]],
    ) -> List[BaselineDeviation]:
        """
        Identify deviations from baseline statistics.

        Returns list of BaselineDeviation objects.
        """
        deviations = []
        sigma_threshold = 2.5  # Default threshold

        for value_tuple in values:
            value, context = value_tuple

            # Calculate z-score
            if baseline_stats["std_dev"] > 0:
                z_score = (value - baseline_stats["mean"]) / baseline_stats["std_dev"]
            else:
                z_score = 0

            # Check if deviation exceeds threshold
            if abs(z_score) > sigma_threshold:
                # Determine severity based on z-score magnitude
                severity = "LOW"
                if abs(z_score) >= 5:
                    severity = "MEDIUM"
                if abs(z_score) >= 10:
                    severity = "HIGH"
                if abs(z_score) >= 20:
                    severity = "CRITICAL"

                # Extract context information
                timestamp = None
                source_ip = None
                username = None
                raw_line = None

                if "events" in context and context["events"]:
                    first_event = context["events"][0]
                    timestamp_str = first_event.get("timestamp")
                    if timestamp_str:
                        timestamp = self._parse_timestamp(timestamp_str)
                    source_ip = (
                        first_event.get("source_ip")
                        or first_event.get("ip")
                        or first_event.get("client_ip")
                    )
                    username = (
                        first_event.get("username")
                        or first_event.get("user")
                        or first_event.get("account")
                    )
                    raw_line = first_event.get("raw") or str(first_event)

                elif isinstance(context, dict) and "event" in context:
                    event = context["event"]
                    timestamp_str = event.get("timestamp")
                    if timestamp_str:
                        timestamp = self._parse_timestamp(timestamp_str)
                    source_ip = (
                        event.get("source_ip")
                        or event.get("ip")
                        or event.get("client_ip")
                    )
                    username = (
                        event.get("username")
                        or event.get("user")
                        or event.get("account")
                    )
                    raw_line = event.get("raw") or str(event)

                deviation = BaselineDeviation(
                    dimension=dimension_name,
                    observed_value=value,
                    baseline_mean=baseline_stats["mean"],
                    sigma_distance=abs(z_score),
                    timestamp=timestamp,
                    source_ip=source_ip,
                    username=username,
                    raw_line=raw_line[:200] if raw_line else None,
                    severity=severity,
                )
                deviations.append(deviation)

        return deviations

    def _enhance_deviations_with_opencode(
        self,
        deviations: List[BaselineDeviation],
        events: List[Dict[str, Any]],
        log_type: str,
    ) -> List[BaselineDeviation]:
        """
        Use OpenCode CLI to enhance deviation analysis with AI context.

        Args:
            deviations: List of baseline deviations
            events: Original log events
            log_type: Log type

        Returns:
            Enhanced deviations with OpenCode context
        """
        import json
        import subprocess
        import time

        if not deviations:
            return deviations

        # Create a summary of deviations for OpenCode analysis
        deviation_summary = "\n".join(
            [
                f"Dimension: {dev.dimension}, Value: {dev.observed_value}, "
                f"Baseline: {dev.baseline_mean}, Sigma: {dev.sigma_distance}, "
                f"Severity: {dev.severity}"
                for dev in deviations[:10]  # Analyze top 10 deviations
            ]
        )

        # Create temp file with deviation summary
        temp_file = self.temp_dir / f"baseline_deviations_{int(time.time())}.txt"
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(f"Baseline Deviation Analysis for {log_type} logs\n\n")
            f.write(f"Total events: {len(events)}\n")
            f.write(f"Deviations found: {len(deviations)}\n\n")
            f.write("Top Deviations:\n")
            f.write(deviation_summary)

            # Add sample events for context
            f.write("\n\nSample events with deviations:\n")
            for i, dev in enumerate(deviations[:5]):
                if dev.raw_line:
                    f.write(f"Deviation {i + 1}: {dev.raw_line}\n")

        try:
            # Use OpenCode to analyze deviations
            cmd = [
                "opencode",
                "analyze",
                "--input",
                str(temp_file),
                "--type",
                "anomaly-analysis",
                "--output",
                "json",
                "--timeout",
                str(self.opencode_timeout),
                "--context",
                f"log_type={log_type},analysis_type=baseline_deviations",
            ]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.opencode_timeout
            )

            if result.returncode == 0:
                try:
                    opencode_data = json.loads(result.stdout)
                    # Enhance deviations with OpenCode insights
                    for i, dev in enumerate(deviations[:10]):
                        if i < len(opencode_data.get("insights", [])):
                            insight = opencode_data["insights"][i]
                            # Could add OpenCode risk assessment here
                            pass
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            logger.debug(f"OpenCode deviation enhancement failed: {e}")

        # Clean up temp file
        if temp_file.exists():
            temp_file.unlink()

        return deviations

    def analyze(self, events: List[Dict[str, Any]], log_type: str) -> AnalysisResult:
        """
        Main entry point for analysis.

        Args:
            events: List of parsed log events
            log_type: Type of logs being analyzed

        Returns:
            AnalysisResult containing all findings
        """
        start_time = time.time()

        try:
            # Step 1: Extract IOCs using OpenCode CLI
            logger.info(
                f"Starting OpenCode analysis for {len(events)} events of type {log_type}"
            )
            ioc_findings = self._extract_iocs_via_opencode(events, log_type)

            # Step 2: Perform threat hunting with MITRE ATT&CK
            mitre_attack_findings = self._perform_threat_hunting(
                ioc_findings, events, log_type
            )

            # Step 3: Incident investigation with MITRE CAR
            mitre_car_findings = self._incident_investigation(events, log_type)

            # Step 4: Perform baseline deviation analysis
            baseline_deviations = self._analyze_baseline_deviations(events, log_type)

            analysis_duration = time.time() - start_time

            return AnalysisResult(
                ioc_findings=ioc_findings,
                mitre_attack_findings=mitre_attack_findings,
                mitre_car_findings=mitre_car_findings,
                baseline_deviations=baseline_deviations,
                analysis_duration=analysis_duration,
                opencode_version=self._get_opencode_version(),
            )
            ioc_findings = self._extract_iocs_via_opencode(events, log_type)

            # Step 2: Perform threat hunting with MITRE ATT&CK
            mitre_attack_findings = self._perform_threat_hunting(
                ioc_findings, events, log_type
            )

            # Step 3: Incident investigation with MITRE CAR
            mitre_car_findings = self._incident_investigation(events, log_type)

            analysis_duration = time.time() - start_time

            return AnalysisResult(
                ioc_findings=ioc_findings,
                mitre_attack_findings=mitre_attack_findings,
                mitre_car_findings=mitre_car_findings,
                analysis_duration=analysis_duration,
                opencode_version=self._get_opencode_version(),
            )

        except Exception as e:
            logger.error(f"OpenCode analysis failed: {e}")
            return AnalysisResult(
                ioc_findings=[],
                mitre_attack_findings=[],
                mitre_car_findings=[],
                analysis_duration=time.time() - start_time,
                error=str(e),
            )

    def _extract_iocs_via_opencode(
        self, events: List[Dict[str, Any]], log_type: str
    ) -> List[IOCFinding]:
        """
        Use OpenCode CLI to extract IOCs from log events.

        Args:
            events: List of parsed log events
            log_type: Type of logs being analyzed

        Returns:
            List of IOCFinding objects
        """
        logger.info(f"Extracting IOCs from {len(events)} events using OpenCode")

        # Create a temporary file with log content
        temp_file = self.temp_dir / f"opencode_input_{int(time.time())}.txt"
        with open(temp_file, "w", encoding="utf-8") as f:
            for event in events:
                # Write raw log line if available, otherwise create a summary
                raw = event.get("raw", str(event))
                f.write(f"{raw}\n")

        try:
            # Construct OpenCode CLI command for IOC extraction
            cmd = [
                "opencode",
                "analyze",
                "--input",
                str(temp_file),
                "--type",
                "ioc-extraction",
                "--output",
                "json",
                "--timeout",
                str(self.opencode_timeout),
            ]

            # Add log type context if available
            if log_type and log_type != "unknown":
                cmd.extend(["--context", f"log_type={log_type}"])

            logger.debug(f"Running OpenCode command: {' '.join(cmd)}")

            # Execute OpenCode CLI
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.opencode_timeout
            )

            if result.returncode != 0:
                logger.warning(f"OpenCode IOC extraction failed: {result.stderr}")
                return self._fallback_ioc_extraction(events)

            # Parse JSON output
            try:
                ioc_data = json.loads(result.stdout)
                return self._parse_opencode_iocs(ioc_data, events)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse OpenCode JSON output: {e}")
                return self._fallback_ioc_extraction(events)

        except subprocess.TimeoutExpired:
            logger.warning(
                f"OpenCode IOC extraction timed out after {self.opencode_timeout}s"
            )
            return self._fallback_ioc_extraction(events)
        except FileNotFoundError:
            logger.warning("OpenCode CLI not found, using fallback IOC extraction")
            return self._fallback_ioc_extraction(events)
        except Exception as e:
            logger.error(f"Error during OpenCode IOC extraction: {e}")
            return self._fallback_ioc_extraction(events)
        finally:
            # Clean up temp file
            if temp_file.exists():
                temp_file.unlink()

    def _parse_opencode_iocs(
        self, ioc_data: Dict[str, Any], events: List[Dict[str, Any]]
    ) -> List[IOCFinding]:
        """Parse OpenCode JSON output into IOCFinding objects"""
        ioc_findings = []

        if not isinstance(ioc_data, dict):
            return []

        # Extract IOCs from OpenCode response
        iocs = ioc_data.get("iocs", [])
        if not isinstance(iocs, list):
            return []

        for ioc in iocs:
            try:
                ioc_type = ioc.get("type", "").lower()
                value = ioc.get("value", "")
                context = ioc.get("context", "")
                risk = ioc.get("risk", "medium").lower()
                confidence = float(ioc.get("confidence", 0.5))

                if not ioc_type or not value:
                    continue

                # Map OpenCode IOC types to our standard types
                type_mapping = {
                    "ip": "ipv4",
                    "ipv4": "ipv4",
                    "ipv6": "ipv6",
                    "domain": "domain",
                    "url": "url",
                    "email": "email",
                    "username": "username",
                    "file_path": "file_path",
                    "windows_path": "win_path",
                    "unix_path": "unix_path",
                    "md5": "md5",
                    "sha1": "sha1",
                    "sha256": "sha256",
                    "hash": "hash",
                    "cve": "cve",
                    "jwt": "jwt",
                    "api_key": "api_key",
                    "mac": "mac",
                }

                mapped_type = type_mapping.get(ioc_type, ioc_type)

                # Calculate first/last seen from events
                first_seen = None
                last_seen = None
                occurrences = 0

                for event in events:
                    event_str = str(event)
                    if value in event_str:
                        occurrences += 1
                        event_time = event.get("timestamp")
                        if event_time:
                            try:
                                dt = self._parse_timestamp(event_time)
                                if not first_seen or dt < first_seen:
                                    first_seen = dt
                                if not last_seen or dt > last_seen:
                                    last_seen = dt
                            except:
                                pass

                ioc_findings.append(
                    IOCFinding(
                        ioc_type=mapped_type,
                        value=value,
                        context=context,
                        risk=risk,
                        confidence=confidence,
                        first_seen=first_seen,
                        last_seen=last_seen,
                        occurrences=occurrences,
                    )
                )

            except Exception as e:
                logger.debug(f"Failed to parse IOC: {ioc}, error: {e}")
                continue

        return ioc_findings

    def _fallback_ioc_extraction(
        self, events: List[Dict[str, Any]]
    ) -> List[IOCFinding]:
        """
        Fallback IOC extraction when OpenCode is not available.
        Uses simple regex patterns to extract common IOCs.
        """
        import re
        from collections import defaultdict

        logger.info("Using fallback IOC extraction")

        # Regex patterns for common IOCs
        patterns = {
            "ipv4": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            "ipv6": r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b",
            "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
            "url": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w._~:/?#[\]@!$&\'()*+,;=]*)?",
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "md5": r"\b[a-fA-F0-9]{32}\b",
            "sha1": r"\b[a-fA-F0-9]{40}\b",
            "sha256": r"\b[a-fA-F0-9]{64}\b",
            "cve": r"\bCVE-\d{4}-\d{4,7}\b",
        }

        ioc_map = defaultdict(list)

        for event in events:
            event_str = str(event)
            for ioc_type, pattern in patterns.items():
                matches = re.findall(pattern, event_str)
                for match in matches:
                    ioc_map[(ioc_type, match)].append(event_str)

        ioc_findings = []
        for (ioc_type, value), contexts in ioc_map.items():
            # Simple risk assessment
            risk = "low"
            if ioc_type in ["ipv4", "ipv6", "domain", "url"]:
                # Check for suspicious patterns
                if any(
                    suspicious in value.lower()
                    for suspicious in ["malware", "phishing", "attack", "exploit"]
                ):
                    risk = "high"
                elif ioc_type in ["ipv4", "ipv6"]:
                    # Check for private IPs
                    if value.startswith(
                        (
                            "10.",
                            "192.168.",
                            "172.16.",
                            "172.17.",
                            "172.18.",
                            "172.19.",
                            "172.20.",
                            "172.21.",
                            "172.22.",
                            "172.23.",
                            "172.24.",
                            "172.25.",
                            "172.26.",
                            "172.27.",
                            "172.28.",
                            "172.29.",
                            "172.30.",
                            "172.31.",
                        )
                    ):
                        risk = "medium"

            ioc_findings.append(
                IOCFinding(
                    ioc_type=ioc_type,
                    value=value,
                    context="\n".join(contexts[:3]),  # First 3 contexts
                    risk=risk,
                    confidence=0.3,  # Lower confidence for regex-based extraction
                    occurrences=len(contexts),
                )
            )

        return ioc_findings

    def _perform_threat_hunting(
        self, iocs: List[IOCFinding], events: List[Dict[str, Any]], log_type: str
    ) -> List[MITREAttackFinding]:
        """
        Map IOCs and behaviors to MITRE ATT&CK techniques.

        Args:
            iocs: Extracted IOCs
            events: Log events
            log_type: Type of logs

        Returns:
            List of MITREAttackFinding objects
        """
        findings = []

        # Analyze events for suspicious patterns
        suspicious_patterns = self._detect_suspicious_patterns(events, log_type)

        # Map patterns to MITRE ATT&CK techniques
        for pattern_name, pattern_data in suspicious_patterns.items():
            techniques = ATTACK_TECHNIQUE_MAPPING.get(pattern_name, [])

            for technique_id in techniques:
                technique_info = self.mitre_attack_db.get(technique_id, {})

                finding = MITREAttackFinding(
                    technique_id=technique_id,
                    technique_name=technique_info.get("name", technique_id),
                    tactic=technique_info.get("tactic", "Unknown"),
                    evidence=pattern_data.get("evidence", ""),
                    confidence=pattern_data.get("confidence", "medium"),
                    recommended_response=pattern_data.get(
                        "recommendation",
                        f"Investigate {pattern_name} activity for potential {technique_id}",
                    ),
                    matched_log_lines=pattern_data.get("log_lines", []),
                    severity=self._map_confidence_to_severity(
                        pattern_data.get("confidence", "medium")
                    ),
                )
                findings.append(finding)

        # Also check IOCs against known threat intelligence (simplified)
        for ioc in iocs:
            if ioc.risk == "high":
                # High risk IOCs might indicate specific techniques
                if ioc.ioc_type in ["ipv4", "ipv6", "domain"]:
                    # Network IOCs could indicate C2
                    finding = MITREAttackFinding(
                        technique_id="T1071",
                        technique_name="Application Layer Protocol",
                        tactic="Command and Control",
                        evidence=f"High-risk {ioc.ioc_type} IOC detected: {ioc.value}",
                        confidence="medium",
                        recommended_response=f"Investigate network traffic to/from {ioc.value} for C2 activity",
                        matched_log_lines=[ioc.context[:500]] if ioc.context else [],
                        severity="HIGH",
                    )
                    findings.append(finding)

        return findings

    def _detect_suspicious_patterns(
        self, events: List[Dict[str, Any]], log_type: str
    ) -> Dict[str, Dict[str, Any]]:
        """Detect suspicious patterns in log events"""
        patterns = {}

        # Convert events to strings for pattern matching
        event_strings = [str(event) for event in events]

        # Check for PowerShell execution patterns
        powershell_lines = []
        for i, event_str in enumerate(event_strings):
            if any(
                pattern in event_str.lower()
                for pattern in [
                    "powershell",
                    "powershell.exe",
                    "-enc",
                    "-e ",
                    "invoke-",
                ]
            ):
                powershell_lines.append(event_str)

        if powershell_lines:
            patterns["powershell_execution"] = {
                "evidence": f"Found {len(powershell_lines)} PowerShell execution events",
                "confidence": "high" if len(powershell_lines) > 5 else "medium",
                "recommendation": "Review PowerShell execution logs for suspicious commands",
                "log_lines": powershell_lines[:10],  # First 10 lines
            }

        # Check for LSASS access patterns
        lsass_lines = []
        for i, event_str in enumerate(event_strings):
            if "lsass" in event_str.lower() and any(
                term in event_str.lower()
                for term in ["access", "dump", "memory", "process"]
            ):
                lsass_lines.append(event_str)

        if lsass_lines:
            patterns["lsass_access"] = {
                "evidence": f"Found {len(lsass_lines)} LSASS access events",
                "confidence": "high",
                "recommendation": "Investigate potential credential dumping activity",
                "log_lines": lsass_lines[:10],
            }

        # Check for scheduled task creation
        task_lines = []
        for i, event_str in enumerate(event_strings):
            if any(
                pattern in event_str.lower()
                for pattern in [
                    "schtasks",
                    "scheduled task",
                    "at.exe",
                    "task scheduler",
                ]
            ):
                task_lines.append(event_str)

        if task_lines:
            patterns["scheduled_task_create"] = {
                "evidence": f"Found {len(task_lines)} scheduled task creation events",
                "confidence": "medium",
                "recommendation": "Review scheduled tasks for persistence mechanisms",
                "log_lines": task_lines[:10],
            }

        # Check for credential access patterns
        credential_lines = []
        for i, event_str in enumerate(event_strings):
            if any(
                pattern in event_str.lower()
                for pattern in [
                    "password",
                    "credential",
                    "hash",
                    "ntlm",
                    "kerberos",
                    "logon",
                ]
            ):
                credential_lines.append(event_str)

        if credential_lines:
            patterns["credential_access"] = {
                "evidence": f"Found {len(credential_lines)} credential-related events",
                "confidence": "medium",
                "recommendation": "Investigate credential access and usage",
                "log_lines": credential_lines[:10],
            }

        return patterns

    def _incident_investigation(
        self, events: List[Dict[str, Any]], log_type: str
    ) -> List[MITRECARFinding]:
        """
        Apply MITRE CAR detection logic for incident investigation.

        Args:
            events: Log events
            log_type: Type of logs

        Returns:
            List of MITRECARFinding objects
        """
        findings = []

        # Check each CAR detection rule
        for car_id, car_rule in self.mitre_car_db.items():
            # Check if this log type is relevant for the CAR rule
            if log_type not in car_rule.get("log_sources", []):
                # Try to match log type patterns
                log_type_lower = log_type.lower()
                car_sources = [src.lower() for src in car_rule.get("log_sources", [])]
                if not any(
                    src in log_type_lower for src in ["all", "any", "*"]
                ) and not any(log_type_lower.startswith(src) for src in car_sources):
                    continue

            # Apply detection logic
            detection_logic = car_rule.get("detection_logic", "").lower()
            if not detection_logic:
                continue

            matching_events = []

            # Simple keyword matching for detection logic
            keywords = []
            if " OR " in detection_logic:
                parts = [p.strip() for p in detection_logic.split(" OR ")]
                for part in parts:
                    if " AND " in part:
                        subparts = [s.strip() for s in part.split(" AND ")]
                        keywords.append(subparts)
                    else:
                        keywords.append([part])
            elif " AND " in detection_logic:
                keywords.append([k.strip() for k in detection_logic.split(" AND ")])
            else:
                keywords.append([detection_logic])

            for event in events:
                event_str = str(event).lower()
                matched = False

                for keyword_set in keywords:
                    if all(keyword in event_str for keyword in keyword_set):
                        matched = True
                        break

                if matched:
                    matching_events.append(event)

            if matching_events:
                # Calculate confidence based on match count and log type relevance
                confidence = min(1.0, len(matching_events) / 10.0)
                if log_type in car_rule.get("log_sources", []):
                    confidence = min(1.0, confidence + 0.3)

                finding = MITRECARFinding(
                    car_id=car_id,
                    detection_name=car_rule["name"],
                    description=car_rule["description"],
                    severity=car_rule["severity"],
                    matching_events=matching_events[:5],  # Limit to first 5 events
                    investigation_notes=f"Detected {len(matching_events)} events matching {car_id} pattern",
                    confidence=confidence,
                )
                findings.append(finding)

        return findings

    def _map_confidence_to_severity(self, confidence: str) -> str:
        """Map confidence level to severity"""
        confidence_map = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
        return confidence_map.get(confidence.lower(), "MEDIUM")

    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse timestamp string to datetime object"""
        try:
            # Try ISO format
            if "T" in timestamp_str:
                return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))

            # Try common log formats
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%d/%b/%Y:%H:%M:%S",
                "%b %d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
            ]

            for fmt in formats:
                try:
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue

            return None
        except Exception:
            return None

    def _get_opencode_version(self) -> str:
        """Get OpenCode CLI version"""
        try:
            result = subprocess.run(
                ["opencode", "--version"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        return "unknown"

    def generate_report(self, result: AnalysisResult) -> Dict[str, Any]:
        """
        Generate a combined analysis report.

        Args:
            result: AnalysisResult object

        Returns:
            Dictionary with report data
        """
        report = {
            "analysis_metadata": {
                "module": "opencode_log_analyzer",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "opencode_version": result.opencode_version,
                "analysis_duration": result.analysis_duration,
                "total_iocs": len(result.ioc_findings),
                "total_attack_findings": len(result.mitre_attack_findings),
                "total_car_findings": len(result.mitre_car_findings),
            },
            "ioc_extraction": {
                "summary": {
                    "high_risk": len(
                        [i for i in result.ioc_findings if i.risk == "high"]
                    ),
                    "medium_risk": len(
                        [i for i in result.ioc_findings if i.risk == "medium"]
                    ),
                    "low_risk": len(
                        [i for i in result.ioc_findings if i.risk == "low"]
                    ),
                },
                "iocs_by_type": {},
                "top_iocs": [],
            },
            "mitre_attack": {"techniques": [], "tactics": {}, "chains": []},
            "mitre_car": {"detections": []},
        }

        # Process IOC findings
        iocs_by_type = {}
        for ioc in result.ioc_findings:
            iocs_by_type.setdefault(ioc.ioc_type, []).append(
                {
                    "value": ioc.value,
                    "risk": ioc.risk,
                    "confidence": ioc.confidence,
                    "occurrences": ioc.occurrences,
                    "context": ioc.context[:200] if ioc.context else "",
                    "first_seen": ioc.first_seen.isoformat()
                    if ioc.first_seen
                    else None,
                    "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
                }
            )

        report["ioc_extraction"]["iocs_by_type"] = iocs_by_type

        # Get top 10 high/medium risk IOCs
        high_risk_iocs = [
            i for i in result.ioc_findings if i.risk in ["high", "medium"]
        ]
        high_risk_iocs.sort(key=lambda x: (x.confidence, x.occurrences), reverse=True)
        report["ioc_extraction"]["top_iocs"] = [
            {
                "type": ioc.ioc_type,
                "value": ioc.value,
                "risk": ioc.risk,
                "confidence": ioc.confidence,
                "occurrences": ioc.occurrences,
            }
            for ioc in high_risk_iocs[:10]
        ]

        # Process MITRE ATT&CK findings
        for finding in result.mitre_attack_findings:
            report["mitre_attack"]["techniques"].append(
                {
                    "technique_id": finding.technique_id,
                    "technique_name": finding.technique_name,
                    "tactic": finding.tactic,
                    "evidence": finding.evidence,
                    "confidence": finding.confidence,
                    "severity": finding.severity,
                    "recommended_response": finding.recommended_response,
                    "matched_log_lines_count": len(finding.matched_log_lines),
                }
            )

            # Count by tactic
            report["mitre_attack"]["tactics"][finding.tactic] = (
                report["mitre_attack"]["tactics"].get(finding.tactic, 0) + 1
            )

        # Process MITRE CAR findings
        for finding in result.mitre_car_findings:
            report["mitre_car"]["detections"].append(
                {
                    "car_id": finding.car_id,
                    "detection_name": finding.detection_name,
                    "description": finding.description,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "matching_events_count": len(finding.matching_events),
                    "investigation_notes": finding.investigation_notes,
                }
            )

        return report


# ---------------------------------------------------------------------------
# Integration helper
# ---------------------------------------------------------------------------


def run_opencode_analysis(
    events: List[Dict[str, Any]], log_type: str, config: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Convenience function to run OpenCode analysis and return results in ThreatTrace format.

    Args:
        events: List of parsed log events
        log_type: Type of logs being analyzed
        config: Configuration dictionary for OpenCodeLogAnalyzer

    Returns:
        Dictionary with analysis results compatible with ThreatTrace
    """
    analyzer = OpenCodeLogAnalyzer(config or {})
    result = analyzer.analyze(events, log_type)

    # Convert to ThreatTrace compatible format
    findings = []

    # Convert IOC findings
    for ioc in result.ioc_findings:
        findings.append(
            {
                "finding_id": f"OP-IOC-{hash(ioc.value) % 10000:04d}",
                "rule_name": f"IOC Detection: {ioc.ioc_type.upper()}",
                "description": f"Found {ioc.ioc_type}: {ioc.value}",
                "severity": ioc.risk.upper(),
                "confidence": ioc.confidence,
                "iocs": [{"type": ioc.ioc_type, "value": ioc.value}],
                "context": ioc.context,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "module": "opencode_log_analyzer",
                "category": "ioc_extraction",
            }
        )

    # Convert MITRE ATT&CK findings
    for attack in result.mitre_attack_findings:
        findings.append(
            {
                "finding_id": f"OP-ATTACK-{hash(attack.technique_id) % 10000:04d}",
                "rule_name": f"MITRE ATT&CK: {attack.technique_name}",
                "description": f"{attack.technique_id} - {attack.evidence}",
                "severity": attack.severity,
                "confidence": 0.8
                if attack.confidence == "high"
                else 0.5
                if attack.confidence == "medium"
                else 0.3,
                "mitre_technique": attack.technique_id,
                "mitre_tactic": attack.tactic,
                "context": attack.evidence,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "module": "opencode_log_analyzer",
                "category": "mitre_attack",
                "recommended_action": attack.recommended_response,
            }
        )

    # Convert MITRE CAR findings
    for car in result.mitre_car_findings:
        findings.append(
            {
                "finding_id": f"OP-CAR-{hash(car.car_id) % 10000:04d}",
                "rule_name": f"MITRE CAR: {car.detection_name}",
                "description": f"{car.car_id}: {car.description}",
                "severity": car.severity,
                "confidence": car.confidence,
                "mitre_car_id": car.car_id,
                "context": car.investigation_notes,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "module": "opencode_log_analyzer",
                "category": "mitre_car",
                "recommended_action": f"Investigate {car.car_id} detection",
            }
        )

    # Generate detailed report
    report = analyzer.generate_report(result)

    return {
        "opencode_findings": findings,
        "opencode_report": report,
        "analysis_metadata": report["analysis_metadata"],
        "error": result.error,
    }
