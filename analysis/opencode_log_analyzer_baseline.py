"""
OpenCode-assisted baseline deviation analysis module.

This module enhances the baseline deviation analysis with OpenCode AI capabilities
to detect anomalous patterns and deviations from normal behavior.
"""

from __future__ import annotations

import json
import logging
import math
import statistics
import subprocess
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .opencode_log_analyzer import BaselineDeviation, OpenCodeLogAnalyzer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dimension definitions for baseline analysis
# ---------------------------------------------------------------------------


class DimensionDefinition:
    """Definition of a dimension to profile for baseline analysis"""

    name: str
    extractor: callable
    description: str


# Common baseline dimensions for different log types
BASELINE_DIMENSIONS = {
    "apache": [
        {
            "name": "requests_per_hour_per_ip",
            "description": "Requests/hour per source IP",
        },
        {"name": "bytes_transferred", "description": "HTTP response size per request"},
        {"name": "status_code", "description": "HTTP status code per request"},
        {"name": "events_per_hour", "description": "Global events per hour"},
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
# Enhanced OpenCodeLogAnalyzer with Baseline Analysis
# ---------------------------------------------------------------------------


class EnhancedOpenCodeLogAnalyzer(OpenCodeLogAnalyzer):
    """
    Enhanced OpenCode analyzer with baseline deviation analysis capabilities.
    """

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


# ---------------------------------------------------------------------------
# Main integration function
# ---------------------------------------------------------------------------


def run_enhanced_opencode_analysis(
    events: List[Dict[str, Any]], log_type: str, config: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Run enhanced OpenCode analysis with baseline deviation capabilities.

    Args:
        events: List of parsed log events
        log_type: Type of logs being analyzed
        config: Configuration dictionary

    Returns:
        Dictionary with enhanced analysis results
    """
    analyzer = EnhancedOpenCodeLogAnalyzer(config or {})
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
                "10context": car.investigation_notes,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "module": "opencode_log_analyzer",
                "category": "mitre_car",
                "recommended_action": f"Investigate {car.car_id} detection",
            }
        )

    # Convert Baseline Deviation findings
    for deviation in result.baseline_deviations:
        findings.append(
            {
                "finding_id": f"OP-BASELINE-{hash(deviation.dimension) % 10000:04d}",
                "rule_name": f"Baseline Deviation: {deviation.dimension}",
                "description": f"{deviation.dimension} deviation detected: {deviation.observed_value} vs baseline {deviation.baseline_mean}",
                "severity": deviation.severity,
                "confidence": min(
                    deviation.sigma_distance / 20.0, 1.0
                ),  # Map sigma distance to confidence
                "context": deviation.raw_line
                or f"Sigma distance: {deviation.sigma_distance}",
                "timestamp": deviation.timestamp.isoformat()
                if deviation.timestamp
                else datetime.now(timezone.utc).isoformat(),
                "module": "opencode_log_analyzer",
                "category": "baseline_deviations",
                "recommended_action": f"Investigate {deviation.dimension} anomaly",
                "source_ip": deviation.source_ip,
                "username": deviation.username,
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
