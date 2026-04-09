"""ThreatTrace Detection Engine — Enhanced with OpenCode Log Analysis."""

from __future__ import annotations

import time
import uuid
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def run_analysis_enhanced(
    events: list,
    log_type: str = "unknown",
    file_path: Optional[str] = None,
    verbose: bool = False,
    enable_opencode: bool = True,
    opencode_config: dict = None,
) -> dict:
    """
    Run the full ThreatTrace analysis pipeline with OpenCode integration.

    New integration point:
    Detection Engine (YARA/Sigma) -> OpenCode Log Analysis Module -> Analytics Modules -> Report Builder

    Returns complete analysis results dict.
    """
    from . import event_matrix as em
    from . import correlator

    try:
        from . import yara_scanner

        _yara_available = True
    except ImportError:
        _yara_available = False
    from . import sigma_scanner

    # Try to import OpenCode analyzer
    try:
        from analysis.opencode_log_analyzer import run_opencode_analysis

        _opencode_available = True
    except ImportError as e:
        logger.warning(f"OpenCode analyzer not available: {e}")
        _opencode_available = False

    start_time = time.time()
    analysis_id = f"TT-ANA-{uuid.uuid4().hex[:8].upper()}"

    if verbose:
        logger.info(
            f"Starting enhanced analysis [{analysis_id}] — {len(events)} events, type={log_type}"
        )

    results = {
        "analysis_id": analysis_id,
        "log_type": log_type,
        "file_path": file_path,
        "total_events": len(events),
        "findings": [],
        "patterns": [],
        "event_matrix": {},
        "correlations": {},
        "analysis_duration_seconds": 0,
        "yara_rules_run": 0,
        "sigma_rules_run": 0,
        "opencode_analysis_performed": False,
        "opencode_findings": [],
        "opencode_report": {},
        "findings_by_severity": {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        },
        "overall_risk": "INFORMATIONAL",
    }

    # Step 1: Build Event Matrix
    if verbose:
        logger.info("Building Event Matrix...")
    try:
        results["event_matrix"] = em.build_event_matrix(events)
    except Exception as exc:
        logger.warning(f"Event matrix failed: {exc}")
        results["event_matrix"] = {}

    # Step 2: Run YARA scanner
    if verbose:
        logger.info("Running YARA scanner...")
    yara_findings = []
    if _yara_available:
        try:
            yara_findings = yara_scanner.scan(events, log_type)
            results["yara_rules_run"] = yara_scanner.get_rules_count()
        except Exception as exc:
            logger.warning(f"YARA scan failed: {exc}")
    results["findings"].extend(yara_findings)

    # Step 3: Run Sigma scanner
    if verbose:
        logger.info("Running Sigma scanner...")
    sigma_findings = []
    try:
        sigma_findings = sigma_scanner.scan(events, log_type)
        results["sigma_rules_run"] = sigma_scanner.get_rules_count()
    except Exception as exc:
        logger.warning(f"Sigma scan failed: {exc}")
    results["findings"].extend(sigma_findings)

    # Step 4: Run OpenCode analysis (if enabled and available)
    if enable_opencode and _opencode_available and events:
        if verbose:
            logger.info("Running OpenCode log analysis...")
        try:
            opencode_config = opencode_config or {
                "timeout": 120,
                "max_retries": 2,
                "temp_dir": "/tmp/threattrace",
            }

            opencode_results = run_opencode_analysis(events, log_type, opencode_config)

            results["opencode_analysis_performed"] = True
            results["opencode_findings"] = opencode_results.get("opencode_findings", [])
            results["opencode_report"] = opencode_results.get("opencode_report", {})

            # Add OpenCode findings to main findings list
            opencode_findings_for_main = []
            for finding in opencode_results.get("opencode_findings", []):
                # Convert OpenCode finding to match ThreatTrace format
                threattrace_finding = {
                    "finding_id": finding.get(
                        "finding_id", f"OP-{uuid.uuid4().hex[:8]}"
                    ),
                    "rule_name": finding.get("rule_name", "OpenCode Analysis"),
                    "description": finding.get("description", ""),
                    "severity": finding.get("severity", "INFO"),
                    "confidence": finding.get("confidence", 0.5),
                    "context": finding.get("context", ""),
                    "timestamp": finding.get("timestamp", ""),
                    "module": finding.get("module", "opencode_log_analyzer"),
                    "category": finding.get("category", "unknown"),
                }

                # Add MITRE fields if present
                if finding.get("mitre_technique"):
                    threattrace_finding["mitre_technique"] = finding["mitre_technique"]
                if finding.get("mitre_tactic"):
                    threattrace_finding["mitre_tactic"] = finding["mitre_tactic"]
                if finding.get("mitre_car_id"):
                    threattrace_finding["mitre_car_id"] = finding["mitre_car_id"]

                # Add IOCs if present
                if finding.get("iocs"):
                    threattrace_finding["iocs"] = finding["iocs"]

                # Add recommended action if present
                if finding.get("recommended_action"):
                    threattrace_finding["recommended_action"] = finding[
                        "recommended_action"
                    ]

                opencode_findings_for_main.append(threattrace_finding)

            results["findings"].extend(opencode_findings_for_main)

            if verbose:
                logger.info(
                    f"OpenCode analysis found {len(opencode_findings_for_main)} findings"
                )

        except Exception as exc:
            logger.warning(f"OpenCode analysis failed: {exc}")
            results["opencode_analysis_performed"] = False
            results["opencode_error"] = str(exc)
    elif enable_opencode and not _opencode_available:
        if verbose:
            logger.warning(
                "OpenCode analyzer not available, skipping OpenCode analysis"
            )

    # Step 5: Run correlation engine
    if verbose:
        logger.info("Running correlation engine...")
    try:
        results["correlations"] = correlator.run_all_correlations(events)
    except Exception as exc:
        logger.warning(f"Correlator failed: {exc}")
        results["correlations"] = {}

    # Step 6: Run suspicious pattern catalogue
    if verbose:
        logger.info("Running pattern catalogue...")
    try:
        results["patterns"] = em.suspicious_pattern_catalogue(
            events, results["findings"]
        )
    except Exception as exc:
        logger.warning(f"Pattern catalogue failed: {exc}")
        results["patterns"] = []

    # Step 7: Assign unique finding IDs and severity counts
    all_findings = results["findings"]
    for i, finding in enumerate(all_findings, 1):
        if "finding_id" not in finding:
            finding["finding_id"] = f"TT-F-{i:03d}"
        sev = finding.get("severity", "INFO")
        if sev in results["findings_by_severity"]:
            results["findings_by_severity"][sev] += 1

    # Step 8: Overall risk rating
    sev_counts = results["findings_by_severity"]
    if sev_counts["CRITICAL"] > 0:
        results["overall_risk"] = "CRITICAL"
    elif sev_counts["HIGH"] > 0:
        results["overall_risk"] = "HIGH"
    elif sev_counts["MEDIUM"] > 0:
        results["overall_risk"] = "MEDIUM"
    elif sev_counts["LOW"] > 0:
        results["overall_risk"] = "LOW"
    else:
        results["overall_risk"] = "INFORMATIONAL"

    results["analysis_duration_seconds"] = round(time.time() - start_time, 2)

    if verbose:
        opencode_status = (
            "enabled" if results["opencode_analysis_performed"] else "disabled/failed"
        )
        logger.info(
            f"Enhanced analysis complete: {len(all_findings)} findings, "
            f"{len(results['patterns'])} patterns, "
            f"OpenCode={opencode_status}, "
            f"risk={results['overall_risk']} ({results['analysis_duration_seconds']}s)"
        )

    return results
