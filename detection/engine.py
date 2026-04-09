"""ThreatTrace Detection Engine — Main Orchestrator."""
from __future__ import annotations
import time
import uuid
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def run_analysis(events: list, log_type: str = "unknown",
                 file_path: Optional[str] = None,
                 verbose: bool = False) -> dict:
    """
    Run the full ThreatTrace analysis pipeline.
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

    start_time = time.time()
    analysis_id = f"TT-ANA-{uuid.uuid4().hex[:8].upper()}"

    if verbose:
        logger.info(f"Starting analysis [{analysis_id}] — {len(events)} events, type={log_type}")

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
        "findings_by_severity": {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
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

    # Step 4: Run correlation engine
    if verbose:
        logger.info("Running correlation engine...")
    try:
        results["correlations"] = correlator.run_all_correlations(events)
    except Exception as exc:
        logger.warning(f"Correlator failed: {exc}")
        results["correlations"] = {}

    # Step 5: Run suspicious pattern catalogue
    if verbose:
        logger.info("Running pattern catalogue...")
    try:
        results["patterns"] = em.suspicious_pattern_catalogue(
            events, results["findings"]
        )
    except Exception as exc:
        logger.warning(f"Pattern catalogue failed: {exc}")
        results["patterns"] = []

    # Step 6: Assign unique finding IDs and severity counts
    all_findings = results["findings"]
    for i, finding in enumerate(all_findings, 1):
        finding["finding_id"] = f"TT-F-{i:03d}"
        sev = finding.get("severity", "INFO")
        if sev in results["findings_by_severity"]:
            results["findings_by_severity"][sev] += 1

    # Step 7: Overall risk rating
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
        logger.info(
            f"Analysis complete: {len(all_findings)} findings, "
            f"{len(results['patterns'])} patterns, "
            f"risk={results['overall_risk']} ({results['analysis_duration_seconds']}s)"
        )

    return results
