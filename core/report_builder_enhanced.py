"""ThreatTrace Report Builder — Enhanced with OpenCode Analysis."""

from __future__ import annotations

import base64
import io
import json
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Import the original report builder functions
from .report_builder import (
    SEVERITY_COLORS,
    SEVERITY_BG,
    HTTP_STATUS_COLORS,
    TLP_COLORS,
    UA_CATEGORY_COLORS,
    _esc,
    _badge,
    _sev_badge,
    _risk_badge,
    _ua_badge,
    _tlp_badge,
    _threat_row,
    _inline_img,
    _table,
    _collapsible,
    _stat_grid,
    _section_card,
    _no_data,
    _try_matplotlib,
    _fig_to_b64,
    _chart_severity_donut,
    _chart_top_ips,
    _chart_timeline,
    _chart_ua_categories,
    _chart_http_status,
    _chart_auth_failures_users,
    _ip_field,
    _ua_field,
    _extract_ip_summary,
    _extract_user_summary,
    _extract_ua_summary,
    _CSS,
    _html_shell,
    _s0_cover,
    _toc,
    _s1_exec_summary,
    _ip_risk_score,
    _s2_source_intel,
    _s3_user_auth,
    _s4_http,
    _s_event_name_analysis,
    _s5_network,
    _s6_events_temporal,
    _s8_nist,
)

# ---------------------------------------------------------------------------
# Section 7: Enhanced Detection Findings (YARA / Sigma / OpenCode)
# ---------------------------------------------------------------------------


def _s7_findings_enhanced(analysis: Dict) -> str:
    """Enhanced detection findings section with OpenCode analysis."""
    findings = analysis.get("findings", [])
    sev = analysis.get("findings_by_severity", {})

    # Check for OpenCode findings
    opencode_findings = analysis.get("opencode_findings", [])
    opencode_report = analysis.get("opencode_report", {})
    opencode_analysis_performed = analysis.get("opencode_analysis_performed", False)

    if not findings and not opencode_findings:
        return _section_card(
            "sec7",
            "7. Detection Findings (YARA / Sigma / OpenCode)",
            _no_data("No rule-based findings in this analysis."),
            "&#x1F50D;",
        )

    # Statistics including OpenCode
    total_findings = len(findings) + len(opencode_findings)

    sev_stats = _stat_grid(
        [
            (sev.get("CRITICAL", 0), "Critical", SEVERITY_COLORS["CRITICAL"]),
            (sev.get("HIGH", 0), "High", SEVERITY_COLORS["HIGH"]),
            (sev.get("MEDIUM", 0), "Medium", SEVERITY_COLORS["MEDIUM"]),
            (sev.get("LOW", 0), "Low", SEVERITY_COLORS["LOW"]),
            (total_findings, "Total Findings", "#2c3e50"),
            (len(opencode_findings), "OpenCode Findings", "#8e44ad"),
        ]
    )

    # Group findings by source/module
    by_module: Dict[str, list] = {"yara": [], "sigma": [], "opencode": [], "other": []}

    for f in findings:
        module = f.get("module", "").lower()
        if "yara" in module:
            by_module["yara"].append(f)
        elif "sigma" in module:
            by_module["sigma"].append(f)
        elif "opencode" in module:
            by_module["opencode"].append(f)
        else:
            by_module["other"].append(f)

    # Add standalone OpenCode findings
    for f in opencode_findings:
        by_module["opencode"].append(f)

    # Module statistics
    module_stats = _stat_grid(
        [
            (len(by_module["yara"]), "YARA", "#1e8449"),
            (len(by_module["sigma"]), "Sigma", "#1a5276"),
            (len(by_module["opencode"]), "OpenCode", "#8e44ad"),
            (len(by_module["other"]), "Other", "#7f8c8d"),
        ]
    )

    findings_html = ""

    # OpenCode Analysis Summary
    if opencode_analysis_performed and opencode_report:
        opencode_meta = opencode_report.get("analysis_metadata", {})
        opencode_iocs = opencode_report.get("ioc_extraction", {})
        opencode_attack = opencode_report.get("mitre_attack", {})
        opencode_car = opencode_report.get("mitre_car", {})

        opencode_summary = f"""
        <div style="margin:1em 0;padding:1em;background:#f8f0ff;border-radius:8px;border-left:4px solid #8e44ad;">
            <h4 style="color:#8e44ad;margin-top:0;">&#x1F4DD; OpenCode Analysis Summary</h4>
            <p><strong>Analysis Duration:</strong> {opencode_meta.get("analysis_duration", 0):.2f}s<br>
            <strong>OpenCode Version:</strong> {opencode_meta.get("opencode_version", "unknown")}</p>
            
            <div style="display:flex;flex-wrap:wrap;gap:10px;margin-top:10px;">
                <div style="flex:1;min-width:120px;background:#fff;padding:8px;border-radius:6px;">
                    <div style="font-size:1.5em;font-weight:bold;color:#8e44ad;">{opencode_meta.get("total_iocs", 0)}</div>
                    <div style="font-size:0.8em;color:#666;">IOCs Extracted</div>
                </div>
                <div style="flex:1;min-width:120px;background:#fff;padding:8px;border-radius:6px;">
                    <div style="font-size:1.5em;font-weight:bold;color:#c0392b;">{opencode_meta.get("total_attack_findings", 0)}</div>
                    <div style="font-size:0.8em;color:#666;">MITRE ATT&CK</div>
                </div>
                <div style="flex:1;min-width:120px;background:#fff;padding:8px;border-radius:6px;">
                    <div style="font-size:1.5em;font-weight:bold;color:#e67e22;">{opencode_meta.get("total_car_findings", 0)}</div>
                    <div style="font-size:0.8em;color:#666;">MITRE CAR</div>
                </div>
            </div>
        """

        # IOC Summary
        if opencode_iocs.get("summary"):
            ioc_summary = opencode_iocs["summary"]
            opencode_summary += f"""
            <div style="margin-top:15px;">
                <h5 style="color:#666;margin-bottom:5px;">IOC Risk Distribution</h5>
                <div style="display:flex;gap:5px;margin-bottom:10px;">
                    <span style="flex:1;background:#c0392b;color:white;padding:3px 8px;border-radius:4px;text-align:center;font-size:0.8em;">
                        High: {ioc_summary.get("high_risk", 0)}
                    </span>
                    <span style="flex:1;background:#e67e22;color:white;padding:3px 8px;border-radius:4px;text-align:center;font-size:0.8em;">
                        Medium: {ioc_summary.get("medium_risk", 0)}
                    </span>
                    <span style="flex:1;background:#27ae60;color:white;padding:3px 8px;border-radius:4px;text-align:center;font-size:0.8em;">
                        Low: {ioc_summary.get("low_risk", 0)}
                    </span>
                </div>
            </div>
            """

        opencode_summary += "</div>"
        findings_html += opencode_summary

    # Group findings by severity
    by_sev: Dict[str, list] = {}
    all_findings = findings + opencode_findings

    for f in all_findings:
        s = f.get("severity", "INFO")
        by_sev.setdefault(s, []).append(f)

    # Render findings by severity
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        group = by_sev.get(level, [])
        if not group:
            continue

        cards = ""
        for f in group:
            fid = f.get("finding_id", "")
            name = f.get("rule_name") or f.get("name", "Unknown")
            desc = f.get("description", "")
            source = f.get("source", "")
            module = f.get("module", "").lower()

            # Module badge
            module_color = {
                "yara": "#1e8449",
                "sigma": "#1a5276",
                "opencode": "#8e44ad",
            }.get(module, "#7f8c8d")

            module_badge = f'<span style="background:{module_color};color:white;padding:2px 8px;border-radius:10px;font-size:0.7em;margin-left:5px;">{module.upper()}</span>'

            # MITRE technique badge
            tech = f.get("mitre_technique") or f.get("technique_id", "")
            tech_tag = f'<span class="mitre-tag">{_esc(tech)}</span>' if tech else ""

            # MITRE CAR badge
            car_id = f.get("mitre_car_id", "")
            car_tag = (
                f'<span style="background:#d35400;color:white;padding:2px 8px;border-radius:10px;font-size:0.7em;margin-left:5px;">CAR: {_esc(car_id)}</span>'
                if car_id
                else ""
            )

            # IOCs
            iocs = f.get("iocs", [])
            ioc_tags = ""
            if iocs:
                ioc_tags = '<div style="margin-top:5px;"><strong>IOCs:</strong> '
                for ioc in iocs[:3]:  # Show first 3 IOCs
                    ioc_type = ioc.get("type", "")
                    ioc_value = ioc.get("value", "")
                    if ioc_type and ioc_value:
                        ioc_tags += f'<span class="ioc-tag">{_esc(ioc_type)}: {_esc(ioc_value[:50])}</span> '
                ioc_tags += "</div>"

            # Context/evidence
            context = f.get("context", "")
            evidence_html = ""
            if context:
                evidence_html = f'<div class="finding-evidence"><code>{_esc(context[:300])}</code></div>'

            # Recommended action
            recommendation = f.get("recommended_action", "")
            rec_html = ""
            if recommendation:
                rec_html = f'<div style="margin-top:5px;padding:5px;background:#eaf4fc;border-radius:4px;font-size:0.9em;"><strong>Recommendation:</strong> {_esc(recommendation)}</div>'

            cards += (
                f'<div class="finding-block {level}">'
                f'<div class="finding-title">[{_esc(fid)}] {_esc(name)} '
                f"&nbsp;{_sev_badge(level)}{module_badge}{tech_tag}{car_tag}</div>"
                f'<div class="finding-meta">Source: {_esc(source)} | '
                f"Module: {module.upper()}</div>"
                f'<div class="finding-desc">{_esc(desc)}</div>'
                f"{ioc_tags}{evidence_html}{rec_html}</div>"
            )

        findings_html += _collapsible(
            f"{level} — {len(group)} finding(s)",
            cards,
            open_=(level in ("CRITICAL", "HIGH")),
        )

    # Detailed OpenCode Analysis Section
    if opencode_analysis_performed and opencode_report:
        detailed_html = "<h3>&#x1F4DD; Detailed OpenCode Analysis</h3>"

        # IOC Extraction Details
        iocs_by_type = opencode_report.get("ioc_extraction", {}).get("iocs_by_type", {})
        if iocs_by_type:
            detailed_html += "<h4>IOC Extraction by Type</h4>"
            ioc_rows = []
            for ioc_type, ioc_list in sorted(iocs_by_type.items()):
                if ioc_list:
                    high_risk = len([i for i in ioc_list if i.get("risk") == "high"])
                    total = len(ioc_list)
                    ioc_rows.append(
                        [
                            f"<code>{_esc(ioc_type)}</code>",
                            str(total),
                            str(high_risk),
                            ", ".join(
                                [_esc(i.get("value", "")[:30]) for i in ioc_list[:3]]
                            ),
                        ]
                    )

            if ioc_rows:
                detailed_html += _table(
                    ["IOC Type", "Total", "High Risk", "Examples"], ioc_rows
                )

        # MITRE ATT&CK Techniques
        attack_techniques = opencode_report.get("mitre_attack", {}).get(
            "techniques", []
        )
        if attack_techniques:
            detailed_html += "<h4>MITRE ATT&CK Techniques Identified</h4>"
            attack_rows = []
            for tech in attack_techniques[:10]:  # Show top 10
                attack_rows.append(
                    [
                        f'<span class="mitre-tag">{_esc(tech.get("technique_id", ""))}</span>',
                        _esc(tech.get("technique_name", "")),
                        _esc(tech.get("tactic", "")),
                        _sev_badge(tech.get("severity", "MEDIUM")),
                        _esc(tech.get("evidence", "")[:100]),
                    ]
                )

            if attack_rows:
                detailed_html += _table(
                    ["Technique", "Name", "Tactic", "Severity", "Evidence"], attack_rows
                )

        # MITRE CAR Detections
        car_detections = opencode_report.get("mitre_car", {}).get("detections", [])
        if car_detections:
            detailed_html += "<h4>MITRE CAR Detections</h4>"
            car_rows = []
            for car in car_detections:
                car_rows.append(
                    [
                        f"<code>{_esc(car.get('car_id', ''))}</code>",
                        _esc(car.get("detection_name", "")),
                        _sev_badge(car.get("severity", "MEDIUM")),
                        str(car.get("matching_events_count", 0)),
                        f"{car.get('confidence', 0):.1%}",
                    ]
                )

            if car_rows:
                detailed_html += _table(
                    ["CAR ID", "Detection Name", "Severity", "Events", "Confidence"],
                    car_rows,
                )

        findings_html += _collapsible(
            "Detailed OpenCode Analysis", detailed_html, open_=False
        )

    body = sev_stats + module_stats + findings_html
    return _section_card(
        "sec7", "7. Detection Findings (YARA / Sigma / OpenCode)", body, "&#x1F50D;"
    )


# ---------------------------------------------------------------------------
# Enhanced Executive Summary with OpenCode
# ---------------------------------------------------------------------------


def _s1_exec_summary_enhanced(analysis: Dict, meta: Dict) -> str:
    """Enhanced executive summary with OpenCode analysis."""
    original_html = _s1_exec_summary(analysis, meta)

    # Check for OpenCode analysis
    opencode_analysis_performed = analysis.get("opencode_analysis_performed", False)
    opencode_report = analysis.get("opencode_report", {})

    if not opencode_analysis_performed:
        return original_html

    # Add OpenCode summary to executive summary
    opencode_meta = opencode_report.get("analysis_metadata", {})
    opencode_iocs = opencode_report.get("ioc_extraction", {})

    opencode_summary = f"""
    <div style="margin:1em 0;padding:1em;background:#f8f0ff;border-radius:8px;border-left:4px solid #8e44ad;">
        <h4 style="color:#8e44ad;margin-top:0;">&#x1F4DD; OpenCode AI Analysis</h4>
        <p>Advanced AI-powered analysis performed using OpenCode CLI with MITRE ATT&CK/CAR integration.</p>
        
        <div style="display:flex;flex-wrap:wrap;gap:10px;margin-top:10px;">
            <div style="flex:1;min-width:100px;background:#fff;padding:8px;border-radius:6px;text-align:center;">
                <div style="font-size:1.2em;font-weight:bold;color:#8e44ad;">{opencode_meta.get("total_iocs", 0)}</div>
                <div style="font-size:0.8em;color:#666;">IOCs Found</div>
            </div>
            <div style="flex:1;min-width:100px;background:#fff;padding:8px;border-radius:6px;text-align:center;">
                <div style="font-size:1.2em;font-weight:bold;color:#c0392b;">{opencode_meta.get("total_attack_findings", 0)}</div>
                <div style="font-size:0.8em;color:#666;">ATT&CK Techniques</div>
            </div>
            <div style="flex:1;min-width:100px;background:#fff;padding:8px;border-radius:6px;text-align:center;">
                <div style="font-size:1.2em;font-weight:bold;color:#e67e22;">{opencode_meta.get("total_car_findings", 0)}</div>
                <div style="font-size:0.8em;color:#666;">CAR Detections</div>
            </div>
        </div>
    """

    # Add top IOCs
    top_iocs = opencode_iocs.get("top_iocs", [])
    if top_iocs:
        opencode_summary += (
            "<h5 style='color:#666;margin-top:15px;'>Top High-Risk IOCs</h5>"
        )
        for ioc in top_iocs[:5]:
            risk_color = {"high": "#c0392b", "medium": "#e67e22", "low": "#27ae60"}.get(
                ioc.get("risk", "low"), "#666"
            )
            opencode_summary += f"""
            <div style="margin:5px 0;padding:5px;background:#fff;border-radius:4px;border-left:3px solid {risk_color};">
                <code>{_esc(ioc.get("type", ""))}: {_esc(ioc.get("value", ""))}</code>
                <span style="float:right;font-size:0.8em;color:{risk_color};">
                    {ioc.get("risk", "").upper()} ({ioc.get("confidence", 0):.0%})
                </span>
            </div>
            """

    opencode_summary += "</div>"

    # Insert OpenCode summary after the original executive summary content
    # We need to extract the body from the section card
    import re

    body_pattern = r'<div class="section-body">(.*?)</div>\s*</div>\s*$'
    match = re.search(body_pattern, original_html, re.DOTALL)

    if match:
        original_body = match.group(1)
        enhanced_body = original_body + opencode_summary
        enhanced_html = original_html.replace(original_body, enhanced_body)
        return enhanced_html

    return original_html


# ---------------------------------------------------------------------------
# Enhanced Table of Contents
# ---------------------------------------------------------------------------


def _toc_enhanced() -> str:
    """Enhanced table of contents with OpenCode mention."""
    items = [
        ("sec1", "1. Executive Summary"),
        ("sec2", "2. Source Intelligence — IPs &amp; User Agents"),
        ("sec3", "3. User &amp; Authentication Analysis"),
        ("sec4", "4. Web &amp; HTTP Analysis"),
        ("sec5", "5. Network &amp; Protocol Analysis"),
        ("sec6", "6. Event &amp; Temporal Analysis"),
        ("sec7", "7. Detection Findings (YARA / Sigma / OpenCode)"),
        ("sec8", "8. NIST Phases: Containment &amp; Post-Incident"),
        ("sec9", "9. Technical Appendix"),
    ]
    li = "".join(f'<li><a href="#{i}">{l}</a></li>' for i, l in items)
    return f'<div class="nav-toc"><h2>Table of Contents</h2><ol>{li}</ol></div>'


# ---------------------------------------------------------------------------
# Main enhanced report generation function
# ---------------------------------------------------------------------------


def save_report_enhanced(
    analysis: Dict[str, Any],
    output_dir: str = "./",
    format_: str = "html",
    events: Optional[List[Dict]] = None,
    analyst: str = "Unknown Analyst",
    tlp: str = "TLP:AMBER",
) -> Optional[str]:
    """
    Save enhanced HTML/JSON report with OpenCode analysis.

    Parameters
    ----------
    analysis      : dict from detection engine (must contain events for HTML)
    output_dir    : directory to write report files
    format_       : "html", "json", or "both"
    events        : optional raw events list (for fallback HTML generation)
    analyst       : analyst name for report header
    tlp           : TLP classification string

    Returns
    -------
    Primary report file path, or None if HTML generation fails.
    """
    import json as json_module
    from pathlib import Path

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Generate timestamp for filenames
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = out_dir / f"threattrace_report_enhanced_{ts}.json"
    html_path = out_dir / f"threattrace_report_enhanced_{ts}.html"

    # Always generate JSON (contains all data)
    analysis_exportable = {
        k: v
        for k, v in analysis.items()
        if k not in ("events", "_events")  # skip raw events to keep file small
    }
    analysis_exportable["total_events"] = analysis.get("total_events", 0)
    analysis_exportable["analyst"] = analyst
    analysis_exportable["tlp"] = tlp
    analysis_exportable["generated_at"] = datetime.now(timezone.utc).isoformat()

    # Add OpenCode metadata if available
    if analysis.get("opencode_analysis_performed"):
        analysis_exportable["opencode_analysis"] = {
            "performed": True,
            "findings_count": len(analysis.get("opencode_findings", [])),
            "report_summary": analysis.get("opencode_report", {}).get(
                "analysis_metadata", {}
            ),
        }

    json_path.write_text(
        json_module.dumps(analysis_exportable, indent=2, default=str),
        encoding="utf-8",
    )

    # HTML report (if requested)
    if format_ in ("html", "both"):
        # Use provided events or extract from analysis
        html_events = events or analysis.get("events") or analysis.get("_events", [])
        analysis["_events"] = html_events  # for HTML builders

        # Build HTML sections
        meta = {
            "analysis_id": analysis.get("analysis_id", f"TT-ANA-{ts}"),
            "log_type": analysis.get("log_type", "unknown"),
            "file_path": analysis.get("file_path", "N/A"),
            "total_events": analysis.get("total_events", 0),
            "analyst": analyst,
            "tlp": tlp,
            "generated_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            ),
            "detection_tier": analysis.get("detection_meta", {}).get("tier", ""),
            "detection_structure": analysis.get("detection_meta", {}).get(
                "structure", ""
            ),
            "detection_signals": analysis.get("detection_meta", {}).get("signals", []),
            "detection_ruleset": analysis.get("detection_meta", {}).get("ruleset", {}),
        }

        html_body = (
            _s0_cover(
                {**meta, "overall_risk": analysis.get("overall_risk", "INFORMATIONAL")}
            )
            + _toc_enhanced()
            + '<div class="content">'
            + _s1_exec_summary_enhanced(analysis, meta)
            + _s2_source_intel(analysis)
            + _s3_user_auth(analysis)
            + _s4_http(analysis)
            + _s5_network(analysis)
            + _s6_events_temporal(analysis)
            + _s7_findings_enhanced(analysis)
            + _s8_nist(analysis)
            + "</div>"
            + "<footer>ThreatTrace v2.0 — Enhanced with OpenCode AI Analysis</footer>"
        )

        html_full = _html_shell(
            f"ThreatTrace Report — {analysis.get('log_type', 'unknown')}", html_body
        )

        html_path.write_text(html_full, encoding="utf-8")

    # Return primary path based on format
    if format_ == "json":
        return str(json_path)
    elif format_ == "html":
        return str(html_path)
    else:  # both
        return f"{json_path},{html_path}"


# ---------------------------------------------------------------------------
# Convenience function for backward compatibility
# ---------------------------------------------------------------------------


def save_report(*args, **kwargs):
    """Wrapper for backward compatibility - uses enhanced version."""
    return save_report_enhanced(*args, **kwargs)
