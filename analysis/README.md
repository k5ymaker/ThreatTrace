# OpenCode Log Analysis Module for ThreatTrace

## Overview

The OpenCode Log Analysis Module integrates OpenCode CLI with ThreatTrace for advanced log analysis, IOC extraction, MITRE ATT&CK threat hunting, and MITRE CAR incident investigation.

## Architecture

```
Detection Engine (YARA/Sigma) -> OpenCode Log Analysis Module -> Analytics Modules -> Report Builder
```

## Key Features

1. **Deep Semantic IOC Extraction** - Uses OpenCode CLI for advanced IOC extraction from log content
2. **MITRE ATT&CK Threat Hunting** - Maps findings to MITRE ATT&CK techniques and tactics
3. **MITRE CAR Incident Investigation** - Applies MITRE CAR detection logic for incident detection
4. **Combined Reporting** - Integrates results with existing Sigma/YARA/Analytics reports

## Module Components

### `OpenCodeLogAnalyzer` Class
Main class that orchestrates all analysis capabilities:
- IOC extraction via OpenCode CLI
- MITRE ATT&CK technique mapping
- MITRE CAR detection engine
- Combined report generation

### Data Models
- `IOCFinding`: Extracted Indicators of Compromise
- `MITREAttackFinding`: MITRE ATT&CK technique findings
- `MITRECARFinding`: MITRE CAR detection findings
- `AnalysisResult`: Container for all analysis results

### Integration Functions
- `run_opencode_analysis`: Convenience function for integration with ThreatTrace pipeline
- `save_report_enhanced`: Enhanced report builder with OpenCode analysis

## MITRE ATT&CK Integration

The module maintains mappings between detected behaviors and ATT&CK techniques:

```python
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
    # ... more mappings
}
```

## MITRE CAR Integration

The module implements CAR detection logic for common attack scenarios:

```python
CAR_DETECTIONS = {
    "CAR-2016-03-001": {
        "name": "Batch file that deletes shadow copies",
        "description": "Detects batch files or commands attempting to delete volume shadow copies",
        "detection_logic": "vssadmin delete shadows OR wmic shadowcopy delete OR wbadmin delete catalog",
        "log_sources": ["windows_security", "sysmon", "windows_event"],
        "severity": "HIGH",
    },
    # ... more detections
}
```

## OpenCode CLI Integration

The module uses OpenCode CLI for semantic analysis:

```python
# Example OpenCode CLI invocation for IOC extraction
cmd = [
    "opencode", "analyze",
    "--input", "/path/to/logfile.log",
    "--type", "ioc-extraction",
    "--output", "json",
    "--timeout", "120"
]
```

## Prompt Engineering for OpenCode

The module uses curated prompts for different analysis tasks:

### Prompt 1: IOC Extraction
Extracts all Indicators of Compromise (IOCs): IPv4/IPv6 addresses, URLs, domains, email addresses, usernames, file paths, hashes, CVE identifiers, JWT tokens, API keys, MAC addresses.

### Prompt 2: Threat Hunting (MITRE ATT&CK)
Analyzes log events and identifies potential attack patterns based on MITRE ATT&CK framework.

### Prompt 3: Incident Investigation (MITRE CAR)
Using MITRE CAR detection logic, analyzes for data exfiltration patterns, lateral movement indicators, privilege escalation chains, credential dumping, and command and control beacons.

## Configuration

```python
config = {
    "enabled": True,
    "timeout": 120,
    "max_retries": 2,
    "temp_dir": "/tmp/threattrace",
    
    "mitre": {
        "attack": {
            "enabled": True,
            "cache_ttl": 3600
        },
        "car": {
            "enabled": True,
            "custom_analytics": []
        }
    },
    
    "ioc_extraction": {
        "extract_all": True,
        "filter_private_ips": True,
        "min_risk_score": 0.2
    }
}
```

## CLI Integration

```bash
# New CLI options for main.py
python main.py --path /var/log/auth.log \
  --enable-opencode-analysis \
  --mitre-attack-hunting \
  --mitre-car-investigation \
  --opencode-timeout 120 \
  --output ./reports
```

## Output Structure

```json
{
  "analysis_metadata": {
    "analysis_id": "TT-ANA-XXXX",
    "timestamp": "2024-XX-XX",
    "log_type": "apache",
    "modules_run": ["yara", "sigma", "opencode_log_analyzer", "baseline", "frequency", "beaconing", "topn", "timeline"]
  },
  "findings": {
    "yara_findings": [],
    "sigma_findings": [],
    "opencode_findings": {
      "ioc_extraction": {},
      "mitre_attack": {
        "techniques": [],
        "tactics": [],
        "chains": []
      },
      "mitre_car": {
        "detections": []
      }
    }
  },
  "analytics_results": {},
  "overall_risk": "HIGH"
}
```

## Testing

Run the test suite:

```bash
python3 test_opencode_analyzer.py
python3 test_full_integration.py
```

## Implementation Status

All phases from the design document have been implemented:

1. **Phase 1: Core Infrastructure** ✓
   - Created `analysis/opencode_log_analyzer.py`
   - Implemented OpenCode CLI wrapper class
   - Basic IOC extraction via CLI

2. **Phase 2: MITRE Integration** ✓
   - Added MITRE ATT&CK technique mapping
   - Implemented MITRE CAR detection engine
   - Added threat hunting logic

3. **Phase 3: Report Integration** ✓
   - Modified `core/report_builder_enhanced.py` to incorporate new findings
   - Added combined report generation
   - Updated JSON output schema

4. **Phase 4: Testing & Optimization** ✓
   - Tested with various log formats
   - Validated MITRE mapping accuracy
   - Optimized OpenCode prompt efficiency

## Usage Example

```python
from analysis.opencode_log_analyzer import run_opencode_analysis

# Run analysis on parsed log events
results = run_opencode_analysis(events, log_type="windows_security", config={
    "timeout": 120,
    "max_retries": 2
})

# Results include:
# - opencode_findings: List of findings in ThreatTrace format
# - opencode_report: Detailed analysis report
# - analysis_metadata: Metadata about the analysis
```

## Integration with ThreatTrace Pipeline

To integrate with the main ThreatTrace pipeline:

1. Use the enhanced detection engine (`detection/engine_enhanced.py`)
2. Enable OpenCode analysis via CLI flag `--enable-opencode-analysis`
3. Generate enhanced reports using `core/report_builder_enhanced.py`

The module follows existing ThreatTrace architecture patterns and integrates seamlessly with the current pipeline.