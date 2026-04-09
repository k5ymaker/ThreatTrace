# ThreatTrace - Comprehensive Documentation

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Module Documentation](#module-documentation)
4. [Data Flow](#data-flow)
5. [Configuration](#configuration)
6. [Detection Rules](#detection-rules)
7. [Usage](#usage)

---

## Overview

### What is ThreatTrace?

ThreatTrace is a **terminal-based cybersecurity log analysis platform** designed to help security analysts quickly analyze various log sources, detect threats using multiple detection methods, and generate actionable reports.

### Key Features

- **30+ Log Format Support**: Apache, Nginx, IIS, Syslog, Windows EVTX, AWS CloudTrail, Azure, GCP, and many more
- **Multi-Layer Detection**: YARA rules, Sigma rules, correlation engine, and heuristic analysis
- **Advanced Analytics**: Baseline profiling, frequency analysis, beaconing detection, timeline reconstruction
- **Rich Terminal UI**: Interactive menus, colored output, progress bars using Rich library
- **Report Generation**: HTML and JSON formats with detailed findings and visualizations
- **Configurable**: YAML-based configuration with TLP (Traffic Light Protocol) classification support
- **Auto-Detection**: Automatic log type detection using fingerprint analysis
- **Threat Intelligence**: High-risk country indicators, scanner User-Agent detection, suspicious port monitoring

### Technology Stack

- **Language**: Python 3.9+
- **CLI Framework**: Click
- **Terminal UI**: Rich
- **Threat Detection**: YARA-Python, Sigma
- **Log Parsing**: python-evtx, custom parsers
- **Data Analysis**: Pandas, SciPy
- **Testing**: Pytest

---

## Architecture

### Directory Structure

```
ThreatTrace/
├── main.py                    # Main entry point (CLI & interactive)
├── config.yaml                # Global configuration
├── pyproject.toml             # Python package configuration
├── requirements.txt           # Dependencies
│
├── threattrace/               # Main Python package
│   ├── __init__.py
│   ├── cli.py                 # CLI entry point (Click-based)
│   ├── app.py                 # Main application orchestrator
│   ├── shell.py               # Interactive shell
│   │
│   ├── parsers/               # Log parsers (organized by type)
│   │   ├── __init__.py        # Parser registry
│   │   ├── base.py            # Base parser class
│   │   ├── web/               # Web server logs
│   │   ├── linux/             # Linux logs
│   │   ├── windows/           # Windows logs
│   │   ├── network/           # Network logs
│   │   ├── cloud/             # Cloud logs
│   │   ├── auth/              # Authentication logs
│   │   ├── endpoint/          # Endpoint logs
│   │   └── generic/           # Generic parsers
│   │
│   ├── detectors/             # Detection engines
│   │   ├── yara_engine.py    # YARA rule scanner
│   │   └── sigma_engine.py   # Sigma rule scanner
│   │
│   ├── models/                # Data models
│   │   ├── finding.py         # Finding model
│   │   ├── log_event.py       # Log event model
│   │   └── report.py          # Report model
│   │
│   ├── reports/               # Report generation
│   │   ├── reporter.py        # Report generator
│   │   └── templates/         # HTML report templates
│   │
│   ├── fingerprint/           # Log type auto-detection
│   │   └── detector.py
│   │
│   └── tui/                   # Terminal UI components
│       ├── console.py         # Console utilities
│       ├── menu.py            # Interactive menus
│       ├── scan_menu.py       # Scan configuration
│       ├── rules_menu.py      # Rules management
│       ├── logsource_menu.py  # Log source selection
│       ├── deps_menu.py       # Dependencies menu
│       └── state.py           # Application state
│
├── core/                      # Core functionality
│   ├── file_handler.py        # File loading and management
│   ├── parser_router.py       # Parser routing logic
│   ├── auto_detector.py       # Auto log type detection
│   ├── menu.py                # Interactive menu system
│   ├── models.py              # Core data models
│   └── report_builder.py      # Report building
│
├── detection/                # Detection engine
│   ├── engine.py              # Main detection orchestrator
│   ├── yara_scanner.py        # YARA scanning module
│   ├── sigma_scanner.py       # Sigma rule scanning
│   ├── correlator.py          # Event correlation
│   ├── event_matrix.py        # Event matrix analysis
│   └── rules/                 # Detection rules directory
│
├── analytics/                # Advanced analytics
│   ├── orchestrator.py        # Analytics orchestrator
│   ├── baseline.py            # Baseline profiling
│   ├── frequency.py           # Frequency analysis
│   ├── beaconing.py           # C2 beaconing detection
│   ├── timeline.py            # Timeline analysis
│   ├── topn.py                # Top-N statistics
│   ├── metrics.py             # Metrics calculation
│   └── correlations/          # Correlation rules
│
├── parsers/                  # Standalone parsers (legacy)
│   ├── apache_parser.py
│   ├── nginx_parser.py
│   ├── iis_parser.py
│   ├── windows_evtx_parser.py
│   ├── sysmon_parser.py
│   ├── linux_*.py
│   ├── dns_parser.py
│   ├── firewall_parser.py
│   ├── cloud_*_parser.py
│   └── [many more...]
│
├── reports/                  # Generated reports directory
│
├── rules/                    # Detection rules
│   ├── yara/                 # YARA rules (by category)
│   │   ├── web/
│   │   ├── linux/
│   │   ├── windows/
│   │   ├── network/
│   │   ├── cloud/
│   │   └── common/
│   │
│   └── sigma/                # Sigma rules (by category)
│       ├── web/
│       ├── linux/
│       ├── windows/
│       ├── network/
│       └── cloud/
│
├── data/                     # Sample/test data
│
└── tests/                    # Test suite
```

---

## Module Documentation

### 1. Entry Points

#### `main.py` (Main Entry Point)
- **Location**: Root directory
- **Purpose**: Primary entry point for ThreatTrace
- **Functionality**:
  - Supports two modes: CLI mode and Interactive mode
  - Lazy imports for performance optimization
  - Integrates all components (file handling, parsing, detection, analytics, reporting)
  - Command-line argument parsing
  - Environment setup and validation

#### `threattrace/cli.py` (CLI Module)
- **Location**: `threattrace/cli.py`
- **Purpose**: Click-based CLI command definitions
- **Functionality**:
  - Defines CLI options: `--type`, `--output`, `--format`, `--rules`, `--verbose`, `--quiet`, `--no-tui`, `--list-types`
  - Provides help text and usage examples
  - Manages CLI-specific configurations

#### `threattrace/app.py` (Application Orchestrator)
- **Location**: `threattrace/app.py`
- **Purpose**: Main application orchestrator that wires all components together
- **Key Classes**:
  - `ThreatTraceApp`: Main application class
- **Key Methods**:
  - `run()`: Main execution flow
  - `_resolve_files()`: Expands directories to individual files
  - `_resolve_log_type()`: Determines log source type
  - `_scan_files()`: Parses and scans files
  - `_display_results()`: Shows findings in terminal
  - `_write_report()`: Saves reports to disk

#### `threattrace/shell.py` (Interactive Shell)
- **Location**: `threattrace/shell.py`
- **Purpose**: Interactive shell for menu-driven operation
- **Functionality**:
  - Provides interactive menu system
  - Allows step-by-step analysis configuration

---

### 2. Parsers Module (`threattrace/parsers/`)

The parsers module is responsible for converting raw log lines into normalized events. Each parser handles a specific log format and extracts relevant fields.

#### Base Parser (`threattrace/parsers/base.py`)

All parsers inherit from a base parser class that provides:
- Common parsing utilities
- Field normalization
- Error handling
- Logging infrastructure

#### Parser Categories

##### Web Server Logs (`threattrace/parsers/web/`)

| Parser | Log Types | Description |
|--------|-----------|-------------|
| `apache_parser.py` | Apache Access Log | Parses Apache HTTP server access logs |
| `nginx_parser.py` | Nginx Access Log | Parses Nginx web server access logs |
| `iis_parser.py` | IIS Log | Parses Microsoft IIS web server logs |
| `haproxy_parser.py` | HAProxy Log | Parses HAProxy load balancer logs |

**Extracted Fields**: timestamp, src_ip, dst_ip, method, uri, status_code, bytes_sent, user_agent

##### Linux Logs (`threattrace/parsers/linux/`)

| Parser | Log Types | Description |
|--------|-----------|-------------|
| `syslog_parser.py` | Syslog | Standard Linux system logging |
| `auth_parser.py` | Auth Log | Authentication logs (login, sudo, ssh) |
| `auditd_parser.py` | Auditd | Linux Audit daemon logs |
| `bash_parser.py` | Bash History | Bash command history |
| `kern_parser.py` | Kernel Log | Linux kernel messages |

**Extracted Fields**: timestamp, hostname, process, pid, username, message, action

##### Windows Logs (`threattrace/parsers/windows/`)

| Parser | Log Types | Description |
|--------|-----------|-------------|
| `evtx_parser.py` | Windows EVTX | Windows Event Log (binary format) |
| `sysmon_parser.py` | Sysmon | Windows Sysmon logs |
| `powershell_parser.py` | PowerShell | PowerShell execution logs |

**Extracted Fields**: timestamp, event_id, level, source, message, process, user

##### Network Logs (`threattrace/parsers/network/`)

| Parser | Log Types | Description |
|--------|-----------|-------------|
| `firewall_parser.py` | Firewall | Generic firewall logs (iptables, etc.) |
| `cisco_parser.py` | Cisco ASA | Cisco firewall logs |
| `paloalto_parser.py` | Palo Alto | Palo Alto Networks logs |
| `fortinet_parser.py` | Fortinet | Fortinet FortiGate logs |
| `pfsense_parser.py` | PfSense | PfSense firewall logs |
| `zeek_parser.py` | Zeek/Bro | Network traffic analysis logs |
| `suricata_parser.py` | Suricata | Intrusion detection logs |
| `dns_parser.py` | DNS | DNS query/response logs |
| `squid_parser.py` | Squid | Squid proxy logs |

**Extracted Fields**: timestamp, src_ip, dst_ip, src_port, dst_port, protocol, action, bytes

##### Cloud Logs (`threattrace/parsers/cloud/`)

| Parser | Log Types | Description |
|--------|-----------|-------------|
| `aws_cloudtrail_parser.py` | AWS CloudTrail | AWS API activity logs |
| `aws_vpc_parser.py` | AWS VPC Flow | AWS VPC Flow Logs |
| `azure_parser.py` | Azure Activity | Microsoft Azure activity logs |
| `gcp_parser.py` | GCP Audit | Google Cloud Platform audit logs |

**Extracted Fields**: timestamp, user, action, resource, source_ip, aws_region, event_type

##### Authentication Logs (`threattrace/parsers/auth/`)

| Parser | Log Types | Description |
|--------|-----------|-------------|
| `okta_parser.py` | Okta | Okta identity logs |
| `ad_parser.py` | Active Directory | Windows AD security logs |
| `ssh_parser.py` | SSH | SSH authentication logs |
| `vpn_parser.py` | VPN | VPN connection logs |

**Extracted Fields**: timestamp, username, src_ip, action, status, service

##### Endpoint Logs (`threattrace/parsers/endpoint/`)

| Parser | Log Types | Description |
|--------|-----------|-------------|
| `docker_parser.py` | Docker | Docker container logs |
| `kubernetes_parser.py` | K8s | Kubernetes pod/logs |

##### Database Logs (`threattrace/parsers/database/`)

| Parser | Log Types | Description |
|--------|-----------|-------------|
| `mysql_parser.py` | MySQL | MySQL database logs |
| `postgres_parser.py` | PostgreSQL | PostgreSQL logs |
| `mssql_parser.py` | MSSQL | Microsoft SQL Server logs |

##### Email Logs (`threattrace/parsers/email/`)

| Parser | Log Types | Description |
|--------|-----------|-------------|
| `postfix_parser.py` | Postfix | Postfix mail server logs |

##### Generic Parsers (`threattrace/parsers/generic/`)

| Parser | Log Types | Description |
|--------|-----------|-------------|
| `json_parser.py` | JSON Lines | JSON-formatted log files |
| `csv_parser.py` | CSV | Comma-separated values |
| `plaintext_parser.py` | Plaintext | Generic plaintext logs |

#### Parser Registry (`threattrace/parsers/__init__.py`)

The parser registry maintains a mapping of log types to parser classes and provides:
- Dynamic parser lookup
- Parser registration
- Type inference

---

### 3. Detection Engines

#### YARA Engine (`threattrace/detectors/yara_engine.py`)

**Purpose**: Pattern matching using YARA rules

**Functionality**:
- Loads YARA rules from `rules/yara/` directory
- Scans parsed log events against rule patterns
- Categories covered:
  - Web attacks (SQLi, XSS, path traversal, web shells)
  - Linux attacks (privilege escalation, persistence)
  - Windows attacks (malware, lateral movement)
  - Network C2 patterns
  - Anti-forensics/evasion techniques

**Key Methods**:
- `load_rules()`: Load YARA rules from files
- `scan()`: Scan events against rules
- `get_matches()`: Retrieve detection results

#### Sigma Engine (`threattrace/detectors/sigma_engine.py`)

**Purpose**: Rule-based detection using Sigma format

**Functionality**:
- Loads Sigma rules from `rules/sigma/` directory
- Converts Sigma rules to searchable patterns
- Supports multiple backends

**Key Methods**:
- `load_rules()`: Load Sigma rules
- `convert_rule()`: Convert Sigma to internal format
- `scan()`: Apply rules to events

#### Detection Engine (`detection/engine.py`)

**Purpose**: Main detection orchestrator

**Functionality**:
- Coordinates YARA, Sigma, and heuristic detections
- Aggregates findings
- Manages detection lifecycle

**Key Methods**:
- `detect()`: Run all detection engines
- `add_finding()`: Add new finding
- `get_findings()`: Retrieve all findings

#### YARA Scanner (`detection/yara_scanner.py`)

**Purpose**: Low-level YARA scanning

**Functionality**:
- Wrapper around yara-python
- Handles rule compilation
- Manages scanning sessions

#### Sigma Scanner (`detection/sigma_scanner.py`)

**Purpose**: Sigma rule scanning

**Functionality**:
- Sigma rule parsing
- Pattern matching
- Detection aggregation

#### Correlator (`detection/correlator.py`)

**Purpose**: Event correlation across multiple log entries

**Functionality**:
- Time-based correlation (default 5-minute window)
- Pattern detection across events
- Attack chain identification
- Correlates:
  - Brute force attempts
  - Port scans
  - Data exfiltration
  - Privilege escalation

**Key Methods**:
- `correlate()`: Perform correlation analysis
- `detect_patterns()`: Identify attack patterns

#### Event Matrix (`detection/event_matrix.py`)

**Purpose**: Build structured event matrices for analysis

**Functionality**:
- Creates data structures from log events
- Identifies suspicious patterns
- Maintains pattern catalog

---

### 4. Analytics Module (`analytics/`)

The analytics module provides advanced threat detection through statistical analysis and pattern recognition.

#### Orchestrator (`analytics/orchestrator.py`)

**Purpose**: Coordinates all analytics modules

**Functionality**:
- Runs analytics in sequence
- Aggregates results
- Manages analytics pipeline

#### Baseline Profiler (`analytics/baseline.py`)

**Purpose**: Establish baseline activity patterns

**Functionality**:
- Learns normal activity patterns
- Identifies deviations from baseline
- Creates activity profiles per source

**Key Methods**:
- `build_baseline()`: Create baseline from historical data
- `detect_anomalies()`: Find deviations from baseline
- `get_deviation_score()`: Calculate anomaly score

#### Frequency Analyzer (`analytics/frequency.py`)

**Purpose**: Statistical frequency analysis

**Functionality**:
- Analyzes event frequencies
- Detects unusual patterns
- Identifies periodic behaviors

**Key Methods**:
- `analyze()`: Perform frequency analysis
- `detect_anomalies()`: Find frequency anomalies

#### Beaconing Detector (`analytics/beaconing.py`)

**Purpose**: Detect C2 beaconing patterns

**Functionality**:
- Identifies regular callback patterns
- Uses statistical analysis (standard deviation threshold)
- Detects communication patterns indicative of compromised hosts

**Key Methods**:
- `detect_beacons()`: Identify beaconing behavior
- `analyze_intervals()`: Analyze communication intervals

#### Timeline Builder (`analytics/timeline.py`)

**Purpose**: Chronological event reconstruction

**Functionality**:
- Builds attack timelines
- Visualizes attack chains
- Sequences events chronologically

**Key Methods**:
- `build_timeline()`: Create chronological timeline
- `identify_chains()`: Detect attack chains

#### Top-N Reporter (`analytics/topn.py`)

**Purpose**: Top-N statistics

**Functionality**:
- Ranks attackers, targets, events
- Identifies most active threats
- Provides ranking statistics

**Key Methods**:
- `get_top_attackers()`: Most active source IPs
- `get_top_targets()`: Most targeted systems
- `get_top_events()`: Most common event types

#### Metrics Calculator (`analytics/metrics.py`)

**Purpose**: Calculate security metrics

**Functionality**:
- Severity scoring
- Risk calculation
- Metric aggregation

#### Correlations (`analytics/correlations/`)

**Purpose**: Advanced correlation rules

**Functionality**:
- Cross-source correlation
- Threat hunting rules
- Anomaly detection

---

### 5. Models (`threattrace/models/`)

Data models for structured information representation.

#### Finding Model (`threattrace/models/finding.py`)

**Purpose**: Represent security findings

**Attributes**:
- `rule_id`: Detection rule identifier
- `severity`: Critical/High/Medium/Low/Info
- `title`: Finding title
- `description`: Detailed description
- `source`: Log source
- `timestamp`: Event timestamp
- `source_ip`: Source IP address
- `destination_ip`: Destination IP address
- `username`: Associated username
- `raw_event`: Original log entry
- `tags`: Additional metadata

#### Log Event Model (`threattrace/models/log_event.py`)

**Purpose**: Represent normalized log events

**Attributes**:
- `timestamp`: Event timestamp
- `log_type`: Log source type
- `raw`: Original raw log line
- `src_ip`: Source IP
- `dst_ip`: Destination IP
- `src_port`: Source port
- `dst_port`: Destination port
- `username`: Username
- `hostname`: Hostname
- `process`: Process name
- `pid`: Process ID
- `action`: Action performed
- `status`: Status (success/failure)
- `method`: HTTP method
- `uri`: Requested URI
- `status_code`: HTTP status code
- `bytes_sent`: Bytes sent
- `bytes_recv`: Bytes received
- `user_agent`: User agent string
- `protocol`: Protocol used
- `severity`: Event severity
- `event_id`: Event identifier
- `message`: Log message
- `country`: Geographic country
- `tags`: Additional tags

#### Report Model (`threattrace/models/report.py`)

**Purpose**: Represent analysis reports

**Attributes**:
- `report_id`: Unique identifier
- `timestamp`: Report generation time
- `analyst`: Analyst name
- `tlp`: TLP classification
- `files_analyzed`: List of analyzed files
- `findings`: List of findings
- `statistics`: Analysis statistics
- `timeline`: Event timeline
- `recommendations`: Security recommendations

---

### 6. Report Generation (`threattrace/reports/`)

#### Reporter (`threattrace/reports/reporter.py`)

**Purpose**: Generate analysis reports

**Functionality**:
- Aggregates findings and analytics
- Formats output (HTML/JSON)
- Uses Jinja2 templates

**Output Formats**:
- **HTML**: Interactive HTML report with charts
- **JSON**: Machine-readable JSON format

**Key Methods**:
- `generate()`: Create report
- `to_html()`: Convert to HTML
- `to_json()`: Convert to JSON

#### Templates (`threattrace/reports/templates/`)

**Purpose**: HTML report templates

**Functionality**:
- Jinja2-based templating
- Responsive design
- Interactive charts

---

### 7. Fingerprinting (`threattrace/fingerprint/`)

#### Log Type Detector (`threattrace/fingerprint/detector.py`)

**Purpose**: Automatic log type detection

**Functionality**:
- Analyzes log file structure
- Matches against known patterns
- Identifies log format

**Detection Methods**:
- Header pattern matching
- Field analysis
- Timestamp format recognition
- Key-value pair identification

---

### 8. Terminal UI (`threattrace/tui/`)

#### Console (`threattrace/tui/console.py`)

**Purpose**: Console output utilities

**Functionality**:
- Rich-formatted output
- Progress bars (tqdm)
- Table rendering
- Color-coded severity display

#### Menu System (`threattrace/tui/menu.py`)

**Purpose**: Interactive menu framework

**Functionality**:
- Menu navigation
- User input handling
- Screen rendering

#### Scan Menu (`threattrace/tui/scan_menu.py`)

**Purpose**: Scan configuration interface

**Functionality**:
- File/directory selection
- Scan options configuration
- Rule selection

#### Rules Menu (`threattrace/tui/rules_menu.py`)

**Purpose**: Rules management interface

**Functionality**:
- View available rules
- Enable/disable rules
- Rule category browsing

#### Log Source Menu (`threattrace/tui/logsource_menu.py`)

**Purpose**: Log source selection

**Functionality**:
- Browse supported log types
- Auto-detection settings
- Custom parser configuration

#### Dependencies Menu (`threattrace/tui/deps_menu.py`)

**Purpose**: Dependencies management

**Functionality**:
- Check installed dependencies
- Version information
- Installation guidance

#### State Management (`threattrace/tui/state.py`)

**Purpose**: Application state management

**Functionality**:
- Menu state tracking
- User preferences
- Session management

---

### 9. Core Modules (`core/`)

#### File Handler (`core/file_handler.py`)

**Purpose**: File loading and management

**Functionality**:
- Recursive directory scanning
- File type detection
- Large file handling
- Encoding detection

**Key Methods**:
- `load_files()`: Load files from paths
- `resolve_directory()`: Expand directories
- `detect_encoding()`: Determine file encoding

#### Parser Router (`core/parser_router.py`)

**Purpose**: Route logs to appropriate parsers

**Functionality**:
- Log type matching
- Parser selection
- Fallback handling

**Key Methods**:
- `route()`: Determine appropriate parser
- `get_parser()`: Retrieve parser instance

#### Auto Detector (`core/auto_detector.py`)

**Purpose**: Automatic log type detection

**Functionality**:
- File content analysis
- Pattern matching
- Confidence scoring

#### Core Models (`core/models.py`)

**Purpose**: Core data structures

**Functionality**:
- Event dataclasses
- Finding structures
- Configuration models

#### Report Builder (`core/report_builder.py`)

**Purpose**: Report construction

**Functionality**:
- Report structure building
- Data aggregation
- Format conversion

---

## Data Flow

### Processing Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                        INPUT LAYER                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │  Log Files   │  │ Directories  │  │  EVTX Files  │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     FILE HANDLER                                │
│  - Load files                                                   │
│  - Detect encoding                                             │
│  - Expand directories                                          │
│  - Validate file types                                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AUTO DETECTOR                                 │
│  - Analyze file content                                        │
│  - Identify log format                                          │
│  - Determine log type                                           │
│  - Confidence scoring                                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PARSER ROUTER                                 │
│  - Match log type to parser                                     │
│  - Select appropriate parser                                   │
│  - Handle parser fallback                                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       PARSERS                                    │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐        │
│  │  Web   │ │ Linux  │ │Windows │ │ Network│ │ Cloud  │  ...   │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘        │
│                                                                  │
│  Output: Normalized Log Events                                  │
│  - timestamp, src_ip, dst_ip, username, action, etc.          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   DETECTION ENGINE                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  YARA SCANNER                                             │  │
│  │  - Pattern matching                                       │  │
│  │  - Web attacks, malware, C2 patterns                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  SIGMA SCANNER                                            │  │
│  │  - Rule-based detection                                    │  │
│  │  - Sigma rule conversion                                   │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  CORRELATION ENGINE                                       │  │
│  │  - Cross-event correlation                                 │  │
│  │  - Attack chain detection                                  │  │
│  │  - Brute force, port scan, exfiltration detection         │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Output: Security Findings                                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ANALYTICS                                   │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐    │
│  │  Baseline  │ │ Frequency  │ │ Beaconing  │ │ Timeline   │    │
│  │  Profiler  │ │  Analyzer  │ │  Detector  │ │  Builder   │    │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘    │
│  ┌────────────┐ ┌────────────┐                                 │
│  │   Top-N    │ │  Metrics   │                                 │
│  │  Reporter  │ │ Calculator │                                 │
│  └────────────┘ └────────────┘                                 │
│                                                                  │
│  Output: Analytics Results                                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   REPORT GENERATOR                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  HTML Report                                              │  │
│  │  - Interactive dashboard                                   │  │
│  │  - Charts and visualizations                              │  │
│  │  - Filterable findings                                     │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  JSON Report                                               │  │
│  │  - Machine-readable format                                │  │
│  │  - API integration                                         │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Output: Analysis Reports                                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        OUTPUT                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Terminal   │  │  HTML File   │  │  JSON File   │          │
│  │    Display   │  │   Report     │  │   Report     │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

### Event Processing Details

1. **Input**: Log files in various formats
2. **File Handler**: Loads files, handles encoding, expands directories
3. **Auto Detector**: Identifies log type based on content patterns
4. **Parser Router**: Selects the appropriate parser for the log type
5. **Parser**: Converts raw log lines into normalized events with standard fields
6. **Detection Engine**: 
   - YARA scanner matches patterns
   - Sigma scanner applies rules
   - Correlator finds attack patterns
7. **Analytics**: Advanced analysis including baseline, frequency, beaconing, timeline
8. **Reporter**: Generates HTML/JSON reports

---

## Configuration

### Configuration File (`config.yaml`)

The configuration file controls all aspects of ThreatTrace behavior.

#### General Settings

```yaml
general:
  version: "1.0.0"
  tool_name: "ThreatTrace"
  tlp: "RED"              # TLP Classification: WHITE/GREEN/AMBER/RED
  timezone: "UTC"         # Timezone for timestamps
  max_events: 100000      # Maximum events to process
  log_level: "INFO"       # Logging level
```

#### Output Settings

```yaml
output:
  directory: "./reports"   # Report output directory
  formats:                # Enabled output formats
    - html
    - json
  template: "default"     # Report template
```

#### Severity Thresholds

```yaml
severity:
  thresholds:
    critical: 80          # Score >= 80 = Critical
    high: 60              # Score >= 60 = High
    medium: 40            # Score >= 40 = Medium
    low: 20               # Score >= 20 = Low
```

#### Detection Engine Configuration

```yaml
detection:
  yara:
    rules_dir: "./rules/yara"
    timeout: 30
  
  sigma:
    rules_dir: "./rules/sigma"
    backend: "python"
  
  correlation:
    time_window: 300      # 5 minutes
    min_events: 3
  
  heuristics:
    brute_force:
      enabled: true
      threshold: 5
    port_scan:
      enabled: true
      threshold: 10
    beaconing:
      enabled: true
      threshold: 0.1
    exfiltration:
      enabled: true
      threshold: 10000000  # 10MB
```

#### Threat Intelligence

```yaml
threat_intel:
  high_risk_countries:
    - RU    # Russia
    - CN    # China
    - KP    # North Korea
    - IR    # Iran
    - SY    # Syria
  
  scanner_user_agents:
    - "sqlmap"
    - "nikto"
    - "nmap"
    - "metasploit"
    # ... 30+ patterns
  
  suspicious_ports:
    high_risk:
      - 4444  # Metasploit
      - 5555  # Adb
      - 6666  # IRC
      - 31337 # Back Orifice
    watch:
      - 21    # FTP
      - 23    # Telnet
      - 445   # SMB
```

---

## Detection Rules

### YARA Rules (`rules/yara/`)

YARA rules are organized by category:

| Category | File | Description |
|----------|------|-------------|
| Web | `web/web_attacks.yr` | SQL injection, XSS, path traversal, web shells, scanners |
| Linux | `linux/linux_attacks.yr` | Privilege escalation, persistence, reverse shells |
| Windows | `windows/windows_attacks.yr` | Malware patterns, lateral movement, registry attacks |
| Network | `network/c2_patterns.yr` | Command & control communication patterns |
| Cloud | `cloud/cloud_attacks.yr` | Cloud-specific attack patterns |
| Common | `common/evasion.yr` | Anti-forensics, evasion techniques |

### Sigma Rules (`rules/sigma/`)

Sigma rules are YAML-based detection rules organized by category:

| Category | Description |
|----------|-------------|
| `web/` | Web application attacks |
| `linux/` | Linux system events |
| `windows/` | Windows security events |
| `network/` | Network-based threats |
| `cloud/` | Cloud service attacks |

### Rule Format Example (YARA)

```yar
rule web_sql_injection {
    meta:
        description = "Detects SQL injection attempt"
        severity = "HIGH"
    
    strings:
        $sql_keywords = /(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP)\b)/i
        $quote = /'/
        $comment = /--/
    
    condition:
        $sql_keywords and ($quote or $comment)
}
```

### Rule Format Example (Sigma)

```yaml
title: Possible SQL Injection
id: 1000001
status: stable
description: Detects SQL injection attempts
author: ThreatTrace
date: 2024/01/01

logsource:
  category: webserver

detection:
  keywords:
    - UNION SELECT
    - OR 1=1
    - ORDER BY
  
  condition: keywords

fields:
  - uri
  - client_ip
```

---

## Usage

### Command Line Interface

#### Basic Usage

```bash
# Analyze a single log file
python main.py --path /var/log/auth.log

# Analyze multiple files
python main.py --path /var/log/apache2/access.log --path /var/log/apache2/error.log

# Analyze a directory recursively
python main.py --path /var/log/ --recursive

# Analyze Windows EVTX file
python main.py --path /logs/windows_events.evtx
```

#### Options

| Option | Description | Example |
|--------|-------------|---------|
| `--path` | Path to log file or directory | `--path /var/log/auth.log` |
| `--type` | Specify log type | `--type apache` |
| `--output` | Output directory | `--output /reports/` |
| `--format` | Report format (html/json/both) | `--format both` |
| `--rules` | Custom rules directory | `--rules ./my_rules/` |
| `--analyst` | Analyst name | `--analyst "John Doe"` |
| `--tlp` | TLP classification | `--tlp AMBER` |
| `--verbose` | Verbose output | `--verbose` |
| `--quiet` | Quiet mode | `--quiet` |
| `--no-tui` | Disable TUI | `--no-tui` |
| `--list-types` | List supported log types | `--list-types` |

#### Interactive Mode

```bash
# Start interactive mode
python main.py

# The TUI will guide you through:
# 1. Log source selection
# 2. File/directory selection
# 3. Analysis options
# 4. Report generation
```

### Supported Log Types

ThreatTrace supports the following log types:

#### Web Server Logs
- Apache Access Log
- Apache Error Log
- Nginx Access Log
- Nginx Error Log
- IIS W3C Log
- HAProxy Log

#### Linux System Logs
- Syslog
- Auth Log
- Auditd
- Bash History
- Kernel Log (dmesg)

#### Windows Logs
- Windows Event Log (EVTX)
- Sysmon
- PowerShell

#### Network Logs
- Firewall Logs (generic)
- Cisco ASA
- Palo Alto Networks
- Fortinet FortiGate
- PfSense
- Zeek/Bro
- Suricata
- DNS Logs
- Squid Proxy

#### Cloud Logs
- AWS CloudTrail
- AWS VPC Flow Logs
- Azure Activity Log
- GCP Audit Log

#### Authentication Logs
- Okta
- Active Directory
- SSH
- VPN

#### Endpoint Logs
- Docker
- Kubernetes

#### Database Logs
- MySQL
- PostgreSQL
- Microsoft SQL Server

#### Email Logs
- Postfix

---

## Severity Classification

Findings are classified by severity:

| Severity | Score Range | Color | Description |
|----------|-------------|-------|-------------|
| Critical | 80-100 | Red | Immediate threat, active attack |
| High | 60-79 | Orange | Significant threat, likely attack |
| Medium | 40-59 | Yellow | Potential threat, suspicious activity |
| Low | 20-39 | Blue | Minor anomalies, informational |
| Info | 0-19 | Green | Informational, no threat |

---

## Report Output

### HTML Report

The HTML report includes:
- Executive summary
- Severity distribution chart
- Timeline of events
- Detailed findings table
- Top attackers list
- Top targets list
- Analytics visualizations

### JSON Report

The JSON report includes:
- Report metadata
- Findings array
- Statistics
- Timeline
- Raw event data

---

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all dependencies are installed (`pip install -r requirements.txt`)
2. **YARA Compilation Errors**: Check YARA rules syntax
3. **Memory Issues**: Reduce `max_events` in config.yaml
4. **Encoding Issues**: Specify encoding in config or use `--encoding` flag

### Performance Optimization

- Use `--type` to specify log type (skips auto-detection)
- Limit `max_events` for large log files
- Use `--no-tui` for faster CLI-only operation

---

## Appendix

### File Extensions to Log Types Mapping

| Extension | Log Type |
|-----------|----------|
| `.log` | auto-detect |
| `.evtx` | windows_evtx |
| `.json` | json |
| `.csv` | csv |
| `.access` | apache |
| `.error` | nginx_error |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `THREATTRACE_CONFIG` | Path to custom config file |
| `THREATTRACE_RULES` | Path to custom rules directory |
| `THREATTRACE_OUTPUT` | Default output directory |

---

*Document Version: 1.0*
*Last Updated: 2026*
