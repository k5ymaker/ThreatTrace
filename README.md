# ThreatTrace

<div align="center">

![ThreatTrace](https://img.shields.io/badge/ThreatTrace-v2.0-brightgreen) ![Python](https://img.shields.io/badge/Python-3.9+-blue) ![License](https://img.shields.io/badge/License-MIT-yellow) ![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)

### Enterprise-Grade Cybersecurity Log Analysis & Threat Detection Platform

**[Features](#key-features)** · **[Architecture](#architecture)** · **[Installation](#installation)** · **[Usage](#usage)** · **[Documentation](#documentation)**

</div>

---

## Overview

ThreatTrace is a powerful **terminal-based cybersecurity log analysis platform** designed for security analysts to quickly analyze various log sources, detect threats using multiple detection methods, and generate actionable reports.

Built with Python 3.9+, ThreatTrace combines advanced pattern matching, statistical analysis, and correlation engines to provide comprehensive threat detection capabilities.

---

## How It Works

ThreatTrace implements a **multi-stage processing pipeline** that transforms raw log data into structured events, runs detection engines (YARA + Sigma rules), performs statistical analytics, and generates reports.

### Processing Pipeline

```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────┐
│   Log Files  │───▶│ File Handler │───▶│Auto Detector │───▶│   Parser    │
│ (30+ types) │    │              │    │              │    │   Router    │
└─────────────┘    └──────────────┘    └──────────────┘    └─────────────┘
                                                                      │
                                                                      ▼
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────┐
│   Reports   │◀───│   Reporter   │◀───│  Analytics  │◀───│  Detection  │
│ (HTML/JSON) │    │              │    │   (5 mods)  │    │   Engine   │
└─────────────┘    └──────────────┘    └──────────────┘    └─────────────┘
```

**Stage 1: File Loading** (`core/file_handler.py`)
- Accepts file paths or directories
- Handles `.gz` compression transparently (auto-decompresses)
- Detects Windows EVTX binary files via magic bytes (`ElfFile\x00`)
- Returns file descriptors with path, size, and extension

**Stage 2: Auto-Detection** (`core/auto_detector.py`)
- 4-phase detection: Extension → Signature Matching → Structural Analysis → Semantic Analysis
- Uses 90+ weighted regex/keyword/JSON key patterns
- Confidence tiers: CONFIRMED (≥80%), LIKELY (50-79%), POSSIBLE (20-49%), FALLBACK (<20%)
- Maps log type to appropriate detection rules (Sigma/YARA categories)

**Stage 3: Parsing** (`core/parser_router.py`)
- Routes each log type to the correct parser (30+ log formats supported)
- Normalizes events into a standard dict structure with: `raw`, `timestamp`, `log_type`, `source_ip`, `username`, `url`, `command_line`, etc.
- Supports streaming for large files (chunk-based processing for files >200MB)

**Stage 4: Detection** (`detection/engine.py`)
- **YARA Scanner**: Pattern matching against raw event content
- **Sigma Scanner**: Rule-based detection using YAML rules with full condition support (AND, OR, NOT, count aggregations)
- **Correlation Engine**: 31 analytics functions for multi-event threat patterns

**Stage 5: Analytics** (`analytics/orchestrator.py`)
- Baseline Profiler: Deviation detection from learned normal behavior
- Frequency Analyzer: Statistical outlier detection (z-score)
- Beaconing Detector: C2 callback pattern identification (jitter, autocorrelation, FFT)
- Top-N Reporter: Ranking of attackers, targets, events
- Timeline Builder: Attack chain reconstruction
- Privilege Escalation Correlation: Windows-specific attack chain detection

**Stage 6: Reporting** (`core/report_builder.py`)
- HTML and JSON output formats
- TLP (Traffic Light Protocol) classification support
- Interactive HTML with severity-colored tables

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Layer Detection** | YARA rules, Sigma rules, correlation engine, and heuristic analysis |
| **30+ Log Formats** | Apache, Nginx, IIS, Syslog, Windows EVTX, AWS CloudTrail, Azure, GCP, and more |
| **Advanced Analytics** | Baseline profiling, frequency analysis, beaconing detection, timeline reconstruction |
| **Auto-Detection** | Automatic log type identification using fingerprint analysis |
| **Rich Terminal UI** | Interactive menus, colored output, progress bars |
| **IOC Extraction** | Automated extraction of Indicators of Compromise |
| **Report Generation** | HTML and JSON formats with detailed findings |
| **TLP Support** | Traffic Light Protocol classification for reports |

---

## Requirements

### Core Dependencies

```
rich>=13.0          # Terminal UI rendering
click>=8.0          # CLI framework
pyyaml>=6.0         # Sigma rule parsing
python-evtx>=0.7.4 # Windows Event Log parsing
xmltodict>=0.13     # XML parsing
python-dateutil>=2.8  # Date/time handling
jinja2>=3.1         # Report templating
tqdm>=4.65          # Progress bars
colorama>=0.4       # Cross-platform colors
tabulate>=0.9       # Table formatting
pandas>=2.0         # Data analysis (analytics)
scipy>=1.11         # Statistical functions (beaconing detection)
pytest>=7.0         # Testing framework
user-agents>=2.2    # User-agent parsing
Whoosh>=2.7.4       # Full-text search indexing
drain3>=0.9.11      # Log clustering
```

### Optional Dependencies

```
yara-python>=4.3   # YARA rule scanning (highly recommended)
numpy               # Numerical computing (analytics modules)
```

---

## Module Architecture

### Core Modules

#### `core/file_handler.py` — File Loading
- **Purpose**: Handles file/directory intake, compression, and EVTX detection
- **Key Functions**:
  - `load_files(path, recursive)` — Main entry point, returns list of file descriptors
  - `_decompress_gz()` — Transparent .gz decompression to temp files
  - `_detect_evtx()` — Magic byte detection for Windows Event Logs
- **Supported Input**: `.log`, `.json`, `.xml`, `.evtx`, `.gz`, `.txt`, `.csv`

#### `core/auto_detector.py` — Log Type Auto-Detection
- **Purpose**: Identifies log format using multi-phase fingerprinting
- **Detection Phases**:
  1. **Extension shortcut**: `.evtx` → `windows_evtx` immediately
  2. **Signature matching**: ~90 weighted regex/keyword/JSON key patterns
  3. **Structural analysis**: Detects JSON, XML, CEF, syslog, key=value, W3C formats
  4. **Semantic analysis**: Domain-specific keyword inference (auth, cloud, network)
- **Confidence Tiers**: CONFIRMED (≥80%), LIKELY (50-79%), POSSIBLE (20-49%), FALLBACK (<20%)
- **Ruleset Mapping**: Automatically selects appropriate Sigma/YARA rule categories based on detected log type

#### `core/parser_router.py` — Parser Routing
- **Purpose**: Routes log types to appropriate parsers, normalizes events
- **Key Functions**:
  - `get_parser(log_type)` — Returns parser instance for specified type
  - `parse_file(descriptor, log_type)` — Parse single file → normalized event list
  - `stream_file_chunked()` — Streaming parser for large files (>200MB)
- **Event Normalization**: All parsers output a standard dict structure:
  ```python
  {
      "raw": "original log line",
      "timestamp": "2024-01-15T14:32:00",
      "log_type": "apache",
      "source_ip": "192.168.1.100",
      "username": "admin",
      "url": "/admin/login",
      "method": "POST",
      "status_code": 401,
      "command_line": "...",
      "user_agent": "..."
  }
  ```

#### `core/models.py` — Data Models
- **Purpose**: Core data structures for log records and analysis results
- **Key Classes**:
  - `LogRecord`: Dataclass for normalized log events
  - `StatResult`: Analytics module output structure
  - `dict_to_log_record()`: Converter from dict to LogRecord

#### `core/report_builder.py` — Report Generation
- **Purpose**: Generates HTML and JSON reports
- **Features**: TLP classification, analyst name, timestamp

---

### Detection Modules

#### `detection/engine.py` — Detection Orchestrator
- **Purpose**: Main detection pipeline coordinator
- **Flow**:
  1. Build event matrix
  2. Run YARA scanner
  3. Run Sigma scanner
  4. Run correlation engine
  5. Run suspicious pattern catalogue
  6. Calculate severity and risk rating
- **Output**: Complete analysis results with findings, patterns, correlations

#### `detection/yara_scanner.py` — YARA Pattern Matching
- **Purpose**: Pattern-based threat detection using YARA rules
- **Features**:
  - Auto-compiles all `.yar` rules in `detection/rules/yara/`
  - Fallback to per-file compilation if combined compilation fails
  - Scans both raw file content and individual event fields
  - Extracts meta fields: severity, MITRE tactic/technique, description
- **Finding Structure**:
  ```python
  {
      "finding_id": "TT-F-001",
      "rule_name": "mimikatz_detection",
      "rule_type": "YARA",
      "severity": "HIGH",
      "mitre_tactic": "Credential Access",
      "mitre_technique": "T1003",
      "matched_events": [...],
      "indicators": {"ips": [], "usernames": [], "commands": []}
  }
  ```

#### `detection/sigma_scanner.py` — Sigma Rule Engine
- **Purpose**: Rule-based detection using Sigma YAML rules
- **Features**:
  - Full Sigma condition support: AND, OR, NOT, count aggregations, wildcards
  - Field mapping: Sigma field names → normalized event keys
  - Modifiers: contains, startswith, endswith, re (regex)
  - Evaluates against all events, returns matching events per rule
- **Sigma Rule Categories** (in `detection/rules/sigma/`):
  - `windows/`: LSASS dumping, DCSync, Kerberoasting, UAC bypass
  - `linux/`: Reverse shell, SUID abuse, SSH brute force
  - `network/`: C2 beaconing, DNS tunneling, port scans
  - `cloud/`: Root login, service account abuse, S3 exfiltration
  - `web/`: Web shells, SQL injection, XSS

#### `detection/correlator.py` — Correlation Engine
- **Purpose**: Multi-event threat pattern detection (31 functions)
- **Correlation Functions**:
  - **Traffic**: Top IPs by requests/bandwidth, unique IPs, user agents
  - **Auth**: Login failures by user/IP, account lockouts, success-after-failure
  - **HTTP**: Status codes, top URLs, methods, referrers
  - **Network**: Destination ports, blocked vs allowed, internal anomalies
  - **DNS**: Queried domains (DGA detection), NXDOMAIN rate, query volume
  - **Temporal**: Timeline distribution, rate spikes, IP first/last seen
  - **Process**: Suspicious commands, top processes, scheduled tasks
  - **Cloud**: API calls by identity, failed APIs, privilege escalation indicators
  - **User-Agent**: Parser with scanner detection
- **Output**: Dictionary of correlation results keyed by function name

---

### Analytics Modules

#### `analytics/orchestrator.py` — Analytics Orchestrator
- **Purpose**: Coordinates all analytics modules, renders terminal output
- **Modules** (run sequentially or in parallel via ThreadPoolExecutor):
  - `baseline` — Deviation detection
  - `frequency` — Statistical frequency analysis
  - `beaconing` — C2 callback detection
  - `topn` — Top-N ranking
  - `timeline` — Attack chain reconstruction
- **Windows-specific**: Privilege escalation correlation engine

#### `analytics/baseline.py` — Baseline Profiler
- **Purpose**: Learns "normal" behavior from 70% of data, flags deviations in remaining 30%
- **Dimensions**: Configurable per log type (bytes transferred, status codes, IP request rates, etc.)
- **Detection**: Sigma-based deviation threshold (configurable, default 3σ)
- **Output**: List of deviations with dimension, observed value, baseline mean, sigma distance

#### `analytics/frequency.py` — Frequency Analyzer
- **Purpose**: Statistical frequency analysis with outlier detection
- **Metrics**: Per-field unique values, mean frequency, IQR (Q1-Q3)
- **Outlier Detection**: Z-score based (high and low frequency outliers)
- **Output**: Field frequencies with outlier lists

#### `analytics/beaconing.py` — Beaconing Detector
- **Purpose**: Identifies C2 callback patterns
- **Algorithms** (any 2 of 3 must trigger):
  1. **Jitter Score**: Coefficient of Variation (CV = std/mean) of inter-arrival times
  2. **Autocorrelation**: Lag-1 autocorrelation of delta series
  3. **FFT Periodicity**: Dominant frequency peak via FFT
- **Scoring**: Combined beacon score (0-1) with severity rating

#### `analytics/topn.py` — Top-N Reporter
- **Purpose**: Ranks attackers, targets, and events by activity
- **Categories**: Source IPs, destination IPs, URLs, user agents, usernames, status codes
- **Features**: Cumulative percentage, anomaly flagging, peak time window detection

#### `analytics/timeline.py` — Timeline Builder
- **Purpose**: Chronological reconstruction of multi-stage attack chains
- **Features**:
  - Event correlation across time windows
  - Kill chain completeness scoring
  - Log source aggregation
- **Output**: Attack chains with stages, duration, pivot values

#### `analytics/correlations/privesc_chains.py` — Privilege Escalation Correlation
- **Purpose**: Windows-specific attack chain detection
- **Techniques**: UAC bypass, token manipulation, SID history injection, DLL hijacking, etc.
- **Output**: Detected chains with MITRE technique mapping, IOCs, recommendations

---

### IOC Extraction Module

#### `extractor/engine.py` — IOC Extraction Engine
- **Purpose**: Automated extraction of Indicators of Compromise
- **Supported IOC Types** (16):
  - Network: IPv4, IPv6, domains, URLs, email addresses, MAC addresses
  - Files: MD5, SHA1, SHA256
  - Credentials: AWS keys, JWTs
  - Vulnerability: CVEs
  - System: Windows paths, Unix paths, usernames, user agents
- **Features**:
  - Risk scoring (0-1) based on: entity type, occurrence count, statistical rarity, suspicious keywords, suspicious TLDs
  - Pivot capability: Drill into specific IOCs to see all related log lines
  - Context discovery: Co-occurring IOCs
- **Output**: Sorted by risk score, with sample lines, timestamps, sources

#### `extractor/line_indexer.py` — Line Indexing
- **Purpose**: Fast lookup of which lines contain which IOCs
- **Features**: In-memory index, timestamp extraction, source tracking

#### `extractor/patterns.py` — Pattern Definitions
- **Purpose**: Regex patterns for each IOC type
- **Pattern Set**: Comprehensive patterns for all 16 IOC categories

---

### Search Module

#### `search/boolean_eval.py` — Boolean Search Engine
- **Purpose**: Advanced log file search with boolean operators
- **Supported Operators**: AND, OR, NOT, XOR with unlimited nested parentheses
- **Operator Precedence**: NOT > AND > XOR > OR
- **Features**:
  - Case-insensitive matching
  - Wildcard support
  - Quoted string support for multi-word phrases
- **Usage**:
  ```bash
  python main.py --path /var/log/auth.log
  # Then use: error AND 404 OR "connection refused"
  ```

#### `search/event_search.py` — Event Search
- **Purpose**: High-level event searching with filters
- **Features**: Field-based filtering, time range queries

#### `search/keyword_search.py` — Keyword Search
- **Purpose**: Simple keyword-based log searching

---

### Parsers

ThreatTrace includes 30+ log format parsers in `threattrace/parsers/`:

| Category | Log Types |
|----------|-----------|
| **Web** | Apache, Nginx, IIS, HAProxy |
| **Windows** | EVTX, Sysmon, PowerShell |
| **Linux** | Syslog, Auth Log, Auditd |
| **Network** | Cisco ASA, Fortinet, Palo Alto, pfSense, Squid, Suricata, Zeek |
| **Cloud** | AWS CloudTrail, Azure Activity, GCP Audit, Okta |
| **Auth** | SSH, VPN, Active Directory |
| **Containers** | Docker, Kubernetes |
| **Database** | MySQL, MSSQL |
| **Email** | Postfix |

---

## Architecture

```
ThreatTrace/
├── main.py                      # Main entry point (CLI & Interactive)
├── core/                        # Core functionality
│   ├── file_handler.py          # File loading & management
│   ├── auto_detector.py         # Log type auto-detection
│   ├── parser_router.py         # Parser routing logic
│   ├── menu.py                  # Interactive menu system
│   ├── models.py                # Core data models
│   └── report_builder.py        # Report generation
│
├── detection/                  # Detection engine
│   ├── engine.py                # Main detection orchestrator
│   ├── yara_scanner.py          # YARA scanning module
│   ├── sigma_scanner.py         # Sigma rule scanning
│   ├── correlator.py            # Event correlation engine
│   ├── event_matrix.py          # Event matrix analysis
│   └── rules/                   # Detection rules (YARA & Sigma)
│       ├── yara/                # YARA rules by category
│       └── sigma/               # Sigma rules by category
│
├── analytics/                  # Advanced analytics
│   ├── orchestrator.py          # Analytics orchestration
│   ├── baseline.py              # Baseline profiling
│   ├── frequency.py             # Frequency analysis
│   ├── beaconing.py             # C2 beaconing detection
│   ├── timeline.py              # Timeline reconstruction
│   ├── topn.py                  # Top-N statistics
│   ├── metrics.py               # Metrics calculation
│   └── correlations/            # Advanced correlation rules
│
├── extractor/                  # IOC extraction engine
├── search/                     # Boolean search functionality
├── threattrace/                # Main Python package
│   ├── parsers/                # Log parsers by category
│   ├── detectors/              # Detection engines
│   ├── models/                 # Data models
│   └── reports/                # Report generation
│
└── data/                       # Sample/test data
```

---

## Processing Pipeline

```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────┐
│   Log Files  │───▶│ File Handler │───▶│Auto Detector │───▶│   Parser    │
│ (30+ types) │    │              │    │              │    │   Router    │
└─────────────┘    └──────────────┘    └──────────────┘    └─────────────┘
                                                                     │
                                                                     ▼
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────┐
│   Reports   │◀───│   Reporter   │◀───│  Analytics  │◀───│  Detection  │
│ (HTML/JSON) │    │              │    │   (5 mods)  │    │   Engine   │
└─────────────┘    └──────────────┘    └──────────────┘    └─────────────┘
```

---

## Installation

### Prerequisites

- Python 3.9+
- pip (package manager)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/your-repo/ThreatTrace.git
cd ThreatTrace

# Install dependencies
pip install -r requirements.txt

# Run ThreatTrace
python main.py
```

### Optional Dependencies

```bash
# For Windows EVTX parsing
pip install python-evtx

# For YARA rules
pip install yara-python

# For enhanced analytics
pip install pandas scipy
```

---

## Usage

### Interactive Mode

```bash
python main.py
```

Launches the interactive menu-driven interface with guided analysis.

### CLI Mode

```bash
# Analyze a single log file
python main.py --path /var/log/apache2/access.log

# Analyze with specific options
python main.py --path /logs/auth.log --output ./reports --format both --analyst "Jane Doe" --tlp AMBER

# Analyze directory recursively
python main.py --path /var/log/ --recursive

# Analyze Windows EVTX
python main.py --path /logs/windows_events.evtx

# Skip analytics (faster detection-only)
python main.py --path /logs/auth.log --no-analytics

# Specify log type explicitly
python main.py --path /var/log/nginx/access.log --type nginx

# Stats-only mode (analytics only)
python main.py --path /logs/apache.log --stats-only
```

### Command Options

| Option | Description | Default |
|--------|-------------|---------|
| `--path`, `-p` | File or directory path | None |
| `--recursive`, `-r` | Recurse into subdirectories | False |
| `--type`, `-t` | Force log type (auto-detect if not set) | auto |
| `--output`, `-o` | Output directory | ./threattrace_reports |
| `--format`, `-f` | Report format (html/json/both) | html |
| `--analyst` | Analyst name for report | Unknown Analyst |
| `--tlp` | TLP classification (WHITE/GREEN/AMBER/RED) | AMBER |
| `--no-analytics` | Skip analytics modules | False |
| `--chunk-size` | Events per batch for large files | 50000 |
| `--stats-only` | Run analytics only, skip detection | False |

---

## Detection Capabilities

### YARA Rules Categories

- **Web Attacks**: SQL injection, XSS, path traversal, web shells, scanners
- **Linux Threats**: Privilege escalation, persistence, reverse shells, rootkits
- **Windows Threats**: Mimikatz, Cobalt Strike, ransomware, PowerShell obfuscation
- **Network Threats**: C2 patterns, data exfiltration, DNS tunneling, port scans
- **Cloud Threats**: AWS IAM abuse, Azure misconfiguration, GCP enumeration
- **Authentication**: Brute force, credential stuffing, pass-the-hash

### Sigma Rules Categories

- **Windows**: LSASS dumping, DCSync, Kerberoasting, UAC bypass, RDP lateral movement
- **Linux**: Reverse shell, SUID abuse, shadow file access, SSH brute force
- **Network**: C2 beaconing, DNS tunneling, port scans, large outbound transfers
- **Cloud**: Root login, service account abuse, S3 exfiltration
- **Web**: Web shells, SQL injection, XSS, brute force

### Correlation Engine

- Brute force attack chains
- Port scanning detection
- Data exfiltration patterns
- Privilege escalation chains

---

## Analytics Modules

| Module | Purpose |
|--------|---------|
| **Baseline Profiler** | Establishes normal activity patterns and detects deviations |
| **Frequency Analyzer** | Statistical analysis of event frequencies |
| **Beaconing Detector** | Identifies regular callback patterns indicative of C2 |
| **Top-N Reporter** | Ranks attackers, targets, and events by activity |
| **Timeline Builder** | Chronological reconstruction of attack chains |

---

## Supported Log Types

### Web Server Logs
- Apache Access/Error Log
- Nginx Access/Error Log
- IIS W3C Log
- HAProxy Log

### Linux System Logs
- Syslog, Auth Log, Auditd
- Bash History, Kernel Log

### Windows Logs
- Windows Event Log (EVTX)
- Sysmon, PowerShell

### Network Logs
- Cisco ASA, Palo Alto, Fortinet
- PfSense, Zeek, Suricata
- DNS, Squid Proxy

### Cloud Logs
- AWS CloudTrail, VPC Flow Logs
- Azure Activity Log
- GCP Audit Log

### Authentication Logs
- Okta, Active Directory
- SSH, VPN

---

## Output Examples

### Terminal Summary
```
┌─────────────────────────────────────────────────────────┐
│  ThreatTrace Analysis Summary                           │
├─────────────────────────────────────────────────────────┤
│  Total Events Parsed     │  125,432                    │
│  Total Findings          │  17                         │
│    Critical              │  3                          │
│    High                  │  5                          │
│    Medium                │  9                          │
│  Overall Risk            │  HIGH                       │
│  Reports Generated       │  2                          │
└─────────────────────────────────────────────────────────┘
```

### Report Files
- `threattrace_report_20260331_185449.html` - Interactive HTML report
- `threattrace_report_20260331_185449.json` - Machine-readable JSON

---

## Configuration

Create a `config.yaml` file for custom settings:

```yaml
general:
  version: "2.0"
  tool_name: "ThreatTrace"
  tlp: "AMBER"
  max_events: 100000

output:
  directory: "./reports"
  formats:
    - html
    - json

detection:
  yara:
    rules_dir: "./detection/rules/yara"
  sigma:
    rules_dir: "./detection/rules/sigma"
  correlation:
    time_window: 300
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `THREATTRACE_CONFIG` | Custom config file path |
| `THREATTRACE_RULES` | Custom rules directory |
| `THREATTRACE_OUTPUT` | Default output directory |

---

## Troubleshooting

### Common Issues

1. **Import Errors**: Run `pip install -r requirements.txt`
2. **YARA Compilation Errors**: Validate YARA rules syntax
3. **Memory Issues**: Reduce `max_events` in config
4. **Encoding Issues**: Specify encoding in config

### Performance Tips

- Use `--type` to skip auto-detection
- Limit `max_events` for large files
- Use `--no-analytics` for faster detection-only mode

---

## License

MIT License - See LICENSE file for details.

---

## Security Note

ThreatTrace is a defensive security tool designed for authorized security testing and log analysis. Always ensure you have proper authorization before analyzing any logs or systems.

---

<div align="center">

**Built with** ![Python](https://img.shields.io/badge/Python-3.9+-blue) ![Rich](https://img.shields.io/badge/Rich-Terminal%20UI-brightgreen) ![YARA](https://img.shields.io/badge/YARA-Pattern%20Matching-yellow)

*Powered by open-source security research*

</div>