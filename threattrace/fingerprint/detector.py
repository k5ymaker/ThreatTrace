"""AutoDetector – fingerprints a log file and returns ranked LogSourceType candidates."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from ..models.log_event import LogSourceType

# (pattern, source_type, weight)
# Weight is a float [0,1] contribution per pattern match
_TEXT_PATTERNS: list[tuple[re.Pattern, LogSourceType, float]] = [
    # Apache Combined Log Format: ip - - [date] "METHOD /path HTTP/x.x" code bytes
    (re.compile(r'\d+\.\d+\.\d+\.\d+ - .+ \[.+\] "[A-Z]+ .+ HTTP/'), LogSourceType.APACHE_ACCESS, 0.9),
    # Apache error log
    (re.compile(r'\[(?:error|warn|notice|info|debug)\] \[.*?\] \[pid \d+\]'), LogSourceType.APACHE_ERROR, 0.9),
    # Nginx access log
    (re.compile(r'\d+\.\d+\.\d+\.\d+ - .+ \[.+\] "[A-Z]+ .+ HTTP/.*" \d{3} \d+'), LogSourceType.NGINX_ACCESS, 0.8),
    # Nginx error log
    (re.compile(r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[(?:error|warn|notice|info|crit)\] \d+#\d+:'), LogSourceType.NGINX_ERROR, 0.9),
    # IIS W3C log
    (re.compile(r'^#Software: Microsoft Internet Information Services'), LogSourceType.IIS_W3C, 1.0),
    (re.compile(r'^#Fields: date time '), LogSourceType.IIS_W3C, 0.8),
    # HAProxy
    (re.compile(r'haproxy\[\d+\]: \d+\.\d+\.\d+\.\d+:\d+ \['), LogSourceType.HAPROXY, 0.9),
    # Linux syslog / messages
    (re.compile(r'^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+:'), LogSourceType.LINUX_SYSLOG, 0.7),
    # Auth.log SSH
    (re.compile(r'sshd\[\d+\]: (?:Accepted|Failed|Invalid) '), LogSourceType.LINUX_AUTH_LOG, 0.95),
    (re.compile(r'sudo:\s+\w+ : TTY='), LogSourceType.LINUX_AUTH_LOG, 0.9),
    # Auditd
    (re.compile(r'^type=\w+ msg=audit\('), LogSourceType.LINUX_AUDIT, 0.95),
    # Cron
    (re.compile(r'CRON\[\d+\]:|crond\[\d+\]:'), LogSourceType.LINUX_CRON, 0.9),
    # Cisco ASA
    (re.compile(r'%ASA-\d+-\d+:'), LogSourceType.FIREWALL_CISCO_ASA, 0.98),
    # Palo Alto
    (re.compile(r'(?:TRAFFIC|THREAT|SYSTEM),\d+,\d{4}/\d{2}/\d{2}'), LogSourceType.FIREWALL_PALO_ALTO, 0.9),
    # Fortinet
    (re.compile(r'logid="\d+" type="traffic"'), LogSourceType.FIREWALL_FORTINET, 0.9),
    (re.compile(r'action=(?:accept|deny|drop) srcip='), LogSourceType.FIREWALL_FORTINET, 0.8),
    # pfSense
    (re.compile(r'filterlog:'), LogSourceType.FIREWALL_PFSENSE, 0.9),
    # Suricata EVE (JSON with event_type)
    (re.compile(r'"event_type"\s*:\s*"(?:alert|dns|http|tls|flow)"'), LogSourceType.SURICATA_EVE, 0.95),
    # Zeek conn.log TSV header
    (re.compile(r'#separator \x09'), LogSourceType.ZEEK_CONN, 0.9),
    (re.compile(r'#fields\s+ts\s+uid\s+id\.orig_h'), LogSourceType.ZEEK_CONN, 0.95),
    (re.compile(r'#fields\s+ts\s+uid\s+id\.orig_h.*query'), LogSourceType.ZEEK_DNS, 0.97),
    # Postfix
    (re.compile(r'postfix/\w+\[\d+\]: '), LogSourceType.POSTFIX, 0.9),
    # Squid proxy
    (re.compile(r'^\d{10}\.\d{3}\s+\d+\s+\d+\.\d+\.\d+\.\d+ TCP_'), LogSourceType.SQUID_PROXY, 0.9),
    # OpenVPN
    (re.compile(r'OpenVPN \d+\.\d+\.\d+ .* built on'), LogSourceType.OPENVPN, 0.95),
    # Okta
    (re.compile(r'"eventType"\s*:\s*"user\.\w+\.'), LogSourceType.OKTA, 0.85),
    # Docker
    (re.compile(r'"container_name":|container_id'), LogSourceType.DOCKER, 0.7),
    # PostgreSQL
    (re.compile(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \w+ LOG:\s+'), LogSourceType.POSTGRESQL, 0.8),
    # MySQL
    (re.compile(r'^\d{6}\s+\d{2}:\d{2}:\d{2}\s+\[\w+\] /usr/sbin/mysqld'), LogSourceType.MYSQL, 0.8),
    (re.compile(r'Timestamp.*Command.*Argument', re.IGNORECASE), LogSourceType.MYSQL, 0.6),
]

_JSON_PATTERNS: list[tuple[str, LogSourceType, float]] = [
    # AWS CloudTrail
    ("eventSource", LogSourceType.AWS_CLOUDTRAIL, 0.5),
    ("userIdentity", LogSourceType.AWS_CLOUDTRAIL, 0.6),
    ("awsRegion", LogSourceType.AWS_CLOUDTRAIL, 0.8),
    # AWS VPC Flow
    ("srcAddr", LogSourceType.AWS_VPC_FLOW, 0.5),
    ("dstAddr", LogSourceType.AWS_VPC_FLOW, 0.5),
    ("vpcId", LogSourceType.AWS_VPC_FLOW, 0.9),
    # Azure
    ("operationName", LogSourceType.AZURE_ACTIVITY, 0.4),
    ("resourceGroupName", LogSourceType.AZURE_ACTIVITY, 0.7),
    # GCP
    ("protoPayload", LogSourceType.GCP_AUDIT, 0.6),
    ("logName", LogSourceType.GCP_AUDIT, 0.5),
    # Suricata
    ("event_type", LogSourceType.SURICATA_EVE, 0.5),
    ("alert", LogSourceType.SURICATA_EVE, 0.4),
    # Okta
    ("eventType", LogSourceType.OKTA, 0.5),
    ("actor", LogSourceType.OKTA, 0.3),
    # CrowdStrike
    ("event_simpleName", LogSourceType.CROWDSTRIKE, 0.8),
    # Carbon Black
    ("cb_server", LogSourceType.CARBON_BLACK, 0.9),
    # osquery
    ("calendarTime", LogSourceType.OSQUERY, 0.5),
    ("decorations", LogSourceType.OSQUERY, 0.7),
    # Kubernetes
    ("apiVersion", LogSourceType.KUBERNETES, 0.5),
    ("requestURI", LogSourceType.KUBERNETES, 0.7),
    ("responseStatus", LogSourceType.KUBERNETES, 0.6),
]

# Magic bytes for binary formats
_MAGIC_BYTES: list[tuple[bytes, int, LogSourceType]] = [
    (b"\x45\x4c\x46\x46", 0, LogSourceType.WINDOWS_EVTX),  # EVTX magic
]


class AutoDetector:
    """Fingerprint a log file and return ranked (LogSourceType, confidence) pairs."""

    SAMPLE_BYTES = 16384  # 16 KB sample

    def detect(self, path: Path) -> list[tuple[LogSourceType, float]]:
        """Return sorted list of (LogSourceType, confidence) pairs, highest first."""
        try:
            raw_bytes = path.read_bytes()[:self.SAMPLE_BYTES]
        except (OSError, PermissionError):
            return [(LogSourceType.UNKNOWN, 0.0)]

        # Binary magic check
        for magic, offset, ltype in _MAGIC_BYTES:
            if raw_bytes[offset:offset + len(magic)] == magic:
                return [(ltype, 1.0)]

        try:
            sample = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            return [(LogSourceType.UNKNOWN, 0.0)]

        lines = sample.splitlines()[:200]

        scores: dict[LogSourceType, float] = {}

        # Text pattern matching
        for pattern, ltype, weight in _TEXT_PATTERNS:
            hits = sum(1 for line in lines if pattern.search(line))
            if hits:
                contribution = weight * min(1.0, hits / max(len(lines), 1) * 10)
                scores[ltype] = scores.get(ltype, 0.0) + contribution

        # JSON field detection
        json_text = sample
        try:
            # Try to parse as JSON array or JSONL
            first_line = lines[0].strip() if lines else ""
            if first_line.startswith("{"):
                obj = json.loads(first_line)
                for key, ltype, weight in _JSON_PATTERNS:
                    if key in obj:
                        scores[ltype] = scores.get(ltype, 0.0) + weight
            elif first_line.startswith("["):
                arr = json.loads(first_line)
                if arr and isinstance(arr[0], dict):
                    for key, ltype, weight in _JSON_PATTERNS:
                        if key in arr[0]:
                            scores[ltype] = scores.get(ltype, 0.0) + weight
        except (json.JSONDecodeError, IndexError):
            pass

        # JSON substring match
        for key, ltype, weight in _JSON_PATTERNS:
            if f'"{key}"' in json_text:
                scores[ltype] = scores.get(ltype, 0.0) + weight * 0.3

        # Normalise scores to [0, 1]
        if scores:
            max_score = max(scores.values())
            if max_score > 0:
                scores = {k: min(1.0, v / max(max_score, 1.0)) for k, v in scores.items()}

        if not scores:
            # Fallback heuristics
            if lines and lines[0].strip().startswith("{"):
                return [(LogSourceType.JSON_LINES, 0.5)]
            return [(LogSourceType.PLAINTEXT, 0.3)]

        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        return ranked[:5]

    def best_guess(self, path: Path) -> tuple[LogSourceType, float]:
        results = self.detect(path)
        return results[0] if results else (LogSourceType.UNKNOWN, 0.0)
