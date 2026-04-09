"""LogEvent data model – a normalised log record."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


class LogSourceType(str, enum.Enum):
    # Windows
    WINDOWS_EVTX = "windows_evtx"
    WINDOWS_EVTX_XML = "windows_evtx_xml"
    WINDOWS_SYSMON = "windows_sysmon"
    WINDOWS_POWERSHELL = "windows_powershell"
    # Linux
    LINUX_SYSLOG = "linux_syslog"
    LINUX_AUTH_LOG = "linux_auth_log"
    LINUX_KERN_LOG = "linux_kern_log"
    LINUX_AUDIT = "linux_audit"
    LINUX_CRON = "linux_cron"
    LINUX_BASH_HISTORY = "linux_bash_history"
    # Web
    APACHE_ACCESS = "apache_access"
    APACHE_ERROR = "apache_error"
    NGINX_ACCESS = "nginx_access"
    NGINX_ERROR = "nginx_error"
    IIS_W3C = "iis_w3c"
    HAPROXY = "haproxy"
    # Network
    FIREWALL_PFSENSE = "firewall_pfsense"
    FIREWALL_CISCO_ASA = "firewall_cisco_asa"
    FIREWALL_PALO_ALTO = "firewall_palo_alto"
    FIREWALL_FORTINET = "firewall_fortinet"
    ZEEK_CONN = "zeek_conn"
    ZEEK_DNS = "zeek_dns"
    ZEEK_HTTP = "zeek_http"
    SURICATA_EVE = "suricata_eve"
    NETFLOW = "netflow"
    # DNS
    DNS_BIND = "dns_bind"
    DNS_WINDOWS = "dns_windows"
    # Proxy
    SQUID_PROXY = "squid_proxy"
    # Auth & IAM
    ACTIVE_DIRECTORY = "active_directory"
    RADIUS = "radius"
    LDAP = "ldap"
    # Cloud
    AWS_CLOUDTRAIL = "aws_cloudtrail"
    AWS_VPC_FLOW = "aws_vpc_flow"
    AZURE_ACTIVITY = "azure_activity"
    AZURE_SIGNIN = "azure_signin"
    GCP_AUDIT = "gcp_audit"
    # Email
    POSTFIX = "postfix"
    EXCHANGE = "exchange"
    # Endpoint/EDR
    CROWDSTRIKE = "crowdstrike"
    CARBON_BLACK = "carbon_black"
    OSQUERY = "osquery"
    # Databases
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    # Containers
    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    # SaaS
    OKTA = "okta"
    GOOGLE_WORKSPACE = "google_workspace"
    # VPN
    OPENVPN = "openvpn"
    CISCO_ANYCONNECT = "cisco_anyconnect"
    GLOBALPROTECT = "globalprotect"
    # Generic
    JSON_LINES = "json_lines"
    CSV_LOG = "csv_log"
    PLAINTEXT = "plaintext"
    UNKNOWN = "unknown"


# Human-readable labels for the TUI menu
LOG_SOURCE_LABELS: dict[LogSourceType, str] = {
    LogSourceType.WINDOWS_EVTX: "Windows Security Event Log (EVTX)",
    LogSourceType.WINDOWS_EVTX_XML: "Windows Event Log (XML export)",
    LogSourceType.WINDOWS_SYSMON: "Windows Sysmon",
    LogSourceType.WINDOWS_POWERSHELL: "Windows PowerShell log",
    LogSourceType.LINUX_SYSLOG: "Linux Syslog (/var/log/syslog)",
    LogSourceType.LINUX_AUTH_LOG: "Linux Auth log (/var/log/auth.log)",
    LogSourceType.LINUX_KERN_LOG: "Linux kern.log",
    LogSourceType.LINUX_AUDIT: "Linux Audit log (auditd)",
    LogSourceType.LINUX_CRON: "Linux Cron log",
    LogSourceType.LINUX_BASH_HISTORY: "Linux Bash history",
    LogSourceType.APACHE_ACCESS: "Apache Access log",
    LogSourceType.APACHE_ERROR: "Apache Error log",
    LogSourceType.NGINX_ACCESS: "Nginx Access log",
    LogSourceType.NGINX_ERROR: "Nginx Error log",
    LogSourceType.IIS_W3C: "IIS W3C log",
    LogSourceType.HAPROXY: "HAProxy log",
    LogSourceType.FIREWALL_PFSENSE: "pfSense Firewall log",
    LogSourceType.FIREWALL_CISCO_ASA: "Cisco ASA log",
    LogSourceType.FIREWALL_PALO_ALTO: "Palo Alto firewall log",
    LogSourceType.FIREWALL_FORTINET: "Fortinet/FortiGate log",
    LogSourceType.ZEEK_CONN: "Zeek conn.log",
    LogSourceType.ZEEK_DNS: "Zeek dns.log",
    LogSourceType.ZEEK_HTTP: "Zeek http.log",
    LogSourceType.SURICATA_EVE: "Suricata EVE JSON",
    LogSourceType.NETFLOW: "NetFlow / IPFIX",
    LogSourceType.DNS_BIND: "DNS (BIND)",
    LogSourceType.DNS_WINDOWS: "DNS (Windows)",
    LogSourceType.SQUID_PROXY: "Squid Proxy log",
    LogSourceType.ACTIVE_DIRECTORY: "Active Directory / LDAP",
    LogSourceType.RADIUS: "RADIUS log",
    LogSourceType.AWS_CLOUDTRAIL: "AWS CloudTrail",
    LogSourceType.AWS_VPC_FLOW: "AWS VPC Flow Logs",
    LogSourceType.AZURE_ACTIVITY: "Azure Activity Log",
    LogSourceType.AZURE_SIGNIN: "Azure AD Sign-in Log",
    LogSourceType.GCP_AUDIT: "GCP Audit Log",
    LogSourceType.POSTFIX: "Postfix / SMTP log",
    LogSourceType.EXCHANGE: "Exchange / O365 Audit",
    LogSourceType.CROWDSTRIKE: "CrowdStrike Falcon",
    LogSourceType.CARBON_BLACK: "VMware Carbon Black",
    LogSourceType.OSQUERY: "osquery",
    LogSourceType.MYSQL: "MySQL audit log",
    LogSourceType.POSTGRESQL: "PostgreSQL log",
    LogSourceType.MSSQL: "MSSQL audit log",
    LogSourceType.DOCKER: "Docker daemon log",
    LogSourceType.KUBERNETES: "Kubernetes API audit",
    LogSourceType.OKTA: "Okta system log",
    LogSourceType.GOOGLE_WORKSPACE: "Google Workspace audit",
    LogSourceType.OPENVPN: "OpenVPN log",
    LogSourceType.CISCO_ANYCONNECT: "Cisco AnyConnect log",
    LogSourceType.GLOBALPROTECT: "Palo Alto GlobalProtect log",
    LogSourceType.JSON_LINES: "Generic JSON Lines",
    LogSourceType.CSV_LOG: "Generic CSV log",
    LogSourceType.PLAINTEXT: "Generic plain text log",
}


@dataclass
class LogEvent:
    """Normalised representation of a single log record."""
    source_type: LogSourceType
    raw: str
    fields: dict[str, Any]
    timestamp: Optional[datetime] = None
    source_file: str = ""
    line_number: int = 0
    parse_confidence: float = 1.0
