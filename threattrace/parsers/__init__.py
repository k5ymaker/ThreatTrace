"""Parser registry and factory."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..models.log_event import LogSourceType
from .base import BaseParser

# Lazy import map: source type → (module_path, class_name)
_REGISTRY: dict[LogSourceType, tuple[str, str]] = {
    LogSourceType.APACHE_ACCESS: ("threattrace.parsers.web.apache", "ApacheAccessParser"),
    LogSourceType.APACHE_ERROR: ("threattrace.parsers.web.apache", "ApacheErrorParser"),
    LogSourceType.NGINX_ACCESS: ("threattrace.parsers.web.nginx", "NginxAccessParser"),
    LogSourceType.NGINX_ERROR: ("threattrace.parsers.web.nginx", "NginxErrorParser"),
    LogSourceType.IIS_W3C: ("threattrace.parsers.web.iis", "IISParser"),
    LogSourceType.HAPROXY: ("threattrace.parsers.web.haproxy", "HAProxyParser"),
    LogSourceType.LINUX_SYSLOG: ("threattrace.parsers.linux.syslog", "SyslogParser"),
    LogSourceType.LINUX_AUTH_LOG: ("threattrace.parsers.linux.auth_log", "AuthLogParser"),
    LogSourceType.LINUX_KERN_LOG: ("threattrace.parsers.linux.syslog", "SyslogParser"),
    LogSourceType.LINUX_AUDIT: ("threattrace.parsers.linux.audit_log", "AuditdParser"),
    LogSourceType.LINUX_CRON: ("threattrace.parsers.linux.syslog", "SyslogParser"),
    LogSourceType.LINUX_BASH_HISTORY: ("threattrace.parsers.linux.bash_history", "BashHistoryParser"),
    LogSourceType.WINDOWS_EVTX: ("threattrace.parsers.windows.evtx", "EVTXParser"),
    LogSourceType.WINDOWS_EVTX_XML: ("threattrace.parsers.windows.evtx_xml", "EVTXXMLParser"),
    LogSourceType.WINDOWS_SYSMON: ("threattrace.parsers.windows.evtx", "EVTXParser"),
    LogSourceType.WINDOWS_POWERSHELL: ("threattrace.parsers.windows.evtx_xml", "EVTXXMLParser"),
    LogSourceType.FIREWALL_CISCO_ASA: ("threattrace.parsers.network.cisco_asa", "CiscoASAParser"),
    LogSourceType.FIREWALL_PALO_ALTO: ("threattrace.parsers.network.palo_alto", "PaloAltoParser"),
    LogSourceType.FIREWALL_FORTINET: ("threattrace.parsers.network.fortinet", "FortinetParser"),
    LogSourceType.FIREWALL_PFSENSE: ("threattrace.parsers.network.pfsense", "PfSenseParser"),
    LogSourceType.ZEEK_CONN: ("threattrace.parsers.network.zeek", "ZeekParser"),
    LogSourceType.ZEEK_DNS: ("threattrace.parsers.network.zeek", "ZeekParser"),
    LogSourceType.ZEEK_HTTP: ("threattrace.parsers.network.zeek", "ZeekParser"),
    LogSourceType.SURICATA_EVE: ("threattrace.parsers.network.suricata", "SuricataEVEParser"),
    LogSourceType.NETFLOW: ("threattrace.parsers.network.netflow", "NetFlowParser"),
    LogSourceType.DNS_BIND: ("threattrace.parsers.linux.syslog", "SyslogParser"),
    LogSourceType.DNS_WINDOWS: ("threattrace.parsers.generic.json_lines", "JSONLinesParser"),
    LogSourceType.SQUID_PROXY: ("threattrace.parsers.network.squid", "SquidParser"),
    LogSourceType.AWS_CLOUDTRAIL: ("threattrace.parsers.cloud.aws_cloudtrail", "CloudTrailParser"),
    LogSourceType.AWS_VPC_FLOW: ("threattrace.parsers.cloud.aws_vpc_flow", "VPCFlowParser"),
    LogSourceType.AZURE_ACTIVITY: ("threattrace.parsers.cloud.azure", "AzureActivityParser"),
    LogSourceType.AZURE_SIGNIN: ("threattrace.parsers.cloud.azure", "AzureActivityParser"),
    LogSourceType.GCP_AUDIT: ("threattrace.parsers.cloud.gcp", "GCPAuditParser"),
    LogSourceType.POSTFIX: ("threattrace.parsers.linux.syslog", "SyslogParser"),
    LogSourceType.CROWDSTRIKE: ("threattrace.parsers.generic.json_lines", "JSONLinesParser"),
    LogSourceType.CARBON_BLACK: ("threattrace.parsers.generic.json_lines", "JSONLinesParser"),
    LogSourceType.OSQUERY: ("threattrace.parsers.generic.json_lines", "JSONLinesParser"),
    LogSourceType.MYSQL: ("threattrace.parsers.generic.plaintext", "PlaintextParser"),
    LogSourceType.POSTGRESQL: ("threattrace.parsers.generic.plaintext", "PlaintextParser"),
    LogSourceType.MSSQL: ("threattrace.parsers.generic.plaintext", "PlaintextParser"),
    LogSourceType.DOCKER: ("threattrace.parsers.generic.json_lines", "JSONLinesParser"),
    LogSourceType.KUBERNETES: ("threattrace.parsers.generic.json_lines", "JSONLinesParser"),
    LogSourceType.OKTA: ("threattrace.parsers.generic.json_lines", "JSONLinesParser"),
    LogSourceType.GOOGLE_WORKSPACE: ("threattrace.parsers.generic.json_lines", "JSONLinesParser"),
    LogSourceType.OPENVPN: ("threattrace.parsers.linux.syslog", "SyslogParser"),
    LogSourceType.CISCO_ANYCONNECT: ("threattrace.parsers.linux.syslog", "SyslogParser"),
    LogSourceType.GLOBALPROTECT: ("threattrace.parsers.generic.plaintext", "PlaintextParser"),
    LogSourceType.ACTIVE_DIRECTORY: ("threattrace.parsers.generic.plaintext", "PlaintextParser"),
    LogSourceType.RADIUS: ("threattrace.parsers.linux.syslog", "SyslogParser"),
    LogSourceType.LDAP: ("threattrace.parsers.generic.plaintext", "PlaintextParser"),
    LogSourceType.EXCHANGE: ("threattrace.parsers.generic.plaintext", "PlaintextParser"),
    LogSourceType.JSON_LINES: ("threattrace.parsers.generic.json_lines", "JSONLinesParser"),
    LogSourceType.CSV_LOG: ("threattrace.parsers.generic.csv_log", "CSVLogParser"),
    LogSourceType.PLAINTEXT: ("threattrace.parsers.generic.plaintext", "PlaintextParser"),
    LogSourceType.UNKNOWN: ("threattrace.parsers.generic.plaintext", "PlaintextParser"),
}


def get_parser(source_type: LogSourceType, source_file: str = "") -> BaseParser:
    """Instantiate and return the appropriate parser for *source_type*."""
    import importlib

    entry = _REGISTRY.get(source_type)
    if entry is None:
        # Fallback to plaintext
        from .generic.plaintext import PlaintextParser
        p = PlaintextParser(source_file=source_file)
        p.source_type = source_type
        return p

    mod_path, cls_name = entry
    try:
        mod = importlib.import_module(mod_path)
        cls = getattr(mod, cls_name)
        return cls(source_file=source_file)
    except Exception:
        from .generic.plaintext import PlaintextParser
        p = PlaintextParser(source_file=source_file)
        p.source_type = source_type
        return p
