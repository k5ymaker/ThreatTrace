"""
ThreatTrace Log Parsers
Export all parser functions for use by the detection engine.
"""

from .apache_parser import parse as parse_apache
from .nginx_parser import parse as parse_nginx
from .iis_parser import parse as parse_iis
from .windows_evtx_parser import parse as parse_windows_evtx
from .sysmon_parser import parse as parse_sysmon
from .linux_syslog_parser import parse as parse_linux_syslog
from .linux_auth_parser import parse as parse_linux_auth
from .linux_audit_parser import parse as parse_linux_audit
from .firewall_parser import parse as parse_firewall
from .dns_parser import parse as parse_dns
from .squid_proxy_parser import parse as parse_squid_proxy
from .aws_cloudtrail_parser import parse as parse_aws_cloudtrail
from .azure_activity_parser import parse as parse_azure_activity
from .gcp_audit_parser import parse as parse_gcp_audit
from .okta_parser import parse as parse_okta
from .ad_parser import parse as parse_ad
from .mssql_parser import parse as parse_mssql
from .mysql_parser import parse as parse_mysql
from .ssh_parser import parse as parse_ssh
from .vpn_parser import parse as parse_vpn
from .email_parser import parse as parse_email
from .docker_parser import parse as parse_docker
from .k8s_parser import parse as parse_k8s

__all__ = [
    "parse_apache",
    "parse_nginx",
    "parse_iis",
    "parse_windows_evtx",
    "parse_sysmon",
    "parse_linux_syslog",
    "parse_linux_auth",
    "parse_linux_audit",
    "parse_firewall",
    "parse_dns",
    "parse_squid_proxy",
    "parse_aws_cloudtrail",
    "parse_azure_activity",
    "parse_gcp_audit",
    "parse_okta",
    "parse_ad",
    "parse_mssql",
    "parse_mysql",
    "parse_ssh",
    "parse_vpn",
    "parse_email",
    "parse_docker",
    "parse_k8s",
]

# Registry mapping log source names to parser functions
PARSER_REGISTRY = {
    "apache": parse_apache,
    "nginx": parse_nginx,
    "iis": parse_iis,
    "windows_evtx": parse_windows_evtx,
    "sysmon": parse_sysmon,
    "linux_syslog": parse_linux_syslog,
    "linux_auth": parse_linux_auth,
    "linux_audit": parse_linux_audit,
    "firewall": parse_firewall,
    "dns": parse_dns,
    "squid_proxy": parse_squid_proxy,
    "aws_cloudtrail": parse_aws_cloudtrail,
    "azure_activity": parse_azure_activity,
    "gcp_audit": parse_gcp_audit,
    "okta": parse_okta,
    "ad": parse_ad,
    "mssql": parse_mssql,
    "mysql": parse_mysql,
    "ssh": parse_ssh,
    "vpn": parse_vpn,
    "email": parse_email,
    "docker": parse_docker,
    "k8s": parse_k8s,
}


def get_parser(log_source: str):
    """Return the parser function for a given log source name."""
    return PARSER_REGISTRY.get(log_source)
