"""
extractor — Context-Aware IOC Extractor for ThreatTrace.

Scans log files or pre-loaded records in a single pass and extracts
16 types of Indicators of Compromise with risk scoring and co-occurrence
context.

Supported IOC types:
    ipv4, ipv6, domain, url, email, mac,
    md5, sha1, sha256, cve,
    win_path, unix_path,
    username, user_agent,
    aws_key, jwt

Quick usage::

    from extractor import ExtractorEngine, ExportManager

    engine = ExtractorEngine()
    engine.load_from_files(["/var/log/auth.log"])
    results = engine.extract()

    mgr = ExportManager(results)
    mgr.export_csv("/tmp/iocs.csv")
    mgr.export_json("/tmp/iocs.json")
"""

from extractor.engine import ExtractorEngine, ExtractionResult, PivotResult
from extractor.exporters import ExportManager

__all__ = [
    "ExtractorEngine",
    "ExtractionResult",
    "PivotResult",
    "ExportManager",
]
