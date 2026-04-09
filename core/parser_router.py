"""
core/parser_router.py — ThreatTrace parser routing layer.

Routes a detected log type to the correct parser class.  Returns a list of
normalised event dicts (one dict per log line / event record).

Supported log types match those defined in config.yaml and detected by
core/auto_detector.py.

Usage
-----
from core.parser_router import get_parser, parse_file

# Option A — use the convenience wrapper
events = parse_file(file_descriptor, log_type)

# Option B — get the parser object and call it yourself
parser = get_parser(log_type)
events = parser.parse(file_path)
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Type

from rich.console import Console

console = Console()

# ---------------------------------------------------------------------------
# Log-type → dotted module path + class name
#
# Format: "package.module.ClassName"
# The router will attempt to import from the threattrace.parsers namespace
# first, then fall back to the top-level parsers namespace, and finally fall
# back to the bundled GenericParser so that the pipeline never crashes.
# ---------------------------------------------------------------------------
_PARSER_MAP: Dict[str, str] = {
    # Web
    "apache":         "threattrace.parsers.web.apache.ApacheAccessParser",
    "nginx":          "threattrace.parsers.web.nginx.NginxAccessParser",
    "iis":            "threattrace.parsers.web.iis.IISParser",
    # Windows
    "windows_evtx":   "threattrace.parsers.windows.evtx.EVTXParser",
    "windows_evtx_xml":"threattrace.parsers.windows.evtx_xml.EVTXXMLParser",
    # Linux / syslog
    "syslog":         "threattrace.parsers.linux.syslog.SyslogParser",
    "auth_log":       "threattrace.parsers.linux.auth_log.AuthLogParser",
    "auditd":         "threattrace.parsers.linux.audit_log.AuditdParser",
    # Network
    "cisco_asa":      "threattrace.parsers.network.cisco_asa.CiscoASAParser",
    "fortinet":       "threattrace.parsers.network.fortinet.FortinetParser",
    "pfsense":        "threattrace.parsers.network.pfsense.PfSenseParser",
    "palo_alto":      "threattrace.parsers.network.palo_alto.PaloAltoParser",
    "squid":          "threattrace.parsers.network.squid.SquidParser",
    "suricata":       "threattrace.parsers.network.suricata.SuricataEVEParser",
    "zeek":           "threattrace.parsers.network.zeek.ZeekParser",
    # Cloud
    "cloudtrail":     "threattrace.parsers.cloud.aws_cloudtrail.CloudTrailParser",
    "azure_activity": "threattrace.parsers.cloud.azure.AzureActivityParser",
    "gcp_audit":      "threattrace.parsers.cloud.gcp.GCPAuditParser",
    # Auth / SSH / VPN (no dedicated parser → auth_log covers syslog-format auth)
    "ssh":            "threattrace.parsers.linux.auth_log.AuthLogParser",
    "okta":           "threattrace.parsers.generic.json_lines.JSONLinesParser",
    # Endpoint / containers
    "sysmon":         "threattrace.parsers.windows.evtx_xml.EVTXXMLParser",
    "docker":         "threattrace.parsers.generic.json_lines.JSONLinesParser",
    "k8s":            "threattrace.parsers.generic.json_lines.JSONLinesParser",
    # DNS
    "dns_bind":       "threattrace.parsers.linux.syslog.SyslogParser",
    # Databases / misc (fall through to plaintext)
    "mssql":          "threattrace.parsers.generic.plaintext.PlaintextParser",
    "mysql":          "threattrace.parsers.generic.plaintext.PlaintextParser",
    "postfix":        "threattrace.parsers.linux.syslog.SyslogParser",
    "vpn":            "threattrace.parsers.linux.syslog.SyslogParser",
    "email":          "threattrace.parsers.linux.syslog.SyslogParser",
    "unknown":        "threattrace.parsers.generic.plaintext.PlaintextParser",
}

_FALLBACK_PARSER_DOTTED = "threattrace.parsers.generic.plaintext.PlaintextParser"


# ---------------------------------------------------------------------------
# Parser protocol / base interface
# ---------------------------------------------------------------------------

class BaseParser:
    """
    Minimal interface that all parsers must implement.

    Subclasses override `parse()` and optionally `parse_line()`.
    """

    log_type: str = "generic"

    def parse(self, file_path: str) -> List[Dict[str, Any]]:  # noqa: D102
        raise NotImplementedError

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:  # noqa: D102
        return None


# ---------------------------------------------------------------------------
# Dynamic import helpers
# ---------------------------------------------------------------------------

def _import_class(dotted: str) -> Optional[Type[BaseParser]]:
    """
    Dynamically import a class from a dotted path string.

    e.g. "threattrace.parsers.web.apache.ApacheParser"
         → import threattrace.parsers.web.apache, return .ApacheParser

    Returns None if the import fails for any reason.
    """
    module_path, _, class_name = dotted.rpartition(".")
    if not module_path:
        return None
    try:
        mod = importlib.import_module(module_path)
        return getattr(mod, class_name)
    except (ImportError, AttributeError):
        return None


def _load_parser_class(log_type: str) -> Type[BaseParser]:
    """
    Return the parser class for *log_type*.

    Resolution order:
      1. Exact entry in _PARSER_MAP
      2. Fallback GenericParser
    """
    dotted = _PARSER_MAP.get(log_type, _FALLBACK_PARSER_DOTTED)
    cls = _import_class(dotted)

    if cls is None and dotted != _FALLBACK_PARSER_DOTTED:
        console.print(
            f"  [yellow]Warning:[/yellow] Parser for '{log_type}' not found "
            f"at '{dotted}'. Falling back to GenericParser."
        )
        cls = _import_class(_FALLBACK_PARSER_DOTTED)

    if cls is None:
        # Last resort: return an inline no-op parser that at least yields raw
        # events so the pipeline can continue.
        cls = _make_inline_generic_parser()

    return cls


def _make_inline_generic_parser() -> Type[BaseParser]:
    """
    Build a minimal GenericParser at runtime if the module is unavailable.
    Reads every line and returns {"raw": line, "log_type": "generic"}.
    """
    class _InlineGenericParser(BaseParser):
        log_type = "generic"

        def parse(self, file_path: str) -> List[Dict[str, Any]]:
            events: List[Dict[str, Any]] = []
            try:
                with open(file_path, "r", errors="replace") as fh:
                    for lineno, line in enumerate(fh, start=1):
                        stripped = line.strip()
                        if stripped:
                            events.append({
                                "log_type": "generic",
                                "line_number": lineno,
                                "raw": stripped,
                                "timestamp": None,
                            })
            except OSError as exc:
                console.print(f"  [red]Error reading '{file_path}': {exc}[/red]")
            return events

    return _InlineGenericParser


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_parser(log_type: str) -> BaseParser:
    """
    Return an instantiated parser for *log_type*.

    Parameters
    ----------
    log_type:
        A string such as "apache", "windows_evtx", "cloudtrail", etc.

    Returns
    -------
    An instance of the appropriate parser class (always non-None).
    """
    cls = _load_parser_class(log_type)
    return cls()


def parse_file(
    file_descriptor: Dict[str, Any],
    log_type: str,
) -> List[Dict[str, Any]]:
    """
    Parse a single file and return normalised events.

    Parameters
    ----------
    file_descriptor:
        A dict produced by core.file_handler.load_files(), e.g.
        {"path": "/tmp/access.log", "size_bytes": 1024, "extension": ".log"}
    log_type:
        The detected / user-supplied log type string.

    Returns
    -------
    list of normalised event dicts.  Each dict always has at minimum:
        - "raw"      (original log line / source text)
        - "log_type" (the log_type string passed in)
    """
    file_path = file_descriptor.get("path", "")

    if not file_path or not Path(file_path).exists():
        console.print(
            f"  [red]parse_file: path '{file_path}' does not exist — skipping.[/red]"
        )
        return []

    parser = get_parser(log_type)

    console.print(
        f"  [dim]Parsing[/dim] [cyan]{Path(file_path).name}[/cyan] "
        f"as [bold]{log_type}[/bold] "
        f"using [dim]{type(parser).__name__}[/dim]"
    )

    try:
        events = parser.parse(file_path)
    except Exception as exc:  # noqa: BLE001
        console.print(
            f"  [red]Parser error for '{file_path}': {exc}[/red]"
        )
        return []

    # Normalise: threattrace parsers return LogEvent dataclasses; flatten to dicts
    normalised: List[Dict[str, Any]] = []
    for event in events:
        if isinstance(event, dict):
            event.setdefault("log_type", log_type)
            normalised.append(event)
        else:
            # LogEvent dataclass → dict
            d: Dict[str, Any] = {}
            # Spread parsed fields first so explicit top-level keys win
            if hasattr(event, "fields") and isinstance(event.fields, dict):
                d.update(event.fields)
            if hasattr(event, "raw"):
                d["raw"] = event.raw
            if hasattr(event, "timestamp") and event.timestamp is not None:
                d["timestamp"] = event.timestamp.isoformat() if hasattr(event.timestamp, "isoformat") else str(event.timestamp)
            if hasattr(event, "source_type"):
                st = event.source_type
                d["source_type"] = st.value if hasattr(st, "value") else str(st)
            if hasattr(event, "line_number"):
                d["line_number"] = event.line_number
            if hasattr(event, "source_file"):
                d["source_file"] = event.source_file
            d.setdefault("log_type", log_type)
            normalised.append(d)

    return normalised


def parse_files(
    file_descriptors: List[Dict[str, Any]],
    log_type: str,
) -> List[Dict[str, Any]]:
    """
    Parse multiple files of the same log type.

    Parameters
    ----------
    file_descriptors:
        Output of core.file_handler.load_files().
    log_type:
        Shared log type for all files.

    Returns
    -------
    Concatenated list of normalised event dicts from all files.
    """
    all_events: List[Dict[str, Any]] = []
    for descriptor in file_descriptors:
        events = parse_file(descriptor, log_type)
        all_events.extend(events)
    return all_events


def list_supported_types() -> List[str]:
    """Return a sorted list of all supported log type strings."""
    return sorted(_PARSER_MAP.keys())


def stream_file_chunked(
    file_descriptor: Dict[str, Any],
    log_type: str,
    chunk_size: int = 50_000,
) -> Generator[List[Dict[str, Any]], None, None]:
    """
    Yield normalised event dicts from a single file in chunks of `chunk_size`.

    Uses true line-by-line streaming for text-based formats (any parser that
    implements ``parse_line()``) so the entire file is never held in RAM.

    For binary/complex formats (EVTX, JSON-array, etc.) that lack
    ``parse_line()``, the parser is called normally and the result is sliced
    into chunks — memory usage is still bounded to the size of one parser run,
    which is unavoidable for those formats.

    Parameters
    ----------
    file_descriptor:
        Dict produced by ``core.file_handler.load_files()``.
    log_type:
        Detected / user-supplied log type string.
    chunk_size:
        Maximum number of events per yielded batch.
    """
    file_path = file_descriptor.get("path", "")
    if not file_path or not Path(file_path).exists():
        console.print(
            f"  [red]stream_file_chunked: '{file_path}' does not exist — skipping.[/red]"
        )
        return

    parser = get_parser(log_type)

    # ------------------------------------------------------------------
    # True streaming path: read line-by-line via parse_line()
    # Supported by all text-based parsers (Apache, Syslog, Auth, etc.)
    # ------------------------------------------------------------------
    if hasattr(parser, "parse_line") and callable(parser.parse_line):
        chunk: List[Dict[str, Any]] = []
        try:
            with open(file_path, "r", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    event = parser.parse_line(stripped)
                    if event is None:
                        # Parser could not parse the line; keep raw content
                        event = {
                            "raw":         stripped,
                            "log_type":    log_type,
                            "line_number": lineno,
                            "timestamp":   None,
                        }
                    event.setdefault("log_type",    log_type)
                    event.setdefault("line_number", lineno)
                    chunk.append(event)
                    if len(chunk) >= chunk_size:
                        yield chunk
                        chunk = []
            if chunk:
                yield chunk
        except OSError as exc:
            console.print(f"  [red]Streaming error for '{file_path}': {exc}[/red]")
        return

    # ------------------------------------------------------------------
    # Fallback: parse all at once, slice into chunks
    # Used for EVTX, CloudTrail JSON, etc.
    # ------------------------------------------------------------------
    console.print(
        f"  [dim yellow]Note:[/dim yellow] {type(parser).__name__} does not support "
        f"line-by-line streaming; loading file into memory for chunked processing."
    )
    events = parse_file(file_descriptor, log_type)
    for i in range(0, max(len(events), 1), chunk_size):
        yield events[i : i + chunk_size]
