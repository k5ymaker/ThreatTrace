"""
analytics/metrics.py — ThreatTrace statistical and classification utilities.

Functions
---------
calculate_entropy(text)         Shannon entropy for DGA detection
calculate_stddev(values)        Population std-dev for beaconing detection
get_ip_type(ip)                 Classify an IP address string
is_high_risk_country(country)   Check ISO-3166-1 alpha-2 against a blocklist
is_scanner_ua(ua_string)        Detect known scanner / attack-tool User-Agents
parse_timestamp(ts)             Multi-format timestamp parser → datetime | None
format_bytes(n)                 Human-readable byte counts
"""

from __future__ import annotations

import ipaddress
import math
import re
from datetime import datetime, timezone
from typing import List, Optional

# Optional — used for richer UA parsing when the package is installed
try:
    from user_agents import parse as _ua_parse  # type: ignore
    _UA_LIB_AVAILABLE = True
except ImportError:
    _UA_LIB_AVAILABLE = False

try:
    from dateutil import parser as _dateutil_parser  # type: ignore
    _DATEUTIL_AVAILABLE = True
except ImportError:
    _DATEUTIL_AVAILABLE = False


# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------

def calculate_entropy(text: str) -> float:
    """
    Calculate the Shannon entropy (bits) of *text*.

    Useful for detecting algorithmically-generated domain names (DGA),
    encoded payloads, or randomised strings.

    Parameters
    ----------
    text:
        Input string; empty strings return 0.0.

    Returns
    -------
    float in the range [0.0, log2(len(charset))]
    """
    if not text:
        return 0.0

    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1

    n = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)

    return entropy


# ---------------------------------------------------------------------------
# Standard deviation
# ---------------------------------------------------------------------------

def calculate_stddev(values: List[float]) -> float:
    """
    Calculate the population standard deviation of *values*.

    Used for beaconing detection: a low std-dev in inter-request intervals
    suggests automated / C2 traffic.

    Parameters
    ----------
    values:
        List of numeric values (e.g. seconds between requests).

    Returns
    -------
    float  — 0.0 if the list has fewer than 2 elements.
    """
    n = len(values)
    if n < 2:
        return 0.0

    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / n
    return math.sqrt(variance)


# ---------------------------------------------------------------------------
# IP address classification
# ---------------------------------------------------------------------------

def get_ip_type(ip: str) -> str:
    """
    Classify an IPv4 or IPv6 address string.

    Returns one of:
        "Public", "Private", "Loopback", "Multicast",
        "Link-Local", "Unspecified", "Reserved", "Invalid"
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return "Invalid"

    if addr.is_loopback:
        return "Loopback"
    if addr.is_multicast:
        return "Multicast"
    if addr.is_link_local:
        return "Link-Local"
    if addr.is_unspecified:
        return "Unspecified"
    if addr.is_private:
        return "Private"
    if addr.is_reserved:
        return "Reserved"
    return "Public"


# ---------------------------------------------------------------------------
# High-risk country check
# ---------------------------------------------------------------------------

# ISO 3166-1 alpha-2 codes — kept in sync with config.yaml
_HIGH_RISK_COUNTRIES: frozenset[str] = frozenset({
    "RU",  # Russia
    "CN",  # China
    "KP",  # North Korea
    "IR",  # Iran
    "NG",  # Nigeria
    "UA",  # Ukraine (conflict-zone)
    "BY",  # Belarus
    "SY",  # Syria
    "CU",  # Cuba
    "VE",  # Venezuela
    "MM",  # Myanmar
    "AF",  # Afghanistan
    "IQ",  # Iraq
    "LY",  # Libya
    "SD",  # Sudan
    "SO",  # Somalia
    "YE",  # Yemen
    "ZW",  # Zimbabwe
})


def is_high_risk_country(country: str) -> bool:
    """
    Return True if *country* (ISO-3166-1 alpha-2, case-insensitive) is on
    the high-risk country list.

    Parameters
    ----------
    country:
        Two-letter country code, e.g. "RU" or "ru".
    """
    return country.upper().strip() in _HIGH_RISK_COUNTRIES


# ---------------------------------------------------------------------------
# Scanner / attack-tool User-Agent detection
# ---------------------------------------------------------------------------

# Compiled regex patterns — covers tool names and common automation UA strings
_SCANNER_UA_PATTERNS: List[re.Pattern] = [re.compile(p, re.IGNORECASE) for p in [
    r"sqlmap",
    r"nikto",
    r"\bnmap\b",
    r"masscan",
    r"burpsuite",
    r"burp\s*suite",
    r"\bZAP\b",
    r"OWASP",
    r"dirbuster",
    r"gobuster",
    r"wfuzz",
    r"\bhydra\b",
    r"\bmedusa\b",
    r"acunetix",
    r"\bnessus\b",
    r"openvas",
    r"\bw3af\b",
    r"\bhavij\b",
    r"\bpangolin\b",
    r"jbrofuzz",
    r"skipfish",
    r"golismero",
    r"\bnuclei\b",
    r"\bffuf\b",
    r"feroxbuster",
    r"metasploit",
    r"msfconsole",
    r"python-requests/2\.",
    r"python-httpx",
    r"Go-http-client",
    r"curl/[0-9]",
    r"libwww-perl",
    r"WinHttp",
    r"\bzgrab\b",
    r"\bshodan\b",
    r"\bcensys\b",
    r"binaryedge",
    r"internet-measurement",
    r"masshttp",
    r"peach\s*fuzzer",
    r"appscan",
    r"qualysguard",
    r"webinspect",
    r"vega\b",
    r"grabber",
    r"httprint",
    r"arachni",
    r"grendel-scan",
    r"paros",
    r"webscarab",
    r"ratproxy",
    r"darkstat",
    r"dirb\b",
    r"dirsearch",
    r"whatweb",
    r"wpscan",
    r"joomscan",
    r"droopescan",
    r"cmseek",
    r"exploit-db",
    r"commix",
    r"dalfox",
    r"xsstrike",
    r"subfinder",
    r"amass\b",
    r"httpx\b",
    r"naabu\b",
]]


def is_scanner_ua(ua_string: str) -> bool:
    """
    Return True if *ua_string* matches any known scanner or attack-tool
    User-Agent pattern.

    Parameters
    ----------
    ua_string:
        The raw User-Agent header value.
    """
    if not ua_string:
        return False

    for pattern in _SCANNER_UA_PATTERNS:
        if pattern.search(ua_string):
            return True

    # Optional deeper check with the user-agents library
    if _UA_LIB_AVAILABLE:
        try:
            ua = _ua_parse(ua_string)
            # Non-browser, non-mobile, non-bot = generic HTTP library → suspicious
            if ua.is_bot:
                return True
        except Exception:  # noqa: BLE001
            pass

    return False


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

# Ordered list of format strings to try before falling back to dateutil
_TS_FORMATS: List[str] = [
    "%Y-%m-%dT%H:%M:%S.%fZ",           # ISO 8601 with microseconds + Z
    "%Y-%m-%dT%H:%M:%SZ",              # ISO 8601 + Z
    "%Y-%m-%dT%H:%M:%S%z",             # ISO 8601 with offset
    "%Y-%m-%dT%H:%M:%S.%f%z",          # ISO 8601 with microseconds + offset
    "%Y-%m-%d %H:%M:%S",               # Common SQL / syslog variant
    "%Y-%m-%d %H:%M:%S.%f",
    "%d/%b/%Y:%H:%M:%S %z",            # Apache CLF: 10/Oct/2000:13:55:36 -0700
    "%d/%b/%Y:%H:%M:%S",               # Apache CLF without offset
    "%b %d %H:%M:%S",                  # syslog: Jan  5 12:00:00
    "%b %d %Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",               # Windows Event format
    "%Y%m%d%H%M%S",                    # Compact numeric
    "%d-%b-%Y %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%Y-%m-%d",
]


def parse_timestamp(ts: str) -> Optional[datetime]:
    """
    Parse a timestamp string into a timezone-aware (or naive) datetime.

    Tries a prioritised list of strptime formats first; falls back to
    python-dateutil if available.

    Parameters
    ----------
    ts:
        Raw timestamp string from a log event.

    Returns
    -------
    datetime object or None if parsing fails.
    """
    if not ts:
        return None

    cleaned = ts.strip()

    # Handle Unix epoch (integer or float seconds)
    _epoch_re = re.match(r'^(\d{10,13})(\.\d+)?$', cleaned)
    if _epoch_re:
        try:
            epoch_val = float(_epoch_re.group(1) + (_epoch_re.group(2) or ""))
            if len(_epoch_re.group(1)) == 13:
                epoch_val /= 1000.0
            return datetime.fromtimestamp(epoch_val, tz=timezone.utc)
        except (ValueError, OSError):
            pass

    # Try explicit formats
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(cleaned, fmt)
            # Ensure syslog-style dates (no year) use current year
            if "%Y" not in fmt and dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt
        except ValueError:
            continue

    # Fallback to dateutil
    if _DATEUTIL_AVAILABLE:
        try:
            return _dateutil_parser.parse(cleaned)
        except Exception:  # noqa: BLE001
            pass

    return None


# ---------------------------------------------------------------------------
# Byte formatting
# ---------------------------------------------------------------------------

def format_bytes(n: int) -> str:
    """
    Convert a byte count to a human-readable string.

    Examples
    --------
    >>> format_bytes(1536)
    '1.5 KB'
    >>> format_bytes(1073741824)
    '1.0 GB'
    """
    if n < 0:
        return "0 B"

    units = ("B", "KB", "MB", "GB", "TB", "PB")
    value = float(n)
    for unit in units:
        if value < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} EB"
