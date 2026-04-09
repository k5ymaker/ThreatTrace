"""
extractor/patterns.py — Compiled regex patterns for IOC extraction.

All patterns are compiled once at module load; never inside loops.

Capture-group note:
  - ``username`` and ``user_agent`` patterns use group(1); all others use
    the full match (.group(0)).

Public API:
    PATTERNS          — dict[str, re.Pattern]  (16 types)
    PRIVATE_IP_RE     — re.Pattern for RFC-1918 / loopback / link-local ranges
    TS_PATTERNS       — list[re.Pattern] for common log timestamp prefixes
    refang(text)      → str  (hxxp→http, [.]→., (dot)→., etc.)
"""

from __future__ import annotations

import re
from typing import Dict, List

# ---------------------------------------------------------------------------
# Refanging helpers
# ---------------------------------------------------------------------------

_REFANG_TABLE: List[tuple[str, str]] = [
    # scheme obfuscation
    (r"hxxps?",             lambda m: m.group(0).replace("xx", "tt")),  # handled below
    # dot obfuscation
    (r"\[\.\]",             "."),
    (r"\(dot\)",            "."),
    (r"\[dot\]",            "."),
    (r"\{dot\}",            "."),
    # at obfuscation
    (r"\[at\]",             "@"),
    (r"\(at\)",             "@"),
    # colon obfuscation
    (r"\[:\]",              ":"),
    # slash obfuscation
    (r"\[/\]",              "/"),
]


def refang(text: str) -> str:
    """
    De-obfuscate (refang) common IOC defanging patterns:

      hxxp  → http
      hxxps → https
      [.]   → .
      (dot) → .
      [dot] → .
      {dot} → .
      [at]  → @
      (at)  → @
      [:]   → :
      [/]   → /
    """
    # hxxp / hxxps first (case-insensitive)
    text = re.sub(r"hxxps", "https", text, flags=re.IGNORECASE)
    text = re.sub(r"hxxp",  "http",  text, flags=re.IGNORECASE)
    # bracket/paren dot
    text = re.sub(r"\[\.\]",  ".",  text)
    text = re.sub(r"\(dot\)", ".",  text, flags=re.IGNORECASE)
    text = re.sub(r"\[dot\]", ".",  text, flags=re.IGNORECASE)
    text = re.sub(r"\{dot\}", ".",  text, flags=re.IGNORECASE)
    # at
    text = re.sub(r"\[at\]",  "@",  text, flags=re.IGNORECASE)
    text = re.sub(r"\(at\)",  "@",  text, flags=re.IGNORECASE)
    # colon
    text = re.sub(r"\[:\]",   ":",  text)
    # slash
    text = re.sub(r"\[/\]",   "/",  text)
    return text


# ---------------------------------------------------------------------------
# Core IOC patterns
# ---------------------------------------------------------------------------

# IPv4 — optional port suffix (:PORT) is NOT included in the match so the
# IP address itself is the canonical value.
_PAT_IPV4 = re.compile(
    r"\b"
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"\b"
)

# IPv6 — covers full, compressed (::), and mapped forms.
_PAT_IPV6 = re.compile(
    r"(?<![:\w])"
    r"(?:"
    # Full 8-group form
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|"
    # Compressed form with ::
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|"
    r":(?::[0-9a-fA-F]{1,4}){1,7}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|"
    r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|"
    r"::"
    r")"
    r"(?![:\w])"
)

# Domain name — must have at least one dot; TLD 2–6 chars.
# Excludes bare hostnames (no dot) and pure IPs.
_PAT_DOMAIN = re.compile(
    r"(?<![/@\w])"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,6}"
    r"(?![.\w])"
)

# URL — http/https/ftp with optional path/query/fragment.
_PAT_URL = re.compile(
    r"https?://[^\s\"'<>\])\}]+"
    r"|ftp://[^\s\"'<>\])\}]+"
)

# Email address
_PAT_EMAIL = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

# MAC address — both colon and hyphen separators
_PAT_MAC = re.compile(
    r"\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b"
)

# Cryptographic hashes
_PAT_MD5    = re.compile(r"\b[0-9a-fA-F]{32}\b")
_PAT_SHA1   = re.compile(r"\b[0-9a-fA-F]{40}\b")
_PAT_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")

# CVE identifier
_PAT_CVE = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    flags=re.IGNORECASE,
)

# Windows filesystem path — drive letter or UNC share
_PAT_WIN_PATH = re.compile(
    r"(?:[A-Za-z]:\\(?:[^\\\s\"\':*?<>|]+\\)*[^\\\s\"\':<>|*?]*)"
    r"|(?:\\\\[^\\\s]+\\[^\\\s]+"
    r"(?:\\[^\\\s\"\':<>|*?]+)*)"
)

# Unix filesystem path — must start with / followed by at least one word char
_PAT_UNIX_PATH = re.compile(
    r"(?<![a-zA-Z0-9_\-])/(?:[a-zA-Z0-9_\-\.]+/)*[a-zA-Z0-9_\-\.]*"
    r"(?![a-zA-Z0-9_\-/])"
)

# Username — matches "user foo", "username=foo", "for user foo", "USER foo"
# group(1) is the captured username token.
_PAT_USERNAME = re.compile(
    r"(?i)(?:user(?:name)?[\s=:]+|for\s+user\s+|USER\s+)([a-zA-Z0-9_.\-@]{1,64})"
)

# User-Agent header — captures the full UA string after "User-Agent: " or
# the quoted value in logs like `"Mozilla/5.0 …"`.
# group(1) is the captured user-agent string.
_PAT_USER_AGENT = re.compile(
    r'(?i)(?:user[-_]?agent\s*[=:]\s*["\']?)([^"\';\r\n]{10,300})'
)

# AWS Access Key ID — starts with AKIA, AROA, ASIA, AIDA, ANPA, ANVA, APKA
_PAT_AWS_KEY = re.compile(
    r"\b(?:AKIA|AROA|ASIA|AIDA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b"
)

# JSON Web Token — three base64url segments separated by dots
_PAT_JWT = re.compile(
    r"\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b"
)


# ---------------------------------------------------------------------------
# Public PATTERNS dict
# ---------------------------------------------------------------------------

PATTERNS: Dict[str, "re.Pattern[str]"] = {
    "ipv4":       _PAT_IPV4,
    "ipv6":       _PAT_IPV6,
    "domain":     _PAT_DOMAIN,
    "url":        _PAT_URL,
    "email":      _PAT_EMAIL,
    "mac":        _PAT_MAC,
    "md5":        _PAT_MD5,
    "sha1":       _PAT_SHA1,
    "sha256":     _PAT_SHA256,
    "cve":        _PAT_CVE,
    "win_path":   _PAT_WIN_PATH,
    "unix_path":  _PAT_UNIX_PATH,
    "username":   _PAT_USERNAME,
    "user_agent": _PAT_USER_AGENT,
    "aws_key":    _PAT_AWS_KEY,
    "jwt":        _PAT_JWT,
}

# Patterns that use group(1) for their value (not the full match)
GROUP1_PATTERNS: frozenset[str] = frozenset({"username", "user_agent"})


# ---------------------------------------------------------------------------
# Private IP filter
# ---------------------------------------------------------------------------

PRIVATE_IP_RE = re.compile(
    r"^(?:"
    # 10.x.x.x
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|"
    # 172.16.x.x – 172.31.x.x
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|"
    # 192.168.x.x
    r"192\.168\.\d{1,3}\.\d{1,3}"
    r"|"
    # 127.x.x.x  (loopback)
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|"
    # 169.254.x.x  (link-local)
    r"169\.254\.\d{1,3}\.\d{1,3}"
    r"|"
    # ::1  (IPv6 loopback)
    r"::1"
    r"|"
    # fc00::/7  (IPv6 ULA)
    r"f[cd][0-9a-fA-F]{2}:"
    r")$"
)


# ---------------------------------------------------------------------------
# Timestamp prefix patterns (used to strip timestamps before IOC search)
# ---------------------------------------------------------------------------

TS_PATTERNS: List["re.Pattern[str]"] = [
    # ISO-8601: 2024-01-15T12:34:56Z  /  2024-01-15 12:34:56.123
    re.compile(
        r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"
    ),
    # Syslog: Jan 15 12:34:56
    re.compile(
        r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    ),
    # Apache/Nginx: [15/Jan/2024:12:34:56 +0000]
    re.compile(
        r"^\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]"
    ),
    # Epoch timestamp: 1705320000.000
    re.compile(r"^\d{10,13}(?:\.\d+)?"),
    # Windows Event log: 2024-01-15 12:34:56 AM/PM
    re.compile(
        r"^\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM)"
    ),
]
