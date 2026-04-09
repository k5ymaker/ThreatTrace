"""ThreatTrace Correlation Engine — 31 analytics functions."""
from __future__ import annotations
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Optional
import math
import statistics
import re

SCANNER_UA_PATTERNS = [
    'sqlmap', 'nikto', 'nmap', 'masscan', 'zap', 'burpsuite', 'burp',
    'acunetix', 'nessus', 'openvas', 'dirbuster', 'gobuster', 'wfuzz',
    'hydra', 'medusa', 'nuclei', 'ffuf', 'feroxbuster', 'metasploit',
    'w3af', 'skipfish', 'arachni', 'qualys', 'rapid7', 'nessus',
]

SENSITIVE_PORTS = {22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP",
                   5985: "WinRM", 5986: "WinRM-SSL", 1433: "MSSQL",
                   3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
                   27017: "MongoDB", 2375: "Docker", 6443: "K8s API"}

HTTP_STATUS_DESCRIPTIONS = {
    200: "OK", 201: "Created", 204: "No Content", 206: "Partial Content",
    301: "Moved Permanently", 302: "Found", 304: "Not Modified",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 408: "Request Timeout",
    429: "Too Many Requests", 499: "Client Closed Request",
    500: "Internal Server Error", 502: "Bad Gateway",
    503: "Service Unavailable", 504: "Gateway Timeout",
}

FAILURE_NAMES = frozenset([
    "Failed Logon", "SSH Failed Password", "SSH Invalid User Attempt",
    "Account Lockout", "Sudo Authentication Failure", "PAM Authentication Failure",
    "Kerberos Pre-Auth Failed", "VPN Auth Failed", "AnyConnect Auth Failed",
    "SQL Login Failed", "MySQL Access Denied", "ACL Deny", "Firewall Block",
    "Proxy Auth Failure", "Proxy Request Denied", "K8s API Auth Failure",
    "SASL Auth Failure", "SSH Max Auth Tries Exceeded",
])

SUCCESS_NAMES = frozenset([
    "Successful Logon", "SSH Accepted Password", "SSH Public Key Accepted",
    "User Login (local)", "VPN Connect", "AnyConnect Session Started",
    "GlobalProtect Connected", "SQL Login Success", "Proxy Request Allowed",
])


def _is_failure(e: dict) -> bool:
    en = e.get("event_name", "") or ""
    if en in FAILURE_NAMES:
        return True
    action = (e.get("action") or "").lower()
    if action in ("deny", "drop", "block", "reject", "failure", "failed"):
        return True
    sc = e.get("status_code")
    if sc and isinstance(sc, int) and sc in (401, 403, 407):
        return True
    return False


def _is_success(e: dict) -> bool:
    en = e.get("event_name", "") or ""
    if en in SUCCESS_NAMES:
        return True
    action = (e.get("action") or "").lower()
    if action in ("allow", "permit", "accept", "success", "pass"):
        return True
    sc = e.get("status_code")
    if sc and isinstance(sc, int) and 200 <= sc < 400:
        return True
    return False


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    ts = ts.rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def _is_internal(ip: str) -> bool:
    if not ip:
        return False
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        f, s = int(parts[0]), int(parts[1])
        if f == 10:
            return True
        if f == 172 and 16 <= s <= 31:
            return True
        if f == 192 and s == 168:
            return True
        if f == 127:
            return True
    except Exception:
        pass
    return False


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _is_scanner_ua(ua: str) -> bool:
    ua_lower = (ua or "").lower()
    return any(p in ua_lower for p in SCANNER_UA_PATTERNS)


# --- 1. TRAFFIC METRICS ---

def top_ips_by_request_count(events: list, n: int = 10) -> list:
    """Top N IPs by total event count."""
    counts: dict = Counter(e.get("source_ip") for e in events if e.get("source_ip"))
    total = len(events)
    result = []
    for ip, count in counts.most_common(n):
        ip_events = [e for e in events if e.get("source_ip") == ip]
        ts = sorted(e.get("timestamp", "") for e in ip_events if e.get("timestamp"))
        result.append({
            "rank": len(result) + 1,
            "ip": ip,
            "country": None,
            "requests": count,
            "percentage": round(count / total * 100, 2) if total else 0.0,
            "bytes": sum(e.get("bytes_sent", 0) or 0 for e in ip_events),
            "first_seen": ts[0] if ts else None,
            "last_seen": ts[-1] if ts else None,
            "threat_flag": _is_scanner_ua(next((e.get("user_agent", "") for e in ip_events if e.get("user_agent")), "")),
        })
    return result


def top_ips_by_bandwidth(events: list, n: int = 10) -> list:
    """Top N IPs by total bytes sent."""
    by_ip: dict = defaultdict(lambda: {"bytes": 0, "count": 0, "protocols": set()})
    for e in events:
        ip = e.get("source_ip")
        if ip and e.get("bytes_sent") and isinstance(e["bytes_sent"], int):
            by_ip[ip]["bytes"] += e["bytes_sent"]
            by_ip[ip]["count"] += 1
            if e.get("protocol"):
                by_ip[ip]["protocols"].add(e["protocol"])
    sorted_ips = sorted(by_ip.items(), key=lambda x: x[1]["bytes"], reverse=True)[:n]
    result = []
    for i, (ip, data) in enumerate(sorted_ips):
        result.append({
            "rank": i + 1,
            "ip": ip,
            "total_bytes": data["bytes"],
            "avg_bytes_per_req": data["bytes"] // data["count"] if data["count"] else 0,
            "request_count": data["count"],
            "protocols": sorted(data["protocols"]),
        })
    return result


def unique_ips(events: list) -> list:
    """All unique source IPs with basic stats."""
    by_ip: dict = Counter(e.get("source_ip") for e in events if e.get("source_ip"))
    return [{"ip": ip, "count": count} for ip, count in by_ip.most_common()]


def top_user_agents(events: list, n: int = 10) -> list:
    """Top N user agents with scanner detection."""
    total = len(events)
    counts: dict = Counter(e.get("user_agent") for e in events if e.get("user_agent"))
    result = []
    for i, (ua, count) in enumerate(counts.most_common(n)):
        result.append({
            "rank": i + 1,
            "ua_string": ua,
            "count": count,
            "percentage": round(count / total * 100, 2) if total else 0.0,
            "category": "Security Scanner" if _is_scanner_ua(ua) else "Web Browser",
            "is_scanner": _is_scanner_ua(ua),
        })
    return result


def unique_user_agents(events: list) -> list:
    """All unique user agents categorized."""
    browser_patterns = ['Mozilla', 'Chrome', 'Safari', 'Firefox', 'Edge', 'MSIE', 'Trident']
    bot_patterns = ['bot', 'crawler', 'spider', 'Googlebot', 'Bingbot', 'Slurp']
    mobile_patterns = ['Android', 'iPhone', 'iPad', 'Mobile']

    counts: dict = Counter(e.get("user_agent") for e in events if e.get("user_agent"))
    result = []
    for ua, count in counts.most_common():
        if _is_scanner_ua(ua):
            category = "Security Scanner"
        elif any(p.lower() in ua.lower() for p in bot_patterns):
            category = "Bot/Crawler"
        elif any(p.lower() in ua.lower() for p in mobile_patterns):
            category = "Mobile Browser"
        elif any(p in ua for p in browser_patterns):
            category = "Web Browser"
        elif ua.startswith(("python-", "Go-", "curl/", "wget/", "libwww")):
            category = "Automated Tool"
        else:
            category = "Unknown"
        result.append({
            "ua": ua,
            "category": category,
            "count": count,
            "threat_flag": _is_scanner_ua(ua),
        })
    return result


# --- 2. AUTH METRICS ---

def top_login_failures_by_user(events: list, n: int = 10) -> list:
    """Top N users by login failure count."""
    by_user: dict = defaultdict(lambda: {"count": 0, "ips": set(), "types": set(), "ts": []})
    for e in events:
        if _is_failure(e) and e.get("username"):
            u = e["username"]
            by_user[u]["count"] += 1
            if e.get("source_ip"):
                by_user[u]["ips"].add(e["source_ip"])
            if e.get("event_name"):
                by_user[u]["types"].add(e["event_name"])
            if e.get("timestamp"):
                by_user[u]["ts"].append(e["timestamp"])
    sorted_users = sorted(by_user.items(), key=lambda x: x[1]["count"], reverse=True)[:n]
    result = []
    for i, (user, data) in enumerate(sorted_users):
        ts_sorted = sorted(data["ts"])
        result.append({
            "rank": i + 1,
            "username": user,
            "failures": data["count"],
            "source_ips": sorted(data["ips"]),
            "failure_types": sorted(data["types"]),
            "first_seen": ts_sorted[0] if ts_sorted else None,
            "last_seen": ts_sorted[-1] if ts_sorted else None,
        })
    return result


def top_login_failures_by_ip(events: list, n: int = 10) -> list:
    """Top N IPs by login failure count."""
    by_ip: dict = defaultdict(lambda: {"count": 0, "users": set(), "protocols": set(), "ts": []})
    for e in events:
        if _is_failure(e) and e.get("source_ip"):
            ip = e["source_ip"]
            by_ip[ip]["count"] += 1
            if e.get("username"):
                by_ip[ip]["users"].add(e["username"])
            if e.get("protocol"):
                by_ip[ip]["protocols"].add(e["protocol"])
            if e.get("timestamp"):
                by_ip[ip]["ts"].append(e["timestamp"])
    sorted_ips = sorted(by_ip.items(), key=lambda x: x[1]["count"], reverse=True)[:n]
    result = []
    for i, (ip, data) in enumerate(sorted_ips):
        ts_sorted = sorted(data["ts"])
        result.append({
            "rank": i + 1,
            "ip": ip,
            "failures": data["count"],
            "targeted_usernames": sorted(data["users"]),
            "protocols": sorted(data["protocols"]),
            "first_seen": ts_sorted[0] if ts_sorted else None,
            "last_seen": ts_sorted[-1] if ts_sorted else None,
        })
    return result


def failed_vs_successful_logins(events: list) -> list:
    """Per-user failure vs success ratio."""
    by_user: dict = defaultdict(lambda: {"success": 0, "fail": 0})
    for e in events:
        user = e.get("username")
        if not user:
            continue
        if _is_failure(e):
            by_user[user]["fail"] += 1
        elif _is_success(e):
            by_user[user]["success"] += 1
    result = []
    for user, data in sorted(by_user.items(), key=lambda x: x[1]["fail"], reverse=True):
        total = data["success"] + data["fail"]
        rate = round(data["fail"] / total * 100, 2) if total else 0.0
        result.append({
            "username": user,
            "successes": data["success"],
            "failures": data["fail"],
            "failure_rate": rate,
            "risk": "HIGH" if rate > 50 and data["fail"] > 5 else
                    "MEDIUM" if rate > 25 else "LOW",
        })
    return result


def account_lockouts(events: list) -> list:
    """List account lockout events."""
    lockouts = [e for e in events if e.get("event_name") == "Account Lockout"]
    result = []
    for e in lockouts:
        result.append({
            "timestamp": e.get("timestamp"),
            "locked_account": e.get("username"),
            "source_ip": e.get("source_ip"),
            "hostname": e.get("hostname"),
            "raw": e.get("raw", "")[:200],
        })
    return result


def successful_logons_after_failures(events: list) -> list:
    """Detect IPs/users that succeeded after multiple failures."""
    fail_by_ip: dict = defaultdict(int)
    success_by_ip: dict = {}
    for e in sorted(events, key=lambda x: x.get("timestamp") or ""):
        ip = e.get("source_ip")
        if not ip:
            continue
        if _is_failure(e):
            fail_by_ip[ip] += 1
        elif _is_success(e) and fail_by_ip.get(ip, 0) >= 3:
            if ip not in success_by_ip:
                success_by_ip[ip] = {
                    "ip": ip,
                    "username": e.get("username"),
                    "failure_count_before": fail_by_ip[ip],
                    "success_timestamp": e.get("timestamp"),
                    "success_event": e.get("event_name"),
                }
    return list(success_by_ip.values())


# --- 3. HTTP METRICS ---

def http_status_code_distribution(events: list) -> list:
    """HTTP status code frequency table."""
    counts: dict = Counter(e.get("status_code") for e in events
                           if e.get("status_code") and isinstance(e["status_code"], int))
    total = sum(counts.values())
    return sorted([
        {
            "status_code": code,
            "description": HTTP_STATUS_DESCRIPTIONS.get(code, "Unknown"),
            "count": count,
            "percentage": round(count / total * 100, 2) if total else 0.0,
        }
        for code, count in counts.items()
    ], key=lambda x: x["count"], reverse=True)


def top_requested_urls(events: list, n: int = 20) -> list:
    """Top N most requested URLs."""
    by_url: dict = defaultdict(lambda: {"count": 0, "methods": set(),
                                         "status_codes": set(), "ips": set()})
    for e in events:
        url = e.get("url")
        if not url:
            continue
        by_url[url]["count"] += 1
        if e.get("method"):
            by_url[url]["methods"].add(e["method"])
        if e.get("status_code"):
            by_url[url]["status_codes"].add(e["status_code"])
        if e.get("source_ip"):
            by_url[url]["ips"].add(e["source_ip"])

    suspicious_keywords = ["/admin", "/login", "/cmd", "/shell", "/exec",
                           "/wp-login", "/.env", "/phpinfo", "/phpmyadmin",
                           "../", "passwd", "shadow"]
    sorted_urls = sorted(by_url.items(), key=lambda x: x[1]["count"], reverse=True)[:n]
    result = []
    for i, (url, data) in enumerate(sorted_urls):
        result.append({
            "rank": i + 1,
            "url": url,
            "method": sorted(data["methods"]),
            "status_codes": sorted(data["status_codes"]),
            "total_requests": data["count"],
            "unique_ips": len(data["ips"]),
            "anomaly_flag": any(kw.lower() in url.lower() for kw in suspicious_keywords),
        })
    return result


def http_methods_distribution(events: list) -> list:
    """HTTP method frequency table."""
    counts: dict = Counter(e.get("method") for e in events if e.get("method"))
    total = sum(counts.values())
    unusual = {"TRACE", "CONNECT", "DELETE", "PUT", "OPTIONS", "PATCH"}
    return sorted([
        {
            "method": method,
            "count": count,
            "percentage": round(count / total * 100, 2) if total else 0.0,
            "anomaly_flag": method.upper() in unusual,
        }
        for method, count in counts.items()
    ], key=lambda x: x["count"], reverse=True)


def top_referrers(events: list, n: int = 10) -> list:
    """Top N referrer URLs."""
    refs: dict = Counter()
    for e in events:
        raw = e.get("raw", "") or ""
        # crude referrer extraction from combined log format
        m = re.search(r'"(https?://[^"]+)"', raw)
        if m and m.group(1) != e.get("url", ""):
            refs[m.group(1)] += 1
    total = sum(refs.values())
    return [{"referrer": ref, "count": count,
             "percentage": round(count / total * 100, 2) if total else 0.0}
            for ref, count in refs.most_common(n)]


# --- 4. NETWORK METRICS ---

def top_destination_ports(events: list, n: int = 10) -> list:
    """Top N destination ports."""
    counts: dict = Counter(e.get("dest_port") for e in events
                           if e.get("dest_port") and isinstance(e["dest_port"], int))
    total = sum(counts.values())
    result = []
    for i, (port, count) in enumerate(counts.most_common(n)):
        ips = set(e.get("source_ip") for e in events
                  if e.get("dest_port") == port and e.get("source_ip"))
        result.append({
            "rank": i + 1,
            "port": port,
            "service_name": SENSITIVE_PORTS.get(port, "Unknown"),
            "count": count,
            "percentage": round(count / total * 100, 2) if total else 0.0,
            "unique_sources": len(ips),
            "protocol": next((e.get("protocol") for e in events if e.get("dest_port") == port and e.get("protocol")), "TCP"),
        })
    return result


def blocked_vs_allowed_traffic(events: list) -> list:
    """Per-source-IP block vs allow ratio."""
    by_ip: dict = defaultdict(lambda: {"allowed": 0, "blocked": 0})
    for e in events:
        ip = e.get("source_ip")
        if not ip:
            continue
        action = (e.get("action") or "").lower()
        en = e.get("event_name", "") or ""
        if action in ("deny", "drop", "block", "reject") or "Block" in en or "Deny" in en:
            by_ip[ip]["blocked"] += 1
        elif action in ("allow", "permit", "pass") or "Allow" in en or "Pass" in en:
            by_ip[ip]["allowed"] += 1
    result = []
    for ip, data in sorted(by_ip.items(), key=lambda x: x[1]["blocked"], reverse=True):
        total = data["allowed"] + data["blocked"]
        rate = round(data["blocked"] / total * 100, 2) if total else 0.0
        result.append({
            "source_ip": ip,
            "allowed": data["allowed"],
            "blocked": data["blocked"],
            "block_rate": rate,
            "risk_flag": rate > 50 and data["blocked"] > 10,
        })
    return result


def unique_countries_ips(events: list) -> list:
    """Country distribution (uses country field if present)."""
    by_country: dict = defaultdict(lambda: {"ips": set(), "count": 0})
    for e in events:
        country = e.get("country")
        if not country:
            fields = e.get("fields")
            if isinstance(fields, dict):
                country = fields.get("country")
        if country and e.get("source_ip"):
            by_country[country]["ips"].add(e["source_ip"])
            by_country[country]["count"] += 1
    return sorted([
        {"country": c, "ip_count": len(d["ips"]), "event_count": d["count"]}
        for c, d in by_country.items()
    ], key=lambda x: x["event_count"], reverse=True)


def internal_to_internal_anomalies(events: list) -> list:
    """Detect internal-to-internal lateral movement on sensitive ports."""
    result_map: dict = defaultdict(lambda: {"count": 0, "ts": []})
    for e in events:
        src = e.get("source_ip")
        dst = e.get("dest_ip")
        port = e.get("dest_port")
        if src and dst and port and _is_internal(src) and _is_internal(dst) and port in SENSITIVE_PORTS:
            key = (src, dst, port)
            result_map[key]["count"] += 1
            if e.get("timestamp"):
                result_map[key]["ts"].append(e["timestamp"])
    result = []
    for (src, dst, port), data in sorted(result_map.items(), key=lambda x: x[1]["count"], reverse=True):
        ts = sorted(data["ts"])
        result.append({
            "source_ip": src,
            "dest_ip": dst,
            "port": port,
            "service": SENSITIVE_PORTS.get(port, "Unknown"),
            "count": data["count"],
            "first_seen": ts[0] if ts else None,
            "last_seen": ts[-1] if ts else None,
        })
    return result


# --- 5. DNS METRICS ---

def top_queried_domains(events: list, n: int = 20) -> list:
    """Top queried domains with DGA entropy scoring."""
    dns_events = [e for e in events if e.get("event_category") == "DNS" and e.get("domain")]
    counts: dict = Counter(e["domain"] for e in dns_events)
    result = []
    for i, (domain, count) in enumerate(counts.most_common(n)):
        # Calculate entropy of the leftmost label
        parts = domain.split(".")
        label = parts[0] if parts else domain
        entropy = _shannon_entropy(label)
        result.append({
            "rank": i + 1,
            "domain": domain,
            "count": count,
            "entropy_score": round(entropy, 3),
            "dga_flag": entropy > 3.5 and len(label) > 10,
        })
    return result


def nxdomain_rate_by_client(events: list) -> list:
    """NXDOMAIN rate per DNS client IP."""
    by_client: dict = defaultdict(lambda: {"total": 0, "nxdomain": 0})
    for e in events:
        if e.get("event_category") == "DNS" and e.get("source_ip"):
            ip = e["source_ip"]
            by_client[ip]["total"] += 1
            if e.get("event_name") == "DNS NXDOMAIN Response":
                by_client[ip]["nxdomain"] += 1
    result = []
    for ip, data in sorted(by_client.items(), key=lambda x: x[1]["nxdomain"], reverse=True):
        total = data["total"]
        rate = round(data["nxdomain"] / total * 100, 2) if total else 0.0
        result.append({
            "client_ip": ip,
            "nxdomain_count": data["nxdomain"],
            "total_queries": total,
            "nxdomain_rate": rate,
            "dga_flag": rate > 30 and data["nxdomain"] > 10,
        })
    return result


def dns_query_volume_by_client(events: list, n: int = 10) -> list:
    """DNS query volume per client with tunneling indicators."""
    by_client: dict = defaultdict(lambda: {"count": 0, "domains": set(), "label_lengths": []})
    for e in events:
        if e.get("event_category") == "DNS" and e.get("source_ip"):
            ip = e["source_ip"]
            by_client[ip]["count"] += 1
            if e.get("domain"):
                by_client[ip]["domains"].add(e["domain"])
                label = e["domain"].split(".")[0] if e["domain"] else ""
                if label:
                    by_client[ip]["label_lengths"].append(len(label))
    sorted_clients = sorted(by_client.items(), key=lambda x: x[1]["count"], reverse=True)[:n]
    result = []
    for ip, data in sorted_clients:
        avg_len = round(sum(data["label_lengths"]) / len(data["label_lengths"]), 1) if data["label_lengths"] else 0
        result.append({
            "client_ip": ip,
            "query_count": data["count"],
            "unique_domains": len(data["domains"]),
            "avg_label_length": avg_len,
            "tunnel_flag": avg_len > 30,
        })
    return result


# --- 6. TEMPORAL METRICS ---

def events_timeline(events: list) -> dict:
    """Hourly and daily event distribution."""
    hourly: dict = Counter()
    daily: dict = Counter()
    after_hours_count = 0
    for e in events:
        ts_str = e.get("timestamp")
        if not ts_str:
            continue
        ts_str = ts_str.rstrip("Z")
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(ts_str, fmt)
                hour_key = dt.strftime("%Y-%m-%dT%H:00")
                day_key = dt.strftime("%Y-%m-%d")
                hourly[hour_key] += 1
                daily[day_key] += 1
                if dt.hour >= 23 or dt.hour < 6:
                    after_hours_count += 1
                break
            except ValueError:
                continue

    hourly_list = sorted([{"hour": h, "count": c} for h, c in hourly.items()], key=lambda x: x["hour"])
    daily_list = sorted([{"date": d, "count": c} for d, c in daily.items()], key=lambda x: x["date"])
    peak_hour = max(hourly.items(), key=lambda x: x[1])[0] if hourly else None
    peak_day = max(daily.items(), key=lambda x: x[1])[0] if daily else None
    return {
        "hourly": hourly_list,
        "daily": daily_list,
        "peak_hour": peak_hour,
        "peak_day": peak_day,
        "after_hours_count": after_hours_count,
    }


def event_rate_spike_detection(events: list) -> list:
    """Detect event rate spikes >3x baseline."""
    hourly: dict = Counter()
    for e in events:
        ts_str = (e.get("timestamp") or "").rstrip("Z")
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(ts_str, fmt)
                hourly[dt.strftime("%Y-%m-%dT%H:00")] += 1
                break
            except ValueError:
                continue
    if not hourly:
        return []
    values = list(hourly.values())
    baseline = sum(values) / len(values) if values else 0
    spikes = []
    for hour, count in sorted(hourly.items()):
        if count > baseline * 3 and baseline > 0:
            spikes.append({
                "period_start": hour,
                "period_end": hour,
                "event_count": count,
                "baseline": round(baseline, 1),
                "spike_ratio": round(count / baseline, 2),
                "spike_type": "High Volume Spike",
            })
    return spikes


def first_and_last_seen_per_ip(events: list) -> list:
    """First/last seen per IP with beaconing gap analysis."""
    by_ip: dict = defaultdict(lambda: {"first": None, "last": None, "count": 0, "ts": []})
    for e in events:
        ip = e.get("source_ip")
        ts = e.get("timestamp")
        if not ip or not ts:
            continue
        by_ip[ip]["count"] += 1
        by_ip[ip]["ts"].append(ts)
    result = []
    for ip, data in sorted(by_ip.items(), key=lambda x: x[1]["count"], reverse=True):
        ts_sorted = sorted(data["ts"])
        try:
            dt_first = datetime.strptime(ts_sorted[0].rstrip("Z"), "%Y-%m-%dT%H:%M:%S")
            dt_last = datetime.strptime(ts_sorted[-1].rstrip("Z"), "%Y-%m-%dT%H:%M:%S")
            duration_h = round((dt_last - dt_first).total_seconds() / 3600, 2)
        except Exception:
            duration_h = 0
        result.append({
            "ip": ip,
            "first_seen": ts_sorted[0] if ts_sorted else None,
            "last_seen": ts_sorted[-1] if ts_sorted else None,
            "total_events": data["count"],
            "active_duration_h": duration_h,
            "regular_intervals": duration_h > 0 and data["count"] > 10,
        })
    return result


# --- 7. COMMAND/PROCESS METRICS ---

def suspicious_commands(events: list) -> list:
    """Detect suspicious command-line patterns."""
    sus_patterns = [
        (r'wget\s+http', "Download Cradle (wget)"),
        (r'curl\s+-[sS]\s*.*http', "Download Cradle (curl)"),
        (r'/dev/tcp/', "Reverse Shell"),
        (r'base64\s+-d', "Base64 Decode"),
        (r'python\s+-c\s+[\'"]import\s+socket', "Python Reverse Shell"),
        (r'nc\s+-e\s+/bin/', "Netcat Reverse Shell"),
        (r'\\x[0-9a-f]{2}\\x[0-9a-f]{2}', "Shellcode Hex"),
        (r'-EncodedCommand', "PowerShell Encoded"),
        (r'sekurlsa::', "Mimikatz"),
        (r'lsadump::', "Credential Dump"),
        (r'vssadmin\s+delete', "Shadow Copy Deletion"),
        (r'certutil.*-urlcache', "LOLBin: certutil"),
        (r'regsvr32.*http', "LOLBin: regsvr32 scrlet"),
    ]
    by_pattern: dict = defaultdict(lambda: {"events": [], "ips": set(), "users": set()})
    for e in events:
        cmd = e.get("command_line") or e.get("raw") or ""
        for pattern, threat_type in sus_patterns:
            if re.search(pattern, cmd, re.IGNORECASE):
                by_pattern[threat_type]["events"].append(e)
                if e.get("source_ip"):
                    by_pattern[threat_type]["ips"].add(e["source_ip"])
                if e.get("username"):
                    by_pattern[threat_type]["users"].add(e["username"])
    result = []
    for threat_type, data in sorted(by_pattern.items(), key=lambda x: len(x[1]["events"]), reverse=True):
        evts = data["events"]
        result.append({
            "command": evts[0].get("command_line", evts[0].get("raw", ""))[:200],
            "event_count": len(evts),
            "source_ips": sorted(data["ips"]),
            "usernames": sorted(data["users"]),
            "threat_type": threat_type,
        })
    return result


def top_process_executions(events: list, n: int = 20) -> list:
    """Top N process executions."""
    suspicious_procs = {"mimikatz.exe", "procdump.exe", "wce.exe", "fgdump.exe",
                        "pwdump.exe", "gsecdump.exe", "cachedump.exe", "msvcp.dll",
                        "meterpreter", "cobaltstrike"}
    counts: dict = Counter(e.get("process_name") for e in events if e.get("process_name"))
    result = []
    for i, (proc, count) in enumerate(counts.most_common(n)):
        users = set(e.get("username") for e in events if e.get("process_name") == proc and e.get("username"))
        hosts = set(e.get("hostname") for e in events if e.get("process_name") == proc and e.get("hostname"))
        result.append({
            "rank": i + 1,
            "process_name": proc,
            "count": count,
            "unique_users": sorted(users),
            "unique_hosts": sorted(hosts),
            "suspicious_flag": proc.lower() in suspicious_procs,
        })
    return result


def new_scheduled_tasks_or_services(events: list) -> list:
    """List new scheduled tasks and services."""
    relevant = [e for e in events
                if e.get("event_name") in ("Scheduled Task Created", "New Service Installed",
                                            "Cron Job Executed", "Scheduled Task Modified")]
    result = []
    for e in relevant:
        en = e.get("event_name", "")
        if "Task" in en:
            item_type = "Scheduled Task"
        elif "Service" in en:
            item_type = "Service"
        else:
            item_type = "Cron"
        result.append({
            "type": item_type,
            "name": e.get("process_name") or e.get("hostname") or "Unknown",
            "creator": e.get("username"),
            "time": e.get("timestamp"),
            "path": e.get("command_line", "")[:200],
            "risk_flag": bool(e.get("command_line") and
                              any(p in (e["command_line"] or "").lower()
                                  for p in ["temp", "appdata", "http://", "powershell"])),
        })
    return result


# --- 8. CLOUD METRICS ---

def api_calls_by_identity(events: list, n: int = 10) -> list:
    """Top N cloud API callers."""
    by_user: dict = defaultdict(lambda: {"count": 0, "apis": set(), "errors": 0})
    cloud_categories = {"IAM", "S3", "EC2", "STS", "CloudTrail", "Lambda",
                        "KMS", "AWS", "Azure", "GCP", "Okta"}
    for e in events:
        if e.get("event_category") in cloud_categories and e.get("username"):
            u = e["username"]
            by_user[u]["count"] += 1
            if e.get("event_name"):
                by_user[u]["apis"].add(e["event_name"])
            if e.get("action") in ("failure", "failed", "error"):
                by_user[u]["errors"] += 1
    sorted_users = sorted(by_user.items(), key=lambda x: x[1]["count"], reverse=True)[:n]
    return [{
        "identity": u,
        "api_call_count": data["count"],
        "unique_apis": sorted(data["apis"]),
        "error_count": data["errors"],
        "risk_flag": data["errors"] > 5 or any(
            a in data["apis"] for a in ("CreateUser", "AttachUserPolicy", "DeleteTrail")
        ),
    } for u, data in sorted_users]


def failed_api_calls_by_identity(events: list) -> list:
    """Failed cloud API calls by identity."""
    by_user: dict = defaultdict(lambda: {"count": 0, "error_types": set(), "apis": set()})
    cloud_categories = {"IAM", "S3", "EC2", "STS", "CloudTrail", "Lambda",
                        "KMS", "AWS", "Azure", "GCP", "Okta"}
    for e in events:
        if (e.get("event_category") in cloud_categories and
                e.get("username") and e.get("action") in ("failure", "failed", "error")):
            u = e["username"]
            by_user[u]["count"] += 1
            if e.get("event_name"):
                by_user[u]["apis"].add(e["event_name"])
    return [{
        "identity": u,
        "failed_count": data["count"],
        "error_types": sorted(data["error_types"]),
        "apis_attempted": sorted(data["apis"]),
    } for u, data in sorted(by_user.items(), key=lambda x: x[1]["count"], reverse=True)]


def privilege_escalation_indicators(events: list) -> list:
    """Detect privilege escalation indicators."""
    priv_event_names = {
        "Special Privileges Assigned", "Sudo Command Executed",
        "Process Tampering", "Explicit Credential Use", "Privilege Change",
        "K8s RBAC Change", "Directory Service Object Access", "UAC Bypass",
    }
    result = []
    for e in events:
        if e.get("event_name") in priv_event_names:
            result.append({
                "username": e.get("username"),
                "ip": e.get("source_ip"),
                "escalation_type": e.get("event_name"),
                "evidence_event": e.get("event_name"),
                "timestamp": e.get("timestamp"),
                "command": e.get("command_line", "")[:200] if e.get("command_line") else None,
            })
    return result


# --- 9. USER-AGENT DEEP ANALYSIS ---

def parse_and_categorize_user_agents(events: list) -> list:
    """Parse and categorize all user agent strings."""
    counts: dict = Counter(e.get("user_agent") for e in events if e.get("user_agent"))
    browser_patterns = {"Chrome": "Chrome", "Firefox": "Firefox", "Safari": "Safari",
                        "MSIE": "Internet Explorer", "Trident": "Internet Explorer",
                        "Edge": "Edge", "Opera": "Opera"}
    os_patterns = {"Windows NT 10": "Windows 10", "Windows NT 6.3": "Windows 8.1",
                   "Windows NT 6.1": "Windows 7", "Mac OS X": "macOS",
                   "Linux": "Linux", "Android": "Android", "iPhone": "iOS"}
    result = []
    for ua, count in counts.most_common():
        browser = next((v for k, v in browser_patterns.items() if k in ua), "Unknown")
        os_name = next((v for k, v in os_patterns.items() if k in ua), "Unknown")
        device = "Mobile" if any(m in ua for m in ["Mobile", "Android", "iPhone"]) else "Desktop"
        if _is_scanner_ua(ua):
            category = "Security Scanner"
        elif any(b in ua for b in ["bot", "Bot", "spider", "crawler", "Googlebot", "Bingbot"]):
            category = "Bot/Crawler"
        elif ua.startswith(("python-", "Go-http-client", "curl/", "wget/", "libwww")):
            category = "Automated Tool"
        elif device == "Mobile":
            category = "Mobile Browser"
        elif browser != "Unknown":
            category = "Web Browser"
        else:
            category = "Unknown"
        result.append({
            "raw_ua": ua,
            "browser": browser,
            "os": os_name,
            "device": device,
            "category": category,
            "count": count,
            "threat_flag": _is_scanner_ua(ua),
        })
    return result


def run_all_correlations(events: list) -> dict:
    """Run all 31 correlation functions and return combined dict."""
    return {
        "top_ips_by_requests": top_ips_by_request_count(events),
        "top_ips_by_bandwidth": top_ips_by_bandwidth(events),
        "unique_ips": unique_ips(events),
        "top_user_agents": top_user_agents(events),
        "all_user_agents": unique_user_agents(events),
        "login_failures_by_user": top_login_failures_by_user(events),
        "login_failures_by_ip": top_login_failures_by_ip(events),
        "failed_vs_success_logins": failed_vs_successful_logins(events),
        "account_lockouts": account_lockouts(events),
        "successful_after_failure": successful_logons_after_failures(events),
        "http_status_dist": http_status_code_distribution(events),
        "top_urls": top_requested_urls(events),
        "http_methods": http_methods_distribution(events),
        "top_referrers": top_referrers(events),
        "top_dest_ports": top_destination_ports(events),
        "blocked_vs_allowed": blocked_vs_allowed_traffic(events),
        "unique_countries": unique_countries_ips(events),
        "internal_anomalies": internal_to_internal_anomalies(events),
        "top_domains": top_queried_domains(events),
        "nxdomain_by_client": nxdomain_rate_by_client(events),
        "dns_volume_by_client": dns_query_volume_by_client(events),
        "timeline": events_timeline(events),
        "rate_spikes": event_rate_spike_detection(events),
        "ip_beaconing": first_and_last_seen_per_ip(events),
        "suspicious_commands": suspicious_commands(events),
        "top_processes": top_process_executions(events),
        "new_tasks_services": new_scheduled_tasks_or_services(events),
        "api_calls": api_calls_by_identity(events),
        "failed_api_calls": failed_api_calls_by_identity(events),
        "priv_escalation": privilege_escalation_indicators(events),
        "user_agents_parsed": parse_and_categorize_user_agents(events),
    }
