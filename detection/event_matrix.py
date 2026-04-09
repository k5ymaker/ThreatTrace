"""
ThreatTrace Event Matrix Engine
Builds comprehensive statistical overview of log data before detection runs.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional
import math
import statistics
import re

# Risk event names - events that warrant security attention
RISK_EVENT_NAMES: frozenset = frozenset([
    "Failed Logon", "Account Lockout", "SSH Failed Password",
    "SSH Invalid User Attempt", "SSH Max Auth Tries Exceeded",
    "SSH Max Auth Exceeded", "Security Log Cleared",
    "Process Creation", "Scheduled Task Created", "Scheduled Task Modified",
    "New Service Installed", "PowerShell Script Block",
    "NTLM Auth Attempted", "Kerberos Service Ticket Requested",
    "Kerberos Pre-Auth Failed", "DCSync Attack",
    "Directory Service Object Access",
    "ProcessAccess", "CreateRemoteThread", "Registry Value Set",
    "Registry Key Created/Deleted", "Registry Key/Value Renamed",
    "ACL Deny", "Firewall Block", "Proxy Request Denied",
    "Proxy Auth Failure", "DNS TXT Query", "DNS NXDOMAIN Response",
    "HTTP POST 401", "HTTP GET 404", "HTTP POST 403",
    "Sudo Authentication Failure", "PAM Authentication Failure",
    "Sudo Command Executed", "Special Privileges Assigned",
    "Local Group Enumeration", "Security Group Enumeration",
    "user.account.lock", "DeleteTrail", "PutBucketPolicy",
    "CreateUser", "AssumeRole", "ConsoleLogin",
    "Driver Loaded", "Image Loaded", "Pipe Created", "Pipe Connected",
    "Process Tampering", "File Delete", "Object Handle Requested",
    "Explicit Credential Use", "Kerberos TGT Requested",
    "Process Execution (execve)", "Network Connection Initiated",
    "File Permission Change", "Privilege Change",
    "K8s RBAC Change", "K8s Secret Accessed", "K8s Exec into Pod",
    "K8s API Auth Failure", "SQL Login Failed", "SQL Access Denied",
    "MySQL Access Denied", "VPN Auth Failed", "AnyConnect Auth Failed",
    "SASL Auth Failure", "Email Rejected",
])

HIGH_RISK_COUNTRIES: frozenset = frozenset([
    "Russia", "China", "North Korea", "Iran", "Nigeria",
    "Romania", "Ukraine", "Brazil", "Vietnam", "Indonesia",
    "Pakistan", "Bangladesh",
])

FAILURE_EVENT_NAMES: frozenset = frozenset([
    "Failed Logon", "SSH Failed Password", "SSH Invalid User Attempt",
    "Account Lockout", "Sudo Authentication Failure", "PAM Authentication Failure",
    "Kerberos Pre-Auth Failed", "VPN Auth Failed", "AnyConnect Auth Failed",
    "SQL Login Failed", "MySQL Access Denied", "ACL Deny", "Firewall Block",
    "Proxy Auth Failure", "Proxy Request Denied", "K8s API Auth Failure",
    "SASL Auth Failure", "SSH Max Auth Tries Exceeded", "SSH Max Auth Exceeded",
])

SUCCESS_EVENT_NAMES: frozenset = frozenset([
    "Successful Logon", "SSH Accepted Password", "SSH Public Key Accepted",
    "User Login (local)", "Kerberos TGT Requested", "VPN Connect",
    "AnyConnect Session Started", "GlobalProtect Connected",
    "SQL Login Success", "Proxy Request Allowed", "Proxy Cache Hit",
    "Firewall Pass",
])

PRIVILEGE_EVENT_NAMES: frozenset = frozenset([
    "Special Privileges Assigned", "Sudo Command Executed",
    "Process Tampering", "Explicit Credential Use", "Privilege Change",
    "K8s RBAC Change", "Directory Service Object Access",
])


def get_ip_type(ip: str) -> str:
    """Classify IP address type."""
    if not ip:
        return "Unknown"
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return "Unknown"
        first = int(parts[0])
        second = int(parts[1])
        if first == 127:
            return "Loopback"
        if first == 10:
            return "Private"
        if first == 172 and 16 <= second <= 31:
            return "Private"
        if first == 192 and second == 168:
            return "Private"
        if first == 169 and second == 254:
            return "Link-Local"
        if first >= 224:
            return "Multicast"
        return "Public"
    except Exception:
        return "Unknown"


def is_failure_event(event: dict) -> bool:
    """Check if an event represents a failure/deny/block."""
    en = event.get("event_name", "") or ""
    if en in FAILURE_EVENT_NAMES:
        return True
    action = (event.get("action") or "").lower()
    if action in ("deny", "drop", "block", "reject", "failure", "failed", "error"):
        return True
    sc = event.get("status_code")
    if sc and isinstance(sc, int) and sc in (401, 403, 407, 500, 503):
        return True
    return False


def is_success_event(event: dict) -> bool:
    """Check if an event represents a success/allow."""
    en = event.get("event_name", "") or ""
    if en in SUCCESS_EVENT_NAMES:
        return True
    action = (event.get("action") or "").lower()
    if action in ("allow", "permit", "accept", "success", "pass"):
        return True
    sc = event.get("status_code")
    if sc and isinstance(sc, int) and 200 <= sc < 400:
        return True
    return False


def parse_ts(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse timestamp string to datetime."""
    if not ts_str:
        return None
    try:
        ts_str = ts_str.rstrip("Z")
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
        ):
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
    except Exception:
        pass
    return None


def _get_time_range(events: list) -> tuple:
    """Return (start_str, end_str) ISO timestamps."""
    timestamps = []
    for e in events:
        t = parse_ts(e.get("timestamp"))
        if t:
            timestamps.append(t)
    if not timestamps:
        return (None, None)
    return (min(timestamps).isoformat() + "Z", max(timestamps).isoformat() + "Z")


def _get_duration_hours(events: list) -> float:
    """Return duration of log coverage in hours."""
    start_str, end_str = _get_time_range(events)
    if not start_str or not end_str:
        return 0.0
    s = parse_ts(start_str)
    e = parse_ts(end_str)
    if not s or not e:
        return 0.0
    delta = e - s
    return round(delta.total_seconds() / 3600, 2)


def total_event_count(events: list) -> int:
    return len(events)


def unique_event_count(events: list) -> int:
    return len(set(e.get("event_name", "") for e in events if e.get("event_name")))


def unique_ip_count(events: list) -> int:
    return len(set(e.get("source_ip") for e in events if e.get("source_ip")))


def unique_username_count(events: list) -> int:
    return len(set(e.get("username") for e in events if e.get("username")))


def unique_hostname_count(events: list) -> int:
    return len(set(e.get("hostname") for e in events if e.get("hostname")))


def event_name_frequency(events: list) -> list:
    """Return event_name frequency table sorted by count desc."""
    total = len(events)
    by_name: dict = defaultdict(lambda: {
        "count": 0, "ips": set(), "users": set(),
        "timestamps": [], "category": None
    })
    for e in events:
        name = e.get("event_name") or "Unknown"
        by_name[name]["count"] += 1
        if e.get("source_ip"):
            by_name[name]["ips"].add(e["source_ip"])
        if e.get("username"):
            by_name[name]["users"].add(e["username"])
        if e.get("timestamp"):
            by_name[name]["timestamps"].append(e["timestamp"])
        if not by_name[name]["category"] and e.get("event_category"):
            by_name[name]["category"] = e["event_category"]

    result = []
    for name, data in by_name.items():
        ts_sorted = sorted(data["timestamps"]) if data["timestamps"] else []
        result.append({
            "event_name": name,
            "event_category": data["category"] or "Unknown",
            "count": data["count"],
            "percentage": round(data["count"] / total * 100, 2) if total else 0.0,
            "first_seen": ts_sorted[0] if ts_sorted else None,
            "last_seen": ts_sorted[-1] if ts_sorted else None,
            "unique_ips": len(data["ips"]),
            "unique_users": len(data["users"]),
            "risk_flag": name in RISK_EVENT_NAMES,
        })
    return sorted(result, key=lambda x: x["count"], reverse=True)


def _calc_risk_score_ip(failure_rate: float, failure_count: int,
                         event_names: list, country: str, ip_type: str,
                         unique_users: int) -> tuple:
    """Calculate IP risk score 0-100."""
    score = 0
    flags = []
    if failure_rate > 50:
        score += 30
        flags.append("High Failure Rate")
    if failure_count > 100:
        score += 20
        flags.append("High Failure Volume")
    if any(en in RISK_EVENT_NAMES for en in event_names):
        score += 15
        flags.append("Risk Events")
    if country and country in HIGH_RISK_COUNTRIES:
        score += 10
        flags.append(f"High-Risk Country ({country})")
    if "Security Log Cleared" in event_names:
        score += 15
        flags.append("Log Cleared")
    if any(x in str(event_names) for x in ("Mimikatz", "DCSync", "lsass")):
        score += 25
        flags.append("Credential Theft Indicator")
    if ip_type == "Public" and failure_count > 10:
        score += 10
        flags.append("External Attacker")
    if unique_users > 5:
        score += 5
        flags.append("Credential Stuffing Indicator")
    score = min(score, 100)
    if score >= 80:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"
    return score, level, flags


def ip_frequency_table(events: list) -> list:
    """Return per-IP frequency table with risk scoring."""
    total = len(events)
    by_ip: dict = defaultdict(lambda: {
        "count": 0, "event_names": set(), "users": set(),
        "timestamps": [], "bytes": 0, "failures": 0, "successes": 0
    })
    for e in events:
        ip = e.get("source_ip")
        if not ip:
            continue
        by_ip[ip]["count"] += 1
        if e.get("event_name"):
            by_ip[ip]["event_names"].add(e["event_name"])
        if e.get("username"):
            by_ip[ip]["users"].add(e["username"])
        if e.get("timestamp"):
            by_ip[ip]["timestamps"].append(e["timestamp"])
        if e.get("bytes_sent") and isinstance(e["bytes_sent"], int):
            by_ip[ip]["bytes"] += e["bytes_sent"]
        if is_failure_event(e):
            by_ip[ip]["failures"] += 1
        elif is_success_event(e):
            by_ip[ip]["successes"] += 1

    result = []
    for ip, data in by_ip.items():
        ts_sorted = sorted(data["timestamps"]) if data["timestamps"] else []
        count = data["count"]
        failure_count = data["failures"]
        failure_rate = round(failure_count / count * 100, 2) if count else 0.0
        ip_type = get_ip_type(ip)
        event_names_list = sorted(data["event_names"])
        unique_users = len(data["users"])
        score, level, flags = _calc_risk_score_ip(
            failure_rate, failure_count, event_names_list,
            None, ip_type, unique_users
        )
        result.append({
            "ip": ip,
            "count": count,
            "percentage": round(count / total * 100, 2) if total else 0.0,
            "first_seen": ts_sorted[0] if ts_sorted else None,
            "last_seen": ts_sorted[-1] if ts_sorted else None,
            "unique_events": len(data["event_names"]),
            "event_names": event_names_list,
            "unique_users": unique_users,
            "usernames": sorted(data["users"]),
            "country": None,
            "ip_type": ip_type,
            "bytes_sent": data["bytes"],
            "failure_count": failure_count,
            "success_count": data["successes"],
            "failure_rate": failure_rate,
            "risk_score": score,
            "risk_level": level,
            "threat_flags": flags,
        })
    return sorted(result, key=lambda x: x["count"], reverse=True)


def username_frequency_table(events: list) -> list:
    """Return per-username frequency table with risk scoring."""
    total = len(events)
    by_user: dict = defaultdict(lambda: {
        "count": 0, "event_names": {}, "ips": set(),
        "timestamps": [], "failures": 0, "successes": 0,
        "success_ts": [], "failure_ts": [], "locked": False,
        "privilege_events": []
    })
    for e in events:
        user = e.get("username")
        if not user:
            continue
        name = e.get("event_name") or "Unknown"
        by_user[user]["count"] += 1
        by_user[user]["event_names"][name] = by_user[user]["event_names"].get(name, 0) + 1
        if e.get("source_ip"):
            by_user[user]["ips"].add(e["source_ip"])
        if e.get("timestamp"):
            by_user[user]["timestamps"].append(e["timestamp"])
        if is_failure_event(e):
            by_user[user]["failures"] += 1
            if e.get("timestamp"):
                by_user[user]["failure_ts"].append(e["timestamp"])
        elif is_success_event(e):
            by_user[user]["successes"] += 1
            if e.get("timestamp"):
                by_user[user]["success_ts"].append(e["timestamp"])
        if name == "Account Lockout":
            by_user[user]["locked"] = True
        if name in PRIVILEGE_EVENT_NAMES:
            by_user[user]["privilege_events"].append(name)

    result = []
    for user, data in by_user.items():
        ts_sorted = sorted(data["timestamps"]) if data["timestamps"] else []
        count = data["count"]
        failures = data["failures"]
        successes = data["successes"]
        failure_rate = round(failures / count * 100, 2) if count else 0.0
        unique_ips = len(data["ips"])

        # Risk scoring
        score = 0
        flags = []
        if failure_rate > 60:
            score += 30
            flags.append("High Failure Rate")
        if failures > 50:
            score += 20
            flags.append("High Failure Volume")
        if data["locked"]:
            score += 15
            flags.append("Account Locked Out")
        if data["privilege_events"]:
            score += 25
            flags.append("Privilege Escalation Events")
        if unique_ips > 3:
            score += 10
            flags.append("Multiple Source IPs")
        if failures > 10 and successes > 0:
            score += 20
            flags.append("Successful After Failures")
        score = min(score, 100)
        if score >= 80:
            level = "CRITICAL"
        elif score >= 50:
            level = "HIGH"
        elif score >= 20:
            level = "MEDIUM"
        else:
            level = "LOW"

        event_breakdown = [{"event_name": k, "count": v} for k, v in data["event_names"].items()]
        event_breakdown.sort(key=lambda x: x["count"], reverse=True)

        result.append({
            "username": user,
            "count": count,
            "percentage": round(count / total * 100, 2) if total else 0.0,
            "first_seen": ts_sorted[0] if ts_sorted else None,
            "last_seen": ts_sorted[-1] if ts_sorted else None,
            "unique_event_names": len(data["event_names"]),
            "event_breakdown": event_breakdown,
            "unique_ips": unique_ips,
            "source_ips": sorted(data["ips"]),
            "failure_count": failures,
            "success_count": successes,
            "failure_rate": failure_rate,
            "last_success": sorted(data["success_ts"])[-1] if data["success_ts"] else None,
            "last_failure": sorted(data["failure_ts"])[-1] if data["failure_ts"] else None,
            "is_locked_out": data["locked"],
            "privilege_events": list(set(data["privilege_events"])),
            "risk_score": score,
            "risk_level": level,
            "threat_flags": flags,
        })
    return sorted(result, key=lambda x: x["count"], reverse=True)


def user_event_matrix(events: list) -> list:
    """Per-user event breakdown."""
    by_user: dict = defaultdict(lambda: defaultdict(lambda: {
        "count": 0, "ips": set(), "timestamps": [],
        "category": None
    }))
    for e in events:
        user = e.get("username")
        if not user:
            continue
        name = e.get("event_name") or "Unknown"
        by_user[user][name]["count"] += 1
        if e.get("source_ip"):
            by_user[user][name]["ips"].add(e["source_ip"])
        if e.get("timestamp"):
            by_user[user][name]["timestamps"].append(e["timestamp"])
        if not by_user[user][name]["category"] and e.get("event_category"):
            by_user[user][name]["category"] = e["event_category"]

    result = []
    for user, event_data in by_user.items():
        events_list = []
        for name, data in event_data.items():
            ts_sorted = sorted(data["timestamps"]) if data["timestamps"] else []
            risk_flag = name in RISK_EVENT_NAMES
            events_list.append({
                "event_name": name,
                "event_category": data["category"] or "Unknown",
                "count": data["count"],
                "first_seen": ts_sorted[0] if ts_sorted else None,
                "last_seen": ts_sorted[-1] if ts_sorted else None,
                "source_ips": sorted(data["ips"]),
                "risk_flag": risk_flag,
            })
        events_list.sort(key=lambda x: (-int(x["risk_flag"]), -x["count"]))
        total_events = sum(e["count"] for e in events_list)
        risk_events = sum(e["count"] for e in events_list if e["risk_flag"])
        risk_score = min(100, risk_events * 2 + len([e for e in events_list if e["risk_flag"]]) * 5)
        result.append({
            "username": user,
            "events": events_list,
            "total_events": total_events,
            "total_risk_events": risk_events,
            "risk_score": risk_score,
        })
    return sorted(result, key=lambda x: (-x["total_risk_events"], -x["total_events"]))


def ip_event_matrix(events: list) -> list:
    """Per-IP event breakdown."""
    by_ip: dict = defaultdict(lambda: defaultdict(lambda: {
        "count": 0, "users": set(), "timestamps": [],
        "category": None
    }))
    for e in events:
        ip = e.get("source_ip")
        if not ip:
            continue
        name = e.get("event_name") or "Unknown"
        by_ip[ip][name]["count"] += 1
        if e.get("username"):
            by_ip[ip][name]["users"].add(e["username"])
        if e.get("timestamp"):
            by_ip[ip][name]["timestamps"].append(e["timestamp"])
        if not by_ip[ip][name]["category"] and e.get("event_category"):
            by_ip[ip][name]["category"] = e["event_category"]

    result = []
    for ip, event_data in by_ip.items():
        events_list = []
        for name, data in event_data.items():
            ts_sorted = sorted(data["timestamps"]) if data["timestamps"] else []
            risk_flag = name in RISK_EVENT_NAMES
            events_list.append({
                "event_name": name,
                "event_category": data["category"] or "Unknown",
                "count": data["count"],
                "first_seen": ts_sorted[0] if ts_sorted else None,
                "last_seen": ts_sorted[-1] if ts_sorted else None,
                "usernames": sorted(data["users"]),
                "risk_flag": risk_flag,
            })
        events_list.sort(key=lambda x: (-int(x["risk_flag"]), -x["count"]))
        total_events = sum(e["count"] for e in events_list)
        risk_events = sum(e["count"] for e in events_list if e["risk_flag"])
        ip_type = get_ip_type(ip)
        failure_count = sum(e["count"] for e in events_list if e["event_name"] in FAILURE_EVENT_NAMES)
        failure_rate = round(failure_count / total_events * 100, 2) if total_events else 0.0
        unique_users_set = set()
        for ed in event_data.values():
            unique_users_set.update(ed["users"])
        score, level, flags = _calc_risk_score_ip(
            failure_rate, failure_count,
            [e["event_name"] for e in events_list],
            None, ip_type, len(unique_users_set)
        )
        result.append({
            "ip": ip,
            "ip_type": ip_type,
            "events": events_list,
            "total_events": total_events,
            "total_risk_events": risk_events,
            "risk_score": score,
            "risk_level": level,
            "threat_flags": flags,
        })
    return sorted(result, key=lambda x: -x["risk_score"])


def suspicious_pattern_catalogue(events: list, findings: list) -> list:
    """Detect and catalogue all suspicious behavioral patterns."""
    patterns = []
    pat_id_counter = [0]

    def next_id():
        pat_id_counter[0] += 1
        return f"TT-PAT-{pat_id_counter[0]:03d}"

    def make_timeline(evts: list, max_items: int = 10) -> list:
        timeline = []
        for e in evts[:max_items]:
            timeline.append({
                "timestamp": e.get("timestamp"),
                "event_name": e.get("event_name"),
                "ip": e.get("source_ip"),
                "username": e.get("username"),
            })
        return timeline

    def sample_event_data(e: dict) -> dict:
        return {
            "timestamp": e.get("timestamp"),
            "event_name": e.get("event_name"),
            "source_ip": e.get("source_ip"),
            "username": e.get("username"),
            "event_category": e.get("event_category"),
            "command_line": e.get("command_line"),
            "hostname": e.get("hostname"),
        }

    # --- BRUTE FORCE PATTERNS ---

    # SSH Brute Force: >10 SSH Failed Password from same IP in 1 hour
    ssh_fails: dict = defaultdict(list)
    for e in events:
        if e.get("event_name") == "SSH Failed Password" and e.get("source_ip"):
            ssh_fails[e["source_ip"]].append(e)
    for ip, evts in ssh_fails.items():
        if len(evts) >= 10:
            users = set(e.get("username") for e in evts if e.get("username"))
            # Check for subsequent success
            ssh_success = [e for e in events
                           if e.get("event_name") in ("SSH Accepted Password", "SSH Public Key Accepted")
                           and e.get("source_ip") == ip]
            ts_sorted = sorted(evts, key=lambda e: e.get("timestamp") or "")
            patterns.append({
                "pattern_id": next_id(),
                "pattern_name": "SSH Brute Force Detected",
                "pattern_type": "Brute Force",
                "severity": "HIGH",
                "mitre_tactic": "TA0006 Credential Access",
                "mitre_technique": "T1110.001 Password Guessing",
                "description": f"IP {ip} performed SSH brute force with {len(evts)} failed attempts targeting {len(users)} usernames.",
                "evidence_summary": (
                    f"IP {ip} made {len(evts)} failed SSH login attempts targeting "
                    f"{len(users)} usernames. "
                    + (f"Subsequent success detected as '{next(iter(e.get('username','?') for e in ssh_success))}'." if ssh_success else "No success detected.")
                ),
                "affected_ips": [ip],
                "affected_users": sorted(users),
                "event_names": ["SSH Failed Password", "SSH Invalid User Attempt"] + (["SSH Accepted Password"] if ssh_success else []),
                "sample_log_lines": [e.get("raw", "") for e in ts_sorted[:5]],
                "sample_event_data": sample_event_data(ts_sorted[0]),
                "occurrence_count": len(evts),
                "first_seen": ts_sorted[0].get("timestamp") if ts_sorted else None,
                "last_seen": ts_sorted[-1].get("timestamp") if ts_sorted else None,
                "timeline": make_timeline(ts_sorted + ssh_success),
            })

    # HTTP Login Brute Force: >20 401/403 to /login or /admin from same IP
    http_bf: dict = defaultdict(list)
    for e in events:
        sc = e.get("status_code")
        url = e.get("url") or ""
        if sc in (401, 403) and any(p in url for p in ("/login", "/admin", "/wp-login", "/signin")):
            ip = e.get("source_ip")
            if ip:
                http_bf[ip].append(e)
    for ip, evts in http_bf.items():
        if len(evts) >= 20:
            ts_sorted = sorted(evts, key=lambda e: e.get("timestamp") or "")
            patterns.append({
                "pattern_id": next_id(),
                "pattern_name": "HTTP Login Brute Force",
                "pattern_type": "Brute Force",
                "severity": "HIGH",
                "mitre_tactic": "TA0006 Credential Access",
                "mitre_technique": "T1110.003 Password Spraying",
                "description": f"IP {ip} made {len(evts)} HTTP 401/403 attempts against login endpoints.",
                "evidence_summary": f"IP {ip} generated {len(evts)} failed HTTP authentication responses to login/admin paths.",
                "affected_ips": [ip],
                "affected_users": sorted(set(e.get("username") for e in evts if e.get("username"))),
                "event_names": [f"HTTP {e.get('method','GET')} {e.get('status_code')}" for e in evts[:5]],
                "sample_log_lines": [e.get("raw", "") for e in ts_sorted[:5]],
                "sample_event_data": sample_event_data(ts_sorted[0]),
                "occurrence_count": len(evts),
                "first_seen": ts_sorted[0].get("timestamp") if ts_sorted else None,
                "last_seen": ts_sorted[-1].get("timestamp") if ts_sorted else None,
                "timeline": make_timeline(ts_sorted),
            })

    # Windows Logon Brute Force: >10 Failed Logon (EventID 4625) from same IP
    win_bf: dict = defaultdict(list)
    for e in events:
        if e.get("event_name") == "Failed Logon" and e.get("source_ip"):
            win_bf[e["source_ip"]].append(e)
    for ip, evts in win_bf.items():
        if len(evts) >= 10:
            ts_sorted = sorted(evts, key=lambda e: e.get("timestamp") or "")
            users = set(e.get("username") for e in evts if e.get("username"))
            patterns.append({
                "pattern_id": next_id(),
                "pattern_name": "Windows Logon Brute Force",
                "pattern_type": "Brute Force",
                "severity": "HIGH",
                "mitre_tactic": "TA0006 Credential Access",
                "mitre_technique": "T1110 Brute Force",
                "description": f"IP {ip} had {len(evts)} failed Windows logon attempts targeting {len(users)} accounts.",
                "evidence_summary": f"EventID 4625 (Failed Logon) repeated {len(evts)} times from {ip}.",
                "affected_ips": [ip],
                "affected_users": sorted(users),
                "event_names": ["Failed Logon"],
                "sample_log_lines": [e.get("raw", "") for e in ts_sorted[:5]],
                "sample_event_data": sample_event_data(ts_sorted[0]),
                "occurrence_count": len(evts),
                "first_seen": ts_sorted[0].get("timestamp") if ts_sorted else None,
                "last_seen": ts_sorted[-1].get("timestamp") if ts_sorted else None,
                "timeline": make_timeline(ts_sorted),
            })

    # Credential Stuffing: >5 failed logins for >5 different usernames from same IP
    cred_stuff: dict = defaultdict(lambda: defaultdict(list))
    for e in events:
        if is_failure_event(e) and e.get("source_ip") and e.get("username"):
            cred_stuff[e["source_ip"]][e["username"]].append(e)
    for ip, user_data in cred_stuff.items():
        if len(user_data) >= 5:
            all_evts = [e for evts in user_data.values() for e in evts]
            ts_sorted = sorted(all_evts, key=lambda e: e.get("timestamp") or "")
            patterns.append({
                "pattern_id": next_id(),
                "pattern_name": "Credential Stuffing Attack",
                "pattern_type": "Brute Force",
                "severity": "HIGH",
                "mitre_tactic": "TA0006 Credential Access",
                "mitre_technique": "T1110.004 Credential Stuffing",
                "description": f"IP {ip} attempted authentication against {len(user_data)} different usernames — likely credential stuffing.",
                "evidence_summary": f"IP {ip} failed authentication for {len(user_data)} distinct usernames: {', '.join(list(user_data.keys())[:5])}{'...' if len(user_data)>5 else ''}",
                "affected_ips": [ip],
                "affected_users": sorted(user_data.keys()),
                "event_names": list(set(e.get("event_name") for e in all_evts if e.get("event_name"))),
                "sample_log_lines": [e.get("raw", "") for e in ts_sorted[:5]],
                "sample_event_data": sample_event_data(ts_sorted[0]),
                "occurrence_count": len(all_evts),
                "first_seen": ts_sorted[0].get("timestamp") if ts_sorted else None,
                "last_seen": ts_sorted[-1].get("timestamp") if ts_sorted else None,
                "timeline": make_timeline(ts_sorted),
            })

    # Successful Brute Force: failures followed by success from same IP
    success_after_fail: dict = {}
    for e in events:
        if is_success_event(e) and e.get("source_ip"):
            ip = e["source_ip"]
            fail_count = sum(1 for fe in events if is_failure_event(fe) and fe.get("source_ip") == ip)
            if fail_count >= 5:
                success_after_fail[ip] = {"success_event": e, "fail_count": fail_count}
    for ip, data in success_after_fail.items():
        se = data["success_event"]
        patterns.append({
            "pattern_id": next_id(),
            "pattern_name": "Successful Brute Force",
            "pattern_type": "Brute Force",
            "severity": "CRITICAL",
            "mitre_tactic": "TA0006 Credential Access",
            "mitre_technique": "T1110.001 Password Guessing",
            "description": f"IP {ip} had {data['fail_count']} auth failures followed by a successful login as '{se.get('username', '?')}'.",
            "evidence_summary": f"Brute force succeeded: {data['fail_count']} failures then login as '{se.get('username', '?')}' at {se.get('timestamp', '?')}",
            "affected_ips": [ip],
            "affected_users": [se.get("username")] if se.get("username") else [],
            "event_names": ["Authentication Failure", se.get("event_name", "Successful Login")],
            "sample_log_lines": [se.get("raw", "")],
            "sample_event_data": sample_event_data(se),
            "occurrence_count": data["fail_count"] + 1,
            "first_seen": se.get("timestamp"),
            "last_seen": se.get("timestamp"),
            "timeline": make_timeline([se]),
        })

    # --- RECONNAISSANCE PATTERNS ---

    # Web Scanner Detected
    scanner_patterns = [
        "sqlmap", "nikto", "nmap", "masscan", "burpsuite", "ZAP",
        "acunetix", "nessus", "openvas", "dirbuster", "gobuster",
        "wfuzz", "hydra", "medusa", "nuclei", "ffuf", "feroxbuster",
        "w3af", "skipfish", "arachni"
    ]
    scanner_events = [e for e in events
                      if e.get("user_agent") and
                      any(p.lower() in e["user_agent"].lower() for p in scanner_patterns)]
    if scanner_events:
        ips = set(e.get("source_ip") for e in scanner_events if e.get("source_ip"))
        patterns.append({
            "pattern_id": next_id(),
            "pattern_name": "Web Scanner Activity Detected",
            "pattern_type": "Reconnaissance",
            "severity": "MEDIUM",
            "mitre_tactic": "TA0043 Reconnaissance",
            "mitre_technique": "T1595 Active Scanning",
            "description": f"Security scanner user agents detected from {len(ips)} IP(s): {len(scanner_events)} requests.",
            "evidence_summary": f"Scanner user agents: {', '.join(set(e.get('user_agent','') for e in scanner_events[:3]))}",
            "affected_ips": sorted(ips),
            "affected_users": [],
            "event_names": list(set(e.get("event_name") for e in scanner_events if e.get("event_name"))),
            "sample_log_lines": [e.get("raw", "") for e in scanner_events[:5]],
            "sample_event_data": sample_event_data(scanner_events[0]),
            "occurrence_count": len(scanner_events),
            "first_seen": min((e.get("timestamp","") for e in scanner_events if e.get("timestamp")), default=None),
            "last_seen": max((e.get("timestamp","") for e in scanner_events if e.get("timestamp")), default=None),
            "timeline": make_timeline(scanner_events),
        })

    # Directory Enumeration: >50 HTTP 404 from same IP
    http_404: dict = defaultdict(list)
    for e in events:
        if e.get("status_code") == 404 and e.get("source_ip"):
            http_404[e["source_ip"]].append(e)
    for ip, evts in http_404.items():
        if len(evts) >= 50:
            ts_sorted = sorted(evts, key=lambda e: e.get("timestamp") or "")
            patterns.append({
                "pattern_id": next_id(),
                "pattern_name": "Directory/Path Enumeration",
                "pattern_type": "Reconnaissance",
                "severity": "MEDIUM",
                "mitre_tactic": "TA0043 Reconnaissance",
                "mitre_technique": "T1083 File and Directory Discovery",
                "description": f"IP {ip} generated {len(evts)} HTTP 404 responses — likely directory/path enumeration.",
                "evidence_summary": f"IP {ip} requested {len(evts)} non-existent URLs resulting in 404 responses.",
                "affected_ips": [ip],
                "affected_users": [],
                "event_names": ["HTTP GET 404", "HTTP POST 404"],
                "sample_log_lines": [e.get("raw", "") for e in ts_sorted[:5]],
                "sample_event_data": sample_event_data(ts_sorted[0]),
                "occurrence_count": len(evts),
                "first_seen": ts_sorted[0].get("timestamp") if ts_sorted else None,
                "last_seen": ts_sorted[-1].get("timestamp") if ts_sorted else None,
                "timeline": make_timeline(ts_sorted),
            })

    # --- INJECTION ATTACK PATTERNS ---
    sqli_patterns = ["UNION SELECT", "UNION%20SELECT", "information_schema",
                     "sleep(", "benchmark(", "xp_cmdshell", "' OR ", "1=1"]
    sqli_events = [e for e in events
                   if e.get("url") and any(p.lower() in e["url"].lower() for p in sqli_patterns)]
    if sqli_events:
        ips = set(e.get("source_ip") for e in sqli_events if e.get("source_ip"))
        patterns.append({
            "pattern_id": next_id(),
            "pattern_name": "SQL Injection Attempts Detected",
            "pattern_type": "Reconnaissance",
            "severity": "HIGH",
            "mitre_tactic": "TA0001 Initial Access",
            "mitre_technique": "T1190 Exploit Public-Facing Application",
            "description": f"SQL injection patterns detected in {len(sqli_events)} requests from {len(ips)} IP(s).",
            "evidence_summary": f"SQL injection payloads found in request URLs from: {', '.join(list(ips)[:3])}",
            "affected_ips": sorted(ips),
            "affected_users": [],
            "event_names": list(set(e.get("event_name") for e in sqli_events if e.get("event_name"))),
            "sample_log_lines": [e.get("raw", "") for e in sqli_events[:5]],
            "sample_event_data": sample_event_data(sqli_events[0]),
            "occurrence_count": len(sqli_events),
            "first_seen": min((e.get("timestamp","") for e in sqli_events if e.get("timestamp")), default=None),
            "last_seen": max((e.get("timestamp","") for e in sqli_events if e.get("timestamp")), default=None),
            "timeline": make_timeline(sqli_events),
        })

    # LFI/Path Traversal
    lfi_patterns = ["../", "..%2F", "/etc/passwd", "/etc/shadow",
                    "php://filter", "php://input", "/proc/self"]
    lfi_events = [e for e in events
                  if e.get("url") and any(p.lower() in e["url"].lower() for p in lfi_patterns)]
    if lfi_events:
        ips = set(e.get("source_ip") for e in lfi_events if e.get("source_ip"))
        patterns.append({
            "pattern_id": next_id(),
            "pattern_name": "Local File Inclusion (LFI) Attempts",
            "pattern_type": "Reconnaissance",
            "severity": "HIGH",
            "mitre_tactic": "TA0001 Initial Access",
            "mitre_technique": "T1190 Exploit Public-Facing Application",
            "description": f"Path traversal/LFI patterns detected in {len(lfi_events)} requests.",
            "evidence_summary": f"LFI payloads targeting local file access from {', '.join(list(ips)[:3])}",
            "affected_ips": sorted(ips),
            "affected_users": [],
            "event_names": list(set(e.get("event_name") for e in lfi_events if e.get("event_name"))),
            "sample_log_lines": [e.get("raw", "") for e in lfi_events[:5]],
            "sample_event_data": sample_event_data(lfi_events[0]),
            "occurrence_count": len(lfi_events),
            "first_seen": min((e.get("timestamp","") for e in lfi_events if e.get("timestamp")), default=None),
            "last_seen": max((e.get("timestamp","") for e in lfi_events if e.get("timestamp")), default=None),
            "timeline": make_timeline(lfi_events),
        })

    # --- DEFENSE EVASION PATTERNS ---

    # Security Log Cleared
    log_cleared = [e for e in events if e.get("event_name") in ("Security Log Cleared",)]
    if log_cleared:
        ips = set(e.get("source_ip") for e in log_cleared if e.get("source_ip"))
        users = set(e.get("username") for e in log_cleared if e.get("username"))
        patterns.append({
            "pattern_id": next_id(),
            "pattern_name": "Security Event Log Cleared",
            "pattern_type": "Defense Evasion",
            "severity": "CRITICAL",
            "mitre_tactic": "TA0005 Defense Evasion",
            "mitre_technique": "T1070.001 Clear Windows Event Logs",
            "description": f"Windows Security event log was cleared {len(log_cleared)} time(s) — strong indicator of attacker covering tracks.",
            "evidence_summary": f"EventID 1102 (log cleared) detected at {log_cleared[0].get('timestamp','?')}",
            "affected_ips": sorted(ips),
            "affected_users": sorted(users),
            "event_names": ["Security Log Cleared"],
            "sample_log_lines": [e.get("raw", "") for e in log_cleared[:5]],
            "sample_event_data": sample_event_data(log_cleared[0]),
            "occurrence_count": len(log_cleared),
            "first_seen": log_cleared[0].get("timestamp"),
            "last_seen": log_cleared[-1].get("timestamp"),
            "timeline": make_timeline(log_cleared),
        })

    # PowerShell Encoded Commands
    ps_encoded = [e for e in events
                  if e.get("command_line") and
                  any(p.lower() in e["command_line"].lower()
                      for p in ["-encodedcommand", "-enc ", " -e ", "iex(", "frombase64string"])]
    if ps_encoded:
        ips = set(e.get("source_ip") for e in ps_encoded if e.get("source_ip"))
        users = set(e.get("username") for e in ps_encoded if e.get("username"))
        patterns.append({
            "pattern_id": next_id(),
            "pattern_name": "PowerShell Encoded Command Execution",
            "pattern_type": "Defense Evasion",
            "severity": "HIGH",
            "mitre_tactic": "TA0005 Defense Evasion",
            "mitre_technique": "T1059.001 PowerShell",
            "description": f"PowerShell encoded/obfuscated commands detected in {len(ps_encoded)} events.",
            "evidence_summary": f"Encoded PowerShell execution: {ps_encoded[0].get('command_line','')[:100]}",
            "affected_ips": sorted(ips),
            "affected_users": sorted(users),
            "event_names": list(set(e.get("event_name") for e in ps_encoded if e.get("event_name"))),
            "sample_log_lines": [e.get("raw", "") for e in ps_encoded[:5]],
            "sample_event_data": sample_event_data(ps_encoded[0]),
            "occurrence_count": len(ps_encoded),
            "first_seen": min((e.get("timestamp","") for e in ps_encoded if e.get("timestamp")), default=None),
            "last_seen": max((e.get("timestamp","") for e in ps_encoded if e.get("timestamp")), default=None),
            "timeline": make_timeline(ps_encoded),
        })

    # --- PERSISTENCE PATTERNS ---
    sched_tasks = [e for e in events if e.get("event_name") in (
        "Scheduled Task Created", "Scheduled Task Modified", "Cron Job Executed")]
    if sched_tasks:
        users = set(e.get("username") for e in sched_tasks if e.get("username"))
        patterns.append({
            "pattern_id": next_id(),
            "pattern_name": "Scheduled Task / Cron Persistence",
            "pattern_type": "Persistence",
            "severity": "MEDIUM",
            "mitre_tactic": "TA0003 Persistence",
            "mitre_technique": "T1053.005 Scheduled Task/Job",
            "description": f"Scheduled task or cron job creation detected in {len(sched_tasks)} events.",
            "evidence_summary": f"{len(sched_tasks)} scheduled task/cron events observed.",
            "affected_ips": sorted(set(e.get("source_ip") for e in sched_tasks if e.get("source_ip"))),
            "affected_users": sorted(users),
            "event_names": list(set(e.get("event_name") for e in sched_tasks if e.get("event_name"))),
            "sample_log_lines": [e.get("raw", "") for e in sched_tasks[:5]],
            "sample_event_data": sample_event_data(sched_tasks[0]),
            "occurrence_count": len(sched_tasks),
            "first_seen": min((e.get("timestamp","") for e in sched_tasks if e.get("timestamp")), default=None),
            "last_seen": max((e.get("timestamp","") for e in sched_tasks if e.get("timestamp")), default=None),
            "timeline": make_timeline(sched_tasks),
        })

    # New Services
    new_services = [e for e in events if e.get("event_name") == "New Service Installed"]
    if new_services:
        patterns.append({
            "pattern_id": next_id(),
            "pattern_name": "New Service Installed",
            "pattern_type": "Persistence",
            "severity": "HIGH",
            "mitre_tactic": "TA0003 Persistence",
            "mitre_technique": "T1543.003 Windows Service",
            "description": f"{len(new_services)} new service installation(s) detected.",
            "evidence_summary": f"Services installed: {', '.join(e.get('process_name','unknown') for e in new_services[:3])}",
            "affected_ips": sorted(set(e.get("source_ip") for e in new_services if e.get("source_ip"))),
            "affected_users": sorted(set(e.get("username") for e in new_services if e.get("username"))),
            "event_names": ["New Service Installed"],
            "sample_log_lines": [e.get("raw", "") for e in new_services[:5]],
            "sample_event_data": sample_event_data(new_services[0]),
            "occurrence_count": len(new_services),
            "first_seen": min((e.get("timestamp","") for e in new_services if e.get("timestamp")), default=None),
            "last_seen": max((e.get("timestamp","") for e in new_services if e.get("timestamp")), default=None),
            "timeline": make_timeline(new_services),
        })

    # --- CREDENTIAL THEFT PATTERNS ---
    lsass_events = [e for e in events
                    if e.get("event_name") in ("ProcessAccess", "LSASS Access") and
                    "lsass" in str(e.get("command_line", "") or e.get("raw", "")).lower()]
    if lsass_events:
        patterns.append({
            "pattern_id": next_id(),
            "pattern_name": "LSASS Memory Access (Credential Dumping)",
            "pattern_type": "Credential Theft",
            "severity": "CRITICAL",
            "mitre_tactic": "TA0006 Credential Access",
            "mitre_technique": "T1003.001 LSASS Memory",
            "description": "LSASS process memory access detected — possible credential dumping.",
            "evidence_summary": f"{len(lsass_events)} LSASS access event(s) observed.",
            "affected_ips": sorted(set(e.get("source_ip") for e in lsass_events if e.get("source_ip"))),
            "affected_users": sorted(set(e.get("username") for e in lsass_events if e.get("username"))),
            "event_names": list(set(e.get("event_name") for e in lsass_events if e.get("event_name"))),
            "sample_log_lines": [e.get("raw", "") for e in lsass_events[:5]],
            "sample_event_data": sample_event_data(lsass_events[0]),
            "occurrence_count": len(lsass_events),
            "first_seen": min((e.get("timestamp","") for e in lsass_events if e.get("timestamp")), default=None),
            "last_seen": max((e.get("timestamp","") for e in lsass_events if e.get("timestamp")), default=None),
            "timeline": make_timeline(lsass_events),
        })

    # Mimikatz
    mimikatz_events = [e for e in events
                       if e.get("command_line") and
                       any(m in (e["command_line"] or "").lower()
                           for m in ["mimikatz", "sekurlsa", "lsadump", "privilege::debug"])]
    if mimikatz_events:
        patterns.append({
            "pattern_id": next_id(),
            "pattern_name": "Mimikatz Credential Theft Tool",
            "pattern_type": "Credential Theft",
            "severity": "CRITICAL",
            "mitre_tactic": "TA0006 Credential Access",
            "mitre_technique": "T1003.001 LSASS Memory",
            "description": f"Mimikatz credential theft tool detected in {len(mimikatz_events)} event(s).",
            "evidence_summary": f"Mimikatz indicators: {mimikatz_events[0].get('command_line','')[:100]}",
            "affected_ips": sorted(set(e.get("source_ip") for e in mimikatz_events if e.get("source_ip"))),
            "affected_users": sorted(set(e.get("username") for e in mimikatz_events if e.get("username"))),
            "event_names": ["Process Creation", "PowerShell Script Block"],
            "sample_log_lines": [e.get("raw", "") for e in mimikatz_events[:5]],
            "sample_event_data": sample_event_data(mimikatz_events[0]),
            "occurrence_count": len(mimikatz_events),
            "first_seen": min((e.get("timestamp","") for e in mimikatz_events if e.get("timestamp")), default=None),
            "last_seen": max((e.get("timestamp","") for e in mimikatz_events if e.get("timestamp")), default=None),
            "timeline": make_timeline(mimikatz_events),
        })

    # --- C2 BEACONING ---
    # Periodic beacon: same source IP with stddev < 30s of inter-request times
    ip_ts: dict = defaultdict(list)
    for e in events:
        ip = e.get("source_ip")
        ts = parse_ts(e.get("timestamp"))
        if ip and ts:
            ip_ts[ip].append(ts)
    for ip, timestamps in ip_ts.items():
        if len(timestamps) < 10:
            continue
        timestamps_sorted = sorted(timestamps)
        gaps = [(timestamps_sorted[i+1] - timestamps_sorted[i]).total_seconds()
                for i in range(len(timestamps_sorted)-1)]
        if not gaps:
            continue
        try:
            std = statistics.stdev(gaps)
            avg = statistics.mean(gaps)
            if std < 30 and avg < 300 and len(timestamps) >= 10:
                beacon_evts = [e for e in events if e.get("source_ip") == ip]
                patterns.append({
                    "pattern_id": next_id(),
                    "pattern_name": "C2 Beaconing Pattern Detected",
                    "pattern_type": "C2 Beaconing",
                    "severity": "HIGH",
                    "mitre_tactic": "TA0011 Command and Control",
                    "mitre_technique": "T1071.001 Web Protocols",
                    "description": f"IP {ip} making requests at regular intervals (avg={avg:.1f}s, stddev={std:.1f}s) — possible C2 beacon.",
                    "evidence_summary": f"Regular interval requests: avg {avg:.1f}s between requests, stddev {std:.1f}s over {len(timestamps)} events.",
                    "affected_ips": [ip],
                    "affected_users": sorted(set(e.get("username") for e in beacon_evts if e.get("username"))),
                    "event_names": list(set(e.get("event_name") for e in beacon_evts if e.get("event_name"))),
                    "sample_log_lines": [e.get("raw", "") for e in beacon_evts[:5]],
                    "sample_event_data": sample_event_data(beacon_evts[0]) if beacon_evts else {},
                    "occurrence_count": len(timestamps),
                    "first_seen": timestamps_sorted[0].isoformat() if timestamps_sorted else None,
                    "last_seen": timestamps_sorted[-1].isoformat() if timestamps_sorted else None,
                    "timeline": make_timeline(beacon_evts),
                })
        except statistics.StatisticsError:
            pass

    # DNS Tunneling: high TXT query volume or long subdomain labels
    dns_txt = [e for e in events if e.get("event_name") == "DNS TXT Query"]
    dns_txt_by_client: dict = defaultdict(list)
    for e in dns_txt:
        if e.get("source_ip"):
            dns_txt_by_client[e["source_ip"]].append(e)
    for ip, evts in dns_txt_by_client.items():
        if len(evts) >= 20:
            patterns.append({
                "pattern_id": next_id(),
                "pattern_name": "DNS Tunneling (TXT Query Volume)",
                "pattern_type": "C2 Beaconing",
                "severity": "HIGH",
                "mitre_tactic": "TA0011 Command and Control",
                "mitre_technique": "T1071.004 DNS",
                "description": f"IP {ip} made {len(evts)} DNS TXT queries — potential DNS tunneling.",
                "evidence_summary": f"{len(evts)} TXT queries from {ip}.",
                "affected_ips": [ip],
                "affected_users": [],
                "event_names": ["DNS TXT Query"],
                "sample_log_lines": [e.get("raw", "") for e in evts[:5]],
                "sample_event_data": sample_event_data(evts[0]),
                "occurrence_count": len(evts),
                "first_seen": min((e.get("timestamp","") for e in evts if e.get("timestamp")), default=None),
                "last_seen": max((e.get("timestamp","") for e in evts if e.get("timestamp")), default=None),
                "timeline": make_timeline(evts),
            })

    # --- DATA EXFILTRATION PATTERNS ---
    # Large outbound: single IP sending >100MB
    outbound_bytes: dict = defaultdict(lambda: {"total": 0, "events": []})
    for e in events:
        if e.get("bytes_sent") and isinstance(e["bytes_sent"], int) and e.get("source_ip"):
            outbound_bytes[e["source_ip"]]["total"] += e["bytes_sent"]
            outbound_bytes[e["source_ip"]]["events"].append(e)
    for ip, data in outbound_bytes.items():
        if data["total"] >= 100 * 1024 * 1024:  # 100MB
            size_mb = data["total"] / (1024 * 1024)
            evts = data["events"]
            patterns.append({
                "pattern_id": next_id(),
                "pattern_name": "Large Outbound Data Transfer",
                "pattern_type": "Data Exfiltration",
                "severity": "HIGH",
                "mitre_tactic": "TA0010 Exfiltration",
                "mitre_technique": "T1048 Exfiltration Over Alternative Protocol",
                "description": f"IP {ip} sent {size_mb:.1f}MB of data — possible data exfiltration.",
                "evidence_summary": f"Total outbound bytes from {ip}: {size_mb:.1f}MB across {len(evts)} events.",
                "affected_ips": [ip],
                "affected_users": sorted(set(e.get("username") for e in evts if e.get("username"))),
                "event_names": list(set(e.get("event_name") for e in evts if e.get("event_name"))),
                "sample_log_lines": [e.get("raw", "") for e in evts[:5]],
                "sample_event_data": sample_event_data(evts[0]),
                "occurrence_count": len(evts),
                "first_seen": min((e.get("timestamp","") for e in evts if e.get("timestamp")), default=None),
                "last_seen": max((e.get("timestamp","") for e in evts if e.get("timestamp")), default=None),
                "timeline": make_timeline(evts),
            })

    # --- ANOMALOUS AUTH ---
    # After-hours logon: successful auth between 23:00-06:00
    after_hours = []
    for e in events:
        if is_success_event(e) and e.get("timestamp"):
            ts = parse_ts(e["timestamp"])
            if ts and (ts.hour >= 23 or ts.hour < 6):
                after_hours.append(e)
    if after_hours:
        users = set(e.get("username") for e in after_hours if e.get("username"))
        patterns.append({
            "pattern_id": next_id(),
            "pattern_name": "Logon Outside Business Hours",
            "pattern_type": "Anomalous Authentication",
            "severity": "MEDIUM",
            "mitre_tactic": "TA0001 Initial Access",
            "mitre_technique": "T1078 Valid Accounts",
            "description": f"{len(after_hours)} successful logon(s) detected between 23:00-06:00.",
            "evidence_summary": f"After-hours logins for accounts: {', '.join(list(users)[:5])}",
            "affected_ips": sorted(set(e.get("source_ip") for e in after_hours if e.get("source_ip"))),
            "affected_users": sorted(users),
            "event_names": list(set(e.get("event_name") for e in after_hours if e.get("event_name"))),
            "sample_log_lines": [e.get("raw", "") for e in after_hours[:5]],
            "sample_event_data": sample_event_data(after_hours[0]),
            "occurrence_count": len(after_hours),
            "first_seen": min((e.get("timestamp","") for e in after_hours if e.get("timestamp")), default=None),
            "last_seen": max((e.get("timestamp","") for e in after_hours if e.get("timestamp")), default=None),
            "timeline": make_timeline(after_hours),
        })

    # Service Account Interactive Logon
    svc_interactive = [e for e in events
                       if e.get("username") and e.get("event_name") in ("Successful Logon", "User Login (local)")
                       and any(p in (e["username"] or "").lower() for p in ("svc_", "service_", "_svc", "$"))]
    if svc_interactive:
        patterns.append({
            "pattern_id": next_id(),
            "pattern_name": "Service Account Interactive Logon",
            "pattern_type": "Anomalous Authentication",
            "severity": "MEDIUM",
            "mitre_tactic": "TA0001 Initial Access",
            "mitre_technique": "T1078.003 Local Accounts",
            "description": f"Service account(s) performing interactive logon: {', '.join(set(e.get('username','') for e in svc_interactive))}",
            "evidence_summary": f"Service accounts used interactively: {', '.join(set(e.get('username','') for e in svc_interactive[:5]))}",
            "affected_ips": sorted(set(e.get("source_ip") for e in svc_interactive if e.get("source_ip"))),
            "affected_users": sorted(set(e.get("username") for e in svc_interactive if e.get("username"))),
            "event_names": ["Successful Logon"],
            "sample_log_lines": [e.get("raw", "") for e in svc_interactive[:5]],
            "sample_event_data": sample_event_data(svc_interactive[0]),
            "occurrence_count": len(svc_interactive),
            "first_seen": min((e.get("timestamp","") for e in svc_interactive if e.get("timestamp")), default=None),
            "last_seen": max((e.get("timestamp","") for e in svc_interactive if e.get("timestamp")), default=None),
            "timeline": make_timeline(svc_interactive),
        })

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    patterns.sort(key=lambda p: sev_order.get(p.get("severity", "LOW"), 3))
    return patterns


def build_event_matrix(events: list) -> dict:
    """Master function: builds complete event matrix."""
    start_ts, end_ts = _get_time_range(events)
    total = len(events)
    high_risk = sum(1 for e in events if e.get("event_name") in RISK_EVENT_NAMES)
    return {
        "overview": {
            "total_events": total,
            "unique_event_types": unique_event_count(events),
            "unique_ips": unique_ip_count(events),
            "unique_usernames": unique_username_count(events),
            "unique_hostnames": unique_hostname_count(events),
            "time_range_start": start_ts,
            "time_range_end": end_ts,
            "duration_hours": _get_duration_hours(events),
            "high_risk_event_count": high_risk,
            "high_risk_event_pct": round(high_risk / total * 100, 2) if total else 0.0,
        },
        "event_frequency": event_name_frequency(events),
        "ip_table": ip_frequency_table(events),
        "username_table": username_frequency_table(events),
        "user_event_matrix": user_event_matrix(events),
        "ip_event_matrix": ip_event_matrix(events),
    }
