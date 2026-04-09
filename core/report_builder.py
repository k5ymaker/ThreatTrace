"""ThreatTrace Report Builder — NIST SP 800-61 Rev.2 aligned HTML + JSON reports."""
from __future__ import annotations

import base64
import io
import json
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
SEVERITY_COLORS: Dict[str, str] = {
    "CRITICAL": "#c0392b", "HIGH": "#e67e22",
    "MEDIUM": "#d4ac0d", "LOW": "#27ae60",
    "INFO": "#2980b9", "INFORMATIONAL": "#2980b9",
}
SEVERITY_BG: Dict[str, str] = {
    "CRITICAL": "#fdecea", "HIGH": "#fef3e2",
    "MEDIUM": "#fefce6", "LOW": "#eafaf1",
    "INFO": "#eaf4fc", "INFORMATIONAL": "#eaf4fc",
}
HTTP_STATUS_COLORS: Dict[int, str] = {
    2: "#27ae60", 3: "#2980b9", 4: "#e67e22", 5: "#c0392b",
}
TLP_COLORS: Dict[str, str] = {
    "TLP:RED": "#c0392b", "TLP:AMBER": "#e67e22",
    "TLP:GREEN": "#27ae60", "TLP:WHITE": "#7f8c8d", "TLP:CLEAR": "#7f8c8d",
}
UA_CATEGORY_COLORS: Dict[str, str] = {
    "Security Scanner": "#c0392b", "Bot/Crawler": "#e67e22",
    "Automated Tool": "#d4ac0d", "Mobile Browser": "#27ae60",
    "Web Browser": "#2980b9", "Unknown": "#7f8c8d",
}

# ---------------------------------------------------------------------------
# Chart helpers (matplotlib optional)
# ---------------------------------------------------------------------------

def _try_matplotlib():
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        return plt
    except ImportError:
        return None


def _fig_to_b64(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=110)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode()


def _chart_severity_donut(sev: Dict[str, int]) -> Optional[str]:
    plt = _try_matplotlib()
    if not plt:
        return None
    labels, sizes, colors = [], [], []
    for s, c in sev.items():
        if c > 0:
            labels.append(f"{s} ({c})")
            sizes.append(c)
            colors.append(SEVERITY_COLORS.get(s, "#95a5a6"))
    if not sizes:
        return None
    fig, ax = plt.subplots(figsize=(4, 4))
    ax.pie(sizes, colors=colors, startangle=90,
           wedgeprops=dict(width=0.5), labels=None)
    ax.legend(labels, loc="lower center", bbox_to_anchor=(0.5, -0.22),
              fontsize=8, frameon=False, ncol=2)
    ax.set_title("Findings by Severity", fontsize=10, pad=6)
    b64 = _fig_to_b64(fig)
    plt.close(fig)
    return b64


def _chart_top_ips(ip_rows: List[Dict], count_key: str = "requests") -> Optional[str]:
    plt = _try_matplotlib()
    if not plt or not ip_rows:
        return None
    top = ip_rows[:15]
    ips = [r.get("ip", "?") for r in top]
    counts = [r.get(count_key, 0) for r in top]
    risks = [r.get("risk_score", r.get("threat_flag", False)) for r in top]
    colors = ["#c0392b" if (isinstance(r, (int, float)) and r >= 70) or r is True
              else "#e67e22" if (isinstance(r, (int, float)) and r >= 40)
              else "#2980b9" for r in risks]
    fig, ax = plt.subplots(figsize=(7, max(3, len(top) * 0.4)))
    ax.barh(ips[::-1], counts[::-1], color=colors[::-1])
    ax.set_xlabel("Events", fontsize=9)
    ax.set_title("Top Source IPs", fontsize=10)
    ax.tick_params(labelsize=8)
    b64 = _fig_to_b64(fig)
    plt.close(fig)
    return b64


def _chart_timeline(hourly: List[Dict]) -> Optional[str]:
    plt = _try_matplotlib()
    if not plt or len(hourly) < 2:
        return None
    items = sorted(hourly, key=lambda x: x.get("hour", x.get("period", "")))
    if len(items) > 72:
        items = items[-72:]
    labels = [x.get("hour", x.get("period", "")) for x in items]
    values = [x.get("count", 0) for x in items]
    fig, ax = plt.subplots(figsize=(11, 3))
    ax.fill_between(range(len(values)), values, alpha=0.25, color="#2980b9")
    ax.plot(range(len(values)), values, color="#2980b9", linewidth=1.5)
    step = max(1, len(labels) // 10)
    ax.set_xticks(range(0, len(labels), step))
    ax.set_xticklabels([labels[i] for i in range(0, len(labels), step)],
                       rotation=25, ha="right", fontsize=7)
    ax.set_ylabel("Events/hr", fontsize=9)
    ax.set_title("Hourly Event Timeline", fontsize=10)
    b64 = _fig_to_b64(fig)
    plt.close(fig)
    return b64


def _chart_ua_categories(ua_data: List[Dict]) -> Optional[str]:
    plt = _try_matplotlib()
    if not plt or not ua_data:
        return None
    cat_counts: Counter = Counter()
    for ua in ua_data:
        cat_counts[ua.get("category", ua.get("cat", "Unknown"))] += ua.get("count", 1)
    if not cat_counts:
        return None
    labels = list(cat_counts.keys())
    sizes = list(cat_counts.values())
    colors = [UA_CATEGORY_COLORS.get(l, "#95a5a6") for l in labels]
    fig, ax = plt.subplots(figsize=(4.5, 3.5))
    ax.pie(sizes, colors=colors, startangle=90, labels=None,
           wedgeprops=dict(width=0.55))
    legend_labels = [f"{l} ({v})" for l, v in zip(labels, sizes)]
    ax.legend(legend_labels, loc="lower center", bbox_to_anchor=(0.5, -0.28),
              fontsize=7.5, frameon=False, ncol=2)
    ax.set_title("User Agent Categories", fontsize=10)
    b64 = _fig_to_b64(fig)
    plt.close(fig)
    return b64


def _chart_http_status(status_data: List[Dict]) -> Optional[str]:
    plt = _try_matplotlib()
    if not plt or not status_data:
        return None
    codes = [str(r["status_code"]) for r in status_data[:12]]
    counts = [r["count"] for r in status_data[:12]]
    colors = [HTTP_STATUS_COLORS.get(r["status_code"] // 100, "#95a5a6")
              for r in status_data[:12]]
    fig, ax = plt.subplots(figsize=(7, 3))
    ax.bar(codes, counts, color=colors, edgecolor="#fff", linewidth=0.5)
    ax.set_xlabel("HTTP Status Code", fontsize=9)
    ax.set_ylabel("Count", fontsize=9)
    ax.set_title("HTTP Status Code Distribution", fontsize=10)
    ax.tick_params(labelsize=8)
    b64 = _fig_to_b64(fig)
    plt.close(fig)
    return b64


def _chart_auth_failures_users(fail_data: List[Dict]) -> Optional[str]:
    plt = _try_matplotlib()
    if not plt or not fail_data:
        return None
    top = fail_data[:12]
    users = [r.get("username", "?") for r in top]
    failures = [r.get("failures", 0) for r in top]
    fig, ax = plt.subplots(figsize=(6, max(3, len(top) * 0.38)))
    ax.barh(users[::-1], failures[::-1], color="#c0392b")
    ax.set_xlabel("Failure Count", fontsize=9)
    ax.set_title("Top Auth Failures by User", fontsize=10)
    ax.tick_params(labelsize=8)
    b64 = _fig_to_b64(fig)
    plt.close(fig)
    return b64


# ---------------------------------------------------------------------------
# Direct-from-events extractors
# (fallback when correlator data is absent / field names differ)
# ---------------------------------------------------------------------------

def _ip_field(event: Dict) -> Optional[str]:
    """Return source IP regardless of field name variant."""
    return (event.get("src_ip") or event.get("source_ip") or
            event.get("ip") or event.get("client_ip") or
            event.get("remote_addr") or event.get("host"))


def _ua_field(event: Dict) -> Optional[str]:
    return (event.get("user_agent") or event.get("ua") or
            event.get("agent") or event.get("http_user_agent"))


def _extract_ip_summary(events: List[Dict], n: int = 20) -> List[Dict]:
    """Build per-IP stats directly from events (handles any field naming)."""
    by_ip: Dict[str, Any] = defaultdict(lambda: {
        "total": 0, "failures": 0, "successes": 0,
        "users": set(), "event_names": Counter(),
        "ts": [], "uas": set(),
    })
    for e in events:
        ip = _ip_field(e)
        if not ip:
            continue
        d = by_ip[ip]
        d["total"] += 1
        en = e.get("event_name") or e.get("event_category") or ""
        d["event_names"][en] += 1
        ec = e.get("event_category", "")
        if any(x in (en + ec).lower() for x in ("fail", "deny", "block", "reject", "error", "invalid")):
            d["failures"] += 1
        elif any(x in (en + ec).lower() for x in ("accept", "success", "allow", "permit", "pass")):
            d["successes"] += 1
        if e.get("username"):
            d["users"].add(e["username"])
        if e.get("timestamp"):
            d["ts"].append(e["timestamp"])
        ua = _ua_field(e)
        if ua:
            d["uas"].add(ua)

    result = []
    for ip, d in sorted(by_ip.items(), key=lambda x: x[1]["total"], reverse=True)[:n]:
        ts = sorted(d["ts"])
        top_events = ", ".join(
            f"{en}({c})" for en, c in d["event_names"].most_common(4) if en
        )
        result.append({
            "ip": ip,
            "total_events": d["total"],
            "failures": d["failures"],
            "successes": d["successes"],
            "unique_users": len(d["users"]),
            "users": sorted(d["users"])[:5],
            "top_events": top_events,
            "first_seen": ts[0] if ts else "",
            "last_seen": ts[-1] if ts else "",
            "user_agents": sorted(d["uas"])[:5],
        })
    return result


def _extract_user_summary(events: List[Dict], n: int = 30) -> List[Dict]:
    """Build per-username stats directly from events."""
    by_user: Dict[str, Any] = defaultdict(lambda: {
        "total": 0, "failures": 0, "successes": 0,
        "ips": set(), "event_names": Counter(), "ts": [],
    })
    for e in events:
        user = e.get("username") or e.get("user") or e.get("account")
        if not user:
            continue
        d = by_user[user]
        d["total"] += 1
        en = e.get("event_name") or e.get("event_category") or ""
        d["event_names"][en] += 1
        if any(x in en.lower() for x in ("fail", "deny", "block", "reject", "error", "invalid")):
            d["failures"] += 1
        elif any(x in en.lower() for x in ("accept", "success", "allow", "permit", "pass")):
            d["successes"] += 1
        ip = _ip_field(e)
        if ip:
            d["ips"].add(ip)
        if e.get("timestamp"):
            d["ts"].append(e["timestamp"])

    result = []
    for user, d in sorted(by_user.items(), key=lambda x: x[1]["total"], reverse=True)[:n]:
        ts = sorted(d["ts"])
        top_events = d["event_names"].most_common(5)
        total = d["total"]
        fail_rate = round(d["failures"] / total * 100, 1) if total else 0.0
        result.append({
            "username": user,
            "total_events": total,
            "failures": d["failures"],
            "successes": d["successes"],
            "failure_rate": fail_rate,
            "unique_ips": len(d["ips"]),
            "source_ips": sorted(d["ips"])[:5],
            "top_events": top_events,
            "first_seen": ts[0] if ts else "",
            "last_seen": ts[-1] if ts else "",
            "risk": "HIGH" if fail_rate > 50 and d["failures"] > 5
                    else "MEDIUM" if fail_rate > 20 or d["failures"] > 20
                    else "LOW",
        })
    return result


def _extract_ua_summary(events: List[Dict]) -> List[Dict]:
    """Build user agent summary directly from events."""
    SCANNER_KEYWORDS = [
        "sqlmap", "nikto", "nmap", "masscan", "zap", "burp", "acunetix",
        "nessus", "openvas", "dirbuster", "gobuster", "wfuzz", "hydra",
        "medusa", "nuclei", "ffuf", "feroxbuster", "metasploit", "w3af",
    ]
    BOT_KEYWORDS = ["bot", "crawler", "spider", "googlebot", "bingbot", "slurp"]
    BROWSER_KEYWORDS = ["mozilla", "chrome", "safari", "firefox", "edge", "msie"]
    AUTO_PREFIXES = ("python-", "go-http", "curl/", "wget/", "libwww", "java/", "httpie")

    counts: Counter = Counter()
    for e in events:
        ua = _ua_field(e)
        if ua:
            counts[ua] += 1

    result = []
    for ua, count in counts.most_common():
        ua_l = ua.lower()
        if any(k in ua_l for k in SCANNER_KEYWORDS):
            cat = "Security Scanner"
        elif any(k in ua_l for k in BOT_KEYWORDS):
            cat = "Bot/Crawler"
        elif ua_l.startswith(AUTO_PREFIXES):
            cat = "Automated Tool"
        elif any(k in ua_l for k in ["android", "iphone", "ipad", "mobile"]):
            cat = "Mobile Browser"
        elif any(k in ua_l for k in BROWSER_KEYWORDS):
            cat = "Web Browser"
        else:
            cat = "Unknown"
        result.append({
            "ua": ua[:120],
            "count": count,
            "category": cat,
            "threat_flag": cat == "Security Scanner",
        })
    return result


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def _esc(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _badge(text: str, color: str, bg: str = "") -> str:
    bg_style = f"background:{bg};" if bg else f"background:{color}22;"
    return (f'<span style="{bg_style}color:{color};border:1px solid {color}80;'
            f'padding:2px 9px;border-radius:11px;font-size:0.76em;font-weight:700;">'
            f"{_esc(str(text))}</span>")


def _sev_badge(sev: str) -> str:
    s = sev.upper()
    return _badge(s, SEVERITY_COLORS.get(s, "#555"), SEVERITY_BG.get(s, "#f9f9f9"))


def _risk_badge(risk: str) -> str:
    color = SEVERITY_COLORS.get(risk.upper(), "#7f8c8d")
    return _badge(risk, color)


def _ua_badge(cat: str) -> str:
    color = UA_CATEGORY_COLORS.get(cat, "#7f8c8d")
    return _badge(cat, color)


def _tlp_badge(tlp: str) -> str:
    color = TLP_COLORS.get(tlp.upper(), "#7f8c8d")
    return _badge(tlp.upper(), "#fff", color)


def _threat_row(threat: bool) -> str:
    return ' style="background:#fff5f5;"' if threat else ""


def _inline_img(b64: Optional[str], alt: str = "") -> str:
    if not b64:
        return ""
    return (f'<img src="data:image/png;base64,{b64}" alt="{_esc(alt)}" '
            f'class="report-chart"/>')


def _table(headers: List[str], rows: List[List[str]], id_: str = "",
           compact: bool = False) -> str:
    th = "".join(f"<th>{h}</th>" for h in headers)
    body = ""
    for row in rows:
        if isinstance(row, dict) and "__tr_style__" in row:
            style = row.pop("__tr_style__", "")
            cells = "".join(f"<td>{c}</td>" for c in row.values())
            body += f'<tr style="{style}">{cells}</tr>\n'
        else:
            cells = "".join(f"<td>{c}</td>" for c in row)
            body += f"<tr>{cells}</tr>\n"
    id_attr = f' id="{id_}"' if id_ else ""
    compact_cls = " compact" if compact else ""
    return (f'<div class="table-wrap"><table{id_attr} class="tt-table{compact_cls}">'
            f"<thead><tr>{th}</tr></thead><tbody>{body}</tbody></table></div>")


def _collapsible(label: str, content: str, open_: bool = False,
                 badge_text: str = "") -> str:
    attr = "open" if open_ else ""
    badge_html = (f' <span style="background:#2c3e50;color:#fff;padding:1px 8px;'
                  f'border-radius:10px;font-size:0.75em;">{_esc(badge_text)}</span>'
                  if badge_text else "")
    return (f'<details {attr} class="collapsible"><summary>{_esc(label)}'
            f'{badge_html}</summary>'
            f'<div class="collapsible-body">{content}</div></details>')


def _stat_grid(stats: List[tuple]) -> str:
    """stats = list of (value, label, color?)"""
    boxes = ""
    for item in stats:
        val, label = item[0], item[1]
        color = item[2] if len(item) > 2 else "#2c3e50"
        boxes += (f'<div class="stat-box"><div class="stat-value" style="color:{color};">'
                  f'{_esc(str(val))}</div>'
                  f'<div class="stat-label">{_esc(label)}</div></div>')
    return f'<div class="stat-grid">{boxes}</div>'


def _section_card(id_: str, title: str, content: str, icon: str = "") -> str:
    return (f'<div class="section-card" id="{id_}">'
            f'<div class="section-header">{icon} {title}</div>'
            f'<div class="section-body">{content}</div></div>')


def _no_data(msg: str = "No data available for this log type.") -> str:
    return f'<p class="no-data">{_esc(msg)}</p>'


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f3f7;color:#2c3e50;font-size:14px;line-height:1.55}
.cover-page{background:linear-gradient(135deg,#1a1a2e 0%,#16213e 60%,#0f3460 100%);color:#fff;padding:70px 56px 52px;min-height:300px}
.cover-logo{font-size:2.6em;font-weight:900;letter-spacing:2px;color:#00d4ff;text-transform:uppercase}
.cover-sub{font-size:1em;color:#a0aec0;margin-top:5px}
.cover-title{font-size:1.9em;font-weight:700;margin-top:36px;color:#e2e8f0;border-left:5px solid #00d4ff;padding-left:16px}
.cover-meta{margin-top:36px;color:#a0aec0;font-size:0.9em;line-height:1.9}
.cover-meta strong{color:#e2e8f0}
.cover-risk{display:inline-block;margin-top:24px;padding:9px 26px;border-radius:6px;font-size:1.25em;font-weight:800;text-transform:uppercase;letter-spacing:1px}
.nav-toc{background:#fff;margin:20px 36px;padding:20px 28px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.06)}
.nav-toc h2{font-size:1em;margin-bottom:10px;color:#2c3e50}
.nav-toc ol{padding-left:18px;column-count:2;column-gap:30px}
.nav-toc li{margin:3px 0}
.nav-toc a{color:#2980b9;text-decoration:none;font-size:.9em}
.nav-toc a:hover{text-decoration:underline}
.content{margin:0 36px 40px}
.section-card{background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.06);margin-bottom:22px;overflow:hidden}
.section-header{background:#1a1a2e;color:#00d4ff;padding:13px 22px;font-size:1em;font-weight:700;letter-spacing:.4px}
.section-body{padding:18px 22px}
.tt-table{width:100%;border-collapse:collapse;font-size:.86em}
.tt-table th{background:#2c3e50;color:#fff;padding:9px 11px;text-align:left;font-weight:600;white-space:nowrap}
.tt-table td{padding:7px 11px;border-bottom:1px solid #ecf0f1;vertical-align:top;word-break:break-word;max-width:300px}
.tt-table tr:hover td{background:#f8f9fa}
.tt-table.compact td,.tt-table.compact th{padding:5px 9px;font-size:.82em}
.table-wrap{overflow-x:auto;margin:10px 0}
.finding-block{border-left:4px solid #bdc3c7;margin:10px 0;padding:11px 15px;background:#fafafa;border-radius:0 6px 6px 0}
.finding-block.CRITICAL{border-color:#c0392b;background:#fdecea}
.finding-block.HIGH{border-color:#e67e22;background:#fef3e2}
.finding-block.MEDIUM{border-color:#d4ac0d;background:#fefce6}
.finding-block.LOW{border-color:#27ae60;background:#eafaf1}
.finding-block.INFO{border-color:#2980b9;background:#eaf4fc}
.finding-title{font-weight:700;font-size:.93em}
.finding-meta{color:#7f8c8d;font-size:.8em;margin-top:3px}
.finding-desc{font-size:.87em;margin-top:5px}
.finding-evidence{font-size:.78em;color:#555;margin-top:4px}
.collapsible{margin:8px 0}
.collapsible summary{cursor:pointer;padding:8px 13px;background:#f0f3f7;border-radius:6px;font-weight:600;font-size:.9em;color:#2c3e50;list-style:none}
.collapsible summary::-webkit-details-marker{display:none}
.collapsible summary::before{content:"▶ ";font-size:.75em}
details[open]>summary::before{content:"▼ "}
.collapsible summary:hover{background:#e8ecf1}
.collapsible-body{padding:10px 13px 6px}
.report-chart{max-width:100%;height:auto;border-radius:6px;margin:8px 0;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.charts-row{display:flex;flex-wrap:wrap;gap:14px;margin:8px 0}
.chart-box{flex:1;min-width:260px}
.stat-grid{display:flex;flex-wrap:wrap;gap:10px;margin:10px 0}
.stat-box{flex:1;min-width:120px;background:#f0f3f7;border-radius:8px;padding:12px 14px;text-align:center}
.stat-value{font-size:1.85em;font-weight:900;color:#2c3e50}
.stat-label{font-size:.76em;color:#7f8c8d;margin-top:2px}
.narrative-box{background:#eaf4fc;border-left:4px solid #2980b9;padding:13px 17px;border-radius:0 6px 6px 0;font-size:.93em;line-height:1.7;margin:10px 0}
.ioc-tag{display:inline-block;background:#2c3e50;color:#fff;padding:1px 7px;border-radius:9px;font-size:.76em;margin:2px;font-family:monospace}
.mitre-tag{display:inline-block;background:#8e44ad;color:#fff;padding:1px 7px;border-radius:9px;font-size:.76em;margin:2px;font-family:monospace}
.pattern-cards{display:flex;flex-wrap:wrap;gap:10px;margin:8px 0}
.pattern-card{flex:1;min-width:200px;max-width:320px;border:1px solid #dde3ec;border-radius:8px;padding:13px 15px;background:#fff}
.pattern-card.triggered{border-color:#e67e22;background:#fff9f0}
.pc-title{font-weight:700;font-size:.88em;color:#1a1a2e}
.pc-count{font-size:2em;font-weight:900;color:#2980b9;line-height:1.15}
.pc-evidence{font-size:.78em;color:#7f8c8d;margin-top:5px}
.threat-row{background:#fff5f5!important}
h3{font-size:.97em;color:#1a1a2e;margin:14px 0 7px;font-weight:700}
h4{font-size:.88em;color:#555;margin:10px 0 5px;font-weight:600}
p{margin:5px 0;line-height:1.65}
ul{padding-left:18px}
li{margin:3px 0;line-height:1.6}
code{background:#f4f6f9;padding:1px 5px;border-radius:3px;font-family:monospace;font-size:.87em}
.no-data{color:#aaa;font-style:italic;padding:8px 0;font-size:.88em}
.info-pill{display:inline-block;background:#eaf4fc;color:#2980b9;border:1px solid #aed6f1;padding:2px 9px;border-radius:10px;font-size:.78em;margin:2px;font-family:monospace}
footer{text-align:center;padding:18px;color:#bdc3c7;font-size:.8em;border-top:1px solid #ecf0f1;margin-top:30px}
"""


def _html_shell(title: str, body: str) -> str:
    return (f"<!DOCTYPE html>\n<html lang='en'>\n<head>\n"
            f"<meta charset='UTF-8'/>\n"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'/>\n"
            f"<title>{_esc(title)}</title>\n"
            f"<style>{_CSS}</style>\n</head>\n<body>\n{body}\n</body>\n</html>")


# ---------------------------------------------------------------------------
# Section: Cover
# ---------------------------------------------------------------------------

def _s0_cover(meta: Dict) -> str:
    risk = meta.get("overall_risk", "INFORMATIONAL")
    rc = SEVERITY_COLORS.get(risk, "#7f8c8d")
    tlp = meta.get("tlp", "TLP:WHITE")
    tc = TLP_COLORS.get(tlp.upper(), "#7f8c8d")
    return f"""
<div class="cover-page">
  <div class="cover-logo">&#x1F6E1; ThreatTrace</div>
  <div class="cover-sub">Cybersecurity Log Intelligence Platform</div>
  <div class="cover-title">Incident Analysis Report</div>
  <div class="cover-meta">
    <strong>Analysis ID:</strong> {_esc(meta.get('analysis_id','N/A'))}<br/>
    <strong>Log Type:</strong> {_esc(meta.get('log_type','Unknown'))}<br/>
    <strong>File / Path:</strong> <code style="color:#a0aec0">{_esc(str(meta.get('file_path') or 'N/A'))}</code><br/>
    <strong>Total Events:</strong> {meta.get('total_events',0):,}<br/>
    <strong>Analyst:</strong> {_esc(meta.get('analyst','N/A'))}<br/>
    <strong>Generated:</strong> {_esc(meta.get('generated_at',''))}<br/>
    <strong>Classification:</strong>
    <span style="background:{tc};color:#fff;padding:2px 10px;border-radius:4px;font-weight:700;">
      {_esc(tlp.upper())}</span>
  </div>
  <div class="cover-risk" style="background:{rc};color:#fff;">Overall Risk: {_esc(risk)}</div>
</div>"""


def _toc() -> str:
    items = [
        ("sec1", "1. Executive Summary"),
        ("sec2", "2. Source Intelligence — IPs &amp; User Agents"),
        ("sec3", "3. User &amp; Authentication Analysis"),
        ("sec4", "4. Web &amp; HTTP Analysis"),
        ("sec5", "5. Network &amp; Protocol Analysis"),
        ("sec6", "6. Event &amp; Temporal Analysis"),
        ("sec7", "7. Detection Findings (YARA / Sigma)"),
        ("sec8", "8. NIST Phases: Containment &amp; Post-Incident"),
        ("sec9", "9. Technical Appendix"),
    ]
    li = "".join(f'<li><a href="#{i}">{l}</a></li>' for i, l in items)
    return (f'<div class="nav-toc"><h2>Table of Contents</h2>'
            f'<ol>{li}</ol></div>')


# ---------------------------------------------------------------------------
# Section 1: Executive Summary
# ---------------------------------------------------------------------------

def _s1_exec_summary(analysis: Dict, meta: Dict) -> str:
    sev = analysis.get("findings_by_severity", {})
    risk = analysis.get("overall_risk", "INFORMATIONAL")
    findings = analysis.get("findings", [])
    patterns = analysis.get("patterns", [])
    events = analysis.get("_events", [])
    total = analysis.get("total_events", 0)
    log_type = analysis.get("log_type", "unknown")

    crit = sev.get("CRITICAL", 0)
    high = sev.get("HIGH", 0)
    med = sev.get("MEDIUM", 0)
    low = sev.get("LOW", 0)

    triggered_patterns = [p for p in patterns if p.get("detected")]
    mitre_set = {
        f.get("mitre_technique") or f.get("technique_id", "")
        for f in findings
        if f.get("mitre_technique") or f.get("technique_id")
    }

    # Narrative
    parts = [f"ThreatTrace analysed <strong>{total:,}</strong> events from "
             f"<strong>{_esc(log_type)}</strong> logs."]
    if crit or high:
        parts.append(f"<strong>{crit} CRITICAL</strong> and "
                     f"<strong>{high} HIGH</strong> severity findings require immediate attention.")
    if triggered_patterns:
        names = ", ".join(f"<em>{p.get('pattern','')}</em>"
                         for p in triggered_patterns[:5])
        if len(triggered_patterns) > 5:
            names += f" and {len(triggered_patterns)-5} more"
        parts.append(f"Behavioural patterns detected: {names}.")
    if risk in ("CRITICAL", "HIGH"):
        parts.append("Immediate incident response is recommended — see Section 8.")
    elif risk == "MEDIUM":
        parts.append("Elevated risk indicators found. Review HIGH/MEDIUM findings promptly.")
    else:
        parts.append("No high-severity threats detected. Continue routine monitoring.")

    narrative = '<div class="narrative-box"><p>' + " ".join(parts) + "</p></div>"

    # Detection provenance block
    det_tier      = meta.get("detection_tier", "")
    det_structure = meta.get("detection_structure", "")
    det_signals   = meta.get("detection_signals", [])
    det_ruleset   = meta.get("detection_ruleset", {})
    det_html = ""
    if det_tier:
        tier_badge_colors = {
            "CONFIRMED": ("#1e8449", "#eafaf1"),
            "LIKELY":    ("#27ae60", "#f0faf3"),
            "POSSIBLE":  ("#b7950b", "#fefce6"),
            "FALLBACK":  ("#7f8c8d", "#f2f3f4"),
        }
        bc, bg = tier_badge_colors.get(det_tier, ("#7f8c8d", "#f2f3f4"))
        sigma_cats = ", ".join(det_ruleset.get("sigma", []))
        yara_cats  = ", ".join(det_ruleset.get("yara",  []))
        signals_html = ""
        if det_signals:
            sig_items = "".join(f"<li>{_esc(s)}</li>" for s in det_signals[:8])
            signals_html = (
                f'<details style="margin-top:.5em;">'
                f'<summary style="cursor:pointer;font-size:.82em;color:#566573;">'
                f'Detection signals ({len(det_signals)})</summary>'
                f'<ul style="font-size:.8em;margin:.4em 0 0 1em;color:#566573;">'
                f'{sig_items}</ul></details>'
            )
        det_html = (
            f'<div style="margin:1em 0;padding:.8em 1em;border-radius:6px;'
            f'background:#f8f9fa;border-left:4px solid {bc};">'
            f'<strong style="color:#2c3e50;">Log Type Detection</strong> &nbsp;'
            f'<span style="background:{bc};color:#fff;padding:.15em .5em;'
            f'border-radius:4px;font-size:.8em;font-weight:700;">{_esc(det_tier)}</span>'
            f'<table style="margin-top:.5em;font-size:.83em;border-collapse:collapse;">'
            f'<tr><td style="color:#7f8c8d;padding-right:1.5em;">Detected type</td>'
            f'<td><code>{_esc(log_type)}</code></td></tr>'
            f'<tr><td style="color:#7f8c8d;padding-right:1.5em;">Format structure</td>'
            f'<td><code>{_esc(det_structure)}</code></td></tr>'
            f'<tr><td style="color:#7f8c8d;padding-right:1.5em;">Sigma rule categories</td>'
            f'<td><code>{_esc(sigma_cats) or "generic"}</code></td></tr>'
            f'<tr><td style="color:#7f8c8d;padding-right:1.5em;">YARA rule categories</td>'
            f'<td><code>{_esc(yara_cats) or "generic"}</code></td></tr>'
            f'</table>'
            f'{signals_html}'
            f'</div>'
        )

    stats = _stat_grid([
        (crit, "Critical", SEVERITY_COLORS["CRITICAL"]),
        (high, "High", SEVERITY_COLORS["HIGH"]),
        (med, "Medium", SEVERITY_COLORS["MEDIUM"]),
        (low, "Low", SEVERITY_COLORS["LOW"]),
        (len(findings), "Total Findings", "#2c3e50"),
        (len(triggered_patterns), "Patterns Triggered", "#8e44ad"),
        (len(mitre_set), "MITRE Techniques", "#1a5276"),
        (analysis.get("yara_rules_run", 0), "YARA Rules Run", "#1e8449"),
        (analysis.get("sigma_rules_run", 0), "Sigma Rules Run", "#1a5276"),
    ])

    # Charts
    donut = _chart_severity_donut(sev)
    tl_data = (analysis.get("correlations", {}).get("timeline") or {}).get("hourly", [])
    if not tl_data:
        # build from events
        hrly: Counter = Counter()
        for e in events:
            ts = e.get("timestamp", "")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    hrly[dt.strftime("%Y-%m-%dT%H:00")] += 1
                except ValueError:
                    pass
        tl_data = [{"hour": h, "count": c} for h, c in sorted(hrly.items())]
    timeline = _chart_timeline(tl_data)

    charts = '<div class="charts-row">'
    if donut:
        charts += f'<div class="chart-box">{_inline_img(donut, "Severity Donut")}</div>'
    if timeline:
        charts += f'<div class="chart-box">{_inline_img(timeline, "Event Timeline")}</div>'
    charts += "</div>"

    # IOC table
    ioc_rows = []
    ip_sum = _extract_ip_summary(events, n=15) if events else []
    for e in ip_sum[:10]:
        score = _ip_risk_score(e)
        if score >= 25:
            ioc_rows.append([
                f'<code>{_esc(e["ip"])}</code>',
                str(e["total_events"]),
                str(e["failures"]),
                _risk_badge("HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"),
            ])
    # Threat user agents from events
    ua_sum = _extract_ua_summary(events) if events else []
    threat_ua_rows = []
    for u in ua_sum:
        if u.get("threat_flag"):
            threat_ua_rows.append([
                f'<code style="font-size:.8em;color:#c0392b">{_esc(u.get("ua",""))}</code>',
                str(u.get("count", 0)),
                _ua_badge(u.get("category", "Security Scanner")),
            ])

    ioc_html = ""
    if ioc_rows:
        ioc_html = "<h3>Key IP Indicators</h3>"
        ioc_html += _table(["IP", "Events", "Failures", "Risk"], ioc_rows)
    if threat_ua_rows:
        ioc_html += "<h3>&#x26A0; Threat / Scanner User Agents Detected</h3>"
        ioc_html += _table(["User Agent", "Occurrences", "Category"], threat_ua_rows)

    # MITRE table
    mitre_rows = []
    seen: set = set()
    for f in findings:
        tid = f.get("mitre_technique") or f.get("technique_id", "")
        if tid and tid not in seen:
            seen.add(tid)
            mitre_rows.append([
                f'<span class="mitre-tag">{_esc(tid)}</span>',
                _esc(f.get("rule_name") or f.get("name", "")),
                _sev_badge(f.get("severity", "INFO")),
            ])
    mitre_html = ""
    if mitre_rows:
        mitre_html = "<h3>MITRE ATT&amp;CK Techniques Observed</h3>"
        mitre_html += _table(["Technique", "Rule", "Severity"], mitre_rows)

    body = narrative + det_html + stats + charts + ioc_html + mitre_html
    return _section_card("sec1", "1. Executive Summary", body, "&#x1F4CB;")


# ---------------------------------------------------------------------------
# Section 2: Source Intelligence
# ---------------------------------------------------------------------------

def _ip_risk_score(e: Dict) -> int:
    score = 0
    total = e.get("total_events", 0)
    fails = e.get("failures", 0)
    if total > 0:
        rate = fails / total
        if rate > 0.7:
            score += 35
        elif rate > 0.4:
            score += 20
    if fails > 50:
        score += 20
    elif fails > 10:
        score += 10
    if e.get("threat_flag"):
        score += 30
    return min(score, 100)


def _s2_source_intel(analysis: Dict) -> str:
    events = analysis.get("_events", [])
    corr = analysis.get("correlations", {})

    # --- 2.1 Top Source IPs ---
    # Prefer correlator data (source_ip field) but fall back to direct extraction
    corr_ips = corr.get("top_ips_by_requests", [])
    if not corr_ips:
        corr_ips = _extract_ip_summary(events, n=25)
        # normalise key names
        for r in corr_ips:
            r.setdefault("requests", r.get("total_events", 0))
    else:
        # merge in failure/success from events
        direct = {d["ip"]: d for d in _extract_ip_summary(events, n=100)}
        for r in corr_ips:
            ip = r.get("ip", "")
            if ip in direct:
                r.setdefault("failures", direct[ip].get("failures", 0))
                r.setdefault("successes", direct[ip].get("successes", 0))
                r.setdefault("top_events", direct[ip].get("top_events", ""))
                r.setdefault("users", direct[ip].get("users", []))
                r.setdefault("user_agents", direct[ip].get("user_agents", []))

    ip_chart = _chart_top_ips(corr_ips)

    ip_rows = []
    for r in corr_ips[:30]:
        ip = r.get("ip", "")
        total = r.get("requests", r.get("total_events", 0))
        fails = r.get("failures", 0)
        succs = r.get("successes", 0)
        score = _ip_risk_score({"total_events": total, "failures": fails,
                                 "threat_flag": r.get("threat_flag", False)})
        top_ev = r.get("top_events", "")
        users_list = r.get("targeted_usernames", r.get("users", []))
        users_str = ", ".join(f'<code>{_esc(u)}</code>' for u in users_list[:4])
        first = r.get("first_seen", "")
        last = r.get("last_seen", "")
        pct = r.get("percentage", "")
        pct_str = f"{pct}%" if pct != "" else ""

        tr_cls = ' class="threat-row"' if score >= 60 else ""
        risk = _risk_badge("HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW" if score >= 20 else "INFO")
        ua_list = r.get("user_agents", [])
        ua_cell = "<br>".join(
            f'<code style="font-size:.73em">{_esc(ua[:90])}</code>'
            for ua in ua_list[:3]
        ) if ua_list else '<span style="color:#bbb">—</span>'
        ip_rows.append([
            f'<code>{_esc(ip)}</code>',
            str(total),
            pct_str,
            f'<span style="color:#c0392b">{fails}</span>' if fails > 0 else "0",
            str(succs),
            risk,
            _esc(top_ev[:60]) if top_ev else "",
            users_str,
            ua_cell,
            f'<span style="font-size:.78em;color:#888">{_esc(str(first)[:16])}</span>',
            f'<span style="font-size:.78em;color:#888">{_esc(str(last)[:16])}</span>',
        ])

    ip_table_html = ""
    if ip_chart:
        ip_table_html += f'<div class="chart-box">{_inline_img(ip_chart, "Top IPs")}</div>'
    if ip_rows:
        ip_table_html += _table(
            ["IP", "Events", "%", "Failures", "Successes", "Risk",
             "Top Events", "Users Targeted", "User Agents", "First Seen", "Last Seen"],
            ip_rows,
        )
    else:
        ip_table_html += _no_data()

    # All unique IPs count
    all_ips_data = corr.get("unique_ips", [])
    if not all_ips_data:
        all_ips_data = _extract_ip_summary(events, n=500)
    unique_ip_count = len(all_ips_data)

    ip_section = (
        f"<p><strong>Total unique source IPs:</strong> {unique_ip_count}</p>"
        + ip_table_html
    )

    # --- 2.2 User Agent Analysis ---
    ua_parsed = corr.get("user_agents_parsed", []) or corr.get("all_user_agents", [])
    if not ua_parsed:
        ua_parsed = _extract_ua_summary(events)

    ua_chart = _chart_ua_categories(ua_parsed)
    threat_uas = [u for u in ua_parsed if u.get("threat_flag")]
    non_threat_uas = [u for u in ua_parsed if not u.get("threat_flag")]

    ua_rows = []
    for ua in ua_parsed[:40]:
        cat = ua.get("category", ua.get("cat", "Unknown"))
        tr_cls = ' class="threat-row"' if ua.get("threat_flag") else ""
        browser = ua.get("browser", "")
        os_ = ua.get("os", "")
        detail = " / ".join(x for x in [browser, os_] if x and x != "Unknown")
        ua_rows.append([
            f'<code style="font-size:.78em">{_esc(ua.get("ua", ua.get("raw_ua",""))[:100])}</code>',
            str(ua.get("count", 0)),
            _ua_badge(cat),
            _esc(detail) if detail else "",
            ("&#x26A0; <strong style='color:#c0392b'>SCANNER</strong>"
             if ua.get("threat_flag") else ""),
        ])

    ua_summary = _stat_grid([
        (len(ua_parsed), "Unique User Agents", "#2c3e50"),
        (len(threat_uas), "Security Scanners", "#c0392b"),
        (len([u for u in ua_parsed if u.get("category") == "Bot/Crawler"]), "Bots/Crawlers", "#e67e22"),
        (len([u for u in ua_parsed if u.get("category") == "Web Browser"]), "Browsers", "#27ae60"),
    ])

    ua_html = ua_summary
    if ua_chart:
        ua_html += f'<div class="chart-box">{_inline_img(ua_chart, "UA Categories")}</div>'
    if threat_uas:
        threat_rows = []
        for ua in threat_uas:
            threat_rows.append([
                f'<code style="font-size:.78em;color:#c0392b">'
                f'{_esc(ua.get("ua", ua.get("raw_ua",""))[:120])}</code>',
                str(ua.get("count", 0)),
                _ua_badge(ua.get("category", "Security Scanner")),
            ])
        ua_html += "<h3>&#x26A0; Security Scanner / Threat User Agents</h3>"
        ua_html += _table(["User Agent", "Count", "Category"], threat_rows)
    if ua_rows:
        ua_html += "<h3>All User Agents</h3>"
        ua_html += _collapsible(
            f"All user agents ({len(ua_parsed)} unique)",
            _table(["User Agent String", "Count", "Category", "Browser/OS", "Threat"], ua_rows, compact=True),
        )

    # --- 2.3 IP Beaconing / Activity Windows ---
    beaconing = corr.get("ip_beaconing", [])
    beacon_rows = []
    for r in beaconing[:20]:
        beacon_rows.append([
            f'<code>{_esc(r.get("ip",""))}</code>',
            str(r.get("total_events", 0)),
            _esc(str(r.get("first_seen",""))[:16]),
            _esc(str(r.get("last_seen",""))[:16]),
            f'{r.get("active_duration_h",0)}h',
            ("&#x1F4E1; <strong>Regular</strong>"
             if r.get("regular_intervals") else ""),
        ])
    beacon_html = (_table(["IP", "Events", "First Seen", "Last Seen",
                            "Active Duration", "Pattern"], beacon_rows)
                   if beacon_rows else _no_data())

    # --- 2.4 Country Distribution ---
    countries = corr.get("unique_countries", [])
    country_rows = [[_esc(c.get("country","")), str(c.get("ip_count",0)),
                     str(c.get("event_count",0))] for c in countries[:20]]
    country_html = (_table(["Country", "Unique IPs", "Events"], country_rows)
                    if country_rows else _no_data("No country data extracted."))

    body = (
        "<h3>2.1 Top Source IPs</h3>" + ip_section
        + "<h3>2.2 User Agent Analysis</h3>" + ua_html
        + "<h3>2.3 IP Activity Windows &amp; Beaconing</h3>"
        + _collapsible(f"IP first/last seen ({len(beaconing)} IPs)", beacon_html)
        + "<h3>2.4 Country / Geolocation Distribution</h3>" + country_html
    )
    return _section_card("sec2", "2. Source Intelligence — IPs &amp; User Agents", body, "&#x1F30D;")


# ---------------------------------------------------------------------------
# Section 3: User & Authentication Analysis
# ---------------------------------------------------------------------------

def _s3_user_auth(analysis: Dict) -> str:
    events = analysis.get("_events", [])
    corr = analysis.get("correlations", {})

    # --- 3.1 Per-user event breakdown ---
    user_sum = _extract_user_summary(events, n=40)
    if not user_sum:
        # try correlator
        fvs = corr.get("failed_vs_success_logins", [])
        for r in fvs:
            user_sum.append({
                "username": r.get("username", ""),
                "total_events": r.get("successes", 0) + r.get("failures", 0),
                "failures": r.get("failures", 0),
                "successes": r.get("successes", 0),
                "failure_rate": r.get("failure_rate", 0.0),
                "unique_ips": 0,
                "source_ips": [],
                "top_events": [],
                "first_seen": "",
                "last_seen": "",
                "risk": r.get("risk", "LOW"),
            })

    user_chart = _chart_auth_failures_users(
        [{"username": u["username"], "failures": u["failures"]}
         for u in user_sum if u["failures"] > 0]
    )

    user_rows = []
    for u in user_sum:
        top_ev_html = " ".join(
            f'<span class="info-pill">{_esc(str(en))}({c})</span>'
            for en, c in (u.get("top_events") or [])[:4]
            if en
        )
        ips_html = " ".join(
            f'<code style="font-size:.78em">{_esc(ip)}</code>'
            for ip in u.get("source_ips", [])[:4]
        )
        risk = u.get("risk", "LOW")
        tr_style = 'background:#fff5f5;' if risk == "HIGH" else ''
        fr = u.get("failure_rate", 0)
        user_rows.append([
            f'<strong>{_esc(u["username"])}</strong>',
            str(u["total_events"]),
            (f'<span style="color:#c0392b;font-weight:700">{u["failures"]}'
             f' ({fr:.0f}%)</span>'
             if u["failures"] > 0 else "0"),
            str(u["successes"]),
            str(u.get("unique_ips", 0)),
            top_ev_html or _esc(u.get("top_events", "")),
            ips_html,
            _risk_badge(risk),
            f'<span style="font-size:.76em;color:#888">{_esc(str(u.get("first_seen",""))[:16])}</span>',
            f'<span style="font-size:.76em;color:#888">{_esc(str(u.get("last_seen",""))[:16])}</span>',
        ])

    user_html = ""
    if user_chart:
        user_html += f'<div class="chart-box">{_inline_img(user_chart, "Auth Failures")}</div>'
    if user_rows:
        user_html += _table(
            ["Username", "Total Events", "Failures (Rate)",
             "Successes", "Unique IPs", "Events Observed",
             "Source IPs", "Risk", "First Seen", "Last Seen"],
            user_rows,
        )
    else:
        user_html += _no_data()

    # --- 3.2 Top auth failures by IP ---
    fail_ips = corr.get("login_failures_by_ip", [])
    if not fail_ips:
        fail_ips = [
            {"ip": d["ip"], "failures": d["failures"],
             "targeted_usernames": d.get("users", []),
             "first_seen": d.get("first_seen", ""),
             "last_seen": d.get("last_seen", "")}
            for d in _extract_ip_summary(events, n=20)
            if d.get("failures", 0) > 0
        ]
    fi_rows = []
    for r in fail_ips[:20]:
        users_str = ", ".join(
            f'<code>{_esc(u)}</code>'
            for u in r.get("targeted_usernames", r.get("users", []))[:6]
        )
        fi_rows.append([
            f'<code>{_esc(r.get("ip",""))}</code>',
            f'<strong style="color:#c0392b">{r.get("failures",0)}</strong>',
            users_str,
            _esc(str(r.get("first_seen",""))[:16]),
            _esc(str(r.get("last_seen",""))[:16]),
        ])
    fail_ip_html = (_table(["IP", "Failures", "Targeted Usernames", "First Seen", "Last Seen"], fi_rows)
                    if fi_rows else _no_data())

    # --- 3.3 Top auth failures by user ---
    fail_users = corr.get("login_failures_by_user", [])
    fu_rows = []
    for r in fail_users[:20]:
        ips_str = ", ".join(f'<code>{_esc(ip)}</code>'
                            for ip in r.get("source_ips", [])[:5])
        fu_rows.append([
            f'<code>{_esc(r.get("username",""))}</code>',
            f'<strong style="color:#c0392b">{r.get("failures",0)}</strong>',
            ips_str,
            ", ".join(_esc(t) for t in r.get("failure_types", [])[:3]),
            _esc(str(r.get("first_seen",""))[:16]),
            _esc(str(r.get("last_seen",""))[:16]),
        ])
    fail_user_html = (_table(["Username", "Failures", "Source IPs",
                               "Failure Types", "First Seen", "Last Seen"], fu_rows)
                      if fu_rows else _no_data())

    # --- 3.4 Success after failure ---
    saf = corr.get("successful_after_failure", [])
    saf_rows = [[
        f'<code>{_esc(r.get("ip",""))}</code>',
        f'<code>{_esc(r.get("username",""))}</code>',
        str(r.get("failure_count_before", 0)),
        _esc(str(r.get("success_timestamp",""))[:16]),
        _esc(r.get("success_event","")),
    ] for r in saf[:20]]
    saf_html = (_table(["IP", "Username", "Failures Before", "Success Time", "Success Event"], saf_rows)
                if saf_rows else _no_data("No successful logins after failures detected."))
    if saf_rows:
        saf_html = (f'<div style="padding:8px 12px;background:#fef3e2;border-left:4px solid #e67e22;'
                    f'border-radius:0 6px 6px 0;margin-bottom:8px;">'
                    f'&#x26A0; <strong>{len(saf_rows)}</strong> IP(s) succeeded after repeated failures '
                    f'— possible successful brute-force.</div>') + saf_html

    # --- 3.5 Account lockouts ---
    lockouts = corr.get("account_lockouts", [])
    lock_rows = [[
        _esc(str(r.get("timestamp",""))[:16]),
        f'<code>{_esc(r.get("locked_account",""))}</code>',
        f'<code>{_esc(r.get("source_ip",""))}</code>',
        _esc(r.get("hostname","")),
    ] for r in lockouts[:20]]
    lock_html = (_table(["Time", "Account", "Source IP", "Hostname"], lock_rows)
                 if lock_rows else _no_data("No account lockouts detected."))

    # --- 3.6 Privilege escalation ---
    priv = corr.get("priv_escalation", [])
    priv_rows = [[
        _esc(str(r.get("timestamp",""))[:16]),
        f'<code>{_esc(r.get("username",""))}</code>',
        f'<code>{_esc(r.get("ip",""))}</code>',
        _esc(r.get("escalation_type","")),
        f'<code style="font-size:.78em">{_esc(str(r.get("command",""))[:100])}</code>',
    ] for r in priv[:20]]
    priv_html = (_table(["Time", "Username", "IP", "Escalation Type", "Command"], priv_rows)
                 if priv_rows else _no_data("No privilege escalation events detected."))

    unique_users = len(set(u["username"] for u in user_sum)) if user_sum else 0
    total_fails = sum(u.get("failures", 0) for u in user_sum)
    high_risk_users = sum(1 for u in user_sum if u.get("risk") == "HIGH")

    stats = _stat_grid([
        (unique_users, "Unique Users", "#2c3e50"),
        (total_fails, "Total Auth Failures", "#c0392b"),
        (high_risk_users, "High-Risk Users", "#e67e22"),
        (len(saf), "Success After Failure", "#d4ac0d"),
        (len(lockouts), "Lockouts", "#c0392b"),
        (len(priv), "Privilege Escalations", "#8e44ad"),
    ])

    body = (
        stats
        + "<h3>3.1 Username Activity &amp; Events</h3>" + user_html
        + "<h3>3.2 Top Authentication Failures by Source IP</h3>" + fail_ip_html
        + "<h3>3.3 Top Authentication Failures by Username</h3>" + fail_user_html
        + "<h3>3.4 Successful Login After Repeated Failures</h3>" + saf_html
        + "<h3>3.5 Account Lockouts</h3>" + lock_html
        + "<h3>3.6 Privilege Escalation Indicators</h3>" + priv_html
    )
    return _section_card("sec3", "3. User &amp; Authentication Analysis", body, "&#x1F511;")


# ---------------------------------------------------------------------------
# Section 4: Web & HTTP Analysis
# ---------------------------------------------------------------------------

def _s4_http(analysis: Dict) -> str:
    corr = analysis.get("correlations", {})

    status_data = corr.get("http_status_dist", [])
    urls_data = corr.get("top_urls", [])
    methods_data = corr.get("http_methods", [])
    referrers_data = corr.get("top_referrers", [])

    if not any([status_data, urls_data, methods_data]):
        return _section_card("sec4", "4. Web &amp; HTTP Analysis",
                             _no_data("No HTTP/web log data found in this analysis."),
                             "&#x1F310;")

    # Status codes
    status_chart = _chart_http_status(status_data)
    status_rows = []
    for r in status_data[:20]:
        code = r.get("status_code", 0)
        grp = code // 100
        color = {2: "#27ae60", 3: "#2980b9", 4: "#e67e22", 5: "#c0392b"}.get(grp, "#888")
        status_rows.append([
            f'<span style="color:{color};font-weight:700">{code}</span>',
            _esc(r.get("description", "")),
            str(r.get("count", 0)),
            f'{r.get("percentage",0):.1f}%',
        ])
    status_html = ""
    if status_chart:
        status_html += _inline_img(status_chart, "HTTP Status")
    status_html += (_table(["Code", "Description", "Count", "% of Total"], status_rows)
                    if status_rows else _no_data())

    # Top URLs
    url_rows = []
    for r in urls_data[:25]:
        anomaly = "&#x26A0;" if r.get("anomaly_flag") else ""
        url_rows.append([
            f'{anomaly}<code style="font-size:.78em">{_esc(str(r.get("url",""))[:120])}</code>',
            str(r.get("total_requests", 0)),
            str(r.get("unique_ips", 0)),
            ", ".join(str(x) for x in r.get("status_codes", [])[:5]),
            ", ".join(_esc(str(m)) for m in r.get("method", [])[:3]),
        ])
    url_html = (_table(["URL", "Requests", "Unique IPs", "Status Codes", "Methods"], url_rows)
                if url_rows else _no_data())

    # HTTP methods
    method_rows = []
    for r in methods_data:
        flag = "&#x26A0;" if r.get("anomaly_flag") else ""
        method_rows.append([
            f'{flag}<strong>{_esc(r.get("method",""))}</strong>',
            str(r.get("count", 0)),
            f'{r.get("percentage",0):.1f}%',
        ])
    method_html = (_table(["Method", "Count", "% of Total"], method_rows)
                   if method_rows else _no_data())

    # Referrers
    ref_rows = [[
        f'<code style="font-size:.78em">{_esc(str(r.get("referrer",""))[:100])}</code>',
        str(r.get("count", 0)),
        f'{r.get("percentage",0):.1f}%',
    ] for r in referrers_data[:15]]
    ref_html = (_table(["Referrer", "Count", "%"], ref_rows)
                if ref_rows else _no_data("No referrer data found."))

    body = (
        "<h3>4.1 HTTP Status Code Distribution</h3>" + status_html
        + "<h3>4.2 Top Requested URLs</h3>" + url_html
        + "<h3>4.3 HTTP Methods Distribution</h3>" + method_html
        + "<h3>4.4 Top Referrers</h3>" + ref_html
    )
    return _section_card("sec4", "4. Web &amp; HTTP Analysis", body, "&#x1F310;")


# ---------------------------------------------------------------------------
# Section 5: Network & Protocol Analysis
# ---------------------------------------------------------------------------

def _s5_network(analysis: Dict) -> str:
    corr = analysis.get("correlations", {})

    ports = corr.get("top_dest_ports", [])
    blocked = corr.get("blocked_vs_allowed", [])
    internal = corr.get("internal_anomalies", [])
    dns_domains = corr.get("top_domains", [])
    dns_nxdomain = corr.get("nxdomain_by_client", [])
    rate_spikes = corr.get("rate_spikes", [])
    bw = corr.get("top_ips_by_bandwidth", [])
    suspicious_cmds = corr.get("suspicious_commands", [])
    processes = corr.get("top_processes", [])
    tasks = corr.get("new_tasks_services", [])

    # Ports
    port_rows = []
    for r in ports[:20]:
        sensitive = r.get("service_name", "") != "Unknown"
        flag = "&#x26A0;" if sensitive else ""
        port_rows.append([
            f'{flag}<strong>{r.get("port","")}</strong>',
            _esc(r.get("service_name", "")),
            _esc(r.get("protocol", "")),
            str(r.get("count", 0)),
            f'{r.get("percentage",0):.1f}%',
            str(r.get("unique_sources", 0)),
        ])
    port_html = (_table(["Port", "Service", "Protocol", "Count", "%", "Unique Sources"], port_rows)
                 if port_rows else _no_data("No destination port data."))

    # Blocked vs allowed
    bva_rows = []
    for r in sorted(blocked, key=lambda x: x.get("blocked", 0), reverse=True)[:20]:
        risk_flag = r.get("risk_flag", False)
        bva_rows.append([
            f'<code>{_esc(r.get("source_ip",""))}</code>',
            str(r.get("allowed", 0)),
            f'<strong style="color:#c0392b">{r.get("blocked",0)}</strong>',
            f'{r.get("block_rate",0):.1f}%',
            ("&#x26A0; High Block Rate" if risk_flag else ""),
        ])
    bva_html = (_table(["Source IP", "Allowed", "Blocked", "Block Rate", "Flag"], bva_rows)
                if bva_rows else _no_data("No block/allow traffic data."))

    # Internal anomalies
    int_rows = [[
        f'<code>{_esc(r.get("source_ip",""))}</code>',
        f'<code>{_esc(r.get("dest_ip",""))}</code>',
        str(r.get("port", "")),
        _esc(r.get("service", "")),
        str(r.get("count", 0)),
        _esc(str(r.get("first_seen",""))[:16]),
        _esc(str(r.get("last_seen",""))[:16]),
    ] for r in internal[:20]]
    int_html = (_table(["Source IP", "Dest IP", "Port", "Service", "Count", "First", "Last"], int_rows)
                if int_rows else _no_data("No internal lateral movement indicators."))

    # DNS
    dns_rows = []
    for r in dns_domains[:20]:
        dga = r.get("dga_flag", False)
        dns_rows.append([
            f'<code>{_esc(r.get("domain",""))}</code>',
            str(r.get("count", 0)),
            f'{r.get("entropy_score",0):.2f}',
            ("&#x26A0; <strong style='color:#c0392b'>DGA Candidate</strong>"
             if dga else ""),
        ])
    dns_html = (_table(["Domain", "Queries", "Entropy", "Flag"], dns_rows)
                if dns_rows else _no_data("No DNS query data."))

    # NXDOMAIN
    nx_rows = [[
        f'<code>{_esc(r.get("client_ip",""))}</code>',
        str(r.get("nxdomain_count", 0)),
        str(r.get("total_queries", 0)),
        f'{r.get("nxdomain_rate",0):.1f}%',
        ("&#x26A0; DGA Candidate" if r.get("dga_flag") else ""),
    ] for r in dns_nxdomain[:15]]
    nx_html = (_table(["Client IP", "NXDOMAIN", "Total Queries", "NX Rate", "Flag"], nx_rows)
               if nx_rows else _no_data())

    # Rate spikes
    spike_rows = [[
        _esc(r.get("period_start","")),
        str(r.get("event_count", 0)),
        f'{r.get("baseline",0):.1f}',
        f'{r.get("spike_ratio",0):.1f}x',
        _esc(r.get("spike_type","")),
    ] for r in rate_spikes[:15]]
    spike_html = (_table(["Period", "Event Count", "Baseline", "Spike Ratio", "Type"], spike_rows)
                  if spike_rows else _no_data("No significant rate spikes detected."))

    # Suspicious commands
    cmd_rows = []
    for r in suspicious_cmds[:20]:
        cmd_rows.append([
            f'<span style="color:#c0392b;font-weight:700">{_esc(r.get("threat_type",""))}</span>',
            str(r.get("event_count", 0)),
            f'<code style="font-size:.76em">{_esc(str(r.get("command",""))[:150])}</code>',
            ", ".join(f'<code>{_esc(ip)}</code>' for ip in r.get("source_ips", [])[:4]),
            ", ".join(f'<code>{_esc(u)}</code>' for u in r.get("usernames", [])[:4]),
        ])
    cmd_html = (_table(["Threat Type", "Count", "Sample Command", "IPs", "Users"], cmd_rows)
                if cmd_rows else _no_data("No suspicious commands detected."))

    # Processes
    proc_rows = []
    for r in processes[:20]:
        flag = "&#x26A0;" if r.get("suspicious_flag") else ""
        proc_rows.append([
            f'{flag}<code>{_esc(r.get("process_name",""))}</code>',
            str(r.get("count", 0)),
            ", ".join(f'<code>{_esc(u)}</code>' for u in r.get("unique_users", [])[:4]),
            ", ".join(_esc(h) for h in r.get("unique_hosts", [])[:4]),
        ])
    proc_html = (_table(["Process", "Executions", "Users", "Hosts"], proc_rows)
                 if proc_rows else _no_data("No process execution data."))

    # Bandwidth
    bw_rows = [[
        f'<code>{_esc(r.get("ip",""))}</code>',
        str(r.get("total_bytes", 0)),
        str(r.get("request_count", 0)),
        str(r.get("avg_bytes_per_req", 0)),
    ] for r in bw[:15]]
    bw_html = (_table(["IP", "Total Bytes", "Requests", "Avg Bytes/Req"], bw_rows)
               if bw_rows else _no_data("No bandwidth data available."))

    body = (
        "<h3>5.1 Top Destination Ports</h3>" + port_html
        + "<h3>5.2 Blocked vs Allowed Traffic</h3>" + bva_html
        + "<h3>5.3 Internal-to-Internal Anomalies (Lateral Movement)</h3>" + int_html
        + "<h3>5.4 Top Queried Domains</h3>" + dns_html
        + "<h3>5.5 NXDOMAIN Rate by Client</h3>" + nx_html
        + "<h3>5.6 Event Rate Spikes</h3>" + spike_html
        + "<h3>5.7 Bandwidth by Source IP</h3>" + bw_html
        + "<h3>5.8 Suspicious Commands Detected</h3>" + cmd_html
        + "<h3>5.9 Top Process Executions</h3>"
        + _collapsible(f"Process executions ({len(processes)} distinct)", proc_html)
    )
    return _section_card("sec5", "5. Network &amp; Protocol Analysis", body, "&#x1F5A7;")


# ---------------------------------------------------------------------------
# Section 6: Event & Temporal Analysis
# ---------------------------------------------------------------------------

def _s6_events_temporal(analysis: Dict) -> str:
    em = analysis.get("event_matrix", {})
    corr = analysis.get("correlations", {})
    patterns = analysis.get("patterns", [])
    events = analysis.get("_events", [])

    # Event name frequency
    event_freq = em.get("event_name_frequency", [])
    if not event_freq:
        ec: Counter = Counter(
            e.get("event_name") or e.get("event_category") or "unknown"
            for e in events
        )
        total_ev = len(events)
        event_freq = [
            {"event_name": en, "count": c,
             "percentage": round(c / total_ev * 100, 1) if total_ev else 0}
            for en, c in ec.most_common(50)
        ]

    ef_rows = []
    for e in event_freq[:60]:
        risk_flag = e.get("risk_flag", False)
        ef_rows.append([
            ("&#x26A0; " if risk_flag else "") +
            f'<code>{_esc(e.get("event_name",""))}</code>',
            str(e.get("count", 0)),
            f'{e.get("percentage",0):.1f}%',
        ])
    ef_html = (_table(["Event Name", "Count", "% of Total"], ef_rows)
               if ef_rows else _no_data())

    # Timeline
    tl = corr.get("timeline", {})
    hourly = tl.get("hourly", [])
    daily = tl.get("daily", [])
    peak_hour = tl.get("peak_hour", "")
    peak_day = tl.get("peak_day", "")
    after_hours = tl.get("after_hours_count", 0)
    if not hourly and events:
        hrly: Counter = Counter()
        for e in events:
            ts = e.get("timestamp", "")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    hrly[dt.strftime("%Y-%m-%dT%H:00")] += 1
                except ValueError:
                    pass
        hourly = [{"hour": h, "count": c} for h, c in sorted(hrly.items())]

    tl_chart = _chart_timeline(hourly)
    tl_img = _inline_img(tl_chart, "Timeline") if tl_chart else ""
    tl_meta = ""
    if peak_hour:
        tl_meta += f"<p><strong>Peak hour:</strong> <code>{_esc(peak_hour)}</code>"
    if peak_day:
        tl_meta += f" &nbsp;|&nbsp; <strong>Peak day:</strong> <code>{_esc(peak_day)}</code>"
    if after_hours:
        tl_meta += (f" &nbsp;|&nbsp; <strong>After-hours events (23:00–06:00):</strong> "
                    f'<span style="color:#e67e22">{after_hours}</span>')
    if tl_meta:
        tl_meta += "</p>"

    daily_rows = [[_esc(d.get("date","d.get('day','')")), str(d.get("count",0))] for d in daily[:30]]
    daily_html = _collapsible(
        f"Daily event counts ({len(daily)} days)",
        _table(["Date", "Events"], daily_rows, compact=True) if daily_rows else _no_data(),
    )

    tl_html = tl_img + tl_meta + daily_html

    # Suspicious pattern catalogue
    triggered = [p for p in patterns if p.get("detected")]
    not_triggered = [p for p in patterns if not p.get("detected")]

    def _pc(p: Dict) -> str:
        name = p.get("pattern", "")
        count = p.get("count", 0)
        evidence = p.get("evidence", [])
        ev_html = "".join(
            f'<div class="pc-evidence">&#x2022; {_esc(str(ev)[:80])}</div>'
            for ev in evidence[:3]
        )
        triggered_ = p.get("detected", False)
        cls = "pattern-card triggered" if triggered_ else "pattern-card"
        icon = "&#x26A0;" if triggered_ else "&#x2713;"
        return (f'<div class="{cls}"><div class="pc-title">{icon} {_esc(name)}</div>'
                f'<div class="pc-count">{count}</div>{ev_html}</div>')

    cards_html = "".join(_pc(p) for p in patterns) if patterns else _no_data()
    pattern_html = f'<div class="pattern-cards">{cards_html}</div>'

    body = (
        "<h3>6.1 Event Name Frequency</h3>"
        + _collapsible(f"Event frequency ({len(ef_rows)} event types)", ef_html, open_=True)
        + "<h3>6.2 Event Timeline</h3>" + tl_html
        + "<h3>6.3 Suspicious Pattern Catalogue</h3>"
        + (f'<p><strong style="color:#e67e22">{len(triggered)} pattern(s) triggered</strong> '
           f'out of {len(patterns)} checks.</p>'
           if patterns else "")
        + pattern_html
    )
    return _section_card("sec6", "6. Event &amp; Temporal Analysis", body, "&#x1F4CA;")


# ---------------------------------------------------------------------------
# Section 7: Detection Findings
# ---------------------------------------------------------------------------

def _s7_findings(analysis: Dict) -> str:
    findings = analysis.get("findings", [])
    sev = analysis.get("findings_by_severity", {})

    if not findings:
        return _section_card("sec7", "7. Detection Findings (YARA / Sigma)",
                             _no_data("No rule-based findings in this analysis."),
                             "&#x1F50D;")

    sev_stats = _stat_grid([
        (sev.get("CRITICAL", 0), "Critical", SEVERITY_COLORS["CRITICAL"]),
        (sev.get("HIGH", 0), "High", SEVERITY_COLORS["HIGH"]),
        (sev.get("MEDIUM", 0), "Medium", SEVERITY_COLORS["MEDIUM"]),
        (sev.get("LOW", 0), "Low", SEVERITY_COLORS["LOW"]),
        (len(findings), "Total", "#2c3e50"),
    ])

    by_sev: Dict[str, list] = {}
    for f in findings:
        s = f.get("severity", "INFO")
        by_sev.setdefault(s, []).append(f)

    findings_html = ""
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        group = by_sev.get(level, [])
        if not group:
            continue
        cards = ""
        for f in group:
            fid = f.get("finding_id", "")
            name = f.get("rule_name") or f.get("name", "Unknown")
            desc = f.get("description", "")
            source = f.get("source", "")
            tech = f.get("mitre_technique") or f.get("technique_id", "")
            matched = f.get("matched_events", [])
            # Collect user agents from indicators and matched events
            ind_uas = f.get("indicators", {}).get("user_agents", [])
            ev_uas = [
                str(ev.get("user_agent") or ev.get("ua") or ev.get("http_user_agent") or "")
                for ev in matched if isinstance(ev, dict)
            ]
            all_uas = list(dict.fromkeys(ua for ua in ind_uas + ev_uas if ua))
            ua_tag = ""
            if all_uas:
                ua_items = "".join(
                    f'<li><code style="font-size:.8em;color:#8e44ad">{_esc(ua[:120])}</code></li>'
                    for ua in all_uas[:6]
                )
                ua_tag = (
                    f'<div style="margin:.4em 0;font-size:.82em;">'
                    f'<strong>User Agent(s):</strong>'
                    f'<ul style="margin:.2em 0 0 1em;padding:0">{ua_items}</ul></div>'
                )
            evidence = "".join(
                f'<div class="finding-evidence"><code>'
                f'{_esc(str(ev.get("raw","") or ev)[:200])}'
                f'</code></div>'
                for ev in matched[:3]
            )
            tech_tag = f'<span class="mitre-tag">{_esc(tech)}</span>' if tech else ""
            cards += (
                f'<div class="finding-block {level}">'
                f'<div class="finding-title">[{_esc(fid)}] {_esc(name)} '
                f'&nbsp;{_sev_badge(level)}{tech_tag}</div>'
                f'<div class="finding-meta">Source: {_esc(source)} | '
                f'Matched: {len(matched)} event(s)</div>'
                f'<div class="finding-desc">{_esc(desc)}</div>'
                f'{ua_tag}{evidence}</div>'
            )
        findings_html += _collapsible(
            f"{level} — {len(group)} finding(s)",
            cards,
            open_=(level in ("CRITICAL", "HIGH")),
        )

    body = sev_stats + findings_html
    return _section_card("sec7", "7. Detection Findings (YARA / Sigma)", body, "&#x1F50D;")


# ---------------------------------------------------------------------------
# Section 8: NIST Containment + Post-Incident
# ---------------------------------------------------------------------------

def _s_event_name_analysis(analysis: Dict) -> str:
    """Render the Event Name Analysis section (from EventNameDetector results)."""
    name_results = analysis.get("event_name_results", [])
    vocab = analysis.get("event_name_vocab", {})
    if not name_results and not vocab:
        return ""

    total = vocab.get("total_templates", 0)
    confirmed = vocab.get("confirmed", 0)
    unknown_count = sum(1 for r in name_results if (r.get("confidence") if isinstance(r, dict) else getattr(r, "confidence", "")) == "UNKNOWN")
    confirmed_pct = f"{confirmed * 100 // max(total, 1)}%" if total else "—"
    unknown_pct = f"{unknown_count * 100 // max(len(name_results), 1)}%" if name_results else "—"

    rows_html = ""
    # Sort by rarity descending to surface rarities first
    def _rarity(r: Any) -> float:
        return r.get("rarity_score", 0) if isinstance(r, dict) else getattr(r, "rarity_score", 0)

    sorted_results = sorted(name_results, key=_rarity, reverse=True)[:50]
    for r in sorted_results:
        if isinstance(r, dict):
            template = _esc(str(r.get("template", "")))
            event_name = _esc(str(r.get("event_name", "")))
            confidence = str(r.get("confidence", ""))
            mitre = _esc(str(r.get("mitre_technique", "") or ""))
            rarity = float(r.get("rarity_score", 0))
        else:
            template = _esc(str(getattr(r, "template", "")))
            event_name = _esc(str(getattr(r, "event_name", "")))
            confidence = str(getattr(r, "confidence", ""))
            mitre = _esc(str(getattr(r, "mitre_technique", "") or ""))
            rarity = float(getattr(r, "rarity_score", 0))

        row_style = ' style="background:#fef3e2"' if confidence == "UNKNOWN" else ""
        rows_html += (
            f"<tr{row_style}>"
            f"<td style='font-family:monospace;font-size:0.85em'>{template[:80]}</td>"
            f"<td>{event_name}</td>"
            f"<td>{confidence}</td>"
            f"<td style='text-align:center'>{rarity:.3f}</td>"
            f"<td>{mitre}</td>"
            f"</tr>"
        )

    top_templates_html = ""
    for tmpl in vocab.get("top_10_templates", [])[:10]:
        top_templates_html += f"<li><code>{_esc(str(tmpl)[:100])}</code></li>"

    return f"""
<section id="event-name-analysis">
  <h2>Event Name Analysis</h2>
  <div class="stat-grid">
    <div class="stat-card"><div class="stat-val">{total}</div><div class="stat-lbl">Templates Mined</div></div>
    <div class="stat-card"><div class="stat-val">{confirmed_pct}</div><div class="stat-lbl">Confirmed</div></div>
    <div class="stat-card"><div class="stat-val">{unknown_pct}</div><div class="stat-lbl">Unknown</div></div>
    <div class="stat-card"><div class="stat-val">{len(name_results)}</div><div class="stat-lbl">Events Analysed</div></div>
  </div>
  {'<h3>Top 10 Rarest Events</h3><table class="data-table"><thead><tr><th>Template</th><th>Event Name</th><th>Confidence</th><th>Rarity</th><th>MITRE</th></tr></thead><tbody>' + rows_html + '</tbody></table>' if rows_html else ''}
  {'<h3>Top 10 Templates by Frequency</h3><ol>' + top_templates_html + '</ol>' if top_templates_html else ''}
</section>"""


def _s_search_index_summary(analysis: Dict) -> str:
    """Render a Search Index Summary section if a search query was run."""
    search_summary = analysis.get("search_summary", {})
    if not search_summary:
        return ""

    query = _esc(str(search_summary.get("query", "")))
    total_matches = int(search_summary.get("total_matches", 0))
    top_log_types = search_summary.get("top_log_types", [])

    lt_rows = "".join(
        f"<tr><td>{_esc(str(lt))}</td><td style='text-align:right'>{cnt}</td></tr>"
        for lt, cnt in top_log_types[:10]
    )

    return f"""
<section id="search-index-summary">
  <h2>Search Index Summary</h2>
  <table class="data-table" style="max-width:480px">
    <tr><th>Query</th><td style="font-family:monospace">{query}</td></tr>
    <tr><th>Total Matches</th><td>{total_matches:,}</td></tr>
  </table>
  {'<h3>Top Log Types in Results</h3><table class="data-table"><thead><tr><th>Log Type</th><th>Count</th></tr></thead><tbody>' + lt_rows + '</tbody></table>' if lt_rows else ''}
</section>"""


def _s8_nist(analysis: Dict, meta: Dict) -> str:
    risk = analysis.get("overall_risk", "INFORMATIONAL")
    patterns = analysis.get("patterns", [])
    em = analysis.get("event_matrix", {})
    ip_freq = em.get("ip_frequency", [])
    triggered = [p.get("pattern", "") for p in patterns if p.get("detected")]
    findings = analysis.get("findings", [])
    sev = analysis.get("findings_by_severity", {})

    block_ips = [
        f'<code>{_esc(e["ip"])}</code>'
        for e in ip_freq
        if e.get("risk_score", 0) >= 70
    ]

    recs = []
    if risk in ("CRITICAL", "HIGH"):
        recs.append("<strong>Immediate isolation:</strong> Isolate affected systems from the network.")
    if block_ips:
        recs.append(f"<strong>Block high-risk source IPs</strong> at perimeter firewall/WAF: "
                    + " ".join(block_ips[:15]))
    if any(x in p.lower() for p in triggered for x in ["brute", "credential", "password"]):
        recs.append("<strong>Authentication hardening:</strong> Enforce lockout (≤5 failures), "
                    "enable MFA, rotate credentials on targeted accounts.")
    if any(x in p.lower() for p in triggered for x in ["web", "sqli", "xss", "shell"]):
        recs.append("<strong>Web application:</strong> Enable WAF blocking, patch injection vulnerabilities.")
    if any(x in p.lower() for p in triggered for x in ["persistence", "task", "service"]):
        recs.append("<strong>Persistence removal:</strong> Audit scheduled tasks, services, Run keys, "
                    "startup folders, WMI subscriptions.")
    if any("lateral" in p.lower() for p in triggered):
        recs.append("<strong>Lateral movement:</strong> Segment affected zones. "
                    "Reset krbtgt (x2), enable SMB signing.")
    if any(x in p.lower() for p in triggered for x in ["exfil", "outbound", "c2", "beacon"]):
        recs.append("<strong>C2/Exfiltration:</strong> Block identified C2 channels at DNS/IP. "
                    "Re-image compromised endpoints.")
    if not recs:
        recs.append("No critical containment actions required. Continue routine monitoring.")

    recs_html = "<ul>" + "".join(f"<li>{r}</li>" for r in recs) + "</ul>"

    # MITRE gap
    mitre_observed = {
        f.get("mitre_technique") or f.get("technique_id", ""): f.get("rule_name","")
        for f in findings
        if f.get("mitre_technique") or f.get("technique_id")
    }
    mitre_rows = [[
        f'<span class="mitre-tag">{_esc(k)}</span>', _esc(v)
    ] for k, v in mitre_observed.items()]
    mitre_html = (_table(["Technique", "Rule Name"], mitre_rows)
                  if mitre_rows else _no_data("No MITRE techniques observed."))

    lessons = [
        "Conduct a post-incident review (PIR) within 5 business days.",
        "Document full attack timeline; compare against MITRE ATT&amp;CK for gap analysis.",
        "Update detection rules to cover all observed TTPs.",
        "Review and patch controls that failed to prevent initial compromise.",
        "Update Incident Response Plan based on this event.",
        "Share sanitised IOCs/TTPs with relevant ISACs (TLP permitting).",
        "Validate backup integrity and test restoration procedures.",
    ]

    metrics = _stat_grid([
        (len(findings), "Total Findings", "#2c3e50"),
        (len(triggered), "Patterns Triggered", "#e67e22"),
        (len(mitre_observed), "MITRE Techniques", "#8e44ad"),
        (analysis.get("yara_rules_run", 0), "YARA Rules", "#1e8449"),
        (analysis.get("sigma_rules_run", 0), "Sigma Rules", "#1a5276"),
        (f'{analysis.get("analysis_duration_seconds",0)}s', "Duration", "#555"),
    ])

    body = (
        "<h3>NIST Phase 3 — Containment, Eradication &amp; Recovery</h3>"
        + "<h4>Containment Recommendations</h4>" + recs_html
        + """<h4>Eradication Checklist</h4>
<ul>
<li>Remove all identified malware, webshells, and implants</li>
<li>Patch all exploited and related vulnerabilities</li>
<li>Remove unauthorised accounts, SSH keys, and API tokens</li>
<li>Verify integrity of system binaries and configurations</li>
<li>Update detection rules to cover observed TTPs</li>
</ul>
<h4>Recovery Steps</h4>
<ul>
<li>Restore services from verified clean backups</li>
<li>Verify service integrity before returning to production</li>
<li>Implement enhanced monitoring for at least 30 days</li>
<li>Re-baseline normal traffic patterns after environment is clean</li>
</ul>"""
        + "<h3>NIST Phase 4 — Post-Incident Activity</h3>"
        + metrics
        + "<h4>MITRE ATT&amp;CK Coverage Gap Review</h4>" + mitre_html
        + "<h4>Lessons Learned</h4>"
        + "<ul>" + "".join(f"<li>{l}</li>" for l in lessons) + "</ul>"
    )
    return _section_card("sec8", "8. NIST Phases: Containment &amp; Post-Incident", body, "&#x1F6E1;")


# ---------------------------------------------------------------------------
# Section 9: Appendix
# ---------------------------------------------------------------------------

def _s9_appendix(analysis: Dict) -> str:
    em = analysis.get("event_matrix", {})
    ip_matrix = em.get("ip_event_matrix", {})
    user_matrix = em.get("user_event_matrix", {})

    ip_mat_rows = []
    for ip, data in list(ip_matrix.items())[:25]:
        ev_str = " ".join(
            f'<span class="info-pill">{_esc(k)}({v})</span>'
            for k, v in list((data.get("events") or {}).items())[:5]
        )
        ip_mat_rows.append([f'<code>{_esc(ip)}</code>', ev_str, str(data.get("risk_score", 0))])

    user_mat_rows = []
    for user, data in list(user_matrix.items())[:25]:
        ev_str = " ".join(
            f'<span class="info-pill">{_esc(k)}({v})</span>'
            for k, v in list((data.get("events") or {}).items())[:5]
        )
        user_mat_rows.append([f'<code>{_esc(user)}</code>', ev_str, str(data.get("risk_score", 0))])

    snippet = json.dumps(analysis.get("findings", [])[:3], indent=2, default=str)
    det = analysis.get("detection_meta", {})
    det_tier      = det.get("tier", "")
    det_structure = det.get("structure", "")
    det_ruleset   = det.get("ruleset", {})
    sigma_cats    = ", ".join(det_ruleset.get("sigma", [])) or "generic"
    yara_cats     = ", ".join(det_ruleset.get("yara",  [])) or "generic"
    meta_rows = [
        ["Analysis ID",          analysis.get("analysis_id", "")],
        ["Log Type",             analysis.get("log_type", "")],
        ["Detection Tier",       det_tier or "N/A"],
        ["Format Structure",     det_structure or "N/A"],
        ["Sigma Rule Categories", sigma_cats],
        ["YARA Rule Categories",  yara_cats],
        ["Total Events",         str(analysis.get("total_events", 0))],
        ["YARA Rules Run",       str(analysis.get("yara_rules_run", 0))],
        ["Sigma Rules Run",      str(analysis.get("sigma_rules_run", 0))],
        ["Duration",             f'{analysis.get("analysis_duration_seconds", 0)}s'],
        ["Overall Risk",         analysis.get("overall_risk", "")],
    ]

    body = (
        "<h3>9.1 Analysis Metadata</h3>"
        + _table(["Field", "Value"], meta_rows)
        + "<h3>9.2 IP-Event Matrix</h3>"
        + _collapsible(
            f"IP event matrix ({len(ip_matrix)} IPs)",
            _table(["IP", "Events (sample)", "Risk Score"], ip_mat_rows)
            if ip_mat_rows else _no_data(),
        )
        + "<h3>9.3 User-Event Matrix</h3>"
        + _collapsible(
            f"User event matrix ({len(user_matrix)} users)",
            _table(["Username", "Events (sample)", "Risk Score"], user_mat_rows)
            if user_mat_rows else _no_data(),
        )
        + "<h3>9.4 Sample Findings JSON</h3>"
        + _collapsible(
            "Sample findings (first 3)",
            f'<pre style="font-size:.76em;overflow-x:auto;">{_esc(snippet)}</pre>',
        )
    )
    return _section_card("sec9", "9. Technical Appendix", body, "&#x1F4CE;")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_html_report(
    analysis: Dict,
    events: Optional[List[Dict]] = None,
    analyst: str = "N/A",
    tlp: str = "TLP:WHITE",
) -> str:
    """Build a complete HTML incident report."""
    # Embed raw events for inline extraction
    work = dict(analysis)
    work["_events"] = events or []

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    det = analysis.get("detection_meta", {})
    meta: Dict = {
        "analysis_id":       analysis.get("analysis_id", "N/A"),
        "log_type":          analysis.get("log_type", "unknown"),
        "file_path":         analysis.get("file_path"),
        "total_events":      analysis.get("total_events", 0),
        "overall_risk":      analysis.get("overall_risk", "INFORMATIONAL"),
        "analyst":           analyst,
        "tlp":               tlp,
        "generated_at":      generated_at,
        "detection_tier":    det.get("tier", ""),
        "detection_structure": det.get("structure", ""),
        "detection_signals": det.get("signals", []),
        "detection_ruleset": det.get("ruleset", {}),
    }

    rc = SEVERITY_COLORS.get(meta["overall_risk"], "#7f8c8d")
    tc = TLP_COLORS.get(tlp.upper(), "#7f8c8d")

    body = (
        _s0_cover(meta)
        + _toc()
        + '<div class="content">'
        + _s1_exec_summary(work, meta)
        + _s2_source_intel(work)
        + _s3_user_auth(work)
        + _s4_http(work)
        + _s5_network(work)
        + _s6_events_temporal(work)
        + _s7_findings(work)
        + _s_event_name_analysis(work)
        + _s_search_index_summary(work)
        + _s8_nist(work, meta)
        + _s9_appendix(work)
        + "</div>"
        + f'<footer>Generated by <strong>ThreatTrace</strong> &mdash; '
          f'NIST SP 800-61 Rev.2 &nbsp;|&nbsp; {_tlp_badge(tlp)} '
          f'&nbsp;|&nbsp; {_esc(generated_at)}</footer>'
    )
    return _html_shell(
        f"ThreatTrace — {analysis.get('analysis_id','')} — {meta['overall_risk']}",
        body,
    )


def build_json_report(
    analysis: Dict,
    analyst: str = "N/A",
    tlp: str = "TLP:WHITE",
) -> Dict:
    """Build a structured JSON report."""
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    em = analysis.get("event_matrix", {})
    corr = analysis.get("correlations", {})
    clean = {k: v for k, v in analysis.items() if not k.startswith("_")}
    return {
        "report_metadata": {
            "tool": "ThreatTrace", "version": "2.0",
            "standard": "NIST SP 800-61 Rev.2",
            "analysis_id": analysis.get("analysis_id"),
            "generated_at": generated_at,
            "analyst": analyst,
            "tlp": tlp,
        },
        "executive_summary": {
            "overall_risk": analysis.get("overall_risk"),
            "findings_by_severity": analysis.get("findings_by_severity", {}),
            "patterns_triggered": [p for p in analysis.get("patterns", []) if p.get("detected")],
            "mitre_techniques": list({
                f.get("mitre_technique") or f.get("technique_id", "")
                for f in analysis.get("findings", [])
                if f.get("mitre_technique") or f.get("technique_id")
            }),
        },
        "source_intelligence": {
            "top_ips": corr.get("top_ips_by_requests", [])[:25],
            "unique_ip_count": len(corr.get("unique_ips", [])),
            "user_agents": corr.get("user_agents_parsed", corr.get("all_user_agents", []))[:30],
            "ip_beaconing": corr.get("ip_beaconing", [])[:20],
            "countries": corr.get("unique_countries", []),
        },
        "user_auth_analysis": {
            "login_failures_by_ip": corr.get("login_failures_by_ip", [])[:25],
            "login_failures_by_user": corr.get("login_failures_by_user", [])[:25],
            "failed_vs_success": corr.get("failed_vs_success_logins", [])[:30],
            "successful_after_failure": corr.get("successful_after_failure", []),
            "account_lockouts": corr.get("account_lockouts", []),
            "privilege_escalation": corr.get("priv_escalation", []),
        },
        "http_analysis": {
            "status_distribution": corr.get("http_status_dist", []),
            "top_urls": corr.get("top_urls", [])[:25],
            "http_methods": corr.get("http_methods", []),
        },
        "network_analysis": {
            "top_dest_ports": corr.get("top_dest_ports", [])[:20],
            "blocked_vs_allowed": corr.get("blocked_vs_allowed", [])[:25],
            "internal_anomalies": corr.get("internal_anomalies", []),
            "dns_top_domains": corr.get("top_domains", [])[:20],
            "rate_spikes": corr.get("rate_spikes", []),
            "suspicious_commands": corr.get("suspicious_commands", []),
        },
        "event_analysis": {
            "event_frequency": em.get("event_name_frequency", [])[:60],
            "ip_frequency": em.get("ip_frequency", [])[:30],
            "username_frequency": em.get("username_frequency", [])[:30],
            "suspicious_patterns": analysis.get("patterns", []),
            "timeline_peak_hour": corr.get("timeline", {}).get("peak_hour"),
            "timeline_after_hours": corr.get("timeline", {}).get("after_hours_count", 0),
        },
        "detection_findings": {
            "total": len(analysis.get("findings", [])),
            "findings": analysis.get("findings", []),
        },
        "raw_analysis": clean,
    }


def save_report(
    analysis: Dict,
    output_dir: str,
    format_: str = "html",
    events: Optional[List[Dict]] = None,
    analyst: str = "N/A",
    tlp: str = "TLP:WHITE",
) -> str:
    """Save report(s) to output_dir. Returns primary saved path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    analysis_id = analysis.get("analysis_id", "report")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"ThreatTrace_{analysis_id}_{ts}"
    saved = ""

    if format_ in ("html", "both"):
        html_content = build_html_report(analysis, events=events, analyst=analyst, tlp=tlp)
        p = out / f"{base}.html"
        p.write_text(html_content, encoding="utf-8")
        logger.info(f"HTML report: {p}")
        saved = str(p)

    if format_ in ("json", "both"):
        json_data = build_json_report(analysis, analyst=analyst, tlp=tlp)
        p = out / f"{base}.json"
        p.write_text(json.dumps(json_data, indent=2, default=str), encoding="utf-8")
        logger.info(f"JSON report: {p}")
        if not saved:
            saved = str(p)

    return saved
