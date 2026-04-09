"""
Email Server Log Parser
Supports Postfix (syslog), Microsoft Exchange (IIS W3C), and O365 (JSON audit).
"""

import re
import json
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

RFC3164_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# --------------------------------------------------------------------------
# Postfix syslog format
# --------------------------------------------------------------------------
# "Jan 15 03:11:02 hostname postfix/smtpd[1234]: ..."
_POSTFIX_HEADER = re.compile(
    r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(postfix/\S+?)(?:\[\d+\])?: (.+)$'
)
_PF_QUEUE_ID = re.compile(r'^([0-9A-F]{10,}|[A-Z0-9]{10,}):\s+(.+)$')
_PF_FROM     = re.compile(r'from=<([^>]*)>')
_PF_TO       = re.compile(r'to=<([^>]*)>')
_PF_SIZE     = re.compile(r'size=(\d+)')
_PF_STATUS   = re.compile(r'status=(\w+)')
_PF_SASL_USER= re.compile(r'sasl_username=(\S+)')
_PF_CONNECT_FROM = re.compile(r'connect from (\S+)\[(\d+\.\d+\.\d+\.\d+)\]')
_PF_DISCONNECT   = re.compile(r'disconnect from (\S+)\[(\d+\.\d+\.\d+\.\d+)\]')
_PF_REJECT       = re.compile(r'NOQUEUE: reject')
_PF_SASL_FAIL    = re.compile(r'SASL (LOGIN|PLAIN|DIGEST-MD5) authentication failed')
_PF_TLS          = re.compile(r'TLS established')
_PF_NOQUEUE_REJECT = re.compile(r'NOQUEUE: reject.*from=<([^>]*)>.*to=<([^>]*)>')

_POSTFIX_SUB_EVENTS = [
    (_PF_CONNECT_FROM,   "SMTP Connection",    "Email"),
    (_PF_DISCONNECT,     "SMTP Disconnect",    "Email"),
    (_PF_REJECT,         "Email Rejected",     "Email"),
    (_PF_SASL_FAIL,      "SASL Auth Failure",  "Email"),
    (_PF_TLS,            "TLS Session",        "Email"),
]


def _normalize_syslog_ts(ts: str) -> str:
    try:
        parts = ts.split()
        if len(parts) == 3:
            month = RFC3164_MONTHS.get(parts[0], 1)
            day   = int(parts[1])
            hms   = parts[2].split(":")
            h, m, s = int(hms[0]), int(hms[1]), int(hms[2])
            year  = datetime.utcnow().year
            d = datetime(year, month, day, h, m, s, tzinfo=timezone.utc)
            return d.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        pass
    return ts


def _parse_postfix_line(line: str) -> Optional[dict]:
    m = _POSTFIX_HEADER.match(line)
    if not m:
        return None

    ts_raw  = m.group(1)
    daemon  = m.group(2)   # e.g. postfix/smtpd
    message = m.group(3)

    timestamp = _normalize_syslog_ts(ts_raw)
    source_ip = None
    username  = None
    from_addr = None
    to_addr   = None
    bytes_sent= None
    event_name    = None
    event_category = "Email"

    # Strip queue_id prefix if present
    mq = _PF_QUEUE_ID.match(message)
    body = mq.group(2) if mq else message

    mf = _PF_FROM.search(body)
    if mf:
        from_addr = mf.group(1)
    mt = _PF_TO.search(body)
    if mt:
        to_addr = mt.group(1)
    msz = _PF_SIZE.search(body)
    if msz:
        bytes_sent = int(msz.group(1))
    msu = _PF_SASL_USER.search(body)
    if msu:
        username = msu.group(1)

    # status= lines (postfix/smtp delivery)
    ms = _PF_STATUS.search(body)
    if ms:
        status = ms.group(1)
        if status == "sent":
            event_name = "Email Sent"
        elif status == "bounced":
            event_name = "Email Bounced"
        elif status == "deferred":
            event_name = "Email Deferred"
        elif status == "undeliverable":
            event_name = "Email Undeliverable"
        else:
            event_name = f"Email {status.title()}"

    if not event_name:
        for pattern, ename, ecat in _POSTFIX_SUB_EVENTS:
            if pattern.search(body):
                event_name     = ename
                event_category = ecat
                # Extract IP from connection patterns
                mc = _PF_CONNECT_FROM.search(body)
                if mc:
                    source_ip = mc.group(2)
                else:
                    md = _PF_DISCONNECT.search(body)
                    if md:
                        source_ip = md.group(2)
                break

    if not event_name:
        return None  # Not a meaningful email event

    return {
        "timestamp":        timestamp,
        "source_ip":        source_ip,
        "dest_ip":          None,
        "source_port":      None,
        "dest_port":        25,
        "username":         username,
        "user_agent":       None,
        "method":           None,
        "url":              None,
        "status_code":      None,
        "bytes_sent":       bytes_sent,
        "protocol":         "SMTP",
        "action":           None,
        "event_id":         None,
        "event_name":       event_name,
        "event_category":   event_category,
        "process_name":     daemon,
        "command_line":     None,
        "hostname":         None,
        "domain":           None,
        "log_source":       "email",
        "from_address":     from_addr,
        "to_address":       to_addr,
        "raw":              line[:500],
    }


# --------------------------------------------------------------------------
# Microsoft Exchange IIS W3C log format
# --------------------------------------------------------------------------
# Fields line: #Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port
#              cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus
_W3C_FIELD_LINE = re.compile(r'^#Fields:\s+(.+)$')
_W3C_DATE_TS    = re.compile(r'^\d{4}-\d{2}-\d{2}$')

_exchange_fields = []


def _parse_exchange_line(line: str, fields: list) -> Optional[dict]:
    if line.startswith("#") or not line.strip():
        return None
    if not fields:
        return None

    parts = line.split()
    if len(parts) < len(fields):
        return None

    row = dict(zip(fields, parts))

    date_val    = row.get("date", "")
    time_val    = row.get("time", "")
    timestamp   = f"{date_val}T{time_val}Z" if date_val and time_val else None
    method      = row.get("cs-method")
    status_code = row.get("sc-status")
    source_ip   = row.get("c-ip")
    username    = row.get("cs-username", "-")
    user_agent  = row.get("cs(User-Agent)", "-")

    if username == "-":
        username = None
    if user_agent == "-":
        user_agent = None

    try:
        sc = int(status_code) if status_code and status_code != "-" else None
    except ValueError:
        sc = None

    event_name = f"Exchange {method} {status_code}" if method else "Exchange Request"

    return {
        "timestamp":        timestamp,
        "source_ip":        source_ip,
        "dest_ip":          row.get("s-ip"),
        "source_port":      None,
        "dest_port":        None,
        "username":         username,
        "user_agent":       user_agent,
        "method":           method,
        "url":              row.get("cs-uri-stem"),
        "status_code":      sc,
        "bytes_sent":       None,
        "protocol":         "HTTP",
        "action":           None,
        "event_id":         None,
        "event_name":       event_name,
        "event_category":   "Email",
        "process_name":     None,
        "command_line":     None,
        "hostname":         None,
        "domain":           None,
        "log_source":       "email",
        "raw":              line[:500],
    }


# --------------------------------------------------------------------------
# O365 JSON audit log
# --------------------------------------------------------------------------
def _parse_o365_record(rec: dict) -> dict:
    op = rec.get("Operation") or rec.get("eventType", "Unknown")
    category = "Email"
    if op.startswith("Mail") or op.startswith("Send") or "Email" in op:
        category = "Email"

    username  = rec.get("UserId") or rec.get("Actor", [{}])[0].get("ID") if isinstance(rec.get("Actor"), list) else rec.get("Actor")
    source_ip = rec.get("ClientIP") or rec.get("ActorIpAddress")

    return {
        "timestamp":        rec.get("CreationTime") or rec.get("time"),
        "source_ip":        source_ip,
        "dest_ip":          None,
        "source_port":      None,
        "dest_port":        None,
        "username":         username,
        "user_agent":       rec.get("UserAgent"),
        "method":           None,
        "url":              None,
        "status_code":      None,
        "bytes_sent":       None,
        "protocol":         None,
        "action":           None,
        "event_id":         rec.get("Id"),
        "event_name":       op,
        "event_category":   category,
        "process_name":     None,
        "command_line":     None,
        "hostname":         None,
        "domain":           rec.get("OrganizationId"),
        "log_source":       "email",
        "raw":              json.dumps(rec)[:500],
    }


def _try_parse_o365(content: str) -> list:
    events = []
    try:
        data = json.loads(content)
        records = data if isinstance(data, list) else [data]
        for rec in records:
            if isinstance(rec, dict) and ("Operation" in rec or "eventType" in rec):
                try:
                    events.append(_parse_o365_record(rec))
                except Exception as e:
                    logger.warning("Email parser (O365): error: %s", e)
        return events
    except json.JSONDecodeError:
        pass

    # newline-delimited JSON
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            if isinstance(rec, dict) and ("Operation" in rec or "eventType" in rec):
                events.append(_parse_o365_record(rec))
        except json.JSONDecodeError:
            pass
        except Exception as e:
            logger.warning("Email parser (O365 NDJSON): error: %s", e)
    return events


def parse(file_path: str) -> list:
    """Parse email server log file (Postfix/Exchange IIS/O365 JSON). Returns normalized events."""
    events = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("Email parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("Email parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        content = fh.read()

    # Try O365 JSON first
    stripped = content.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        o365_events = _try_parse_o365(content)
        if o365_events:
            return o365_events

    # Detect W3C (Exchange IIS) vs Postfix
    w3c_fields = []
    is_w3c = False
    for line in content.splitlines():
        if line.startswith("#Fields:"):
            m = _W3C_FIELD_LINE.match(line)
            if m:
                w3c_fields = m.group(1).split()
                is_w3c = True
            break
        if line.startswith("#Software:") or line.startswith("#Version:"):
            is_w3c = True
            break

    for lineno, line in enumerate(content.splitlines(), 1):
        line = line.rstrip()
        if not line:
            continue
        try:
            if is_w3c:
                # Update fields if this is a new #Fields line
                if line.startswith("#Fields:"):
                    m = _W3C_FIELD_LINE.match(line)
                    if m:
                        w3c_fields = m.group(1).split()
                    continue
                if line.startswith("#"):
                    continue
                rec = _parse_exchange_line(line, w3c_fields)
            else:
                rec = _parse_postfix_line(line)

            if rec:
                events.append(rec)
        except Exception as e:
            logger.warning("Email parser: error on line %d: %s", lineno, e)

    return events
