"""
Linux Auditd Log Parser
Correlates audit records by serial number and extracts fields from
SYSCALL, EXECVE, PROCTITLE, PATH, CWD, SOCKADDR records.
"""

import re
import logging
import socket
import struct
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional

logger = logging.getLogger(__name__)

# audit(1234567890.123:456) serial extraction
AUDIT_HEADER = re.compile(r'^type=(\S+) msg=audit\((\d+\.\d+):(\d+)\): (.+)$')

# Syscall number -> name mapping (common ones; rest fall through)
SYSCALL_NAMES = {
    "59":  "execve",
    "2":   "open",
    "257": "openat",
    "42":  "connect",
    "49":  "bind",
    "90":  "chmod",
    "92":  "chown",
    "0":   "read",
    "1":   "write",
    "41":  "socket",
    "43":  "accept",
    "56":  "clone",
    "57":  "fork",
    "62":  "kill",
    "82":  "rename",
    "87":  "unlink",
    "105": "setuid",
    "106": "setgid",
    "3":   "close",
    "4":   "stat",
    "5":   "fstat",
    "6":   "lstat",
    "63":  "uname",
    "84":  "rmdir",
    "80":  "chdir",
    "85":  "mkdir",
    "83":  "symlink",
    "88":  "unlinkat",
    "316": "renameat2",
    "317": "copy_file_range",
}

# Syscall name -> (event_name, event_category)
SYSCALL_EVENT_MAP = {
    "execve":   ("Process Execution (execve)",      "Process"),
    "open":     ("File Open",                       "File"),
    "openat":   ("File Open",                       "File"),
    "connect":  ("Network Connection Initiated",    "Network"),
    "bind":     ("Socket Bind",                     "Network"),
    "chmod":    ("File Permission Change",          "File"),
    "chown":    ("File Permission Change",          "File"),
    "read":     ("File Read",                       "File"),
    "write":    ("File Write",                      "File"),
    "socket":   ("Socket Created",                  "Network"),
    "accept":   ("Network Connection Accepted",     "Network"),
    "clone":    ("Process Fork",                    "Process"),
    "fork":     ("Process Fork",                    "Process"),
    "kill":     ("Process Kill Signal",             "Process"),
    "rename":   ("File Renamed",                    "File"),
    "unlink":   ("File Deleted",                    "File"),
    "setuid":   ("Privilege Change",                "Privilege"),
    "setgid":   ("Privilege Change",                "Privilege"),
}


def _parse_timestamp(epoch_str: str) -> str:
    try:
        ts = float(epoch_str)
        dt = datetime.utcfromtimestamp(ts).replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return epoch_str


def _safe_int(val) -> Optional[int]:
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _is_hex_string(val: str) -> bool:
    """Return True if val looks like a hex-encoded string (even length, all hex digits, length > 4)."""
    if len(val) < 2 or len(val) % 2 != 0:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in val)


def _decode_hex(val: str) -> str:
    """Decode a hex-encoded string value."""
    try:
        return bytes.fromhex(val).decode("utf-8", errors="replace")
    except Exception:
        return val


def _parse_kv(text: str) -> dict:
    """Parse key=value pairs from audit record, handling quoted values."""
    result = {}
    pattern = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
    for m in pattern.finditer(text):
        k = m.group(1)
        v = m.group(2)
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        elif _is_hex_string(v) and len(v) > 4:
            decoded = _decode_hex(v)
            # Only replace if the decoded result is printable ASCII
            if decoded.isprintable():
                v = decoded
        result[k] = v
    return result


def _decode_sockaddr(hex_addr: str) -> tuple:
    """Decode a hex sockaddr to (ip, port)."""
    try:
        raw = bytes.fromhex(hex_addr)
        if len(raw) >= 8:
            family = struct.unpack("H", raw[:2])[0]
            if family == 2:  # AF_INET
                port = struct.unpack("!H", raw[2:4])[0]
                ip   = socket.inet_ntoa(raw[4:8])
                return (ip, port)
            elif family == 10 and len(raw) >= 28:  # AF_INET6
                port = struct.unpack("!H", raw[2:4])[0]
                ip   = socket.inet_ntop(socket.AF_INET6, raw[8:24])
                return (ip, port)
    except Exception:
        pass
    return (None, None)


def _merge_group(records: list) -> dict:
    """Merge a group of correlated audit records into one event."""
    syscall_rec   = {}
    execve_args   = {}
    proctitle_val = None
    cwd_val       = None
    path_val      = None
    sockaddr_val  = None
    timestamp_val = None
    serial_val    = None

    for rec_type, timestamp, serial, fields in records:
        if timestamp_val is None:
            timestamp_val = timestamp
            serial_val    = serial

        if rec_type == "SYSCALL":
            syscall_rec = fields

        elif rec_type == "EXECVE":
            argc = _safe_int(fields.get("argc", "0")) or 0
            for i in range(argc):
                arg_key = f"a{i}"
                if arg_key in fields:
                    execve_args[i] = fields[arg_key]

        elif rec_type == "PROCTITLE":
            pt = fields.get("proctitle", "")
            if _is_hex_string(pt):
                pt = _decode_hex(pt).replace("\x00", " ").strip()
            proctitle_val = pt

        elif rec_type == "CWD":
            cwd_val = fields.get("cwd")

        elif rec_type == "PATH":
            if path_val is None:
                path_val = fields.get("name")

        elif rec_type == "SOCKADDR":
            saddr = fields.get("saddr", "")
            if saddr:
                sockaddr_val = saddr

    # Determine syscall name
    syscall_num  = syscall_rec.get("syscall", "")
    syscall_name = SYSCALL_NAMES.get(syscall_num, syscall_rec.get("syscall_name", syscall_num))

    if syscall_name in SYSCALL_EVENT_MAP:
        event_name, event_category = SYSCALL_EVENT_MAP[syscall_name]
    else:
        event_name     = f"Syscall: {syscall_name}"
        event_category = "Syscall"

    # Build command line
    command_line = None
    if execve_args:
        command_line = " ".join(execve_args[i] for i in sorted(execve_args))
    elif proctitle_val:
        command_line = proctitle_val

    # IP/port from SOCKADDR
    source_ip   = None
    source_port = None
    if sockaddr_val:
        source_ip, source_port = _decode_sockaddr(sockaddr_val)

    # Username: prefer auid, then uid
    uid     = syscall_rec.get("uid", "-")
    auid    = syscall_rec.get("auid", "-")
    username = None
    if auid and auid not in ("4294967295", "-1", "-", "unset"):
        username = f"uid:{auid}"
    elif uid and uid not in ("-", ""):
        username = f"uid:{uid}"

    process_name = syscall_rec.get("exe") or syscall_rec.get("comm")
    hostname     = syscall_rec.get("hostname")
    domain       = None

    return {
        "timestamp":      _parse_timestamp(timestamp_val) if timestamp_val else None,
        "source_ip":      source_ip,
        "dest_ip":        None,
        "source_port":    source_port,
        "dest_port":      None,
        "username":       username,
        "user_agent":     None,
        "method":         None,
        "url":            path_val or cwd_val,
        "status_code":    None,
        "bytes_sent":     None,
        "protocol":       None,
        "action":         syscall_rec.get("success"),
        "event_id":       serial_val,
        "event_name":     event_name,
        "event_category": event_category,
        "process_name":   process_name,
        "command_line":   command_line,
        "hostname":       hostname,
        "domain":         domain,
        "log_source":     "linux_audit",
        "raw":            f"serial={serial_val} syscall={syscall_name}",
    }


def parse(file_path: str) -> list:
    """Parse auditd log file. Correlates records by serial. Returns normalized events."""
    events = []

    try:
        fh = open(file_path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        logger.error("Audit parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("Audit parser: failed to open %s: %s", file_path, e)
        return events

    # Group records by serial
    groups = defaultdict(list)  # serial -> [(type, timestamp, serial, fields), ...]

    with fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n\r")
            if not line:
                continue

            m = AUDIT_HEADER.match(line)
            if not m:
                logger.debug("Audit parser: no match at line %d", lineno)
                continue

            try:
                rec_type  = m.group(1)
                timestamp = m.group(2)
                serial    = m.group(3)
                body      = m.group(4)
                fields    = _parse_kv(body)
                groups[serial].append((rec_type, timestamp, serial, fields))
            except Exception as e:
                logger.warning("Audit parser: error on line %d: %s", lineno, e)
                continue

    # Merge each group into one event
    for serial, records in groups.items():
        try:
            # Only emit an event if there's a SYSCALL record
            has_syscall = any(r[0] == "SYSCALL" for r in records)
            if has_syscall:
                event = _merge_group(records)
                events.append(event)
            else:
                # Emit one event per non-SYSCALL record type (e.g., USER_AUTH, USER_LOGIN)
                for rec_type, timestamp, serial, fields in records:
                    if rec_type.startswith("USER") or rec_type in ("DAEMON_START", "CONFIG_CHANGE"):
                        event_name = rec_type.replace("_", " ").title()
                        events.append({
                            "timestamp":      _parse_timestamp(timestamp),
                            "source_ip":      fields.get("addr"),
                            "dest_ip":        None,
                            "source_port":    None,
                            "dest_port":      None,
                            "username":       fields.get("acct") or fields.get("id"),
                            "user_agent":     None,
                            "method":         None,
                            "url":            None,
                            "status_code":    None,
                            "bytes_sent":     None,
                            "protocol":       None,
                            "action":         fields.get("res") or fields.get("success"),
                            "event_id":       serial,
                            "event_name":     event_name,
                            "event_category": "Authentication",
                            "process_name":   fields.get("exe"),
                            "command_line":   None,
                            "hostname":       fields.get("hostname"),
                            "domain":         None,
                            "log_source":     "linux_audit",
                            "raw":            f"type={rec_type} serial={serial}",
                        })
        except Exception as e:
            logger.warning("Audit parser: error merging serial %s: %s", serial, e)
            continue

    return events
