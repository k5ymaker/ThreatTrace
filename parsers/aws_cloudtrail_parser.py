"""
AWS CloudTrail Log Parser
Parses CloudTrail JSON log files (Records array or newline-delimited JSON).
Supports compressed .json.gz files.
"""

import gzip
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Map eventSource prefix -> event_category
_SOURCE_CATEGORY = {
    "iam":          "IAM",
    "s3":           "S3",
    "ec2":          "EC2",
    "sts":          "STS",
    "cloudtrail":   "CloudTrail",
    "kms":          "KMS",
    "lambda":       "Lambda",
}


def _event_category(event_source: Optional[str]) -> str:
    if not event_source:
        return "AWS"
    src = event_source.lower()
    for prefix, cat in _SOURCE_CATEGORY.items():
        if src.startswith(prefix):
            return cat
    return "AWS"


def _normalize_record(rec: dict) -> dict:
    """Convert a single CloudTrail record dict to a normalized event dict."""
    user_identity = rec.get("userIdentity") or {}
    uid_type = user_identity.get("type")
    uid_arn  = user_identity.get("arn")
    # Prefer userName, fall back to principalId, then arn
    username = (
        user_identity.get("userName")
        or user_identity.get("principalId")
        or uid_arn
    )

    event_source = rec.get("eventSource", "")
    error_code   = rec.get("errorCode")

    return {
        "timestamp":        rec.get("eventTime"),
        "source_ip":        rec.get("sourceIPAddress"),
        "dest_ip":          None,
        "source_port":      None,
        "dest_port":        None,
        "username":         username,
        "user_agent":       rec.get("userAgent"),
        "method":           None,
        "url":              None,
        "status_code":      None,
        "bytes_sent":       None,
        "protocol":         None,
        "action":           "failure" if error_code else "success",
        "event_id":         rec.get("eventID"),
        "event_name":       rec.get("eventName"),
        "event_category":   _event_category(event_source),
        "process_name":     None,
        "command_line":     None,
        "hostname":         None,
        "domain":           event_source,
        "log_source":       "cloudtrail",
        # Extra CloudTrail fields
        "aws_region":       rec.get("awsRegion"),
        "error_code":       error_code,
        "error_message":    rec.get("errorMessage"),
        "request_params":   rec.get("requestParameters"),
        "response_elements":rec.get("responseElements"),
        "user_identity_type": uid_type,
        "user_identity_arn":  uid_arn,
        "raw":              json.dumps(rec)[:500],
    }


def _open_file(file_path: str):
    """Open regular or gzip-compressed file, return file object."""
    if file_path.endswith(".gz"):
        return gzip.open(file_path, "rt", encoding="utf-8", errors="replace")
    return open(file_path, "r", encoding="utf-8", errors="replace")


def parse(file_path: str) -> list:
    """Parse AWS CloudTrail log file. Returns list of normalized event dicts."""
    events = []

    try:
        fh = _open_file(file_path)
    except FileNotFoundError:
        logger.error("CloudTrail parser: file not found: %s", file_path)
        return events
    except Exception as e:
        logger.error("CloudTrail parser: failed to open %s: %s", file_path, e)
        return events

    with fh:
        content = fh.read()

    # Try full JSON first (Records array format)
    try:
        data = json.loads(content)
        records = data.get("Records", [])
        if not isinstance(records, list):
            records = [data]
        for rec in records:
            try:
                events.append(_normalize_record(rec))
            except Exception as e:
                logger.warning("CloudTrail parser: error processing record: %s", e)
        return events
    except json.JSONDecodeError:
        pass

    # Fall back to newline-delimited JSON
    for lineno, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            events.append(_normalize_record(rec))
        except json.JSONDecodeError:
            logger.debug("CloudTrail parser: skipping non-JSON line %d", lineno)
        except Exception as e:
            logger.warning("CloudTrail parser: error on line %d: %s", lineno, e)

    return events
