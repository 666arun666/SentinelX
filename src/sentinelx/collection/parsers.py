import json
import re
import shlex
from datetime import UTC, datetime
from typing import Any

# Pre-compile common regexes
# Example syslog/auth log: "Oct 12 10:11:12 hostname sshd[1234]: Failed password for invalid user from 1.2.3.4 port 123"
SYSLOG_TS_PATTERN = re.compile(
    r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s+(.*)$"
)

IPV4_PATTERN = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


def extract_indicators(raw_log: str) -> dict[str, Any]:
    """Extract IOCs deterministically without LLMs or external enrichment."""
    indicators = {}
    ips = IPV4_PATTERN.findall(raw_log)
    if ips:
        # Just grab the first plausible IP as source if we can't parse it structurally,
        # but normally we want structured parsing. This is a fallback indicator extraction.
        indicators["ipv4"] = list(set(ips))
    return indicators


def parse_syslog_timestamp(ts_str: str) -> datetime:
    """
    Parses a month-day-time syslog timestamp and infers the year.
    Returns UTC datetime (naive in python, but conceptually UTC or local depending on server).
    For M2, we use configured/default local timezone assumption, then convert to UTC.
    For simplicity here we assume it's current year, and if it's in the future, it's last year.
    """
    now = datetime.now(UTC)
    try:
        dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")  # noqa: DTZ007
        dt = dt.replace(year=now.year, tzinfo=UTC)
        if dt > now:
            dt = dt.replace(year=now.year - 1)
        # Assuming system local time is UTC for this basic implementation as per typical cloud servers.
        # Can be enhanced with pytz if a specific tz is configured.
        return dt
    except ValueError:
        return now


def parse_auth_log(raw_log: str) -> dict[str, Any]:
    """Parse auth.log line deterministically."""
    result = {
        "raw_log": raw_log,
        "indicators": extract_indicators(raw_log),
        "event_type": "system",
    }

    match = SYSLOG_TS_PATTERN.match(raw_log)
    if match:
        ts_str, hostname, process_str, message = match.groups()
        result["event_time"] = parse_syslog_timestamp(ts_str)
        result["hostname"] = hostname
        result["message"] = message

        # Parse process and pid
        if "[" in process_str and "]" in process_str:
            proc, _ = process_str.split("[", 1)
            result["process"] = proc
        else:
            result["process"] = process_str

        # SSH parsing heuristic
        if result["process"] == "sshd":
            result["event_type"] = "ssh"
            if "Failed password" in message:
                result["severity"] = "high"
                result["event_type"] = "authentication_failed"
            elif "Accepted" in message:
                result["severity"] = "info"
                result["event_type"] = "authentication_success"

            # Try to extract user and IP from sshd message
            # e.g., "Failed password for root from 1.2.3.4 port 1234"
            m = re.search(r"(?:for|user)\s+([^\s]+)\s+from\s+([0-9\.]+)", message)
            if m:
                result["username"] = m.group(1)
                if m.group(1) == "invalid":
                    # "Failed password for invalid user root"
                    m2 = re.search(
                        r"invalid user\s+([^\s]+)\s+from\s+([0-9\.]+)", message
                    )
                    if m2:
                        result["username"] = m2.group(1)
                        result["source_ip"] = m2.group(2)
                else:
                    result["source_ip"] = m.group(2)
        elif result["process"] == "sudo":
            result["event_type"] = "sudo"
            if "COMMAND=" in message:
                cmd_match = re.search(r"COMMAND=(.*)", message)
                if cmd_match:
                    result["command"] = cmd_match.group(1)
    else:
        result["event_time"] = datetime.now(UTC)

    return result


def parse_syslog(raw_log: str) -> dict[str, Any]:
    """Parse general syslog line."""
    result = {
        "raw_log": raw_log,
        "indicators": extract_indicators(raw_log),
        "event_type": "system",
    }
    match = SYSLOG_TS_PATTERN.match(raw_log)
    if match:
        ts_str, hostname, process_str, message = match.groups()
        result["event_time"] = parse_syslog_timestamp(ts_str)
        result["hostname"] = hostname
        result["message"] = message
        if "[" in process_str:
            result["process"] = process_str.split("[")[0]
        else:
            result["process"] = process_str
    else:
        result["event_time"] = datetime.now(UTC)
    return result


def parse_journal_json(raw_json: str) -> dict[str, Any] | None:
    """Parse journalctl json output."""
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return None

    result = {
        "raw_log": raw_json,
        "indicators": extract_indicators(raw_json),
        "event_type": "system",
    }

    # __REALTIME_TIMESTAMP is in microseconds
    if "__REALTIME_TIMESTAMP" in data:
        try:
            ts_us = int(data["__REALTIME_TIMESTAMP"])
            result["event_time"] = datetime.fromtimestamp(ts_us / 1000000.0, tz=UTC)
        except ValueError:
            result["event_time"] = datetime.now(UTC)
    else:
        result["event_time"] = datetime.now(UTC)

    result["hostname"] = data.get("_HOSTNAME")
    result["process"] = data.get("_COMM")
    result["message"] = data.get("MESSAGE")

    # Example cursor: "s=1234;i=5678;b=9012;m=3456;t=7890;x=1234"
    if "__CURSOR" in data:
        result["_cursor"] = data["__CURSOR"]

    return result


def parse_auditd(raw_log: str) -> dict[str, Any]:
    """Parse auditd key=value format safely."""
    result = {
        "raw_log": raw_log,
        "indicators": extract_indicators(raw_log),
        "event_type": "audit",
    }
    result["event_time"] = datetime.now(UTC)  # Fallback

    # Audit log format: type=SYSCALL msg=audit(1610000000.123:456): arch=c000003e syscall=59 ...
    # Extract timestamp if possible
    ts_match = re.search(r"msg=audit\(([0-9\.]+):\d+\)", raw_log)
    if ts_match:
        try:
            result["event_time"] = datetime.fromtimestamp(
                float(ts_match.group(1)), tz=UTC
            )
        except ValueError:
            pass

    # Extract key=value using shlex
    try:
        # Split by space, keeping quoted strings together
        tokens = shlex.split(raw_log)
        kv_pairs = {}
        for token in tokens:
            if "=" in token:
                k, v = token.split("=", 1)
                kv_pairs[k] = v

        if "exe" in kv_pairs:
            result["file_path"] = kv_pairs["exe"]
            result["process"] = kv_pairs["exe"]
        if "comm" in kv_pairs:
            result["command"] = kv_pairs["comm"]
        if "res" in kv_pairs:
            result["severity"] = "info" if kv_pairs["res"] == "success" else "high"

        result["message"] = raw_log
    except ValueError:
        # shlex failed on malformed quotes
        result["message"] = raw_log

    return result
