"""LogScope - Log Analysis Platform (CS50P Final Project).

This module holds the core, framework-independent logic of LogScope:

* ``parse_log_line``            - turn one raw log line into a normalized entry
* ``normalize_log_level``       - map level spellings (warn, ERR, fatal...) to one vocabulary
* ``parse_log_text``            - parse a whole file, counting invalid lines
* ``analyze_log_entries``       - compute statistics (levels, status codes, IPs, timeline)
* ``detect_suspicious_activity``- transparent, rule-based, time-window detection

The FastAPI web application in ``backend/app`` imports and uses these
functions directly, so there is exactly one implementation of the parsing,
analysis and detection logic.  ``main()`` starts that web application.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

LOG_LEVELS: tuple[str, ...] = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

# Common spellings found in real-world logs, mapped to the canonical level.
LEVEL_ALIASES: dict[str, str] = {
    "TRACE": "DEBUG",
    "DEBUG": "DEBUG",
    "INFO": "INFO",
    "INFORMATION": "INFO",
    "NOTICE": "INFO",
    "WARN": "WARNING",
    "WARNING": "WARNING",
    "ERR": "ERROR",
    "ERROR": "ERROR",
    "CRIT": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "FATAL": "CRITICAL",
    "ALERT": "CRITICAL",
    "EMERG": "CRITICAL",
    "EMERGENCY": "CRITICAL",
}

HTTP_METHODS: frozenset[str] = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"}
)

# Lines longer than this are rejected; protects against pathological input.
MAX_LINE_LENGTH = 4096

# Default detection rules. ``threshold`` events inside any sliding window of
# ``window_seconds`` trigger the rule. Explained in README.md.
DEFAULT_THRESHOLDS: dict[str, dict[str, int]] = {
    "brute_force": {"threshold": 5, "window_seconds": 120},
    "excessive_404": {"threshold": 20, "window_seconds": 300},
    "server_error_spike": {"threshold": 10, "window_seconds": 60},
    "high_volume": {"threshold": 120, "window_seconds": 60},
}

RULE_TITLES: dict[str, str] = {
    "brute_force": "Possible brute-force activity",
    "excessive_404": "Excessive 404 responses",
    "server_error_spike": "Server error spike",
    "high_volume": "Unusually high request volume",
}

SEVERITY_ORDER: dict[str, int] = {"high": 0, "medium": 1, "low": 2}

_TIMESTAMP = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"

# Format 1 - LogScope / application access log:
#   2026-11-11T14:23:01 WARNING 203.0.113.7 POST /login 401 - Failed login for user "admin"
APP_LOG_PATTERN = re.compile(
    rf"^(?P<timestamp>{_TIMESTAMP})\s+\[?(?P<level>[A-Za-z]+)\]?:?\s+"
    r"(?P<ip>[0-9A-Fa-f.:]+)\s+(?P<method>[A-Z]+)\s+(?P<endpoint>/\S*)\s+"
    r"(?P<status>\d{3})(?:\s+(?:-\s*)?(?P<message>.*))?$"
)

# Format 2 - Apache / Nginx "common" and "combined" log formats:
#   203.0.113.7 - - [11/Nov/2026:14:23:01 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8.0"
COMBINED_LOG_PATTERN = re.compile(
    r'^(?P<ip>[0-9A-Fa-f.:]+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<endpoint>\S+)(?: HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}) (?:\d+|-)(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?\s*$'
)

# Format 3 - plain application log without HTTP fields:
#   2026-11-11 14:23:01,123 ERROR Database connection lost
SIMPLE_LOG_PATTERN = re.compile(
    rf"^(?P<timestamp>{_TIMESTAMP})\s+\[?(?P<level>[A-Za-z]+)\]?:?\s+(?P<message>.+)$"
)

FAILED_LOGIN_PATHS = ("login", "signin", "sign-in", "auth", "session", "wp-login")
FAILED_LOGIN_MESSAGE = re.compile(
    r"(failed|invalid|unsuccessful|bad)\s+(login|password|credentials|authentication)"
    r"|authentication\s+fail|login\s+failed",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def main() -> None:
    """Start the LogScope web application with Uvicorn."""
    parser = argparse.ArgumentParser(description="LogScope - Log Analysis Platform")
    parser.add_argument("--host", default=os.environ.get("LOGSCOPE_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("LOGSCOPE_PORT", "8000")))
    args = parser.parse_args()

    import uvicorn  # imported lazily so the core functions can be used without it

    if args.host not in ("127.0.0.1", "localhost", "::1", "0.0.0.0", "::"):
        # Requests addressed to this host name are accepted by the request guard.
        hosts = os.environ.get("LOGSCOPE_ALLOWED_HOSTS", "")
        os.environ["LOGSCOPE_ALLOWED_HOSTS"] = ",".join(filter(None, [hosts, args.host]))
    if args.host in ("0.0.0.0", "::"):
        print("Warning: LogScope has no login. Listening on all interfaces exposes it to your network.")

    print(f"LogScope running at http://{args.host}:{args.port}  (press CTRL+C to stop)")
    uvicorn.run("backend.app.main:app", host=args.host, port=args.port)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def normalize_log_level(level: str) -> str:
    """Return the canonical log level for ``level``.

    Accepts different cases, surrounding brackets/colons and common aliases
    (``warn`` -> ``WARNING``, ``fatal`` -> ``CRITICAL``...).

    Raises:
        TypeError: if ``level`` is not a string.
        ValueError: if ``level`` is not a recognised log level.
    """
    if not isinstance(level, str):
        raise TypeError("level must be a string")
    key = level.strip().strip("[]:").strip().upper()
    if key not in LEVEL_ALIASES:
        raise ValueError(f"Unknown log level: {level!r}")
    return LEVEL_ALIASES[key]


def parse_log_line(line: str, default_timezone: tzinfo | None = None) -> dict[str, Any] | None:
    """Parse one raw log line into a normalized entry dictionary.

    Supported formats: LogScope/application access log, Apache/Nginx
    common or combined log format, and plain ``timestamp level message`` lines.

    Returns a dict with the keys ``timestamp`` (naive UTC ``datetime``),
    ``level``, ``ip``, ``method``, ``endpoint``, ``status`` and ``message``
    (fields that a format does not provide are ``None``), or ``None`` when the
    line is blank, too long or malformed.

    ``default_timezone`` says which zone timestamps *without* an offset were
    written in (for example Europe/Istanbul server time). If omitted they are
    assumed to be UTC. Timestamps that include an offset are never changed by it.

    Raises:
        TypeError: if ``line`` is not a string.
    """
    if not isinstance(line, str):
        raise TypeError("line must be a string")
    line = line.strip()
    if not line or len(line) > MAX_LINE_LENGTH:
        return None

    if match := APP_LOG_PATTERN.match(line):
        # Structurally an access-log line: if a field is invalid, the line is
        # invalid (we do not silently reinterpret it as a plain message).
        return _build_http_entry(
            timestamp=_parse_timestamp(match["timestamp"], default_timezone),
            level=match["level"],
            ip=match["ip"],
            method=match["method"],
            endpoint=match["endpoint"],
            status=match["status"],
            message=(match["message"] or "").strip(),
        )

    if match := COMBINED_LOG_PATTERN.match(line):
        try:
            timestamp = _to_naive_utc(datetime.strptime(match["timestamp"], "%d/%b/%Y:%H:%M:%S %z"))
        except ValueError:
            return None
        status = int(match["status"])
        return _build_http_entry(
            timestamp=timestamp,
            level=_level_from_status(status),
            ip=match["ip"],
            method=match["method"],
            endpoint=match["endpoint"],
            status=match["status"],
            message=match["agent"] or "",
        )

    if match := SIMPLE_LOG_PATTERN.match(line):
        timestamp = _parse_timestamp(match["timestamp"], default_timezone)
        try:
            level = normalize_log_level(match["level"])
        except ValueError:
            return None
        if timestamp is None:
            return None
        return {
            "timestamp": timestamp,
            "level": level,
            "ip": None,
            "method": None,
            "endpoint": None,
            "status": None,
            "message": match["message"].strip(),
        }

    return None


W3C_DIRECTIVES = ("#Software:", "#Version:", "#Date:", "#Fields:", "#Remark:", "#Start-Date:", "#End-Date:")


def parse_w3c_line(line: str, fields: list[str]) -> dict[str, Any] | None:
    """Parse one data line of a W3C extended log (the IIS default format).

    ``fields`` comes from the file's ``#Fields:`` directive, e.g.
    ``date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username
    c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken``.
    W3C timestamps are UTC by definition. Returns None for a malformed line.
    """
    if not isinstance(line, str) or not isinstance(fields, list):
        raise TypeError("line must be a string and fields a list")
    values = line.split()
    if not values or len(values) != len(fields):
        return None
    row = dict(zip(fields, values))
    try:
        timestamp = datetime.fromisoformat(f"{row['date']}T{row['time']}")
        status = int(row["sc-status"])
    except (KeyError, ValueError):
        return None
    query = row.get("cs-uri-query", "-")
    agent = row.get("cs(User-Agent)", "-")
    return _build_http_entry(
        timestamp=_to_naive_utc(timestamp.replace(tzinfo=timezone.utc)),
        level=_level_from_status(status),
        ip=row.get("c-ip", ""),
        method=row.get("cs-method", ""),
        endpoint=row.get("cs-uri-stem", "") + ("" if query in ("-", "") else f"?{query}"),
        status=str(status),
        message="" if agent == "-" else agent.replace("+", " "),
    )


def parse_log_text(
    text: str, default_timezone: tzinfo | None = None, context: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Parse a whole log document (or a newly appended part of one).

    Returns ``(entries, invalid_line_count)``. Blank lines and W3C directive
    lines (``#Fields:`` ...) are ignored and not counted as invalid. Each
    entry gets a 1-based ``line_number``.

    ``context`` carries parser state between calls, so a file read in several
    parts keeps its W3C ``#Fields:`` definition; it is updated in place.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    context = context if context is not None else {}
    entries: list[dict[str, Any]] = []
    invalid = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith(W3C_DIRECTIVES):
            if stripped.startswith("#Fields:"):
                context["w3c_fields"] = stripped[len("#Fields:"):].split()
            continue
        entry = None
        if context.get("w3c_fields"):
            entry = parse_w3c_line(stripped, context["w3c_fields"])
        if entry is None:
            entry = parse_log_line(raw, default_timezone)
        if entry is None:
            invalid += 1
            continue
        entry["line_number"] = number
        entries.append(entry)
    return entries, invalid


def _build_http_entry(
    *, timestamp: datetime | None, level: str, ip: str, method: str,
    endpoint: str, status: str, message: str,
) -> dict[str, Any] | None:
    """Validate the fields of an HTTP-style line and assemble the entry."""
    try:
        normalized_level = normalize_log_level(level)
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return None
    code = int(status)
    if timestamp is None or method not in HTTP_METHODS or not 100 <= code <= 599:
        return None
    return {
        "timestamp": timestamp,
        "level": normalized_level,
        "ip": ip,
        "method": method,
        "endpoint": endpoint[:512],
        "status": code,
        "message": message[:1024],
    }


def _parse_timestamp(text: str, default_timezone: tzinfo | None = None) -> datetime | None:
    """Parse an ISO-8601-like timestamp and return it as naive UTC.

    Values without an offset are interpreted in ``default_timezone`` (UTC if None).
    """
    try:
        # Python's logging module writes "2026-11-11 10:00:00,123".
        moment = datetime.fromisoformat(text.replace(",", "."))
    except ValueError:
        return None
    if moment.tzinfo is None and default_timezone is not None:
        moment = moment.replace(tzinfo=default_timezone)
    return _to_naive_utc(moment)


def _to_naive_utc(moment: datetime) -> datetime:
    """Store every timestamp as naive UTC so that all comparisons are consistent."""
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc).replace(tzinfo=None)
    return moment


def _level_from_status(status: int) -> str:
    """Infer a log level for access-log formats that have no level field."""
    if status >= 500:
        return "ERROR"
    if status >= 400:
        return "WARNING"
    return "INFO"


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #


def analyze_log_entries(entries: list[dict[str, Any]], top_n: int = 10) -> dict[str, Any]:
    """Compute summary statistics for parsed log entries.

    The result only contains JSON-serializable values so it can be stored as-is.
    An empty list produces a valid, all-zero summary.
    """
    if not isinstance(entries, list):
        raise TypeError("entries must be a list of parsed entries")

    level_counts = {level: 0 for level in LOG_LEVELS}
    status_counts: Counter[int] = Counter()
    ip_counts: Counter[str] = Counter()
    endpoint_counts: Counter[str] = Counter()
    method_counts: Counter[str] = Counter()
    timestamps: list[datetime] = []

    for entry in entries:
        level = entry.get("level")
        if level in level_counts:
            level_counts[level] += 1
        if entry.get("status") is not None:
            status_counts[entry["status"]] += 1
        if entry.get("ip"):
            ip_counts[entry["ip"]] += 1
        if entry.get("endpoint"):
            endpoint_counts[entry["endpoint"]] += 1
        if entry.get("method"):
            method_counts[entry["method"]] += 1
        if entry.get("timestamp"):
            timestamps.append(entry["timestamp"])

    total = len(entries)
    status_classes = {f"{n}xx": 0 for n in range(1, 6)}
    for code, count in status_counts.items():
        status_classes[f"{code // 100}xx"] += count

    start = min(timestamps) if timestamps else None
    end = max(timestamps) if timestamps else None
    errors = level_counts["ERROR"] + level_counts["CRITICAL"]

    return {
        "total_entries": total,
        "level_counts": level_counts,
        "status_counts": {str(code): status_counts[code] for code in sorted(status_counts)},
        "status_classes": status_classes,
        "top_ips": [{"ip": ip, "count": n} for ip, n in ip_counts.most_common(top_n)],
        "top_endpoints": [{"endpoint": ep, "count": n} for ep, n in endpoint_counts.most_common(top_n)],
        "method_counts": dict(method_counts.most_common()),
        "unique_ips": len(ip_counts),
        "start_time": start.isoformat() if start else None,
        "end_time": end.isoformat() if end else None,
        "duration_seconds": int((end - start).total_seconds()) if start and end else 0,
        "error_rate": round(errors / total * 100, 2) if total else 0.0,
        "timeline": build_timeline(entries),
    }


# Candidate bucket sizes for the activity chart, from 10 seconds to 1 week.
_BUCKET_SIZES = (10, 30, 60, 300, 600, 900, 1800, 3600, 10800, 21600, 43200, 86400, 604800)


def choose_bucket_size(span_seconds: float, max_buckets: int = 60) -> int:
    """Smallest bucket size (seconds) giving at most ``max_buckets`` buckets."""
    return next((s for s in _BUCKET_SIZES if span_seconds / s < max_buckets), _BUCKET_SIZES[-1])


def build_timeline(entries: list[dict[str, Any]], max_buckets: int = 60) -> list[dict[str, Any]]:
    """Group entries into evenly sized time buckets for the activity chart.

    Picks the smallest bucket size that yields at most ``max_buckets`` buckets,
    and includes empty buckets so the chart shows real gaps in activity.
    """
    dated = [e for e in entries if e.get("timestamp")]
    if not dated:
        return []
    epoch = datetime(1970, 1, 1)
    start = min(e["timestamp"] for e in dated)
    end = max(e["timestamp"] for e in dated)
    span = (end - start).total_seconds()
    size = choose_bucket_size(span, max_buckets)

    first = int((start - epoch).total_seconds()) // size
    last = int((end - epoch).total_seconds()) // size
    totals = [0] * (last - first + 1)
    errors = [0] * (last - first + 1)
    for entry in dated:
        index = int((entry["timestamp"] - epoch).total_seconds()) // size - first
        totals[index] += 1
        if entry.get("level") in ("ERROR", "CRITICAL"):
            errors[index] += 1

    return [
        {
            "time": (epoch + timedelta(seconds=(first + i) * size)).isoformat(),
            "total": totals[i],
            "errors": errors[i],
        }
        for i in range(len(totals))
    ]


# Quoted values, hex ids and numbers (incl. IPs, durations, ids) vary between
# otherwise identical messages; they are masked so the messages group together.
_VARIABLE_PARTS = re.compile(r'"[^"]*"|\'[^\']*\'|\b0x[0-9a-fA-F]+\b|\d+(?:[.:]\d+)*')
_SEVERITY_RANK = {"CRITICAL": 0, "ERROR": 1, "WARNING": 2, "INFO": 3, "DEBUG": 4}


def normalize_message(message: str) -> str:
    """Mask the variable parts of a log message: 'took 35 ms' -> 'took # ms'."""
    if not isinstance(message, str):
        raise TypeError("message must be a string")
    return " ".join(_VARIABLE_PARTS.sub("#", message).split())


def recurring_key(entry: dict[str, Any]) -> str:
    """The pattern under which an entry is grouped as a recurring issue.

    Normally the normalized message. Access-log lines whose "message" is only
    a browser name (Apache/Nginx/IIS user agent) or empty are grouped by the
    normalized request instead, e.g. ``GET /item/#``.
    """
    message = entry.get("message") or ""
    pattern = normalize_message(message)
    if entry.get("status") is not None and (not pattern or _looks_like_user_agent(message)):
        pattern = normalize_message(f"{entry.get('method') or ''} {entry.get('endpoint') or ''}")
    return pattern


_USER_AGENT = re.compile(r"^(Mozilla/|curl/|Wget/|python-requests/|Go-http-client/|okhttp/|Java/|"
                         r"PostmanRuntime/|[\w.-]+bot\b|[\w.-]+/[\d.]+(\s|$))", re.IGNORECASE)


def _looks_like_user_agent(message: str) -> bool:
    return bool(_USER_AGENT.match(message.strip()))


def message_search_text(message: str) -> str:
    """A literal leading piece of a message (before the first variable part), for text search."""
    literal = _VARIABLE_PARTS.split(message or "")[0].strip()
    return literal if len(literal) >= 4 else ""


def recurring_search_text(pattern: str, example: str) -> str:
    """Text to search for the records of a recurring issue (message or request path)."""
    if normalize_message(example or "") == pattern:
        return message_search_text(example)
    path = pattern.split(" ", 1)[-1].split("#", 1)[0].strip()  # "GET /products/#" -> "/products/"
    return path if len(path) >= 4 else ""


def group_recurring_messages(
    entries: list[dict[str, Any]],
    levels: tuple[str, ...] = ("WARNING", "ERROR", "CRITICAL"),
    min_count: int = 2,
    limit: int | None = 20,
) -> list[dict[str, Any]]:
    """Group repeated problems (same level, status and message pattern).

    Returns the groups seen at least ``min_count`` times, most severe and most
    frequent first. Each group has ``level``, ``status``, ``pattern``,
    ``count``, ``first_seen``, ``last_seen``, ``example``, ``ip_count`` and
    ``search`` (a literal piece of the message, usable for a text search).

    Raises:
        TypeError: if ``entries`` is not a list.
        ValueError: if ``min_count`` is smaller than 1.
    """
    if not isinstance(entries, list):
        raise TypeError("entries must be a list of parsed entries")
    if min_count < 1:
        raise ValueError("min_count must be at least 1")

    groups: dict[tuple, dict[str, Any]] = {}
    for entry in entries:
        if entry.get("level") not in levels:
            continue
        message = entry.get("message") or ""
        pattern = recurring_key(entry)
        key = (entry["level"], entry.get("status"), pattern)
        group = groups.get(key)
        moment = entry.get("timestamp")
        if group is None:
            groups[key] = group = {
                "level": entry["level"], "status": entry.get("status"), "pattern": pattern,
                "count": 0, "first_seen": moment, "last_seen": moment,
                "example": message, "_ips": set(),
            }
        group["count"] += 1
        if moment is not None:
            if group["first_seen"] is None or moment < group["first_seen"]:
                group["first_seen"] = moment
            if group["last_seen"] is None or moment > group["last_seen"]:
                group["last_seen"] = moment
        if entry.get("ip"):
            group["_ips"].add(entry["ip"])

    result = []
    for group in groups.values():
        if group["count"] < min_count:
            continue
        ips = group.pop("_ips")
        group["ip_count"] = len(ips)
        group["search"] = recurring_search_text(group["pattern"], group["example"])
        result.append(group)
    result.sort(key=lambda g: (_SEVERITY_RANK.get(g["level"], 9), -g["count"], g["pattern"]))
    return result[:limit] if limit else result


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #


def is_failed_login(entry: dict[str, Any]) -> bool:
    """Return True if an entry looks like a failed authentication attempt."""
    endpoint = (entry.get("endpoint") or "").split("?", 1)[0].lower()
    if entry.get("status") in (401, 403) and any(p in endpoint for p in FAILED_LOGIN_PATHS):
        return True
    return bool(FAILED_LOGIN_MESSAGE.search(entry.get("message") or ""))


def peak_window(timestamps: list[datetime], window_seconds: int) -> tuple[int, datetime | None, datetime | None]:
    """Find the busiest sliding time window.

    ``timestamps`` must be sorted. Returns ``(count, first, last)`` for the
    window of length ``window_seconds`` containing the most events.
    Uses a two-pointer sweep, so it runs in O(n).
    """
    best: tuple[int, datetime | None, datetime | None] = (0, None, None)
    left = 0
    for right, moment in enumerate(timestamps):
        while (moment - timestamps[left]).total_seconds() > window_seconds:
            left += 1
        count = right - left + 1
        if count > best[0]:
            best = (count, timestamps[left], moment)
    return best


RULE_NOUNS: dict[str, str] = {
    "brute_force": "failed login attempts",
    "excessive_404": "404 Not Found responses",
    "server_error_spike": "HTTP 5xx responses",
    "high_volume": "requests",
}


def classify_entry(entry: dict[str, Any]) -> list[tuple[str, str | None]]:
    """The ``(rule, ip)`` groups an entry counts toward (ip is None for global rules)."""
    groups: list[tuple[str, str | None]] = []
    ip, status = entry.get("ip"), entry.get("status")
    if ip:
        groups.append(("high_volume", ip))
        if is_failed_login(entry):
            groups.append(("brute_force", ip))
        if status == 404:
            groups.append(("excessive_404", ip))
    if status is not None and 500 <= status <= 599:
        groups.append(("server_error_spike", None))
    return groups


def detect_suspicious_activity(
    entries: list[dict[str, Any]],
    thresholds: dict[str, dict[str, int]] | None = None,
) -> list[dict[str, Any]]:
    """Apply the rule-based detectors and return the flagged patterns.

    Rules (see ``DEFAULT_THRESHOLDS``):

    * ``brute_force``        - failed logins from one IP within a time window
    * ``excessive_404``      - 404 responses for one IP within a time window
    * ``server_error_spike`` - HTTP 5xx responses (all IPs) within a time window
    * ``high_volume``        - requests from one IP within a time window

    Each rule uses the *peak* sliding window, not a global count, so the same
    number of events spread over a day is not flagged. Results are possible
    patterns that deserve review, not confirmed attacks.

    Raises:
        ValueError: if a threshold override is unknown or not a positive int.
    """
    config = _merge_thresholds(thresholds)
    dated = sorted((e for e in entries if e.get("timestamp")), key=lambda e: e["timestamp"])

    times_by_group: dict[tuple[str, str | None], list[datetime]] = defaultdict(list)
    for entry in dated:
        for group in classify_entry(entry):
            times_by_group[group].append(entry["timestamp"])

    detections: list[dict[str, Any]] = []
    for (rule, ip), times in times_by_group.items():
        count, first, last = peak_window(times, config[rule]["window_seconds"])
        if detection := make_detection(rule, ip, count, first, last, len(times), config[rule]):
            detections.append(detection)

    detections.sort(key=lambda d: (SEVERITY_ORDER[d["severity"]], -d["count"], d["rule"]))
    return detections


def _merge_thresholds(overrides: dict[str, dict[str, int]] | None) -> dict[str, dict[str, int]]:
    """Combine user overrides with the defaults, validating every value."""
    config = {rule: dict(values) for rule, values in DEFAULT_THRESHOLDS.items()}
    for rule, values in (overrides or {}).items():
        if rule not in config:
            raise ValueError(f"Unknown detection rule: {rule!r}")
        for key, value in values.items():
            if key not in config[rule]:
                raise ValueError(f"Unknown setting {key!r} for rule {rule!r}")
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{rule}.{key} must be a positive integer")
            config[rule][key] = value
    return config


def make_detection(
    rule: str, ip: str | None, count: int, first: datetime | None, last: datetime | None,
    total: int, settings: dict[str, int],
) -> dict[str, Any] | None:
    """Build a detection when the peak window ``count`` reaches the rule threshold, else None.

    ``first``/``last`` delimit the peak window and ``total`` is the number of
    matching events in the whole log for this rule and IP.
    """
    threshold, window = settings["threshold"], settings["window_seconds"]
    if count < threshold or first is None or last is None:
        return None
    noun = RULE_NOUNS[rule]

    ratio = count / threshold
    severity = "high" if ratio >= 4 else "medium" if ratio >= 2 else "low"
    source = f"from {ip}" if ip else "across all clients"
    # Times are deliberately not embedded in the text: they are stored in
    # first_seen/last_seen and converted to the viewer's timezone on display.
    explanation = (
        f"{count} {noun} {source} within {window} seconds. "
        f"Rule threshold: {threshold} in {window} s. "
        f"{total} matching events in total. "
        "This is a pattern worth reviewing, not a confirmed attack."
    )
    return {
        "rule": rule,
        "title": RULE_TITLES[rule],
        "severity": severity,
        "ip": ip,
        "count": count,
        "total_matches": total,
        "threshold": threshold,
        "window_seconds": window,
        "first_seen": first,
        "last_seen": last,
        "explanation": explanation,
    }


if __name__ == "__main__":
    main()
