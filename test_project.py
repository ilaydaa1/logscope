"""Pytest tests for the core functions in project.py (CS50P requirement)."""

from datetime import datetime, timedelta

import pytest

from project import (
    analyze_log_entries,
    build_timeline,
    choose_bucket_size,
    classify_entry,
    detect_suspicious_activity,
    group_recurring_messages,
    is_failed_login,
    make_detection,
    normalize_message,
    parse_w3c_line,
    recurring_key,
    recurring_search_text,
    normalize_log_level,
    parse_log_line,
    parse_log_text,
    peak_window,
)

T0 = datetime(2026, 11, 11, 12, 0, 0)


def make_entry(seconds=0, ip="10.0.0.1", status=200, endpoint="/", level="INFO", method="GET", message=""):
    """Build a parsed entry like parse_log_line would return."""
    return {
        "timestamp": T0 + timedelta(seconds=seconds), "level": level, "ip": ip,
        "method": method, "endpoint": endpoint, "status": status, "message": message,
    }


# --------------------------------------------------------------------- normalize_log_level
def test_normalize_log_level():
    assert normalize_log_level("INFO") == "INFO"
    assert normalize_log_level("info") == "INFO"
    assert normalize_log_level("  Warning ") == "WARNING"
    assert normalize_log_level("[ERROR]") == "ERROR"
    assert normalize_log_level("ERROR:") == "ERROR"


def test_normalize_log_level_aliases():
    assert normalize_log_level("warn") == "WARNING"
    assert normalize_log_level("err") == "ERROR"
    assert normalize_log_level("fatal") == "CRITICAL"
    assert normalize_log_level("crit") == "CRITICAL"
    assert normalize_log_level("trace") == "DEBUG"


def test_normalize_log_level_invalid():
    with pytest.raises(ValueError):
        normalize_log_level("verbose")
    with pytest.raises(ValueError):
        normalize_log_level("")
    with pytest.raises(TypeError):
        normalize_log_level(None)
    with pytest.raises(TypeError):
        normalize_log_level(3)


# --------------------------------------------------------------------- parse_log_line
def test_parse_log_line():
    entry = parse_log_line('2026-11-11T14:23:01 WARNING 203.0.113.7 POST /login 401 - Failed login for user "admin"')
    assert entry == {
        "timestamp": datetime(2026, 11, 11, 14, 23, 1),
        "level": "WARNING",
        "ip": "203.0.113.7",
        "method": "POST",
        "endpoint": "/login",
        "status": 401,
        "message": 'Failed login for user "admin"',
    }


def test_parse_log_line_combined_format():
    line = '203.0.113.7 - - [11/Nov/2026:14:23:01 +0200] "GET /index.html HTTP/1.1" 503 512 "-" "curl/8.0"'
    entry = parse_log_line(line)
    assert entry["timestamp"] == datetime(2026, 11, 11, 12, 23, 1)  # converted to UTC
    assert entry["ip"] == "203.0.113.7"
    assert entry["method"] == "GET"
    assert entry["endpoint"] == "/index.html"
    assert entry["status"] == 503
    assert entry["level"] == "ERROR"  # inferred from the 5xx status
    assert entry["message"] == "curl/8.0"


def test_parse_log_line_simple_format():
    entry = parse_log_line("2026-11-11 08:00:00,250 fatal Database connection lost")
    assert entry["level"] == "CRITICAL"
    assert entry["timestamp"] == datetime(2026, 11, 11, 8, 0, 0, 250000)
    assert entry["message"] == "Database connection lost"
    assert entry["ip"] is None and entry["status"] is None


def test_parse_log_line_ipv6_and_missing_message():
    entry = parse_log_line("2026-11-11T14:23:01Z info ::1 GET /healthz 200")
    assert entry["ip"] == "::1"
    assert entry["message"] == ""


def test_parse_log_line_invalid():
    assert parse_log_line("") is None
    assert parse_log_line("   ") is None
    assert parse_log_line("this is not a log line") is None
    assert parse_log_line("2026-13-45T25:00:00 INFO 10.0.0.1 GET / 200") is None  # bad date
    assert parse_log_line("2026-11-11T14:23:01 INFO 999.1.1.1 GET / 200") is None  # bad IP
    assert parse_log_line("2026-11-11T14:23:01 INFO 10.0.0.1 GET / 999") is None  # bad status
    assert parse_log_line("2026-11-11T14:23:01 LOUD 10.0.0.1 GET / 200") is None  # bad level
    assert parse_log_line("2026-11-11T14:23:01 INFO 10.0.0.1 FETCH / 200") is None  # bad method
    assert parse_log_line("2026-11-11T14:23:01 INFO 10.0.0.1 GET / 200 " + "x" * 5000) is None  # too long
    with pytest.raises(TypeError):
        parse_log_line(None)


def test_parse_log_line_default_timezone():
    from zoneinfo import ZoneInfo

    istanbul = ZoneInfo("Europe/Istanbul")
    # No offset in the line: interpreted in the given zone, stored as UTC.
    entry = parse_log_line("2026-11-11 14:00:00 INFO 10.0.0.1 GET / 200", istanbul)
    assert entry["timestamp"] == datetime(2026, 11, 11, 11, 0, 0)
    # An explicit offset always wins over the default zone (no double conversion).
    entry = parse_log_line("2026-11-11T14:00:00Z INFO 10.0.0.1 GET / 200", istanbul)
    assert entry["timestamp"] == datetime(2026, 11, 11, 14, 0, 0)
    # Without a default zone, naive timestamps are UTC.
    assert parse_log_line("2026-11-11 14:00:00 INFO 10.0.0.1 GET / 200")["timestamp"] == datetime(2026, 11, 11, 14)


# --------------------------------------------------------------------- parse_log_text
def test_parse_log_text():
    text = "\n".join([
        "2026-11-11T10:00:00 INFO 10.0.0.1 GET / 200 - ok",
        "",
        "garbage line",
        "2026-11-11T10:00:01 ERROR 10.0.0.2 GET /api 500 - boom",
    ])
    entries, invalid = parse_log_text(text)
    assert len(entries) == 2
    assert invalid == 1  # blank lines are not counted as invalid
    assert [e["line_number"] for e in entries] == [1, 4]
    assert parse_log_text("") == ([], 0)


# --------------------------------------------------------------------- analyze_log_entries
def test_analyze_log_entries():
    entries = [
        make_entry(0, ip="10.0.0.1", status=200),
        make_entry(10, ip="10.0.0.1", status=404, level="WARNING"),
        make_entry(20, ip="10.0.0.2", status=500, level="ERROR"),
        make_entry(30, ip="10.0.0.1", status=200, level="CRITICAL"),
    ]
    summary = analyze_log_entries(entries)
    assert summary["total_entries"] == 4
    assert summary["level_counts"] == {"DEBUG": 0, "INFO": 1, "WARNING": 1, "ERROR": 1, "CRITICAL": 1}
    assert summary["status_counts"] == {"200": 2, "404": 1, "500": 1}
    assert summary["status_classes"]["2xx"] == 2 and summary["status_classes"]["5xx"] == 1
    assert summary["top_ips"][0] == {"ip": "10.0.0.1", "count": 3}
    assert summary["unique_ips"] == 2
    assert summary["error_rate"] == 50.0
    assert summary["duration_seconds"] == 30
    assert summary["start_time"] == "2026-11-11T12:00:00"
    assert sum(bucket["total"] for bucket in summary["timeline"]) == 4


def test_analyze_log_entries_empty():
    summary = analyze_log_entries([])
    assert summary["total_entries"] == 0
    assert summary["error_rate"] == 0.0
    assert summary["top_ips"] == []
    assert summary["timeline"] == []
    assert summary["start_time"] is None


def test_analyze_log_entries_invalid():
    with pytest.raises(TypeError):
        analyze_log_entries("not a list")


def test_build_timeline():
    entries = [make_entry(0), make_entry(5, level="ERROR"), make_entry(125)]
    timeline = build_timeline(entries)
    assert sum(b["total"] for b in timeline) == 3
    assert sum(b["errors"] for b in timeline) == 1
    assert len(timeline) <= 60
    assert build_timeline([]) == []


# --------------------------------------------------------------------- recurring issues
def test_normalize_message():
    assert normalize_message('Failed login for user "bob"') == "Failed login for user #"
    assert normalize_message("Request took 35 ms on 10.0.0.1:8080") == "Request took # ms on #"
    assert normalize_message("  extra   spaces  ") == "extra spaces"
    with pytest.raises(TypeError):
        normalize_message(None)


def test_group_recurring_messages():
    entries = [
        make_entry(0, level="ERROR", status=500, message="Timeout after 30 s", ip="10.0.0.1"),
        make_entry(60, level="ERROR", status=500, message="Timeout after 45 s", ip="10.0.0.2"),
        make_entry(90, level="ERROR", status=500, message="Timeout after 31 s", ip="10.0.0.1"),
        make_entry(10, level="CRITICAL", status=None, message="Disk 1 full"),
        make_entry(20, level="CRITICAL", status=None, message="Disk 2 full"),
        make_entry(30, level="WARNING", status=404, message="Not found"),   # only once
        make_entry(40, level="INFO", message="Request completed"),           # level not included
    ]
    groups = group_recurring_messages(entries)
    assert [g["pattern"] for g in groups] == ["Disk # full", "Timeout after # s"]  # CRITICAL first
    timeout = groups[1]
    assert timeout["count"] == 3
    assert timeout["ip_count"] == 2
    assert timeout["first_seen"] == T0 and timeout["last_seen"] == T0 + timedelta(seconds=90)
    assert timeout["search"] == "Timeout after"


def test_group_recurring_messages_edge_cases():
    assert group_recurring_messages([]) == []
    # Access-log lines with no message are grouped by request instead.
    entries = [make_entry(i, level="WARNING", status=404, endpoint=f"/item/{i}", message="") for i in range(3)]
    assert group_recurring_messages(entries)[0]["pattern"] == "GET /item/#"
    assert len(group_recurring_messages(entries, min_count=4)) == 0
    with pytest.raises(TypeError):
        group_recurring_messages("x")
    with pytest.raises(ValueError):
        group_recurring_messages([], min_count=0)


def test_recurring_key():
    assert recurring_key(make_entry(level="ERROR", message="Timeout after 30 s")) == "Timeout after # s"
    # Access-log lines whose message is only a browser name are grouped by request.
    apache = make_entry(level="WARNING", status=404, endpoint="/img/12.png", message="Mozilla/5.0 (Windows NT 10.0)")
    assert recurring_key(apache) == "GET /img/#.png"
    assert recurring_search_text("GET /img/#.png", apache["message"]) == "/img/"
    assert recurring_search_text("Timeout after # s", "Timeout after 30 s") == "Timeout after"


# --------------------------------------------------------------------- W3C / IIS
W3C_FIELDS = ("date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip "
              "cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken").split()


def test_parse_w3c_line():
    line = "2026-11-11 10:00:05 10.0.0.5 GET /shop/item.aspx id=7 443 - 203.0.113.9 Mozilla/5.0+(Windows) - 404 0 2 15"
    entry = parse_w3c_line(line, W3C_FIELDS)
    assert entry["timestamp"] == datetime(2026, 11, 11, 10, 0, 5)
    assert entry["ip"] == "203.0.113.9" and entry["method"] == "GET"
    assert entry["endpoint"] == "/shop/item.aspx?id=7" and entry["status"] == 404
    assert entry["level"] == "WARNING" and entry["message"] == "Mozilla/5.0 (Windows)"
    assert parse_w3c_line("too few values", W3C_FIELDS) is None
    assert parse_w3c_line(line.replace(" 404 ", " abc "), W3C_FIELDS) is None
    with pytest.raises(TypeError):
        parse_w3c_line(None, W3C_FIELDS)


def test_parse_log_text_w3c_context():
    header = "#Software: IIS\n#Fields: " + " ".join(W3C_FIELDS) + "\n"
    body = "2026-11-11 10:00:05 10.0.0.5 GET / - 443 - 203.0.113.9 - - 200 0 0 15\n"
    context = {}
    entries, invalid = parse_log_text(header, context=context)
    assert entries == [] and invalid == 0                     # directives are not "unreadable"
    entries, invalid = parse_log_text(body, context=context)  # a later chunk of the same file
    assert len(entries) == 1 and invalid == 0
    assert parse_log_text(body) == ([], 1)                    # without the header it is unreadable


# --------------------------------------------------------------------- detection helpers
def test_classify_entry():
    assert classify_entry(make_entry(ip="10.0.0.1", status=200)) == [("high_volume", "10.0.0.1")]
    assert ("brute_force", "10.0.0.1") in classify_entry(make_entry(ip="10.0.0.1", endpoint="/login", status=401))
    assert ("excessive_404", "10.0.0.1") in classify_entry(make_entry(ip="10.0.0.1", status=404))
    assert classify_entry(make_entry(ip=None, status=503)) == [("server_error_spike", None)]
    assert classify_entry(make_entry(ip=None, status=None)) == []


def test_make_detection():
    settings = {"threshold": 5, "window_seconds": 120}
    detection = make_detection("brute_force", "10.0.0.1", 20, T0, T0 + timedelta(seconds=90), 25, settings)
    assert detection["severity"] == "high" and detection["total_matches"] == 25
    assert make_detection("brute_force", "10.0.0.1", 4, T0, T0, 4, settings) is None


def test_choose_bucket_size():
    assert choose_bucket_size(0) == 10
    assert choose_bucket_size(3000) == 60          # 50 minutes -> 1-minute buckets
    assert choose_bucket_size(3600) == 300         # exactly 60 buckets is too many -> 5 minutes
    assert choose_bucket_size(10 ** 9) == 604800   # very long logs -> weekly buckets
def test_is_failed_login():
    assert is_failed_login(make_entry(endpoint="/login", status=401, method="POST"))
    assert is_failed_login(make_entry(endpoint="/api/auth/token", status=403))
    assert is_failed_login(make_entry(endpoint=None, status=None, message="Authentication failure for root"))
    assert not is_failed_login(make_entry(endpoint="/login", status=200))
    assert not is_failed_login(make_entry(endpoint="/products", status=401))


def test_peak_window():
    times = [T0 + timedelta(seconds=s) for s in (0, 10, 20, 200, 205, 210, 215)]
    count, first, last = peak_window(times, 60)
    assert count == 4
    assert first == T0 + timedelta(seconds=200)
    assert last == T0 + timedelta(seconds=215)
    assert peak_window([], 60) == (0, None, None)


# --------------------------------------------------------------------- detect_suspicious_activity
def test_detect_suspicious_activity():
    entries = [make_entry(i * 10, ip="203.0.113.5", endpoint="/login", status=401, method="POST") for i in range(6)]
    entries += [make_entry(i, ip="10.0.0.9") for i in range(5)]
    detections = detect_suspicious_activity(entries)
    assert len(detections) == 1
    detection = detections[0]
    assert detection["rule"] == "brute_force"
    assert detection["ip"] == "203.0.113.5"
    assert detection["count"] == 6
    assert detection["threshold"] == 5
    assert "not a confirmed attack" in detection["explanation"]


def test_detect_suspicious_activity_respects_time_window():
    # 30 failed logins spread over 5 hours (one every 10 minutes): never 5 in 120 s.
    slow = [make_entry(i * 600, ip="203.0.113.5", endpoint="/login", status=401) for i in range(30)]
    assert detect_suspicious_activity(slow) == []


def test_detect_suspicious_activity_all_rules():
    entries = (
        [make_entry(i * 5, ip="198.51.100.1", endpoint=f"/probe{i}", status=404) for i in range(25)]
        + [make_entry(i * 3, ip=f"10.0.1.{i}", status=503, level="CRITICAL") for i in range(12)]
        + [make_entry(i * 0.25, ip="198.51.100.2") for i in range(130)]
    )
    rules = {d["rule"] for d in detect_suspicious_activity(entries)}
    assert rules == {"excessive_404", "server_error_spike", "high_volume"}
    spike = next(d for d in detect_suspicious_activity(entries) if d["rule"] == "server_error_spike")
    assert spike["ip"] is None


def test_detect_suspicious_activity_custom_thresholds():
    entries = [make_entry(i, ip="10.0.0.1", endpoint="/login", status=401) for i in range(3)]
    assert detect_suspicious_activity(entries) == []
    custom = detect_suspicious_activity(entries, {"brute_force": {"threshold": 3}})
    assert [d["rule"] for d in custom] == ["brute_force"]


def test_detect_suspicious_activity_invalid_input():
    assert detect_suspicious_activity([]) == []
    with pytest.raises(ValueError):
        detect_suspicious_activity([], {"unknown_rule": {"threshold": 1}})
    with pytest.raises(ValueError):
        detect_suspicious_activity([], {"brute_force": {"threshold": 0}})
    with pytest.raises(ValueError):
        detect_suspicious_activity([], {"brute_force": {"window_seconds": "60"}})
