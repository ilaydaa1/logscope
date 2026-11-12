"""Tests for automatic folder monitoring (backend/app/services/monitor.py)."""

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from backend.app.database import SessionLocal, init_db
from backend.app.main import app
from backend.app.models import Analysis, LogEntry, WatchedFile
from backend.app.services import monitor


def line(i: int, level: str = "INFO", status: int = 200, message: str = "ok") -> str:
    return f"2026-11-11T10:{i // 60:02d}:{i % 60:02d}Z {level} 10.0.0.{i % 5 + 1} GET /page/{i} {status} - {message}\n"


@pytest.fixture(autouse=True)
def immediate_statistics(monkeypatch):
    """Refresh statistics on every scan so tests can check them right away."""
    monkeypatch.setattr(monitor, "STATS_INTERVAL", 0)
    monkeypatch.setattr(monitor, "REFRESH_DURING_BACKLOG", 0)


@pytest.fixture
def db():
    init_db()
    session = SessionLocal()
    yield session
    monitor.stop_monitoring(session)
    session.close()


@pytest.fixture
def folder(tmp_path):
    path = tmp_path / "logs"
    path.mkdir()
    return path


def start(db, folder, include_existing=True):
    monitor.start_monitoring(db, str(folder), "UTC", include_existing)


def watched(db, name):
    return db.scalar(select(WatchedFile).where(WatchedFile.path.endswith(name)))


def records(db, name):
    wf = watched(db, name)
    db.refresh(wf)
    if not wf.analysis_id:
        return 0
    return db.scalar(select(func.count()).select_from(LogEntry).where(LogEntry.analysis_id == wf.analysis_id))


def write(path, text, mode="a"):
    with open(path, mode, encoding="utf-8", newline="") as handle:
        handle.write(text)


# ------------------------------------------------------------------ settings and permission

def test_validate_directory(folder):
    assert monitor.validate_directory(str(folder)) == folder.resolve()
    with pytest.raises(monitor.MonitorError, match="full path"):
        monitor.validate_directory("relative/logs")
    with pytest.raises(monitor.MonitorError, match="does not exist"):
        monitor.validate_directory(str(folder / "missing"))
    (folder / "file.log").write_text("x")
    with pytest.raises(monitor.MonitorError, match="not a folder"):
        monitor.validate_directory(str(folder / "file.log"))
    with pytest.raises(monitor.MonitorError, match="Enter the full path"):
        monitor.validate_directory("  ")


def test_nothing_is_read_without_permission(db, folder):
    write(folder / "app.log", line(1))
    result = monitor.scan_once(db)  # monitoring never started
    assert result.state == "stopped"
    assert db.scalar(select(func.count()).select_from(WatchedFile)) == 0


def test_only_log_files_in_the_folder_are_read(db, folder):
    write(folder / "app.log", line(1))
    write(folder / "notes.md", line(2))
    (folder / "sub").mkdir()
    write(folder / "sub" / "nested.log", line(3))
    start(db, folder)
    monitor.scan_once(db)
    names = {os.path.basename(wf.path) for wf in db.scalars(select(WatchedFile))}
    assert names == {"app.log"}


# ------------------------------------------------------------------ incremental reading

def test_new_file_and_appended_lines_are_processed_once(db, folder):
    start(db, folder)
    log = folder / "app.log"
    write(log, line(1) + line(2) + line(3))
    result = monitor.scan_once(db)
    assert result.new_records == 3
    assert records(db, "app.log") == 3

    write(log, line(4) + line(5))
    result = monitor.scan_once(db)
    assert result.new_records == 2                       # only the new lines
    assert records(db, "app.log") == 5
    assert monitor.scan_once(db).new_records == 0        # nothing new, nothing re-read

    analysis = db.get(Analysis, watched(db, "app.log").analysis_id)
    db.refresh(analysis)
    assert analysis.source == "monitor"
    assert analysis.total_entries == 5
    assert analysis.summary["total_entries"] == 5        # statistics refreshed
    numbers = sorted(db.scalars(select(LogEntry.line_number).where(LogEntry.analysis_id == analysis.id)))
    assert numbers == [1, 2, 3, 4, 5]


def test_unfinished_line_waits_for_newline(db, folder):
    start(db, folder)
    log = folder / "app.log"
    full = line(2)
    write(log, line(1) + full[:20])                      # second line still being written
    assert monitor.scan_once(db).new_records == 1
    write(log, full[20:])
    assert monitor.scan_once(db).new_records == 1
    assert records(db, "app.log") == 2


def test_last_line_without_newline_is_read_once_file_is_stable(db, folder):
    start(db, folder)
    log = folder / "app.log"
    write(log, line(1) + line(2).rstrip("\n"))
    assert monitor.scan_once(db).new_records == 1        # first look: may still be written
    assert monitor.scan_once(db).new_records == 1        # unchanged since: treat as complete
    assert records(db, "app.log") == 2


def test_existing_content_can_be_skipped(db, folder):
    log = folder / "app.log"
    write(log, line(1) + line(2))
    start(db, folder, include_existing=False)
    assert monitor.scan_once(db).new_records == 0
    write(log, line(3))
    assert monitor.scan_once(db).new_records == 1
    assert records(db, "app.log") == 1


def test_large_file_is_read_in_chunks(db, folder, monkeypatch):
    monkeypatch.setattr(monitor, "CHUNK_BYTES", 300)
    start(db, folder)
    write(folder / "big.log", "".join(line(i) for i in range(40)))
    first = monitor.scan_once(db)
    assert first.backlog and 0 < first.new_records < 40
    for _ in range(50):
        if not monitor.scan_once(db).backlog:
            break
    assert records(db, "big.log") == 40


# ------------------------------------------------------------------ rotation, missing, errors

def test_truncated_file_is_read_again(db, folder):
    start(db, folder)
    log = folder / "app.log"
    write(log, line(1) + line(2) + line(3))
    monitor.scan_once(db)
    write(log, line(10), mode="w")                        # copy-truncate style rotation
    assert monitor.scan_once(db).new_records == 1
    assert "rotated" in watched(db, "app.log").message
    assert records(db, "app.log") == 4


def test_replaced_file_is_read_from_start(db, folder):
    start(db, folder)
    log = folder / "app.log"
    write(log, line(1) + line(2))
    monitor.scan_once(db)
    replacement = folder / "app.log.new"
    write(replacement, line(20) + line(21) + line(22) + line(23))
    os.replace(replacement, log)                          # rename-style rotation (new file)
    assert monitor.scan_once(db).new_records == 4
    assert records(db, "app.log") == 6


def test_missing_file_is_reported(db, folder):
    start(db, folder)
    log = folder / "app.log"
    write(log, line(1))
    monitor.scan_once(db)
    log.unlink()
    monitor.scan_once(db)
    assert watched(db, "app.log").status == "missing"


def test_malformed_and_binary_content(db, folder):
    start(db, folder)
    write(folder / "app.log", line(1) + "garbage line\n" + line(2))
    (folder / "blob.txt").write_bytes(b"abc\x00def\n")
    result = monitor.scan_once(db)
    assert result.new_records == 2 and result.invalid_lines == 1
    blob = watched(db, "blob.txt")
    assert blob.status == "error" and "Binary" in blob.message
    assert monitor.scan_once(db).new_records == 0         # binary part is not retried


def test_permission_error_is_reported(db, folder, monkeypatch):
    start(db, folder)
    write(folder / "app.log", line(1))

    def deny(*_args):
        raise PermissionError("denied")

    monkeypatch.setattr(monitor, "_read_chunk", deny)
    monitor.scan_once(db)
    wf = watched(db, "app.log")
    assert wf.status == "error" and "Permission denied" in wf.message


def test_removed_folder_is_reported(db, folder):
    start(db, folder)
    folder.rmdir()
    result = monitor.run_scan(db)
    assert result.error == "The monitored folder no longer exists."
    assert monitor.monitor_status(db)["last_error"] == result.error


# ------------------------------------------------------------------ controls and status

def test_pause_resume_and_stop(db, folder):
    start(db, folder)
    log = folder / "app.log"
    write(log, line(1))
    monitor.scan_once(db)
    monitor.pause_monitoring(db)
    write(log, line(2))
    assert monitor.scan_once(db).state == "paused"
    assert records(db, "app.log") == 1
    monitor.resume_monitoring(db)
    assert monitor.scan_once(db).new_records == 1
    analysis_id = watched(db, "app.log").analysis_id
    monitor.stop_monitoring(db)
    assert db.scalar(select(func.count()).select_from(WatchedFile)) == 0
    assert db.get(Analysis, analysis_id) is not None      # results are kept


def test_monitor_pages_and_status_api(db, folder):
    with TestClient(app) as client:
        response = client.post("/monitor/start", data={"directory": str(folder), "timezone": "UTC"})
        assert response.status_code == 400 and "Confirm" in response.text
        response = client.post("/monitor/start", data={"directory": str(folder / "nope"), "timezone": "UTC",
                                                        "consent": "1"})
        assert response.status_code == 400 and "does not exist" in response.text

        response = client.post("/monitor/start", data={"directory": str(folder), "timezone": "UTC",
                                                       "include_existing": "1", "consent": "1"},
                               follow_redirects=False)
        assert response.status_code == 303
        write(folder / "web.log", "".join(line(i, "ERROR", 500, f"Timeout after {i} s") for i in range(12)))
        assert client.post("/monitor/scan", follow_redirects=False).status_code == 303

        status = client.get("/api/monitor/status").json()
        assert status["state"] == "running"
        assert status["files"][0]["name"] == "web.log"
        assert status["files"][0]["records"] == 12 and status["files"][0]["progress"] == 100
        assert status["last_scan_at"]

        page = client.get("/monitor").text
        assert "web.log" in page and "Pause" in page and "Scan now" in page
        analysis_id = status["files"][0]["analysis_id"]
        dashboard = client.get(f"/?analysis_id={analysis_id}").text
        assert "Monitored file" in dashboard and "Timeout after # s" in dashboard
        findings = client.get(f"/events?analysis_id={analysis_id}").text
        assert "Server error spike" in findings and "Recurring issues" in findings
        assert "Monitored file" in client.get(f"/reports/{analysis_id}/download").text

        client.post("/monitor/pause")
        assert client.get("/api/monitor/status").json()["state"] == "paused"
        client.post("/monitor/resume")
        client.post("/monitor/stop")
        assert client.get("/api/monitor/status").json()["state"] == "stopped"


def test_worker_thread_starts_and_stops():
    worker = monitor.MonitorWorker()
    worker.start()
    assert worker.alive
    worker.stop()
    assert not worker.alive


# ------------------------------------------------------------------ duplicate prevention (fingerprints)

def test_rewritten_file_with_same_content_is_not_read_twice(db, folder):
    """Editors and sync tools may save a file as a *new* file containing the old lines."""
    start(db, folder)
    log = folder / "app.log"
    write(log, line(1) + line(2) + line(3))
    monitor.scan_once(db)
    replacement = folder / "app.log.tmp"
    write(replacement, line(1) + line(2) + line(3) + line(4))  # same content plus one new line
    os.replace(replacement, log)                                 # new file identity
    assert monitor.scan_once(db).new_records == 1
    assert records(db, "app.log") == 4


def test_truncated_file_that_grew_past_old_position_is_detected(db, folder):
    start(db, folder)
    log = folder / "app.log"
    write(log, line(1) + line(2))
    monitor.scan_once(db)
    write(log, "".join(line(i) for i in range(30, 36)), mode="w")  # larger than before, other content
    assert monitor.scan_once(db).new_records == 6
    assert "rotated" in watched(db, "app.log").message
    assert records(db, "app.log") == 8


# ------------------------------------------------------------------ Windows formats

def test_utf16_file_is_read(db, folder):
    start(db, folder)
    log = folder / "service.log"
    with open(log, "w", encoding="utf-16", newline="") as handle:   # BOM + UTF-16-LE, like many Windows tools
        handle.write(line(1) + line(2, "ERROR", 500, "Crash"))
    assert monitor.scan_once(db).new_records == 2
    assert watched(db, "service.log").encoding == "utf-16-le"
    with open(log, "a", encoding="utf-16-le", newline="") as handle:
        handle.write(line(3))
    assert monitor.scan_once(db).new_records == 1
    assert records(db, "service.log") == 3


IIS_HEADER = ("#Software: Microsoft Internet Information Services 10.0\n#Version: 1.0\n#Date: 2026-11-11 10:00:00\n"
              "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip "
              "cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken\n")


def iis_line(i: int, status: int = 200) -> str:
    return (f"2026-11-11 10:00:{i % 60:02d} 10.0.0.5 GET /shop/item.aspx id={i} 443 - 203.0.113.9 "
            f"Mozilla/5.0+(Windows+NT+10.0) - {status} 0 0 {i}\n")


def test_iis_log_header_is_remembered_between_reads(db, folder, monkeypatch):
    monkeypatch.setattr(monitor, "CHUNK_BYTES", 400)  # header and data end up in different reads
    start(db, folder)
    write(folder / "u_ex261111.log", IIS_HEADER + "".join(iis_line(i, 404 if i % 2 else 200) for i in range(12)))
    for _ in range(20):
        if not monitor.scan_once(db).backlog:
            break
    assert records(db, "u_ex261111.log") == 12
    assert watched(db, "u_ex261111.log").parser_state["w3c_fields"][0] == "date"
    analysis = db.get(Analysis, watched(db, "u_ex261111.log").analysis_id)
    db.refresh(analysis)
    assert analysis.invalid_lines == 0
    assert analysis.summary["status_counts"] == {"200": 6, "404": 6}


# ------------------------------------------------------------------ incremental statistics and findings

def test_incremental_results_match_full_analysis(db, folder):
    """Statistics, findings and recurring issues built piece by piece equal a one-shot analysis."""
    from backend.app.services import analysis_service as svc
    from backend.app.services.generator import generate_logs
    from datetime import datetime as dt
    from project import analyze_log_entries, detect_suspicious_activity, group_recurring_messages, parse_log_text

    lines = generate_logs("mixed", 1500, seed=5, start=dt(2026, 11, 11, 8))
    start(db, folder)
    log = folder / "web.log"
    for part in range(0, len(lines), 250):                       # arrives in six pieces
        write(log, "\n".join(lines[part:part + 250]) + "\n")
        monitor.scan_once(db)

    analysis = db.get(Analysis, watched(db, "web.log").analysis_id)
    db.refresh(analysis)
    entries, _ = parse_log_text("\n".join(lines))
    expected = analyze_log_entries(entries)
    actual = svc.summarize_analysis(db, analysis.id)
    for key in ("total_entries", "level_counts", "status_counts", "status_classes", "unique_ips",
                "start_time", "end_time", "error_rate", "timeline", "method_counts"):
        assert actual[key] == expected[key], key
    # Same ranking; IPs with equal counts may be listed in a different order.
    assert [r["count"] for r in actual["top_ips"]] == [r["count"] for r in expected["top_ips"]]

    full = {(d["rule"], d["ip"]): (d["count"], d["total_matches"]) for d in detect_suspicious_activity(entries)}
    stored = {(d.rule, d.ip): (d.count, d.total_matches) for d in svc.get_detections(db, analysis.id)}
    assert stored == full

    grouped = {(g["level"], g["status"], g["pattern"]): g["count"] for g in group_recurring_messages(entries, limit=None)}
    via_sql = {(g["level"], g["status"], g["pattern"]): g["count"]
               for g in svc.recurring_issues(db, analysis.id, limit=None)}
    assert via_sql == grouped


def test_synced_folder_is_flagged(monkeypatch, tmp_path):
    monkeypatch.setenv("OneDrive", str(tmp_path / "OneDrive"))
    assert monitor.in_synced_folder(str(tmp_path / "OneDrive" / "Desktop" / "logs"))
    assert not monitor.in_synced_folder(str(tmp_path / "local" / "logs"))
