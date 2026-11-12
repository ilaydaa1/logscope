"""Long-running monitoring: rotation by renaming, retention, streaming detection,
running counters, single-instance lock, offline notice, autostart, performance."""

import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from backend.app.database import PROJECT_ROOT, SessionLocal, init_db
from backend.app.main import app
from backend.app.models import Analysis, Detection, LogEntry, RuleCount, Setting, WatchedFile
from backend.app.services import analysis_service as svc
from backend.app.services import autostart, monitor
from backend.app.services.generator import generate_logs
from project import detect_suspicious_activity, parse_log_text


def line(i: int, when: datetime | None = None, status: int = 200) -> str:
    when = when or datetime(2026, 11, 11, 10, 0, 0) + timedelta(seconds=i)
    return f"{when:%Y-%m-%dT%H:%M:%S}Z INFO 10.0.0.{i % 7 + 1} GET /page/{i} {status} - ok\n"


@pytest.fixture(autouse=True)
def immediate_statistics(monkeypatch):
    monkeypatch.setattr(monitor, "STATS_INTERVAL", 0)
    monkeypatch.setattr(monitor, "REFRESH_DURING_BACKLOG", 0)


@pytest.fixture
def db():
    init_db()
    session = SessionLocal()
    yield session
    monitor.stop_monitoring(session)
    config = monitor.get_config(session)
    config.retention_days = 30
    monitor._save_config(session, config)
    session.close()


@pytest.fixture
def folder(tmp_path):
    path = tmp_path / "logs"
    path.mkdir()
    return path


def write(path, text, mode="a"):
    with open(path, mode, encoding="utf-8", newline="") as handle:
        handle.write(text)


def records_for(db, name):
    wf = db.scalar(select(WatchedFile).where(WatchedFile.path.endswith(name)))
    db.refresh(wf)
    return db.scalar(select(func.count()).select_from(LogEntry).where(LogEntry.analysis_id == wf.analysis_id))


# ------------------------------------------------------------------ H1: rotation by renaming

def test_lines_written_before_rename_rotation_are_read(db, folder):
    monitor.start_monitoring(db, str(folder), "UTC", True)
    log = folder / "app.log"
    write(log, line(1) + line(2))
    monitor.scan_once(db)
    write(log, line(3) + line(4))               # written after the last scan ...
    os.rename(log, folder / "app.log.1")        # ... then the log is rotated by renaming
    write(log, line(5))                          # and a new app.log is started
    result = monitor.scan_once(db)
    assert result.new_records == 3              # lines 3, 4 (old file) and 5 (new file)
    assert records_for(db, "app.log") == 5
    wf = db.scalar(select(WatchedFile).where(WatchedFile.path.endswith("app.log")))
    assert "rotated file app.log.1" in wf.message


def test_rename_without_new_file_is_drained(db, folder):
    monitor.start_monitoring(db, str(folder), "UTC", True)
    log = folder / "app.log"
    write(log, line(1))
    monitor.scan_once(db)
    write(log, line(2))
    os.rename(log, folder / "app.log.1")        # no new app.log yet
    assert monitor.scan_once(db).new_records == 1
    write(log, line(3))                          # new file appears later
    assert monitor.scan_once(db).new_records == 1
    assert records_for(db, "app.log") == 3


# ------------------------------------------------------------------ H2: retention

def test_retention_deletes_only_old_monitored_records(db, folder):
    now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
    monitor.start_monitoring(db, str(folder), "UTC", True)
    def scan(i, when):  # one client requesting missing pages
        return f"{when:%Y-%m-%dT%H:%M:%S}Z WARNING 203.0.113.9 GET /missing/{i} 404 - Not found\n"
    old = "".join(scan(i, now - timedelta(days=40, seconds=i)) for i in range(30))
    new = "".join(scan(i, now - timedelta(hours=1, seconds=i)) for i in range(5))
    write(folder / "web.log", old + new)
    monitor.scan_once(db)
    upload = svc.create_analysis(db, text=old, name="kept.log", source="upload")
    analysis_id = db.scalar(select(WatchedFile.analysis_id).where(WatchedFile.path.endswith("web.log")))
    assert db.scalar(select(func.count()).where(Detection.analysis_id == analysis_id)) >= 1  # old 404 burst

    monitor.save_retention(db, 30)
    assert monitor.run_cleanup(db) == 30
    analysis = db.get(Analysis, analysis_id)
    db.refresh(analysis)
    assert analysis.total_entries == 5 and analysis.summary["total_entries"] == 5
    assert db.scalar(select(func.count()).where(Detection.analysis_id == analysis_id)) == 0   # findings rebuilt
    assert db.get(Analysis, upload.id).total_entries == 30                                    # uploads untouched
    assert "old records removed" in monitor.monitor_status(db)["last_cleanup"]

    monitor.save_retention(db, 0)                 # forever: nothing deleted
    assert monitor.run_cleanup(db) == 0
    with pytest.raises(monitor.MonitorError):
        monitor.save_retention(db, 3)


def test_database_size_and_compaction(db):
    assert monitor.database_size() > 0
    monitor.compact_database()                    # must not fail while the app is in use


# ------------------------------------------------------------------ H3/H4: streaming detection and counters

def test_streaming_detection_equals_in_memory_detection(db):
    text = "\n".join(generate_logs("mixed", 3000, seed=21, start=datetime(2026, 11, 11, 8)))
    analysis = svc.create_analysis(db, text=text, name="mixed.log", source="upload")
    entries, _ = parse_log_text(text)
    expected = detect_suspicious_activity(entries)
    streamed, totals = svc.scan_detections(db, analysis.id, svc.saved_thresholds(db))
    assert streamed == expected
    assert totals[("high_volume", entries[0]["ip"])] == sum(1 for e in entries if e["ip"] == entries[0]["ip"])


def test_counters_are_built_once_for_older_analyses(db):
    text = "\n".join(generate_logs("brute_force", 600, seed=3, start=datetime(2026, 11, 11, 8)))
    analysis = svc.create_analysis(db, text=text, name="old.log", source="upload")
    assert not analysis.counters_ready
    svc.update_detections(db, analysis, [{"timestamp": datetime(2026, 11, 11, 9), "ip": "203.0.113.45",
                                          "status": 401, "endpoint": "/login", "message": ""}])
    db.commit()
    assert analysis.counters_ready
    counted = db.scalar(select(RuleCount.count).where(RuleCount.analysis_id == analysis.id,
                                                      RuleCount.rule == "brute_force",
                                                      RuleCount.key == "203.0.113.45"))
    entries, _ = parse_log_text(text)
    assert counted == sum(1 for e in entries if e["ip"] == "203.0.113.45" and e["status"] == 401)


def test_rerun_detection_uses_streaming(db, monkeypatch):
    text = "\n".join(generate_logs("scan_404", 500, seed=4, start=datetime(2026, 11, 11, 8)))
    analysis = svc.create_analysis(db, text=text, name="scan.log", source="upload")
    monkeypatch.setattr(svc, "load_entries", lambda *a, **k: pytest.fail("must not load all records"))
    assert svc.rerun_detection(db, analysis, {"excessive_404": {"threshold": 5}}) >= 1


# ------------------------------------------------------------------ H5: single instance, offline notice, autostart

def test_second_process_cannot_monitor_the_same_database():
    assert monitor.acquire_instance_lock()
    script = ("from backend.app.services import monitor; "
              "print('locked' if not monitor.acquire_instance_lock() else 'acquired')")
    output = subprocess.run([sys.executable, "-c", script], cwd=PROJECT_ROOT, env=dict(os.environ),
                            capture_output=True, text=True, timeout=60)
    assert output.stdout.strip() == "locked", output.stderr
    monitor.release_instance_lock()


def test_offline_gap_is_reported(db, folder):
    monitor.start_monitoring(db, str(folder), "UTC", True)
    db.merge(Setting(key=monitor.HEARTBEAT_KEY,
                     value={"at": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()}))
    db.commit()
    monitor.note_offline_gap(db)
    assert "Monitoring was not running" in monitor.monitor_status(db)["offline_gap"]
    monitor._set_runtime(offline_gap=None)


def test_autostart_script(tmp_path, monkeypatch):
    monkeypatch.setattr(autostart, "startup_folder", lambda: tmp_path)
    assert autostart.supported() and not autostart.enabled()
    path = autostart.enable(port=8123)
    script = path.read_text(encoding="utf-16")
    assert "project.py" in script and "--port 8123" in script and "shell.Run" in script
    assert str(PROJECT_ROOT) in script                     # non-ASCII project paths survive (UTF-16)
    assert autostart.enabled()
    autostart.disable()
    assert not autostart.enabled()
    monkeypatch.setattr(autostart, "startup_folder", lambda: None)
    assert not autostart.supported()
    with pytest.raises(OSError):
        autostart.enable()


def test_settings_routes(db, tmp_path, monkeypatch):
    monkeypatch.setattr(autostart, "startup_folder", lambda: tmp_path)
    with TestClient(app) as client:
        page = client.get("/monitor").text
        assert "Keep monitored records" in page and "Start at sign-in" in page
        assert client.post("/monitor/settings", data={"retention_days": "90"}, follow_redirects=False).status_code == 303
        assert client.get("/api/monitor/status").json()["retention_days"] == 90
        assert client.post("/monitor/settings", data={"retention_days": "5"}).status_code == 400
        assert client.post("/monitor/autostart", data={"enable": "1"}, follow_redirects=False).status_code == 303
        assert autostart.enabled()
        client.post("/monitor/autostart", data={})
        assert not autostart.enabled()
        assert client.post("/monitor/compact", follow_redirects=False).status_code == 303


# ------------------------------------------------------------------ performance

def test_large_busy_log_is_processed_quickly(db, folder):
    """100,000 access-log lines from 5,000 different IPs, read in several chunks."""
    start = datetime(2026, 11, 11, 0, 0, 0)
    lines = [f"{start + timedelta(seconds=i // 4):%Y-%m-%dT%H:%M:%S}Z INFO 10.{i % 50}.{(i // 50) % 100}.1 "
             f"GET /p/{i % 300} {404 if i % 9 == 0 else 200} - ok\n" for i in range(100_000)]
    monitor.start_monitoring(db, str(folder), "UTC", True)
    write(folder / "busy.log", "".join(lines))
    began = time.perf_counter()
    for _ in range(100):
        if not monitor.scan_once(db).backlog:
            break
    elapsed = time.perf_counter() - began
    assert records_for(db, "busy.log") == 100_000
    assert elapsed < 120, f"took {elapsed:.1f} s"
