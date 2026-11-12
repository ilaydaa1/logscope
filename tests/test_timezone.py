"""Timezone conversion and report timestamp tests (UTC storage, Istanbul display)."""

import re
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.app.database import SessionLocal
from backend.app.main import app
from backend.app.models import Analysis, LogEntry
from backend.app.services.reports import build_csv_report, build_text_report
from backend.app.timeutils import DISPLAY_TIMEZONE, ensure_utc, format_local, timezone_label, to_local, utc_now

ISTANBUL = ZoneInfo("Europe/Istanbul")


def test_display_timezone_is_istanbul():
    assert DISPLAY_TIMEZONE == ISTANBUL
    assert timezone_label(datetime(2026, 11, 11, tzinfo=timezone.utc)) == "Europe/Istanbul (UTC+03:00)"


@pytest.mark.parametrize("utc_value, expected", [
    (datetime(2026, 11, 11, 15, 43, 10), "2026-11-11 18:43:10"),          # naive = UTC by convention
    (datetime(2026, 11, 11, 15, 43, 10, tzinfo=timezone.utc), "2026-11-11 18:43:10"),
    (datetime(2026, 12, 31, 22, 30, 0, tzinfo=timezone.utc), "2027-01-01 01:30:00"),  # crosses midnight + year
    ("2026-07-01T00:00:00", "2026-07-01 03:00:00"),                        # ISO strings from summary JSON
])
def test_format_local(utc_value, expected):
    assert format_local(utc_value) == expected


def test_format_local_empty():
    assert format_local(None) == "-"
    assert format_local("") == "-"


def test_no_double_conversion():
    """Converting an already-local aware value must not shift it again."""
    local = datetime(2026, 11, 11, 18, 43, 10, tzinfo=ISTANBUL)
    assert format_local(local) == "2026-11-11 18:43:10"
    assert to_local(to_local(datetime(2026, 11, 11, 15, 43, 10))) == local
    assert ensure_utc(local) == datetime(2026, 11, 11, 15, 43, 10, tzinfo=timezone.utc)


def test_database_stores_utc_and_returns_aware():
    db = SessionLocal()
    try:
        from backend.app.database import init_db
        init_db()
        analysis = Analysis(name="tz-test", source="upload", summary={}, thresholds={},
                            created_at=datetime(2026, 11, 11, 18, 0, tzinfo=ISTANBUL))
        db.add(analysis)
        db.commit()
        raw = db.execute(select(Analysis.created_at).where(Analysis.id == analysis.id)).scalar_one()
        assert raw == datetime(2026, 11, 11, 15, 0, tzinfo=timezone.utc)  # stored as UTC, returned aware
        db.delete(analysis)
        db.commit()
    finally:
        db.close()


def make_report_inputs():
    analysis = SimpleNamespace(
        id=7, name="demo", source="generated", filename=None, total_entries=2, invalid_lines=0,
        error_rate=0.0, thresholds={"brute_force": {"threshold": 5, "window_seconds": 120}},
        created_at=datetime(2026, 11, 11, 15, 43, 10, tzinfo=timezone.utc),
        summary={
            "start_time": "2026-11-10T08:00:00", "end_time": "2026-11-10T09:30:00", "unique_ips": 1,
            "level_counts": {"DEBUG": 0, "INFO": 2, "WARNING": 0, "ERROR": 0, "CRITICAL": 0},
            "status_counts": {"200": 2}, "top_ips": [{"ip": "10.0.0.1", "count": 2}],
        },
    )
    detection = SimpleNamespace(
        title="Possible brute-force activity", severity="low", ip="203.0.113.5", count=6, threshold=5,
        window_seconds=120, total_matches=6,
        first_seen=datetime(2026, 11, 10, 8, 10, tzinfo=timezone.utc),
        last_seen=datetime(2026, 11, 10, 8, 11, tzinfo=timezone.utc),
        explanation="6 failed login attempts from 203.0.113.5 within 120 seconds "
                    "(2026-11-10 08:10:00 to 08:11:00 UTC). Rule threshold: 5 in 120 s.",
    )
    return analysis, [detection]


def test_text_report_keeps_times_separate():
    analysis, detections = make_report_inputs()
    generated = datetime(2026, 11, 12, 9, 0, 0, tzinfo=timezone.utc)
    report = build_text_report(analysis, detections, generated)
    assert "Report generated:   2026-11-12 12:00:00" in report        # real generation time, Istanbul
    assert "Analysis created:   2026-11-11 18:43:10" in report        # when the analysis ran
    assert "Log period:         2026-11-10 11:00:00  to  2026-11-10 12:30:00" in report  # events
    assert "2026-11-10 11:10:00  to  2026-11-10 11:11:00" in report  # detection window in Istanbul time
    assert "UTC)" not in report.replace("(UTC+03:00)", "")           # old embedded UTC text removed
    assert "Europe/Istanbul (UTC+03:00)" in report


def test_csv_report_generation_time():
    analysis, detections = make_report_inputs()
    generated = datetime(2026, 11, 12, 21, 30, 0, tzinfo=timezone.utc)
    csv_text = build_csv_report(analysis, detections, generated)
    assert "report,generated_at,2026-11-13 00:30:00,Europe/Istanbul (UTC+03:00)" in csv_text
    assert "analysis,created_at,2026-11-11 18:43:10" in csv_text
    assert "analysis,log_period_start,2026-11-10 11:00:00" in csv_text


def test_downloaded_report_uses_current_time():
    """The report's generation time is 'now', not the log's event time."""
    with TestClient(app) as client:
        response = client.post("/generate", data={"scenario": "normal", "count": "200", "seed": "5"},
                               follow_redirects=False)
        analysis_id = int(response.headers["location"].split("analysis_id=")[1].split("&")[0])
        before = utc_now().replace(microsecond=0)
        report = client.get(f"/reports/{analysis_id}/download?format=txt").text
        after = utc_now()

        stamp = re.search(r"Report generated:\s+(\S+ \S+)", report).group(1)
        generated = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=ISTANBUL)
        assert before <= generated <= after + timedelta(seconds=1)

        # Event timestamps are older than the report and shown separately.
        period = re.search(r"Log period:\s+(\S+ \S+)", report).group(1)
        assert period != stamp

        # The HTML pages show the same Istanbul conversion as the report.
        db = SessionLocal()
        try:
            created = db.get(Analysis, analysis_id).created_at
            first = db.scalars(select(LogEntry).where(LogEntry.analysis_id == analysis_id)
                               .order_by(LogEntry.timestamp)).first()
            assert created.tzinfo is not None and first.timestamp.tzinfo is not None
        finally:
            db.close()
        history = client.get("/history").text
        assert created.astimezone(ISTANBUL).strftime("%Y-%m-%d %H:%M") in history
        explorer = client.get(f"/explorer?analysis_id={analysis_id}&order=oldest").text
        assert first.timestamp.astimezone(ISTANBUL).strftime("%Y-%m-%d %H:%M:%S") in explorer
