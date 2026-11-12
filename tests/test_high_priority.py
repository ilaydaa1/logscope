"""Tests for: upload time zone, explorer time range, precise event links,
friendly invalid-link page, and remembered detection limits."""

import re
from html import unescape

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def analysis_id_from(response) -> int:
    return int(response.headers["location"].split("analysis_id=")[1].split("&")[0])


def upload(client, content: bytes, timezone: str = "UTC") -> int:
    response = client.post("/upload", files={"file": ("tz.log", content, "text/plain")},
                           data={"timezone": timezone}, follow_redirects=False)
    assert response.status_code == 303
    return analysis_id_from(response)


def test_upload_timezone_is_applied(client):
    line = b"2026-11-11 14:00:00 INFO 10.0.0.1 GET / 200 - ok\n"
    as_utc = upload(client, line, "UTC")
    as_istanbul = upload(client, line, "Europe/Istanbul")
    # UTC 14:00 is shown as 17:00 Istanbul; Istanbul 14:00 stays 14:00.
    assert "2026-11-11 17:00:00" in client.get(f"/explorer?analysis_id={as_utc}").text
    page = client.get(f"/explorer?analysis_id={as_istanbul}").text
    assert "2026-11-11 14:00:00" in page
    assert "times read as Europe/Istanbul" in page
    report = client.get(f"/reports/{as_istanbul}/download").text
    assert "Log times read as:  Europe/Istanbul" in report


def test_upload_rejects_unknown_timezone(client):
    response = client.post("/upload", files={"file": ("a.log", b"x", "text/plain")}, data={"timezone": "Mars/Base"})
    assert response.status_code == 400
    assert "choose a time zone" in response.text


def test_explorer_time_range(client):
    lines = b"".join(
        f"2026-11-11T10:0{i}:00Z INFO 10.0.0.1 GET /p{i} 200 - ok\n".encode() for i in range(5)
    )
    analysis_id = upload(client, lines)
    # Inputs are in Istanbul time (UTC+3): 13:01-13:03 local = 10:01-10:03 UTC -> 3 records.
    page = client.get(f"/explorer?analysis_id={analysis_id}&start=2026-11-11T13:01:00&end=2026-11-11T13:03:00").text
    assert "3 matching records" in page
    # Values with an explicit UTC marker (used by the chart) work as well.
    page = client.get(f"/explorer?analysis_id={analysis_id}&start=2026-11-11T10:04:00Z").text
    assert "1 matching record" in page
    # Invalid values are ignored rather than causing an error.
    assert "5 matching records" in client.get(f"/explorer?analysis_id={analysis_id}&start=yesterday").text


def test_event_links_open_exact_records(client):
    response = client.post("/generate", data={"scenario": "brute_force", "count": "1000", "seed": "4"},
                           follow_redirects=False)
    analysis_id = analysis_id_from(response)
    events = client.get(f"/events?analysis_id={analysis_id}").text
    match = re.search(r'href="(/explorer\?[^"]*q=login[^"]*)">View the ([\d,]+) failed logins', events)
    assert match, "brute-force link should filter failed logins in the peak window"
    link, count = unescape(match.group(1)), match.group(2)
    assert "start=" in link and "end=" in link
    assert f"{count} matching records" in client.get(link).text


def test_invalid_link_shows_friendly_page(client):
    response = client.get("/reports/abc/download")
    assert response.status_code == 400
    assert "text/html" in response.headers["content-type"]
    assert "This link contains an invalid value." in response.text


def test_remember_and_reset_thresholds(client):
    from backend.app.database import SessionLocal
    from backend.app.services.analysis_service import saved_thresholds
    from project import DEFAULT_THRESHOLDS

    first = analysis_id_from(client.post("/generate", data={"scenario": "normal", "count": "200", "seed": "2"},
                                         follow_redirects=False))
    form = {f"{rule}.{key}": str(value) for rule, cfg in DEFAULT_THRESHOLDS.items() for key, value in cfg.items()}
    form["high_volume.threshold"] = "3"
    form["remember"] = "1"
    response = client.post(f"/events/{first}/thresholds", data=form, follow_redirects=False)
    assert response.headers["location"].endswith("notice=remembered")

    # A new analysis now starts with the saved limit.
    second = analysis_id_from(client.post("/generate", data={"scenario": "normal", "count": "200", "seed": "3"},
                                          follow_redirects=False))
    db = SessionLocal()
    try:
        assert saved_thresholds(db)["high_volume"]["threshold"] == 3
    finally:
        db.close()
    assert "your default: 3 in 1 minute" in client.get(f"/events?analysis_id={second}").text

    # Reset restores the built-in defaults for future analyses.
    response = client.post(f"/events/{second}/thresholds", data={"action": "reset"}, follow_redirects=False)
    assert response.headers["location"].endswith("notice=reset")
    db = SessionLocal()
    try:
        assert saved_thresholds(db) == DEFAULT_THRESHOLDS
    finally:
        db.close()
