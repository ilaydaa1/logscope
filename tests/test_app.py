"""End-to-end tests of the web application and services (uses a temporary database)."""

from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.services.generator import SCENARIOS, generate_logs
from backend.app.services.uploads import sanitize_filename

START = datetime(2026, 11, 11, 8, 0, 0)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def latest_id(response) -> int:
    return int(response.headers["location"].split("analysis_id=")[1].split("&")[0])


# ----------------------------------------------------------------- generator
def test_generator_is_deterministic():
    assert generate_logs("mixed", 500, seed=7, start=START) == generate_logs("mixed", 500, seed=7, start=START)
    assert generate_logs("mixed", 500, seed=7, start=START) != generate_logs("mixed", 500, seed=8, start=START)


@pytest.mark.parametrize("scenario", list(SCENARIOS))
def test_generator_lines_are_parseable(scenario):
    from project import parse_log_text

    lines = generate_logs(scenario, 300, seed=1, start=START)
    entries, invalid = parse_log_text("\n".join(lines))
    assert invalid == 0
    assert 250 <= len(entries) <= 350


def test_generator_rejects_invalid_input():
    with pytest.raises(ValueError):
        generate_logs("nope", 500)
    with pytest.raises(ValueError):
        generate_logs("normal", 5)


def test_sanitize_filename():
    assert sanitize_filename("../../etc/passwd.log") == "passwd.log"
    assert sanitize_filename("C:\\Users\\me\\app<1>.txt") == "app_1_.txt"
    assert sanitize_filename("") == "upload.log"


# ----------------------------------------------------------------- pages
def test_empty_pages_render(client):
    for path in ("/", "/upload", "/generate", "/explorer", "/events", "/reports", "/history"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "LogScope" in response.text


def test_generate_and_browse(client):
    response = client.post("/generate", data={"scenario": "brute_force", "count": "1000", "seed": "3"},
                           follow_redirects=False)
    assert response.status_code == 303
    analysis_id = latest_id(response)

    dashboard = client.get(f"/?analysis_id={analysis_id}&notice=generated")
    assert "Sample data generated and analyzed" in dashboard.text
    assert "Possible brute-force activity" in dashboard.text

    events = client.get(f"/events?analysis_id={analysis_id}")
    assert "203.0.113.45" in events.text

    explorer = client.get(f"/explorer?analysis_id={analysis_id}&ip=203.0.113.45&status=401")
    assert explorer.status_code == 200
    assert "matching record" in explorer.text

    # Invalid filter values are ignored, not errors.
    assert client.get(f"/explorer?analysis_id={analysis_id}&status=abc&level=LOUD&page=-3").status_code == 200

    txt = client.get(f"/reports/{analysis_id}/download?format=txt")
    assert txt.status_code == 200 and "LOGSCOPE ANALYSIS REPORT" in txt.text
    assert "attachment" in txt.headers["content-disposition"]
    csv_report = client.get(f"/reports/{analysis_id}/download?format=csv")
    assert csv_report.text.startswith("section,item,value,details")
    assert client.get(f"/reports/{analysis_id}/download?format=pdf").status_code == 400


def test_generate_download_and_invalid(client):
    response = client.post("/generate", data={"scenario": "normal", "count": "200", "action": "download"})
    assert response.status_code == 200
    assert response.text.count("\n") == 200
    bad = client.post("/generate", data={"scenario": "normal", "count": "999999"})
    assert bad.status_code == 400


def test_upload_flow(client):
    content = (
        b"2026-11-11T10:00:00 INFO 10.0.0.1 GET / 200 - ok\n"
        b"not a log line\n"
        b'203.0.113.7 - - [11/Nov/2026:10:00:05 +0000] "GET /x HTTP/1.1" 404 0 "-" "curl"\n'
    )
    response = client.post("/upload", files={"file": ("../server.log", content, "text/plain")},
                           follow_redirects=False)
    assert response.status_code == 303
    analysis_id = latest_id(response)
    history = client.get("/history").text
    assert "server.log" in history and "../server.log" not in history

    page = client.get(f"/?analysis_id={analysis_id}").text
    assert "1 unreadable lines skipped" in page


@pytest.mark.parametrize("name, content, message", [
    ("evil.exe", b"MZ", "Unsupported file type"),
    ("empty.log", b"   \n", "empty"),
    ("binary.log", b"abc\x00def", "binary"),
    ("junk.txt", b"hello\nworld\n", "No valid log lines"),
])
def test_upload_rejections(client, name, content, message):
    response = client.post("/upload", files={"file": (name, content, "text/plain")})
    assert response.status_code == 400
    assert message in response.text


def test_rerun_thresholds_and_delete(client):
    response = client.post("/generate", data={"scenario": "normal", "count": "200", "seed": "1"},
                           follow_redirects=False)
    analysis_id = latest_id(response)
    form = {f"{rule}.{key}": "1" for rule in ("brute_force", "excessive_404", "server_error_spike", "high_volume")
            for key in ("threshold", "window_seconds")}
    rerun = client.post(f"/events/{analysis_id}/thresholds", data=form, follow_redirects=False)
    assert rerun.status_code == 303
    page = client.get(f"/events?analysis_id={analysis_id}&notice=rerun").text
    assert "Detection re-run" in page
    assert ">0 suspicious patterns<" not in page  # threshold 1 flags every IP

    form["high_volume.threshold"] = "zero"
    assert client.post(f"/events/{analysis_id}/thresholds", data=form).status_code == 400

    deleted = client.post(f"/history/{analysis_id}/delete", follow_redirects=False)
    assert deleted.status_code == 303
    assert client.get(f"/?analysis_id={analysis_id}").status_code == 404
