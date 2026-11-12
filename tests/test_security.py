"""Request guard (cross-site requests, host names), storage migration and encodings."""

import sqlite3

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text

from backend.app.database import Base, add_missing_columns, copy_legacy_database
from backend.app.main import app
from backend.app.services.textcodec import complete_lines_end, decode, detect_encoding, is_binary

ORIGIN = "http://testserver"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


# ------------------------------------------------------------------ cross-site request forgery

@pytest.mark.parametrize("headers", [
    {"Origin": "https://evil.example"},
    {"Origin": "null"},
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site"},                 # e.g. another app on localhost:3000
    {"Referer": "https://evil.example/page.html"},
])
def test_cross_site_changes_are_blocked(client, tmp_path, headers):
    data = {"directory": str(tmp_path), "timezone": "UTC", "consent": "1"}
    response = client.post("/monitor/start", data=data, headers=headers, follow_redirects=False)
    assert response.status_code == 403
    assert client.get("/api/monitor/status").json()["state"] == "stopped"
    assert client.post("/history/1/delete", headers=headers).status_code == 403


def test_same_origin_changes_are_allowed(client):
    headers = {"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin", "Referer": ORIGIN + "/monitor"}
    response = client.post("/monitor/pause", headers=headers, follow_redirects=False)
    assert response.status_code == 303


def test_reading_pages_cross_site_is_allowed(client):
    # Links from elsewhere may open pages; only changes are restricted.
    assert client.get("/", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 200


def test_unknown_host_names_are_rejected(client):
    """Protects the status API against DNS-rebinding pages."""
    assert client.get("/api/monitor/status", headers={"Host": "attacker.example"}).status_code == 403
    assert client.get("/api/monitor/status", headers={"Host": "127.0.0.1:8000"}).status_code == 200
    assert client.get("/api/monitor/status", headers={"Host": "[::1]:8000"}).status_code == 200


def test_allowed_hosts_can_be_extended(client, monkeypatch):
    monkeypatch.setenv("LOGSCOPE_ALLOWED_HOSTS", "logs.internal")
    assert client.get("/api/monitor/status", headers={"Host": "logs.internal:8000"}).status_code == 200


# ------------------------------------------------------------------ storage

def test_add_missing_columns(tmp_path):
    from backend.app import models  # noqa: F401  (registers tables)

    engine = create_engine(f"sqlite:///{(tmp_path / 'old.db').as_posix()}")
    with engine.begin() as connection:  # a watched_files table from an older version
        connection.execute(text("CREATE TABLE watched_files (id INTEGER PRIMARY KEY, path VARCHAR(1024))"))
    Base.metadata.create_all(engine)
    added = add_missing_columns(engine)
    assert "watched_files.head_hash" in added and "watched_files.encoding" in added
    columns = {c["name"] for c in inspect(engine).get_columns("watched_files")}
    assert {"offset", "head_hash", "tail_hash", "parser_state"} <= columns
    assert add_missing_columns(engine) == []  # idempotent


def test_copy_legacy_database(tmp_path):
    source, target = tmp_path / "old" / "logscope.db", tmp_path / "new" / "logscope.db"
    source.parent.mkdir()
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE t (x)")
        connection.execute("INSERT INTO t VALUES (42)")
    assert copy_legacy_database(source, target)
    with sqlite3.connect(target) as connection:
        assert connection.execute("SELECT x FROM t").fetchone() == (42,)
    assert source.exists()                              # the original is kept
    assert not copy_legacy_database(source, target)     # only once


# ------------------------------------------------------------------ encodings

def test_detect_encoding():
    assert detect_encoding("line\n".encode("utf-16")) == "utf-16-le"            # BOM
    assert detect_encoding("line one\n".encode("utf-16-le")) == "utf-16-le"     # no BOM
    assert detect_encoding("line one\n".encode("utf-16-be")) == "utf-16-be"
    assert detect_encoding("﻿zaman çizelgesi\n".encode("utf-8")) == "utf-8"
    assert detect_encoding(b"") == "utf-8"


def test_complete_lines_and_binary():
    assert complete_lines_end(b"a\nb\nc", "utf-8") == 4
    assert complete_lines_end(b"no newline", "utf-8") == 0
    data = "a\nbc".encode("utf-16-le")
    assert complete_lines_end(data, "utf-16-le") == 4
    assert decode(data[:4], "utf-16-le", at_file_start=False) == "a\n"
    assert is_binary(b"a\x00b", "utf-8") and not is_binary(data, "utf-16-le")
    assert decode("﻿x".encode("utf-8"), "utf-8", at_file_start=True) == "x"


def test_upload_utf16_file(client):
    content = "2026-11-11T10:00:00Z ERROR 10.0.0.1 GET /x 500 - boom\n".encode("utf-16")
    response = client.post("/upload", files={"file": ("win.log", content, "text/plain")},
                           data={"timezone": "UTC"}, follow_redirects=False)
    assert response.status_code == 303
