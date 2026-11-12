# LogScope – Log Analysis Platform

#### Video Demo: <URL HERE>

#### Description:

LogScope is a local log analysis tool with a web interface. It **monitors a log folder on your computer** and analyzes new lines automatically as they are written, or analyzes files you upload. It turns raw log lines into structured records, computes statistics (log levels, HTTP status codes, most active IP addresses, activity over time), groups **recurring warnings and errors**, and applies **transparent, rule-based detection** to highlight suspicious patterns such as possible brute-force logins, bursts of 404 responses, server error spikes and unusually high request volume.

Every analysis is stored in a local SQLite database, so results can be reopened and exported as TXT or CSV reports. A synthetic log generator provides repeatable test data.

LogScope is rule-based, **not** an AI security product: a finding means "this crossed a threshold and deserves a look", never "this was an attack".

This is my final project for Harvard's CS50's Introduction to Programming with Python (CS50P). A complete user manual is in [USER_GUIDE.md](USER_GUIDE.md). Licensed under the MIT License; tests run on Windows, macOS and Linux via GitHub Actions.

---

## Main features

| Page | What it does |
|------|--------------|
| **Dashboard** | Monitoring status (state, folder, files, last scan, last new data, errors) with live updates; records, errors, warnings and findings; top suspicious patterns and recurring issues; activity chart (click to drill down); log levels, HTTP status, top IPs; recent activity. |
| **Log Analysis → Folder monitoring** | User-approved folder, `.log`/`.txt` files only, no sub-folders or links. Background polling every 5 s, incremental reading by byte offset (only new lines), chunked reading of large files, rotation/truncation detection, missing/permission/binary handling. Start, Scan now, Pause, Resume, Stop; per-file status table that updates live. Resumes automatically after a restart. |
| **Log Analysis → Upload file** | `.log` / `.txt` upload (10 MB, drag & drop) with validation and a time-zone choice for timestamps without an offset. |
| **Log Analysis → Sample data** | Seven deterministic scenarios (200–20,000 records, optional seed); analyze directly or download as `.log`. |
| **Findings** | Suspicious patterns with rule, peak window and suggested check, linking to the exact records; recurring issues (warnings/errors grouped by normalized message with count, IPs, first/last seen); editable detection limits that can be saved as defaults. |
| **Logs** | Paginated record table with text search and filters for level, IP, status (`404` or `5xx`) and a From/To time range. |
| **Reports** | TXT and CSV reports with separate report, analysis and log-period times. |
| **History** | All analyses (uploaded, monitored, sample) with open, report download and delete. |

---

## Technologies

* **Python 3.11+** (developed and tested on 3.13)
* **FastAPI** for the web framework, with **Uvicorn** as the ASGI server
* **Jinja2** templates rendered on the server, plus **HTML, CSS and vanilla JavaScript**
* **SQLite** through **SQLAlchemy 2.0**
* **python-multipart** for file uploads
* **pytest** (and **httpx** for FastAPI's `TestClient`)

The timeline chart is a small hand-written SVG chart (`static/js/charts.js`) and all icons are inline SVG, so the application works completely offline with no CDN.

---

## Installation and usage

```bash
cd path/to/project
python -m venv .venv
# Windows:  .venv\Scripts\activate      macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
```

Start the application:

```bash
python project.py
```

Then open **http://127.0.0.1:8000** in a browser. Use another port with `python project.py --port 8080` (or the `LOGSCOPE_PORT` environment variable). The SQLite database is created automatically in your local application-data folder, `%LOCALAPPDATA%\LogScope\logscope.db` on Windows (`~/Library/Application Support/LogScope` on macOS, `~/.local/share/logscope` on Linux), so it is never inside a synced folder such as OneDrive. A database from an earlier version (`data/logscope.db`) is copied there once. Set `LOGSCOPE_DATA_DIR` or `LOGSCOPE_DATABASE_URL` to use another location.

Quick start: open **Log Analysis**, enter the full path of a log folder, tick the permission box and click **Start monitoring**. Without log files, use the **Sample data** tab.

Optional environment variables: `LOGSCOPE_PORT`, `LOGSCOPE_TIMEZONE` (display zone; default: your computer's time zone), `LOGSCOPE_DATA_DIR` / `LOGSCOPE_DATABASE_URL` (database location), `LOGSCOPE_SCAN_INTERVAL` (folder scan interval in seconds, default 5), `LOGSCOPE_ALLOWED_HOSTS` (extra host names accepted when not using localhost).

### Running the tests

```bash
python -m pytest
```

This runs `test_project.py` (the core functions), `tests/test_app.py` (generator, upload validation and the web pages end-to-end) and `tests/test_timezone.py` (UTC storage, Istanbul display and report timestamps), all against a temporary database. To run only the CS50P tests: `python -m pytest test_project.py`.

---

## Files and directories

```
project.py              Core logic + main(): parsing, normalisation, analysis, detection
test_project.py         pytest tests for the functions in project.py
requirements.txt        Python dependencies
pytest.ini              Test configuration (adds the project root to sys.path)
backend/app/
    main.py             FastAPI app: static files, routers, startup, error page
    database.py         SQLAlchemy engine, session factory, init_db(), get_db()
    models.py           ORM models: Analysis, LogEntry, Detection
    templating.py       Jinja2 environment, navigation, filters, rule explanations, render()
    timeutils.py        UTC storage type and local-time display conversion (zoneinfo, tzlocal)
    security.py         Request guard: allowed host names, same-origin check for changes
    routes/pages.py     Dashboard, Logs, Findings (+ threshold re-run), History
    routes/ingest.py    Upload file and Sample data
    routes/monitor.py   Folder monitoring controls and /api/monitor/status (JSON)
    routes/reports.py   Reports page and TXT/CSV downloads
    services/analysis_service.py  Runs project.py functions and stores/queries results
    services/monitor.py           Folder monitor: permission, incremental reading, fingerprints, rotation, worker
    services/textcodec.py         UTF-8 / UTF-16 detection and line splitting
    services/generator.py         Deterministic synthetic log generator
    services/uploads.py           Upload validation and filename sanitising
    services/reports.py           TXT and CSV report builders
templates/              Jinja2 templates (base layout, one per page, shared macros)
static/css/app.css      The dark navy UI theme and responsive layout
static/js/charts.js     Dependency-free SVG timeline chart
static/js/monitor.js    Live monitoring status (polls the status API)
tests/                  Web application tests (conftest.py sets a temporary database)
data/                   SQLite database (created at runtime, ignored by git)
```

### The core functions in `project.py`

* **`main()`** parses `--host` / `--port` and starts the FastAPI app with Uvicorn.
* **`normalize_log_level(level)`** maps different spellings (`warn`, `[ERROR]`, `fatal`, `crit`…) to one of `DEBUG, INFO, WARNING, ERROR, CRITICAL`. It raises `ValueError` for unknown levels and `TypeError` for non-strings.
* **`parse_log_line(line)`** tries three regular expressions (see formats below), validates every field (real date, valid IPv4/IPv6 via `ipaddress`, known HTTP method, status 100–599, known level) and returns a normalized dictionary, or `None` for a blank, oversized or malformed line. Time-zone-aware timestamps are converted to UTC.
* **`parse_log_text(text, default_timezone=None)`** parses a whole file (or a newly appended chunk), numbering lines and counting invalid ones (blank lines are ignored).
* **`analyze_log_entries(entries)`** computes level counts, status code and status class counts, top IPs and endpoints, unique IPs, time range, error rate and an activity timeline (`build_timeline`). The result contains only JSON-serializable values so it is stored directly in the database.
* **`group_recurring_messages(entries)`** groups repeated warnings/errors by level, status and message pattern (`normalize_message()` masks numbers, IDs and quoted values) with count, distinct IPs and first/last seen.
* **`detect_suspicious_activity(entries, thresholds=None)`** groups events per IP (or globally for 5xx), finds the busiest sliding time window with `peak_window()` and creates a detection when it reaches the threshold.

The web application imports and uses these functions directly; there is no second implementation of parsing or detection anywhere else.

---

## Supported log formats

1. **LogScope / application access log** (what the generator writes)
   `2026-11-11T14:23:01 WARNING 203.0.113.7 POST /login 401 - Failed login for user "admin"`
2. **Apache / Nginx common or combined log format** – the level is inferred from the status (5xx → ERROR, 4xx → WARNING, otherwise INFO)
   `203.0.113.7 - - [11/Nov/2026:14:23:01 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8.0"`
3. **Plain application log** without HTTP fields (Python `logging` style is supported, including `,123` milliseconds)
   `2026-11-11 14:23:01,123 ERROR Database connection lost`
4. **W3C extended / IIS logs** – the `#Fields:` header defines the columns; times are UTC by definition.

Files may be UTF-8 or UTF-16 (detected automatically).

### Limitations

* Other formats (JSON logs, syslog, Windows Event Logs `.evtx`, multi-line stack traces) are counted as invalid lines.
* Timestamps without a time zone are read in the zone chosen when uploading or starting monitoring (UTC or the local zone); timestamps with an offset are always converted correctly.
* A recent browser is needed for the chart's time labels (it uses `Intl.DateTimeFormat` with a time zone).
* Upload size is limited to 10 MB per file; the file is processed synchronously in the request, which is fine for this size but would move to a background worker in a larger version.
* Thresholds are global defaults that can be changed per analysis on the Findings page; they are not learned from the data.
* There are no user accounts: it is designed as a local, single-user tool.

---

## Detection rules and default thresholds

Each rule uses a **sliding time window**: LogScope looks for the busiest window of the given length and compares the number of matching events in it with the threshold. The same number of events spread over a whole day is therefore *not* flagged. One detection is reported per IP and rule (per log for the 5xx rule), showing the peak window.

| Rule | Matches | Grouped by | Default |
|------|---------|-----------|---------|
| **Possible brute-force activity** | 401/403 on a login/auth path (`login`, `signin`, `auth`, `session`…) or a message like "failed login" / "authentication failure" | IP | **5** in **120 s** |
| **Excessive 404 responses** | HTTP 404 | IP | **20** in **300 s** |
| **Server error spike** | HTTP 500–599 | all clients | **10** in **60 s** |
| **Unusually high request volume** | any request | IP | **120** in **60 s** (2 requests/second sustained for a minute) |

Why these values: a person who mistypes a password fails a few times, not five times in two minutes; normal browsing produces occasional 404s (favicons, old links), but twenty in five minutes looks like automated path probing; ten 5xx responses in a minute indicates a backend problem rather than an isolated bug; and two requests per second for a full minute from one client is well above typical human browsing.

**Severity** is relative to the threshold: *low* below 2×, *medium* from 2×, *high* from 4× the threshold.

---

## Design decisions

* **Core logic in `project.py`, framework code in `backend/`.** The parsing, analysis and detection functions are pure Python with no FastAPI or database dependency. This keeps them easy to unit-test and satisfies the CS50P structure, while the web layer simply calls them.
* **Server-rendered pages instead of a single-page app.** Jinja2 templates keep the MVP reliable and fast to build; every button is a real link or form, so the app works with JavaScript disabled; only the chart, drag & drop and live monitoring updates need it. A JSON API and a React front end can be added later on top of the same services.
* **Sliding windows with a two-pointer sweep.** `peak_window()` runs in O(n) on sorted timestamps, so detection on 20,000 entries is instant, and it avoids the common mistake of counting all matching events regardless of time.
* **Explainable output.** Each detection stores its peak count, threshold, window, first/last timestamp and an explanation sentence, so a user can see exactly why something was flagged and verify it on the Logs page through the provided link.
* **Bulk inserts** (`insert(LogEntry)` with a list of rows) instead of adding thousands of ORM objects keeps uploads and generation fast.
* **Safe uploads.** Files are read in chunks with a size limit, rejected when empty or binary (NUL bytes), decoded as text with replacement of invalid bytes, never executed and never saved under the client's filename; the filename is sanitized before it is shown. Jinja2 auto-escaping prevents log content from injecting HTML.
* **Deterministic synthetic data.** The generator uses `random.Random(seed)` so scenarios are reproducible in tests. Suspicious traffic always uses the RFC 5737 documentation ranges `203.0.113.0/24` and `198.51.100.0/24`, so sample data never points at a real third party. Normal users use private address ranges.
* **No fake numbers.** When there is no analysis, the dashboard shows an empty state instead of placeholder statistics.
* **Store in UTC, show in local time.** Log timestamps are normalized to UTC when parsed. SQLite has no time-zone-aware type, so a small SQLAlchemy `TypeDecorator` (`UTCDateTime`) writes naive UTC and returns *aware* UTC datetimes. Conversion to the display zone (the computer's zone via `tzlocal`, or `LOGSCOPE_TIMEZONE`) happens exactly once, when a value is displayed (Jinja `localtime` filter, report builders, and `Intl.DateTimeFormat` in the chart). Change the display zone with `LOGSCOPE_TIMEZONE`.
* **Three different times are never mixed up.** *Report generated* is the moment a report is built, *analysis created* is when the data was analyzed, and the *log period* is the first/last event inside the log. The Reports page and both report formats show them separately.

* **Folder monitoring by polling, not OS events.** `os.scandir` + `os.stat` every few seconds behaves the same on Windows, macOS and Linux and needs no extra dependency. Each `WatchedFile` stores its byte offset, line count, size, mtime and device/inode, so only appended bytes are read, unfinished lines wait, and replaced or truncated files are detected and re-read. One lock serializes the background thread and the "Scan now" button; SQLite runs in WAL mode so pages stay readable while the monitor writes.
* **Rotation by renaming.** When a fingerprint mismatch is caused by `app.log` being renamed (e.g. to `app.log.1`), the renamed file is found by its device/inode identity and the lines appended to it since the last scan are read before the new file — nothing is lost in the seconds before rotation.
* **No duplicate reads.** Each watched file stores SHA-256 fingerprints of its first bytes and of the bytes just before the read position. Matching fingerprints mean the file was only appended to (even if an editor or OneDrive rewrote it as a new file); a mismatch means rotation, truncation or replacement, and the file is read from the start.
* **Scales with log size.** Statistics of monitored files are SQL aggregates (`summarize_analysis`), findings are updated only for the time range around new records (`update_detections`, using the same `classify_entry`/`make_detection` functions as the in-memory detector), and recurring issues are a `GROUP BY` on a pattern stored at insert time. Totals come from running per-rule counters (`rule_counts`, an SQLite upsert per scan) and full re-detection streams rows from SQLite in time order per IP (`scan_detections`), so memory does not grow with the log. Composite indexes start with `analysis_id`. Tests check that incremental and streamed results equal a one-shot in-memory analysis, and that 100,000 lines from 5,000 IPs are processed in seconds.
* **Request guard.** Without user accounts, any website could otherwise submit LogScope's forms in the background. Changes are rejected unless the browser reports a same-origin request (`Sec-Fetch-Site`, `Origin`, `Referer`), and only localhost host names are answered, which also blocks DNS rebinding.
* **Database outside synced folders** with a minimal migration (`add_missing_columns`) so existing databases keep working when columns are added.
* **Long-running use.** Retention (default 30 days, by log time, monitored files only) runs hourly and compacts the database after large clean-ups; a heartbeat shows gaps when monitoring was not running; a file lock lets only one LogScope process monitor a database; on Windows, *Start at sign-in* writes a small `LogScope.vbs` to the user's Startup folder that runs `pythonw project.py`.
* **Explicit permission.** A folder is only read after the user enters it and ticks a consent box; only regular `.log`/`.txt` files directly inside it are read and links are not followed. Stop withdraws access.

## Future work

Several monitored folders, sub-folder and compressed-file support, cross-file findings, alerting (desktop/webhook), more log formats (JSON, syslog, `.evtx`), user accounts and a React front end.
