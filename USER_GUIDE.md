# LogScope User Guide

LogScope analyzes server and application log files on your own computer. It can watch a log folder and analyze new lines automatically, or analyze files you upload. It shows errors, warnings, recurring issues and suspicious activity, and produces downloadable reports.

---

## Contents

1. [What is LogScope?](#1-what-is-logscope)
2. [Getting started](#2-getting-started)
3. [The interface](#3-the-interface)
4. [Pages and features](#4-pages-and-features)
5. [Common tasks](#5-common-tasks)
6. [Understanding the results](#6-understanding-the-results)
7. [Supported inputs and outputs](#7-supported-inputs-and-outputs)
8. [Limitations](#8-limitations)
9. [Quick reference](#9-quick-reference)

---

## 1. What is LogScope?

Servers write a line of text for every request, error or event. On a busy system these log files grow quickly and problems are easy to miss. LogScope:

- **reads log files automatically** from a folder you choose, processing only new lines as they are written;
- **summarizes** them: number of records, errors, warnings, HTTP status codes, most active IP addresses, activity over time;
- **finds problems**: suspicious patterns (rule-based) and recurring warnings/errors;
- **lets you drill down** to the exact log lines behind every number;
- **exports reports** as TXT or CSV and keeps a history of all analyses.

It is meant for developers, system administrators and anyone who needs a quick, local view of what their logs contain. Detection is rule-based and transparent: a finding means "this deserves a look", not "this is a confirmed attack". LogScope runs locally for one user; data stays in a database file on your computer.

---

## 2. Getting started

1. Install the requirements once: `pip install -r requirements.txt`
2. Start LogScope: `python project.py`
3. Open **http://127.0.0.1:8000** in your browser. Stop LogScope with **Ctrl+C** in the terminal.

Use another port with `python project.py --port 8080`. If `http://localhost:8000` shows another program, use `127.0.0.1` or another port.

**First analysis:**
- To watch a real log folder: **Log Analysis → Folder monitoring** (see [5.1](#51-monitor-a-log-folder)).
- To analyze one file: **Log Analysis → Upload file**.
- To try LogScope without logs: **Log Analysis → Sample data → Generate and analyze**.

---

## 3. The interface

| Area | What it shows |
|---|---|
| **Sidebar** | Main menu: Dashboard, Log Analysis, Findings, Logs, Reports, History. The red number next to Findings is the number of suspicious patterns in the selected analysis. On small screens, open it with **☰**. |
| **Monitoring badge** (sidebar) | Green **Monitoring**, amber **Paused** or grey **Off**. Click it to open folder monitoring. |
| **Analysis bar** | On Dashboard, Findings, Logs and Reports: the name of the analysis shown, its source (Uploaded file, Monitored file, Sample data), when it was analyzed or last updated, the number of records and how timestamps were read. |
| **Analysis selector** | In the analysis bar when several analyses exist: switch the page to another analysis. |
| **Messages** | Green box: an action succeeded. Red box: what went wrong. |

**What is an analysis?** Every uploaded file, every generated sample, and every file in a monitored folder becomes one *analysis*: its records, statistics and findings. Analyses are numbered (#1, #2 …) and saved. Pages show the newest analysis unless you choose another one. A monitored file's analysis keeps growing as new lines arrive.

All times are shown in your computer's time zone (set `LOGSCOPE_TIMEZONE` to choose another one).

---

## 4. Pages and features

### 4.1 Dashboard

| Section | Content | Interaction |
|---|---|---|
| **Monitored files** | When a folder is monitored: one row per file with status, records, errors, warnings, findings and last new data, plus totals for the whole folder. The file currently shown is highlighted. | Click a file to show it; click a findings number to open its findings |
| **System status** | Monitoring state, monitored folder, number of files and records, time of the last scan and of the last new data, and any folder error. Updates every few seconds. | **Set up / Manage** opens folder monitoring |
| **New records banner** | Appears when the monitored file you are viewing has received new lines since the page was loaded. | **Refresh** reloads the page |
| **Records** | Number of readable records (and unreadable lines skipped, or number of IP addresses). | Opens Logs |
| **Errors** | ERROR + CRITICAL records, critical count and error rate. | Opens Logs filtered to ERROR |
| **Warnings** | WARNING records and their share. | Opens Logs filtered to WARNING |
| **Findings** | Suspicious patterns and number of recurring issues. | Opens Findings |
| **Suspicious patterns** | Up to 5 patterns, most severe first, with a one-line summary. | **→** opens that finding |
| **Recurring issues** | Up to 5 repeated warnings/errors with count and last time seen. | **→** opens the matching records |
| **Activity** | Records per time interval (blue) and errors (red). | Hover for values; **click a point** to open the records of that interval |
| **Log levels / HTTP status / Top IP addresses** | Distributions as bars. | Click a bar to filter Logs |
| **Recent activity** | The 8 most recent records. | **All logs →** |

### 4.2 Log Analysis

Three tabs:

#### Folder monitoring

When monitoring is **off**, a form is shown:

| Field | Meaning |
|---|---|
| **Folder path** | Full path of the folder, e.g. `C:\logs\myapp` or `/var/log/myapp`. Only `.log` and `.txt` files directly in this folder are read (no sub-folders, no shortcuts/links). |
| **Timestamps without a zone are in** | UTC or your local time zone. Used only for times that do not include a zone. |
| **Existing content** | *Analyze existing lines too*, or *Only new lines from now on* (what the files already contain is skipped). |
| **I allow LogScope to read the log files in this folder** | Required. LogScope never reads a folder without this confirmation. |
| **Start monitoring** | Checks the folder (exists, is a folder, is readable) and starts. |

When monitoring is **on**:

| Element | Meaning |
|---|---|
| State badge and folder path | Monitoring or Paused. |
| **Scan now** | Reads new data immediately instead of waiting for the next automatic scan. |
| **Pause** / **Resume** | Pause stops reading but remembers where each file was; Resume continues from there. |
| **Stop** | Stops monitoring and withdraws access to the folder (asks for confirmation). Analyses created so far are kept. |
| Files · Records · Last scan · Last new data · Interval | Overall status. The folder is checked every 5 seconds. |
| **File table** | For each file: name (click to open its Dashboard), status, size, how much has been read, records, findings, time of last new data, and a note (e.g. "File was rotated…"). Updates automatically. |

File statuses: **Waiting** (not read yet), **Ok**, **Missing** (deleted or moved), **Error** (e.g. permission denied, file in use by another program, binary content).

**Settings** (below the file table, always available):

| Setting | Meaning |
|---|---|
| **Keep monitored records** | 7 days, 30 days (default), 90 days, 1 year or Forever. Records of monitored files whose log time is older are deleted every hour, and statistics and findings are recalculated. Uploaded files and sample data are never deleted automatically. **Save** applies it immediately. |
| **Database** | Current size of LogScope's database. **Compact now** gives the space of deleted records back to the disk (also done automatically after large clean-ups). |
| **Start at sign-in** (Windows) | **Turn on** makes LogScope start in the background whenever you sign in to Windows, so monitoring continues without opening a terminal. It adds one file, `LogScope.vbs`, to your Startup folder; **Turn off** removes it. |

If LogScope was closed for a while (or the computer was off), the status shows *Monitoring was not running from … to …*. Lines written during that time are read when it starts again.

Only one LogScope can monitor at a time. If a second copy is started (for example once by sign-in and once by hand), it shows a message instead of reading the files a second time.

If the folder is inside OneDrive, a warning is shown: OneDrive may download online-only files when they are read and may rewrite files while syncing. LogScope handles rewrites without reading lines twice, but a local folder (e.g. `C:\Logs`) is more reliable.

#### Upload file

Choose or drag a `.log`/`.txt` file (max 10 MB), choose the time zone for timestamps without a zone, and click **Upload and analyze**. You land on the Dashboard of the new analysis. The supported formats are shown on the page.

#### Sample data

Generates synthetic logs for testing rules and reports (not real events). Choose a scenario (Normal traffic, Failed login attempts, Password guessing, Many 'page not found' errors, Server errors, Very high request volume, Mixed traffic), the number of records (200–20,000; quick buttons 200/1,000/5,000/10,000) and an optional seed (same seed = same events). **Generate and analyze** creates an analysis; **Download .log file** saves the file instead. Suspicious sample traffic uses reserved example addresses (203.0.113.x, 198.51.100.x).

### 4.3 Findings

| Section | Content |
|---|---|
| **Summary** | Suspicious patterns, recurring issues, errors, warnings. |
| **Suspicious patterns** | One card per finding: severity, rule, IP address (or "all clients"), summary; **Rule** (what is counted and the limit, peak and total), **When** (busiest time window), **Suggested check**. **View the N … in this window** opens exactly those records; **All records from [IP]** opens everything from that client. |
| **Recurring issues** | Warnings and errors that occur more than once, grouped by message (numbers and quoted values are ignored, so "timeout after 31 s" and "timeout after 45 s" are one issue). Columns: level, message pattern, status, count, number of IPs, first and last seen. **View** opens matching records. |
| **Detection rules** (click to open) | Limit and time window of each rule. **Run detection again** applies new values to this analysis; tick **Use these limits for future analyses** to keep them; **Reset to built-in defaults** restores the originals. Values: whole numbers 1–86,400. |

### 4.4 Logs

Searchable table of all records of an analysis.

| Filter | Behavior |
|---|---|
| **Search text** | Message, path or IP contains the text (not case-sensitive for English letters). |
| **Level** | One log level. |
| **IP address** | Exact address (suggestions offered). |
| **HTTP status** | A group (2xx–5xx) or an exact code. |
| **From / To** | Time range in Istanbul time, both inclusive. |

**Search** applies, **Clear filters** removes all. Active filters are listed above the table. **Newest first / Oldest first** switches the order (newest first by default, so the latest monitored lines are on page 1). Columns: Time, IP address (click to filter), Level, Request, Status, Message, Line (line number in the file). 50 records per page with First/Previous/Next/Last. Invalid filter values are ignored.

### 4.5 Reports

**Download TXT** or **Download CSV** for the selected analysis. The page shows three separate times — *Report generated*, *Analysis created*, *Log period* — and a preview of the TXT report. Files are named `logscope-report-<id>-<date>-<time>.txt/.csv`.

### 4.6 History

All analyses, newest first: name (click to open), number, source, unreadable lines, analysis time, records, error rate, number of findings (click to open Findings), and **Open**, **Report** and **Delete** (with confirmation; cannot be undone). Deleting the analysis of a monitored file does not stop monitoring: the next new lines of that file start a new analysis.

---

## 5. Common tasks

### 5.1 Monitor a log folder

1. Open **Log Analysis** (Folder monitoring tab).
2. Enter the full folder path, e.g. `C:\inetpub\logs\myapp` or `/var/log/nginx`.
3. Choose the time zone of timestamps that have no zone (the server's local zone; UTC if unsure).
4. Choose whether existing lines should be analyzed or only new ones.
5. Tick the permission box and click **Start monitoring**.
6. Within seconds the file table fills in. Every file becomes its own analysis — click a file name to open its Dashboard.
7. Leave LogScope running. New lines are read every 5 seconds; the Dashboard status and file table update by themselves. Monitoring also resumes automatically after LogScope is restarted.
8. Optional: in **Settings**, turn on **Start at sign-in** so you never have to start it by hand, and choose how long records are kept.

**Example:** your application writes `C:\logs\shop\app.log`. Monitor `C:\logs\shop`. When the application logs `2026-11-11 21:50:00 ERROR Payment service timeout after 30 s` several times, the **Errors** count rises and "Payment service timeout after # s" appears under **Recurring issues**.

### 5.2 Analyze a single file

**Log Analysis → Upload file** → choose the file and time zone → **Upload and analyze**.

If an error appears: *Unsupported file type* (use .log/.txt), *File is too large* (limit 10 MB — or monitor its folder instead, which has no size limit), *empty*, *binary* (not plain text), *No valid log lines were found* (format not supported, see [section 7](#7-supported-inputs-and-outputs)).

### 5.3 Investigate a problem

1. On the **Dashboard**, look at **Errors**, **Warnings**, **Suspicious patterns** and **Recurring issues**.
2. Click **→** next to a finding. The Findings card explains which rule triggered, the busiest time window and what to check.
3. Click **View the N … in this window** to see exactly the records involved.
4. Click an IP address in the table to see everything that client did; widen the **From / To** range to see what happened before and after.

*Example:* "Possible brute-force activity — 44 failed logins from 203.0.113.45 within 2 minutes" → **View the 44 failed logins in this window** → check the user names tried → **All records from 203.0.113.45** to see whether a later login succeeded.

### 5.4 Look at a specific time

Click the point in the **Activity** chart, or enter **From / To** on the Logs page.

### 5.5 Adjust detection sensitivity

**Findings → Detection rules** → change Limit/Window → **Run detection again**. Lower limits flag more; higher limits flag less. Tick **Use these limits for future analyses** to keep them (also applies to newly monitored files).

### 5.6 Export results

**Reports → Download TXT** (readable) or **Download CSV** (spreadsheet). Or **History → Report** for any analysis.

### 5.7 Pause or stop monitoring

**Log Analysis → Pause** (keeps the reading position) / **Resume**. **Stop** withdraws folder access; analyses stay in History. Turning off **Start at sign-in** keeps LogScope from starting automatically next time.

---

## 6. Understanding the results

### 6.1 Numbers

| Metric | Meaning |
|---|---|
| Records | Lines LogScope could read. |
| Unreadable lines | Lines in an unknown format or with invalid values (blank lines are ignored). Many unreadable lines usually mean an unsupported format. |
| Errors | ERROR + CRITICAL records; error rate = their share of all records. |
| Warnings | WARNING records. |
| IP addresses | Distinct clients. |
| Findings | Suspicious patterns from the detection rules. |
| Recurring issues | Warning/error message patterns that occur at least twice. |

### 6.2 Log levels and status codes

Levels: DEBUG (technical detail), INFO (normal), WARNING (unusual), ERROR (failure), CRITICAL (serious failure). Spellings such as `warn`, `err`, `fatal`, `crit`, `alert`, `emerg`, `trace`, `notice` are recognized.

HTTP status: **2xx** success, **3xx** redirect, **4xx** request problem (401 unauthorized, 403 forbidden, 404 not found), **5xx** server problem (500, 502, 503).

### 6.3 Detection rules

A rule looks for the **busiest time window** of a given length and flags it when the number of matching events reaches the limit.

| Rule | Counts | Per | Built-in limit |
|---|---|---|---|
| Possible brute-force activity | 401/403 on a login/auth path (`login`, `signin`, `auth`, `session`, `wp-login`…) or messages like "failed login", "invalid password", "authentication failure" | IP | 5 in 2 minutes |
| Excessive 404 responses | 404 responses | IP | 20 in 5 minutes |
| Server error spike | 500–599 responses | all clients | 10 in 1 minute |
| Unusually high request volume | any record with an IP | IP | 120 in 1 minute |

**Severity:** Low = reached the limit; Medium = at least 2× the limit; High = at least 4×. Example: 44 failed logins with a limit of 5 → 8.8× → High.

Only the busiest window per rule and IP is reported. A finding is a reason to check, not proof; activity that matches none of the rules is not flagged.

### 6.4 Recurring issues

Messages are compared after replacing numbers, IDs, IP addresses and quoted values with `#`. Example: `Failed login for user "bob"` and `Failed login for user "root"` both become `Failed login for user #`. Records without a message (e.g. Apache lines) are grouped by request (`GET /item/#`). Sorted by level (critical first), then by count.

### 6.5 Times

Three kinds of time are kept apart: **event time** (from the log), **analysis created/updated** (when LogScope processed it) and **report generated**. All are shown in Istanbul time.

### 6.6 Reports

**TXT:** report time, analyzed data (source, analysis time, log period, time zone used), summary, level distribution, HTTP status distribution, top 10 IP addresses, suspicious patterns with explanation, rules used, disclaimer.
**CSV:** columns `section, item, value, details`; sections `report`, `analysis`, `summary`, `level`, `status`, `top_ip`, `suspicious_pattern`, `note`.

---

## 7. Supported inputs and outputs

### 7.1 Files

| | Upload | Folder monitoring |
|---|---|---|
| File types | `.log`, `.txt` | `.log`, `.txt` directly in the chosen folder |
| Size | max 10 MB | no limit (read in 8 MB steps) |
| Content | plain text, one record per line, UTF-8 or UTF-16 (detected automatically; invalid characters are replaced) | same; binary content is skipped and reported |
| Max line length | 4,096 characters | 4,096 characters |

### 7.2 Log formats

1. **Application access log**
   `2026-11-11T14:23:01Z WARNING 203.0.113.7 POST /login 401 - Failed login for user "admin"`
2. **Apache / Nginx** (common or combined) — level derived from status (5xx ERROR, 4xx WARNING, else INFO)
   `203.0.113.7 - - [11/Nov/2026:14:23:01 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8.0"`
3. **Application log** (no request fields)
   `2026-11-11 14:23:01,123 ERROR Database connection lost`
4. **IIS / W3C extended log** — the `#Fields:` line describes the columns; times are UTC
   `2026-11-11 10:00:05 10.0.0.5 GET /shop/item.aspx id=7 443 - 203.0.113.9 Mozilla/5.0 - 404 0 2 15`

Accepted details: ISO-style times with optional fractions and zone (`Z`, `+03:00`, `+0300`), levels with brackets/colon (`[ERROR]`, `ERROR:`), IPv4 and IPv6, methods GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS/CONNECT/TRACE, status 100–599. Other lines are counted as unreadable.

### 7.3 How monitoring reads files

- Each file's read position is remembered; only new bytes are read, so lines are never analyzed twice (also across restarts).
- An unfinished last line is held until it is complete (or the file has not changed for one scan).
- **No duplicates:** LogScope remembers a fingerprint of each file's beginning and of the part it has read. If a program saves the file again with the same old lines plus new ones (some editors and OneDrive do this), only the new lines are read.
- **Rotation:** if a log is rotated by renaming (`app.log` → `app.log.1`, then a new `app.log`), LogScope first reads the lines that were still added to the old file, then reads the new file from the beginning. If the old content is simply gone (truncated or replaced), the new content is read from the beginning. Rotated files themselves (e.g. `app.log.1`) are not monitored as separate files.
- Missing files, permission problems and a missing folder are shown in the file table / status instead of stopping monitoring.

### 7.4 Outputs

Dashboard and pages; TXT and CSV reports; sample `.log` files. All data is stored in `%LOCALAPPDATA%\LogScope\logscope.db` on Windows (`~/Library/Application Support/LogScope` on macOS, `~/.local/share/logscope` on Linux) — outside synced folders such as OneDrive. A database from an earlier version in the project's `data` folder is copied there automatically once.

---

## 8. Limitations

- **One folder** at a time, not including sub-folders; only `.log`/`.txt` names (compressed or numbered rotated files such as `.gz` or `.log.1` are not read).
- **Polling every 5 seconds**, not instant. LogScope must be running to monitor (use *Start at sign-in*); lines written while it is off are read when it starts again. If a file was rotated *several* times while LogScope was off, only the last rotated file and the new file are read.
- **Statistics delay:** for monitored files, totals and charts are updated at most every 10 seconds (30 s while catching up on a big file); findings are updated with every scan.
- A last line without a newline that is extended later (after being read) is split into two records.
- **Formats:** JSON logs, syslog, Windows Event Log files (`.evtx`) and multi-line entries (stack traces) are not supported.
- Timestamps without a zone can only be read as UTC or the local time zone.
- **Detection:** four fixed rules; one result (busiest window) per rule and IP; records without IP are not counted by per-IP rules; the failed-login link searches for "login". No alerts or notifications.
- **Logs page:** sorting by time only (newest or oldest first); no partial-IP search; filtered results cannot be exported separately.
- Uploading the same file twice creates two analyses; analyses cannot be renamed; deletion cannot be undone.
- Single user without login. LogScope only answers requests addressed to this computer (localhost) and rejects changes coming from other websites, but it should not be exposed to a network.
- Reports: TXT and CSV only.

---

## 9. Quick reference

| I want to… | Do this |
|---|---|
| Watch a log folder | Log Analysis → Folder monitoring → path, permission → Start monitoring |
| Check new data now | Log Analysis → Scan now |
| Temporarily stop reading | Log Analysis → Pause (→ Resume) |
| Remove folder access | Log Analysis → Stop |
| Analyze one file | Log Analysis → Upload file |
| Try without logs | Log Analysis → Sample data → Generate and analyze |
| See the overall state | Dashboard |
| See what went wrong | Dashboard → Errors / Recurring issues, or Findings |
| See the lines behind a finding | Findings → View the N … in this window |
| Look at a time period | Click the Activity chart, or Logs → From / To |
| Change detection sensitivity | Findings → Detection rules |
| Export | Reports → Download TXT / CSV |
| Open an older analysis | History, or the analysis selector |

**Start options:** `--port` (default 8000), `--host` (default 127.0.0.1). Environment variables: `LOGSCOPE_TIMEZONE` (display zone, default: the computer's zone), `LOGSCOPE_DATA_DIR` / `LOGSCOPE_DATABASE_URL` (database location), `LOGSCOPE_ALLOWED_HOSTS` (extra host names), `LOGSCOPE_SCAN_INTERVAL` (seconds between folder scans, default 5).
