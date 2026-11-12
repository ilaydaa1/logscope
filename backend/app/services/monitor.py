"""Automatic monitoring of one user-approved local log folder.

How it works
------------
* The user explicitly selects a folder and confirms read access. Only that
  folder is read (not sub-folders), only ``.log``/``.txt`` files, and
  symbolic links are not followed.
* A background thread polls the folder every few seconds (polling works the
  same on Windows, macOS and Linux and needs no extra dependency).
* For every file LogScope remembers how many bytes it has already processed
  (``WatchedFile.offset``). Each scan reads only the bytes appended since then,
  so files are never analyzed twice. Large files are read in chunks.
* Incomplete last lines are kept until the line is finished (or the file has
  not changed for one scan interval).
* Continuity check: a fingerprint of the file's first bytes and of the bytes
  just before the read position is stored. If both still match, the file was
  only appended to - even when an editor or sync tool rewrote it as a new
  file - so nothing is read twice. If they differ (rotation, truncation,
  replacement with other content), the file is read again from the start.
* UTF-8 and UTF-16 files are supported; W3C/IIS ``#Fields:`` headers are
  remembered between reads.
* Each monitored file has its own analysis that grows as new lines arrive.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from project import parse_log_text

from ..database import SessionLocal
from ..models import Analysis, Setting, WatchedFile
from ..timeutils import format_local, utc_now
from . import analysis_service as svc
from .textcodec import UTF8, complete_lines_end, decode, detect_encoding, is_binary

log = logging.getLogger("logscope.monitor")

CONFIG_KEY = "monitor"
ALLOWED_EXTENSIONS = {".log", ".txt"}
CHUNK_BYTES = 8 * 1024 * 1024        # read at most 8 MB per file per scan
SCAN_INTERVAL = float(os.environ.get("LOGSCOPE_SCAN_INTERVAL", "5"))
REFRESH_DURING_BACKLOG = 30.0        # seconds between statistics refreshes while catching up
STATS_INTERVAL = 10.0                # seconds between statistics refreshes of a growing file
HEAD_BYTES = 1024                    # fingerprint: start of the file
TAIL_BYTES = 256                     # fingerprint: bytes just before the read position

# Only one scan at a time (background thread vs. "Scan now" button).
_SCAN_LOCK = threading.Lock()
_runtime_lock = threading.Lock()
_runtime: dict[str, Any] = {"last_scan_at": None, "last_error": None, "last_new_records": 0}
_last_refresh: dict[int, float] = {}
_dirty: set[int] = set()             # analyses whose statistics wait for a refresh


class MonitorError(ValueError):
    """A user-facing problem with the monitoring settings."""


@dataclass
class MonitorConfig:
    state: str = "stopped"            # running | paused | stopped
    directory: str = ""
    timezone: str = "UTC"             # zone of timestamps without an offset
    include_existing: bool = True     # also read what the files already contain
    started_at: str | None = None


@dataclass
class ScanResult:
    state: str = "running"
    files: int = 0
    new_records: int = 0
    invalid_lines: int = 0
    backlog: bool = False
    error: str | None = None
    new_entries: dict[int, list] = field(default_factory=dict)  # analysis id -> records added this scan


# --------------------------------------------------------------------------- configuration

def get_config(db: Session) -> MonitorConfig:
    setting = db.get(Setting, CONFIG_KEY)
    data = setting.value if setting else {}
    return MonitorConfig(**{k: v for k, v in data.items() if k in MonitorConfig.__dataclass_fields__})


def _save_config(db: Session, config: MonitorConfig) -> None:
    setting = db.get(Setting, CONFIG_KEY)
    if setting:
        setting.value = asdict(config)
    else:
        db.add(Setting(key=CONFIG_KEY, value=asdict(config)))
    db.commit()


def validate_directory(raw: str) -> Path:
    """Check that ``raw`` is an existing, readable folder given as a full path."""
    text = (raw or "").strip().strip('"').strip("'")
    if not text:
        raise MonitorError("Enter the full path of the folder to monitor.")
    path = Path(text).expanduser()
    if not path.is_absolute():
        raise MonitorError("Enter a full path, for example C:\\logs or /var/log/myapp.")
    try:
        path = path.resolve(strict=True)
    except OSError:
        raise MonitorError("This folder does not exist.") from None
    if not path.is_dir():
        raise MonitorError("This path is a file, not a folder.")
    try:
        with os.scandir(path):
            pass
    except PermissionError:
        raise MonitorError("LogScope does not have permission to read this folder.") from None
    except OSError as error:
        raise MonitorError(f"The folder cannot be read: {error.strerror or error}.") from None
    return path


def start_monitoring(db: Session, directory: str, timezone: str, include_existing: bool) -> MonitorConfig:
    """Grant access to ``directory`` and start monitoring it."""
    path = validate_directory(directory)
    try:
        ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError):
        raise MonitorError("Choose a time zone from the list.") from None

    with _SCAN_LOCK:
        previous = get_config(db)
        if previous.directory != str(path) or previous.state == "stopped":
            db.execute(delete(WatchedFile))  # new permission: start tracking from scratch
        config = MonitorConfig("running", str(path), timezone, include_existing, utc_now().isoformat())
        _save_config(db, config)
        _register_existing_files(db, path, include_existing)
        db.commit()
    _set_runtime(last_error=None)
    return config


def pause_monitoring(db: Session) -> None:
    config = get_config(db)
    if config.state == "running":
        config.state = "paused"
        _save_config(db, config)


def resume_monitoring(db: Session) -> None:
    config = get_config(db)
    if config.state == "paused" and config.directory:
        config.state = "running"
        _save_config(db, config)


def stop_monitoring(db: Session) -> None:
    """Stop and withdraw folder access. Analyses created so far are kept."""
    with _SCAN_LOCK:
        config = get_config(db)
        config.state = "stopped"
        _save_config(db, config)
        db.execute(delete(WatchedFile))
        db.commit()
    _set_runtime(last_error=None)


# --------------------------------------------------------------------------- scanning

def _list_log_files(directory: Path) -> dict[str, os.stat_result]:
    """Regular .log/.txt files directly inside ``directory`` (no sub-folders, no links)."""
    files = {}
    with os.scandir(directory) as entries:
        for entry in entries:
            if Path(entry.name).suffix.lower() not in ALLOWED_EXTENSIONS:
                continue
            try:
                if entry.is_file(follow_symlinks=False):
                    # os.stat (not entry.stat) so Windows also reports the file index.
                    files[entry.path] = os.stat(entry.path, follow_symlinks=False)
            except OSError:
                continue  # vanished or unreadable between listing and stat
    return files


def _identity(stat: os.stat_result) -> str:
    return f"{stat.st_dev}:{stat.st_ino}" if stat.st_ino else ""


def _register_existing_files(db: Session, directory: Path, include_existing: bool) -> None:
    known = {wf.path for wf in db.scalars(select(WatchedFile))}
    for path, stat in _list_log_files(directory).items():
        if path in known:
            continue
        watched = WatchedFile(
            path=path, offset=0 if include_existing else stat.st_size, file_id=_identity(stat),
            size=stat.st_size, mtime=stat.st_mtime, status="waiting",
            message="" if include_existing else "Existing content skipped; waiting for new lines.",
        )
        if not include_existing:
            try:
                with open(path, "rb") as handle:
                    watched.encoding = detect_encoding(handle.read(4096))
                _remember_fingerprint(Path(path), watched)
            except OSError:
                pass  # reported on the first scan
        db.add(watched)


def _read_chunk(path: Path, offset: int, length: int) -> bytes:
    with open(path, "rb") as handle:
        handle.seek(offset)
        return handle.read(length)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _remember_fingerprint(path: Path, watched: WatchedFile) -> None:
    """Store hashes of the file start and of the bytes just before ``offset``."""
    watched.head_len = min(HEAD_BYTES, watched.offset)
    watched.head_hash = _digest(_read_chunk(path, 0, watched.head_len))
    tail_start = max(0, watched.offset - TAIL_BYTES)
    watched.tail_hash = _digest(_read_chunk(path, tail_start, watched.offset - tail_start))


def _same_content(path: Path, watched: WatchedFile, stat: os.stat_result) -> bool:
    """True if the bytes already processed are unchanged, i.e. the file was only appended to."""
    if stat.st_size < watched.offset:
        return False                                   # truncated
    if not watched.head_hash:                          # stored by an older version: use identity
        identity = _identity(stat)
        return not (watched.file_id and identity and watched.file_id != identity)
    if _digest(_read_chunk(path, 0, watched.head_len)) != watched.head_hash:
        return False
    tail_start = max(0, watched.offset - TAIL_BYTES)
    return _digest(_read_chunk(path, tail_start, watched.offset - tail_start)) == watched.tail_hash


def scan_once(db: Session) -> ScanResult:
    """Process everything that was added to the monitored files since the last scan."""
    with _SCAN_LOCK:
        config = get_config(db)
        if config.state != "running":
            return ScanResult(state=config.state)
        result = ScanResult()
        try:
            files = _list_log_files(Path(config.directory))
        except FileNotFoundError:
            result.error = "The monitored folder no longer exists."
            return result
        except PermissionError:
            result.error = "Permission to read the monitored folder was denied."
            return result
        except OSError as error:
            result.error = f"The monitored folder cannot be read: {error.strerror or error}."
            return result

        timezone = ZoneInfo(config.timezone)
        tracked = {wf.path: wf for wf in db.scalars(select(WatchedFile))}
        result.files = len(files)
        for path, stat in sorted(files.items()):
            watched = tracked.pop(path, None)
            if watched is None:  # a file created after monitoring started: read it completely
                watched = WatchedFile(path=path, offset=0, file_id=_identity(stat), size=-1, mtime=0.0)
                db.add(watched)
                db.flush()
            _process_file(db, watched, stat, timezone, config, result)

        for watched in tracked.values():
            if watched.status != "missing":
                watched.status = "missing"
                watched.message = "File not found (deleted, moved or rotated away)."

        _refresh_touched(db, result)
        db.commit()
        return result


def _process_file(db: Session, watched: WatchedFile, stat: os.stat_result, timezone: ZoneInfo,
                  config: MonitorConfig, result: ScanResult) -> None:
    path = Path(watched.path)
    note = ""
    try:
        if watched.offset > 0 and not _same_content(path, watched, stat):
            # Rotated, truncated or replaced by different content: start over.
            watched.offset = watched.line_count = 0
            watched.encoding, watched.parser_state, watched.head_hash = "", None, ""
            note = "File was rotated or replaced with new content; reading it from the start."
        stable = watched.size == stat.st_size and watched.mtime == stat.st_mtime
        watched.file_id, watched.size, watched.mtime = _identity(stat), stat.st_size, stat.st_mtime

        if stat.st_size <= watched.offset:
            if watched.status in ("waiting", "missing"):
                watched.status, watched.message = "ok", note
            if watched.offset and not watched.head_hash:
                _remember_fingerprint(path, watched)   # upgrade rows from older versions
            return

        data = _read_chunk(path, watched.offset, min(CHUNK_BYTES, stat.st_size - watched.offset))
        if watched.offset == 0:
            watched.encoding = detect_encoding(data[:4096])
        encoding = watched.encoding or UTF8
        more = watched.offset + len(data) < stat.st_size
        end = complete_lines_end(data, encoding)
        if end > 0 and not (stable and not more):
            chunk = data[:end]                    # complete lines only; keep the unfinished one
        elif end > 0 or stable or len(data) >= CHUNK_BYTES:
            chunk = data                          # unchanged file, or a single oversized line
        else:
            chunk = b""                           # a line is still being written
        result.backlog = result.backlog or more
        if not chunk:
            return

        at_start = watched.offset == 0
        if is_binary(chunk, encoding):
            watched.offset += len(chunk)
            _remember_fingerprint(path, watched)
            watched.status, watched.message = "error", "Binary (non-text) content was skipped."
            return

        text = decode(chunk, encoding, at_file_start=at_start)
        context = dict(watched.parser_state or {})
        entries, invalid = parse_log_text(text, timezone, context)
        watched.parser_state = context or None
        for entry in entries:
            entry["line_number"] += watched.line_count
        watched.line_count += text.count("\n") + (0 if text.endswith("\n") else 1)
        watched.offset += len(chunk)
        _remember_fingerprint(path, watched)
    except FileNotFoundError:
        watched.status, watched.message = "missing", "File disappeared while it was being read."
        return
    except PermissionError:
        watched.status, watched.message = "error", "Permission denied; LogScope cannot read this file."
        return
    except OSError as error:
        watched.status, watched.message = "error", f"Read error: {error.strerror or error}"[:300]
        return

    watched.status = "ok"
    watched.message = note or (f"{invalid} unreadable line(s) skipped in the last update." if invalid else "")
    if entries or invalid:
        analysis = _analysis_for(db, watched, config)
        svc.append_entries(db, analysis, entries, invalid)
        result.new_entries.setdefault(analysis.id, []).extend(entries)
        result.new_records += len(entries)
        result.invalid_lines += invalid
        if entries:
            watched.last_data_at = utc_now()


def _analysis_for(db: Session, watched: WatchedFile, config: MonitorConfig) -> Analysis:
    analysis = db.get(Analysis, watched.analysis_id) if watched.analysis_id else None
    if analysis is None:
        name = Path(watched.path).name
        analysis = svc.create_empty_analysis(
            db, name=name, source="monitor", filename=name,
            extra_summary={"source_timezone": config.timezone, "monitor_path": watched.path},
        )
        watched.analysis_id = analysis.id
    return analysis


def _refresh_touched(db: Session, result: ScanResult) -> None:
    """Update findings for the new records now; statistics at most every few seconds.

    Findings only need the time range around the new records. Statistics are
    SQL aggregates over the whole file, so they are throttled (10 s, or 30 s
    while catching up on a large file) and flushed on a later scan.
    """
    for analysis_id, new in result.new_entries.items():
        analysis = db.get(Analysis, analysis_id)
        if analysis is not None:
            svc.update_detections(db, analysis, new)
            _dirty.add(analysis_id)
    now = time.monotonic()
    interval = REFRESH_DURING_BACKLOG if result.backlog else STATS_INTERVAL
    for analysis_id in list(_dirty):
        if now - _last_refresh.get(analysis_id, float("-inf")) < interval:
            continue
        analysis = db.get(Analysis, analysis_id)
        if analysis is not None:
            svc.refresh_statistics(db, analysis)
        _last_refresh[analysis_id] = now
        _dirty.discard(analysis_id)


# --------------------------------------------------------------------------- status

def _set_runtime(**values: Any) -> None:
    with _runtime_lock:
        _runtime.update(values)


def run_scan(db: Session | None = None) -> ScanResult | None:
    """Scan once and record the outcome for the status display. Never raises."""
    own_session = db is None
    db = db or SessionLocal()
    try:
        result = scan_once(db)
        if result.state == "running":
            _set_runtime(last_scan_at=utc_now(), last_error=result.error, last_new_records=result.new_records)
        return result
    except Exception as error:  # keep the monitor alive whatever happens
        log.exception("Monitoring scan failed")
        db.rollback()
        _set_runtime(last_scan_at=utc_now(), last_error=f"Scan failed: {error}")
        return None
    finally:
        if own_session:
            db.close()


def in_synced_folder(path: str) -> bool:
    """True for folders synced by OneDrive (files may be rewritten or downloaded on access)."""
    if not path:
        return False
    target = os.path.normcase(os.path.abspath(path))
    for variable in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        root = os.environ.get(variable)
        if root and (target + os.sep).startswith(os.path.normcase(os.path.abspath(root)) + os.sep):
            return True
    return any(part.lower().startswith("onedrive") for part in Path(path).parts)


def monitor_status(db: Session) -> dict[str, Any]:
    """Everything the pages need to show the monitoring state (JSON-serializable)."""
    config = get_config(db)
    with _runtime_lock:
        runtime = dict(_runtime)
    files = []
    last_data = None
    for watched in db.scalars(select(WatchedFile).order_by(WatchedFile.path)):
        analysis = db.get(Analysis, watched.analysis_id) if watched.analysis_id else None
        if watched.last_data_at and (last_data is None or watched.last_data_at > last_data):
            last_data = watched.last_data_at
        files.append({
            "name": Path(watched.path).name,
            "size": watched.size if watched.size >= 0 else 0,
            "processed": min(watched.offset, max(watched.size, 0)),
            "progress": round(min(watched.offset / watched.size, 1) * 100) if watched.size > 0 else 100,
            "records": analysis.total_entries if analysis else 0,
            "findings": analysis.detection_count if analysis else 0,
            "errors": _level(analysis, "ERROR") + _level(analysis, "CRITICAL"),
            "warnings": _level(analysis, "WARNING"),
            "analysis_id": analysis.id if analysis else None,
            "status": watched.status,
            "message": watched.message,
            "last_data_at": format_local(watched.last_data_at, "%Y-%m-%d %H:%M:%S") if watched.last_data_at else "",
        })
    return {
        "state": config.state,
        "directory": config.directory,
        "timezone": config.timezone,
        "include_existing": config.include_existing,
        "worker_alive": worker.alive,
        "interval": SCAN_INTERVAL,
        "last_scan_at": format_local(runtime["last_scan_at"]) if runtime["last_scan_at"] else "",
        "last_data_at": format_local(last_data) if last_data else "",
        "last_error": runtime["last_error"] if config.state == "running" else None,
        "files": files,
        "total_records": sum(f["records"] for f in files),
        "total_errors": sum(f["errors"] for f in files),
        "total_warnings": sum(f["warnings"] for f in files),
        "total_findings": sum(f["findings"] for f in files),
        "synced_folder": in_synced_folder(config.directory),
    }


def _level(analysis: Analysis | None, level: str) -> int:
    return (analysis.summary.get("level_counts") or {}).get(level, 0) if analysis else 0


# --------------------------------------------------------------------------- background worker

class MonitorWorker:
    """Runs ``run_scan`` in a daemon thread until the application stops."""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._wake = threading.Event()

    @property
    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self.alive:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="logscope-monitor", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout)

    def wake(self) -> None:
        """Scan as soon as possible (e.g. right after monitoring was started)."""
        self._wake.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            result = run_scan()
            # Catch up quickly on large files, otherwise wait for the next interval.
            delay = 0.2 if result is not None and result.backlog else SCAN_INTERVAL
            self._wake.wait(delay)
            self._wake.clear()


worker = MonitorWorker()
