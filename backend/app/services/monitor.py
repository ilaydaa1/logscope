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
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import delete, distinct, select
from sqlalchemy.orm import Session

from project import parse_log_text

from ..database import SessionLocal, engine
from ..models import Analysis, LogEntry, Setting, WatchedFile
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
MAX_DRAIN_BYTES = 64 * 1024 * 1024   # max. bytes read from a renamed (rotated) file
RETENTION_CHOICES = (7, 30, 90, 365, 0)   # days of monitored records to keep; 0 = forever
RETENTION_INTERVAL = 3600.0          # seconds between automatic clean-ups
COMPACT_AFTER_ROWS = 10_000          # compact the database file after deleting this many records
HEARTBEAT_KEY = "monitor_heartbeat"

# Only one scan at a time (background thread vs. "Scan now" button).
_SCAN_LOCK = threading.Lock()
_runtime_lock = threading.Lock()
_runtime: dict[str, Any] = {"last_scan_at": None, "last_error": None, "last_new_records": 0,
                            "offline_gap": None, "last_cleanup": None}
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
    retention_days: int = 30          # monitored records older than this are deleted (0 = keep)


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
        config = MonitorConfig("running", str(path), timezone, include_existing, utc_now().isoformat(),
                               previous.retention_days)
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
            # Renamed away (e.g. app.log -> app.log.1) before a new file appeared:
            # read what was appended to it since the last scan.
            if watched.offset:
                try:
                    note = _drain_renamed(db, watched, timezone, config, result)
                except OSError:
                    note = ""
                if note:
                    watched.message = note
            if watched.status != "missing":
                watched.status = "missing"
                watched.message = watched.message if "rotated file" in watched.message else \
                    "File not found (deleted, moved or rotated away)."

        _refresh_touched(db, result)
        db.commit()
        return result


def _find_renamed(directory: Path, file_id: str, current: str) -> Path | None:
    """The file that still has the old identity, e.g. ``app.log`` renamed to ``app.log.1``.

    Rotated names often have other extensions, so every regular file in the
    folder is checked (this only happens when a rotation was detected).
    """
    if not file_id:
        return None
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.path == current:
                    continue
                try:
                    if entry.is_file(follow_symlinks=False) and \
                            _identity(os.stat(entry.path, follow_symlinks=False)) == file_id:
                        return Path(entry.path)
                except OSError:
                    continue
    except OSError:
        return None
    return None


def _drain_renamed(db: Session, watched: WatchedFile, timezone: ZoneInfo, config: MonitorConfig,
                   result: ScanResult) -> str:
    """Read lines written to a log after the last scan but before it was renamed away."""
    old = _find_renamed(Path(watched.path).parent, watched.file_id, watched.path)
    if old is None:
        return ""
    stat = os.stat(old)
    if not _same_content(old, watched, stat) or stat.st_size <= watched.offset:
        return ""
    remaining = stat.st_size - watched.offset
    data = _read_chunk(old, watched.offset, min(remaining, MAX_DRAIN_BYTES))
    _consume(db, watched, data, watched.encoding or UTF8, timezone, config, result, old)
    note = f"Read the last {len(data):,} bytes of the rotated file {old.name}."
    if remaining > MAX_DRAIN_BYTES:
        note += f" {remaining - MAX_DRAIN_BYTES:,} further bytes were skipped."
    return note


def _consume(db: Session, watched: WatchedFile, chunk: bytes, encoding: str, timezone: ZoneInfo,
             config: MonitorConfig, result: ScanResult, source: Path) -> int:
    """Parse and store ``chunk`` (bytes from ``watched.offset`` of ``source``). Returns unreadable lines."""
    at_start = watched.offset == 0
    if is_binary(chunk, encoding):
        watched.offset += len(chunk)
        _remember_fingerprint(source, watched)
        watched.status, watched.message = "error", "Binary (non-text) content was skipped."
        return 0

    text = decode(chunk, encoding, at_file_start=at_start)
    context = dict(watched.parser_state or {})
    entries, invalid = parse_log_text(text, timezone, context)
    watched.parser_state = context or None
    for entry in entries:
        entry["line_number"] += watched.line_count
    watched.line_count += text.count("\n") + (0 if text.endswith("\n") else 1)
    watched.offset += len(chunk)
    _remember_fingerprint(source, watched)

    if entries or invalid:
        analysis = _analysis_for(db, watched, config)
        svc.append_entries(db, analysis, entries, invalid)
        result.new_entries.setdefault(analysis.id, []).extend(entries)
        result.new_records += len(entries)
        result.invalid_lines += invalid
        if entries:
            watched.last_data_at = utc_now()
    return invalid


def _process_file(db: Session, watched: WatchedFile, stat: os.stat_result, timezone: ZoneInfo,
                  config: MonitorConfig, result: ScanResult) -> None:
    path = Path(watched.path)
    note = ""
    try:
        if watched.offset > 0 and not _same_content(path, watched, stat):
            # Rotated, truncated or replaced by different content. If the old file
            # was renamed (rename-style rotation), first read what it still had.
            drained = _drain_renamed(db, watched, timezone, config, result)
            watched.offset = watched.line_count = 0
            watched.encoding, watched.parser_state, watched.head_hash = "", None, ""
            note = " ".join(filter(None, [drained, "File was rotated or replaced; reading the new file from the start."]))
        stable = watched.size == stat.st_size and watched.mtime == stat.st_mtime
        watched.file_id, watched.size, watched.mtime = _identity(stat), stat.st_size, stat.st_mtime

        if stat.st_size <= watched.offset:
            if watched.status in ("waiting", "missing") or note:
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
            if note:
                watched.status, watched.message = "ok", note
            return
        invalid = _consume(db, watched, chunk, encoding, timezone, config, result, path)
        if watched.status == "error" and watched.message.startswith("Binary"):
            return
    except FileNotFoundError:
        watched.status, watched.message = "missing", "File disappeared while it was being read."
        return
    except PermissionError as error:
        watched.status = "error"
        # Windows reports files opened exclusively by another program (error 32) as PermissionError.
        watched.message = ("File is in use by another program; LogScope will retry."
                           if getattr(error, "winerror", None) == 32
                           else "Permission denied; LogScope cannot read this file.")
        return
    except OSError as error:
        watched.status, watched.message = "error", f"Read error: {error.strerror or error}"[:300]
        return

    watched.status = "ok"
    watched.message = note or (f"{invalid} unreadable line(s) skipped in the last update." if invalid else "")


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


# --------------------------------------------------------------------------- retention and database size

def save_retention(db: Session, days: int) -> None:
    if days not in RETENTION_CHOICES:
        raise MonitorError("Choose a retention period from the list.")
    config = get_config(db)
    config.retention_days = days
    _save_config(db, config)


def apply_retention(db: Session) -> int:
    """Delete monitored records older than the retention period; returns the number deleted.

    Only analyses created by folder monitoring are cleaned up (uploads and
    sample data are kept as they are). Age is measured by the event time in
    the log. Statistics, findings and counters of affected files are rebuilt.
    """
    with _SCAN_LOCK:
        days = get_config(db).retention_days
        if not days:
            return 0
        cutoff = utc_now() - timedelta(days=days)
        monitored = select(Analysis.id).where(Analysis.source == "monitor")
        old = (LogEntry.analysis_id.in_(monitored), LogEntry.timestamp < cutoff)
        affected = list(db.scalars(select(distinct(LogEntry.analysis_id)).where(*old)))
        if not affected:
            return 0
        deleted = db.execute(LogEntry.__table__.delete().where(*old)).rowcount or 0
        for analysis_id in affected:
            analysis = db.get(Analysis, analysis_id)
            if analysis is not None:
                svc.refresh_analysis(db, analysis)
        db.commit()
    _set_runtime(last_cleanup={"at": utc_now(), "deleted": deleted})
    log.info("Retention: deleted %s records older than %s days", deleted, days)
    return deleted


def database_file() -> Path | None:
    name = engine.url.database
    return Path(name) if engine.url.get_backend_name() == "sqlite" and name and name != ":memory:" else None


def database_size() -> int:
    """Size of the database including its write-ahead log, in bytes."""
    path = database_file()
    if path is None:
        return 0
    return sum(p.stat().st_size for p in (path, Path(f"{path}-wal")) if p.exists())


def compact_database() -> None:
    """Give space freed by deleted records back to the operating system."""
    if database_file() is None:
        return
    with _SCAN_LOCK, engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        connection.exec_driver_sql("VACUUM")
        connection.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")


def run_cleanup(db: Session | None = None) -> int:
    """Retention plus compaction when much was deleted. Never raises."""
    own_session = db is None
    db = db or SessionLocal()
    try:
        deleted = apply_retention(db)
        if deleted >= COMPACT_AFTER_ROWS:
            compact_database()
        return deleted
    except Exception:
        log.exception("Retention clean-up failed")
        db.rollback()
        return 0
    finally:
        if own_session:
            db.close()


# --------------------------------------------------------------------------- single instance

_lock_handle = None


def _lock_file() -> Path:
    database = database_file()
    return Path(f"{database}.lock") if database else Path.home() / ".logscope.lock"


def acquire_instance_lock() -> bool:
    """Only one LogScope process may monitor a database; otherwise lines would be stored twice."""
    global _lock_handle
    if _lock_handle is not None:
        return True
    path = _lock_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "a+b")
    try:
        if sys.platform == "win32":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return False
    _lock_handle = handle
    return True


def release_instance_lock() -> None:
    global _lock_handle
    if _lock_handle is None:
        return
    try:
        if sys.platform == "win32":
            import msvcrt

            _lock_handle.seek(0)
            msvcrt.locking(_lock_handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(_lock_handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass
    _lock_handle.close()
    _lock_handle = None


# --------------------------------------------------------------------------- offline detection

def _write_heartbeat(db: Session) -> None:
    setting = db.get(Setting, HEARTBEAT_KEY)
    value = {"at": utc_now().isoformat()}
    if setting:
        setting.value = value
    else:
        db.add(Setting(key=HEARTBEAT_KEY, value=value))
    db.commit()


def note_offline_gap(db: Session) -> None:
    """Remember how long monitoring was not running (LogScope closed or computer off)."""
    setting = db.get(Setting, HEARTBEAT_KEY)
    if not setting or get_config(db).state != "running":
        return
    last = datetime.fromisoformat(setting.value["at"])
    gap = utc_now() - last
    if gap > timedelta(seconds=max(60, 3 * SCAN_INTERVAL)):
        _set_runtime(offline_gap={"since": last, "until": utc_now()})


# --------------------------------------------------------------------------- status

def _set_runtime(**values: Any) -> None:
    with _runtime_lock:
        _runtime.update(values)


def run_scan(db: Session | None = None) -> ScanResult | None:
    """Scan once and record the outcome for the status display. Never raises."""
    if not acquire_instance_lock():
        _set_runtime(last_error="Another LogScope window or process is already monitoring. "
                                "Close it, or use that instance.")
        return None
    own_session = db is None
    db = db or SessionLocal()
    try:
        result = scan_once(db)
        if result.state == "running":
            _set_runtime(last_scan_at=utc_now(), last_error=result.error, last_new_records=result.new_records)
            _write_heartbeat(db)
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
        "retention_days": config.retention_days,
        "retention_choices": RETENTION_CHOICES,
        "database_size": database_size(),
        "database_path": str(database_file() or ""),
        "offline_gap": (
            f"Monitoring was not running from {format_local(runtime['offline_gap']['since'], '%Y-%m-%d %H:%M')} "
            f"to {format_local(runtime['offline_gap']['until'], '%Y-%m-%d %H:%M')}. Lines written in that time "
            "were read when LogScope started again."
            if runtime.get("offline_gap") and config.state == "running" else ""
        ),
        "last_cleanup": (
            f"{runtime['last_cleanup']['deleted']:,} old records removed at "
            f"{format_local(runtime['last_cleanup']['at'], '%Y-%m-%d %H:%M')}" if runtime.get("last_cleanup") else ""
        ),
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
        db = SessionLocal()
        try:
            note_offline_gap(db)
        except Exception:
            log.exception("Could not read the monitoring heartbeat")
        finally:
            db.close()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="logscope-monitor", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout)
        release_instance_lock()

    def wake(self) -> None:
        """Scan as soon as possible (e.g. right after monitoring was started)."""
        self._wake.set()

    def _run(self) -> None:
        next_cleanup = time.monotonic() + 30  # first clean-up shortly after start
        while not self._stop.is_set():
            if time.monotonic() >= next_cleanup:
                run_cleanup()
                next_cleanup = time.monotonic() + RETENTION_INTERVAL
            result = run_scan()
            # Catch up quickly on large files, otherwise wait for the next interval.
            delay = 0.2 if result is not None and result.backlog else SCAN_INTERVAL
            self._wake.wait(delay)
            self._wake.clear()


worker = MonitorWorker()
