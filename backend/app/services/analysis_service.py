"""Glue between the core functions in project.py and the database.

Uploads and sample data are analyzed in memory with the core functions.
Monitored files grow continuously, so their statistics are computed with SQL
aggregates (``summarize_analysis``) and their findings are updated only for the
time range touched by new records (``update_detections``); memory use does
not grow with the size of the log.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import Integer, case, cast, delete, distinct, func, insert, or_, select, tuple_, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from project import (
    DEFAULT_THRESHOLDS,
    LOG_LEVELS,
    SEVERITY_ORDER,
    analyze_log_entries,
    choose_bucket_size,
    classify_entry,
    detect_suspicious_activity,
    is_failed_login,
    make_detection,
    recurring_search_text,
    parse_log_text,
    peak_window,
    recurring_key,
)

from ..models import Analysis, Detection, LogEntry, RuleCount, Setting
from ..timeutils import utc_now

ENTRY_FIELDS = ("line_number", "timestamp", "level", "ip", "method", "endpoint", "status", "message")
PROBLEM_LEVELS = ("WARNING", "ERROR", "CRITICAL")
_EPOCH = datetime(1970, 1, 1)


class AnalysisError(ValueError):
    """Raised when input cannot be analysed (e.g. no valid lines)."""


def create_analysis(
    db: Session, *, text: str, name: str, source: str,
    filename: str | None = None, scenario: str | None = None, source_timezone: str = "UTC",
) -> Analysis:
    """Parse, analyse and detect on ``text``, then persist everything.

    ``source_timezone`` is the zone of timestamps that have no offset in the file.
    """
    entries, invalid = parse_log_text(text, ZoneInfo(source_timezone))
    if not entries:
        raise AnalysisError(
            f"No valid log lines were found ({invalid} invalid line(s)). "
            "See the supported formats on this page."
        )

    summary = analyze_log_entries(entries)
    summary["source_timezone"] = source_timezone  # shown on pages and in reports
    thresholds = saved_thresholds(db)
    detections = detect_suspicious_activity(entries, thresholds)

    analysis = Analysis(
        name=name[:200], source=source, filename=filename, scenario=scenario,
        total_entries=len(entries), invalid_lines=invalid, detection_count=len(detections),
        error_rate=summary["error_rate"], summary=summary, thresholds=thresholds,
    )
    db.add(analysis)
    db.flush()  # assigns analysis.id
    _insert_entries(db, analysis.id, entries)
    _store_detections(db, analysis.id, detections)
    db.commit()
    return analysis


def _insert_entries(db: Session, analysis_id: int, entries: list[dict[str, Any]]) -> None:
    """Bulk insert (much faster than ORM objects), storing the recurring-issue key."""
    if entries:
        db.execute(insert(LogEntry), [
            {"analysis_id": analysis_id, **{field: entry[field] for field in ENTRY_FIELDS},
             "pattern": recurring_key(entry)[:300] if entry["level"] in PROBLEM_LEVELS else None}
            for entry in entries
        ])


def _naive(value: Any) -> datetime | None:
    """Aggregates may come back as strings or aware datetimes; return naive UTC."""
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def load_entries(
    db: Session, analysis_id: int, levels: tuple[str, ...] | None = None,
    start: datetime | None = None, end: datetime | None = None, ip: str | None = None,
) -> list[dict[str, Any]]:
    """Stored records as the dicts the core functions expect (naive UTC timestamps)."""
    query = select(LogEntry.timestamp, LogEntry.level, LogEntry.ip, LogEntry.method,
                   LogEntry.endpoint, LogEntry.status, LogEntry.message).where(LogEntry.analysis_id == analysis_id)
    if levels:
        query = query.where(LogEntry.level.in_(levels))
    if start is not None:
        query = query.where(LogEntry.timestamp >= start.replace(tzinfo=timezone.utc))
    if end is not None:
        query = query.where(LogEntry.timestamp <= end.replace(tzinfo=timezone.utc))
    if ip is not None:
        query = query.where(LogEntry.ip == ip)
    return [
        {"timestamp": t.replace(tzinfo=None), "level": lv, "ip": i, "method": m, "endpoint": ep,
         "status": st, "message": msg}
        for t, lv, i, m, ep, st, msg in db.execute(query)
    ]


def create_empty_analysis(db: Session, *, name: str, source: str, filename: str | None,
                          extra_summary: dict[str, Any] | None = None) -> Analysis:
    """An analysis that receives records incrementally (used by folder monitoring)."""
    summary = analyze_log_entries([])
    summary.update(extra_summary or {})
    analysis = Analysis(name=name[:200], source=source, filename=filename, summary=summary,
                        thresholds=saved_thresholds(db), total_entries=0, invalid_lines=0,
                        detection_count=0, error_rate=0.0, counters_ready=True)
    db.add(analysis)
    db.flush()
    return analysis


def append_entries(db: Session, analysis: Analysis, entries: list[dict[str, Any]], invalid: int) -> None:
    """Store newly parsed records; statistics and findings are updated separately."""
    _insert_entries(db, analysis.id, entries)
    analysis.total_entries += len(entries)
    analysis.invalid_lines += invalid


# --------------------------------------------------------------------------- statistics (SQL)

def summarize_analysis(db: Session, analysis_id: int, top_n: int = 10) -> dict[str, Any]:
    """Same result as ``project.analyze_log_entries`` but computed by SQLite.

    Runs a few GROUP BY queries instead of loading every record into memory.
    """
    of_analysis = LogEntry.analysis_id == analysis_id
    total = db.scalar(select(func.count()).where(of_analysis)) or 0

    level_counts = {level: 0 for level in LOG_LEVELS}
    for level, count in db.execute(select(LogEntry.level, func.count()).where(of_analysis).group_by(LogEntry.level)):
        if level in level_counts:
            level_counts[level] = count

    status_rows = db.execute(select(LogEntry.status, func.count()).where(of_analysis, LogEntry.status.is_not(None))
                             .group_by(LogEntry.status).order_by(LogEntry.status)).all()
    status_classes = {f"{n}xx": 0 for n in range(1, 6)}
    for status, count in status_rows:
        status_classes[f"{status // 100}xx"] += count

    def top(column, label):
        rows = db.execute(select(column, func.count().label("n")).where(of_analysis, column.is_not(None), column != "")
                          .group_by(column).order_by(func.count().desc(), column).limit(top_n))
        return [{label: value, "count": count} for value, count in rows]

    methods = db.execute(select(LogEntry.method, func.count()).where(of_analysis, LogEntry.method.is_not(None))
                         .group_by(LogEntry.method).order_by(func.count().desc(), LogEntry.method))
    unique_ips = db.scalar(select(func.count(distinct(LogEntry.ip))).where(of_analysis, LogEntry.ip.is_not(None))) or 0
    first, last = db.execute(select(func.min(LogEntry.timestamp), func.max(LogEntry.timestamp)).where(of_analysis)).one()
    start, end = _naive(first), _naive(last)
    errors = level_counts["ERROR"] + level_counts["CRITICAL"]

    return {
        "total_entries": total,
        "level_counts": level_counts,
        "status_counts": {str(status): count for status, count in status_rows},
        "status_classes": status_classes,
        "top_ips": top(LogEntry.ip, "ip"),
        "top_endpoints": top(LogEntry.endpoint, "endpoint"),
        "method_counts": {method: count for method, count in methods},
        "unique_ips": unique_ips,
        "start_time": start.isoformat() if start else None,
        "end_time": end.isoformat() if end else None,
        "duration_seconds": int((end - start).total_seconds()) if start and end else 0,
        "error_rate": round(errors / total * 100, 2) if total else 0.0,
        "timeline": _timeline(db, analysis_id, start, end),
    }


def _timeline(db: Session, analysis_id: int, start: datetime | None, end: datetime | None) -> list[dict[str, Any]]:
    """SQL version of ``project.build_timeline`` (same bucket sizes and output)."""
    if start is None or end is None:
        return []
    size = choose_bucket_size((end - start).total_seconds())
    first = int((start - _EPOCH).total_seconds()) // size
    last = int((end - _EPOCH).total_seconds()) // size
    # "//" is integer division in SQL (plain "/" would be decimal division in SQLAlchemy 2).
    bucket = cast(func.strftime("%s", LogEntry.timestamp), Integer) // size
    rows = db.execute(
        select(bucket.label("b"), func.count(),
               func.sum(case((LogEntry.level.in_(("ERROR", "CRITICAL")), 1), else_=0)))
        .where(LogEntry.analysis_id == analysis_id).group_by("b")
    )
    totals = [0] * (last - first + 1)
    errors = [0] * (last - first + 1)
    for index, count, error_count in rows:
        index = int(index) if index is not None else None  # SQLAlchemy may return Decimal
        if index is not None and 0 <= index - first < len(totals):
            totals[index - first] += count
            errors[index - first] += error_count or 0
    return [
        {"time": (_EPOCH + timedelta(seconds=(first + i) * size)).isoformat(), "total": totals[i], "errors": errors[i]}
        for i in range(len(totals))
    ]


def refresh_statistics(db: Session, analysis: Analysis) -> None:
    """Recompute an analysis' statistics from the database (no records loaded into memory)."""
    summary = summarize_analysis(db, analysis.id)
    for key in ("source_timezone", "monitor_path"):
        if key in analysis.summary:
            summary[key] = analysis.summary[key]
    summary["updated_at"] = utc_now().isoformat()
    analysis.summary = summary
    analysis.total_entries = summary["total_entries"]
    analysis.error_rate = summary["error_rate"]


# --------------------------------------------------------------------------- findings

_STREAM_BATCH = 5000
# SQL pre-filter for failed logins: a superset of project.is_failed_login, refined in Python.
_LOGIN_HINTS = ("%fail%", "%invalid%", "%unsuccessful%", "%bad%")


def _group_rows(db: Session, analysis_id: int, rule: str):
    """Yield (ip, naive timestamp) of the records a rule counts, sorted by ip then time.

    Rows are streamed from SQLite in batches, so memory does not grow with the log.
    """
    of_analysis = LogEntry.analysis_id == analysis_id
    if rule == "server_error_spike":
        query = (select(LogEntry.timestamp).where(of_analysis, LogEntry.status.between(500, 599))
                 .order_by(LogEntry.timestamp))
        for (moment,) in db.execute(query.execution_options(yield_per=_STREAM_BATCH)):
            yield None, _naive(moment)
        return
    with_ip = [of_analysis, LogEntry.ip.is_not(None), LogEntry.ip != ""]
    if rule == "brute_force":
        hints = or_(LogEntry.status.in_((401, 403)), *(LogEntry.message.like(h) for h in _LOGIN_HINTS))
        query = (select(LogEntry.ip, LogEntry.timestamp, LogEntry.endpoint, LogEntry.status, LogEntry.message)
                 .where(*with_ip, hints).order_by(LogEntry.ip, LogEntry.timestamp))
        for ip, moment, endpoint, status, message in db.execute(query.execution_options(yield_per=_STREAM_BATCH)):
            if is_failed_login({"endpoint": endpoint, "status": status, "message": message}):
                yield ip, _naive(moment)
        return
    if rule == "excessive_404":
        with_ip.append(LogEntry.status == 404)
    query = select(LogEntry.ip, LogEntry.timestamp).where(*with_ip).order_by(LogEntry.ip, LogEntry.timestamp)
    for ip, moment in db.execute(query.execution_options(yield_per=_STREAM_BATCH)):
        yield ip, _naive(moment)


def _stream_peaks(rows, window_seconds: int):
    """Busiest window per key from rows sorted by (key, time).

    Same result as ``project.peak_window`` per group, but keeps only the
    current window in memory. Yields ``(key, total, (count, first, last))``.
    """
    sentinel = object()
    current, window, best, total = sentinel, deque(), (0, None, None), 0
    for key, moment in rows:
        if key != current:
            if total:
                yield current, total, best
            current, window, best, total = key, deque(), (0, None, None), 0
        total += 1
        window.append(moment)
        while (moment - window[0]).total_seconds() > window_seconds:
            window.popleft()
        if len(window) > best[0]:
            best = (len(window), window[0], moment)
    if total:
        yield current, total, best


def scan_detections(
    db: Session, analysis_id: int, thresholds: dict[str, dict[str, int]],
) -> tuple[list[dict[str, Any]], dict[tuple[str, str | None], int]]:
    """Full detection over a stored analysis without loading it into memory.

    Returns the detections (same as ``project.detect_suspicious_activity``)
    and the number of matching records per (rule, ip) group.
    """
    config = {rule: {**cfg, **(thresholds or {}).get(rule, {})} for rule, cfg in DEFAULT_THRESHOLDS.items()}
    detections, totals = [], {}
    for rule, settings in config.items():
        for key, total, (count, first, last) in _stream_peaks(_group_rows(db, analysis_id, rule),
                                                              settings["window_seconds"]):
            totals[(rule, key)] = total
            if detection := make_detection(rule, key, count, first, last, total, settings):
                detections.append(detection)
    detections.sort(key=lambda d: (SEVERITY_ORDER[d["severity"]], -d["count"], d["rule"]))
    return detections, totals


def _replace_findings(db: Session, analysis: Analysis, thresholds: dict[str, dict[str, int]]) -> int:
    """Recompute all findings and running counters of an analysis (streaming)."""
    detections, totals = scan_detections(db, analysis.id, thresholds)
    db.execute(delete(Detection).where(Detection.analysis_id == analysis.id))
    _store_detections(db, analysis.id, detections)
    db.execute(delete(RuleCount).where(RuleCount.analysis_id == analysis.id))
    if totals:
        db.execute(insert(RuleCount), [
            {"analysis_id": analysis.id, "rule": rule, "key": key or "", "count": count}
            for (rule, key), count in totals.items()
        ])
    analysis.counters_ready = True
    analysis.detection_count = len(detections)
    return len(detections)


def _add_to_counters(db: Session, analysis_id: int, added: Counter) -> dict[tuple[str, str | None], int]:
    """Add new matches to the running counters and return the updated totals."""
    rows = [{"analysis_id": analysis_id, "rule": rule, "key": key or "", "count": n}
            for (rule, key), n in added.items()]
    statement = sqlite_insert(RuleCount)
    db.execute(statement.on_conflict_do_update(
        index_elements=["analysis_id", "rule", "key"],
        set_={"count": RuleCount.count + statement.excluded["count"]},
    ), rows)
    totals = {}
    groups = [(rule, key or "") for rule, key in added]
    for start in range(0, len(groups), 400):  # keep the SQL parameter list small
        part = groups[start:start + 400]
        for rule, key, count in db.execute(
            select(RuleCount.rule, RuleCount.key, RuleCount.count)
            .where(RuleCount.analysis_id == analysis_id, tuple_(RuleCount.rule, RuleCount.key).in_(part))
        ):
            totals[(rule, key or None)] = count
    return totals


def update_detections(db: Session, analysis: Analysis, new_entries: list[dict[str, Any]]) -> None:
    """Update findings after ``new_entries`` were stored, without rescanning the whole log.

    A busiest window that contains a new record lies within one rule window of
    the new records' time range, so only that slice is re-checked. For each
    rule and IP the larger peak (old or new) is kept. Totals come from running
    counters that are increased by the new records only.
    """
    thresholds = {rule: {**cfg, **(analysis.thresholds or {}).get(rule, {})} for rule, cfg in DEFAULT_THRESHOLDS.items()}
    if not analysis.counters_ready:
        # Analyses from older versions or uploads: build findings and counters once.
        _replace_findings(db, analysis, thresholds)
        return
    dated = [entry["timestamp"] for entry in new_entries if entry.get("timestamp")]
    added = Counter(group for entry in new_entries for group in classify_entry(entry))
    if not dated or not added:
        return
    totals = _add_to_counters(db, analysis.id, added)

    reach = timedelta(seconds=max(cfg["window_seconds"] for cfg in thresholds.values()))
    times: dict[tuple[str, str | None], list[datetime]] = {}
    for entry in sorted(load_entries(db, analysis.id, start=min(dated) - reach, end=max(dated) + reach),
                        key=lambda e: e["timestamp"]):
        for group in classify_entry(entry):
            if group in added:
                times.setdefault(group, []).append(entry["timestamp"])

    existing = {(d.rule, d.ip): d for d in db.scalars(select(Detection).where(Detection.analysis_id == analysis.id))}
    for rule, ip in added:
        settings = thresholds[rule]
        count, first, last = peak_window(times.get((rule, ip), []), settings["window_seconds"])
        old = existing.get((rule, ip))
        if old is not None and old.count >= count:
            count, first, last = old.count, _naive(old.first_seen), _naive(old.last_seen)
        detection = make_detection(rule, ip, count, first, last, totals.get((rule, ip), 0), settings)
        if detection is None:
            continue
        if old is None:
            db.add(Detection(analysis_id=analysis.id, **detection))
        else:
            for key, value in detection.items():
                setattr(old, key, value)
    db.flush()
    analysis.detection_count = db.scalar(select(func.count()).where(Detection.analysis_id == analysis.id)) or 0


def refresh_analysis(db: Session, analysis: Analysis) -> None:
    """Full recomputation of statistics and findings (streaming, constant memory)."""
    refresh_statistics(db, analysis)
    _replace_findings(db, analysis, analysis.thresholds or saved_thresholds(db))


# --------------------------------------------------------------------------- recurring issues (SQL)

def _backfill_patterns(db: Session, analysis_id: int) -> None:
    """Records stored before the pattern column existed get their key once."""
    missing = db.execute(
        select(LogEntry.id, LogEntry.level, LogEntry.method, LogEntry.endpoint, LogEntry.status, LogEntry.message)
        .where(LogEntry.analysis_id == analysis_id, LogEntry.level.in_(PROBLEM_LEVELS), LogEntry.pattern.is_(None))
    ).all()
    if missing:
        db.execute(update(LogEntry), [
            {"id": row.id, "pattern": recurring_key(row._asdict())[:300]} for row in missing
        ])
        db.commit()


def recurring_issues(db: Session, analysis_id: int, limit: int | None = 20, min_count: int = 2) -> list[dict[str, Any]]:
    """Repeated warnings and errors (same result as ``project.group_recurring_messages``), via GROUP BY."""
    _backfill_patterns(db, analysis_id)
    rank = case((LogEntry.level == "CRITICAL", 0), (LogEntry.level == "ERROR", 1), else_=2)
    query = (
        select(LogEntry.level, LogEntry.status, LogEntry.pattern, func.count().label("n"),
               func.min(LogEntry.timestamp), func.max(LogEntry.timestamp),
               func.count(distinct(LogEntry.ip)), func.min(LogEntry.message))
        .where(LogEntry.analysis_id == analysis_id, LogEntry.level.in_(PROBLEM_LEVELS))
        .group_by(LogEntry.level, LogEntry.status, LogEntry.pattern)
        .having(func.count() >= min_count)
        .order_by(rank, func.count().desc(), LogEntry.pattern)
    )
    if limit:
        query = query.limit(limit)
    return [
        {"level": level, "status": status, "pattern": pattern, "count": count,
         "first_seen": _naive(first), "last_seen": _naive(last), "ip_count": ips,
         "example": example or "", "search": recurring_search_text(pattern or "", example or "")}
        for level, status, pattern, count, first, last, ips, example in db.execute(query)
    ]


def rerun_detection(db: Session, analysis: Analysis, thresholds: dict[str, dict[str, int]]) -> int:
    """Re-run detection for a stored analysis with custom thresholds (streaming)."""
    merged = {rule: {**DEFAULT_THRESHOLDS[rule], **thresholds.get(rule, {})} for rule in DEFAULT_THRESHOLDS}
    analysis.thresholds = merged
    count = _replace_findings(db, analysis, merged)
    db.commit()
    return count


THRESHOLDS_KEY = "detection_thresholds"


def saved_thresholds(db: Session) -> dict[str, dict[str, int]]:
    """Rule limits for new analyses: the user's saved values, else the built-in defaults."""
    setting = db.get(Setting, THRESHOLDS_KEY)
    saved = setting.value if setting else {}
    return {rule: {**cfg, **saved.get(rule, {})} for rule, cfg in DEFAULT_THRESHOLDS.items()}


def save_thresholds(db: Session, thresholds: dict[str, dict[str, int]] | None) -> None:
    """Remember rule limits for future analyses (None restores the built-in defaults)."""
    setting = db.get(Setting, THRESHOLDS_KEY)
    if thresholds is None:
        if setting:
            db.delete(setting)
    elif setting:
        setting.value = thresholds
    else:
        db.add(Setting(key=THRESHOLDS_KEY, value=thresholds))
    db.commit()


def _store_detections(db: Session, analysis_id: int, detections: list[dict[str, Any]]) -> None:
    if detections:
        db.execute(insert(Detection), [{"analysis_id": analysis_id, **d} for d in detections])


def get_analysis(db: Session, analysis_id: int | None) -> Analysis | None:
    """Return the requested analysis, or the most recent one when no id is given."""
    if analysis_id is not None:
        return db.get(Analysis, analysis_id)
    return db.scalars(select(Analysis).order_by(Analysis.id.desc()).limit(1)).first()


def list_analyses(db: Session) -> list[Analysis]:
    return list(db.scalars(select(Analysis).order_by(Analysis.id.desc())))


def get_detections(db: Session, analysis_id: int) -> list[Detection]:
    severity_rank = {"high": 0, "medium": 1, "low": 2}
    rows = list(db.scalars(select(Detection).where(Detection.analysis_id == analysis_id)))
    return sorted(rows, key=lambda d: (severity_rank.get(d.severity, 3), -d.count))


def recent_entries(db: Session, analysis_id: int, limit: int = 8) -> list[LogEntry]:
    return list(db.scalars(
        select(LogEntry).where(LogEntry.analysis_id == analysis_id)
        .order_by(LogEntry.timestamp.desc(), LogEntry.id.desc()).limit(limit)
    ))


@dataclass
class ExplorerFilters:
    q: str = ""
    level: str = ""
    ip: str = ""
    status: str = ""  # exact code ("404") or class ("5xx")
    start: datetime | None = None  # aware datetimes, inclusive range
    end: datetime | None = None

    @property
    def active(self) -> bool:
        return bool(self.q or self.level or self.ip or self.status or self.start or self.end)


def query_entries(
    db: Session, analysis_id: int, filters: ExplorerFilters, page: int, per_page: int, newest_first: bool = True,
) -> tuple[list[LogEntry], int]:
    """Return one page of filtered entries plus the total number of matches."""
    conditions = [LogEntry.analysis_id == analysis_id]
    if filters.q:
        # autoescape makes % and _ in user input literal characters.
        conditions.append(or_(
            LogEntry.message.contains(filters.q, autoescape=True),
            LogEntry.endpoint.contains(filters.q, autoescape=True),
            LogEntry.ip.contains(filters.q, autoescape=True),
        ))
    if filters.level:
        conditions.append(LogEntry.level == filters.level)
    if filters.ip:
        conditions.append(LogEntry.ip == filters.ip)
    if filters.status:
        if filters.status.endswith("xx"):
            base = int(filters.status[0]) * 100
            conditions.append(LogEntry.status.between(base, base + 99))
        else:
            conditions.append(LogEntry.status == int(filters.status))

    if filters.start:
        conditions.append(LogEntry.timestamp >= filters.start)
    if filters.end:
        conditions.append(LogEntry.timestamp <= filters.end)

    total = db.scalar(select(func.count()).select_from(LogEntry).where(*conditions)) or 0
    rows = db.scalars(
        select(LogEntry).where(*conditions)
        .order_by(*((LogEntry.timestamp.desc(), LogEntry.id.desc()) if newest_first
                     else (LogEntry.timestamp, LogEntry.id)))
        .offset((page - 1) * per_page).limit(per_page)
    )
    return list(rows), total


def delete_analysis(db: Session, analysis: Analysis) -> None:
    # Explicit deletes keep this fast for large analyses (no ORM loading of children).
    # A monitored file keeps being watched; its next new lines start a fresh analysis.
    db.execute(delete(LogEntry).where(LogEntry.analysis_id == analysis.id))
    db.execute(delete(Detection).where(Detection.analysis_id == analysis.id))
    db.execute(delete(RuleCount).where(RuleCount.analysis_id == analysis.id))
    db.delete(analysis)
    db.commit()
