"""ORM models: an Analysis owns its parsed log entries and detections."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base
from .timeutils import UTCDateTime, utc_now


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    source: Mapped[str] = mapped_column(String(20))  # "upload" or "generated"
    filename: Mapped[str | None] = mapped_column(String(120), nullable=True)
    scenario: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)  # when the analysis ran
    total_entries: Mapped[int] = mapped_column(Integer, default=0)
    invalid_lines: Mapped[int] = mapped_column(Integer, default=0)
    detection_count: Mapped[int] = mapped_column(Integer, default=0)
    error_rate: Mapped[float] = mapped_column(default=0.0)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)  # output of analyze_log_entries
    thresholds: Mapped[dict] = mapped_column(JSON, default=dict)  # rules used for detection

    entries: Mapped[list[LogEntry]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", passive_deletes=True
    )
    detections: Mapped[list[Detection]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", passive_deletes=True
    )


class LogEntry(Base):
    __tablename__ = "log_entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    line_number: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, index=True)  # event time from the log
    level: Mapped[str] = mapped_column(String(10), index=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    message: Mapped[str] = mapped_column(Text, default="")
    # Recurring-issue key (project.recurring_key) for WARNING/ERROR/CRITICAL records,
    # stored once at insert time so recurring issues are a cheap GROUP BY.
    pattern: Mapped[str | None] = mapped_column(String(300), nullable=True)

    analysis: Mapped[Analysis] = relationship(back_populates="entries")


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    rule: Mapped[str] = mapped_column(String(40))
    title: Mapped[str] = mapped_column(String(120))
    severity: Mapped[str] = mapped_column(String(10))
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    count: Mapped[int] = mapped_column(Integer)
    total_matches: Mapped[int] = mapped_column(Integer)
    threshold: Mapped[int] = mapped_column(Integer)
    window_seconds: Mapped[int] = mapped_column(Integer)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime)
    explanation: Mapped[str] = mapped_column(Text)

    analysis: Mapped[Analysis] = relationship(back_populates="detections")


class Setting(Base):
    """Small key/value store for user preferences (e.g. saved detection limits)."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(60), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)


class WatchedFile(Base):
    """A log file in the monitored folder and how far it has been read."""

    __tablename__ = "watched_files"

    id: Mapped[int] = mapped_column(primary_key=True)
    path: Mapped[str] = mapped_column(String(1024), unique=True)
    analysis_id: Mapped[int | None] = mapped_column(
        ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True)
    offset: Mapped[int] = mapped_column(Integer, default=0)       # bytes already processed
    line_count: Mapped[int] = mapped_column(Integer, default=0)   # lines already processed
    file_id: Mapped[str] = mapped_column(String(64), default="")  # device:inode, detects replacement
    size: Mapped[int] = mapped_column(Integer, default=0)
    mtime: Mapped[float] = mapped_column(default=0.0)
    status: Mapped[str] = mapped_column(String(20), default="waiting")  # waiting|ok|missing|error
    message: Mapped[str] = mapped_column(String(300), default="")
    last_data_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # Content fingerprints: hash of the first head_len bytes and of the bytes just
    # before `offset`. If both still match, the file was only appended to (even if
    # an editor or sync tool replaced it); otherwise it is a new file.
    head_hash: Mapped[str] = mapped_column(String(64), default="")
    head_len: Mapped[int] = mapped_column(Integer, default=0)
    tail_hash: Mapped[str] = mapped_column(String(64), default="")
    encoding: Mapped[str] = mapped_column(String(20), default="")       # utf-8, utf-16-le, utf-16-be
    parser_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # e.g. W3C #Fields
