"""SQLite database setup (SQLAlchemy 2.0).

The database lives in the user's local application-data folder, *not* in the
project folder: projects are often inside synced folders (OneDrive, Dropbox),
and syncing an open SQLite database can lock or corrupt it.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import sys
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

log = logging.getLogger("logscope.database")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
LEGACY_DB_PATH = PROJECT_ROOT / "data" / "logscope.db"  # location used by earlier versions


def default_data_dir() -> Path:
    """Per-user, non-synced data folder (override with LOGSCOPE_DATA_DIR)."""
    if custom := os.environ.get("LOGSCOPE_DATA_DIR"):
        return Path(custom).expanduser()
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "LogScope"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "LogScope"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "logscope"


DEFAULT_DB_PATH = default_data_dir() / "logscope.db"
# Override with e.g. LOGSCOPE_DATABASE_URL=sqlite:///other.db (keeps paths out of code).
DATABASE_URL = os.environ.get("LOGSCOPE_DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH.as_posix()}")


class Base(DeclarativeBase):
    """Base class for ORM models."""


def make_engine(url: str):
    """Create an engine; SQLite needs check_same_thread=False for FastAPI's threadpool."""
    # timeout: wait for a lock instead of failing while the monitor thread writes.
    engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30})

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _record):  # pragma: no cover - trivial
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        # WAL lets pages read while the background monitor is writing.
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    return engine


engine = make_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def copy_legacy_database(source: Path, target: Path) -> bool:
    """Copy an existing database to the new location once (the original is kept).

    Uses SQLite's backup API so a database in WAL mode is copied consistently.
    """
    if target.exists() or not source.exists():
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(source) as old, sqlite3.connect(target) as new:
        old.backup(new)
    log.warning("Copied existing database from %s to %s", source, target)
    return True


def add_missing_columns(bind) -> list[str]:
    """Minimal migration: add columns that exist in the models but not in the database.

    ``create_all`` only creates missing tables. Columns added in later versions
    are appended with ALTER TABLE so existing databases keep working.
    """
    added = []
    inspector = inspect(bind)
    with bind.begin() as connection:
        for table in Base.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue
            existing = {column["name"] for column in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing:
                    continue
                ddl = f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {column.type.compile(bind.dialect)}'
                default = column.default.arg if column.default is not None and column.default.is_scalar else None
                if isinstance(default, (int, float)) and not isinstance(default, bool):
                    ddl += f" DEFAULT {default}"
                elif isinstance(default, str):
                    ddl += " DEFAULT '" + default.replace("'", "''") + "'"
                connection.execute(text(ddl))
                added.append(f"{table.name}.{column.name}")
    return added


def add_missing_indexes(bind) -> list[str]:
    """Create indexes defined in the models that an older database does not have yet."""
    added = []
    inspector = inspect(bind)
    for table in Base.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        existing = {index["name"] for index in inspector.get_indexes(table.name)}
        for index in table.indexes:
            if index.name not in existing:
                index.create(bind)
                added.append(index.name)
    return added


def init_db() -> None:
    """Create the data folder and tables, migrating older databases if needed."""
    from . import models  # noqa: F401  (registers the models on Base.metadata)

    if "LOGSCOPE_DATABASE_URL" not in os.environ:
        DEFAULT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        copy_legacy_database(LEGACY_DB_PATH, DEFAULT_DB_PATH)
    Base.metadata.create_all(bind=engine)
    add_missing_columns(engine)
    add_missing_indexes(engine)


def get_db() -> Iterator[Session]:
    """FastAPI dependency that yields a database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
