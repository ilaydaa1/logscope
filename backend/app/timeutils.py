"""Timezone handling.

Convention used everywhere in LogScope:

* **Storage and computation: UTC.** SQLite has no timezone-aware datetime
  type, so values are written as naive UTC (see ``UTCDateTime``) and come
  back from the database as *aware* UTC datetimes.
* **Display: the computer's local time zone** (detected with tzlocal), or
  ``LOGSCOPE_TIMEZONE`` when set (e.g. ``Europe/Istanbul``).
  Conversion happens exactly once, at the very end, in the templates and
  report builders via ``format_local``. Nothing adds hours by hand.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from sqlalchemy.types import DateTime, TypeDecorator

def _local_timezone_name() -> str:
    """IANA name of this computer's time zone, e.g. 'Europe/Istanbul' (UTC if unknown)."""
    try:
        from tzlocal import get_localzone_name

        name = get_localzone_name()
        ZoneInfo(name)  # must be known to zoneinfo/tzdata
        return name
    except Exception:  # missing package, unusual system settings
        return "UTC"


DISPLAY_TIMEZONE_NAME = os.environ.get("LOGSCOPE_TIMEZONE") or _local_timezone_name()
DISPLAY_TIMEZONE = ZoneInfo(DISPLAY_TIMEZONE_NAME)

DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def utc_now() -> datetime:
    """The current moment as an aware UTC datetime."""
    return datetime.now(timezone.utc)


def ensure_utc(moment: datetime) -> datetime:
    """Return an aware UTC datetime.

    Naive values are, by LogScope's convention, already UTC, so the UTC tzinfo
    is attached without shifting the clock. Aware values are converted.
    """
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def to_local(moment: datetime | str) -> datetime:
    """Convert a UTC datetime (or ISO string) to the display timezone."""
    if isinstance(moment, str):
        moment = datetime.fromisoformat(moment)
    return ensure_utc(moment).astimezone(DISPLAY_TIMEZONE)


def format_local(moment: datetime | str | None, fmt: str = DATETIME_FORMAT) -> str:
    """Format a stored UTC value for people to read, in the display timezone."""
    if moment is None or moment == "":
        return "-"
    return to_local(moment).strftime(fmt)


def parse_time_input(text: str | None) -> datetime | None:
    """Read a date/time from a URL or form field as an aware UTC datetime.

    Values with an offset (e.g. ``...Z``) are used as-is; values without one
    (what a ``datetime-local`` input sends) are in the display timezone.
    Returns None for empty or invalid input.
    """
    if not text or not text.strip():
        return None
    try:
        moment = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=DISPLAY_TIMEZONE)
    return moment.astimezone(timezone.utc)


def to_input_value(moment: datetime | None) -> str:
    """Format for an <input type="datetime-local"> in the display timezone."""
    return format_local(moment, "%Y-%m-%dT%H:%M:%S") if moment else ""


def timezone_label(moment: datetime | None = None) -> str:
    """Human-readable zone label, e.g. 'Europe/Istanbul (UTC+03:00)'."""
    offset = (moment or utc_now()).astimezone(DISPLAY_TIMEZONE).strftime("%z")
    return f"{DISPLAY_TIMEZONE_NAME} (UTC{offset[:3]}:{offset[3:]})"


class UTCDateTime(TypeDecorator):
    """Stores datetimes as naive UTC in SQLite and returns aware UTC datetimes.

    Existing rows (written as naive UTC before this type existed) are read
    correctly because the stored format is unchanged.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return ensure_utc(value).replace(tzinfo=None)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=timezone.utc)
