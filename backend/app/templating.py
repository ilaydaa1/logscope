"""Shared Jinja2 environment, navigation and page-context helper."""

from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from project import LOG_LEVELS

from .database import PROJECT_ROOT
from .models import Analysis
from .services.analysis_service import list_analyses
from .services.reports import detection_text
from .timeutils import DISPLAY_TIMEZONE_NAME, format_local, timezone_label, to_input_value

templates = Jinja2Templates(directory=str(PROJECT_ROOT / "templates"))

# Sidebar, in the order a user works: add data -> review -> share/revisit.
# (key, label, url, needs an analysis selected)
NAVIGATION = [
    ("", [
        ("overview", "Dashboard", "/", True),
        ("analysis", "Log Analysis", "/monitor", False),
        ("events", "Findings", "/events", True),
        ("explorer", "Logs", "/explorer", True),
        ("reports", "Reports", "/reports", True),
        ("history", "History", "/history", False),
    ]),
]

SOURCE_LABELS = {"upload": "Uploaded file", "generated": "Sample data", "monitor": "Monitored file"}

# Short status codes passed in redirects -> messages (never reflects raw user text).
NOTICES = {
    "uploaded": "File uploaded and analyzed.",
    "generated": "Sample data generated and analyzed.",
    "monitor_started": "Monitoring started.",
    "monitor_paused": "Monitoring paused. No files are read until you resume.",
    "monitor_resumed": "Monitoring resumed.",
    "monitor_stopped": "Monitoring stopped and folder access withdrawn. Existing analyses were kept.",
    "scanned": "Folder scanned.",
    "settings_saved": "Settings saved. Old records were cleaned up.",
    "compacted": "Database compacted.",
    "autostart_on": "LogScope will start automatically when you sign in to Windows.",
    "autostart_off": "LogScope will no longer start automatically.",
    "rerun": "Detection re-run with the new rule settings.",
    "remembered": "Detection was run again, and these limits will also be used for new analyses.",
    "reset": "Rules were reset to the built-in defaults for this and future analyses.",
    "deleted": "The analysis was deleted.",
}


def _number(value: Any) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "-"


def _percent(part: int, whole: int) -> float:
    return round(part / whole * 100, 1) if whole else 0.0


def _duration(seconds: int) -> str:
    """120 -> '2 minutes', 90 -> '90 seconds'."""
    if seconds % 3600 == 0:
        hours = seconds // 3600
        return f"{hours} hour{'s' if hours != 1 else ''}"
    if seconds % 60 == 0:
        minutes = seconds // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    return f"{seconds} seconds"


# Plain-language explanations for each detection rule.
RULE_GUIDE = {
    "brute_force": {
        "summary": "{count} failed logins from {ip} within {window}",
        "matches": "failed login attempts (HTTP 401/403 on a login page, or a 'failed login' message) from one IP address",
        "advice": "Someone may be guessing passwords. Check whether a login from this IP address eventually "
                  "succeeded, and consider blocking or rate-limiting it.",
    },
    "excessive_404": {
        "summary": "{count} 'page not found' (404) responses for {ip} within {window}",
        "matches": "'page not found' (HTTP 404) responses for one IP address",
        "advice": "Automated tools often probe for hidden admin pages, backups or config files this way. "
                  "Look at which paths were requested.",
    },
    "server_error_spike": {
        "summary": "{count} server errors (5xx) within {window}",
        "matches": "server errors (HTTP 500-599) across all visitors",
        "advice": "Many requests failed on the server at the same time. This usually points to an outage or a bug "
                  "rather than an attack. Check the application and its dependencies for that period.",
    },
    "high_volume": {
        "summary": "{count} requests from {ip} within {window}",
        "matches": "requests of any kind from one IP address",
        "advice": "One client sent far more requests than a normal visitor. It could be a scraper, a misconfigured "
                  "script, or an attempt to overload the site.",
    },
}


def _detection_summary(detection) -> str:
    template = RULE_GUIDE.get(detection.rule, {}).get("summary", "{count} matching events within {window}")
    return template.format(count=f"{detection.count:,}", ip=detection.ip or "all clients",
                           window=_duration(detection.window_seconds))


templates.env.filters["number"] = _number
templates.env.filters["duration"] = _duration
templates.env.filters["summary"] = _detection_summary
templates.env.filters["localtime"] = format_local  # UTC -> Europe/Istanbul, once, at display time
templates.env.filters["explain"] = detection_text
templates.env.filters["input_time"] = to_input_value
templates.env.filters["source_label"] = lambda source: SOURCE_LABELS.get(source, source)
templates.env.filters["filesize"] = lambda n: (f"{n / 1048576:.1f} MB" if n >= 1048576 else f"{n / 1024:.0f} KB" if n >= 1024 else f"{n} B")
def _asset_version() -> str:
    """Changes whenever CSS/JS change, so browsers never use a stale cached copy."""
    files = list((PROJECT_ROOT / "static").rglob("*.*"))
    return str(int(max((f.stat().st_mtime for f in files), default=0)))


templates.env.globals.update(
    ASSET_VERSION=_asset_version(),
    percent=_percent,
    LOG_LEVELS=LOG_LEVELS,
    NAVIGATION=NAVIGATION,
    RULE_GUIDE=RULE_GUIDE,
    TIMEZONE_NAME=DISPLAY_TIMEZONE_NAME,
    timezone_label=timezone_label,
)


def render(
    request: Request, db: Session, template: str, *, active: str,
    analysis: Analysis | None = None, status_code: int = 200, **context: Any,
):
    """Render a page with the sidebar and analysis context every page needs."""
    notice = NOTICES.get(request.query_params.get("notice", ""))
    from .services.monitor import get_config  # local import avoids a circular import
    context.setdefault("monitor_state", get_config(db).state)
    return templates.TemplateResponse(
        request, template,
        {"active": active, "analysis": analysis, "analyses": list_analyses(db), "notice": notice, **context},
        status_code=status_code,
    )
