"""Dashboard, Logs, Findings and History pages."""

from __future__ import annotations

import math
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from project import DEFAULT_THRESHOLDS, LOG_LEVELS, RULE_TITLES

from ..database import get_db
from ..services import analysis_service as svc
from ..services import monitor
from ..templating import render
from ..timeutils import parse_time_input

router = APIRouter()

PER_PAGE = 50
STATUS_FILTER = re.compile(r"^(?:[1-5]\d{2}|[1-5]xx)$")


def resolve_analysis(db: Session, analysis_id: str | None):
    """Turn an optional ?analysis_id= query value into an Analysis (or None)."""
    if analysis_id in (None, ""):
        return svc.get_analysis(db, None)
    if not analysis_id.isdigit():
        raise HTTPException(status_code=404, detail="Analysis not found")
    analysis = svc.get_analysis(db, int(analysis_id))
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis


@router.get("/")
def dashboard(request: Request, analysis_id: str | None = None, db: Session = Depends(get_db)):
    analysis = resolve_analysis(db, analysis_id)
    context = {"monitor_status": monitor.monitor_status(db)}
    if analysis:
        context.update(
            detections=svc.get_detections(db, analysis.id)[:5],
            recurring=svc.recurring_issues(db, analysis.id, limit=5),
            recent=svc.recent_entries(db, analysis.id, limit=8),
        )
    return render(request, db, "dashboard.html", active="overview", analysis=analysis, **context)


@router.get("/explorer")
def explorer(
    request: Request, analysis_id: str | None = None, q: str = "", level: str = "",
    ip: str = "", status: str = "", start: str = "", end: str = "", order: str = "newest", page: str = "1",
    db: Session = Depends(get_db),
):
    analysis = resolve_analysis(db, analysis_id)
    # Invalid filter values are ignored instead of causing an error page.
    filters = svc.ExplorerFilters(
        q=q.strip()[:200],
        level=level if level in LOG_LEVELS else "",
        ip=ip.strip()[:45],
        status=status.strip().lower() if STATUS_FILTER.match(status.strip().lower()) else "",
        start=parse_time_input(start),
        end=parse_time_input(end),
    )
    page_number = int(page) if page.isdigit() and int(page) > 0 else 1
    newest_first = order != "oldest"
    rows, total, pages = [], 0, 1
    if analysis:
        rows, total = svc.query_entries(db, analysis.id, filters, page_number, PER_PAGE, newest_first)
        pages = max(1, math.ceil(total / PER_PAGE))
        if page_number > pages:
            page_number = pages
            rows, total = svc.query_entries(db, analysis.id, filters, page_number, PER_PAGE, newest_first)
    return render(
        request, db, "explorer.html", active="explorer", analysis=analysis,
        rows=rows, total=total, page=page_number, pages=pages, filters=filters, per_page=PER_PAGE,
        order="newest" if newest_first else "oldest",
    )


@router.get("/events")
def events(request: Request, analysis_id: str | None = None, db: Session = Depends(get_db)):
    analysis = resolve_analysis(db, analysis_id)
    return _events_view(request, db, analysis)


def _events_view(request: Request, db: Session, analysis, error: str | None = None, status_code: int = 200):
    detections = svc.get_detections(db, analysis.id) if analysis else []
    return render(
        request, db, "events.html", active="events", analysis=analysis, detections=detections,
        rule_titles=RULE_TITLES, defaults=DEFAULT_THRESHOLDS, saved=svc.saved_thresholds(db),
        recurring=svc.recurring_issues(db, analysis.id) if analysis else [],
        error=error, status_code=status_code,
    )


@router.post("/events/{analysis_id}/thresholds")
async def update_thresholds(analysis_id: int, request: Request, db: Session = Depends(get_db)):
    analysis = svc.get_analysis(db, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    form = await request.form()
    if form.get("action") == "reset":
        # Back to the built-in defaults, for this analysis and for future ones.
        svc.save_thresholds(db, None)
        svc.rerun_detection(db, analysis, DEFAULT_THRESHOLDS)
        return RedirectResponse(f"/events?analysis_id={analysis.id}&notice=reset", status_code=303)
    thresholds: dict[str, dict[str, int]] = {}
    try:
        for rule in DEFAULT_THRESHOLDS:
            thresholds[rule] = {}
            for key in ("threshold", "window_seconds"):
                raw = str(form.get(f"{rule}.{key}", "")).strip()
                value = int(raw)
                if not 1 <= value <= 86400:
                    raise ValueError
                thresholds[rule][key] = value
    except ValueError:
        return _events_view(request, db, analysis, status_code=400,
                            error="Every limit and time window must be a whole number between 1 and 86400.")
    svc.rerun_detection(db, analysis, thresholds)
    notice = "rerun"
    if form.get("remember"):
        svc.save_thresholds(db, thresholds)
        notice = "remembered"
    return RedirectResponse(f"/events?analysis_id={analysis.id}&notice={notice}", status_code=303)


@router.get("/history")
def history(request: Request, db: Session = Depends(get_db)):
    return render(request, db, "history.html", active="history", analysis=svc.get_analysis(db, None))


@router.post("/history/{analysis_id}/delete")
def delete(analysis_id: int, db: Session = Depends(get_db)):
    analysis = svc.get_analysis(db, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    svc.delete_analysis(db, analysis)
    return RedirectResponse("/history?notice=deleted", status_code=303)
