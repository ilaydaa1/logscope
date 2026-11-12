"""Log Analysis -> Folder monitoring: controls and live status."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..services import analysis_service as svc
from ..services import monitor
from ..templating import render
from .ingest import SOURCE_TIMEZONES

router = APIRouter()


def _monitor_view(request: Request, db: Session, error: str | None = None, status_code: int = 200,
                  form: dict | None = None):
    status = monitor.monitor_status(db)
    return render(
        request, db, "monitor.html", active="analysis", tab="monitor", analysis=svc.get_analysis(db, None),
        status=status, source_timezones=SOURCE_TIMEZONES, error=error, status_code=status_code,
        form=form or {"directory": status["directory"], "timezone": status["timezone"],
                      "include_existing": status["include_existing"]},
    )


@router.get("/monitor")
def monitor_page(request: Request, db: Session = Depends(get_db)):
    return _monitor_view(request, db)


@router.post("/monitor/start")
def start(
    request: Request,
    directory: str = Form(""),
    timezone: str = Form("UTC"),
    include_existing: str = Form(""),
    consent: str = Form(""),
    db: Session = Depends(get_db),
):
    form = {"directory": directory, "timezone": timezone, "include_existing": bool(include_existing)}
    if not consent:
        return _monitor_view(request, db, status_code=400, form=form,
                             error="Confirm that LogScope may read the log files in this folder.")
    if timezone not in SOURCE_TIMEZONES:
        return _monitor_view(request, db, status_code=400, form=form, error="Choose a time zone from the list.")
    try:
        monitor.start_monitoring(db, directory, timezone, bool(include_existing))
    except monitor.MonitorError as error:
        db.rollback()
        return _monitor_view(request, db, error=str(error), status_code=400, form=form)
    monitor.worker.wake()
    return RedirectResponse("/monitor?notice=monitor_started", status_code=303)


@router.post("/monitor/pause")
def pause(db: Session = Depends(get_db)):
    monitor.pause_monitoring(db)
    return RedirectResponse("/monitor?notice=monitor_paused", status_code=303)


@router.post("/monitor/resume")
def resume(db: Session = Depends(get_db)):
    monitor.resume_monitoring(db)
    monitor.worker.wake()
    return RedirectResponse("/monitor?notice=monitor_resumed", status_code=303)


@router.post("/monitor/stop")
def stop(db: Session = Depends(get_db)):
    monitor.stop_monitoring(db)
    return RedirectResponse("/monitor?notice=monitor_stopped", status_code=303)


@router.post("/monitor/scan")
def scan_now(db: Session = Depends(get_db)):
    """Run a scan immediately in this request (shares the lock with the background thread)."""
    monitor.run_scan(db)
    return RedirectResponse("/monitor?notice=scanned", status_code=303)


@router.get("/api/monitor/status")
def status(db: Session = Depends(get_db)):
    return JSONResponse(monitor.monitor_status(db))
