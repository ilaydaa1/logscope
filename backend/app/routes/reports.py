"""Reports page and report downloads."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..database import get_db
from ..services import analysis_service as svc
from ..services.reports import build_csv_report, build_text_report
from ..templating import render
from ..timeutils import to_local, utc_now
from .pages import resolve_analysis

router = APIRouter()


@router.get("/reports")
def reports_page(request: Request, analysis_id: str | None = None, db: Session = Depends(get_db)):
    analysis = resolve_analysis(db, analysis_id)
    generated_at = utc_now()
    detections = svc.get_detections(db, analysis.id) if analysis else []
    preview = build_text_report(analysis, detections, generated_at) if analysis else ""
    return render(request, db, "reports.html", active="reports", analysis=analysis,
                  preview=preview, generated_at=generated_at, detection_count=len(detections))


@router.get("/reports/{analysis_id}/download")
def download_report(analysis_id: int, format: str = "txt", db: Session = Depends(get_db)):
    analysis = svc.get_analysis(db, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    if format not in ("txt", "csv"):
        raise HTTPException(status_code=400, detail="format must be txt or csv")
    detections = svc.get_detections(db, analysis.id)
    generated_at = utc_now()  # the real moment this report is produced
    if format == "csv":
        body, media = build_csv_report(analysis, detections, generated_at), "text/csv; charset=utf-8"
    else:
        body, media = build_text_report(analysis, detections, generated_at), "text/plain; charset=utf-8"
    stamp = to_local(generated_at).strftime("%Y%m%d-%H%M")
    return Response(body, media_type=media, headers={
        "Content-Disposition": f'attachment; filename="logscope-report-{analysis.id}-{stamp}.{format}"'
    })
