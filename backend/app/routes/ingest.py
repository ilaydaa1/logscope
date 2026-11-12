"""Upload Logs and Generate Sample Logs pages."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from ..database import get_db
from ..services import analysis_service as svc
from ..services.generator import MAX_ENTRIES, MIN_ENTRIES, SCENARIOS, generate_logs
from ..services.uploads import MAX_UPLOAD_BYTES, UploadError, read_upload
from ..templating import render
from ..timeutils import DISPLAY_TIMEZONE_NAME

router = APIRouter()

SIZE_PRESETS = [200, 1000, 5000, 10000]

# Zones a user can pick for log timestamps that carry no offset.
SOURCE_TIMEZONES = {
    "UTC": "UTC",
    DISPLAY_TIMEZONE_NAME: DISPLAY_TIMEZONE_NAME.replace("_", " ") + " (local time)",
}


@router.get("/upload")
def upload_page(request: Request, db: Session = Depends(get_db)):
    return _upload_view(request, db)


@router.post("/upload")
async def upload_file(
    request: Request, file: UploadFile | None = File(None), timezone: str = Form("UTC"),
    db: Session = Depends(get_db),
):
    try:
        if timezone not in SOURCE_TIMEZONES:
            raise UploadError("Please choose a time zone from the list.")
        filename, text = await read_upload(file)
        analysis = svc.create_analysis(db, text=text, name=filename, source="upload", filename=filename,
                                       source_timezone=timezone)
    except (UploadError, svc.AnalysisError) as error:
        db.rollback()
        return _upload_view(request, db, error=str(error), status_code=400)
    return RedirectResponse(f"/?analysis_id={analysis.id}&notice=uploaded", status_code=303)


def _upload_view(request: Request, db: Session, error: str | None = None, status_code: int = 200):
    return render(
        request, db, "upload.html", active="analysis", tab="upload", analysis=svc.get_analysis(db, None),
        error=error, max_mb=MAX_UPLOAD_BYTES // (1024 * 1024), status_code=status_code,
        source_timezones=SOURCE_TIMEZONES,
    )


@router.get("/generate")
def generate_page(request: Request, db: Session = Depends(get_db)):
    return _generate_view(request, db)


@router.post("/generate")
def generate(
    request: Request,
    scenario: str = Form("mixed"),
    count: str = Form("1000"),
    seed: str = Form(""),
    action: str = Form("analyze"),
    db: Session = Depends(get_db),
):
    try:
        entry_count = int(count)
        seed_value = int(seed) if seed.strip() else None
        lines = generate_logs(scenario, entry_count, seed=seed_value)
    except ValueError:
        message = (f"Choose a listed scenario, a size between {MIN_ENTRIES} and {MAX_ENTRIES}, "
                   "and a whole-number seed (or leave the seed empty).")
        return _generate_view(request, db, error=message, status_code=400)

    text = "\n".join(lines) + "\n"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"logscope-{scenario}-{stamp}.log"

    if action == "download":
        # Lets the user try the Upload page with realistic data.
        return Response(text, media_type="text/plain; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    label = SCENARIOS[scenario]["label"].replace(" (recommended)", "")
    name = f"Sample data: {label} ({entry_count:,} records" + (f", seed {seed_value})" if seed_value is not None else ")")
    analysis = svc.create_analysis(db, text=text, name=name, source="generated", scenario=scenario)
    return RedirectResponse(f"/?analysis_id={analysis.id}&notice=generated", status_code=303)


def _generate_view(request: Request, db: Session, error: str | None = None, status_code: int = 200):
    return render(
        request, db, "generate.html", active="analysis", tab="generate", analysis=svc.get_analysis(db, None),
        scenarios=SCENARIOS, presets=SIZE_PRESETS, min_entries=MIN_ENTRIES, max_entries=MAX_ENTRIES,
        error=error, status_code=status_code,
    )
