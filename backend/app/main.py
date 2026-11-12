"""FastAPI application factory for LogScope."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from .database import PROJECT_ROOT, SessionLocal, init_db
from .routes import ingest, monitor as monitor_routes, pages, reports
from .security import check_request
from .services.monitor import worker
from .templating import render


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    # The folder monitor runs in the background; tests disable it and scan explicitly.
    run_monitor = os.environ.get("LOGSCOPE_MONITOR_THREAD", "1") != "0"
    if run_monitor:
        worker.start()
    yield
    if run_monitor:
        worker.stop()


app = FastAPI(title="LogScope", description="Rule-based log analysis platform", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(PROJECT_ROOT / "static")), name="static")
app.include_router(pages.router)
app.include_router(ingest.router)
app.include_router(reports.router)
app.include_router(monitor_routes.router)


@app.middleware("http")
async def request_guard(request: Request, call_next):
    """Reject foreign hosts and cross-site changes (see security.py)."""
    if reason := check_request(request):
        return PlainTextResponse(f"Request blocked: {reason}", status_code=403)
    return await call_next(request)


def _error_page(request: Request, code: int, detail: str):
    db = SessionLocal()
    try:
        return render(request, db, "error.html", active="", status_code=code, code=code, detail=detail)
    finally:
        db.close()


@app.exception_handler(StarletteHTTPException)
async def html_error_page(request: Request, exc: StarletteHTTPException):
    """Show a friendly error page that keeps the app navigation."""
    return _error_page(request, exc.status_code, exc.detail)


@app.exception_handler(RequestValidationError)
async def invalid_link_page(request: Request, exc: RequestValidationError):
    """Malformed links (e.g. /reports/abc/download) get the same page instead of raw JSON."""
    return _error_page(request, 400, "This link contains an invalid value.")


@app.exception_handler(Exception)
async def unexpected_error_page(request: Request, exc: Exception):
    """Unexpected server errors keep the normal layout instead of a bare text page."""
    return _error_page(request, 500, "An unexpected error occurred. Details are in the terminal output.")
