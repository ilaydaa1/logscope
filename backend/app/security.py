"""Request guard for a local web app without user accounts.

LogScope can be told to read a folder on this computer, so a request that
changes something must really come from LogScope's own pages:

* **Host check** - only requests addressed to localhost (or hosts listed in
  ``LOGSCOPE_ALLOWED_HOSTS``) are answered. This blocks DNS-rebinding pages
  that try to read the status API through another host name.
* **Same-origin check for changes** - POST/PUT/PATCH/DELETE requests are
  rejected when the browser reports that they come from another site
  (``Sec-Fetch-Site``), or when ``Origin``/``Referer`` name another origin.
  This stops other websites from silently starting folder monitoring or
  deleting analyses (cross-site request forgery).

Requests without any of these headers (curl, scripts, tests) are allowed:
browsers always send at least one of them on cross-site form posts.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

from starlette.requests import Request

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "testserver"}


def allowed_hosts() -> set[str]:
    extra = os.environ.get("LOGSCOPE_ALLOWED_HOSTS", "")
    return LOCAL_HOSTS | {h.strip().lower() for h in extra.split(",") if h.strip()}


def _hostname(host_header: str) -> str:
    """'127.0.0.1:8000' -> '127.0.0.1', '[::1]:8000' -> '::1'."""
    host = host_header.strip().lower()
    if host.startswith("["):
        return host[1:host.find("]")] if "]" in host else host
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}".lower() if parts.scheme and parts.netloc else ""


def check_request(request: Request) -> str | None:
    """Return a reason to reject the request, or None if it is acceptable."""
    host_header = request.headers.get("host", "")
    if _hostname(host_header) not in allowed_hosts():
        return "This host name is not allowed."
    if request.method in SAFE_METHODS:
        return None

    own_origin = f"{request.url.scheme}://{host_header}".lower()
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site and fetch_site not in ("same-origin", "none"):
        return "Cross-site requests are not allowed."
    origin = request.headers.get("origin")
    if origin is not None:
        if origin.lower() != own_origin:
            return "Requests from other websites are not allowed."
    else:
        referer = request.headers.get("referer")
        if referer and _origin_of(referer) != own_origin:
            return "Requests from other websites are not allowed."
    return None
