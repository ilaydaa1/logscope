"""Safe handling of uploaded log files.

Uploaded files are only ever read as text: they are never executed, never
written to disk under their original name, and the filename is sanitized
before it is displayed or stored.
"""

from __future__ import annotations

import re
from pathlib import PurePath

from fastapi import UploadFile

from .textcodec import decode, detect_encoding, is_binary

ALLOWED_EXTENSIONS = {".log", ".txt"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
CHUNK_SIZE = 64 * 1024


class UploadError(ValueError):
    """A user-facing validation problem with an uploaded file."""


def sanitize_filename(filename: str | None) -> str:
    """Strip directories and unusual characters from a client-supplied filename."""
    name = PurePath((filename or "").replace("\\", "/")).name
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(" .")
    return name[:100] or "upload.log"


async def read_upload(upload: UploadFile) -> tuple[str, str]:
    """Validate an upload and return ``(safe_filename, text)``.

    Raises:
        UploadError: wrong extension, too large, empty, or binary content.
    """
    if upload is None or not upload.filename:
        raise UploadError("Please choose a .log or .txt file to upload.")
    safe_name = sanitize_filename(upload.filename)
    if PurePath(safe_name).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise UploadError("Unsupported file type. Only .log and .txt files are accepted.")

    # Read in chunks so an oversized file is rejected without loading it fully.
    data = bytearray()
    while chunk := await upload.read(CHUNK_SIZE):
        data.extend(chunk)
        if len(data) > MAX_UPLOAD_BYTES:
            raise UploadError(f"File is too large. The limit is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")

    raw = bytes(data)
    encoding = detect_encoding(raw[:4096])      # UTF-8 or UTF-16 (common on Windows)
    if is_binary(raw, encoding):
        raise UploadError("The file looks binary. Please upload a plain-text log file.")
    # Undecodable bytes are replaced instead of failing; a byte-order mark is dropped.
    text = decode(raw, encoding, at_file_start=True)
    if not text.strip():
        raise UploadError("The uploaded file is empty.")
    return safe_name, text
