"""Text encoding helpers shared by uploads and folder monitoring.

Many Windows programs write logs as UTF-16 (two bytes per character). Those
files contain zero bytes, so they must be recognised before the "binary file"
check, and their line breaks are two bytes long.
"""

from __future__ import annotations

UTF8 = "utf-8"
UTF16_LE = "utf-16-le"
UTF16_BE = "utf-16-be"

_NEWLINE = {UTF16_LE: b"\n\x00", UTF16_BE: b"\x00\n"}


def detect_encoding(sample: bytes) -> str:
    """Guess the encoding from the start of a file: BOM first, then zero-byte pattern."""
    if sample.startswith(b"\xff\xfe"):
        return UTF16_LE
    if sample.startswith(b"\xfe\xff"):
        return UTF16_BE
    if sample.startswith(b"\xef\xbb\xbf"):
        return UTF8
    pairs = len(sample) // 2
    if pairs >= 2:
        # ASCII text in UTF-16 has a zero in every second byte.
        zero_odd = sum(1 for i in range(1, pairs * 2, 2) if sample[i] == 0)
        zero_even = sum(1 for i in range(0, pairs * 2, 2) if sample[i] == 0)
        if zero_odd > pairs * 0.6 and zero_even < pairs * 0.1:
            return UTF16_LE
        if zero_even > pairs * 0.6 and zero_odd < pairs * 0.1:
            return UTF16_BE
    return UTF8


def complete_lines_end(data: bytes, encoding: str) -> int:
    """Number of leading bytes of ``data`` that form complete lines (0 if none)."""
    newline = _NEWLINE.get(encoding)
    if newline is None:
        return data.rfind(b"\n") + 1
    position = data.rfind(newline)
    while position > 0 and position % 2:      # must start on a character boundary
        position = data.rfind(newline, 0, position)
    return position + 2 if position >= 0 and position % 2 == 0 else 0


def is_binary(data: bytes, encoding: str) -> bool:
    """Zero bytes are normal in UTF-16 but mean binary content in UTF-8."""
    return encoding == UTF8 and b"\x00" in data


def decode(data: bytes, encoding: str, at_file_start: bool) -> str:
    """Decode text, replacing invalid bytes and dropping a byte-order mark at the file start."""
    text = data.decode(encoding, errors="replace")
    return text.lstrip("﻿") if at_file_start else text
