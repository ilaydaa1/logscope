"""Start LogScope automatically when the user signs in to Windows.

Enabling writes one small script, ``LogScope.vbs``, to the user's Startup
folder. It starts ``pythonw project.py`` without a console window, so folder
monitoring resumes after every sign-in. Disabling deletes that script. No
system settings, registry keys or administrator rights are involved.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from ..database import PROJECT_ROOT

SCRIPT_NAME = "LogScope.vbs"


def startup_folder() -> Path | None:
    """The per-user Windows Startup folder, or None on other systems."""
    appdata = os.environ.get("APPDATA")
    if sys.platform != "win32" or not appdata:
        return None
    return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"


def supported() -> bool:
    folder = startup_folder()
    return folder is not None and folder.is_dir()


def script_path() -> Path | None:
    folder = startup_folder()
    return folder / SCRIPT_NAME if folder else None


def enabled() -> bool:
    path = script_path()
    return bool(path and path.exists())


def _vbs_string(text: str) -> str:
    return '"' + text.replace('"', '""') + '"'


def build_script(python: Path, project: Path, port: int) -> str:
    """VBScript that runs LogScope hidden (window style 0) in the project folder."""
    command = f'"{python}" "{project / "project.py"}" --port {port}'
    return (
        "' Starts LogScope (log monitoring) at sign-in. Delete this file or use\r\n"
        "' Log Analysis > Start at sign-in in LogScope to turn it off.\r\n"
        'Set shell = CreateObject("WScript.Shell")\r\n'
        f"shell.CurrentDirectory = {_vbs_string(str(project))}\r\n"
        f"shell.Run {_vbs_string(command)}, 0, False\r\n"
    )


def enable(port: int | None = None) -> Path:
    """Create the startup script. Raises OSError if it cannot be written."""
    path = script_path()
    if path is None:
        raise OSError("Starting at sign-in is only available on Windows.")
    executable = Path(sys.executable)
    windowless = executable.with_name("pythonw.exe")  # no console window
    python = windowless if windowless.exists() else executable
    port = port or int(os.environ.get("LOGSCOPE_PORT", "8000"))
    # Windows Script Host reads non-ASCII paths (e.g. "Masaüstü") correctly only from UTF-16 files.
    path.write_text(build_script(python, PROJECT_ROOT, port), encoding="utf-16")
    return path


def disable() -> None:
    path = script_path()
    if path and path.exists():
        path.unlink()
