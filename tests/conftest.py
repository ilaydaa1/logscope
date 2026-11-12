"""Point the web app at a throwaway SQLite file before it is imported."""

import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="logscope-test-"))
os.environ["LOGSCOPE_MONITOR_THREAD"] = "0"  # tests call scans directly
os.environ["LOGSCOPE_TIMEZONE"] = "Europe/Istanbul"  # expected display zone in assertions
os.environ["LOGSCOPE_DATABASE_URL"] = f"sqlite:///{(_TMP / 'test.db').as_posix()}"
