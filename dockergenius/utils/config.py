from __future__ import annotations

from pathlib import Path


DG_HOME = Path.home() / ".dockergenius"
SNAP_DIR = DG_HOME / "snapshots"
REPORT_DIR = DG_HOME / "reports"


def ensure_storage() -> None:
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
