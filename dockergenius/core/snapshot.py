from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from dockergenius.utils.config import SNAP_DIR, ensure_storage


def utc_now_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def build_snapshot(*, name: str, profile: str, containers: list[dict], images: list[dict]) -> Dict[str, Any]:
    return {
        "meta": {
            "name": name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "profile": profile,
            "version": "0.1.0",
        },
        "containers": containers,
        "images": images,
    }


def save_snapshot(snapshot: Dict[str, Any]) -> Path:
    import json

    ensure_storage()
    name = snapshot["meta"]["name"]
    path = SNAP_DIR / f"{name}.json"
    path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    return path


def load_snapshot(name: str) -> Dict[str, Any]:
    import json

    ensure_storage()
    path = SNAP_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"Snapshot not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def latest_snapshot_name() -> str:
    ensure_storage()
    files = sorted(SNAP_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        raise FileNotFoundError("No snapshots available")
    return files[0].stem
