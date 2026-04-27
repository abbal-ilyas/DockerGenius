from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from dockergenius.utils.config import DG_HOME, ensure_storage


CACHE_DIR = DG_HOME / "cache"


def _ensure_cache_dir() -> None:
    ensure_storage()
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def cache_path(key: str) -> Path:
    _ensure_cache_dir()
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in key)
    return CACHE_DIR / f"{safe}.json"


def load_cache(key: str, max_age_minutes: int = 30) -> Optional[Dict[str, Any]]:
    p = cache_path(key)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        ts = datetime.fromisoformat(data.get("_cached_at"))
        if datetime.now(timezone.utc) - ts > timedelta(minutes=max_age_minutes):
            return None
        return data.get("payload")
    except Exception:
        return None


def save_cache(key: str, payload: Dict[str, Any]) -> None:
    p = cache_path(key)
    blob = {
        "_cached_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }
    p.write_text(json.dumps(blob, indent=2), encoding="utf-8")
