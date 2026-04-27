from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from dockergenius.utils.config import REPORT_DIR, ensure_storage


def write_snapshot_diff_markdown(*, from_name: str, to_name: str, diff_result: Dict[str, Any]) -> Path:
    ensure_storage()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = REPORT_DIR / f"snapshot_diff_{from_name}_to_{to_name}_{ts}.md"

    s = diff_result["summary"]
    lines = [
        "# DockerGenius Snapshot Diff",
        "",
        f"- From: `{from_name}`",
        f"- To: `{to_name}`",
        f"- Drift Score: **{s['drift_score']}** ({s['drift_level']})",
        f"- Changes: **{s['changes_count']}**",
        "",
        "## Summary",
        "",
        f"- Containers added: {s['containers_added']}",
        f"- Containers removed: {s['containers_removed']}",
        f"- Images added: {s['images_added']}",
        f"- Images removed: {s['images_removed']}",
        "",
        "## Changes (sorted by risk)",
        "",
    ]

    for c in diff_result.get("changes", []):
        ctype = c.get("type", "change")
        score = c.get("score", 0)
        target = c.get("container") or c.get("image") or "-"
        lines.append(f"- [{score}] `{ctype}` -> `{target}`")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
