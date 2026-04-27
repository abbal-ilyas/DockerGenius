from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from dockergenius.utils.config import REPORT_DIR, ensure_storage


def write_fix_script(audit_result: Dict[str, Any], name: str = "containers_audit_fix") -> Path:
    ensure_storage()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = REPORT_DIR / f"{name}_{ts}.sh"

    lines: List[str] = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        'echo "DockerGenius remediation script (review before execute)"',
        "",
    ]

    seen = set()
    for f in audit_result.get("findings", []):
        cmd = str(f.get("fix_cmd") or "").strip()
        if not cmd or cmd in seen:
            continue
        seen.add(cmd)
        lines.append(f"# [{f.get('severity','?')}] {f.get('container','?')} - {f.get('check','?')}")
        lines.append(cmd)
        lines.append("")

    if len(lines) <= 5:
        lines.append('echo "No actionable commands generated."')

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o750)
    return path
