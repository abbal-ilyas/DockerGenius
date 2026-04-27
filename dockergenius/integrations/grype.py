from __future__ import annotations

import json
import subprocess
from typing import Any, Dict, List


def grype_available() -> bool:
    try:
        subprocess.check_output(["grype", "version"], stderr=subprocess.STDOUT, text=True)
        return True
    except Exception:
        return False


def _parse_grype_json(raw: str, image_ref: str) -> Dict[str, Any]:
    data = json.loads(raw)
    vulns: List[dict] = []

    for m in data.get("matches", []) or []:
        v = m.get("vulnerability") or {}
        a = m.get("artifact") or {}
        vulns.append({
            "id": v.get("id"),
            "pkg": a.get("name"),
            "installed": a.get("version"),
            "fixed": ", ".join(v.get("fix", {}).get("versions", []) or []),
            "severity": (v.get("severity") or "UNKNOWN").upper(),
            "title": v.get("description") or "",
            "target": a.get("locations", [{}])[0].get("path"),
            "type": a.get("type"),
        })

    return {"tool": "grype", "image": image_ref, "vulnerabilities": vulns}


def scan_image_with_grype(image_ref: str, timeout_sec: int = 180) -> Dict[str, Any]:
    cmd = ["grype", image_ref, "-o", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)

    stdout = (proc.stdout or "").strip()
    if not stdout:
        err = (proc.stderr or "").strip()
        return {"tool": "grype", "image": image_ref, "error": err or "No output", "vulnerabilities": []}

    try:
        return _parse_grype_json(stdout, image_ref)
    except Exception as exc:
        return {
            "tool": "grype",
            "image": image_ref,
            "error": f"parse_error: {exc}",
            "raw_head": stdout[:500],
            "vulnerabilities": [],
        }
