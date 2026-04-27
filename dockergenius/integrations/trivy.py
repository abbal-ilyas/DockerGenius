from __future__ import annotations

import json
import subprocess
from typing import Any, Dict, List


def trivy_available() -> bool:
    try:
        subprocess.check_output(["trivy", "--version"], stderr=subprocess.STDOUT, text=True)
        return True
    except Exception:
        return False


def _parse_trivy_json(raw: str, image_ref: str) -> Dict[str, Any]:
    data = json.loads(raw)
    vulns: List[dict] = []

    for res in data.get("Results", []) or []:
        target = res.get("Target")
        vtype = res.get("Type")
        for v in res.get("Vulnerabilities", []) or []:
            vulns.append({
                "id": v.get("VulnerabilityID"),
                "pkg": v.get("PkgName"),
                "installed": v.get("InstalledVersion"),
                "fixed": v.get("FixedVersion"),
                "severity": (v.get("Severity") or "UNKNOWN").upper(),
                "title": v.get("Title") or "",
                "target": target,
                "type": vtype,
            })

    return {
        "tool": "trivy",
        "image": image_ref,
        "vulnerabilities": vulns,
    }


def scan_image_with_trivy(image_ref: str, timeout_sec: int = 180) -> Dict[str, Any]:
    cmd = ["trivy", "image", "--quiet", "--format", "json", image_ref]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)

    # trivy may return non-zero when vulns found; parse stdout anyway
    stdout = (proc.stdout or "").strip()
    if not stdout:
        err = (proc.stderr or "").strip()
        return {"tool": "trivy", "image": image_ref, "error": err or "No output", "vulnerabilities": []}

    try:
        return _parse_trivy_json(stdout, image_ref)
    except Exception as exc:
        return {
            "tool": "trivy",
            "image": image_ref,
            "error": f"parse_error: {exc}",
            "raw_head": stdout[:500],
            "vulnerabilities": [],
        }
