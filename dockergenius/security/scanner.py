from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List

from dockergenius.integrations.trivy import trivy_available, scan_image_with_trivy
from dockergenius.integrations.grype import grype_available, scan_image_with_grype
from dockergenius.utils.cache import load_cache, save_cache


SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def summarize_vulns(vulns: List[dict]) -> Dict[str, int]:
    c = Counter((v.get("severity") or "UNKNOWN").upper() for v in vulns)
    return {k: int(c.get(k, 0)) for k in SEV_ORDER}


def choose_image_ref(image: Dict[str, Any]) -> str:
    tags = image.get("tags") or []
    if tags:
        # prefer non-none tag
        for t in tags:
            if t != "<none>:<none>":
                return t
        return tags[0]
    return image.get("short_id") or image.get("id") or "unknown-image"


def scan_images(images: List[Dict[str, Any]], use_cache: bool = True, cache_minutes: int = 30) -> Dict[str, Any]:
    tool = None
    if trivy_available():
        tool = "trivy"
    elif grype_available():
        tool = "grype"
    else:
        return {
            "tool": "none",
            "error": "No scanner found. Install trivy or grype.",
            "images": [],
            "summary": {k: 0 for k in SEV_ORDER},
        }

    per_image: List[dict] = []
    all_vulns: List[dict] = []

    for img in images:
        ref = choose_image_ref(img)
        key = f"scan_{tool}_{ref}"

        payload = load_cache(key, max_age_minutes=cache_minutes) if use_cache else None
        if payload is None:
            payload = scan_image_with_trivy(ref) if tool == "trivy" else scan_image_with_grype(ref)
            if use_cache:
                save_cache(key, payload)

        vulns = payload.get("vulnerabilities", []) or []
        sev = summarize_vulns(vulns)
        risk_points = sev["CRITICAL"] * 20 + sev["HIGH"] * 8 + sev["MEDIUM"] * 3 + sev["LOW"] * 1

        per_image.append({
            "image": ref,
            "tool": payload.get("tool", tool),
            "error": payload.get("error"),
            "counts": sev,
            "vuln_count": len(vulns),
            "risk_points": risk_points,
            "top_vulns": vulns[:20],
        })
        all_vulns.extend(vulns)

    total = summarize_vulns(all_vulns)
    per_image.sort(key=lambda x: int(x["risk_points"]), reverse=True)

    return {
        "tool": tool,
        "summary": {
            **total,
            "images_scanned": len(per_image),
            "total_vulns": sum(total.values()),
        },
        "images": per_image,
    }
