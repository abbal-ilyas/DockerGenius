from __future__ import annotations

from typing import Any, Dict, List

from dockergenius.core.advisor import analyze_container, analyze_images
from dockergenius.core.scorer import global_score, risk_level


def run_analysis(*, profile: str, containers: List[Dict[str, Any]], images: List[Dict[str, Any]], top: int = 5) -> Dict[str, Any]:
    findings: List[dict] = []

    per_container_score: Dict[str, int] = {}
    for c in containers:
        f = analyze_container(c, profile)
        per_container_score[c.get("name", "unknown")] = sum(int(x.get("score", 0)) for x in f)
        findings.extend(f)

    findings.extend(analyze_images(images, profile))
    findings = sorted(findings, key=lambda x: int(x.get("score", 0)), reverse=True)
    score = global_score(findings)

    return {
        "profile": profile,
        "global_score": score,
        "global_risk": risk_level(score),
        "total_findings": len(findings),
        "containers_scored": per_container_score,
        "top_actions": findings[: max(1, top)],
        "all_findings": findings,
    }
