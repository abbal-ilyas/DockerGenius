from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


PROFILES = {"dev", "staging", "prod", "security"}


@dataclass(frozen=True)
class RuleWeights:
    root_user: int
    privileged: int
    docker_sock: int
    sensitive_port: int
    no_restart: int
    no_mem_limit: int
    no_healthcheck: int
    latest_tag: int
    writable_rootfs: int


WEIGHTS: Dict[str, RuleWeights] = {
    "dev": RuleWeights(10, 30, 35, 15, 10, 10, 5, 5, 8),
    "staging": RuleWeights(20, 40, 45, 25, 15, 15, 10, 10, 10),
    "prod": RuleWeights(35, 50, 60, 35, 20, 25, 20, 20, 12),
    "security": RuleWeights(45, 70, 80, 45, 15, 20, 15, 25, 15),
}


def clamp_0_100(value: int) -> int:
    return max(0, min(100, value))


def global_score(findings: List[dict]) -> int:
    """Normalize total risk points into 0..100 score (higher is worse)."""
    total = sum(int(f.get("score", 0)) for f in findings)
    # Soft normalization for Docker host scale
    return clamp_0_100(total // 5)


def risk_level(score_0_100: int) -> str:
    if score_0_100 >= 70:
        return "HIGH"
    if score_0_100 >= 35:
        return "MEDIUM"
    return "LOW"
