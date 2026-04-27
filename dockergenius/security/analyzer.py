from __future__ import annotations

from typing import Any, Dict, List


SENSITIVE_PORTS = {"22", "2375", "2376", "3306", "5432", "6379", "27017", "50000"}


def _is_public(ip: str | None) -> bool:
    ip = (ip or "0.0.0.0").strip()
    return ip in {"0.0.0.0", "::", ""}


def audit_containers(containers: List[Dict[str, Any]]) -> Dict[str, Any]:
    findings: List[dict] = []

    for c in containers:
        name = c.get("name", "unknown")
        user = (c.get("user") or "").strip()
        privileged = bool(c.get("privileged", False))
        restart_policy = (c.get("restart_policy") or "").strip()
        health = bool(c.get("healthcheck", False))
        readonly = bool(c.get("readonly_rootfs", False))
        mem_limit = int(c.get("memory_limit") or 0)

        # root user
        if user in {"", "root", "0", "root:root", "0:0"}:
            findings.append({
                "container": name,
                "severity": "high",
                "check": "root_user",
                "insight": f"{name} runs as root",
                "move": "Set non-root USER in Dockerfile/compose.",
                "fix_cmd": f"# set user in compose/Dockerfile for {name}",
            })

        # privileged
        if privileged:
            findings.append({
                "container": name,
                "severity": "critical",
                "check": "privileged",
                "insight": f"{name} runs with privileged=true",
                "move": "Disable privileged mode.",
                "fix_cmd": f"# remove privileged: true for {name}",
            })

        # docker.sock mount
        for m in c.get("mounts", []) or []:
            src = str(m.get("source") or "")
            dst = str(m.get("target") or "")
            if dst == "/var/run/docker.sock" or src.endswith("/docker.sock"):
                findings.append({
                    "container": name,
                    "severity": "critical",
                    "check": "docker_sock",
                    "insight": f"{name} mounts docker.sock",
                    "move": "Remove Docker socket mount.",
                    "fix_cmd": f"# remove /var/run/docker.sock mount for {name}",
                })
                break

        # sensitive public ports
        for p in c.get("ports", []) or []:
            hp = str(p.get("host_port") or "")
            hip = str(p.get("host_ip") or "0.0.0.0")
            if hp in SENSITIVE_PORTS and _is_public(hip):
                findings.append({
                    "container": name,
                    "severity": "high",
                    "check": "sensitive_public_port",
                    "insight": f"{name} exposes sensitive port {hp} on {hip}",
                    "move": "Bind to 127.0.0.1 or firewall/reverse proxy.",
                    "fix_cmd": f"# change bind {name}:{hp} to 127.0.0.1:{hp}",
                })

        # no restart policy
        if restart_policy in {"", "no"}:
            findings.append({
                "container": name,
                "severity": "medium",
                "check": "restart_policy",
                "insight": f"{name} has no restart policy",
                "move": "Set unless-stopped or always.",
                "fix_cmd": f"docker update --restart unless-stopped {name}",
            })

        # no memory limit
        if mem_limit == 0:
            findings.append({
                "container": name,
                "severity": "medium",
                "check": "memory_limit",
                "insight": f"{name} has no memory limit",
                "move": "Set memory limit.",
                "fix_cmd": f"docker update --memory 512m --memory-swap 512m {name}",
            })

        # no healthcheck
        if not health:
            findings.append({
                "container": name,
                "severity": "medium",
                "check": "healthcheck",
                "insight": f"{name} has no healthcheck",
                "move": "Add HEALTHCHECK in Dockerfile/compose.",
                "fix_cmd": f"# add HEALTHCHECK for {name}",
            })

        # writable rootfs
        if not readonly:
            findings.append({
                "container": name,
                "severity": "medium",
                "check": "writable_rootfs",
                "insight": f"{name} uses writable root filesystem",
                "move": "Enable read-only root filesystem when possible.",
                "fix_cmd": f"# set read_only: true for {name}",
            })

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    findings.sort(key=lambda x: sev_rank.get(x["severity"], 0), reverse=True)

    return {
        "summary": {
            "containers": len(containers),
            "findings": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "low": sum(1 for f in findings if f["severity"] == "low"),
        },
        "findings": findings,
    }
