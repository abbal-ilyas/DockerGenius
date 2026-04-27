from __future__ import annotations

from typing import Any, Dict, List

from dockergenius.core.scorer import WEIGHTS


def _is_public(ip: str | None) -> bool:
    ip = (ip or "0.0.0.0").strip()
    return ip in {"0.0.0.0", "::", ""}


def _port_bindings(container: dict) -> List[dict]:
    return container.get("ports", []) or []


def _mounts(container: dict) -> List[dict]:
    return container.get("mounts", []) or []


def _is_root_user(user: str | None) -> bool:
    u = (user or "").strip()
    return u in {"", "root", "0", "root:root", "0:0"}


def analyze_container(container: Dict[str, Any], profile: str) -> List[dict]:
    w = WEIGHTS[profile]
    name = container.get("name", "unknown")
    findings: List[dict] = []

    if _is_root_user(container.get("user")):
        findings.append({
            "scope": f"container:{name}",
            "key": "root_user",
            "score": w.root_user,
            "insight": f"{name} runs as root user",
            "move": "Set a non-root USER in Dockerfile/compose.",
        })

    if bool(container.get("privileged", False)):
        findings.append({
            "scope": f"container:{name}",
            "key": "privileged",
            "score": w.privileged,
            "insight": f"{name} has privileged=true",
            "move": "Disable privileged mode unless absolutely required.",
        })

    for m in _mounts(container):
        src = str(m.get("source") or "")
        dst = str(m.get("target") or "")
        if dst == "/var/run/docker.sock" or src.endswith("/docker.sock"):
            findings.append({
                "scope": f"container:{name}",
                "key": "docker_sock",
                "score": w.docker_sock,
                "insight": f"{name} mounts docker.sock",
                "move": "Remove docker socket mount or isolate with strict controls.",
            })
            break

    sensitive = {"22", "2375", "2376", "3306", "5432", "6379", "27017", "50000"}
    for p in _port_bindings(container):
        hp = str(p.get("host_port") or "")
        hip = str(p.get("host_ip") or "0.0.0.0")
        if hp in sensitive and _is_public(hip):
            findings.append({
                "scope": f"container:{name}",
                "key": "sensitive_port",
                "score": w.sensitive_port,
                "insight": f"{name} exposes sensitive port {hp} publicly ({hip})",
                "move": "Bind to 127.0.0.1 or protect with firewall/reverse proxy.",
            })
            break

    rp = (container.get("restart_policy") or "").strip()
    if rp in {"", "no"}:
        findings.append({
            "scope": f"container:{name}",
            "key": "no_restart",
            "score": w.no_restart,
            "insight": f"{name} has no restart policy",
            "move": f"Run: docker update --restart unless-stopped {name}",
        })

    mem = int(container.get("memory_limit") or 0)
    if mem == 0:
        findings.append({
            "scope": f"container:{name}",
            "key": "no_mem_limit",
            "score": w.no_mem_limit,
            "insight": f"{name} has no memory limit",
            "move": f"Run: docker update --memory 512m --memory-swap 512m {name}",
        })

    if not bool(container.get("healthcheck", False)):
        findings.append({
            "scope": f"container:{name}",
            "key": "no_healthcheck",
            "score": w.no_healthcheck,
            "insight": f"{name} has no healthcheck",
            "move": "Add HEALTHCHECK to Dockerfile/compose.",
        })

    if not bool(container.get("readonly_rootfs", False)):
        findings.append({
            "scope": f"container:{name}",
            "key": "writable_rootfs",
            "score": w.writable_rootfs,
            "insight": f"{name} has writable root filesystem",
            "move": "Enable read-only root filesystem when possible.",
        })

    return findings


def analyze_images(images: List[Dict[str, Any]], profile: str) -> List[dict]:
    w = WEIGHTS[profile]
    findings: List[dict] = []
    for img in images:
        tags = img.get("tags") or []
        if any(str(t).endswith(":latest") for t in tags):
            findings.append({
                "scope": "images",
                "key": "latest_tag",
                "score": w.latest_tag,
                "insight": f"Image uses mutable :latest tag ({', '.join(tags[:2])})",
                "move": "Pin explicit tag/digest for reproducibility.",
            })
    return findings
