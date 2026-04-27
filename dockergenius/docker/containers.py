from __future__ import annotations

from typing import Any, Dict, List


def parse_ports(attrs: dict) -> List[dict]:
    pb = attrs.get("HostConfig", {}).get("PortBindings") or {}
    out = []
    for cport, binds in pb.items():
        if not binds:
            out.append({"container_port": cport, "host_ip": None, "host_port": None})
        else:
            for b in binds:
                out.append({
                    "container_port": cport,
                    "host_ip": b.get("HostIp", "0.0.0.0"),
                    "host_port": b.get("HostPort"),
                })
    return out


def parse_mounts(attrs: dict) -> List[dict]:
    mounts = attrs.get("Mounts", [])
    return [{
        "type": m.get("Type"),
        "source": m.get("Source") or m.get("Name"),
        "target": m.get("Destination"),
        "rw": m.get("RW", True),
        "name": m.get("Name"),
    } for m in mounts]


def list_containers_full(client) -> List[Dict[str, Any]]:
    data = []
    for c in client.containers.list(all=True):
        attrs = c.attrs
        cfg = attrs.get("Config", {})
        host = attrs.get("HostConfig", {})
        state = attrs.get("State", {})
        nets = (attrs.get("NetworkSettings") or {}).get("Networks") or {}
        data.append({
            "id": c.id,
            "short_id": c.short_id,
            "name": c.name,
            "status": c.status,
            "image": cfg.get("Image"),
            "restart_policy": (host.get("RestartPolicy") or {}).get("Name", ""),
            "memory_limit": host.get("Memory", 0),
            "nano_cpus": host.get("NanoCpus", 0),
            "privileged": host.get("Privileged", False),
            "user": cfg.get("User") or "",
            "healthcheck": bool(cfg.get("Healthcheck")),
            "ports": parse_ports(attrs),
            "mounts": parse_mounts(attrs),
            "running": state.get("Running", False),
            "readonly_rootfs": bool(host.get("ReadonlyRootfs", False)),
            "networks": list(nets.keys()),
        })
    return data
