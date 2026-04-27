from __future__ import annotations

from typing import Any, Dict, List


DRIFT_WEIGHTS = {
    "container_added": 8,
    "container_removed": 8,
    "image_added": 3,
    "image_removed": 3,
    "restart_policy_changed": 4,
    "memory_limit_changed": 6,
    "privileged_changed": 10,
    "user_changed": 5,
    "ports_changed": 7,
    "mounts_changed": 6,
    "image_size_growth_mb": 1,  # per 100MB chunk
}


def _by_name_containers(snapshot: Dict[str, Any]) -> Dict[str, dict]:
    return {c["name"]: c for c in snapshot.get("containers", [])}


def _by_id_images(snapshot: Dict[str, Any]) -> Dict[str, dict]:
    out = {}
    for i in snapshot.get("images", []):
        out[i.get("id") or i.get("short_id") or "|".join(i.get("tags", []))] = i
    return out


def _norm_ports(c: dict) -> List[tuple]:
    ports = c.get("ports", []) or []
    return sorted((str(p.get("container_port")), str(p.get("host_ip")), str(p.get("host_port"))) for p in ports)


def _norm_mounts(c: dict) -> List[tuple]:
    mounts = c.get("mounts", []) or []
    return sorted((str(m.get("source")), str(m.get("target")), bool(m.get("rw", True))) for m in mounts)


def compute_diff(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    old_c = _by_name_containers(old)
    new_c = _by_name_containers(new)

    old_i = _by_id_images(old)
    new_i = _by_id_images(new)

    added_containers = sorted(set(new_c) - set(old_c))
    removed_containers = sorted(set(old_c) - set(new_c))

    added_images = sorted(set(new_i) - set(old_i))
    removed_images = sorted(set(old_i) - set(new_i))

    changes: List[dict] = []
    drift_points = 0

    for name in added_containers:
        drift_points += DRIFT_WEIGHTS["container_added"]
        changes.append({"type": "container_added", "container": name, "score": DRIFT_WEIGHTS["container_added"]})

    for name in removed_containers:
        drift_points += DRIFT_WEIGHTS["container_removed"]
        changes.append({"type": "container_removed", "container": name, "score": DRIFT_WEIGHTS["container_removed"]})

    common = sorted(set(old_c) & set(new_c))
    for name in common:
        o = old_c[name]
        n = new_c[name]

        if (o.get("restart_policy") or "") != (n.get("restart_policy") or ""):
            s = DRIFT_WEIGHTS["restart_policy_changed"]
            drift_points += s
            changes.append({"type": "restart_policy_changed", "container": name, "from": o.get("restart_policy"), "to": n.get("restart_policy"), "score": s})

        if int(o.get("memory_limit") or 0) != int(n.get("memory_limit") or 0):
            s = DRIFT_WEIGHTS["memory_limit_changed"]
            drift_points += s
            changes.append({"type": "memory_limit_changed", "container": name, "from": o.get("memory_limit"), "to": n.get("memory_limit"), "score": s})

        if bool(o.get("privileged", False)) != bool(n.get("privileged", False)):
            s = DRIFT_WEIGHTS["privileged_changed"]
            drift_points += s
            changes.append({"type": "privileged_changed", "container": name, "from": o.get("privileged"), "to": n.get("privileged"), "score": s})

        if (o.get("user") or "") != (n.get("user") or ""):
            s = DRIFT_WEIGHTS["user_changed"]
            drift_points += s
            changes.append({"type": "user_changed", "container": name, "from": o.get("user"), "to": n.get("user"), "score": s})

        if _norm_ports(o) != _norm_ports(n):
            s = DRIFT_WEIGHTS["ports_changed"]
            drift_points += s
            changes.append({"type": "ports_changed", "container": name, "score": s})

        if _norm_mounts(o) != _norm_mounts(n):
            s = DRIFT_WEIGHTS["mounts_changed"]
            drift_points += s
            changes.append({"type": "mounts_changed", "container": name, "score": s})

    for iid in added_images:
        drift_points += DRIFT_WEIGHTS["image_added"]
        changes.append({"type": "image_added", "image": iid, "score": DRIFT_WEIGHTS["image_added"]})

    for iid in removed_images:
        drift_points += DRIFT_WEIGHTS["image_removed"]
        changes.append({"type": "image_removed", "image": iid, "score": DRIFT_WEIGHTS["image_removed"]})

    # image growth on common ids
    for iid in sorted(set(old_i) & set(new_i)):
        old_size = int(old_i[iid].get("size") or 0)
        new_size = int(new_i[iid].get("size") or 0)
        delta = new_size - old_size
        if delta > 0:
            chunks = max(1, delta // (100 * 1024 * 1024))
            s = chunks * DRIFT_WEIGHTS["image_size_growth_mb"]
            drift_points += s
            changes.append({
                "type": "image_size_growth",
                "image": iid,
                "delta_bytes": delta,
                "score": s,
            })

    drift_score = max(0, min(100, drift_points))
    drift_level = "HIGH" if drift_score >= 60 else ("MEDIUM" if drift_score >= 25 else "LOW")

    return {
        "summary": {
            "containers_added": len(added_containers),
            "containers_removed": len(removed_containers),
            "images_added": len(added_images),
            "images_removed": len(removed_images),
            "changes_count": len(changes),
            "drift_score": drift_score,
            "drift_level": drift_level,
        },
        "changes": sorted(changes, key=lambda x: int(x.get("score", 0)), reverse=True),
    }
