from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

import psutil
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from dockergenius.core.engine import run_analysis
from dockergenius.core.scorer import PROFILES
from dockergenius.core.snapshot import (
    build_snapshot,
    save_snapshot,
    load_snapshot,
    latest_snapshot_name,
)
from dockergenius.core.diff import compute_diff
from dockergenius.docker.client import get_client
from dockergenius.docker.containers import list_containers_full
from dockergenius.docker.images import list_images_full
from dockergenius.docker.networks import list_networks_full
from dockergenius.docker.system import get_system_summary
from dockergenius.docker.volumes import list_volumes_full
from dockergenius.security.analyzer import audit_containers
from dockergenius.security.scanner import scan_images, choose_image_ref
from dockergenius.remediation.fixer import generate_fix_artifacts
from dockergenius.utils.config import SNAP_DIR, ensure_storage

app = FastAPI(title="dockergenius API", version="0.1.0")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _page(name: str):
    f = STATIC_DIR / name
    if not f.exists():
        raise HTTPException(status_code=404, detail="Frontend not found")
    return FileResponse(str(f))


class SnapshotSaveRequest(BaseModel):
    name: Optional[str] = Field(default=None, description="Snapshot name. If omitted, UTC timestamp is used.")
    profile: Literal["dev", "staging", "prod", "security"] = "dev"


class ContainerActionRequest(BaseModel):
    identifier: str = Field(..., description="Container name or id")
    action: Literal["start", "stop", "restart", "pause", "unpause", "remove"]


class ImageActionRequest(BaseModel):
    reference: str = Field(..., description="Image reference, tag, or id")
    action: Literal["remove", "pull"]


class NetworkActionRequest(BaseModel):
    name: str
    action: Literal["create", "remove", "connect", "disconnect"]
    driver: Optional[str] = None
    container: Optional[str] = None


class VolumeActionRequest(BaseModel):
    name: str
    action: Literal["create", "remove", "prune"]
    driver: Optional[str] = None


# ---------- Pages ----------
@app.get("/")
def index():
    return _page("index.html")


@app.get("/advisor")
def advisor_page():
    return _page("advisor.html")


@app.get("/audit")
def audit_page():
    return _page("audit.html")


@app.get("/scan")
def scan_page():
    return _page("scan.html")


@app.get("/snapshots")
def snapshots_page():
    return _page("snapshots.html")


@app.get("/storage")
def storage_page():
    return _page("storage.html")


@app.get("/containers")
def containers_page():
    return _page("containers.html")


@app.get("/images")
def images_page():
    return _page("images.html")


@app.get("/networks")
def networks_page():
    return _page("networks.html")


@app.get("/volumes")
def volumes_page():
    return _page("volumes.html")


@app.get("/system")
def system_page():
    return _page("system.html")


# ---------- Core ----------
@app.get("/health")
def health():
    return {"status": "ok", "service": "dockergenius-api"}


@app.get("/advisor/data")
def advisor(
    profile: str = Query("dev", description="dev|staging|prod|security"),
    top: int = Query(5, ge=1, le=50),
):
    profile = profile.strip().lower()
    if profile not in PROFILES:
        raise HTTPException(status_code=400, detail="Invalid profile. Use dev|staging|prod|security")

    try:
        client = get_client()
        containers = list_containers_full(client)
        images = list_images_full(client)
        result = run_analysis(profile=profile, containers=containers, images=images, top=top)
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Advisor failed: {exc}")


@app.get("/containers/audit")
def containers_audit(
    fix_script: bool = Query(False),
    dry_run: bool = Query(False),
):
    try:
        client = get_client()
        containers = list_containers_full(client)
        audit = audit_containers(containers)
        if fix_script and not dry_run:
            audit["remediation"] = generate_fix_artifacts(audit)
        return audit
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Audit failed: {exc}")


@app.get("/containers/list")
def containers_list():
    try:
        client = get_client()
        containers = list_containers_full(client)
        return {"containers": [c.get("name", "unknown") for c in containers]}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Container list failed: {exc}")


@app.get("/containers/data")
def containers_data():
    try:
        client = get_client()
        containers = list_containers_full(client)
        return {
            "summary": {
                "total": len(containers),
                "running": sum(1 for c in containers if c.get("running")),
                "paused": sum(1 for c in containers if c.get("status") == "paused"),
                "stopped": sum(1 for c in containers if not c.get("running") and c.get("status") != "paused"),
            },
            "containers": containers,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Container data failed: {exc}")


@app.post("/containers/action")
def containers_action(payload: ContainerActionRequest, dry_run: bool = Query(False)):
    try:
        client = get_client()
        container = client.containers.get(payload.identifier)

        preview = {
            "identifier": payload.identifier,
            "name": getattr(container, "name", payload.identifier),
            "status": getattr(container, "status", "unknown"),
            "action": payload.action,
        }

        if dry_run:
            return {
                "ok": True,
                "dry_run": True,
                "preview": f"Would {payload.action} container {preview['name']} (status: {preview['status']})",
                **preview,
            }

        if payload.action == "start":
            container.start()
        elif payload.action == "stop":
            container.stop()
        elif payload.action == "restart":
            container.restart()
        elif payload.action == "pause":
            container.pause()
        elif payload.action == "unpause":
            container.unpause()
        elif payload.action == "remove":
            container.remove(force=True)

        return {"ok": True, "dry_run": False, "action": payload.action, "identifier": payload.identifier, "name": preview["name"]}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Container action failed: {exc}")


@app.get("/images/scan")
def images_scan(
    no_cache: bool = Query(False),
    cache_minutes: int = Query(30, ge=1, le=24 * 60),
    image: Optional[str] = Query(None, description="Optional single image ref"),
    dry_run: bool = Query(False),
):
    try:
        client = get_client()
        images = list_images_full(client)

        if image:
            def _match(img):
                if image in (img.get("tags") or []):
                    return True
                if image in {img.get("id"), img.get("short_id")}:
                    return True
                return choose_image_ref(img) == image

            images = [img for img in images if _match(img)]
            if not images:
                raise HTTPException(status_code=404, detail="Image not found")

        result = scan_images(images, use_cache=not no_cache, cache_minutes=cache_minutes)
        if result.get("tool") == "none":
            raise HTTPException(status_code=503, detail=result.get("error", "No scanner available"))
        result["dry_run"] = dry_run
        return result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Image scan failed: {exc}")


@app.get("/images/list")
def images_list():
    try:
        client = get_client()
        images = list_images_full(client)
        refs = [choose_image_ref(img) for img in images]
        return {"images": refs}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Image list failed: {exc}")


@app.get("/images/data")
def images_data():
    try:
        client = get_client()
        images = list_images_full(client)
        return {
            "summary": {
                "total": len(images),
                "total_size": sum(int(img.get("size", 0) or 0) for img in images),
            },
            "images": [{**img, "ref": choose_image_ref(img)} for img in images],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Image data failed: {exc}")


@app.post("/images/action")
def images_action(payload: ImageActionRequest, dry_run: bool = Query(False)):
    try:
        client = get_client()
        if payload.action == "pull":
            if dry_run:
                return {
                    "ok": True,
                    "dry_run": True,
                    "preview": f"Would pull image {payload.reference}",
                    "action": "pull",
                    "reference": payload.reference,
                }
            client.images.pull(payload.reference)
            return {"ok": True, "dry_run": False, "action": "pull", "reference": payload.reference}

        image = client.images.get(payload.reference)
        if dry_run:
            return {
                "ok": True,
                "dry_run": True,
                "preview": f"Would remove image {payload.reference}",
                "action": "remove",
                "reference": payload.reference,
                "tags": image.tags or [],
            }
        image.remove(force=True)
        return {"ok": True, "dry_run": False, "action": "remove", "reference": payload.reference}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Image action failed: {exc}")


@app.get("/networks/data")
def networks_data():
    try:
        client = get_client()
        networks = list_networks_full(client)
        return {
            "summary": {
                "total": len(networks),
                "internal": sum(1 for n in networks if n.get("internal")),
                "attachable": sum(1 for n in networks if n.get("attachable")),
            },
            "networks": networks,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Network data failed: {exc}")


@app.post("/networks/action")
def networks_action(payload: NetworkActionRequest, dry_run: bool = Query(False)):
    try:
        client = get_client()
        if payload.action == "create":
            if dry_run:
                return {
                    "ok": True,
                    "dry_run": True,
                    "preview": f"Would create network {payload.name} with driver {payload.driver or 'bridge'}",
                    "action": "create",
                    "name": payload.name,
                    "driver": payload.driver or "bridge",
                }
            network = client.networks.create(payload.name, driver=payload.driver or "bridge")
            return {"ok": True, "dry_run": False, "action": "create", "name": payload.name, "id": network.id}

        network = client.networks.get(payload.name)
        if dry_run:
            target = payload.container or "<no container>"
            return {
                "ok": True,
                "dry_run": True,
                "preview": f"Would {payload.action} network {payload.name}" + (f" for container {target}" if payload.action in {"connect", "disconnect"} else ""),
                "action": payload.action,
                "name": payload.name,
                "container": payload.container,
            }
        if payload.action == "remove":
            network.remove()
        elif payload.action == "connect":
            if not payload.container:
                raise HTTPException(status_code=400, detail="container is required for connect")
            network.connect(payload.container)
        elif payload.action == "disconnect":
            if not payload.container:
                raise HTTPException(status_code=400, detail="container is required for disconnect")
            network.disconnect(payload.container, force=True)
        return {"ok": True, "dry_run": False, "action": payload.action, "name": payload.name, "container": payload.container}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Network action failed: {exc}")


@app.get("/volumes/data")
def volumes_data():
    try:
        client = get_client()
        volumes = list_volumes_full(client)
        return {
            "summary": {
                "total": len(volumes),
                "total_size": sum(int(v.get("size", 0) or 0) for v in volumes),
                "with_usage": sum(1 for v in volumes if int(v.get("ref_count", 0) or 0) > 0),
            },
            "volumes": volumes,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Volume data failed: {exc}")


@app.post("/volumes/action")
def volumes_action(payload: VolumeActionRequest, dry_run: bool = Query(False)):
    try:
        client = get_client()
        if payload.action == "create":
            if dry_run:
                return {
                    "ok": True,
                    "dry_run": True,
                    "preview": f"Would create volume {payload.name} with driver {payload.driver or 'local'}",
                    "action": "create",
                    "name": payload.name,
                    "driver": payload.driver or "local",
                }
            volume = client.volumes.create(name=payload.name, driver=payload.driver or "local")
            return {"ok": True, "dry_run": False, "action": "create", "name": payload.name, "id": volume.id}
        if payload.action == "prune":
            if dry_run:
                return {
                    "ok": True,
                    "dry_run": True,
                    "preview": "Would prune unused Docker volumes",
                    "action": "prune",
                }
            result = client.volumes.prune()
            return {"ok": True, "dry_run": False, "action": "prune", "result": result}

        volume = client.volumes.get(payload.name)
        if dry_run:
            return {
                "ok": True,
                "dry_run": True,
                "preview": f"Would remove volume {payload.name}",
                "action": "remove",
                "name": payload.name,
            }
        volume.remove()
        return {"ok": True, "dry_run": False, "action": "remove", "name": payload.name}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Volume action failed: {exc}")


@app.get("/system/data")
def system_data():
    try:
        client = get_client()
        return get_system_summary(client)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"System data failed: {exc}")


@app.post("/snapshot/save")
def snapshot_save(payload: SnapshotSaveRequest, dry_run: bool = Query(False)):
    try:
        profile = payload.profile.strip().lower()
        if profile not in PROFILES:
            raise HTTPException(status_code=400, detail="Invalid profile. Use dev|staging|prod|security")

        name = payload.name or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        if dry_run:
            return {"ok": True, "dry_run": True, "snapshot_name": name, "profile": profile}

        client = get_client()
        containers = list_containers_full(client)
        images = list_images_full(client)

        snapshot = build_snapshot(name=name, profile=profile, containers=containers, images=images)
        path = save_snapshot(snapshot)

        return {
            "ok": True,
            "snapshot_name": name,
            "path": str(path),
            "containers": len(containers),
            "images": len(images),
            "profile": profile,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Snapshot save failed: {exc}")


@app.get("/snapshot/diff")
def snapshot_diff(
    from_name: str = Query(..., alias="from"),
    to_name: str = Query("latest", alias="to"),
):
    try:
        real_to = latest_snapshot_name() if to_name == "latest" else to_name
        old = load_snapshot(from_name)
        new = load_snapshot(real_to)
        diff_result = compute_diff(old, new)
        return {"from": from_name, "to": real_to, "diff": diff_result}
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Snapshot diff failed: {exc}")


@app.get("/snapshot/list")
def snapshot_list():
    ensure_storage()
    if not SNAP_DIR.exists():
        return {"snapshots": []}
    names = sorted([p.stem for p in SNAP_DIR.glob("*.json")])
    return {"snapshots": names}


# ---------- Metrics ----------
@app.get("/metrics/system")
def system_metrics():
    vmem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()
    load = psutil.getloadavg() if hasattr(psutil, "getloadavg") else (0, 0, 0)

    return {
        "cpu": {
            "percent": psutil.cpu_percent(interval=0.2),
            "count": psutil.cpu_count(logical=True),
            "load_avg": {"1m": load[0], "5m": load[1], "15m": load[2]},
        },
        "memory": {
            "total": vmem.total,
            "used": vmem.used,
            "free": vmem.available,
            "percent": vmem.percent,
        },
        "swap": {"total": swap.total, "used": swap.used, "percent": swap.percent},
        "disk": {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent,
        },
        "net": {"sent": net.bytes_sent, "recv": net.bytes_recv},
        "boot_time": psutil.boot_time(),
        "uptime_seconds": int(time.time() - psutil.boot_time()),
    }


@app.get("/docker/usage")
def docker_usage():
    client = get_client()
    df = client.df()
    return df


@app.post("/docker/cleanup")
def docker_cleanup(dry_run: bool = Query(True)):
    return {"dry_run": dry_run, "message": "Cleanup is disabled (dry-run only)."}