from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Query
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
from dockergenius.security.analyzer import audit_containers
from dockergenius.security.scanner import scan_images
from dockergenius.remediation.fixer import generate_fix_artifacts

app = FastAPI(title="dockergenius API", version="0.1.0")


class SnapshotSaveRequest(BaseModel):
    name: Optional[str] = Field(default=None, description="Snapshot name. If omitted, UTC timestamp is used.")
    profile: Literal["dev", "staging", "prod", "security"] = "dev"


@app.get("/health")
def health():
    return {"status": "ok", "service": "dockergenius-api"}


@app.get("/advisor")
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
def containers_audit(fix_script: bool = Query(False)):
    try:
        client = get_client()
        containers = list_containers_full(client)
        audit = audit_containers(containers)
        if fix_script:
            audit["remediation"] = generate_fix_artifacts(audit)
        return audit
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Audit failed: {exc}")


@app.get("/images/scan")
def images_scan(
    no_cache: bool = Query(False),
    cache_minutes: int = Query(30, ge=1, le=24 * 60),
):
    try:
        client = get_client()
        images = list_images_full(client)
        result = scan_images(images, use_cache=not no_cache, cache_minutes=cache_minutes)
        if result.get("tool") == "none":
            raise HTTPException(status_code=503, detail=result.get("error", "No scanner available"))
        return result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Image scan failed: {exc}")


@app.post("/snapshot/save")
def snapshot_save(payload: SnapshotSaveRequest):
    try:
        name = payload.name or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        profile = payload.profile.strip().lower()
        if profile not in PROFILES:
            raise HTTPException(status_code=400, detail="Invalid profile. Use dev|staging|prod|security")

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
        return {
            "from": from_name,
            "to": real_to,
            "diff": diff_result,
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Snapshot diff failed: {exc}")
