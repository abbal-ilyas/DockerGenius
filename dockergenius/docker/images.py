from __future__ import annotations

from typing import Any, Dict, List


def list_images_full(client) -> List[Dict[str, Any]]:
    out = []
    for i in client.images.list():
        attrs = i.attrs or {}
        out.append({
            "id": i.id,
            "short_id": i.short_id,
            "tags": i.tags or ["<none>:<none>"],
            "size": int(attrs.get("Size", 0) or 0),
            "created": attrs.get("Created"),
            "repo_digests": attrs.get("RepoDigests") or [],
        })
    return out
