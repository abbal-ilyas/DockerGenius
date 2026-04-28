from __future__ import annotations

from typing import Any, Dict, List


def list_volumes_full(client) -> List[Dict[str, Any]]:
	data: List[Dict[str, Any]] = []
	for volume in client.volumes.list():
		attrs = volume.attrs or {}
		usage = attrs.get("UsageData") or {}
		data.append({
			"name": volume.name,
			"driver": attrs.get("Driver", ""),
			"scope": attrs.get("Scope", ""),
			"mountpoint": attrs.get("Mountpoint", ""),
			"created_at": attrs.get("CreatedAt", ""),
			"status": attrs.get("Status") or {},
			"size": usage.get("Size", 0),
			"ref_count": usage.get("RefCount", 0),
			"labels": attrs.get("Labels") or {},
		})
	return data
