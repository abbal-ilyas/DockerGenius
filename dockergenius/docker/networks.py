from __future__ import annotations

from typing import Any, Dict, List


def list_networks_full(client) -> List[Dict[str, Any]]:
	data: List[Dict[str, Any]] = []
	for network in client.networks.list():
		attrs = network.attrs or {}
		ipam_configs = ((attrs.get("IPAM") or {}).get("Config") or [])
		containers = attrs.get("Containers") or {}
		data.append({
			"id": network.id,
			"short_id": network.short_id,
			"name": network.name,
			"driver": attrs.get("Driver", ""),
			"scope": attrs.get("Scope", ""),
			"internal": bool(attrs.get("Internal", False)),
			"attachable": bool(attrs.get("Attachable", False)),
			"ingress": bool(attrs.get("Ingress", False)),
			"containers": len(containers),
			"subnets": [cfg.get("Subnet") for cfg in ipam_configs if cfg.get("Subnet")],
			"gateways": [cfg.get("Gateway") for cfg in ipam_configs if cfg.get("Gateway")],
			"labels": attrs.get("Labels") or {},
		})
	return data
