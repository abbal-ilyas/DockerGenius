from __future__ import annotations

from typing import Any, Dict


def get_system_summary(client) -> Dict[str, Any]:
	info = client.info()
	df = client.df()

	return {
		"engine": {
			"server_version": info.get("ServerVersion", ""),
			"os": info.get("OperatingSystem", ""),
			"architecture": info.get("Architecture", ""),
			"kernel_version": info.get("KernelVersion", ""),
			"docker_root_dir": info.get("DockerRootDir", ""),
			"driver": info.get("Driver", ""),
			"logging_driver": info.get("LoggingDriver", ""),
			"default_runtime": info.get("DefaultRuntime", ""),
			"swarm": info.get("Swarm", {}).get("LocalNodeState", "inactive"),
			"warnings": info.get("Warnings") or [],
		},
		"counts": {
			"containers": len(df.get("Containers") or []),
			"images": len(df.get("Images") or []),
			"volumes": len(df.get("Volumes") or []),
			"networks": len(df.get("Networks") or []),
		},
		"raw_df": df,
	}
