from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from dockergenius.remediation.scripts import write_fix_script


def generate_fix_artifacts(audit_result: Dict[str, Any]) -> Dict[str, Any]:
    script_path: Path = write_fix_script(audit_result)
    return {
        "script_path": str(script_path),
        "executable": True,
    }
