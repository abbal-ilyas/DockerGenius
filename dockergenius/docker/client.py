from __future__ import annotations

import docker
from rich.console import Console
import typer

console = Console()


def get_client() -> docker.DockerClient:
    try:
        return docker.from_env()
    except Exception as exc:
        console.print(f"[red]Docker daemon connection error:[/red] {exc}")
        raise typer.Exit(1)
