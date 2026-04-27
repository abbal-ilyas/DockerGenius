from __future__ import annotations

import json
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import box

from dockergenius.docker.client import get_client
from dockergenius.docker.containers import list_containers_full
from dockergenius.docker.images import list_images_full
from dockergenius.core.engine import run_analysis
from dockergenius.core.scorer import PROFILES

app = typer.Typer(help="dockergenius CLI")
console = Console()


def _risk_color(level: str) -> str:
    level = str(level).upper()
    if level == "HIGH":
        return "[red]HIGH[/red]"
    if level == "MEDIUM":
        return "[yellow]MEDIUM[/yellow]"
    return "[green]LOW[/green]"


@app.command()
def doctor():
    console.print("[green]dockergenius is installed and runnable[/green]")


@app.command("advisor-run")
def advisor_run(
    profile: str = typer.Option("dev", "--profile", help="dev|staging|prod|security"),
    top: int = typer.Option(5, "--top", help="Top prioritized actions"),
    json_mode: bool = typer.Option(False, "--json"),
):
    profile = profile.strip().lower()
    if profile not in PROFILES:
        console.print("[red]Invalid profile. Use dev|staging|prod|security[/red]")
        raise typer.Exit(1)

    client = get_client()
    containers = list_containers_full(client)
    images = list_images_full(client)
    result = run_analysis(profile=profile, containers=containers, images=images, top=top)

    if json_mode:
        console.print_json(data=result)
        raise typer.Exit()

    t = Table(title="Dockergenius Advisor", box=box.SIMPLE_HEAVY)
    t.add_column("Field", style="bold cyan")
    t.add_column("Value")
    t.add_row("profile", result["profile"])
    t.add_row("global_score", str(result["global_score"]))
    t.add_row("global_risk", result["global_risk"])
    t.add_row("findings", str(result["total_findings"]))
    console.print(t)

    ta = Table(title=f"🔥 Fix these first (Top {len(result['top_actions'])})", box=box.MINIMAL)
    ta.add_column("Rank", style="bold cyan")
    ta.add_column("Score")
    ta.add_column("Scope")
    ta.add_column("Insight")
    ta.add_column("Move")
    for i, f in enumerate(result["top_actions"], 1):
        ta.add_row(
            str(i),
            str(f.get("score", 0)),
            str(f.get("scope", "-")),
            str(f.get("insight", "")),
            str(f.get("move", "")),
        )
    console.print(ta)


@app.command("system-analyze")
def system_analyze(profile: str = typer.Option("dev", "--profile"), json_mode: bool = typer.Option(False, "--json")):
    """Alias operation for quick full advisor pass."""
    ctx = typer.get_current_context()
    ctx.invoke(advisor_run, profile=profile, top=7, json_mode=json_mode)


@app.command("snapshot-save")
def snapshot_save(name: str = "baseline"):
    console.print(f"[magenta]snapshot scaffold pending implementation: {name}[/magenta]")


@app.command("snapshot-diff")
def snapshot_diff(from_name: str, to_name: str = "latest"):
    console.print(f"[magenta]snapshot diff scaffold pending implementation: {from_name} -> {to_name}[/magenta]")


@app.command()
def ui(web: bool = False):
    console.print("[blue]starting web ui scaffold[/blue]" if web else "[blue]starting tui scaffold[/blue]")


if __name__ == "__main__":
    app()
