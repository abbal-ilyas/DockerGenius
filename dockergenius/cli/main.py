from __future__ import annotations

from datetime import datetime, timezone
import json
import typer
from rich.console import Console
from rich.table import Table
from rich import box

from dockergenius.docker.client import get_client
from dockergenius.docker.containers import list_containers_full
from dockergenius.docker.images import list_images_full
from dockergenius.core.engine import run_analysis
from dockergenius.core.scorer import PROFILES
from dockergenius.core.snapshot import build_snapshot, save_snapshot, load_snapshot, latest_snapshot_name
from dockergenius.core.diff import compute_diff
from dockergenius.output.markdown import write_snapshot_diff_markdown

app = typer.Typer(help="dockergenius CLI")
console = Console()


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
def system_analyze(
    profile: str = typer.Option("dev", "--profile"),
    json_mode: bool = typer.Option(False, "--json"),
):
    advisor_run(profile=profile, top=7, json_mode=json_mode)


@app.command("snapshot-save")
def snapshot_save_cmd(
    name: str = typer.Option("", "--name", help="Snapshot name, default timestamp"),
    profile: str = typer.Option("dev", "--profile"),
    json_mode: bool = typer.Option(False, "--json"),
):
    profile = profile.strip().lower()
    if profile not in PROFILES:
        console.print("[red]Invalid profile. Use dev|staging|prod|security[/red]")
        raise typer.Exit(1)

    if not name:
        name = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    client = get_client()
    containers = list_containers_full(client)
    images = list_images_full(client)

    snapshot = build_snapshot(name=name, profile=profile, containers=containers, images=images)
    path = save_snapshot(snapshot)

    out = {
        "ok": True,
        "snapshot_name": name,
        "path": str(path),
        "containers": len(containers),
        "images": len(images),
    }

    if json_mode:
        console.print_json(data=out)
        raise typer.Exit()

    console.print(f"[green]Snapshot saved:[/green] {path}")
    console.print(f"Containers: {len(containers)} | Images: {len(images)}")


@app.command("snapshot-diff")
def snapshot_diff_cmd(
    from_name: str = typer.Option(..., "--from", help="Source snapshot name"),
    to_name: str = typer.Option("latest", "--to", help="Target snapshot name or 'latest'"),
    markdown: bool = typer.Option(False, "--markdown", help="Export markdown report"),
    json_mode: bool = typer.Option(False, "--json"),
):
    real_to = latest_snapshot_name() if to_name == "latest" else to_name
    old = load_snapshot(from_name)
    new = load_snapshot(real_to)
    diff_result = compute_diff(old, new)

    out = {
        "from": from_name,
        "to": real_to,
        "diff": diff_result,
    }

    md_path = None
    if markdown:
        md_path = write_snapshot_diff_markdown(from_name=from_name, to_name=real_to, diff_result=diff_result)
        out["markdown_report"] = str(md_path)

    if json_mode:
        console.print_json(data=out)
        raise typer.Exit()

    s = diff_result["summary"]
    t = Table(title=f"Snapshot Diff: {from_name} -> {real_to}", box=box.SIMPLE_HEAVY)
    t.add_column("Metric", style="bold cyan")
    t.add_column("Value")
    t.add_row("containers_added", str(s["containers_added"]))
    t.add_row("containers_removed", str(s["containers_removed"]))
    t.add_row("images_added", str(s["images_added"]))
    t.add_row("images_removed", str(s["images_removed"]))
    t.add_row("changes_count", str(s["changes_count"]))
    t.add_row("drift_score", str(s["drift_score"]))
    t.add_row("drift_level", str(s["drift_level"]))
    console.print(t)

    ch = Table(title="Top drift changes", box=box.MINIMAL)
    ch.add_column("Score")
    ch.add_column("Type")
    ch.add_column("Target")
    for c in diff_result.get("changes", [])[:15]:
        ch.add_row(
            str(c.get("score", 0)),
            str(c.get("type", "")),
            str(c.get("container") or c.get("image") or "-"),
        )
    console.print(ch)

    if md_path:
        console.print(f"[green]Markdown report:[/green] {md_path}")


@app.command()
def ui(web: bool = False):
    console.print("[blue]starting web ui scaffold[/blue]" if web else "[blue]starting tui scaffold[/blue]")


if __name__ == "__main__":
    app()
