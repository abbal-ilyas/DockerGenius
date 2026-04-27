import typer
from rich.console import Console

app = typer.Typer(help='dockergenius CLI')
console = Console()

@app.command()
def doctor():
    console.print('[green]dockergenius is installed and runnable[/green]')

@app.command('system-analyze')
def system_analyze():
    console.print('[cyan]system analyze: scaffold ready[/cyan]')

@app.command('advisor-run')
def advisor_run(profile: str = 'dev'):
    console.print(f'[yellow]advisor run: profile={profile}[/yellow]')

@app.command('snapshot-save')
def snapshot_save(name: str = 'baseline'):
    console.print(f'[magenta]snapshot saved: {name}[/magenta]')

@app.command('snapshot-diff')
def snapshot_diff(from_name: str, to_name: str = 'latest'):
    console.print(f'[magenta]snapshot diff: {from_name} -> {to_name}[/magenta]')

@app.command()
def ui(web: bool = False):
    console.print('[blue]starting web ui scaffold[/blue]' if web else '[blue]starting tui scaffold[/blue]')

if __name__ == '__main__':
    app()
