# DockerGenius

Professional Docker intelligence platform scaffold:
- CLI (Typer)
- Core engine scaffolding
- Snapshot/Drift scaffolding
- Security/Runtime scaffolding
- TUI/Web API scaffolding

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
dockergenius doctor
uvicorn dockergenius.ui.web.api:app --reload
```
