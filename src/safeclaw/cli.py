"""Typer CLI — the main entry point for Safeclaw.

    safeclaw scan          # scan stdin (also works as Claude Code hook)
    safeclaw serve         # start HTTP server on localhost
    safeclaw mcp           # start MCP stdio server
    safeclaw install       # install as Claude Code hook
    safeclaw uninstall     # remove from Claude Code
    safeclaw init          # create .safeclaw.yaml in cwd
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(
    name="safeclaw",
    help="Universal outbound data guard for AI agents.",
    no_args_is_help=True,
    add_completion=False,
)


# ── scan ──────────────────────────────────────────────────────────────────────


@app.command()
def scan(
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to .safeclaw.yaml"),
    output_json: bool = typer.Option(False, "--json", help="Always output JSON"),
    detect_only: bool = typer.Option(False, "--detect-only", help="List entities without modifying text"),
) -> None:
    """Scan stdin for sensitive data. Works as a standalone scanner and as a Claude Code PreToolUse hook."""
    from safeclaw.config import load_config
    from safeclaw.hook import handle_hook
    from safeclaw.pipeline import Pipeline
    from safeclaw.redactor import guard

    cfg = load_config(config)
    pipeline = Pipeline()
    raw = sys.stdin.read()

    # ── Try Claude Code hook JSON ─────────────────────────────────────────
    hook_data = None
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict) and "hook_event_name" in parsed and "tool_input" in parsed:
            hook_data = parsed
    except (json.JSONDecodeError, TypeError):
        pass

    if hook_data is not None:
        decision = handle_hook(hook_data, cfg, pipeline)
        if decision is None:
            raise SystemExit(0)
        if decision.decision == "block":
            sys.stdout.write(decision.model_dump_json() + "\n")
            raise SystemExit(2)
        if decision.tool_input is not None:
            sys.stdout.write(decision.model_dump_json(exclude_none=True) + "\n")
            raise SystemExit(0)

    # ── Plain text mode ───────────────────────────────────────────────────
    if detect_only:
        spans = pipeline.run(raw, threshold=cfg.threshold, disabled_types=cfg.disabled_types)
        out = {"count": len(spans), "entities": [s.model_dump() for s in spans]}
        sys.stdout.write(json.dumps(out, indent=2, default=str) + "\n")
        raise SystemExit(0)

    result = guard(raw, config=cfg, pipeline=pipeline)

    if output_json:
        sys.stdout.write(result.model_dump_json(indent=2) + "\n")
        raise SystemExit(0 if result.safe else 1)

    if result.safe:
        sys.stdout.write(raw)
        raise SystemExit(0)

    if result.blocked:
        sys.stderr.write(result.text + "\n")
        raise SystemExit(1)

    # Redacted
    sys.stdout.write(result.text)
    raise SystemExit(0)


# ── serve ─────────────────────────────────────────────────────────────────────


@app.command()
def serve(
    port: int = typer.Option(18791, "--port", "-p", help="Port to listen on"),
    secret: Optional[str] = typer.Option(None, "--secret", "-s", help="Shared secret (auto-generated)"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to .safeclaw.yaml"),
) -> None:
    """Start the local HTTP scan server on 127.0.0.1."""
    from safeclaw.server import run_server

    run_server(port=port, secret=secret, config_path=config)


# ── mcp ───────────────────────────────────────────────────────────────────────


@app.command()
def mcp(
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to .safeclaw.yaml"),
) -> None:
    """Start as an MCP server (stdio transport)."""
    import asyncio

    from safeclaw.mcp_server import run_mcp

    asyncio.run(run_mcp(config_path=config))


# ── install ───────────────────────────────────────────────────────────────────


@app.command()
def install(
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without writing"),
    with_mcp: bool = typer.Option(False, "--mcp", help="Also add MCP server entry"),
) -> None:
    """Install Safeclaw as a Claude Code PreToolUse hook."""
    settings_path = Path.home() / ".claude" / "settings.json"
    settings: dict = {}

    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except json.JSONDecodeError:
            typer.echo(f"Could not parse {settings_path}", err=True)
            raise SystemExit(1)

    changed = False

    # Hook
    hooks = settings.setdefault("hooks", {})
    pre_hooks: list = hooks.setdefault("PreToolUse", [])

    already = any(
        any("safeclaw" in hh.get("command", "") for hh in h.get("hooks", []))
        for h in pre_hooks
    )

    if not already:
        pre_hooks.append({
            "matcher": ".*",
            "hooks": [{"type": "command", "command": "safeclaw scan"}],
        })
        changed = True
        typer.echo("+ PreToolUse hook: safeclaw scan")
    else:
        typer.echo("  PreToolUse hook already present")

    # MCP
    if with_mcp:
        servers = settings.setdefault("mcpServers", {})
        if "safeclaw" not in servers:
            servers["safeclaw"] = {
                "command": "safeclaw",
                "args": ["mcp"],
                "type": "stdio",
            }
            changed = True
            typer.echo("+ MCP server: safeclaw")
        else:
            typer.echo("  MCP server already present")

    if not changed:
        typer.echo("Nothing to do.")
        return

    if dry_run:
        typer.echo("\n[dry-run] Would write:")
        typer.echo(json.dumps(settings, indent=2))
        return

    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    typer.echo(f"\nWritten to {settings_path}")


# ── uninstall ─────────────────────────────────────────────────────────────────


@app.command()
def uninstall(
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without writing"),
) -> None:
    """Remove Safeclaw from Claude Code settings."""
    settings_path = Path.home() / ".claude" / "settings.json"

    if not settings_path.exists():
        typer.echo("No Claude Code settings found.")
        return

    try:
        settings = json.loads(settings_path.read_text())
    except json.JSONDecodeError:
        typer.echo(f"Could not parse {settings_path}", err=True)
        raise SystemExit(1)

    changed = False

    pre_hooks = settings.get("hooks", {}).get("PreToolUse", [])
    before = len(pre_hooks)
    filtered = [
        h for h in pre_hooks
        if not any("safeclaw" in hh.get("command", "") for hh in h.get("hooks", []))
    ]
    if len(filtered) < before:
        settings["hooks"]["PreToolUse"] = filtered
        changed = True
        typer.echo("- Removed PreToolUse hook")

    if settings.get("mcpServers", {}).get("safeclaw"):
        del settings["mcpServers"]["safeclaw"]
        changed = True
        typer.echo("- Removed MCP server entry")

    if not changed:
        typer.echo("Nothing to remove.")
        return

    if dry_run:
        typer.echo("\n[dry-run] Would write:")
        typer.echo(json.dumps(settings, indent=2))
        return

    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    typer.echo(f"Written to {settings_path}")


# ── init ──────────────────────────────────────────────────────────────────────


@app.command()
def init() -> None:
    """Create a .safeclaw.yaml config file in the current directory."""
    dest = Path.cwd() / ".safeclaw.yaml"
    if dest.exists():
        typer.echo(".safeclaw.yaml already exists", err=True)
        raise SystemExit(1)

    src = Path(__file__).parent.parent.parent / "default.config.yaml"
    if src.exists():
        shutil.copy(src, dest)
    else:
        # Fallback: generate from defaults
        from safeclaw.config import SafeclawConfig
        import yaml
        cfg = SafeclawConfig()
        data = cfg.model_dump(mode="json")
        dest.write_text(yaml.dump(data, sort_keys=False, default_flow_style=False))

    typer.echo("Created .safeclaw.yaml")
