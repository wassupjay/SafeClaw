"""MCP server — exposes Safeclaw as tools over stdio.

Any MCP-compatible agent (Claude Code, OpenClaw, etc.) can connect:

    { "command": "safeclaw", "args": ["mcp"], "type": "stdio" }

Exposes two tools:
    safeclaw_scan   — full guard (scan + redact/block)
    safeclaw_detect — detection only (returns entities, no modification)
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from safeclaw.config import SafeclawConfig, load_config
from safeclaw.models import EntityType
from safeclaw.pipeline import Pipeline
from safeclaw.redactor import guard

_mcp = FastMCP("safeclaw")
_config: SafeclawConfig | None = None
_pipeline: Pipeline | None = None


def _get_config() -> SafeclawConfig:
    global _config
    if _config is None:
        _config = load_config()
    return _config


def _get_pipeline() -> Pipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = Pipeline()
    return _pipeline


@_mcp.tool()
def safeclaw_scan(text: str) -> str:
    """Scan text for sensitive data and apply the configured policy.

    Returns JSON with:
    - safe: true if no sensitive data found
    - blocked: true if the message was blocked entirely
    - text: original, redacted, or block-warning text
    - entities: list of detected entities with type, confidence, and action
    """
    result = guard(text, config=_get_config(), pipeline=_get_pipeline())
    return result.model_dump_json(indent=2)


@_mcp.tool()
def safeclaw_detect(text: str) -> str:
    """Detect sensitive entities without modifying or blocking.

    Returns JSON with count and a list of detected spans — useful for
    auditing or building custom handling logic on top of Safeclaw.
    """
    cfg = _get_config()
    spans = _get_pipeline().run(
        text,
        threshold=cfg.threshold,
        disabled_types=cfg.disabled_types,
    )
    import json
    return json.dumps(
        {"count": len(spans), "entities": [s.model_dump() for s in spans]},
        indent=2,
    )


async def run_mcp(config_path: str | None = None) -> None:
    """Start the MCP server on stdio."""
    global _config
    _config = load_config(config_path)
    _get_pipeline()  # warm up
    await _mcp.run_stdio_async()
