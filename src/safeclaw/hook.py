"""Claude Code PreToolUse hook handler.

When invoked as a hook, Claude Code pipes a JSON payload to stdin:

    {
        "session_id": "...",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "curl -H 'Authorization: Bearer sk-...'" }
    }

This module scans every string value inside `tool_input`, then:
    - Clean     → returns None (caller exits 0, tool proceeds)
    - Blocked   → returns {"decision": "block", "reason": "..."} (caller exits 2)
    - Redacted  → returns {"tool_input": {...}} with redacted values (caller exits 0)
"""

from __future__ import annotations

import copy
from typing import Any

from safeclaw.config import SafeclawConfig
from safeclaw.models import Action, HookDecision
from safeclaw.pipeline import Pipeline
from safeclaw.redactor import guard


def handle_hook(
    hook_data: dict[str, Any],
    config: SafeclawConfig,
    pipeline: Pipeline | None = None,
) -> HookDecision | None:
    """Process a Claude Code hook payload and return a decision."""
    tool_input = hook_data.get("tool_input", {})
    strings = _extract_strings(tool_input)

    if not strings:
        return None

    combined = "\n".join(s["value"] for s in strings)
    result = guard(combined, config=config, pipeline=pipeline)

    if result.safe:
        return None

    if result.blocked:
        labels = list(dict.fromkeys(
            e.label for e in result.entities if e.action == Action.BLOCK
        ))
        return HookDecision(
            decision="block",
            reason=f"Safeclaw: message contains sensitive data — {', '.join(labels)}",
        )

    # Redact: apply redactions to each field independently
    redacted_input = _redact_input(tool_input, result.entities)
    return HookDecision(tool_input=redacted_input)


def _extract_strings(
    obj: Any,
    path: list[str | int] | None = None,
) -> list[dict[str, Any]]:
    """Recursively extract all string values with their key paths."""
    path = path or []
    results: list[dict[str, Any]] = []

    if isinstance(obj, str):
        results.append({"path": path, "value": obj})
    elif isinstance(obj, dict):
        for key, val in obj.items():
            results.extend(_extract_strings(val, [*path, key]))
    elif isinstance(obj, list):
        for i, val in enumerate(obj):
            results.extend(_extract_strings(val, [*path, i]))

    return results


def _redact_input(
    tool_input: dict[str, Any],
    entities: list,
) -> dict[str, Any]:
    """Return a deep copy of tool_input with redacted entity values."""
    result = copy.deepcopy(tool_input)
    strings = _extract_strings(result)

    for item in strings:
        redacted = item["value"]
        for entity in entities:
            if entity.action == Action.REDACT:
                redacted = redacted.replace(
                    entity.value,
                    f"[REDACTED:{entity.entity_type.value.upper()}]",
                )
        _set_path(result, item["path"], redacted)

    return result


def _set_path(obj: Any, path: list[str | int], value: Any) -> None:
    """Set a nested value by key path."""
    current = obj
    for key in path[:-1]:
        current = current[key]
    current[path[-1]] = value
