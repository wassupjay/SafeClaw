"""Guard logic — scan text and apply the configured policy (redact or block)."""

from __future__ import annotations

from safeclaw.config import SafeclawConfig, load_config
from safeclaw.models import Action, Entity, GuardResult
from safeclaw.pipeline import Pipeline


# ANSI color codes for colored output
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


# Module-level default pipeline (singleton — avoids re-init on every call)
_default_pipeline = Pipeline()


def guard(
    text: str,
    config: SafeclawConfig | None = None,
    pipeline: Pipeline | None = None,
    use_colors: bool = True,
) -> GuardResult:
    """Scan *text* and return a `GuardResult`.

    - If no entities found → `safe=True`, original text returned.
    - If any entity has action=block → `blocked=True`, entire text replaced.
    - Otherwise → redact-only entities get `[REDACTED:TYPE]` placeholders.
    """
    cfg = config or load_config()
    pipe = pipeline or _default_pipeline

    spans = pipe.run(
        text,
        threshold=cfg.threshold,
        disabled_types=cfg.disabled_types,
    )

    if not spans:
        return GuardResult(safe=True, text=text)

    # Enrich spans with the policy action
    entities = [
        Entity(
            **span.model_dump(),
            action=cfg.action_for(span.entity_type),
        )
        for span in spans
    ]

    blocked = [e for e in entities if e.action == Action.BLOCK]

    if blocked:
        labels = list(dict.fromkeys(e.label for e in blocked))  # unique, order-preserved
        block_prefix = f"{RED}[SAFECLAW BLOCKED]{RESET}" if use_colors else "[SAFECLAW BLOCKED]"
        return GuardResult(
            safe=False,
            blocked=True,
            text=(
                f"{block_prefix} This message was not delivered because it "
                f"contained sensitive data: {', '.join(labels)}"
            ),
            entities=entities,
        )

    # Redact-only path
    redacted_text = _apply_redactions(text, entities, use_colors)
    return GuardResult(
        safe=False,
        blocked=False,
        text=redacted_text,
        entities=entities,
    )


def _apply_redactions(text: str, entities: list[Entity], use_colors: bool = True) -> str:
    """Replace matched spans with `[REDACTED:TYPE]` placeholders.

    Processes from the end of the string so earlier offsets stay valid.
    """
    sorted_ents = sorted(entities, key=lambda e: e.start, reverse=True)
    result = text
    for ent in sorted_ents:
        color_prefix = YELLOW if use_colors else ""
        color_suffix = RESET if use_colors else ""
        placeholder = f"{color_prefix}[REDACTED:{ent.entity_type.value.upper()}]{color_suffix}"
        result = result[: ent.start] + placeholder + result[ent.end :]
    return result
