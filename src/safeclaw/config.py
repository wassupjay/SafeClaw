"""Configuration loader.

Looks for `.safeclaw.yaml` in: explicit path → cwd → home dir → defaults.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from safeclaw.models import Action, EntityType


class RuleConfig(BaseModel):
    action: Action = Action.BLOCK
    enabled: bool = True


class ServerConfig(BaseModel):
    port: int = 18791


class SafeclawConfig(BaseModel):
    version: int = 1
    threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    fail_open: bool = True
    rules: dict[EntityType, RuleConfig] = Field(default_factory=lambda: {
        EntityType.API_KEY:      RuleConfig(action=Action.BLOCK),
        EntityType.PRIVATE_KEY:  RuleConfig(action=Action.BLOCK),
        EntityType.JWT:          RuleConfig(action=Action.REDACT),
        EntityType.PASSWORD:     RuleConfig(action=Action.BLOCK),
        EntityType.EMAIL:        RuleConfig(action=Action.REDACT),
        EntityType.PHONE:        RuleConfig(action=Action.REDACT),
        EntityType.SSN:          RuleConfig(action=Action.BLOCK),
        EntityType.PASSPORT:     RuleConfig(action=Action.REDACT),
        EntityType.IP_ADDRESS:   RuleConfig(action=Action.REDACT, enabled=False),
        EntityType.CREDIT_CARD:  RuleConfig(action=Action.BLOCK),
        EntityType.BANK_ACCOUNT: RuleConfig(action=Action.BLOCK),
    })
    server: ServerConfig = Field(default_factory=ServerConfig)

    @property
    def disabled_types(self) -> set[EntityType]:
        return {t for t, r in self.rules.items() if not r.enabled}

    def action_for(self, entity_type: EntityType) -> Action:
        rule = self.rules.get(entity_type)
        if rule:
            return rule.action
        # Sensible default: block high-risk types, redact everything else
        high_risk = {
            EntityType.API_KEY, EntityType.PRIVATE_KEY, EntityType.SSN,
            EntityType.CREDIT_CARD, EntityType.BANK_ACCOUNT, EntityType.PASSWORD,
        }
        return Action.BLOCK if entity_type in high_risk else Action.REDACT


def load_config(explicit_path: str | Path | None = None) -> SafeclawConfig:
    """Load config from the first `.safeclaw.yaml` found, or return defaults."""
    candidates: list[Path] = []
    if explicit_path:
        candidates.append(Path(explicit_path))
    candidates.append(Path.cwd() / ".safeclaw.yaml")
    candidates.append(Path.home() / ".safeclaw.yaml")

    for path in candidates:
        if path.is_file():
            try:
                raw: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
                return _parse_raw(raw)
            except Exception as exc:
                import sys
                print(f"safeclaw: failed to parse {path}: {exc}", file=sys.stderr)

    return SafeclawConfig()


def _parse_raw(raw: dict[str, Any]) -> SafeclawConfig:
    """Convert a raw YAML dict into a validated SafeclawConfig."""
    # Normalise rule keys: YAML uses snake_case strings, we need EntityType enums
    if "rules" in raw and isinstance(raw["rules"], dict):
        normalised: dict[str, Any] = {}
        for key, val in raw["rules"].items():
            normalised[key] = val
        raw["rules"] = normalised

    return SafeclawConfig.model_validate(raw)
