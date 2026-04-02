"""Core data models for Safeclaw.

Uses Pydantic v2 for runtime validation, serialization, and schema generation.
These models follow NER (Named Entity Recognition) conventions so the project
speaks the same language as the broader NLP / AI-safety ecosystem.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ── Entity taxonomy ──────────────────────────────────────────────────────────


class EntityType(str, Enum):
    """Supported sensitive-data entity types, inspired by common NER tag sets."""

    API_KEY = "api_key"
    PRIVATE_KEY = "private_key"
    JWT = "jwt"
    PASSWORD = "password"
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    PASSPORT = "passport"
    IP_ADDRESS = "ip_address"
    CREDIT_CARD = "credit_card"
    BANK_ACCOUNT = "bank_account"


class Action(str, Enum):
    """What to do when an entity is detected."""

    BLOCK = "block"    # Replace entire message with a warning
    REDACT = "redact"  # Replace only the matched span with [REDACTED:TYPE]


# ── Span: the atomic detection unit ─────────────────────────────────────────


class Span(BaseModel):
    """A detected entity span — the atomic output of a detector backend.

    Mirrors spaCy's `Span` concept: a slice of text with a label and score.
    """

    entity_type: EntityType
    label: str = Field(description="Human-readable name, e.g. 'OpenAI API Key'")
    value: str = Field(description="The matched substring")
    start: int = Field(ge=0, description="Start character offset (inclusive)")
    end: int = Field(ge=0, description="End character offset (exclusive)")
    confidence: float = Field(ge=0.0, le=1.0)
    source: str = Field(
        default="regex",
        description="Which detector backend produced this span (regex, ml, ensemble)",
    )


# ── Entity: Span + policy decision ──────────────────────────────────────────


class Entity(Span):
    """A Span enriched with the policy action that should be applied."""

    action: Action


# ── Guard result ─────────────────────────────────────────────────────────────


class GuardResult(BaseModel):
    """The output of the guard pipeline.

    Callers inspect `safe` and `blocked` to decide what to do, then use `text`
    as the (possibly redacted) output.
    """

    safe: bool = Field(description="True when no entities were detected")
    blocked: bool = Field(default=False, description="True when at least one block-action entity was found")
    text: str = Field(description="Original text, redacted text, or block warning")
    entities: list[Entity] = Field(default_factory=list)


# ── Hook decision (Claude Code integration) ─────────────────────────────────


class HookDecision(BaseModel):
    """JSON structure returned to Claude Code's PreToolUse hook."""

    decision: str | None = None  # "block" or None
    reason: str | None = None
    tool_input: dict[str, Any] | None = None  # Modified tool_input for redaction


# ── Scan request / response (HTTP + MCP) ────────────────────────────────────


class ScanRequest(BaseModel):
    text: str = Field(min_length=1, description="The text to scan")


class DetectResponse(BaseModel):
    """Detection-only response — entities without policy application."""

    count: int
    entities: list[Span]
