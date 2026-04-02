"""Base class for regex-based entity detectors.

Every pattern file registers a list of `PatternRule` instances. The scan
pipeline iterates over all registered rules, runs their regex, applies
optional validators, and yields `Span` objects.

This is the "regex backend" — the first component in Safeclaw's detector
pipeline. The architecture is designed so you can drop in an ML backend
(transformer, GLiNER, ONNX) alongside the regex backend without changing
any calling code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from safeclaw.models import EntityType, Span


@dataclass(frozen=True, slots=True)
class PatternRule:
    """A single regex-based detection rule.

    Attributes:
        id:         Unique identifier (e.g. 'openai_key').
        entity_type: The NER entity type this rule detects.
        label:      Human-readable description shown in results.
        pattern:    Compiled regex with at least one capture or full match.
        confidence: Static confidence score for matches from this rule.
        validator:  Optional callable for post-match validation
                    (e.g. Luhn check for credit cards). Return False to reject.
    """

    id: str
    entity_type: EntityType
    label: str
    pattern: re.Pattern[str]
    confidence: float = 0.90
    validator: Callable[[str], bool] | None = None

    def detect(self, text: str) -> list[Span]:
        """Run the pattern against *text* and return validated spans."""
        spans: list[Span] = []
        for match in self.pattern.finditer(text):
            value = match.group(0)
            if self.validator and not self.validator(value):
                continue
            spans.append(
                Span(
                    entity_type=self.entity_type,
                    label=self.label,
                    value=value,
                    start=match.start(),
                    end=match.end(),
                    confidence=self.confidence,
                    source="regex",
                )
            )
        return spans
