"""Scan pipeline — orchestrates one or more detector backends.

Architecture follows the sklearn / spaCy convention: a Pipeline holds an
ordered list of detector components.  Each component implements a `detect`
protocol (text → list[Span]).  The pipeline merges results, resolves
overlapping spans, and filters by the active config.

Currently ships with one backend (RegexDetector).  Drop in an MLDetector
later without changing any calling code.
"""

from __future__ import annotations

from typing import Protocol

from safeclaw.models import EntityType, Span
from safeclaw.patterns import ALL_RULES, PatternRule


# ── Detector protocol ────────────────────────────────────────────────────────


class Detector(Protocol):
    """Any object that can scan text and return spans."""

    def detect(self, text: str) -> list[Span]: ...


# ── Regex backend ─────────────────────────────────────────────────────────────


class RegexDetector:
    """Fast, zero-dependency detector backed by compiled regex patterns."""

    def __init__(self, rules: list[PatternRule] | None = None) -> None:
        self.rules = rules if rules is not None else ALL_RULES

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for rule in self.rules:
            spans.extend(rule.detect(text))
        return spans


# ── Pipeline ──────────────────────────────────────────────────────────────────


class Pipeline:
    """Composable scan pipeline.

    Usage::

        pipe = Pipeline()                      # regex only (default)
        pipe = Pipeline([RegexDetector(), ml])  # regex + ML ensemble

        spans = pipe.run("some text", config)
    """

    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self.detectors: list[Detector] = detectors or [RegexDetector()]

    def run(
        self,
        text: str,
        *,
        threshold: float = 0.75,
        disabled_types: set[EntityType] | None = None,
    ) -> list[Span]:
        """Run all detectors, merge, deduplicate, and filter."""
        if not text:
            return []

        disabled = disabled_types or set()
        raw_spans: list[Span] = []

        for detector in self.detectors:
            raw_spans.extend(detector.detect(text))

        # Filter by config
        filtered = [
            s for s in raw_spans
            if s.confidence >= threshold and s.entity_type not in disabled
        ]

        return _resolve_overlaps(filtered)


def _resolve_overlaps(spans: list[Span]) -> list[Span]:
    """Deduplicate overlapping spans — keep the highest-confidence match.

    When two spans overlap, the one with higher confidence wins.
    Ties are broken by earlier start offset (prefer the leftmost match).
    """
    # Sort: highest confidence first, then earliest position
    ranked = sorted(spans, key=lambda s: (-s.confidence, s.start))

    kept: list[Span] = []
    for span in ranked:
        if not any(s.start < span.end and span.start < s.end for s in kept):
            kept.append(span)

    # Return in document order
    kept.sort(key=lambda s: s.start)
    return kept
