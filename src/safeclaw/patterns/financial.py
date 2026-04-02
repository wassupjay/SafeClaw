"""Detection rules for financial data: credit cards, IBANs, routing numbers."""

from __future__ import annotations

import re

from safeclaw.models import EntityType
from safeclaw.patterns.base import PatternRule


def _luhn_check(num: str) -> bool:
    """Validate a number string using the Luhn algorithm (ISO/IEC 7812-1)."""
    digits = "".join(c for c in num if c.isdigit())
    if len(digits) < 13:
        return False
    total = 0
    alt = False
    for ch in reversed(digits):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


RULES: list[PatternRule] = [
    PatternRule(
        id="credit_card",
        entity_type=EntityType.CREDIT_CARD,
        label="Credit Card Number",
        # Visa, Mastercard, Amex, Discover — contiguous digits
        pattern=re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|"
            r"3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|"
            r"6(?:011|5[0-9]{2})[0-9]{12})\b"
        ),
        confidence=0.88,
        validator=_luhn_check,
    ),
    PatternRule(
        id="credit_card_spaced",
        entity_type=EntityType.CREDIT_CARD,
        label="Credit Card Number (spaced)",
        # 4-4-4-4 format with spaces or dashes
        pattern=re.compile(r"\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b"),
        confidence=0.80,
        validator=lambda m: _luhn_check(m.replace(" ", "").replace("-", "")),
    ),
    PatternRule(
        id="iban",
        entity_type=EntityType.BANK_ACCOUNT,
        label="IBAN",
        pattern=re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b"),
        confidence=0.85,
    ),
    PatternRule(
        id="routing_account",
        entity_type=EntityType.BANK_ACCOUNT,
        label="US Routing + Account Number",
        pattern=re.compile(r"\b\d{9}\s+\d{8,17}\b"),
        confidence=0.72,
    ),
]
