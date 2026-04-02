"""Detection rules for personally identifiable information (PII)."""

from __future__ import annotations

import re

from safeclaw.models import EntityType
from safeclaw.patterns.base import PatternRule

RULES: list[PatternRule] = [
    PatternRule(
        id="email",
        entity_type=EntityType.EMAIL,
        label="Email Address",
        pattern=re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        confidence=0.95,
    ),
    PatternRule(
        id="us_phone",
        entity_type=EntityType.PHONE,
        label="US Phone Number",
        pattern=re.compile(r"\b(?:\+1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b"),
        confidence=0.78,
    ),
    PatternRule(
        id="intl_phone",
        entity_type=EntityType.PHONE,
        label="International Phone Number",
        pattern=re.compile(
            r"\+(?!1\b)[1-9]\d{0,2}[\s\-.]?\(?\d{1,4}\)?(?:[\s\-.]?\d{1,4}){2,4}\b"
        ),
        confidence=0.76,
    ),
    PatternRule(
        id="us_ssn",
        entity_type=EntityType.SSN,
        label="US Social Security Number",
        pattern=re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        confidence=0.96,
    ),
    PatternRule(
        id="us_passport",
        entity_type=EntityType.PASSPORT,
        label="US Passport Number",
        pattern=re.compile(r"\b[A-Z]\d{8}\b"),
        confidence=0.72,
    ),
    PatternRule(
        id="ipv4",
        entity_type=EntityType.IP_ADDRESS,
        label="IPv4 Address",
        pattern=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        confidence=0.80,
    ),
]
