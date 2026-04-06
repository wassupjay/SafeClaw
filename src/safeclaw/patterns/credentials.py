"""Detection rules for API keys, tokens, secrets, private keys, and passwords."""

from __future__ import annotations

import re

from safeclaw.models import EntityType
from safeclaw.patterns.base import PatternRule

RULES: list[PatternRule] = [
    PatternRule(
        id="anthropic_key",
        entity_type=EntityType.API_KEY,
        label="Anthropic API Key",
        pattern=re.compile(r"\bsk-ant-[a-zA-Z0-9\-_]{6,}\b"),
        confidence=0.99,
    ),
    PatternRule(
        id="openai_key",
        entity_type=EntityType.API_KEY,
        label="OpenAI API Key",
        # Covers sk-<org>-... and sk-proj-... formats
        pattern=re.compile(r"\bsk-(?!ant-)[a-zA-Z0-9\-_]{6,}\b"),
        confidence=0.97,
    ),
    PatternRule(
        id="aws_access_key",
        entity_type=EntityType.API_KEY,
        label="AWS Access Key ID",
        pattern=re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
        confidence=0.99,
    ),
    PatternRule(
        id="github_token",
        entity_type=EntityType.API_KEY,
        label="GitHub Token",
        pattern=re.compile(r"\bgh[pohsr]_[A-Za-z0-9_]{36,}\b"),
        confidence=0.99,
    ),
    PatternRule(
        id="stripe_key",
        entity_type=EntityType.API_KEY,
        label="Stripe API Key",
        pattern=re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[a-zA-Z0-9]{24,}\b"),
        confidence=0.98,
    ),
    PatternRule(
        id="slack_token",
        entity_type=EntityType.API_KEY,
        label="Slack Token",
        pattern=re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
        confidence=0.98,
    ),
    PatternRule(
        id="google_api_key",
        entity_type=EntityType.API_KEY,
        label="Google API Key",
        pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        confidence=0.97,
    ),
    PatternRule(
        id="bearer_token",
        entity_type=EntityType.API_KEY,
        label="Bearer Token",
        pattern=re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}\b"),
        confidence=0.85,
    ),
    PatternRule(
        id="private_key_pem",
        entity_type=EntityType.PRIVATE_KEY,
        label="PEM Private Key",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
            r"[\s\S]{20,}?"
            r"-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
        confidence=0.99,
    ),
    PatternRule(
        id="jwt",
        entity_type=EntityType.JWT,
        label="JSON Web Token",
        pattern=re.compile(r"\beyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+/]*\b"),
        confidence=0.95,
    ),
    PatternRule(
        id="password_in_url",
        entity_type=EntityType.PASSWORD,
        label="Credentials in URL",
        pattern=re.compile(r"[a-zA-Z][a-zA-Z0-9+\-.]*://[^:\s@/]+:[^@\s/]{3,}@[^\s/]+"),
        confidence=0.95,
    ),
    PatternRule(
        id="password_kv",
        entity_type=EntityType.PASSWORD,
        label="Password or Secret in Assignment",
        pattern=re.compile(
            r"\b(?:password|passwd|secret|api[_\-]?key|auth[_\-]?token|"
            r"access[_\-]?token|client[_\-]?secret)\s*[:=]\s*['\"`]?[^\s'\"`]{8,}['\"`]?",
            re.IGNORECASE,
        ),
        confidence=0.82,
    ),
]
