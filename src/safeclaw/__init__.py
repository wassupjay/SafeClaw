"""Safeclaw — universal outbound data guard for AI agents.

    from safeclaw import guard, scan, Pipeline

    result = guard("text with sk-ant-abc123...")
    print(result.safe, result.text)
"""

from safeclaw.config import SafeclawConfig, load_config
from safeclaw.models import Action, Entity, EntityType, GuardResult, Span
from safeclaw.pipeline import Pipeline, RegexDetector
from safeclaw.redactor import guard

__all__ = [
    "guard",
    "load_config",
    "Action",
    "Entity",
    "EntityType",
    "GuardResult",
    "Pipeline",
    "RegexDetector",
    "SafeclawConfig",
    "Span",
]

__version__ = "0.1.0"
