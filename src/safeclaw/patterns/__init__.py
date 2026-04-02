"""Pattern registry — collects all detection rules from sub-modules.

To add a new category, create a module with a `RULES: list[PatternRule]`
attribute and import it here.
"""

from __future__ import annotations

from safeclaw.patterns.base import PatternRule
from safeclaw.patterns.credentials import RULES as _credentials
from safeclaw.patterns.financial import RULES as _financial
from safeclaw.patterns.personal import RULES as _personal

ALL_RULES: list[PatternRule] = [*_credentials, *_personal, *_financial]

__all__ = ["ALL_RULES", "PatternRule"]
