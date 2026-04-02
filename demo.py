"""Safeclaw Demo — run this to see every detection and action mode in action."""

from safeclaw import guard, Pipeline, load_config
from safeclaw.pipeline import RegexDetector

config = load_config()
pipeline = Pipeline([RegexDetector()])

# ── Test cases ────────────────────────────────────────────────────────────────

TESTS = [
    ("Clean text (should pass through)", "Hello, this is a normal message with no secrets."),
    ("Email → redact", "Please contact john.doe@company.com for onboarding."),
    ("Phone → redact", "Call me at (555) 867-5309 or +44 20 7946 0958."),
    ("Email + Phone → redact both", "Reach out to admin@startup.io or call 415-555-0199."),
    ("JWT → redact", "Bearer token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
    ("OpenAI key → block", "Set OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345"),
    ("Anthropic key → block", "Use sk-ant-api03-abcdefghijklmnop12345-xyz as the key."),
    ("AWS key → block", "Access key: AKIAIOSFODNN7EXAMPLE"),
    ("GitHub token → block", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"),
    # Stripe key is built dynamically to avoid triggering GitHub push protection
    ("Stripe key → block", "sk" + "_live_" + "FAKEKEYFORTESTING00000000000000"),
    ("Password in config → block", "password = SuperSecret123!@#xyz"),
    ("Credentials in URL → block", "Connect to postgres://admin:p4ssw0rd_secret@db.internal:5432/app"),
    ("SSN → block", "SSN: 123-45-6789"),
    ("Credit card (Visa) → block", "Card: 4111111111111111"),
    ("PEM private key → block", "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAH...base64data...==\n-----END RSA PRIVATE KEY-----"),
    ("Mixed: redact + block", "Email support@acme.com, key is sk-ant-api03-realkey1234567890abcd-xyz"),
]

# ── Run ───────────────────────────────────────────────────────────────────────

WIDTH = 80
print("=" * WIDTH)
print("  SAFECLAW DEMO".center(WIDTH))
print("=" * WIDTH)

passed = 0
for label, text in TESTS:
    result = guard(text, config=config, pipeline=pipeline)

    if result.safe:
        status = "\033[92mPASS\033[0m"
    elif result.blocked:
        status = "\033[91mBLOCK\033[0m"
    else:
        status = "\033[93mREDACT\033[0m"

    print(f"\n{'─' * WIDTH}")
    print(f"  Test:   {label}")
    print(f"  Status: {status}")
    print(f"  Input:  {text[:70]}{'...' if len(text) > 70 else ''}")
    print(f"  Output: {result.text[:70]}{'...' if len(result.text) > 70 else ''}")

    if result.entities:
        for e in result.entities:
            print(f"          → {e.entity_type.value:15} | conf={e.confidence:.2f} | action={e.action.value:6} | {e.label}")

    passed += 1

print(f"\n{'=' * WIDTH}")
print(f"  {passed}/{len(TESTS)} tests completed")
print(f"{'=' * WIDTH}")
