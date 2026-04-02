# Safeclaw

**Universal outbound data guard for AI agents.**

Safeclaw catches sensitive data (API keys, passwords, emails, credit cards) before an AI agent accidentally leaks it. Runs on-premise with zero external calls — works for local dev, CI/CD pipelines, and enterprise deployments alike.

```bash
pip install git+https://github.com/wassupjay/SafeClaw.git
```

---

## Why This Exists

AI agents have access to your codebase, `.env` files, databases, and configs. When they generate output — a shell command, a file, an API call — they can accidentally include secrets in plaintext. The agent doesn't know it's leaking. Safeclaw stops that at the exit.

```mermaid
flowchart LR
    ENV["Your secrets\n.env files, API keys\npasswords, customer data"]
    AGENT["AI Agent\nClaude Code, Cursor, etc."]
    SCAN["SAFECLAW\nscans outbound message"]
    PASS["Pass through"]
    REDACT["Redact PII"]
    BLOCK["Block secrets"]
    OUT["Outside world\nterminal, files, APIs"]

    ENV --> AGENT
    AGENT --> SCAN
    SCAN -- clean --> PASS
    SCAN -- email, phone --> REDACT
    SCAN -- API key, password --> BLOCK
    PASS --> OUT
    REDACT --> OUT

    style ENV fill:#6c757d,stroke:#333,color:#fff
    style AGENT fill:#4a90d9,stroke:#333,color:#fff
    style SCAN fill:#e8943a,stroke:#333,color:#fff
    style PASS fill:#5cb85c,stroke:#333,color:#fff
    style REDACT fill:#f0ad4e,stroke:#333,color:#fff
    style BLOCK fill:#d9534f,stroke:#333,color:#fff
    style OUT fill:#6c757d,stroke:#333,color:#fff
```

**In plain English:** The AI agent reads your secrets to do its job. Safeclaw makes sure those secrets don't appear in the output.

### Block vs Redact

```
Input:  "Deploy with key sk-ant-api03-realkey123..."
Output: "[SAFECLAW BLOCKED] contains sensitive data: Anthropic API Key"

Input:  "Send report to john@acme.com and call 555-867-5309"
Output: "Send report to [REDACTED:EMAIL] and call [REDACTED:PHONE]"
```

Configurable per entity type — API keys block, emails redact. Your call.

---

## Get Started

### Claude Code (1 command)

```bash
pip install git+https://github.com/wassupjay/SafeClaw.git
safeclaw install
```

Every tool call is now auto-scanned.

### Python library

```python
from safeclaw import guard

result = guard("Contact john@acme.com with key sk-ant-api03-abc123...")
print(result.safe)      # False
print(result.blocked)   # True — API key detected
print(result.text)      # [SAFECLAW BLOCKED] ...
```

### HTTP server (any language)

```bash
safeclaw serve   # starts on localhost:18791
```

```bash
curl -X POST http://127.0.0.1:18791/scan \
  -H "X-Safeclaw-Secret: <secret>" \
  -d '{"text": "your text here"}'
```

### MCP server (any MCP-compatible agent)

```bash
safeclaw install --mcp
```

---

## What It Detects

| Entity | Default | Examples |
|--------|---------|---------|
| API Keys | 🔴 Block | `sk-ant-...`, `AKIA...`, `ghp_...`, `sk_live_...` |
| Private Keys | 🔴 Block | PEM-encoded RSA/EC keys |
| Passwords | 🔴 Block | `password = "..."`, `postgres://user:pass@host` |
| Credit Cards | 🔴 Block | Visa, Mastercard, Amex (Luhn-validated) |
| SSNs | 🔴 Block | `123-45-6789` |
| JWTs | 🟡 Redact | `eyJhbG...` base64 tokens |
| Emails | 🟡 Redact | `user@domain.com` |
| Phone Numbers | 🟡 Redact | US and international formats |

---

## Architecture

```mermaid
graph TB
    subgraph "Safeclaw Core"
        P["Pipeline"]
        R["RegexDetector"]
        M["MLDetector (pluggable)"]
        P --> R
        P --> M
    end

    subgraph "Integration Layer"
        CLI["CLI (stdin/stdout)"]
        HOOK["Claude Code Hook"]
        MCP["MCP Server (stdio)"]
        HTTP["HTTP Server (FastAPI)"]
    end

    subgraph "Policy Engine"
        CFG["safeclaw.yaml config"]
        RED["Redactor"]
        GUARD["Guard"]
    end

    P --> GUARD
    CFG --> GUARD
    GUARD --> RED

    CLI --> P
    HOOK --> P
    MCP --> P
    HTTP --> P

    style P fill:#4a90d9,stroke:#333,color:#fff
    style R fill:#5cb85c,stroke:#333,color:#fff
    style M fill:#5cb85c,stroke:#333,color:#fff,stroke-dasharray: 5 5
    style GUARD fill:#e8943a,stroke:#333,color:#fff
```

- **Pipeline pattern** (spaCy/sklearn-inspired) — pluggable detectors. Ships with `RegexDetector`, drop in an ML model later without changing any code.
- **Pydantic v2 models** — typed `Span`, `Entity`, `GuardResult` following NER conventions.
- **Confidence scoring** — every match has a score (0.0–1.0). Only flags above your threshold.
- **Overlap resolution** — when two patterns match the same span, highest confidence wins.

---

## Configuration

```bash
safeclaw init    # creates .safeclaw.yaml
```

```yaml
threshold: 0.75       # confidence cutoff
fail_open: true       # if error: pass through (true) or block (false)

rules:
  api_key:    { action: block,  enabled: true }
  email:      { action: redact, enabled: true }
  phone:      { action: redact, enabled: true }
  ip_address: { action: redact, enabled: false }  # too noisy
```

---

## Commands

| Command | What it does |
|---------|-------------|
| `safeclaw scan` | Scan stdin (also works as Claude Code hook) |
| `safeclaw serve` | HTTP server on localhost |
| `safeclaw mcp` | MCP stdio server |
| `safeclaw install` | Add to Claude Code |
| `safeclaw uninstall` | Remove from Claude Code |
| `safeclaw init` | Create config file |

---

## Try It

```bash
git clone https://github.com/wassupjay/SafeClaw.git && cd SafeClaw
python -m venv .venv && source .venv/bin/activate
pip install -e .
python demo.py
```

<details>
<summary>Demo output</summary>

```
  Clean text          → ✅ PASS
  Email               → 🟡 REDACT  [REDACTED:EMAIL]
  Phone               → 🟡 REDACT  [REDACTED:PHONE]
  JWT                 → 🟡 REDACT  [REDACTED:JWT]
  OpenAI key          → 🔴 BLOCK
  Anthropic key       → 🔴 BLOCK
  AWS key             → 🔴 BLOCK
  GitHub token        → 🔴 BLOCK
  Stripe key          → 🔴 BLOCK
  Password            → 🔴 BLOCK
  Credentials in URL  → 🔴 BLOCK
  SSN                 → 🔴 BLOCK
  Credit card         → 🔴 BLOCK
  PEM private key     → 🔴 BLOCK
  16/16 tests passed
```

</details>

---

## License

MIT
