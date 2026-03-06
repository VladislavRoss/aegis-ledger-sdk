# Aegis Ledger SDK

**Tamperproof execution ledger for AI agents.**

Every tool call, decision, and error your agent makes — cryptographically sealed, hash-chained, and independently verifiable. Built on the [Internet Computer](https://internetcomputer.org) for immutability that doesn't depend on trusting a database admin.

[![PyPI](https://img.shields.io/pypi/v/aegis-ledger-sdk)](https://pypi.org/project/aegis-ledger-sdk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

```
pip install aegis-ledger-sdk
```

## Why

Your AI agent just autonomously called a payment API, transferred $47,000, and the client says it wasn't authorized. Your logs are in CloudWatch. The client's lawyer asks: **"Can you prove these logs haven't been edited since the incident?"**

You can't.

Aegis fixes this. Every action is append-only, hash-chained (each entry includes the cryptographic hash of the previous entry), and stored on tamperproof infrastructure. No one can alter them — not you, not your ops team, not the hosting provider.

## Quickstart (5 minutes)

### 1. Generate a signing key

```bash
aegis keygen ./agent_key.pem
# → Private key: ./agent_key.pem
# → Public key:  ./agent_key.pem.pub (register this in the dashboard)
```

### 2. Initialize the client

```python
from aegis import AegisClient

client = AegisClient(
    canister_id="toqqq-lqaaa-aaaae-afc2a-cai",  # From https://www.aegis-ledger.com/dashboard
    api_key_id="ak_3f8a9b2c1d4e5f60",            # From dashboard
    private_key_path="./agent_key.pem",
    agent_id="agent_billing_v2",
)
```

### 3. Add the `@trace` decorator to any function

```python
@client.trace()
def call_stripe(amount: int, currency: str) -> dict:
    return stripe.PaymentIntent.create(amount=amount, currency=currency)

# Every call is now tamperproof-logged with:
#   - SHA-256 hashes of input and output
#   - Wall-clock execution time
#   - Ed25519 signature from your agent's key
#   - Hash-chain link to the previous entry
```

### 4. Or drop it into your framework

```python
# LangChain
from aegis.langchain import AegisCallbackHandler
handler = AegisCallbackHandler(client)
agent.invoke({"input": "Process refund"}, config={"callbacks": [handler]})

# CrewAI
from aegis.crewai import aegis_step_callback
crew = Crew(agents=[...], tasks=[...], step_callback=aegis_step_callback(client))

# OpenAI Agents SDK
from aegis.openai_agents import AegisTracingProcessor
processor = AegisTracingProcessor(client)

# AutoGen / AG2
from aegis.autogen import AegisAutoGenHook
hook = AegisAutoGenHook(client)
```

## How it works

```
Your Agent                    Aegis SDK                    ICP Canister
    |                             |                             |
    |-- call_stripe(500, "usd") ->|                             |
    |                             |-- SHA-256(input)            |
    |                             |-- SHA-256(output)           |
    |                             |-- Ed25519 sign ------------>|
    |                             |                    verify signature
    |                             |                    check sequence
    |                             |                    chain_hash = SHA-256(
    |                             |                      prev_hash + payload
    |                             |                    )
    |                             |                    store immutably
    |                             |<-- action_id ---------------|
    |<-- return result -----------|                             |

Fail-open: if canister unreachable, entries buffer locally and retry.
```

## Verification

Anyone can verify a ledger entry's integrity — no authentication required:

```bash
aegis verify toqqq-lqaaa-aaaae-afc2a-cai act_a7f3b2c19e4d
# VERIFIED — chain hash valid, signature valid
```

## What gets logged

| Field | Description |
|-------|-------------|
| `input_hash` | SHA-256 of full input (raw data never stored on-chain) |
| `output_hash` | SHA-256 of full output |
| `input_preview` | Truncated, auto-redacted preview (secrets masked) |
| `tool` | Tool/API name |
| `duration_ms` | Wall-clock execution time |
| `chain_hash` | SHA-256 linking to previous entry |
| `payload_signature` | Ed25519 signature from your agent's key |
| `sequence_number` | Monotonic counter (gap detection) |

**What does NOT get logged:** Raw payloads, API keys, secrets, PII. Only hashes — you control your data.

## PII Detection & Redaction

The SDK automatically detects and redacts sensitive data in previews:

- Swiss AHV numbers (756-prefix + Luhn validation)
- Credit card numbers (13-19 digits + Luhn validation)
- Social Security Numbers, Email addresses, Phone numbers, IP addresses

Each redacted value is replaced with a deterministic `sha256:<16hex>` token.

## Compliance Reports

Generate compliance reports for regulatory frameworks:

```python
from aegis.report import generate_report, generate_pdf, ReportFormat

report = generate_report(
    "toqqq-lqaaa-aaaae-afc2a-cai",
    format=ReportFormat.EU_AI_ACT,
    stats=stats,
    health=health,
)
generate_pdf(report, "compliance-report.pdf")
```

Supported frameworks: **EU AI Act Art. 12**, **ISO/IEC 42001**, **AIUC-1** (insurance underwriting).

## eIDAS Timestamps

Attach RFC 3161 qualified timestamps from EU-certified TSAs:

```python
from aegis.timestamp import TimestampAuthority

tsa = TimestampAuthority()
token = tsa.timestamp(hash_bytes)
```

## Install options

```bash
pip install aegis-ledger-sdk                     # core only
pip install "aegis-ledger-sdk[icp]"              # + ICP transport
pip install "aegis-ledger-sdk[langchain]"         # + LangChain
pip install "aegis-ledger-sdk[crewai]"            # + CrewAI
pip install "aegis-ledger-sdk[openai-agents]"     # + OpenAI Agents SDK
pip install "aegis-ledger-sdk[autogen]"           # + AutoGen/AG2
pip install "aegis-ledger-sdk[pdf]"               # + PDF report generation
pip install "aegis-ledger-sdk[all]"               # everything
```

## Links

- [Dashboard](https://www.aegis-ledger.com)
- [Documentation](https://www.aegis-ledger.com/docs)
- [GitHub](https://github.com/VladislavRoss/aegis-ledger-sdk)
- [PyPI](https://pypi.org/project/aegis-ledger-sdk/)

Normal logging = trust the system. **Aegis = verify the record.**

## License

MIT
