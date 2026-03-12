# Aegis Ledger SDK

**Tamper-evident audit logs for AI agents.**

When autonomous agents take actions, their logs become verifiable audit evidence. Aegis hash-chains every tool call, signs it with Ed25519, and stores it on the [Internet Computer](https://internetcomputer.org) — where tampering is cryptographically detectable. Not you, not your ops team, not the hosting provider can silently alter an entry.

[![PyPI](https://img.shields.io/pypi/v/aegis-ledger-sdk)](https://pypi.org/project/aegis-ledger-sdk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

```
pip install aegis-ledger-sdk
```

## The Problem

Your AI agent just autonomously called a payment API, transferred $47,000, and the client says it wasn't authorized. Your logs are in CloudWatch. The client's lawyer asks: **"Can you prove these logs haven't been edited since the incident?"**

You can't. Aegis fixes this.

## Quickstart

```python
from aegis import AegisClient

client = AegisClient(
    canister_id="toqqq-lqaaa-aaaae-afc2a-cai",  # From dashboard
    api_key_id="ak_3f8a9b2c1d4e5f60",            # From dashboard
    private_key_path="./agent_key.pem",            # aegis keygen
    agent_id="agent_billing_v2",
)

@client.trace()
def call_stripe(amount: int, currency: str) -> dict:
    return stripe.PaymentIntent.create(amount=amount, currency=currency)

# Every call is now tamper-evident-logged:
#   SHA-256(input) + SHA-256(output) + Ed25519 signature + hash-chain link
```

Verify any entry — no authentication required:

```bash
aegis verify toqqq-lqaaa-aaaae-afc2a-cai act_a7f3b2c19e4d
# VERIFIED — chain hash valid, signature valid
```

## Framework Integrations

### LangChain

```python
from aegis.langchain import AegisCallbackHandler

handler = AegisCallbackHandler(client)
agent.invoke({"input": "Process refund"}, config={"callbacks": [handler]})
```

### CrewAI

```python
from aegis.crewai import aegis_step_callback

crew = Crew(agents=[...], tasks=[...], step_callback=aegis_step_callback(client))
```

### OpenAI Agents SDK

```python
from aegis.openai_agents import AegisTracingProcessor

processor = AegisTracingProcessor(client)
# Automatically traces all agent runs
```

### AutoGen / AG2

```python
from aegis.autogen import AegisAutoGenHook

hook = AegisAutoGenHook(client)
# Hook into AutoGen message flow
```

## Async & Batch Support

```python
# Async functions work directly with @trace
@client.trace()
async def fetch_data(url: str) -> dict:
    async with aiohttp.ClientSession() as session:
        resp = await session.get(url)
        return await resp.json()

# Batch-log multiple entries with correct hash-chaining
client.log_batch([
    {"tool": "search", "status": "ok", "input_data": "query"},
    {"tool": "summarize", "status": "ok", "input_data": "results"},
])
```

## PII Protection

PII is automatically detected and redacted before transmission (enabled by default):

```python
client = AegisClient(..., redact_pii=True)  # default

# Detected patterns: email, phone, IP, SSN, AHV (Swiss), credit cards
# PII is replaced with sha256:<128-bit hash> — verifiable but not reversible
```

## How It Works

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
    |                             |                      prev_hash + ":" +
    |                             |                      canonical_json(entry)
    |                             |                    )
    |                             |                    store on-chain
    |                             |<-- action_id ---------------|
    |<-- return result -----------|                             |

Fail-open: if canister unreachable, entries buffer locally and retry.
```

## What Gets Logged

| Field | Description |
|-------|-------------|
| `input_hash` | SHA-256 of full input (raw data never stored on-chain) |
| `output_hash` | SHA-256 of full output |
| `tool` | Tool/API name |
| `duration_ms` | Wall-clock execution time |
| `chain_hash` | SHA-256 linking to previous entry |
| `payload_signature` | Ed25519 signature from your agent's key |
| `sequence_number` | Monotonic counter (gap detection) |

**What does NOT get logged:** Raw payloads, API keys, secrets, PII. Only hashes — you control your data.

## Compliance

Generate verifiable compliance reports:

```python
from aegis.report import generate_report, generate_pdf, ReportFormat

report = generate_report("toqqq-...", format=ReportFormat.EU_AI_ACT, stats=stats, health=health)
generate_pdf(report, "compliance-report.pdf")
```

Supported frameworks: **EU AI Act Art. 12**, **ISO/IEC 42001**, **AIUC-1** (insurance underwriting).

## Links

- [Dashboard](https://www.aegis-ledger.com/dashboard)
- [Documentation](https://www.aegis-ledger.com/docs)
- [GitHub](https://github.com/VladislavRoss/aegis-ledger-sdk)

Normal logging = trust the system. **Aegis = verify the record.**

## License

MIT
