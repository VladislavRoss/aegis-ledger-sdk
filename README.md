# Aegis Ledger SDK

**Tamper-evident audit logs for AI agents.**

When autonomous agents take actions, their logs become verifiable audit evidence. Aegis hash-chains every tool call, signs it with Ed25519 or post-quantum signatures (ML-DSA-65, ML-DSA-87, SLH-DSA-128s, Hybrid), and stores it on the [Internet Computer](https://internetcomputer.org) — where tampering is cryptographically detectable. Not by you, not your ops team, not the hosting provider — any modification breaks the hash chain.

[![PyPI](https://img.shields.io/pypi/v/aegis-ledger-sdk)](https://pypi.org/project/aegis-ledger-sdk/)
[![Python](https://img.shields.io/pypi/pyversions/aegis-ledger-sdk)](https://pypi.org/project/aegis-ledger-sdk/)
[![Downloads](https://img.shields.io/pypi/dm/aegis-ledger-sdk)](https://pypi.org/project/aegis-ledger-sdk/)
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

# After: pip install aegis-ledger-sdk && aegis init
client = AegisClient.from_config()

@client.trace()
def call_stripe(amount: int, currency: str) -> dict:
    return stripe.PaymentIntent.create(amount=amount, currency=currency)

# Every call is now tamper-evident logged:
#   SHA-256(input) + SHA-256(output) + signature (Ed25519/PQ) + hash-chain link
```

Verify any entry — no authentication required:

```bash
aegis verify toqqq-lqaaa-aaaae-afc2a-cai act_a7f3b2c19e4d
# VERIFIED — chain hash valid, signature valid
```

## Explicit Logging API

```python
# Tool/API calls
client.log_tool_call("stripe.charge", input_data={"amount": 5000}, output_data={"id": "ch_xxx"}, duration_ms=340)

# Decisions with reasoning
client.log_decision("Selected cheapest shipping provider", confidence=0.92, input_data=options)

# Observations (sensor data, API responses)
client.log_observation(input_data=sensor_reading, output_data=parsed_result)

# Errors
client.log_error("payment.process", input_data=request, error=exc, duration_ms=120)

# Human overrides (EU AI Act Art. 14 compliance)
client.log_human_override("Manager approved exception", input_data=original, output_data=override)

# Batch import
client.log_batch([
    {"tool": "search", "input_data": "query", "output_data": "results"},
    {"tool": "summarize", "input_data": "results", "output_data": "summary"},
])
```

## Span Grouping

Group related actions under a parent for structured traces:

```python
with client.span("process_order", reasoning="Customer checkout flow") as span_id:
    client.log_tool_call("inventory.check", ...)
    client.log_tool_call("payment.charge", ...)
    # Both calls have parent_action_id = span_id
```

## Session Management

```python
# Start a new session (resets sequence counter)
new_id = client.new_session()

# Use as context manager for automatic cleanup
with AegisClient(...) as client:
    client.log_tool_call(...)
# Spill buffer drained on exit
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
from aegis.openai_agents import AegisAgentTracer

tracer = AegisAgentTracer(client)
with tracer.trace() as tid:
    result = await Runner.run(agent, "Process this request")
```

### AutoGen / AG2

```python
from aegis.autogen import AegisAutoGenHook

hook = AegisAutoGenHook(client)
hook.on_tool_call("search", arguments={"q": "test"}, caller="assistant")
hook.on_tool_result("search", result="found 5 items", caller="assistant")
```

### Anthropic Agent SDK

```python
from aegis.anthropic_sdk import AegisAnthropicTracer

tracer = AegisAnthropicTracer(client)
tracer.on_tool_use("search", tool_input={"q": "test"}, tool_response="5 results")
tracer.on_session_start("session_123")
tracer.on_subagent_start("sub_1", "researcher")
```

### MCP (Model Context Protocol)

```bash
pip install aegis-ledger-sdk[mcp]
aegis-mcp  # starts MCP server (stdio transport)
```

Any MCP-compatible agent can log actions to the tamper-evident ledger via MCP tools.

## Async & Batch Support

```python
# Async functions work directly with @trace
@client.trace()
async def fetch_data(url: str) -> dict:
    async with aiohttp.ClientSession() as session:
        resp = await session.get(url)
        return await resp.json()
```

## Post-Quantum Signatures

Five signature algorithms with crypto-agility:

| Algorithm | Type | Key Size | Use Case |
|-----------|------|----------|----------|
| Ed25519 | Classical | 32 B | Default, fast |
| ML-DSA-65 | Post-Quantum (FIPS 204) | 1952 B | PQ Level 3 |
| ML-DSA-87 | Post-Quantum (FIPS 204) | 2592 B | CNSA 2.0 Level 5 |
| SLH-DSA-128s | Hash-based (FIPS 205) | 32 B | Conservative PQ fallback |
| Hybrid | Ed25519 + ML-DSA-65 | 1984 B | Best of both worlds |

```python
# Generate PQ keys
# aegis keygen ./key.mldsa65 --algorithm ml-dsa-65
# aegis keygen ./key --algorithm hybrid

client = AegisClient(
    ...,
    signature_scheme="hybrid",
    signing_key_path="./key.mldsa65",
)
```

Configure via `~/.aegis/config.toml`:

```toml
[signing]
default_scheme = "hybrid"
signing_key_path = "~/.aegis/keys/agent.mldsa65"
```

## PII Protection

PII is automatically detected and redacted before transmission (enabled by default):

```python
client = AegisClient(..., redact_pii=True)  # default

# Detected patterns: email, phone, IP, SSN, AHV (Swiss), credit cards
# PII is replaced with sha256:<128-bit hash> — verifiable but not reversible
```

## CLI

```bash
aegis init                                                 # Interactive setup (recommended)
aegis keygen ./key.pem                                     # Generate Ed25519 keypair (advanced)
aegis keygen ./key.mldsa65 --algorithm ml-dsa-65           # Generate ML-DSA-65 keypair
aegis keygen ./key --algorithm hybrid                      # Generate Hybrid keypair
aegis verify <canister_id> <action_id>                     # Verify single entry
aegis verify-chain <canister_id> <session_id>              # Verify full session chain
aegis status <canister_id>                                 # Check canister health
aegis report <canister_id> --format eu-ai-act              # Generate compliance report
aegis report <canister_id> --format all -o ./reports/      # All formats
aegis migrate <canister_id> <session_id> --to hybrid       # Re-sign with new algorithm
aegis version                                              # Print SDK version
```

## How It Works

```
Your Agent                    Aegis SDK                    ICP Canister
    |                             |                             |
    |-- call_stripe(500, "usd") ->|                             |
    |                             |-- SHA-256(input)            |
    |                             |-- SHA-256(output)           |
    |                             |-- sign (Ed25519/PQ) ------->|
    |                             |                    verify signature
    |                             |                    check sequence
    |                             |                    chain_hash = SHA-256(
    |                             |                      prev_hash + payload
    |                             |                    )
    |                             |                    store in append-only ledger
    |                             |<-- action_id ---------------|
    |<-- return result -----------|                             |

Fail-open: if canister unreachable, entries buffer locally (~/.aegis/spill/) and retry.
```

## What Gets Logged

| Field | Description |
|-------|-------------|
| `input_hash` | SHA-256 of full input (raw data never stored on-chain) |
| `output_hash` | SHA-256 of full output |
| `tool` | Tool/API name |
| `duration_ms` | Wall-clock execution time |
| `chain_hash` | SHA-256 linking to previous entry |
| `payload_signature` | Cryptographic signature (Ed25519, ML-DSA-65, ML-DSA-87, SLH-DSA-128s, or Hybrid) |
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

- [Dashboard](https://www.aegis-ledger.com)
- [Documentation](https://www.aegis-ledger.com/docs)
- [GitHub](https://github.com/VladislavRoss/aegis-ledger-sdk)

Normal logging = trust the system. **Aegis = verify the record.**

## License

MIT
