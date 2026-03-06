# Aegis Ledger SDK

**Tamperproof execution ledger for AI agents.**

Every tool call, decision, and error your agent makes — cryptographically sealed, hash-chained, and independently verifiable. Built on the [Internet Computer](https://internetcomputer.org) for immutability that doesn't depend on trusting a database admin.

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
    canister_id="toqqq-lqaaa-aaaae-afc2a-cai",  # From dashboard
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

### 4. Or drop it into LangChain with zero config

```python
from aegis.integrations.langchain import AegisCallbackHandler

handler = AegisCallbackHandler(client)

agent.invoke(
    {"input": "Process the refund for order #4821"},
    config={"callbacks": [handler]},  # ← That's it
)
```

## How it works

```
Your Agent                    Aegis SDK                    ICP Canister
    │                             │                             │
    ├── call_stripe(500, "usd") ──►                             │
    │                             ├── SHA-256(input)            │
    │                             ├── SHA-256(output)           │
    │                             ├── canonical JSON            │
    │                             ├── Ed25519 sign ─────────────►
    │                             │                    verify signature
    │                             │                    check sequence
    │                             │                    chain_hash = SHA-256(
    │                             │                      ...fields...
    │                             │                      + previous_chain_hash
    │                             │                    )
    │                             │                    store immutably
    │                             ◄── action_id ────────────────┤
    ◄── return result ────────────┤                             │
```

**Fail-open by design:** If the canister is unreachable, entries are buffered locally and retried automatically. Your agent never blocks on logging infrastructure.

## Verification

Anyone can verify a ledger entry's integrity — no authentication required:

```bash
aegis verify toqqq-lqaaa-aaaae-afc2a-cai act_a7f3b2c19e4d
# ✓ VERIFIED — Entry act_a7f3b2c19e4d chain hash is valid
#   Hash:     9f86d081884c7d659a2feaa0...
#   Previous: 2c26b46b68ffc68ff99b453c...
```

## What gets logged

| Field | Description |
|-------|-------------|
| `input_hash` | SHA-256 of the full input (raw data never stored on-chain) |
| `output_hash` | SHA-256 of the full output |
| `input_preview` | Truncated, auto-redacted preview (secrets masked) |
| `tool` | Name of the tool/API called |
| `duration_ms` | Wall-clock execution time |
| `chain_hash` | SHA-256 of this entry + all fields + previous entry's hash |
| `payload_signature` | Ed25519 signature proving the entry came from your agent's key |
| `sequence_number` | Monotonic counter per session (gap detection) |

## What does NOT get logged

- Raw input/output payloads (only hashes — you control your data)
- API keys, secrets, tokens (auto-redacted in previews)
- PII (the SDK redacts fields matching common sensitive patterns)

## License

MIT
