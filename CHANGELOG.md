# Changelog

All notable changes to `aegis-ledger-sdk` are documented here.

## [0.1.0] — 2026-03-07

### Added
- **`AegisClient`** — `log_tool_call`, `log_decision`, `log_observation`, `log_error`, `log_batch()`
- **`@trace` decorator** — sync and async function tracing with automatic hash-chaining
- **Ed25519 signing + SHA-256 hash-chaining** — tamperproof audit trail on ICP
- **`CanisterTransport`** — ICP canister communication with 3x retry + exponential backoff
- **Spill buffer** — fail-open with `~/.aegis/spill/`, drain on next success
- **PII detection & redaction** — `detect_pii()` and `redact_pii()` with 6 patterns (AHV, credit card, SSN, email, phone, IP); `redact_pii=True` by default
- **Framework integrations** — LangChain, CrewAI, OpenAI Agents SDK, AutoGen/AG2
- **eIDAS timestamps** — RFC 3161 qualified timestamps
- **Compliance reports** — EU AI Act Art. 12, ISO 42001, AIUC-1 (PDF generation)
- **CLI** — `aegis keygen`, `aegis verify`, `aegis export`
