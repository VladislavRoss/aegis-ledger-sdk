# Changelog

All notable changes to `aegis-ledger-sdk` are documented here.

## [0.4.0] — 2026-03-07

### Added
- **Async `@trace` support** — decorate `async def` functions directly; no more `TypeError`
- **`log_batch()`** — log multiple entries sequentially with correct hash-chaining
- **PII test suite** — 19 dedicated tests for detect/redact (email, phone, IP, SSN, AHV, credit card)

### Changed
- **PII hash truncation** — `sha256:<32hex>` (128-bit) instead of `sha256:<16hex>` (64-bit)

### Fixed
- `@trace` async guard removed — async functions are now fully supported

## [0.3.0] — 2026-03-06

### Added
- **PII detection & redaction** — `detect_pii()` and `redact_pii()` with 6 patterns (AHV, credit card, SSN, email, phone, IP)
- **AutoGen/AG2 integration** — `AegisAutoGenHook` with `on_message_sent`, `on_message_received`, `on_tool_call`, `on_completion`
- **OpenAI Agents SDK tracer** — `AegisOpenAITracer` for OpenAI Agents framework
- **eIDAS timestamps** — RFC 3161 qualified timestamps via `AegisTimestamper`
- **Compliance report generator** — EU AI Act, ISO 42001, AIUC-1 reports via `AegisReportGenerator`

### Changed
- Default `redact_pii=True` in `AegisClient` — PII is hashed before transmission

## [0.2.0] — 2026-02-15

### Added
- **CrewAI integration** — `AegisCrewAICallback` step_callback
- **LangChain handler** — `AegisCallbackHandler` for LangChain/LangGraph
- **CLI** — `aegis keygen`, `aegis verify`, `aegis export` commands
- **Spill buffer** — fail-open with `~/.aegis/spill/` directory, drain on next success

### Changed
- Transport retry: 3x exponential backoff before spill

## [0.1.0] — 2026-01-20

### Added
- Initial release
- `AegisClient` with `log_tool_call`, `log_decision`, `log_observation`, `log_error`
- `@trace` decorator for sync functions
- Ed25519 signing + SHA-256 hash-chaining
- `CanisterTransport` for ICP canister communication
