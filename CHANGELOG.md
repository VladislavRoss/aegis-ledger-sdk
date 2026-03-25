# Changelog

All notable changes to `aegis-ledger-sdk` are documented here.

## [0.2.5] — 2026-03-25

### Added
- **Client-side integrity snapshots** — `verify_integrity(sample_size=10)` detects tampered on-chain entries by comparing local chain-hash cache against canister state
- **Snapshot storage** — `~/.aegis/snapshots/<canister_id>.jsonl` written on every `addLedgerEntry` call
- 8 new tests for integrity snapshot + verification

### Changed
- `AegisClient.from_config()` is now the primary factory (docstrings updated)

## [0.2.4] — 2026-03-24

### Fixed
- **CLI config.toml support** — `verify`, `status`, `report`, `verify-chain` now read `~/.aegis/config.toml` for canister_id and private_key_path. No more random identity / empty results.
- **Candid field-hash mapping** — CLI commands now correctly map ic-py hash keys (e.g. `_576569836`) to field names (`totalEntries`). Fixes N/A output in `aegis status` and "unknown reason" in `aegis verify`.
- **Health hash swap** — `totalKeys` and `totalOrgs` hashes were swapped in report.py. Now computed from Candid spec.
- **CLI args now optional** — `aegis status`, `aegis report`, `aegis verify <action_id>` work without explicit canister_id if configured.

### Changed
- `aegis status` output shows human-readable heap (MB) and cycles (T) formatting.
- `aegis verify` shows signature algorithm detail in success message.

## [0.2.2] — 2026-03-23

### Fixed
- `log_human_override()` — correct ActionType mapping (was missing HUMAN_OVERRIDE variant)
- Algo-PK cross-validation — reject mismatched key lengths during registration
- GDPR `deleteMyData` — clean up `userRoles` and `orgAliases` residue
- Declaration re-generation after GDPR + algo-PK fixes

## [0.2.0] — 2026-03-15

### Added
- **ML-DSA-87** (FIPS 204, CNSA 2.0 Level 5) — 5th signature algorithm
- **SLH-DSA-128s** (FIPS 205) — hash-based post-quantum fallback
- **Hybrid signatures** (Ed25519 + ML-DSA-65) — classical + PQ combined
- **`log_human_override()`** — EU AI Act Art. 14 human oversight logging
- **`span()` context manager** — group nested actions under a parent
- **`new_session()`** — start new sessions with sequence reset
- **MCP server** (`aegis-mcp`) — Model Context Protocol integration
- **`aegis verify-chain`** — offline full-session hash-chain verification
- **`aegis status`** — canister health check CLI command
- **`aegis migrate`** — re-sign entries with a new signature algorithm
- **`aegis report --format all`** — generate all compliance formats at once
- **Anthropic Agent SDK integration** — `AegisAnthropicTracer`
- **Config file** (`~/.aegis/config.toml`) — default_scheme, signing_key_path
- **Modular crypto** (`schemes.py`) — pluggable `SignatureScheme` protocol
- **Modular PII** (`pii.py`) — extracted PII detection/redaction module
- **Context manager** — `with AegisClient(...) as client:` for automatic cleanup

### Changed
- Terminology: "tamperproof" -> "tamper-evident" throughout

## [0.1.0] — 2026-03-07

### Added
- **`AegisClient`** — `log_tool_call`, `log_decision`, `log_observation`, `log_error`, `log_batch()`
- **`@trace` decorator** — sync and async function tracing with automatic hash-chaining
- **Ed25519 signing + SHA-256 hash-chaining** — tamper-evident audit trail on ICP
- **`CanisterTransport`** — ICP canister communication with 3x retry + exponential backoff
- **Spill buffer** — fail-open with `~/.aegis/spill/`, drain on next success
- **PII detection & redaction** — `detect_pii()` and `redact_pii()` with 6 patterns (AHV, credit card, SSN, email, phone, IP); `redact_pii=True` by default
- **Framework integrations** — LangChain, CrewAI, OpenAI Agents SDK, AutoGen/AG2
- **eIDAS timestamps** — RFC 3161 qualified timestamps
- **Compliance reports** — EU AI Act Art. 12, ISO 42001, AIUC-1 (PDF generation)
- **CLI** — `aegis keygen`, `aegis verify`, `aegis report`
