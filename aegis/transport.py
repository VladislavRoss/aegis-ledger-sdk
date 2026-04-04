"""
aegis.transport — Internet Computer canister communication layer.

Handles the actual HTTPS calls to the ICP canister via the ic-py library.
Falls back to a local buffer if the canister is unreachable (fail-open
for logging, fail-closed for verification).

Design decisions:
  - Async-first with sync wrappers for simplicity.
  - Automatic retry with exponential backoff (3 attempts, 1s/2s/4s).
  - Local spill buffer: if canister is unreachable, entries are written
    to a local JSONL file and retried on the next successful call.
    This prevents agent execution from blocking on network issues.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("aegis.transport")


_ALLOWED_SPILL_METHODS: frozenset[str] = frozenset({"addLedgerEntry", "addLedgerEntryV2"})
_MAX_SPILL_ENTRIES: int = 1000


def _opt(rec: dict, key: str, default: Any) -> Any:
    """Extract first element from Candid Opt list, or default."""
    v = rec.get(key)
    return v[0] if v else default


def _principal_text_to_bytes(text: str) -> bytes:
    """Convert a Principal text (e.g. 'xxxxx-xxxxx-...') to raw bytes.

    Self-contained implementation — does NOT monkey-patch ic-py.
    ic-py 1.0.1 has ``raise "string"`` (Python 2 syntax) in Principal.from_str
    which crashes on Python 3.13. This function replaces that entirely.
    """
    import base64
    import math

    if isinstance(text, bytes):
        return text

    crc_len = 4
    s1 = text.replace("-", "")
    pad_len = math.ceil(len(s1) / 8) * 8 - len(s1)
    try:
        b = base64.b32decode(s1.upper().encode() + b"=" * pad_len)
    except Exception as exc:
        raise ValueError(f"Invalid principal text: {text!r}") from exc
    if len(b) < crc_len:
        raise ValueError(f"Principal too short: {text!r}")
    return b[crc_len:]

_ACTION_TYPE_MAP: dict[str, str] = {
    "tool_call": "toolCall",
    "decision": "decision",
    "observation": "observation",
    "error": "error",
    "human_override": "humanOverride",
}

_REVERSE_ACTION_TYPE_MAP: dict[str, str] = {v: k for k, v in _ACTION_TYPE_MAP.items()}


def action_type_to_candid_variant(action_type: str) -> dict[str, None]:
    """Konvertiert Python ActionType-String zu Candid Variant dict."""
    if action_type not in _ACTION_TYPE_MAP:
        raise ValueError(
            f"Unknown action type: {action_type!r}. Expected one of: {list(_ACTION_TYPE_MAP)}"
        )
    return {_ACTION_TYPE_MAP[action_type]: None}


from aegis.errors import AegisError, AegisTransportError, CanisterError, translate_error  # noqa: E402, F401, I001 — re-export after conditional import


def _build_add_ledger_entry_args(
    *,
    action_id: str,
    org_id: str,
    agent_id: str,
    session_id: str,
    sequence_number: int,
    action_type: str,
    tool: str,
    input_hash: str,
    output_hash: str,
    input_preview: str,
    output_preview: str,
    duration_ms: int,
    status: str,
    parent_action_id: str,
    decision_reasoning: str,
    confidence_score: float,
    framework: str,
    model_id: str,
    client_timestamp_ms: int,
    payload_signature: str,
    chain_hash: str,
    previous_chain_hash: str,
    payload_hex: str = "",
    key_id: str = "",
) -> list[dict[str, Any]]:
    """Baut die 24 Candid-Positionalargumente für addLedgerEntry."""
    try:
        from ic.candid import Types  # type: ignore[import-untyped]
    except ImportError as e:
        raise CanisterError(
            "ic-py not installed — cannot build Candid args. "
            "Fix: pip install ic-py",
            error_code="NO_IC_PY",
        ) from e

    # Types.Variant muss mit dem vollständigen Schema-Dict aufgerufen werden.
    # Types.Variant ohne Argument ist eine Funktion, kein Typ-Objekt.
    _action_type_variant = Types.Variant({
        "toolCall": Types.Null,
        "decision": Types.Null,
        "observation": Types.Null,
        "error": Types.Null,
        "humanOverride": Types.Null,
    })

    return [
        {"type": Types.Text,           "value": action_id},
        {"type": Types.Principal,      "value": _principal_text_to_bytes(org_id)},
        {"type": Types.Text,           "value": agent_id},
        {"type": Types.Text,           "value": session_id},
        {"type": Types.Nat,            "value": sequence_number},
        {"type": _action_type_variant, "value": action_type_to_candid_variant(action_type)},
        {"type": Types.Text,      "value": tool},
        {"type": Types.Text,      "value": input_hash},
        {"type": Types.Text,      "value": output_hash},
        {"type": Types.Text,      "value": input_preview},
        {"type": Types.Text,      "value": output_preview},
        {"type": Types.Nat,       "value": duration_ms},
        {"type": Types.Text,      "value": status},
        {"type": Types.Text,      "value": parent_action_id},
        {"type": Types.Text,      "value": decision_reasoning},
        {"type": Types.Float64,   "value": confidence_score},
        {"type": Types.Text,      "value": framework},
        {"type": Types.Text,      "value": model_id},
        {"type": Types.Int,       "value": client_timestamp_ms},
        {"type": Types.Text,      "value": payload_signature},
        {"type": Types.Text,      "value": chain_hash},
        {"type": Types.Text,      "value": previous_chain_hash},
        {"type": Types.Text,      "value": payload_hex},
        {"type": Types.Text,      "value": key_id},
    ]


def _build_add_ledger_entry_v2_args(
    *,
    action_id: str,
    org_id: str,
    agent_id: str,
    session_id: str,
    sequence_number: int,
    action_type: str,
    tool: str,
    input_hash: str,
    output_hash: str,
    input_preview: str,
    output_preview: str,
    duration_ms: int,
    status: str,
    parent_action_id: str,
    decision_reasoning: str,
    confidence_score: float,
    framework: str,
    model_id: str,
    client_timestamp_ms: int,
    payload_signature: str,
    chain_hash: str,
    previous_chain_hash: str,
    payload_hex: str = "",
    key_id: str = "",
    metadata: str = "",
    sdk_version: str = "",
    schema_version: int = 2,
    otel_trace_id: str = "",
    otel_span_id: str = "",
    otel_parent_span_id: str = "",
    cost_usd: float = 0.0,
    token_count: int = 0,
    parent_session_id: str = "",
) -> list[dict[str, Any]]:
    """Build a single Candid Record argument for addLedgerEntryV2."""
    try:
        from ic.candid import Types  # type: ignore[import-untyped]
    except ImportError as e:
        raise CanisterError(
            "ic-py not installed — cannot build Candid args. Fix: pip install ic-py",
            error_code="NO_IC_PY",
        ) from e

    _action_type_variant = Types.Variant({
        "toolCall": Types.Null,
        "decision": Types.Null,
        "observation": Types.Null,
        "error": Types.Null,
        "humanOverride": Types.Null,
    })

    record_type = Types.Record({
        "actionId": Types.Text,
        "orgId": Types.Principal,
        "agentId": Types.Text,
        "sessionId": Types.Text,
        "sequenceNumber": Types.Nat,
        "actionType": _action_type_variant,
        "tool": Types.Text,
        "inputHash": Types.Text,
        "outputHash": Types.Text,
        "inputPreview": Types.Text,
        "outputPreview": Types.Text,
        "durationMs": Types.Nat,
        "status": Types.Text,
        "parentActionId": Types.Text,
        "decisionReasoning": Types.Text,
        "confidenceScore": Types.Float64,
        "framework": Types.Text,
        "modelId": Types.Text,
        "clientTimestampMs": Types.Int,
        "payloadSignature": Types.Text,
        "chainHash": Types.Text,
        "previousChainHash": Types.Text,
        "payloadHex": Types.Text,
        "keyId": Types.Text,
        "metadata": Types.Opt(Types.Text),
        "sdkVersion": Types.Opt(Types.Text),
        "schemaVersion": Types.Opt(Types.Nat),
        "otelTraceId": Types.Opt(Types.Text),
        "otelSpanId": Types.Opt(Types.Text),
        "otelParentSpanId": Types.Opt(Types.Text),
        "costUsd": Types.Opt(Types.Float64),
        "tokenCount": Types.Opt(Types.Nat),
        "parentSessionId": Types.Opt(Types.Text),
    })

    record_value = {
        "actionId": action_id,
        "orgId": org_id if isinstance(org_id, bytes) else _principal_text_to_bytes(org_id),
        "agentId": agent_id,
        "sessionId": session_id,
        "sequenceNumber": sequence_number,
        "actionType": action_type_to_candid_variant(action_type),
        "tool": tool,
        "inputHash": input_hash,
        "outputHash": output_hash,
        "inputPreview": input_preview,
        "outputPreview": output_preview,
        "durationMs": duration_ms,
        "status": status,
        "parentActionId": parent_action_id,
        "decisionReasoning": decision_reasoning,
        "confidenceScore": confidence_score,
        "framework": framework,
        "modelId": model_id,
        "clientTimestampMs": client_timestamp_ms,
        "payloadSignature": payload_signature,
        "chainHash": chain_hash,
        "previousChainHash": previous_chain_hash,
        "payloadHex": payload_hex,
        "keyId": key_id,
        "metadata": [metadata] if metadata else [],
        "sdkVersion": [sdk_version] if sdk_version else [],
        "schemaVersion": [schema_version],
        "otelTraceId": [otel_trace_id] if otel_trace_id else [],
        "otelSpanId": [otel_span_id] if otel_span_id else [],
        "otelParentSpanId": [otel_parent_span_id] if otel_parent_span_id else [],
        "costUsd": [cost_usd] if cost_usd > 0.0 else [],
        "tokenCount": [token_count] if token_count > 0 else [],
        "parentSessionId": [parent_session_id] if parent_session_id else [],
    }

    return [{"type": record_type, "value": record_value}]


class TransportConfig:
    """Configuration for the canister transport layer."""

    __slots__ = (
        "canister_id",
        "network",
        "max_retries",
        "retry_base_delay_s",
        "timeout_s",
        "spill_dir",
        "private_key_path",
    )

    def __init__(
        self,
        canister_id: str,
        network: str = "https://icp-api.io",
        max_retries: int = 3,
        retry_base_delay_s: float = 1.0,
        timeout_s: float = 30.0,
        spill_dir: str | Path | None = None,
        private_key_path: str | Path | None = None,
    ):
        if max_retries < 0:
            raise ValueError(f"max_retries must be >= 0, got {max_retries}")
        if retry_base_delay_s < 0:
            raise ValueError(f"retry_base_delay_s must be >= 0, got {retry_base_delay_s}")
        if timeout_s <= 0:
            raise ValueError(f"timeout_s must be > 0, got {timeout_s}")

        self.canister_id = canister_id
        self.network = network
        self.max_retries = max_retries
        self.retry_base_delay_s = retry_base_delay_s
        self.timeout_s = timeout_s
        self.spill_dir = Path(spill_dir) if spill_dir else Path.home() / ".aegis" / "spill"
        self.private_key_path = Path(private_key_path) if private_key_path else None


class CanisterTransport:
    """
    Manages communication with the Aegis Motoko canister on ICP.

    Uses ic-py for candid-encoded canister calls. If ic-py is not
    installed, falls back to raw HTTP agent calls.

    The transport is intentionally synchronous because agent tool
    execution is typically synchronous. Async support can be layered
    on top without changing the interface.
    """

    def __init__(self, config: TransportConfig):
        self._config = config
        self._agent: Any = None
        self._spill_path = config.spill_dir / f"{config.canister_id}.jsonl"
        self._cached_spill_count: int = -1  # -1 = not yet loaded
        self._init_agent()

    def _init_agent(self) -> None:
        """Initialize the ic-py agent. Deferred import to keep it optional."""
        try:
            from ic.agent import Agent  # type: ignore[import-untyped]
            from ic.client import Client  # type: ignore[import-untyped]
            from ic.identity import Identity  # type: ignore[import-untyped]

            client = Client(url=self._config.network)

            # Use the agent's PEM key as IC signing identity so that
            # msg.caller == principal(private_key) == org_id on the canister.
            if self._config.private_key_path and self._config.private_key_path.exists():
                pem_size = self._config.private_key_path.stat().st_size
                if pem_size > 100_000:
                    raise ValueError(
                        f"PEM file too large ({pem_size} bytes) — expected <100KB"
                    )
                pem_str = self._config.private_key_path.read_text()
                identity = Identity.from_pem(pem_str)
                logger.debug(
                    "ic-py agent using key identity %s for %s",
                    identity.sender(),
                    self._config.canister_id,
                )
            else:
                identity = Identity()
                logger.debug(
                    "No private_key_path set — using random IC identity. "
                    "Public queries work fine. For writes, set private_key_path. "
                    "Random principal: %s",
                    identity.sender(),
                )

            self._agent = Agent(identity, client)
            self._ic_available = True

        except ImportError:
            self._ic_available = False
            logger.warning(
                "ic-py not installed. Running in offline mode. "
                "Install with: pip install ic-py"
            )

    def call_update(self, method: str, args: list[Any]) -> dict:
        """
        Call a canister update method with retry and spill-to-disk.

        Update calls mutate canister state (log_action, create_api_key, etc.).
        They go through consensus and are slower (~2s) but guaranteed.

        Rate-limit errors get longer backoff (2s base) to avoid hammering.
        Per-key rate limits get short backoff (100ms) as they clear quickly.
        """
        last_error: Exception | None = None
        for attempt in range(self._config.max_retries):
            try:
                return self._do_call(method, args, call_type="update")
            except Exception as e:  # noqa: BLE001 — fail-open retry: any error triggers retry + spill
                last_error = e
                err_str = str(e).lower()

                # Classify error for appropriate backoff
                if "rate limit" in err_str:
                    if "per-key" in err_str or "per_key" in err_str:
                        delay = 0.1 * (2**attempt)  # 100ms/200ms/400ms
                    else:
                        delay = 2.0 * (2**attempt)  # 2s/4s/8s — org-level, back off more
                elif "sequence" in err_str:
                    delay = 0.05  # 50ms — sequence race, retry fast
                else:
                    delay = self._config.retry_base_delay_s * (2**attempt)

                # H-2: secure jitter (0.5x–1.0x, cryptographically random)
                delay *= 0.5 + secrets.randbelow(50) / 100.0

                if attempt < self._config.max_retries - 1:
                    logger.warning(
                        "Canister call %s failed (attempt %d/%d): %s. Retrying in %.1fs",
                        method,
                        attempt + 1,
                        self._config.max_retries,
                        e,
                        delay,
                    )
                    time.sleep(delay)
                else:
                    logger.warning(
                        "Canister call %s failed (attempt %d/%d): %s",
                        method,
                        attempt + 1,
                        self._config.max_retries,
                        e,
                    )

        # All retries exhausted — spill to local disk (only allowed methods)
        if method in _ALLOWED_SPILL_METHODS:
            self._spill_to_disk(method, args)
        else:
            logger.warning(
                "Method %s is not spillable — discarding failed call", method
            )

        # Translate raw error to typed exception with human-readable message
        typed_error = translate_error(str(last_error or "Unknown error"))
        if isinstance(typed_error, AegisTransportError):
            logger.error(
                "All retries exhausted for %s: %s. Entry spilled to %s",
                method,
                typed_error,
                self._spill_path,
            )
            raise typed_error from last_error

        logger.error(
            "All retries exhausted for %s. Entry spilled to %s",
            method,
            self._spill_path,
        )
        raise CanisterError(
            f"Canister unreachable after {self._config.max_retries} attempts. "
            f"Entry saved locally at {self._spill_path} for later retry.\n"
            "Run 'aegis spill-status' to see pending entries.",
            error_code="TRANSPORT_EXHAUSTED",
        ) from last_error

    def call_query(self, method: str, args: list[Any]) -> dict:
        """
        Call a canister query method (no retry, no spill).

        Query calls are read-only, fast (~200ms), and don't go through
        consensus. Used for getHealth, verifyEntry, getTrace.
        """
        return self._do_call(method, args, call_type="query")

    def _do_call(self, method: str, args: list[Any], call_type: str) -> dict:
        """Execute a single canister call."""
        if not self._ic_available:
            raise CanisterError(
                "ic-py not installed. Cannot communicate with canister. Fix: pip install ic-py",
                error_code="NO_IC_PY",
            )

        try:
            from ic.candid import encode  # type: ignore[import-untyped]

            # args is already a list of {type: ..., value: ...} dicts
            # built by _build_add_ledger_entry_args() — use directly.
            params = args

            if call_type == "update":
                # update_raw() internally calls decode() — result is already a list
                response = self._agent.update_raw(
                    self._config.canister_id, method, encode(params)
                )
            else:
                # query_raw() internally calls decode() — result is already a list
                response = self._agent.query_raw(
                    self._config.canister_id, method, encode(params)
                )

            # response is already decoded (ic-py handles this internally)
            if isinstance(response, list) and len(response) > 0:
                result = response[0]
                if isinstance(result, dict) and "value" in result:
                    # ic-py returns [{"type": ..., "value": {...}}] for record types
                    val = result["value"]
                    return val if isinstance(val, dict) else {"raw": val}
                return result if isinstance(result, dict) else {"raw": result}

            return {"raw": response}

        except ImportError as err:
            raise CanisterError("ic-py encoding failed", error_code="CANDID_ERROR") from err

    def _spill_to_disk(self, method: str, args: list[Any]) -> None:
        """Write a failed call to local disk for later retry."""
        spill_dir = self._spill_path.parent
        # C-2 TOCTOU: symlink check BEFORE mkdir()
        if spill_dir.exists() and spill_dir.is_symlink():
            raise OSError(
                f"Spill directory {spill_dir} is a symlink (security violation) — refusing to write"
            )
        spill_dir.mkdir(parents=True, exist_ok=True)
        # Paranoid post-creation check: attacker may race between exists() and mkdir()
        if spill_dir.is_symlink():
            raise OSError(
                f"Spill directory {spill_dir} became a symlink after creation — aborting"
            )
        spill_dir.chmod(0o700)  # owner-only directory

        # Enforce spill buffer size limit — discard oldest entries if full
        trimmed = False
        if self._spill_path.exists():
            # Guard against unbounded memory from corrupted/bloated spill files
            spill_size = self._spill_path.stat().st_size
            if spill_size > 10 * 1024 * 1024:  # 10 MB safety limit
                logger.error(
                    "Spill file too large (%d bytes) — truncating to empty.",
                    spill_size,
                )
                self._spill_path.unlink()
                self._cached_spill_count = 0
            if self._spill_path.exists():
                existing = self._spill_path.read_text().strip().split("\n")
            else:
                existing = []
            existing = [line for line in existing if line]
            if len(existing) >= _MAX_SPILL_ENTRIES:
                discard_count = len(existing) - _MAX_SPILL_ENTRIES + 1
                logger.warning(
                    "Spill buffer full (%d entries). Discarding %d oldest entries.",
                    len(existing),
                    discard_count,
                )
                existing = existing[discard_count:]
                tmp = self._spill_path.with_suffix(".tmp")
                # H-1: GR-7 atomic write — os.open+fsync+replace prevents corruption on crash
                content = "\n".join(existing) + "\n"
                fd2 = os.open(str(tmp), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
                try:
                    with os.fdopen(fd2, "w", encoding="utf-8") as ftmp:
                        ftmp.write(content)
                        ftmp.flush()
                        os.fsync(ftmp.fileno())
                except Exception:
                    with contextlib.suppress(OSError):
                        os.unlink(str(tmp))
                    raise
                os.replace(str(tmp), str(self._spill_path))
                trimmed = True

        # H-3 FIX: Extract raw values from Candid args so they survive
        # JSON serialization. ic-py Types objects are NOT JSON-serializable,
        # so json.dumps(default=str) corrupts them irreversibly.
        # Bytes (Principal) are stored as hex strings to avoid corruption.
        is_v2_record = (
            len(args) == 1
            and isinstance(args[0].get("value"), dict)
            and "actionId" in args[0]["value"]
        )
        if is_v2_record:
            # V2 Record: single dict — convert bytes fields to hex
            rec = {}
            for k, v in args[0]["value"].items():
                rec[k] = v.hex() if isinstance(v, (bytes, bytearray)) else v
            entry = {
                "method": method,
                "record_value": rec,
                "timestamp_ms": int(time.time() * 1000),
                "canister_id": self._config.canister_id,
                "spill_version": 4,
            }
        else:
            # V1 positional args: list of values
            raw_values = []
            for arg in args:
                val = arg["value"]
                raw_values.append(val.hex() if isinstance(val, (bytes, bytearray)) else val)
            entry = {
                "method": method,
                "raw_values": raw_values,
                "timestamp_ms": int(time.time() * 1000),
                "canister_id": self._config.canister_id,
                "spill_version": 3,
            }
        # H-1: create/append with 0o600 (owner read/write only)
        fd = os.open(str(self._spill_path), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        try:
            with os.fdopen(fd, "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except Exception:  # noqa: BLE001 — re-raises after fd cleanup
            # fdopen failed — close the raw fd to prevent leak
            with contextlib.suppress(OSError):
                os.close(fd)
            raise
        # Update cached count — cap at MAX after overflow trim
        if trimmed:
            self._cached_spill_count = _MAX_SPILL_ENTRIES
        elif self._cached_spill_count < 0:
            self._cached_spill_count = 1
        else:
            self._cached_spill_count += 1

    def drain_spill_buffer(self, max_entries: int = 10) -> int:
        """
        Retry spilled entries. Returns count of successfully drained entries.

        Called automatically on each successful log_action to clear the backlog.
        Entries that fail again remain in the spill file.
        Processes at most ``max_entries`` per call to prevent RAM exhaustion
        (each replay creates ic-py Agent objects that are expensive).
        """
        if not self._spill_path.exists():
            return 0

        lines = self._spill_path.read_text().strip().split("\n")
        if not lines or lines == [""]:
            return 0

        failed: list[str] = []
        drained = 0
        skipped = 0

        raw_ttl = int(os.environ.get("AEGIS_SPILL_TTL_DAYS", "30"))
        spill_ttl_days = max(1, min(365, raw_ttl))
        if raw_ttl != spill_ttl_days:
            logger.warning(
                "AEGIS_SPILL_TTL_DAYS=%d out of range [1,365], clamped to %d",
                raw_ttl, spill_ttl_days,
            )
        spill_ttl_ms = spill_ttl_days * 24 * 60 * 60 * 1000
        now_ms = int(time.time() * 1000)

        for line in lines:
            # Batch limit: defer remaining entries to next drain cycle
            if drained + skipped >= max_entries:
                failed.append(line)
                continue

            try:
                entry = json.loads(line)

                # TTL: discard entries older than 30 days
                age_ms = now_ms - entry.get("timestamp_ms", 0)
                if age_ms > spill_ttl_ms:
                    age_days = age_ms // (24 * 60 * 60 * 1000)
                    logger.warning(
                        "Discarding spill entry older than %dd (age=%dd)",
                        spill_ttl_days, age_days,
                    )
                    continue

                method = entry.get("method", "")
                if method not in _ALLOWED_SPILL_METHODS:
                    logger.error("Discarding spill entry with disallowed method %r", method)
                    continue

                # Rebuild Candid args from stored raw values
                spill_ver = entry.get("spill_version", 1)
                if spill_ver == 4:
                    # V2 Record format — rebuild from record_value dict
                    rec = entry["record_value"]
                    # Convert orgId hex back to bytes
                    org_hex = rec.get("orgId", "")
                    try:
                        org_bytes = bytes.fromhex(org_hex) if isinstance(org_hex, str) else org_hex
                    except ValueError:
                        logger.warning(
                            "Discarding v4 spill: invalid orgId hex: %s",
                            str(org_hex)[:50],
                        )
                        continue
                    rec_copy = dict(rec)
                    rec_copy["orgId"] = org_bytes
                    # M-4: guard against corrupted actionType (empty dict → StopIteration)
                    action_type_dict = rec_copy.get("actionType") or {}
                    if not action_type_dict:
                        logger.warning("Discarding v4 spill entry: missing or empty actionType")
                        skipped += 1
                        continue
                    # Reconstruct V2 Candid Record args
                    args = _build_add_ledger_entry_v2_args(
                        action_id=rec_copy["actionId"],
                        org_id=org_bytes,  # pre-converted from hex
                        agent_id=rec_copy["agentId"],
                        session_id=rec_copy["sessionId"],
                        sequence_number=rec_copy["sequenceNumber"],
                        action_type=_REVERSE_ACTION_TYPE_MAP[next(iter(action_type_dict))],
                        tool=rec_copy["tool"],
                        input_hash=rec_copy["inputHash"],
                        output_hash=rec_copy["outputHash"],
                        input_preview=rec_copy["inputPreview"],
                        output_preview=rec_copy["outputPreview"],
                        duration_ms=rec_copy["durationMs"],
                        status=rec_copy["status"],
                        parent_action_id=rec_copy["parentActionId"],
                        decision_reasoning=rec_copy["decisionReasoning"],
                        confidence_score=rec_copy["confidenceScore"],
                        framework=rec_copy["framework"],
                        model_id=rec_copy["modelId"],
                        client_timestamp_ms=rec_copy["clientTimestampMs"],
                        payload_signature=rec_copy["payloadSignature"],
                        chain_hash=rec_copy["chainHash"],
                        previous_chain_hash=rec_copy["previousChainHash"],
                        payload_hex=rec_copy["payloadHex"],
                        key_id=rec_copy["keyId"],
                        metadata=_opt(rec_copy, "metadata", ""),
                        sdk_version=_opt(rec_copy, "sdkVersion", ""),
                        otel_trace_id=_opt(rec_copy, "otelTraceId", ""),
                        otel_span_id=_opt(rec_copy, "otelSpanId", ""),
                        otel_parent_span_id=_opt(
                            rec_copy, "otelParentSpanId", "",
                        ),
                        cost_usd=_opt(rec_copy, "costUsd", 0.0),
                        token_count=_opt(rec_copy, "tokenCount", 0),
                    )
                elif spill_ver >= 2:
                    v = entry["raw_values"]

                    # Validate org_id (index 1) — detect corruption from
                    # old entries where bytes were serialized via str()
                    org_id_val = str(v[1])
                    if org_id_val.startswith(("b'", 'b"', "b\\")) or not org_id_val:
                        logger.warning(
                            "Discarding spill entry with corrupt principal: %s",
                            org_id_val[:50],
                        )
                        continue

                    # v3: org_id is stored as hex of principal bytes.
                    # _build_add_ledger_entry_args expects principal text,
                    # but for v3 we can pass hex directly via bytes.
                    if spill_ver >= 3:
                        # v3 stores principal as hex — convert to bytes
                        try:
                            org_id_bytes = bytes.fromhex(org_id_val)
                        except ValueError:
                            logger.warning(
                                "Discarding spill entry with invalid principal hex: %s",
                                org_id_val[:50],
                            )
                            continue

                    # v[5] is the variant dict, e.g. {"toolCall": null}
                    variant_dict = v[5]
                    action_type_str = _REVERSE_ACTION_TYPE_MAP[next(iter(variant_dict))]

                    if spill_ver >= 3:
                        # Build args directly with pre-converted principal bytes
                        from ic.candid import Types  # type: ignore[import-untyped]
                        _action_type_variant = Types.Variant({
                            "toolCall": Types.Null, "decision": Types.Null,
                            "observation": Types.Null, "error": Types.Null,
                            "humanOverride": Types.Null,
                        })
                        args = [
                            {"type": Types.Text, "value": v[0]},
                            {"type": Types.Principal, "value": org_id_bytes},
                            {"type": Types.Text, "value": v[2]},
                            {"type": Types.Text, "value": v[3]},
                            {"type": Types.Nat, "value": v[4]},
                            {"type": _action_type_variant,
                             "value": action_type_to_candid_variant(action_type_str)},
                            {"type": Types.Text, "value": v[6]},
                            {"type": Types.Text, "value": v[7]},
                            {"type": Types.Text, "value": v[8]},
                            {"type": Types.Text, "value": v[9]},
                            {"type": Types.Text, "value": v[10]},
                            {"type": Types.Nat, "value": v[11]},
                            {"type": Types.Text, "value": v[12]},
                            {"type": Types.Text, "value": v[13]},
                            {"type": Types.Text, "value": v[14]},
                            {"type": Types.Float64, "value": v[15]},
                            {"type": Types.Text, "value": v[16]},
                            {"type": Types.Text, "value": v[17]},
                            {"type": Types.Int, "value": v[18]},
                            {"type": Types.Text, "value": v[19]},
                            {"type": Types.Text, "value": v[20]},
                            {"type": Types.Text, "value": v[21]},
                            {"type": Types.Text, "value": v[22]},
                            {"type": Types.Text, "value": v[23]},
                        ]
                    else:
                        # v2: org_id is text — pass through
                        args = _build_add_ledger_entry_args(
                            action_id=v[0], org_id=v[1], agent_id=v[2],
                            session_id=v[3], sequence_number=v[4],
                            action_type=action_type_str, tool=v[6],
                            input_hash=v[7], output_hash=v[8],
                            input_preview=v[9], output_preview=v[10],
                            duration_ms=v[11], status=v[12],
                            parent_action_id=v[13], decision_reasoning=v[14],
                            confidence_score=v[15], framework=v[16],
                            model_id=v[17], client_timestamp_ms=v[18],
                            payload_signature=v[19], chain_hash=v[20],
                            previous_chain_hash=v[21], payload_hex=v[22],
                            key_id=v[23],
                        )
                else:
                    # Legacy v1 format — args contain stringified Types,
                    # cannot be reconstructed. Log and discard.
                    logger.warning(
                        "Discarding legacy v1 spill entry — Types objects "
                        "were corrupted by json.dumps(default=str)"
                    )
                    continue

                self._do_call(method, args, call_type="update")
                drained += 1
            except Exception as exc:  # noqa: BLE001 — fail-open spill replay
                err_msg = str(exc).lower()
                # Permanent failures: drop instead of endless retry
                if any(sig in err_msg for sig in (
                    "sequence number must be strictly increasing",
                    "sequence",
                    "duplicate",
                    "already exists",
                    "rate limit",
                    "does not belong",
                    "unauthorized",
                    "dpa not accepted",
                    "concurrent write",
                    "key not found",
                    "key is revoked",
                    "anonymous",
                    "invalid principal",
                )):
                    logger.warning(
                        "Discarding spill entry (permanent failure): %s",
                        str(exc)[:200],
                    )
                    skipped += 1
                else:
                    # Transient failure (network, timeout) — retry with counter
                    retry_count = entry.get("_retry_count", 0) + 1
                    if retry_count >= 5:
                        logger.warning(
                            "Discarding spill entry after %d retries: %s",
                            retry_count, str(exc)[:200],
                        )
                        skipped += 1
                    else:
                        entry["_retry_count"] = retry_count
                        logger.warning(
                            "Spill replay failed (retry %d/5)",
                            retry_count, exc_info=True,
                        )
                        failed.append(json.dumps(entry))

        # Rewrite spill file with only the still-failed entries (atomic: GR-7)
        if failed:
            tmp = self._spill_path.with_suffix(".tmp")
            tmp.write_text("\n".join(failed) + "\n", encoding="utf-8")
            tmp.replace(self._spill_path)
        else:
            self._spill_path.unlink(missing_ok=True)

        self._cached_spill_count = len(failed)

        if drained > 0:
            logger.info("Drained %d spilled entries from buffer", drained)

        return drained

    @property
    def spill_count(self) -> int:
        """Number of entries waiting in the local spill buffer (cached)."""
        if self._cached_spill_count >= 0:
            return self._cached_spill_count
        # First access — read from disk once, then cache
        if not self._spill_path.exists():
            self._cached_spill_count = 0
            return 0
        text = self._spill_path.read_text().strip()
        if not text:
            self._cached_spill_count = 0
            return 0
        self._cached_spill_count = len([line for line in text.split("\n") if line])
        return self._cached_spill_count
