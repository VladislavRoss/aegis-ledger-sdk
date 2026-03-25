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
import random
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("aegis.transport")


_ALLOWED_SPILL_METHODS: frozenset[str] = frozenset({"addLedgerEntry"})
_MAX_SPILL_ENTRIES: int = 1000


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


class AegisError(Exception):
    """Base exception for all Aegis SDK errors."""


class CanisterError(AegisError):
    """Raised when the canister returns an error response."""

    def __init__(self, message: str, error_code: str = "UNKNOWN"):
        self.error_code = error_code
        super().__init__(f"[{error_code}] {message}")


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
                pem_str = self._config.private_key_path.read_text()
                identity = Identity.from_pem(pem_str)
                logger.debug(
                    "ic-py agent using key identity %s for %s",
                    identity.sender(),
                    self._config.canister_id,
                )
            else:
                identity = Identity()
                logger.warning(
                    "No private_key_path set — using random IC identity. "
                    "Canister caller check will fail unless org_id matches this principal: %s",
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
        """
        for attempt in range(self._config.max_retries):
            try:
                return self._do_call(method, args, call_type="update")
            except Exception as e:  # noqa: BLE001 — fail-open retry: any error triggers retry + spill
                # Skip sleep after last attempt (we're about to spill anyway)
                if attempt < self._config.max_retries - 1:
                    delay = self._config.retry_base_delay_s * (2**attempt)
                    # Add jitter (0.5x-1.0x) to prevent thundering herd
                    delay *= 0.5 + random.random() * 0.5  # noqa: S311
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

        # All retries exhausted — spill to local disk
        self._spill_to_disk(method, args)
        logger.error(
            "All retries exhausted for %s. Entry spilled to %s",
            method,
            self._spill_path,
        )
        raise CanisterError(
            f"Canister unreachable after {self._config.max_retries} attempts. "
            f"Entry saved locally at {self._spill_path} for later retry.\n"
            "What to do next:\n"
            "  1. Check your internet connection\n"
            "  2. Run 'aegis status' to verify canister availability\n"
            "  3. Run 'aegis spill-status' to see pending entries\n"
            "  4. Entries will auto-retry on next SDK call",
            error_code="TRANSPORT_EXHAUSTED",
        )

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
        spill_dir.mkdir(parents=True, exist_ok=True)
        # S-H2: symlink check — refuse to write if directory is a symlink (TOCTOU mitigation)
        if spill_dir.is_symlink():
            raise OSError(
                f"Spill directory {spill_dir} is a symlink — refusing to write for security"
            )
        spill_dir.chmod(0o700)  # owner-only directory

        # Enforce spill buffer size limit — discard oldest entries if full
        trimmed = False
        if self._spill_path.exists():
            existing = self._spill_path.read_text().strip().split("\n")
            existing = [line for line in existing if line]
            if len(existing) >= _MAX_SPILL_ENTRIES:
                discard_count = len(existing) - _MAX_SPILL_ENTRIES + 1
                logger.warning(
                    "Spill buffer full (%d entries). Discarding %d oldest entries.",
                    len(existing),
                    discard_count,
                )
                existing = existing[discard_count:]
                self._spill_path.write_text("\n".join(existing) + "\n")
                trimmed = True

        # H-3 FIX: Extract raw values from Candid args so they survive
        # JSON serialization. ic-py Types objects are NOT JSON-serializable,
        # so json.dumps(default=str) corrupts them irreversibly.
        raw_values = [arg["value"] for arg in args]
        entry = {
            "method": method,
            "raw_values": raw_values,
            "timestamp_ms": int(time.time() * 1000),
            "canister_id": self._config.canister_id,
            "spill_version": 2,
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

    def drain_spill_buffer(self) -> int:
        """
        Retry all spilled entries. Returns count of successfully drained entries.

        Called automatically on each successful log_action to clear the backlog.
        Entries that fail again remain in the spill file.
        """
        if not self._spill_path.exists():
            return 0

        lines = self._spill_path.read_text().strip().split("\n")
        if not lines or lines == [""]:
            return 0

        failed: list[str] = []
        drained = 0

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

                # H-3 FIX: Rebuild Candid args from stored raw values
                if entry.get("spill_version") == 2:
                    v = entry["raw_values"]
                    # v[5] is the variant dict, e.g. {"toolCall": null}
                    variant_dict = v[5]
                    action_type_str = _REVERSE_ACTION_TYPE_MAP[next(iter(variant_dict))]
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
            except Exception:  # noqa: BLE001 — fail-open spill replay
                logger.warning("Spill replay failed for entry", exc_info=True)
                failed.append(line)

        # Rewrite spill file with only the still-failed entries
        if failed:
            self._spill_path.write_text("\n".join(failed) + "\n")
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
