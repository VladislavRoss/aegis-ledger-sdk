"""
aegis.client — The primary interface for the Aegis Ledger SDK.

Usage (after ``aegis init``)::

    from aegis import AegisClient

    client = AegisClient.from_config()

    client.log_tool_call(
        tool="stripe.create_charge",
        input_data={"amount": 5000, "currency": "usd"},
        output_data={"id": "ch_xxx", "status": "succeeded"},
        duration_ms=340,
    )

    @client.trace(action_type="tool_call")
    def search_web(query: str) -> dict:
        return requests.get(f"https://api.search.com?q={query}").json()
"""

from __future__ import annotations

import contextlib
import functools
import inspect
import logging
import sys
import threading
import time
import uuid
from collections.abc import Callable, Generator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from pathlib import Path

from aegis import __version__  # single source of truth in __init__.py
from aegis.canister_ops import CanisterOpsMixin
from aegis.config import get_client_config, get_default_scheme, get_signing_key_path, load_config
from aegis.crypto import (
    canonical_json,
    compute_chain_hash,
    create_scheme,
    extract_otel_context,
    load_mldsa65_private_key,
    load_private_key,
    load_slhdsa128s_private_key,
    redact_pii_data,
    sha256_json,
    truncate_preview,
)
from aegis.errors import translate_error
from aegis.transport import (
    CanisterTransport,
    TransportConfig,
    _build_add_ledger_entry_v2_args,
)
from aegis.types import (
    ActionContext,
    ActionPayload,
    ActionStatus,
    ActionType,
    Environment,
    LogEntry,
)

logger = logging.getLogger("aegis")

F = TypeVar("F", bound=Callable[..., Any])


class AegisClient(CanisterOpsMixin):
    """
    Client for logging AI agent actions to the Aegis Ledger.

    Thread-safe. One client instance per agent process. The client
    maintains a monotonic sequence counter per session and handles
    key loading, payload construction, signing, and transport.
    """

    def __init__(
        self,
        canister_id: str,
        api_key_id: str,
        private_key_path: str | Path,
        agent_id: str,
        org_id: str = "aaaaa-aa",
        session_id: str | None = None,
        environment: Environment | None = None,
        network: str = "https://icp-api.io",
        fail_open: bool = True,
        redact_pii: bool = True,
        signature_scheme: str | None = None,
        signing_key_path: str | Path | None = None,
        metadata: dict[str, str] | None = None,
    ):
        """Initialize the Aegis client for logging AI agent actions."""
        # --- Input validation ---
        if not canister_id or not canister_id.strip():
            raise ValueError("canister_id must not be empty")
        if not api_key_id or not api_key_id.strip():
            raise ValueError("api_key_id must not be empty")
        if not agent_id or not agent_id.strip():
            raise ValueError("agent_id must not be empty")
        if metadata:
            for k, v in metadata.items():
                if not isinstance(v, str):
                    raise TypeError(
                        f"metadata values must be str, got {type(v).__name__} for key {k!r}"
                    )
        self._canister_id = canister_id
        self._api_key_id = api_key_id
        self._agent_id = agent_id
        self._org_id = org_id
        self._session_id = session_id or agent_id or f"agent_{uuid.uuid4().hex[:8]}"
        self._sequence: int = 0
        self._lock = threading.Lock()
        self._fail_open = fail_open
        self._redact_pii = redact_pii
        self._default_metadata = metadata or {}
        # Resolve signature_scheme from config if not explicit
        if signature_scheme is None:
            _cfg = load_config()
            signature_scheme = get_default_scheme(_cfg)
            if signing_key_path is None and signature_scheme in (
                "hybrid", "ml-dsa-65", "ml-dsa-87", "slh-dsa-128s",
            ):
                signing_key_path = get_signing_key_path(_cfg)
        # Always load Ed25519 PEM for ICP transport + org_id derivation
        self._private_key = load_private_key(private_key_path)
        # Load the signing scheme
        if signature_scheme == "hybrid":
            if signing_key_path is None:
                raise ValueError("signing_key_path is required when signature_scheme='hybrid'")
            sk_bytes = load_mldsa65_private_key(signing_key_path)
            self._scheme = create_scheme(signature_scheme, (self._private_key, sk_bytes))
        elif signature_scheme == "ml-dsa-65":
            if signing_key_path is None:
                raise ValueError("signing_key_path is required when signature_scheme='ml-dsa-65'")
            sk_bytes = load_mldsa65_private_key(signing_key_path)
            self._scheme = create_scheme(signature_scheme, sk_bytes)
        elif signature_scheme == "ml-dsa-87":
            if signing_key_path is None:
                raise ValueError("signing_key_path is required when signature_scheme='ml-dsa-87'")
            from aegis.crypto import load_mldsa87_private_key
            sk_bytes = load_mldsa87_private_key(signing_key_path)
            self._scheme = create_scheme(signature_scheme, sk_bytes)
        elif signature_scheme == "slh-dsa-128s":
            if signing_key_path is None:
                raise ValueError(
                    "signing_key_path required for slh-dsa-128s"
                )
            sk_bytes = load_slhdsa128s_private_key(signing_key_path)
            self._scheme = create_scheme(signature_scheme, sk_bytes)
        else:
            self._scheme = create_scheme(signature_scheme, self._private_key)
        # Auto-detect environment if not provided
        self._environment = environment or self._detect_environment()
        # Initialize transport
        transport_config = TransportConfig(
            canister_id=canister_id, network=network, private_key_path=private_key_path,
        )
        self._transport = CanisterTransport(transport_config)
        # Auto-derive org_id from loaded key if caller left the default "aaaaa-aa"
        if self._org_id == "aaaaa-aa":
            self._org_id = self._derive_org_id()
        self._action_stack: list[str] = []  # parent-child tracking
        self._chain_heads: dict[str, str] = {}  # session_id → last chainHash
        # Agent-centric: sync sequence from canister if reusing existing session
        self._sync_sequence_from_canister()
        logger.info(
            "Aegis client initialized: agent=%s session=%s canister=%s seq=%d",
            self._agent_id,
            self._session_id,
            self._canister_id,
            self._sequence,
        )

    def _sync_sequence_from_canister(self) -> None:
        """Query canister for latest sequence head — agent-centric session reuse."""
        try:
            from ic.candid import Types
            raw = self._transport.call_query(
                "getSessionSequenceHead",
                [{"type": Types.Text, "value": self._session_id}],
            )
            if not isinstance(raw, dict):
                return
            seq_head = raw.get("sequenceHead")
            chain_hash = raw.get("chainHash")
            if seq_head is None and chain_hash is None:
                for v in raw.values():
                    if isinstance(v, list) and v and isinstance(v[0], (int, float)):
                        seq_head = v[0]
                    elif isinstance(v, str) and len(v) == 64:
                        chain_hash = v
            if isinstance(seq_head, list) and seq_head:
                seq_head = seq_head[0]
            has_entries = isinstance(chain_hash, str) and len(chain_hash) == 64
            if isinstance(seq_head, (int, float)) and (int(seq_head) > 0 or has_entries):
                self._sequence = int(seq_head) + 1
            if has_entries:
                self._chain_heads[self._session_id] = chain_hash
        except Exception:
            pass

    # -- Factory: zero-config construction from ~/.aegis/config.toml ----

    @classmethod
    def from_config(
        cls,
        *,
        agent_id: str | None = None,
        session_id: str | None = None,
        config_path: str | Path | None = None,
        **overrides: Any,
    ) -> AegisClient:
        """Create AegisClient from ``~/.aegis/config.toml`` (after ``aegis init``)."""
        from pathlib import Path as _Path

        cfg_path = _Path(config_path) if config_path else None
        cfg = load_config(config_path=cfg_path)
        if not cfg:
            default_path = _Path("~/.aegis/config.toml").expanduser()
            raise FileNotFoundError(
                f"No config found at {cfg_path or default_path}. "
                "Run 'aegis init' to set up your configuration."
            )

        client_cfg = get_client_config(cfg)
        required = ("canister_id", "api_key_id", "private_key_path")
        missing = [k for k in required if k not in client_cfg and k not in overrides]
        if missing:
            raise ValueError(
                f"Missing required config fields: {', '.join(missing)}. "
                "Run 'aegis init' to configure them."
            )

        # Build constructor kwargs: config < overrides
        kwargs: dict[str, Any] = {}
        kwargs["canister_id"] = overrides.pop("canister_id", client_cfg.get("canister_id", ""))
        kwargs["api_key_id"] = overrides.pop("api_key_id", client_cfg.get("api_key_id", ""))
        kwargs["private_key_path"] = overrides.pop(
            "private_key_path", client_cfg.get("private_key_path", "")
        )
        kwargs["agent_id"] = agent_id or overrides.pop(
            "agent_id", client_cfg.get("agent_id", "agent")
        )
        cfg_org_id = client_cfg.get("org_id", "")
        if cfg_org_id:
            kwargs["org_id"] = overrides.pop("org_id", cfg_org_id)
        if session_id:
            kwargs["session_id"] = session_id
        kwargs.update(overrides)

        return cls(**kwargs)

    # ------------------------------------------------------------------
    # PUBLIC API: Explicit logging methods
    # ------------------------------------------------------------------

    def log_tool_call(
        self,
        tool: str,
        input_data: Any,
        output_data: Any,
        duration_ms: int,
        status: ActionStatus = ActionStatus.SUCCESS,
        reasoning: str = "",
        confidence: float = 0.0,
        metadata: dict[str, str] | None = None,
    ) -> str:
        """
        Log a tool/API call made by the agent.

        Returns the action_id assigned by the canister.
        """
        return self._log(
            action_type=ActionType.TOOL_CALL,
            tool=tool,
            input_data=input_data,
            output_data=output_data,
            duration_ms=duration_ms,
            status=status,
            reasoning=reasoning,
            confidence=confidence,
            metadata=metadata,
        )

    def log_decision(
        self,
        reasoning: str,
        confidence: float,
        input_data: Any = None,
        output_data: Any = None,
        duration_ms: int = 0,
        metadata: dict[str, str] | None = None,
    ) -> str:
        """Log a decision/reasoning step by the agent."""
        return self._log(
            action_type=ActionType.DECISION,
            tool="",
            input_data=input_data or {},
            output_data=output_data or {},
            duration_ms=duration_ms,
            status=ActionStatus.SUCCESS,
            reasoning=reasoning,
            confidence=confidence,
            metadata=metadata,
        )

    def log_observation(
        self,
        input_data: Any,
        output_data: Any = None,
        duration_ms: int = 0,
        metadata: dict[str, str] | None = None,
    ) -> str:
        """Log an observation received by the agent (e.g., sensor data, API response)."""
        return self._log(
            action_type=ActionType.OBSERVATION,
            tool="",
            input_data=input_data,
            output_data=output_data or {},
            duration_ms=duration_ms,
            status=ActionStatus.SUCCESS,
            reasoning="",
            confidence=0.0,
            metadata=metadata,
        )

    def log_error(
        self,
        tool: str,
        input_data: Any,
        error: Exception | str,
        duration_ms: int = 0,
        metadata: dict[str, str] | None = None,
    ) -> str:
        """Log an error encountered during agent execution."""
        error_output = {
            "error_type": type(error).__name__ if isinstance(error, Exception) else "Error",
            "error_message": str(error),
        }
        return self._log(
            action_type=ActionType.ERROR,
            tool=tool,
            input_data=input_data,
            output_data=error_output,
            duration_ms=duration_ms,
            status=ActionStatus.ERROR,
            reasoning="",
            confidence=0.0,
            metadata=metadata,
        )

    def log_human_override(
        self,
        override_reason: str,
        input_data: Any = None,
        output_data: Any = None,
        duration_ms: int = 0,
        metadata: dict[str, str] | None = None,
    ) -> str:
        """Log a human override of an agent decision."""
        return self._log(
            action_type=ActionType.HUMAN_OVERRIDE,
            tool="",
            input_data=input_data or {},
            output_data=output_data or {},
            duration_ms=duration_ms,
            status=ActionStatus.SUCCESS,
            reasoning=override_reason,
            confidence=0.0,
            metadata=metadata,
        )

    def attest_human_review(
        self,
        action_id: str,
        decision: str,
        reasoning: str = "",
    ) -> dict:
        """Attest a human review of an agent action (EU AI Act Art. 14).

        Args:
            action_id: The action_id of the entry being reviewed.
            decision: One of "approved", "rejected", "escalated".
            reasoning: Free-text explanation (max 2048 chars).

        Returns:
            The attestation record from the canister.
        """
        if decision not in ("approved", "rejected", "escalated"):
            raise ValueError(
                f"Invalid decision {decision!r}. Must be: approved, rejected, escalated"
            )
        try:
            from ic.candid import Types  # type: ignore[import-untyped]
        except ImportError as e:
            raise ImportError("ic-py required for attest_human_review") from e

        args = [
            {"type": Types.Text, "value": action_id},
            {"type": Types.Text, "value": decision},
            {"type": Types.Text, "value": reasoning[:2048]},
        ]
        return self._transport.call_update("attestHumanReview", args)

    def get_session_completeness(self, session_id: str) -> dict:
        """Get analytics for a session (error rate, duration, action type distribution)."""
        try:
            from ic.candid import Types  # type: ignore[import-untyped]
        except ImportError as e:
            raise ImportError("ic-py required for get_session_completeness") from e
        args = [{"type": Types.Text, "value": session_id}]
        return self._transport.call_query("getSessionCompleteness", args)

    def get_org_stats(self) -> dict:
        """Get aggregated org statistics (entries, sessions, monthly count, top agents)."""
        return self._transport.call_query("getOrgStats", [])


    # ------------------------------------------------------------------
    # PUBLIC API: The @trace decorator
    # ------------------------------------------------------------------

    def trace(
        self,
        action_type: str | ActionType = ActionType.TOOL_CALL,
        tool_name: str | None = None,
        capture_output: bool = True,
        metadata: dict[str, str] | None = None,
    ) -> Callable[[F], F]:
        """
        Decorator that automatically logs function execution to Aegis.

        Usage:
            @client.trace()
            def search_database(query: str) -> list[dict]:
                return db.search(query)

            @client.trace(action_type="decision", tool_name="route_selector")
            def pick_next_action(state: dict) -> str:
                return "search" if state["needs_data"] else "respond"

        The decorator:
          1. Captures all function arguments as the input payload.
          2. Captures the return value as the output payload.
          3. Measures wall-clock execution time.
          4. Catches and re-raises exceptions (logging them as errors).
          5. Maintains parent-child relationships when traced functions
             call other traced functions.

        Args:
            action_type: The action type category. String or ActionType enum.
            tool_name: Override the tool name. Defaults to the function's
                       qualified name.
            capture_output: If False, output is logged as {} (useful for
                           functions returning sensitive data).
            metadata: Additional metadata for this specific trace.
        """
        if isinstance(action_type, str):
            action_type = ActionType(action_type)

        def decorator(func: F) -> F:
            resolved_tool = tool_name or func.__qualname__

            def _build_input(func_: Any, args: Any, kwargs: Any) -> dict[str, Any]:
                sig = inspect.signature(func_)
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                return dict(bound.arguments)

            def _log_success(
                input_data: dict[str, Any], result: Any, elapsed: int,
            ) -> None:
                output_data = result if capture_output else {}
                self._log(
                    action_type=action_type,
                    tool=resolved_tool,
                    input_data=input_data,
                    output_data=output_data,
                    duration_ms=elapsed,
                    status=ActionStatus.SUCCESS,
                    reasoning="",
                    confidence=0.0,
                    metadata=metadata,
                )

            def _log_failure(
                input_data: dict[str, Any], error: Exception, elapsed: int,
            ) -> None:
                self.log_error(
                    tool=resolved_tool,
                    input_data=input_data,
                    error=error,
                    duration_ms=elapsed,
                    metadata=metadata,
                )

            if inspect.iscoroutinefunction(func):
                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    input_data = _build_input(func, args, kwargs)
                    start_ms = int(time.time() * 1000)
                    try:
                        result = await func(*args, **kwargs)
                        _log_success(input_data, result, int(time.time() * 1000) - start_ms)
                        return result
                    except Exception as e:
                        _log_failure(input_data, e, int(time.time() * 1000) - start_ms)
                        raise

                return async_wrapper  # type: ignore[return-value]

            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                input_data = _build_input(func, args, kwargs)
                start_ms = int(time.time() * 1000)
                try:
                    result = func(*args, **kwargs)
                    _log_success(input_data, result, int(time.time() * 1000) - start_ms)
                    return result
                except Exception as e:
                    _log_failure(input_data, e, int(time.time() * 1000) - start_ms)
                    raise  # Always re-raise — we observe, never interfere

            return wrapper  # type: ignore[return-value]

        return decorator

    # ------------------------------------------------------------------
    # PUBLIC API: Context manager for parent-child grouping
    # ------------------------------------------------------------------

    @contextmanager
    def span(
        self,
        name: str,
        action_type: ActionType = ActionType.DECISION,
        reasoning: str = "",
        metadata: dict[str, str] | None = None,
    ) -> Generator[str, None, None]:
        """
        Context manager that groups nested actions under a parent.

        Usage:
            with client.span("process_order", reasoning="Customer checkout flow") as span_id:
                client.log_tool_call("inventory.check", ...)
                client.log_tool_call("payment.charge", ...)
                # Both calls have parent_action_id = span_id

        Yields the action_id of the span's own log entry.
        """
        action_id = self.log_decision(
            reasoning=reasoning or f"Entering span: {name}",
            confidence=1.0,
            input_data={"span_name": name},
            metadata=metadata,
        )

        with self._lock:
            self._action_stack.append(action_id)
        try:
            yield action_id
        finally:
            with self._lock:
                self._action_stack.pop()

    # ------------------------------------------------------------------
    # PUBLIC API: Session and state management
    # ------------------------------------------------------------------

    def new_session(self, session_id: str | None = None) -> str:
        """
        Start a new session, resetting the sequence counter.

        Returns the new session_id.
        """
        with self._lock:
            old_session_id = self._session_id
            prefix = self._agent_id or "agent"
            self._session_id = session_id or f"{prefix}_{uuid.uuid4().hex[:8]}"
            self._sequence = 0
            self._action_stack.clear()
            # Clean up chain state from the OLD session
            self._chain_heads.pop(old_session_id, None)
        logger.info("New session started: %s", self._session_id)
        return self._session_id

    @property
    def session_id(self) -> str:
        """Current session ID."""
        return self._session_id

    @property
    def sequence_number(self) -> int:
        """Current sequence number (next entry will use this value)."""
        return self._sequence

    @property
    def pending_spill_count(self) -> int:
        """Number of entries in the local spill buffer awaiting retry."""
        return self._transport.spill_count

    def flush(self) -> int:
        """Manually drain the spill buffer. Returns count of drained entries."""
        return self._transport.drain_spill_buffer()

    def log_batch(self, entries: list[dict[str, Any]]) -> list[str]:
        """
        Log multiple entries sequentially, returning a list of action_ids.

        Each entry dict should contain keyword arguments matching _log:
        action_type, tool, input_data, output_data, duration_ms, status,
        reasoning, confidence, metadata.

        Entries are logged atomically one-by-one (each acquires the lock),
        guaranteeing monotonic sequence numbers and correct hash-chaining.
        """
        valid_action_types = {e.value for e in ActionType}
        valid_statuses = {e.value for e in ActionStatus}
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise TypeError(f"log_batch entry[{i}] must be a dict, got {type(entry).__name__}")
            at = entry.get("action_type", "tool_call")
            if at not in valid_action_types:
                raise ValueError(
                    f"log_batch entry[{i}]: invalid action_type {at!r}. "
                    f"Valid: {', '.join(sorted(valid_action_types))}"
                )
            st = entry.get("status", "success")
            if st not in valid_statuses:
                raise ValueError(
                    f"log_batch entry[{i}]: invalid status {st!r}. "
                    f"Valid: {', '.join(sorted(valid_statuses))}"
                )

        results: list[str] = []
        for entry in entries:
            action_id = self._log(
                action_type=ActionType(entry.get("action_type", "tool_call")),
                tool=entry.get("tool", "batch"),
                input_data=entry.get("input_data", {}),
                output_data=entry.get("output_data", {}),
                duration_ms=entry.get("duration_ms", 0),
                status=ActionStatus(entry.get("status", "success")),
                reasoning=entry.get("reasoning", ""),
                confidence=entry.get("confidence", 0.0),
                metadata=entry.get("metadata"),
            )
            results.append(action_id)
        return results

    # Self-service + KYA methods → canister_ops.py (CanisterOpsMixin)

    def close(self) -> None:
        """Drain spill buffer and release resources."""
        with contextlib.suppress(Exception):
            self._transport.drain_spill_buffer()
        logger.info("Aegis client closed: agent=%s session=%s", self._agent_id, self._session_id)

    def __enter__(self) -> AegisClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # INTERNAL: Core logging implementation
    # ------------------------------------------------------------------

    def _prepare_entry(
        self,
        action_type: ActionType,
        tool: str,
        input_data: Any,
        output_data: Any,
        duration_ms: int,
        status: ActionStatus,
        reasoning: str,
        confidence: float,
        merged_metadata: dict[str, str],
        now_ms: int,
        parent_id: str,
    ) -> LogEntry:
        """Build a LogEntry from validated, PII-redacted inputs (called inside lock)."""
        otel_trace_id, otel_span_id, otel_parent_span_id = extract_otel_context()
        return LogEntry(
            agent_id=self._agent_id,
            session_id=self._session_id,
            sequence_number=self._sequence,
            action=ActionPayload(
                type=action_type,
                tool=tool,
                input_hash=sha256_json(input_data),
                output_hash=sha256_json(output_data),
                input_preview=truncate_preview(input_data),
                output_preview=truncate_preview(output_data),
                duration_ms=duration_ms,
                status=status,
            ),
            context=ActionContext(
                parent_action_id=parent_id,
                decision_reasoning=reasoning,
                confidence_score=confidence,
            ),
            environment=self._environment,
            metadata=merged_metadata,
            client_timestamp_ms=now_ms,
            sdk_version=__version__,
            api_key_id=self._api_key_id,
            otel_trace_id=otel_trace_id,
            otel_span_id=otel_span_id,
            otel_parent_span_id=otel_parent_span_id,
        )

    def _build_candid_args(
        self,
        entry: LogEntry,
        chain_hash: str,
        previous_chain_hash: str,
        action_id: str,
        payload_bytes: bytes,
    ) -> list[Any]:
        """Build a single Candid Record argument for addLedgerEntryV2."""
        metadata_json = ""
        if entry.metadata:
            import json as _json
            metadata_json = _json.dumps(entry.metadata, sort_keys=True)
        return _build_add_ledger_entry_v2_args(
            action_id=action_id,
            org_id=self._org_id,
            agent_id=entry.agent_id,
            session_id=entry.session_id,
            sequence_number=entry.sequence_number,
            action_type=entry.action.type.value,
            tool=entry.action.tool,
            input_hash=entry.action.input_hash,
            output_hash=entry.action.output_hash,
            input_preview="",
            output_preview="",
            duration_ms=entry.action.duration_ms,
            status=entry.action.status.value,
            parent_action_id=entry.context.parent_action_id,
            decision_reasoning=entry.context.decision_reasoning,
            confidence_score=entry.context.confidence_score,
            framework=entry.environment.framework,
            model_id=entry.environment.model_id,
            client_timestamp_ms=entry.client_timestamp_ms,
            payload_signature=entry.payload_signature,
            chain_hash=chain_hash,
            previous_chain_hash=previous_chain_hash,
            payload_hex=payload_bytes.hex(),
            key_id=self._api_key_id,
            metadata=metadata_json,
            sdk_version=entry.sdk_version,
            otel_trace_id=entry.otel_trace_id,
            otel_span_id=entry.otel_span_id,
            otel_parent_span_id=entry.otel_parent_span_id,
            cost_usd=entry.cost_usd,
            token_count=entry.token_count,
        )

    def _log(
        self,
        action_type: ActionType,
        tool: str,
        input_data: Any,
        output_data: Any,
        duration_ms: int,
        status: ActionStatus,
        reasoning: str,
        confidence: float,
        metadata: dict[str, str] | None,
    ) -> str:
        """
        Internal method that constructs, signs, and submits a log entry.

        This is the ONLY path through which entries reach the canister.
        """
        # Coerce string status to ActionStatus enum (common user mistake)
        if isinstance(status, str):
            try:
                status = ActionStatus(status)
            except ValueError:
                valid = ', '.join(s.value for s in ActionStatus)
                raise ValueError(
                    f"Invalid status {status!r}. Valid values: {valid}"
                ) from None

        if duration_ms < 0:
            raise ValueError(f"duration_ms must be >= 0, got {duration_ms}")
        if not (0.0 <= confidence <= 1.0):
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {confidence}")

        now_ms = int(time.time() * 1000)

        # Merge metadata
        merged_metadata = {**self._default_metadata}
        if metadata:
            merged_metadata.update(metadata)

        # C-1 FIX: Apply PII redaction before hashing (DPA Art. 28 compliance)
        if self._redact_pii:
            input_data = redact_pii_data(input_data)
            output_data = redact_pii_data(output_data)
            if reasoning:
                reasoning = str(redact_pii_data(reasoning))

        # C4: Lock um den gesamten kritischen Bereich
        # (sequence read → sign → hash-chain → submit → increment)
        should_drain = False
        with self._lock:
            parent_id = self._action_stack[-1] if self._action_stack else ""

            entry = self._prepare_entry(
                action_type, tool, input_data, output_data, duration_ms,
                status, reasoning, confidence, merged_metadata, now_ms, parent_id,
            )

            # Sign the payload
            signable = entry.to_signable_dict()
            payload_bytes = canonical_json(signable)
            entry.payload_signature = self._scheme.sign(payload_bytes)

            # SHA-256 Hash-Chain
            previous_chain_hash = self._chain_heads.get(entry.session_id, "")
            chain_hash = compute_chain_hash(previous_chain_hash, payload_bytes)
            local_action_id = f"act_{uuid.uuid4().hex[:16]}"

            candid_args = self._build_candid_args(
                entry, chain_hash, previous_chain_hash, local_action_id, payload_bytes,
            )

            try:
                result = self._transport.call_update("addLedgerEntryV2", candid_args)
                action_id = (
                    result.get("actionId")
                    or result.get("_3776271665")
                    or f"local_{uuid.uuid4().hex[:8]}"
                )

                self._chain_heads[entry.session_id] = chain_hash
                self._sequence += 1
                should_drain = self._transport.spill_count > 0

                self._write_snapshot(action_id, chain_hash, entry.session_id, now_ms)

                logger.debug(
                    "Logged action: seq=%d type=%s tool=%s → %s",
                    entry.sequence_number, action_type.value, tool, action_id,
                )

            except Exception as e:
                # Auto-recovery: re-sync sequence on conflict and retry once
                if "Sequence number must be strictly increasing" in str(e):
                    self._sync_sequence_from_canister()
                    entry.sequence_number = self._sequence
                    candid_args = self._build_candid_args(
                        entry, chain_hash, previous_chain_hash, local_action_id, payload_bytes,
                    )
                    try:
                        result = self._transport.call_update("addLedgerEntryV2", candid_args)
                        action_id = (
                            result.get("actionId") or result.get("_3776271665") or local_action_id
                        )
                        self._chain_heads[entry.session_id] = chain_hash
                        self._sequence += 1
                        self._write_snapshot(action_id, chain_hash, entry.session_id, now_ms)
                        return action_id
                    except Exception:
                        pass  # Fall through to spill
                if self._fail_open:
                    translated = translate_error(str(e), key_id=self._api_key_id)
                    logger.warning("Failed to log action (fail_open=True): %s", translated)
                    return f"spilled_{uuid.uuid4().hex[:8]}"
                raise

        # H-2 FIX: Drain spill buffer OUTSIDE the lock
        if should_drain:
            with contextlib.suppress(Exception):
                self._transport.drain_spill_buffer()

        return action_id

    # ------------------------------------------------------------------
    # Integrity Snapshot — delegated to integrity.py
    # ------------------------------------------------------------------

    @property
    def _snapshot_path(self) -> Path:
        from .integrity import snapshot_path
        return snapshot_path(self._transport._config.spill_dir, self._canister_id)

    def _write_snapshot(
        self, action_id: str, chain_hash: str, session_id: str, ts_ms: int,
    ) -> None:
        from .integrity import write_snapshot
        write_snapshot(self._snapshot_path, action_id, chain_hash, session_id, ts_ms)

    def verify_integrity(self, sample_size: int = 10) -> dict:
        """Verify canister entries against locally stored chain-hash snapshots."""
        from .integrity import verify_integrity
        return verify_integrity(self._snapshot_path, self._transport, sample_size)

    # ------------------------------------------------------------------
    # INTERNAL: Environment auto-detection
    # ------------------------------------------------------------------

    def _derive_org_id(self) -> str:
        """Derive ICP principal from Ed25519 key. Fallback: 'aaaaa-aa'."""
        try:
            from cryptography.hazmat.primitives.serialization import (
                Encoding as _Enc,
            )
            from cryptography.hazmat.primitives.serialization import (
                NoEncryption as _NoEnc,
            )
            from cryptography.hazmat.primitives.serialization import (
                PrivateFormat as _PF,  # noqa: N814
            )
            from ic.identity import Identity  # type: ignore[import-untyped]

            pem_bytes = self._private_key.private_bytes(_Enc.PEM, _PF.PKCS8, _NoEnc())
            identity = Identity.from_pem(pem_bytes.decode("ascii"))
            derived = str(identity.sender())
            logger.info("Derived org_id from PEM key: %s", derived)
            return derived
        except (ImportError, ValueError, AttributeError, TypeError) as exc:
            logger.warning("Could not derive org_id from PEM (%s) — using 'aaaaa-aa'", exc)
            return "aaaaa-aa"

    @staticmethod
    def _detect_environment() -> Environment:
        """Auto-detect runtime environment by sniffing installed packages."""
        frameworks: list[str] = []
        versions: list[str] = []
        model_provider = ""
        model_id = ""

        for mod_name, fw_name in [
            ("langchain", "langchain"), ("crewai", "crewai"),
            ("autogen", "autogen"), ("openai", "openai_agents"),
            ("claude_agent_sdk", "anthropic_sdk"),
        ]:
            try:
                mod = __import__(mod_name)
                frameworks.append(fw_name)
                versions.append(getattr(mod, "__version__", "unknown"))
            except ImportError:
                pass
        framework = "+".join(frameworks) if frameworks else "unknown"
        framework_version = "+".join(versions) if versions else "0.0.0"
        runtime = f"python{sys.version_info.major}.{sys.version_info.minor}"
        return Environment(
            framework=framework,
            framework_version=framework_version,
            model_provider=model_provider,
            model_id=model_id,
            runtime=runtime,
        )
