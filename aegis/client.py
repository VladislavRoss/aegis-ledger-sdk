"""
aegis.client — The primary interface for the Aegis Ledger SDK.

Usage:
    from aegis import AegisClient

    client = AegisClient(
        canister_id="toqqq-lqaaa-aaaae-afc2a-cai",
        api_key_id="ak_3f8a9b2c1d4e5f60",
        private_key_path="./agent_key.pem",
        agent_id="agent_billing_v2",
        org_id="your-org-principal-id",
    )

    # Option 1: Explicit logging
    client.log_tool_call(
        tool="stripe.create_charge",
        input_data={"amount": 5000, "currency": "usd"},
        output_data={"id": "ch_xxx", "status": "succeeded"},
        duration_ms=340,
    )

    # Option 2: Decorator (zero-effort integration)
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
from pathlib import Path
from typing import Any, TypeVar

from aegis.crypto import (
    canonical_json,
    compute_chain_hash,
    load_private_key,
    sha256_json,
    sign_payload,
    truncate_preview,
)
from aegis.transport import CanisterTransport, TransportConfig, _build_add_ledger_entry_args
from aegis.types import (
    ActionContext,
    ActionPayload,
    ActionStatus,
    ActionType,
    Environment,
    LogEntry,
)

logger = logging.getLogger("aegis")

__version__ = "0.1.0"

F = TypeVar("F", bound=Callable[..., Any])


class AegisClient:
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
        metadata: dict[str, str] | None = None,
    ):
        """
        Initialize the Aegis client.

        Args:
            canister_id: The ICP canister ID hosting the Aegis ledger.
            api_key_id: The API key ID obtained from the Aegis dashboard.
            private_key_path: Path to the Ed25519 PEM private key file.
            agent_id: Unique identifier for this agent (must match the
                      prefix registered with the API key).
            org_id: The ICP Principal of the organisation owning this key.
                    Defaults to the anonymous principal ("aaaaa-aa").
            session_id: Optional session ID. Auto-generated if not provided.
                        Use a stable session_id to group related actions
                        into a single trace.
            environment: Runtime environment metadata. Auto-detected if
                         not provided.
            network: ICP network URL. Defaults to mainnet.
            fail_open: If True, agent execution continues even if logging
                       fails (entries spill to disk). If False, logging
                       failures raise exceptions. Default True because
                       agent execution should never be blocked by
                       observability infrastructure.
            metadata: Default metadata attached to every log entry. Can be
                      overridden per-call.
        """
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
        self._session_id = session_id or f"sess_{uuid.uuid4().hex[:16]}"
        self._sequence: int = 0
        self._lock = threading.Lock()
        self._fail_open = fail_open
        self._default_metadata = metadata or {}

        # Load the signing key
        self._private_key = load_private_key(private_key_path)

        # Auto-detect environment if not provided
        self._environment = environment or self._detect_environment()

        # Initialize transport — pass PEM key so IC identity matches org_id
        transport_config = TransportConfig(
            canister_id=canister_id,
            network=network,
            private_key_path=private_key_path,
        )
        self._transport = CanisterTransport(transport_config)

        # Auto-derive org_id from loaded key if caller left the default "aaaaa-aa"
        if self._org_id == "aaaaa-aa":
            self._org_id = self._derive_org_id()

        # Action ID stack for parent-child tracking
        self._action_stack: list[str] = []

        # SHA-256 Hash-Chain state: session_id → last chainHash
        self._chain_heads: dict[str, str] = {}

        logger.info(
            "Aegis client initialized: agent=%s session=%s canister=%s",
            self._agent_id,
            self._session_id,
            self._canister_id,
        )

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
            self._session_id = session_id or f"sess_{uuid.uuid4().hex[:16]}"
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

    def close(self) -> None:
        """Drain spill buffer and release resources."""
        with contextlib.suppress(Exception):
            self._transport.drain_spill_buffer()
        logger.info("Aegis client closed: agent=%s session=%s", self._agent_id, self._session_id)

    def __enter__(self) -> "AegisClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # INTERNAL: Core logging implementation
    # ------------------------------------------------------------------

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
        if duration_ms < 0:
            raise ValueError(f"duration_ms must be >= 0, got {duration_ms}")
        if not (0.0 <= confidence <= 1.0):
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {confidence}")

        now_ms = int(time.time() * 1000)

        # Merge metadata
        merged_metadata = {**self._default_metadata}
        if metadata:
            merged_metadata.update(metadata)

        # C4: Lock um den gesamten kritischen Bereich
        # (sequence read → sign → hash-chain → submit → increment)
        with self._lock:
            # Determine parent from the action stack (inside lock for thread safety)
            parent_id = self._action_stack[-1] if self._action_stack else ""
            # Build the entry
            entry = LogEntry(
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
            )

            # Sign the payload
            signable = entry.to_signable_dict()
            payload_bytes = canonical_json(signable)
            entry.payload_signature = sign_payload(payload_bytes, self._private_key)

            # SHA-256 Hash-Chain: berechne chain_hash aus vorherigem + aktuellem Payload
            previous_chain_hash = self._chain_heads.get(entry.session_id, "")
            chain_hash = compute_chain_hash(previous_chain_hash, payload_bytes)

            # Lokale action_id generieren (Canister gibt ggf. eine andere zurück)
            local_action_id = f"act_{uuid.uuid4().hex[:16]}"

            # 24 Candid-Positionalargumente für addLedgerEntry bauen
            candid_args = _build_add_ledger_entry_args(
                action_id=local_action_id,
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
                decision_reasoning="",
                confidence_score=entry.context.confidence_score,
                framework=entry.environment.framework,
                model_id=entry.environment.model_id,
                client_timestamp_ms=entry.client_timestamp_ms,
                payload_signature=entry.payload_signature,
                chain_hash=chain_hash,
                previous_chain_hash=previous_chain_hash,
                payload_hex=payload_bytes.hex(),
                key_id=self._api_key_id,
            )

            try:
                result = self._transport.call_update("addLedgerEntry", candid_args)
                # ic-py decodes Candid record fields as hash-keyed dicts ("_<hash>").
                # Candid hash of "actionId" = 3776271665.
                action_id = (
                    result.get("actionId")
                    or result.get("_3776271665")
                    or f"local_{uuid.uuid4().hex[:8]}"
                )

                # Chain-Head nach erfolgreichem Canister-Call updaten
                self._chain_heads[entry.session_id] = chain_hash

                # Increment sequence on success
                self._sequence += 1

                # Opportunistically drain spill buffer
                if self._transport.spill_count > 0:
                    with contextlib.suppress(Exception):
                        self._transport.drain_spill_buffer()

                logger.debug(
                    "Logged action: seq=%d type=%s tool=%s → %s",
                    entry.sequence_number,
                    action_type.value,
                    tool,
                    action_id,
                )
                return action_id

            except Exception as e:
                if self._fail_open:
                    logger.warning(
                        "Failed to log action (fail_open=True, continuing): %s", e,
                        exc_info=True,
                    )
                    # Keep chain continuity: advance heads so subsequent
                    # entries chain off this entry's hash even if it was spilled.
                    self._chain_heads[entry.session_id] = chain_hash
                    self._sequence += 1
                    return f"spilled_{uuid.uuid4().hex[:8]}"
                raise

    # ------------------------------------------------------------------
    # INTERNAL: Environment auto-detection
    # ------------------------------------------------------------------

    def _derive_org_id(self) -> str:
        """
        Derive the ICP principal from the loaded Ed25519 private key.

        Re-serializes the already-loaded key to PEM in memory (avoids
        TOCTOU issues from re-reading the PEM file on disk).
        Falls back to 'aaaaa-aa' if ic-py is unavailable.
        """
        try:
            from cryptography.hazmat.primitives.serialization import (
                Encoding as _Enc,
                NoEncryption as _NoEnc,
                PrivateFormat as _PF,
            )
            from ic.identity import Identity  # type: ignore[import-untyped]

            pem_bytes = self._private_key.private_bytes(_Enc.PEM, _PF.PKCS8, _NoEnc())
            identity = Identity.from_pem(pem_bytes.decode("ascii"))
            derived = str(identity.sender())
            logger.info("Derived org_id from PEM key: %s", derived)
            return derived
        except Exception as exc:
            logger.warning("Could not derive org_id from PEM (%s) — using 'aaaaa-aa'", exc)
            return "aaaaa-aa"

    @staticmethod
    def _detect_environment() -> Environment:
        """
        Auto-detect the agent's runtime environment.

        Sniffs for known frameworks by checking installed packages.
        """
        framework = "unknown"
        framework_version = "0.0.0"
        model_provider = ""
        model_id = ""

        # Detect LangChain
        try:
            import langchain  # type: ignore[import-untyped]

            framework = "langchain"
            framework_version = getattr(langchain, "__version__", "unknown")
        except ImportError:
            pass

        # Detect CrewAI
        try:
            import crewai  # type: ignore[import-untyped]

            framework = "crewai"
            framework_version = getattr(crewai, "__version__", "unknown")
        except ImportError:
            pass

        # Detect AutoGPT/AutoGen
        try:
            import autogen  # type: ignore[import-untyped]

            framework = "autogen"
            framework_version = getattr(autogen, "__version__", "unknown")
        except ImportError:
            pass

        runtime = f"python{sys.version_info.major}.{sys.version_info.minor}"

        return Environment(
            framework=framework,
            framework_version=framework_version,
            model_provider=model_provider,
            model_id=model_id,
            runtime=runtime,
        )
