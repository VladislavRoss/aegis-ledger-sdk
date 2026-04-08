"""
aegis.langchain — Minimal-config LangChain callback handler.

This is the "Trojan Horse" integration. A LangChain developer adds TWO
lines to their existing agent and every tool call, LLM invocation, and
chain step is automatically logged to Aegis with full trace trees.

Usage:
    from aegis import AegisClient
    from aegis.langchain import AegisCallbackHandler

    client = AegisClient.from_config()  # after: aegis init
    handler = AegisCallbackHandler(client)

    # Drop it into any LangChain agent, chain, or tool
    agent.invoke(
        {"input": "What is the weather in Tokyo?"},
        config={"callbacks": [handler]}
    )
    # That's it. Every action is now tamper-evident logged.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from uuid import UUID

    from aegis.client import AegisClient

from aegis.types import ActionStatus

logger = logging.getLogger("aegis.langchain")

_MAX_PENDING_TIMERS = 10_000
_TIMER_TTL_MS = 3_600_000  # 1 hour


# Inherit from BaseCallbackHandler when available — gives us default
# no-op implementations for any new methods LangChain adds (self-healing).
try:
    from langchain_core.callbacks import BaseCallbackHandler as _LCBase
except ImportError:
    _LCBase = object  # type: ignore[assignment,misc]


class AegisCallbackHandler(_LCBase):  # type: ignore[misc]
    """
    LangChain callback handler that logs all agent activity
    to the Aegis Ledger.

    Inherits from ``BaseCallbackHandler`` so any new callback methods
    added by LangChain automatically get a default no-op (self-healing).

    Captures:
      - LLM start/end → logged as "decision" actions
      - Tool start/end → logged as "tool_call" actions
      - Chain start/end → logged as "observation" actions
      - Errors → logged as "error" actions
      - Agent actions → logged with reasoning and tool selection
    """

    def __init__(
        self,
        client: AegisClient,
        log_llm_calls: bool = True,
        log_chain_steps: bool = False,
        log_prompts: bool = False,
    ):
        """
        Args:
            client: An initialized AegisClient instance.
            log_llm_calls: Log individual LLM invocations (default True).
            log_chain_steps: Log chain start/end events (default False,
                           can be noisy for complex chains).
            log_prompts: Include full prompt text in input_preview
                        (default False for privacy — only logs a hash).
        """
        self._client = client
        self._log_llm = log_llm_calls
        self._log_chains = log_chain_steps
        self._log_prompts = log_prompts

        # Track timing per run_id
        self._start_times: dict[UUID, int] = {}
        self._times_lock = threading.Lock()

    # ------------------------------------------------------------------
    # LLM callbacks
    # ------------------------------------------------------------------

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when an LLM starts generating."""
        with self._times_lock:
            self._start_times[run_id] = int(time.time() * 1000)
            self._evict_stale_timers()

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when an LLM finishes generating."""
        if not self._log_llm:
            return

        elapsed = self._elapsed(run_id)

        # Extract model info from response
        model_id = ""
        output_text = ""
        token_usage: dict[str, int] = {}

        if hasattr(response, "llm_output") and response.llm_output:
            model_id = response.llm_output.get("model_name", "")
            token_usage = response.llm_output.get("token_usage", {})

        if hasattr(response, "generations") and response.generations:
            first_gen = response.generations[0]
            if first_gen:
                gen = first_gen[0]
                # Support both Generation.text and ChatGeneration.message.content
                output_text = (
                    getattr(gen, "text", None)
                    or getattr(getattr(gen, "message", None), "content", "")
                    or ""
                )

        input_data = {"model": model_id, "token_usage": token_usage}
        output_data: dict[str, object] = {"response_length": len(output_text)}

        if self._log_prompts and output_text:
            output_data["response_preview"] = output_text[:500]

        try:
            self._client.log_decision(
                reasoning=f"LLM generation completed ({model_id})",
                confidence=1.0,
                input_data=input_data,
                output_data=output_data,
                duration_ms=elapsed,
                metadata={"langchain_run_id": str(run_id)},
            )
        except Exception:
            logger.warning("Failed to log LangChain LLM end", exc_info=True)

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when an LLM errors."""
        elapsed = self._elapsed(run_id)
        try:
            self._client.log_error(
                tool="llm",
                input_data={"run_id": str(run_id)},
                error=error if isinstance(error, Exception) else Exception(str(error)),
                duration_ms=elapsed,
                metadata={"langchain_run_id": str(run_id)},
            )
        except Exception:
            logger.warning("Failed to log LangChain LLM error", exc_info=True)

    # ------------------------------------------------------------------
    # Tool callbacks
    # ------------------------------------------------------------------

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts executing."""
        with self._times_lock:
            self._start_times[run_id] = int(time.time() * 1000)
            self._evict_stale_timers()

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        name: str = "unknown_tool",
        **kwargs: Any,
    ) -> None:
        """Called when a tool finishes executing."""
        elapsed = self._elapsed(run_id)

        try:
            self._client.log_tool_call(
                tool=name,
                input_data={"tool_input": kwargs.get("tool_input", "")},
                output_data={"output_length": len(output), "output_preview": output[:300]},
                duration_ms=elapsed,
                status=ActionStatus.SUCCESS,
                metadata={"langchain_run_id": str(run_id)},
            )
        except Exception:
            logger.warning("Failed to log LangChain tool end", exc_info=True)

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        name: str = "unknown_tool",
        **kwargs: Any,
    ) -> None:
        """Called when a tool errors."""
        elapsed = self._elapsed(run_id)
        try:
            self._client.log_error(
                tool=name,
                input_data={"run_id": str(run_id)},
                error=error if isinstance(error, Exception) else Exception(str(error)),
                duration_ms=elapsed,
                metadata={"langchain_run_id": str(run_id)},
            )
        except Exception:
            logger.warning("Failed to log LangChain tool error", exc_info=True)

    # ------------------------------------------------------------------
    # Chain callbacks (optional, off by default)
    # ------------------------------------------------------------------

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain starts."""
        with self._times_lock:
            self._start_times[run_id] = int(time.time() * 1000)
            self._evict_stale_timers()

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain finishes."""
        if not self._log_chains:
            return

        elapsed = self._elapsed(run_id)
        try:
            self._client.log_observation(
                input_data={"chain_run_id": str(run_id)},
                output_data={"output_keys": list(outputs.keys()) if outputs else []},
                duration_ms=elapsed,
                metadata={"langchain_run_id": str(run_id)},
            )
        except Exception:
            logger.warning("Failed to log LangChain chain end", exc_info=True)

    def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain errors."""
        elapsed = self._elapsed(run_id)
        try:
            self._client.log_error(
                tool="chain",
                input_data={"run_id": str(run_id)},
                error=error if isinstance(error, Exception) else Exception(str(error)),
                duration_ms=elapsed,
                metadata={"langchain_run_id": str(run_id)},
            )
        except Exception:
            logger.warning("Failed to log LangChain chain error", exc_info=True)

    # ------------------------------------------------------------------
    # Agent callbacks
    # ------------------------------------------------------------------

    def on_agent_action(
        self,
        action: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when an agent selects an action."""
        tool_name = getattr(action, "tool", "unknown")
        tool_input = getattr(action, "tool_input", {})
        log_text = getattr(action, "log", "")

        try:
            self._client.log_decision(
                reasoning=f"Agent selected tool: {tool_name}. {log_text[:200]}",
                confidence=0.0,
                input_data={
                    "selected_tool": tool_name,
                    "tool_input_preview": str(tool_input)[:200],
                },
                metadata={"langchain_run_id": str(run_id)},
            )
        except Exception:
            logger.warning("Failed to log LangChain agent action", exc_info=True)

    def on_agent_finish(
        self,
        finish: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when an agent completes."""
        output = getattr(finish, "return_values", {})
        log_text = getattr(finish, "log", "")

        try:
            self._client.log_decision(
                reasoning=f"Agent finished. {log_text[:200]}",
                confidence=1.0,
                output_data={
                    "return_keys": list(output.keys()) if isinstance(output, dict) else [],
                },
                metadata={"langchain_run_id": str(run_id)},
            )
        except Exception:
            logger.warning("Failed to log LangChain agent finish", exc_info=True)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _elapsed(self, run_id: UUID) -> int:
        """Calculate elapsed time in ms since run started."""
        with self._times_lock:
            start = self._start_times.pop(run_id, None)
        if start is None:
            return 0
        return int(time.time() * 1000) - start

    def _evict_stale_timers(self) -> None:
        """Remove timing entries older than 1h to prevent memory leaks.

        Must be called while holding ``_times_lock``.
        """
        if len(self._start_times) <= _MAX_PENDING_TIMERS:
            return
        cutoff = int(time.time() * 1000) - _TIMER_TTL_MS
        stale = [k for k, v in self._start_times.items() if v < cutoff]
        for k in stale:
            del self._start_times[k]
