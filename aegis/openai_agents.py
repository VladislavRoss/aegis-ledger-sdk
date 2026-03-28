"""
aegis.openai_agents -- OpenAI Agents SDK tracing integration.

Provides both:
1. **AegisRunHooks** — a ``RunHooks`` subclass for automatic capture via
   ``Runner.run(agent, ..., hooks=AegisRunHooks(client))``
2. **AegisAgentTracer** — manual wrapper with ``trace()`` context manager.

Official RunHooks usage (recommended):
    from aegis import AegisClient
    from aegis.openai_agents import AegisRunHooks

    client = AegisClient.from_config()
    result = await Runner.run(agent, "Hello", hooks=AegisRunHooks(client))

Manual tracer usage:
    from aegis import AegisClient
    from aegis.openai_agents import AegisAgentTracer

    client = AegisClient.from_config()
    tracer = AegisAgentTracer(client)
    with tracer.trace():
        result = await Runner.run(agent, "Hello")
"""

from __future__ import annotations

import contextlib
import contextvars
import logging
import threading
import time
import uuid
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Generator

    from aegis.client import AegisClient

from aegis.types import ActionStatus

logger = logging.getLogger("aegis.openai_agents")

_PREVIEW_MAX = 300
_MAX_PENDING_TIMERS = 10_000
_TIMER_TTL_MS = 3_600_000  # 1 hour

_active_trace_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "aegis_oai_trace_id", default=None
)


class AegisAgentTracer:
    """
    Tracing wrapper for the OpenAI Agents SDK.

    Provides a context manager ``trace()`` that tracks the lifecycle of
    an agent run, plus explicit methods for logging tool calls, handoffs,
    and guardrail checks.

    Captures:
      - Function tool calls -> logged as "tool_call" actions
      - Agent handoffs -> logged as "decision" actions
      - Guardrail checks -> logged as "observation" actions
      - Run completion -> logged as "decision" actions
      - Errors -> logged as "error" actions
    """

    def __init__(
        self,
        client: AegisClient,
        log_handoffs: bool = True,
        log_guardrails: bool = True,
    ) -> None:
        """
        Args:
            client: An initialized AegisClient instance.
            log_handoffs: Log agent handoff events (default True).
            log_guardrails: Log guardrail check events (default True).
        """
        self._client = client
        self._log_handoffs = log_handoffs
        self._log_guardrails = log_guardrails

        # Track timing per trace_id (guarded by _times_lock for thread safety)
        self._start_times: dict[str, int] = {}
        self._times_lock = threading.Lock()

    @contextmanager
    def trace(
        self,
        trace_id: str | None = None,
    ) -> Generator[str, None, None]:
        """
        Context manager that wraps an OpenAI Agents SDK run.

        Records the start and end of the agent run and provides a trace_id
        for correlating all events within the run.

        Args:
            trace_id: Optional trace ID. Auto-generated if not provided.

        Yields:
            The trace_id for this run.
        """
        tid = trace_id or f"oai_{uuid.uuid4().hex[:16]}"
        _active_trace_var.set(tid)
        with self._times_lock:
            self._start_times[tid] = int(time.time() * 1000)
            self._evict_stale_timers()

        try:
            yield tid
        except Exception as exc:
            elapsed = self._elapsed(tid)
            with contextlib.suppress(Exception):
                self._client.log_error(
                    tool="openai_agents",
                    input_data={"trace_id": tid},
                    error=exc if isinstance(exc, Exception) else Exception(str(exc)),
                    duration_ms=elapsed,
                    metadata={"framework": "openai_agents", "trace_id": tid},
                )
            raise
        else:
            elapsed = self._elapsed(tid)
            with contextlib.suppress(Exception):
                self._client.log_decision(
                    reasoning="OpenAI Agents run completed",
                    confidence=1.0,
                    input_data={"trace_id": tid},
                    output_data={"status": "completed"},
                    duration_ms=elapsed,
                    metadata={"framework": "openai_agents", "trace_id": tid},
                )
        finally:
            _active_trace_var.set(None)

    # ------------------------------------------------------------------
    # Event logging methods
    # ------------------------------------------------------------------

    def log_tool_call(
        self,
        tool_name: str,
        input_data: Any = None,
        output_data: Any = None,
        duration_ms: int = 0,
        status: ActionStatus = ActionStatus.SUCCESS,
    ) -> None:
        """
        Log a function tool call made by the agent.

        Args:
            tool_name: Name of the function tool.
            input_data: Tool input arguments.
            output_data: Tool return value.
            duration_ms: Execution time in milliseconds.
            status: Outcome status.
        """
        input_preview = str(input_data)[:_PREVIEW_MAX] if input_data else ""
        output_preview = str(output_data)[:_PREVIEW_MAX] if output_data else ""

        try:
            self._client.log_tool_call(
                tool=tool_name,
                input_data={"tool_input": input_preview},
                output_data={
                    "output_preview": output_preview,
                    "output_length": len(str(output_data)) if output_data else 0,
                },
                duration_ms=duration_ms,
                status=status,
                metadata=self._trace_metadata(),
            )
        except Exception:
            logger.warning("Failed to log OpenAI Agents tool call", exc_info=True)

    def log_handoff(
        self,
        from_agent: str,
        to_agent: str,
        reason: str = "",
    ) -> None:
        """
        Log an agent-to-agent handoff.

        Args:
            from_agent: Name of the source agent.
            to_agent: Name of the target agent.
            reason: Reason for the handoff.
        """
        if not self._log_handoffs:
            return

        try:
            self._client.log_decision(
                reasoning=f"Handoff: {from_agent} -> {to_agent}. {reason[:200]}",
                confidence=1.0,
                input_data={
                    "from_agent": from_agent,
                    "to_agent": to_agent,
                },
                output_data={"reason": reason[:_PREVIEW_MAX]},
                metadata=self._trace_metadata(),
            )
        except Exception:
            logger.warning("Failed to log OpenAI Agents handoff", exc_info=True)

    def log_guardrail(
        self,
        guardrail_name: str,
        passed: bool,
        details: str = "",
    ) -> None:
        """
        Log a guardrail check result.

        Args:
            guardrail_name: Name of the guardrail.
            passed: Whether the guardrail check passed.
            details: Additional details about the check.
        """
        if not self._log_guardrails:
            return

        try:
            self._client.log_observation(
                input_data={
                    "guardrail": guardrail_name,
                    "passed": passed,
                },
                output_data={"details": details[:_PREVIEW_MAX]},
                metadata=self._trace_metadata(),
            )
        except Exception:
            logger.warning("Failed to log OpenAI Agents guardrail", exc_info=True)

    def log_error(self, error: Exception, context: str = "") -> None:
        """Log an error that occurred during an agent run."""
        try:
            self._client.log_error(
                tool="openai_agents",
                input_data={"context": context[:_PREVIEW_MAX]},
                error=error,
                metadata=self._trace_metadata(),
            )
        except Exception:
            logger.warning("Failed to log OpenAI Agents error", exc_info=True)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _elapsed(self, trace_id: str) -> int:
        """Calculate elapsed time in ms since trace started."""
        with self._times_lock:
            start = self._start_times.pop(trace_id, None)
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

    def _trace_metadata(self) -> dict[str, str]:
        """Build metadata dict with framework and active trace_id."""
        meta: dict[str, str] = {"framework": "openai_agents"}
        active_tid = _active_trace_var.get()
        if active_tid:
            meta["trace_id"] = active_tid
        return meta


# ======================================================================
# Official RunHooks subclass for OpenAI Agents SDK
# ======================================================================
#
# Usage:
#   from agents import Agent, Runner
#   from aegis.openai_agents import AegisRunHooks
#
#   client = AegisClient.from_config()
#   result = await Runner.run(agent, "Hello", hooks=AegisRunHooks(client))
#
# Captures on_agent_start, on_agent_end, on_tool_start, on_tool_end,
# on_handoff automatically — no manual calls needed.


# Inherit from RunHooks when available — gives us default no-op
# implementations for any new methods the SDK adds (self-healing).
try:
    from agents import RunHooks as _RunHooksBase
except ImportError:
    _RunHooksBase = object  # type: ignore[assignment,misc]


class AegisRunHooks(_RunHooksBase):  # type: ignore[misc]
    """``RunHooks`` subclass for the OpenAI Agents SDK.

    Drop-in replacement — pass as ``hooks=`` to ``Runner.run()``.
    Inherits from ``RunHooks`` so any new lifecycle methods added
    by the SDK automatically get a default no-op (self-healing).

    Overrides:
      - ``on_agent_start(context, agent)``
      - ``on_agent_end(context, agent, output)``
      - ``on_tool_start(context, agent, tool)``
      - ``on_tool_end(context, agent, tool, result)``
      - ``on_handoff(context, from_agent, to_agent)``
    """

    def __init__(self, client: AegisClient) -> None:
        self._client = client
        self._start_times: dict[str, int] = {}
        self._lock = threading.Lock()

    async def on_agent_start(self, context: Any, agent: Any) -> None:
        agent_name = getattr(agent, "name", str(agent))
        with self._lock:
            self._start_times[f"agent:{agent_name}"] = int(time.time() * 1000)
        try:
            self._client.log_observation(
                input_data={"event": "agent_start", "agent": agent_name},
                output_data={"status": "started"},
                metadata={"framework": "openai_agents"},
            )
        except Exception:
            logger.warning("Failed to log agent start", exc_info=True)

    async def on_agent_end(self, context: Any, agent: Any, output: Any) -> None:
        agent_name = getattr(agent, "name", str(agent))
        elapsed = self._elapsed(f"agent:{agent_name}")
        usage = getattr(context, "usage", None)
        try:
            self._client.log_decision(
                reasoning=f"Agent {agent_name} completed",
                confidence=1.0,
                input_data={"agent": agent_name},
                output_data={
                    "status": "completed",
                    "usage": str(usage)[:_PREVIEW_MAX] if usage else "",
                },
                duration_ms=elapsed,
                metadata={"framework": "openai_agents"},
            )
        except Exception:
            logger.warning("Failed to log agent end", exc_info=True)

    async def on_tool_start(self, context: Any, agent: Any, tool: Any) -> None:
        tool_name = getattr(tool, "name", str(tool))
        with self._lock:
            self._start_times[f"tool:{tool_name}"] = int(time.time() * 1000)

    async def on_tool_end(
        self, context: Any, agent: Any, tool: Any, result: Any,
    ) -> None:
        tool_name = getattr(tool, "name", str(tool))
        elapsed = self._elapsed(f"tool:{tool_name}")
        try:
            self._client.log_tool_call(
                tool=tool_name,
                input_data={"agent": getattr(agent, "name", "")},
                output_data={
                    "result_preview": str(result)[:_PREVIEW_MAX],
                },
                duration_ms=elapsed,
                status=ActionStatus.SUCCESS,
                metadata={"framework": "openai_agents"},
            )
        except Exception:
            logger.warning("Failed to log tool end", exc_info=True)

    async def on_llm_start(
        self, context: Any, agent: Any, *args: Any, **kwargs: Any,
    ) -> None:
        pass  # Intentionally not logged — accepts any future params

    async def on_llm_end(
        self, context: Any, agent: Any, *args: Any, **kwargs: Any,
    ) -> None:
        pass  # Intentionally not logged — accepts any future params

    async def on_handoff(
        self, context: Any, from_agent: Any, to_agent: Any,
    ) -> None:
        source_name = getattr(from_agent, "name", str(from_agent))
        target_name = getattr(to_agent, "name", str(to_agent))
        try:
            self._client.log_decision(
                reasoning=f"Handoff: {source_name} -> {target_name}",
                confidence=1.0,
                input_data={"from": source_name, "to": target_name},
                output_data={"status": "handoff"},
                metadata={"framework": "openai_agents"},
            )
        except Exception:
            logger.warning("Failed to log handoff", exc_info=True)

    def _elapsed(self, key: str) -> int:
        with self._lock:
            start = self._start_times.pop(key, None)
        return (int(time.time() * 1000) - start) if start else 0
