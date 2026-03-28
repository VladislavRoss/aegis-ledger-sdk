"""
aegis.anthropic_sdk -- Anthropic Agent SDK (Claude) tracing integration.

Provides both:
1. **HookMatcher-compatible async hooks** for the official Claude Agent SDK
   (PreToolUse, PostToolUse, SessionStart, SessionEnd, Stop)
2. **AegisAnthropicTracer** class for manual/explicit integration.

Official Claude Agent SDK hook usage (recommended):
    from aegis import AegisClient
    from aegis.anthropic_sdk import aegis_hooks

    client = AegisClient.from_config()
    hooks = aegis_hooks(client)

    # Pass to ClaudeAgentOptions:
    # options = ClaudeAgentOptions(hooks=hooks)

Manual tracer usage:
    from aegis import AegisClient
    from aegis.anthropic_sdk import AegisAnthropicTracer

    client = AegisClient.from_config()
    tracer = AegisAnthropicTracer(client)
    tracer.on_tool_use("search", {"query": "test"}, {"results": [...]})
"""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.client import AegisClient

from aegis.types import ActionStatus

logger = logging.getLogger("aegis.anthropic_sdk")

_PREVIEW_MAX = 300
_MAX_PENDING_TIMERS = 10_000
_TIMER_TTL_MS = 3_600_000  # 1 hour


class AegisAnthropicTracer:
    """
    Tracing integration for the Anthropic Agent SDK (Claude).

    Provides explicit hook methods that map to the Agent SDK's
    lifecycle events: PostToolUse, SessionStart, SessionEnd,
    SubagentStart, SubagentStop, and Stop.

    Captures:
      - Tool calls (PostToolUse) -> logged as "tool_call" actions
      - Session start/end -> logged as "observation" / "decision" actions
      - Subagent start/end -> logged as "observation" / "decision" actions
      - Agent stop -> logged as "decision" actions
      - Errors -> logged as "error" actions
    """

    def __init__(
        self,
        client: AegisClient,
        log_tool_calls: bool = True,
        log_subagents: bool = True,
    ) -> None:
        """
        Args:
            client: An initialized AegisClient instance.
            log_tool_calls: Log tool use events (default True).
            log_subagents: Log subagent lifecycle events (default True).
        """
        self._client = client
        self._log_tool_calls = log_tool_calls
        self._log_subagents = log_subagents

        self._start_times: dict[str, int] = {}
        self._times_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Tool hooks
    # ------------------------------------------------------------------

    def on_tool_use(
        self,
        tool_name: str,
        tool_input: Any = None,
        tool_response: Any = None,
        tool_use_id: str = "",
        duration_ms: int = 0,
        status: ActionStatus = ActionStatus.SUCCESS,
    ) -> None:
        """
        Log a tool call made by the Claude agent (PostToolUse event).

        Args:
            tool_name: Name of the tool invoked.
            tool_input: Tool input arguments.
            tool_response: Tool return value.
            tool_use_id: Unique tool use identifier.
            duration_ms: Execution time in milliseconds.
            status: Outcome status.
        """
        if not self._log_tool_calls:
            return

        input_preview = str(tool_input)[:_PREVIEW_MAX] if tool_input else ""
        response_preview = str(tool_response)[:_PREVIEW_MAX] if tool_response else ""

        try:
            self._client.log_tool_call(
                tool=tool_name,
                input_data={"tool_input": input_preview, "tool_use_id": tool_use_id},
                output_data={
                    "response_preview": response_preview,
                    "response_length": len(str(tool_response)) if tool_response else 0,
                },
                duration_ms=duration_ms,
                status=status,
                metadata={"framework": "anthropic_sdk"},
            )
        except Exception:
            logger.warning("Failed to log Anthropic tool call", exc_info=True)

    # ------------------------------------------------------------------
    # Session hooks
    # ------------------------------------------------------------------

    def on_session_start(self, session_id: str = "") -> None:
        """
        Log the start of a Claude agent session (SessionStart event).

        Args:
            session_id: Session identifier from the Agent SDK.
        """
        with self._times_lock:
            if session_id:
                self._start_times[f"session:{session_id}"] = int(time.time() * 1000)
            self._evict_stale_timers()

        try:
            self._client.log_observation(
                input_data={"event": "session_start", "session_id": session_id},
                output_data={"status": "started"},
                metadata={"framework": "anthropic_sdk"},
            )
        except Exception:
            logger.warning("Failed to log Anthropic session start", exc_info=True)

    def on_session_end(self, session_id: str = "") -> None:
        """
        Log the end of a Claude agent session (SessionEnd event).

        Args:
            session_id: Session identifier from the Agent SDK.
        """
        elapsed = self._elapsed(f"session:{session_id}") if session_id else 0

        try:
            self._client.log_decision(
                reasoning="Anthropic Agent session completed",
                confidence=1.0,
                input_data={"event": "session_end", "session_id": session_id},
                output_data={"status": "completed"},
                duration_ms=elapsed,
                metadata={"framework": "anthropic_sdk"},
            )
        except Exception:
            logger.warning("Failed to log Anthropic session end", exc_info=True)

    # ------------------------------------------------------------------
    # Subagent hooks
    # ------------------------------------------------------------------

    def on_subagent_start(self, agent_id: str, agent_type: str = "") -> None:
        """
        Log a subagent being launched (SubagentStart event).

        Args:
            agent_id: Unique identifier of the subagent.
            agent_type: Type or name of the subagent.
        """
        if not self._log_subagents:
            return

        with self._times_lock:
            self._start_times[f"sub:{agent_id}"] = int(time.time() * 1000)
            self._evict_stale_timers()

        try:
            self._client.log_observation(
                input_data={
                    "event": "subagent_start",
                    "agent_id": agent_id,
                    "agent_type": agent_type,
                },
                output_data={"status": "launched"},
                metadata={"framework": "anthropic_sdk"},
            )
        except Exception:
            logger.warning("Failed to log Anthropic subagent start", exc_info=True)

    def on_subagent_end(self, agent_id: str, agent_type: str = "") -> None:
        """
        Log a subagent completing (SubagentStop event).

        Args:
            agent_id: Unique identifier of the subagent.
            agent_type: Type or name of the subagent.
        """
        if not self._log_subagents:
            return

        elapsed = self._elapsed(f"sub:{agent_id}")

        try:
            self._client.log_decision(
                reasoning=f"Subagent {agent_type or agent_id} completed",
                confidence=1.0,
                input_data={
                    "event": "subagent_end",
                    "agent_id": agent_id,
                    "agent_type": agent_type,
                },
                output_data={"status": "completed"},
                duration_ms=elapsed,
                metadata={"framework": "anthropic_sdk"},
            )
        except Exception:
            logger.warning("Failed to log Anthropic subagent end", exc_info=True)

    # ------------------------------------------------------------------
    # Stop / Error hooks
    # ------------------------------------------------------------------

    def on_stop(self, session_id: str = "", summary: str = "") -> None:
        """
        Log the agent stopping (Stop event).

        Args:
            session_id: Session identifier.
            summary: Summary of the agent run.
        """
        elapsed = self._elapsed(f"session:{session_id}") if session_id else 0

        try:
            self._client.log_decision(
                reasoning="Anthropic Agent run stopped",
                confidence=1.0,
                input_data={"event": "stop", "session_id": session_id},
                output_data={"summary": summary[:_PREVIEW_MAX]},
                duration_ms=elapsed,
                metadata={"framework": "anthropic_sdk"},
            )
        except Exception:
            logger.warning("Failed to log Anthropic agent stop", exc_info=True)

    def log_error(self, error: Exception, context: str = "") -> None:
        """
        Log an error from the Claude agent.

        Args:
            error: The exception that occurred.
            context: Additional context about the error.
        """
        try:
            self._client.log_error(
                tool="anthropic_sdk",
                input_data={"context": context[:_PREVIEW_MAX]},
                error=error,
                metadata={"framework": "anthropic_sdk"},
            )
        except Exception:
            logger.warning("Failed to log Anthropic error", exc_info=True)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _elapsed(self, key: str) -> int:
        """Calculate elapsed time in ms since operation started."""
        with self._times_lock:
            start = self._start_times.pop(key, None)
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


# ======================================================================
# Claude Agent SDK HookMatcher-compatible async hooks
# ======================================================================
#
# These functions match the signature the Claude Agent SDK expects:
#   async def hook(input_data: dict, tool_use_id: str | None, context) -> dict
#
# Usage with ClaudeAgentOptions:
#   from claude_agent_sdk import ClaudeAgentOptions, HookMatcher
#   from aegis.anthropic_sdk import aegis_hooks
#
#   client = AegisClient.from_config()
#   options = ClaudeAgentOptions(hooks=aegis_hooks(client))


def aegis_hooks(client: AegisClient) -> dict[str, list]:
    """Build a hooks dict for ``ClaudeAgentOptions``.

    Returns a dict mapping hook event names to lists of HookMatcher-like
    dicts, ready to be spread into ``ClaudeAgentOptions(hooks=...)``.

    This captures:
      - **PostToolUse**: Every tool call with name, input, output
      - **SessionStart**: Agent session begin
      - **Stop**: Agent session end

    Args:
        client: An initialized AegisClient instance.

    Returns:
        Dict with "PostToolUse", "SessionStart", "Stop" keys.
        Each value is a list suitable for HookMatcher ``hooks`` param.
    """
    tracer = AegisAnthropicTracer(client)

    async def _post_tool_use(
        input_data: dict[str, Any],
        tool_use_id: str | None,
        context: Any,
    ) -> dict[str, Any]:
        """PostToolUse hook — logs every tool call to Aegis Ledger."""
        tool_name = input_data.get("tool_name", "unknown")
        tool_input = input_data.get("tool_input", {})
        tool_output = input_data.get("tool_output", {})
        tracer.on_tool_use(
            tool_name=tool_name,
            tool_input=tool_input,
            tool_response=tool_output,
            tool_use_id=tool_use_id or "",
        )
        return {}

    async def _session_start(
        input_data: dict[str, Any],
        tool_use_id: str | None,
        context: Any,
    ) -> dict[str, Any]:
        """SessionStart hook — logs agent session begin."""
        session_id = input_data.get("session_id", "")
        tracer.on_session_start(session_id=session_id)
        return {}

    async def _stop(
        input_data: dict[str, Any],
        tool_use_id: str | None,
        context: Any,
    ) -> dict[str, Any]:
        """Stop hook — logs agent session end."""
        session_id = input_data.get("session_id", "")
        summary = input_data.get("summary", "")
        tracer.on_stop(session_id=session_id, summary=summary)
        return {}

    # Return format matches ClaudeAgentOptions hooks dict.
    # Users wrap with HookMatcher: HookMatcher(hooks=[fn])
    return {
        "PostToolUse": [_post_tool_use],
        "SessionStart": [_session_start],
        "Stop": [_stop],
    }
