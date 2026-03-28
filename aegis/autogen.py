"""
aegis.autogen -- AutoGen/AG2 message hook integration.

Hooks into AutoGen's (AG2 v0.4+) message passing system to log
agent-to-agent messages, tool invocations, and completions to
the Aegis Ledger.

Usage:
    from aegis import AegisClient
    from aegis.autogen import AegisAutoGenHook

    client = AegisClient.from_config()  # after: aegis init
    hook = AegisAutoGenHook(client)

    # Use directly in agent callbacks (explicit logging):
    agent = AssistantAgent(
        "assistant",
        model_client=model_client,
        tools=[get_weather],
    )
    hook.on_message_sent(sender="user", receiver="assistant", message="Hello")
    hook.on_tool_call(tool_name="get_weather", arguments={"city": "Zurich"}, caller="assistant")
    hook.on_tool_result(tool_name="get_weather", result="22C sunny", caller="assistant")

    # For auto-interception, use AG2 v0.4+ InterventionHandler:
    # runtime = SingleThreadedAgentRuntime(intervention_handlers=[AegisInterventionHandler(client)])
"""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.client import AegisClient

from aegis.types import ActionStatus

logger = logging.getLogger("aegis.autogen")

_PREVIEW_MAX = 300
_MAX_PENDING_TIMERS = 10_000
_TIMER_TTL_MS = 3_600_000  # 1 hour


class AegisAutoGenHook:
    """
    AutoGen/AG2-compatible hook that logs all agent activity
    to the Aegis Ledger.

    Compatible with AG2 (AutoGen v0.4+). Provides explicit methods
    for logging message passing, tool invocations, and completions.

    Captures:
      - Agent-to-agent messages -> logged as "observation" actions
      - Tool invocations -> logged as "tool_call" actions
      - Agent completions -> logged as "decision" actions
      - Errors -> logged as "error" actions
    """

    def __init__(
        self,
        client: AegisClient,
        log_messages: bool = True,
        log_tool_calls: bool = True,
    ) -> None:
        """
        Args:
            client: An initialized AegisClient instance.
            log_messages: Log agent-to-agent messages (default True).
            log_tool_calls: Log tool invocations (default True).
        """
        self._client = client
        self._log_messages = log_messages
        self._log_tool_calls = log_tool_calls

        # Track timing per conversation key
        self._start_times: dict[str, int] = {}
        self._times_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Message hooks
    # ------------------------------------------------------------------

    def on_message_sent(
        self,
        sender: str,
        receiver: str,
        message: Any,
    ) -> None:
        """
        Called when an agent sends a message to another agent.

        Args:
            sender: Name or ID of the sending agent.
            receiver: Name or ID of the receiving agent.
            message: The message content (str or dict).
        """
        if not self._log_messages:
            return

        content = self._extract_content(message)

        try:
            self._client.log_observation(
                input_data={
                    "sender": str(sender),
                    "receiver": str(receiver),
                },
                output_data={
                    "content_preview": content[:_PREVIEW_MAX],
                    "content_length": len(content),
                },
                metadata={"framework": "autogen", "direction": "sent"},
            )
        except Exception:
            logger.warning("Failed to log AutoGen message", exc_info=True)

    def on_message_received(
        self,
        sender: str,
        receiver: str,
        message: Any,
    ) -> None:
        """
        Called when an agent receives a message from another agent.

        Args:
            sender: Name or ID of the sending agent.
            receiver: Name or ID of the receiving agent.
            message: The message content (str or dict).
        """
        if not self._log_messages:
            return

        content = self._extract_content(message)

        try:
            self._client.log_observation(
                input_data={
                    "sender": str(sender),
                    "receiver": str(receiver),
                },
                output_data={
                    "content_preview": content[:_PREVIEW_MAX],
                    "content_length": len(content),
                },
                metadata={"framework": "autogen", "direction": "received"},
            )
        except Exception:
            logger.warning("Failed to log AutoGen message received", exc_info=True)

    # ------------------------------------------------------------------
    # Tool hooks
    # ------------------------------------------------------------------

    def on_tool_call(
        self,
        tool_name: str,
        arguments: Any = None,
        caller: str = "",
    ) -> None:
        """
        Record the start of a tool invocation.

        Args:
            tool_name: Name of the tool being called.
            arguments: Tool call arguments.
            caller: Name or ID of the agent invoking the tool.
        """
        key = f"{caller}:{tool_name}"
        with self._times_lock:
            self._start_times[key] = int(time.time() * 1000)
            self._evict_stale_timers()

    def on_tool_result(
        self,
        tool_name: str,
        result: Any = None,
        caller: str = "",
        status: ActionStatus = ActionStatus.SUCCESS,
    ) -> None:
        """
        Log the result of a tool invocation.

        Args:
            tool_name: Name of the tool that was called.
            result: The tool's return value.
            caller: Name or ID of the agent that invoked the tool.
            status: Outcome status.
        """
        if not self._log_tool_calls:
            return

        key = f"{caller}:{tool_name}"
        elapsed = self._elapsed(key)

        result_str = str(result) if result is not None else ""

        try:
            self._client.log_tool_call(
                tool=tool_name,
                input_data={"caller": str(caller)},
                output_data={
                    "result_preview": result_str[:_PREVIEW_MAX],
                    "result_length": len(result_str),
                },
                duration_ms=elapsed,
                status=status,
                metadata={"framework": "autogen", "caller": str(caller)},
            )
        except Exception:
            logger.warning("Failed to log AutoGen tool result", exc_info=True)

    # ------------------------------------------------------------------
    # Completion hooks
    # ------------------------------------------------------------------

    def on_completion(
        self,
        agent_name: str,
        summary: str = "",
        chat_history_length: int = 0,
    ) -> None:
        """
        Log agent conversation completion.

        Args:
            agent_name: Name or ID of the completing agent.
            summary: Summary of the conversation.
            chat_history_length: Number of messages in the chat history.
        """
        try:
            self._client.log_decision(
                reasoning=f"AutoGen conversation completed by {agent_name}",
                confidence=1.0,
                input_data={
                    "agent": str(agent_name),
                    "chat_history_length": chat_history_length,
                },
                output_data={"summary": summary[:_PREVIEW_MAX]},
                metadata={"framework": "autogen"},
            )
        except Exception:
            logger.warning("Failed to log AutoGen completion", exc_info=True)

    # ------------------------------------------------------------------
    # Error hooks
    # ------------------------------------------------------------------

    def log_error(
        self,
        error: Exception,
        agent_name: str = "",
        context: str = "",
    ) -> None:
        """
        Log an error from an AutoGen agent.

        Args:
            error: The exception that occurred.
            agent_name: Name or ID of the agent where the error occurred.
            context: Additional context about the error.
        """
        try:
            self._client.log_error(
                tool=f"autogen:{agent_name}" if agent_name else "autogen",
                input_data={"context": context[:_PREVIEW_MAX], "agent": agent_name},
                error=error,
                metadata={"framework": "autogen"},
            )
        except Exception:
            logger.warning("Failed to log AutoGen error", exc_info=True)

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

    @staticmethod
    def _extract_content(message: Any) -> str:
        """Extract text content from an AutoGen message (str or dict).

        Returns a safe preview — never the full repr of arbitrary objects
        (which could leak internal data to the ledger).
        """
        if isinstance(message, str):
            return message[:_PREVIEW_MAX]
        if isinstance(message, dict):
            return str(message.get("content", ""))[:_PREVIEW_MAX]
        return f"<{type(message).__name__}>"
