"""
aegis.crewai -- CrewAI step callback integration.

Hooks into CrewAI's step_callback system to log every agent step,
tool invocation, and task completion to the Aegis Ledger.

Usage:
    from aegis import AegisClient
    from aegis.crewai import AegisCrewCallback

    client = AegisClient(
        canister_id="toqqq-lqaaa-aaaae-afc2a-cai",
        api_key_id="ak_3f8a...",
        private_key_path="./agent_key.pem",
        agent_id="agent_crew_v1",
    )

    callback = AegisCrewCallback(client)

    crew = Crew(
        agents=[...],
        tasks=[...],
        step_callback=callback,
    )
"""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.client import AegisClient

from aegis.types import ActionStatus

logger = logging.getLogger("aegis.crewai")

_PREVIEW_MAX = 300


class AegisCrewCallback:
    """
    CrewAI-compatible step callback that logs all agent activity
    to the Aegis Ledger.

    CrewAI invokes step_callback(step_output) after each agent step.
    This class implements __call__ so it can be passed directly as
    the step_callback parameter.

    Captures:
      - Tool usage steps -> logged as "tool_call" actions
      - Task completions -> logged as "decision" actions
      - Errors -> logged as "error" actions
    """

    def __init__(
        self,
        client: AegisClient,
        log_task_completions: bool = True,
    ) -> None:
        """
        Args:
            client: An initialized AegisClient instance.
            log_task_completions: Log task completion events (default True).
        """
        self._client = client
        self._log_task_completions = log_task_completions

        # Track timing per task description (CrewAI does not expose UUIDs)
        self._start_times: dict[str, int] = {}
        self._times_lock = threading.Lock()

    def __call__(self, step_output: Any) -> None:
        """
        Called by CrewAI after each agent step.

        Dispatches to the appropriate handler based on the step_output type.
        CrewAI passes either an AgentAction (tool use) or a TaskOutput
        (task completion).
        """
        type_name = type(step_output).__name__

        if type_name == "AgentAction":
            self._handle_agent_action(step_output)
        elif type_name == "TaskOutput":
            self._handle_task_output(step_output)
        else:
            # Unknown step type -- log as observation
            self._handle_unknown_step(step_output)

    # ------------------------------------------------------------------
    # Task timing
    # ------------------------------------------------------------------

    def start_task(self, task_description: str) -> None:
        """Record the start time for a task. Call before crew.kickoff()."""
        with self._times_lock:
            self._start_times[task_description] = int(time.time() * 1000)

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    def _handle_agent_action(self, action: Any) -> None:
        """Handle a CrewAI AgentAction (tool invocation)."""
        tool = getattr(action, "tool", "unknown_tool")
        tool_input = getattr(action, "tool_input", "")
        log_text = getattr(action, "log", "")
        result = getattr(action, "result", "")

        input_preview = str(tool_input)[:_PREVIEW_MAX]
        output_preview = str(result)[:_PREVIEW_MAX] if result else ""

        try:
            self._client.log_tool_call(
                tool=str(tool),
                input_data={"tool_input": input_preview},
                output_data={
                    "result_preview": output_preview,
                    "result_length": len(str(result)) if result else 0,
                },
                duration_ms=0,
                status=ActionStatus.SUCCESS,
                metadata={"framework": "crewai", "agent_log": str(log_text)[:200]},
            )
        except Exception:
            logger.warning("Failed to log CrewAI agent action", exc_info=True)

    def _handle_task_output(self, task_output: Any) -> None:
        """Handle a CrewAI TaskOutput (task completion)."""
        if not self._log_task_completions:
            return

        description = getattr(task_output, "description", "")
        raw_output = getattr(task_output, "raw", "")
        agent_name = getattr(task_output, "agent", "")
        summary = getattr(task_output, "summary", "")

        elapsed = self._elapsed(str(description))

        output_text = str(raw_output) if raw_output else str(summary)

        try:
            self._client.log_decision(
                reasoning=f"Task completed: {str(description)[:200]}",
                confidence=1.0,
                input_data={
                    "task_description": str(description)[:_PREVIEW_MAX],
                    "agent": str(agent_name)[:100],
                },
                output_data={
                    "output_preview": output_text[:_PREVIEW_MAX],
                    "output_length": len(output_text),
                },
                duration_ms=elapsed,
                metadata={"framework": "crewai"},
            )
        except Exception:
            logger.warning("Failed to log CrewAI task output", exc_info=True)

    def _handle_unknown_step(self, step_output: Any) -> None:
        """Handle an unknown step type as a generic observation."""
        text = str(step_output)[:_PREVIEW_MAX]

        try:
            self._client.log_observation(
                input_data={"step_type": type(step_output).__name__},
                output_data={"output_preview": text},
                metadata={"framework": "crewai"},
            )
        except Exception:
            logger.warning("Failed to log CrewAI unknown step", exc_info=True)

    def log_error(self, error: Exception, context: str = "") -> None:
        """Log a CrewAI error to the Aegis Ledger."""
        try:
            self._client.log_error(
                tool="crewai",
                input_data={"context": context[:_PREVIEW_MAX]},
                error=error,
                metadata={"framework": "crewai"},
            )
        except Exception:
            logger.warning("Failed to log CrewAI error (secondary failure)", exc_info=True)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _elapsed(self, key: str) -> int:
        """Calculate elapsed time in ms since task started.

        Returns 0 if no start time was recorded or if clock skew
        produced a negative duration.
        """
        with self._times_lock:
            start = self._start_times.pop(key, None)
        if start is None:
            return 0
        return max(0, int(time.time() * 1000) - start)
