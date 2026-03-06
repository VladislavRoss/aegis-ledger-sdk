"""Tests for aegis.crewai -- CrewAI step callback integration."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from aegis.crewai import AegisCrewCallback
from aegis.types import ActionStatus  # noqa: F401

# ---------------------------------------------------------------------------
# Mock CrewAI types (lightweight stand-ins)
# ---------------------------------------------------------------------------


class AgentAction:
    """Stand-in for crewai.AgentAction."""

    def __init__(self, **kwargs: object) -> None:
        for k, v in kwargs.items():
            setattr(self, k, v)


class TaskOutput:
    """Stand-in for crewai.TaskOutput."""

    def __init__(self, **kwargs: object) -> None:
        for k, v in kwargs.items():
            setattr(self, k, v)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_client() -> MagicMock:
    """Mock AegisClient with all log_* methods."""
    client = MagicMock()
    client.log_decision = MagicMock()
    client.log_tool_call = MagicMock()
    client.log_observation = MagicMock()
    client.log_error = MagicMock()
    return client


@pytest.fixture()
def callback(mock_client: MagicMock) -> AegisCrewCallback:
    return AegisCrewCallback(mock_client)


# ---------------------------------------------------------------------------
# Init / Config
# ---------------------------------------------------------------------------


class TestInit:
    def test_default_config(self, mock_client: MagicMock) -> None:
        cb = AegisCrewCallback(mock_client)
        assert cb._log_task_completions is True

    def test_custom_config(self, mock_client: MagicMock) -> None:
        cb = AegisCrewCallback(mock_client, log_task_completions=False)
        assert cb._log_task_completions is False

    def test_callable(self, callback: AegisCrewCallback) -> None:
        assert callable(callback)


# ---------------------------------------------------------------------------
# AgentAction handling
# ---------------------------------------------------------------------------


class TestAgentAction:
    def test_logs_tool_call(
        self, callback: AegisCrewCallback, mock_client: MagicMock
    ) -> None:
        action = AgentAction(
            tool="search", tool_input="query=test",
            log="Searching", result="found it",
        )
        callback(action)
        mock_client.log_tool_call.assert_called_once()
        kw = mock_client.log_tool_call.call_args.kwargs
        assert kw["tool"] == "search"
        assert kw["status"] == ActionStatus.SUCCESS

    def test_input_preview_truncated(
        self, callback: AegisCrewCallback, mock_client: MagicMock
    ) -> None:
        action = AgentAction(tool="t", tool_input="x" * 500, log="", result="")
        callback(action)
        kw = mock_client.log_tool_call.call_args.kwargs
        assert len(kw["input_data"]["tool_input"]) == 300

    def test_handles_missing_attributes(
        self, callback: AegisCrewCallback, mock_client: MagicMock
    ) -> None:
        action = AgentAction()
        callback(action)
        mock_client.log_tool_call.assert_called_once()
        kw = mock_client.log_tool_call.call_args.kwargs
        assert kw["tool"] == "unknown_tool"

    def test_result_preview_in_output(
        self, callback: AegisCrewCallback, mock_client: MagicMock
    ) -> None:
        action = AgentAction(tool="calc", tool_input="2+2", log="", result="4")
        callback(action)
        kw = mock_client.log_tool_call.call_args.kwargs
        assert kw["output_data"]["result_preview"] == "4"
        assert kw["output_data"]["result_length"] == 1

    def test_log_failure_suppressed(
        self, callback: AegisCrewCallback, mock_client: MagicMock
    ) -> None:
        mock_client.log_tool_call.side_effect = RuntimeError("network")
        action = AgentAction(tool="t", tool_input="", log="", result="")
        # Should not raise
        callback(action)


# ---------------------------------------------------------------------------
# TaskOutput handling
# ---------------------------------------------------------------------------


class TestTaskOutput:
    def test_logs_decision(
        self, callback: AegisCrewCallback, mock_client: MagicMock
    ) -> None:
        task = TaskOutput(
            description="Research AI", raw="Results here",
            agent="researcher", summary="Done",
        )
        callback(task)
        mock_client.log_decision.assert_called_once()
        kw = mock_client.log_decision.call_args.kwargs
        assert "Research AI" in kw["reasoning"]
        assert kw["confidence"] == 1.0

    def test_skipped_when_disabled(self, mock_client: MagicMock) -> None:
        cb = AegisCrewCallback(mock_client, log_task_completions=False)
        task = TaskOutput(description="Task", raw="Output", agent="a", summary="s")
        cb(task)
        mock_client.log_decision.assert_not_called()

    def test_output_preview_truncated(
        self, callback: AegisCrewCallback, mock_client: MagicMock
    ) -> None:
        task = TaskOutput(description="D", raw="R" * 500, agent="a", summary="")
        callback(task)
        kw = mock_client.log_decision.call_args.kwargs
        assert len(kw["output_data"]["output_preview"]) == 300

    def test_uses_summary_when_raw_empty(
        self, callback: AegisCrewCallback, mock_client: MagicMock
    ) -> None:
        task = TaskOutput(description="D", raw="", agent="a", summary="Summary text")
        callback(task)
        kw = mock_client.log_decision.call_args.kwargs
        assert "Summary text" in kw["output_data"]["output_preview"]


# ---------------------------------------------------------------------------
# Unknown step type
# ---------------------------------------------------------------------------


class TestUnknownStep:
    def test_logs_observation(
        self, callback: AegisCrewCallback, mock_client: MagicMock
    ) -> None:
        step = {"some": "data"}
        callback(step)
        mock_client.log_observation.assert_called_once()
        kw = mock_client.log_observation.call_args.kwargs
        assert kw["input_data"]["step_type"] == "dict"


# ---------------------------------------------------------------------------
# Task timing
# ---------------------------------------------------------------------------


class TestTiming:
    def test_start_task_records_time(self, callback: AegisCrewCallback) -> None:
        callback.start_task("my task")
        assert "my task" in callback._start_times
        assert callback._start_times["my task"] > 0

    def test_elapsed_without_start_returns_zero(
        self, callback: AegisCrewCallback
    ) -> None:
        assert callback._elapsed("nonexistent") == 0

    def test_elapsed_with_start_returns_positive(
        self, callback: AegisCrewCallback
    ) -> None:
        callback._start_times["key"] = 1000
        elapsed = callback._elapsed("key")
        assert elapsed > 0

    def test_elapsed_pops_key(self, callback: AegisCrewCallback) -> None:
        callback._start_times["key"] = 1000
        callback._elapsed("key")
        assert "key" not in callback._start_times

    def test_task_timing_flows_to_decision(
        self, callback: AegisCrewCallback, mock_client: MagicMock
    ) -> None:
        callback.start_task("Research AI")
        task = TaskOutput(
            description="Research AI", raw="Done", agent="a", summary="",
        )
        callback(task)
        kw = mock_client.log_decision.call_args.kwargs
        assert isinstance(kw["duration_ms"], int)
        assert kw["duration_ms"] >= 0


# ---------------------------------------------------------------------------
# Explicit error logging
# ---------------------------------------------------------------------------


class TestLogError:
    def test_logs_error(
        self, callback: AegisCrewCallback, mock_client: MagicMock
    ) -> None:
        callback.log_error(ValueError("boom"), context="during research")
        mock_client.log_error.assert_called_once()
        kw = mock_client.log_error.call_args.kwargs
        assert kw["tool"] == "crewai"
        assert isinstance(kw["error"], ValueError)
        assert kw["input_data"]["context"] == "during research"
