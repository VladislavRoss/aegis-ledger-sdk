"""Tests for aegis.anthropic_sdk -- Anthropic Agent SDK tracing integration."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest
from aegis.anthropic_sdk import AegisAnthropicTracer
from aegis.types import ActionStatus

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
def tracer(mock_client: MagicMock) -> AegisAnthropicTracer:
    return AegisAnthropicTracer(mock_client)


# ---------------------------------------------------------------------------
# Init / Config
# ---------------------------------------------------------------------------


class TestInit:
    def test_default_config(self, mock_client: MagicMock) -> None:
        t = AegisAnthropicTracer(mock_client)
        assert t._log_tool_calls is True
        assert t._log_subagents is True

    def test_custom_config(self, mock_client: MagicMock) -> None:
        t = AegisAnthropicTracer(
            mock_client, log_tool_calls=False, log_subagents=False,
        )
        assert t._log_tool_calls is False
        assert t._log_subagents is False


# ---------------------------------------------------------------------------
# Tool use logging (PostToolUse)
# ---------------------------------------------------------------------------


class TestToolUse:
    def test_logs_tool_call(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        tracer.on_tool_use(
            "search", tool_input={"query": "test"}, tool_response="result",
        )
        mock_client.log_tool_call.assert_called_once()
        kw = mock_client.log_tool_call.call_args.kwargs
        assert kw["tool"] == "search"
        assert kw["status"] == ActionStatus.SUCCESS
        assert kw["metadata"]["framework"] == "anthropic_sdk"

    def test_custom_status(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        tracer.on_tool_use("fail_tool", status=ActionStatus.ERROR)
        kw = mock_client.log_tool_call.call_args.kwargs
        assert kw["status"] == ActionStatus.ERROR

    def test_tool_use_id_passed(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        tracer.on_tool_use("t", tool_use_id="tu_abc123")
        kw = mock_client.log_tool_call.call_args.kwargs
        assert kw["input_data"]["tool_use_id"] == "tu_abc123"

    def test_response_preview_truncated(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        tracer.on_tool_use("t", tool_response="x" * 500)
        kw = mock_client.log_tool_call.call_args.kwargs
        assert len(kw["output_data"]["response_preview"]) == 300

    def test_none_input_response(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        tracer.on_tool_use("t")
        kw = mock_client.log_tool_call.call_args.kwargs
        assert kw["input_data"]["tool_input"] == ""
        assert kw["output_data"]["response_length"] == 0

    def test_skipped_when_disabled(self, mock_client: MagicMock) -> None:
        t = AegisAnthropicTracer(mock_client, log_tool_calls=False)
        t.on_tool_use("search", tool_input="x")
        mock_client.log_tool_call.assert_not_called()

    def test_log_failure_suppressed(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        mock_client.log_tool_call.side_effect = RuntimeError("network")
        tracer.on_tool_use("t", tool_input="x")  # Should not raise


# ---------------------------------------------------------------------------
# Session hooks
# ---------------------------------------------------------------------------


class TestSession:
    def test_session_start_logs_observation(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        tracer.on_session_start("sess_001")
        mock_client.log_observation.assert_called_once()
        kw = mock_client.log_observation.call_args.kwargs
        assert kw["input_data"]["event"] == "session_start"
        assert kw["input_data"]["session_id"] == "sess_001"
        assert kw["metadata"]["framework"] == "anthropic_sdk"

    def test_session_start_records_timer(
        self, tracer: AegisAnthropicTracer,
    ) -> None:
        tracer.on_session_start("sess_002")
        assert "session:sess_002" in tracer._start_times

    def test_session_end_logs_decision(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        tracer.on_session_start("sess_003")
        tracer.on_session_end("sess_003")
        mock_client.log_decision.assert_called_once()
        kw = mock_client.log_decision.call_args.kwargs
        assert kw["reasoning"] == "Anthropic Agent session completed"
        assert kw["input_data"]["event"] == "session_end"
        assert isinstance(kw["duration_ms"], int)
        assert kw["duration_ms"] >= 0

    def test_session_end_without_start(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        tracer.on_session_end("unknown")
        kw = mock_client.log_decision.call_args.kwargs
        assert kw["duration_ms"] == 0

    def test_session_start_failure_suppressed(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        mock_client.log_observation.side_effect = RuntimeError("fail")
        tracer.on_session_start("s1")  # Should not raise

    def test_session_end_failure_suppressed(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        mock_client.log_decision.side_effect = RuntimeError("fail")
        tracer.on_session_end("s1")  # Should not raise


# ---------------------------------------------------------------------------
# Subagent hooks
# ---------------------------------------------------------------------------


class TestSubagent:
    def test_subagent_start_logs_observation(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        tracer.on_subagent_start("sub_1", "researcher")
        mock_client.log_observation.assert_called_once()
        kw = mock_client.log_observation.call_args.kwargs
        assert kw["input_data"]["agent_id"] == "sub_1"
        assert kw["input_data"]["agent_type"] == "researcher"

    def test_subagent_start_records_timer(
        self, tracer: AegisAnthropicTracer,
    ) -> None:
        tracer.on_subagent_start("sub_2")
        assert "sub:sub_2" in tracer._start_times

    def test_subagent_end_logs_decision(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        tracer.on_subagent_start("sub_3", "coder")
        tracer.on_subagent_end("sub_3", "coder")
        mock_client.log_decision.assert_called_once()
        kw = mock_client.log_decision.call_args.kwargs
        assert "coder" in kw["reasoning"]
        assert kw["input_data"]["event"] == "subagent_end"
        assert isinstance(kw["duration_ms"], int)

    def test_subagent_end_without_start(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        tracer.on_subagent_end("unknown")
        kw = mock_client.log_decision.call_args.kwargs
        assert kw["duration_ms"] == 0

    def test_skipped_when_disabled(self, mock_client: MagicMock) -> None:
        t = AegisAnthropicTracer(mock_client, log_subagents=False)
        t.on_subagent_start("sub_x")
        t.on_subagent_end("sub_x")
        mock_client.log_observation.assert_not_called()
        mock_client.log_decision.assert_not_called()


# ---------------------------------------------------------------------------
# Stop hook
# ---------------------------------------------------------------------------


class TestStop:
    def test_logs_stop_decision(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        tracer.on_stop(session_id="sess_x", summary="Task completed")
        mock_client.log_decision.assert_called_once()
        kw = mock_client.log_decision.call_args.kwargs
        assert kw["reasoning"] == "Anthropic Agent run stopped"
        assert kw["output_data"]["summary"] == "Task completed"

    def test_summary_truncated(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        tracer.on_stop(summary="x" * 500)
        kw = mock_client.log_decision.call_args.kwargs
        assert len(kw["output_data"]["summary"]) == 300

    def test_stop_with_session_timing(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        tracer.on_session_start("sess_y")
        tracer.on_stop(session_id="sess_y")
        kw = mock_client.log_decision.call_args.kwargs
        assert kw["duration_ms"] >= 0


# ---------------------------------------------------------------------------
# Error logging
# ---------------------------------------------------------------------------


class TestLogError:
    def test_logs_error(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        tracer.log_error(ValueError("boom"), context="during tool call")
        mock_client.log_error.assert_called_once()
        kw = mock_client.log_error.call_args.kwargs
        assert kw["tool"] == "anthropic_sdk"
        assert isinstance(kw["error"], ValueError)
        assert kw["metadata"]["framework"] == "anthropic_sdk"

    def test_context_truncated(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        tracer.log_error(RuntimeError("x"), context="c" * 500)
        kw = mock_client.log_error.call_args.kwargs
        assert len(kw["input_data"]["context"]) == 300

    def test_error_failure_suppressed(
        self, tracer: AegisAnthropicTracer, mock_client: MagicMock,
    ) -> None:
        mock_client.log_error.side_effect = RuntimeError("double fault")
        tracer.log_error(ValueError("original"))  # Should not raise


# ---------------------------------------------------------------------------
# Elapsed timing
# ---------------------------------------------------------------------------


class TestElapsed:
    def test_elapsed_without_start_returns_zero(
        self, tracer: AegisAnthropicTracer,
    ) -> None:
        assert tracer._elapsed("nonexistent") == 0

    def test_elapsed_with_start_returns_positive(
        self, tracer: AegisAnthropicTracer,
    ) -> None:
        tracer._start_times["key"] = 1000
        elapsed = tracer._elapsed("key")
        assert elapsed > 0

    def test_elapsed_pops_key(self, tracer: AegisAnthropicTracer) -> None:
        tracer._start_times["key"] = 1000
        tracer._elapsed("key")
        assert "key" not in tracer._start_times


# ---------------------------------------------------------------------------
# Eviction
# ---------------------------------------------------------------------------


class TestEviction:
    def test_no_eviction_under_threshold(
        self, tracer: AegisAnthropicTracer,
    ) -> None:
        tracer._start_times["a"] = int(time.time() * 1000)
        tracer._evict_stale_timers()
        assert "a" in tracer._start_times

    def test_eviction_over_threshold(
        self, tracer: AegisAnthropicTracer,
    ) -> None:
        old_ts = int(time.time() * 1000) - 7_200_000  # 2h ago
        for i in range(10_001):
            tracer._start_times[f"key_{i}"] = old_ts
        tracer._evict_stale_timers()
        assert len(tracer._start_times) == 0
