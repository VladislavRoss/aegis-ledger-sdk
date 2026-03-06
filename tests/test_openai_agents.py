"""Tests for aegis.openai_agents -- OpenAI Agents SDK tracing integration."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from aegis.openai_agents import AegisAgentTracer
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
def tracer(mock_client: MagicMock) -> AegisAgentTracer:
    return AegisAgentTracer(mock_client)


# ---------------------------------------------------------------------------
# Init / Config
# ---------------------------------------------------------------------------


class TestInit:
    def test_default_config(self, mock_client: MagicMock) -> None:
        t = AegisAgentTracer(mock_client)
        assert t._log_handoffs is True
        assert t._log_guardrails is True

    def test_custom_config(self, mock_client: MagicMock) -> None:
        t = AegisAgentTracer(
            mock_client, log_handoffs=False, log_guardrails=False,
        )
        assert t._log_handoffs is False
        assert t._log_guardrails is False

    def test_no_active_trace(self, tracer: AegisAgentTracer) -> None:
        assert tracer._active_trace_id is None


# ---------------------------------------------------------------------------
# Context manager (trace)
# ---------------------------------------------------------------------------


class TestTrace:
    def test_yields_trace_id(self, tracer: AegisAgentTracer) -> None:
        with tracer.trace() as tid:
            assert tid.startswith("oai_")
            assert len(tid) > 4

    def test_custom_trace_id(self, tracer: AegisAgentTracer) -> None:
        with tracer.trace(trace_id="custom_123") as tid:
            assert tid == "custom_123"

    def test_active_trace_id_set_inside(
        self, tracer: AegisAgentTracer
    ) -> None:
        with tracer.trace() as tid:
            assert tracer._active_trace_id == tid

    def test_active_trace_id_cleared_after(
        self, tracer: AegisAgentTracer
    ) -> None:
        with tracer.trace():
            pass
        assert tracer._active_trace_id is None

    def test_logs_completion_on_success(
        self, tracer: AegisAgentTracer, mock_client: MagicMock
    ) -> None:
        with tracer.trace():
            pass
        mock_client.log_decision.assert_called_once()
        kw = mock_client.log_decision.call_args.kwargs
        assert kw["reasoning"] == "OpenAI Agents run completed"
        assert kw["confidence"] == 1.0
        assert kw["output_data"]["status"] == "completed"

    def test_logs_error_on_exception(
        self, tracer: AegisAgentTracer, mock_client: MagicMock
    ) -> None:
        with pytest.raises(ValueError, match="test error"), tracer.trace():
            raise ValueError("test error")
        mock_client.log_error.assert_called_once()
        kw = mock_client.log_error.call_args.kwargs
        assert kw["tool"] == "openai_agents"
        assert isinstance(kw["error"], ValueError)

    def test_no_decision_on_exception(
        self, tracer: AegisAgentTracer, mock_client: MagicMock
    ) -> None:
        with pytest.raises(ValueError), tracer.trace():
            raise ValueError("boom")
        mock_client.log_decision.assert_not_called()

    def test_trace_id_cleared_on_exception(
        self, tracer: AegisAgentTracer
    ) -> None:
        with pytest.raises(RuntimeError), tracer.trace():
            raise RuntimeError("fail")
        assert tracer._active_trace_id is None

    def test_duration_in_completion(
        self, tracer: AegisAgentTracer, mock_client: MagicMock
    ) -> None:
        with tracer.trace():
            pass
        kw = mock_client.log_decision.call_args.kwargs
        assert isinstance(kw["duration_ms"], int)
        assert kw["duration_ms"] >= 0


# ---------------------------------------------------------------------------
# Tool call logging
# ---------------------------------------------------------------------------


class TestToolCall:
    def test_logs_tool_call(
        self, tracer: AegisAgentTracer, mock_client: MagicMock
    ) -> None:
        tracer.log_tool_call(
            "get_weather", input_data={"city": "Zurich"}, output_data="25C",
        )
        mock_client.log_tool_call.assert_called_once()
        kw = mock_client.log_tool_call.call_args.kwargs
        assert kw["tool"] == "get_weather"
        assert kw["status"] == ActionStatus.SUCCESS

    def test_custom_status(
        self, tracer: AegisAgentTracer, mock_client: MagicMock
    ) -> None:
        tracer.log_tool_call("fail_tool", status=ActionStatus.ERROR)
        kw = mock_client.log_tool_call.call_args.kwargs
        assert kw["status"] == ActionStatus.ERROR

    def test_output_preview_truncated(
        self, tracer: AegisAgentTracer, mock_client: MagicMock
    ) -> None:
        tracer.log_tool_call("t", output_data="x" * 500)
        kw = mock_client.log_tool_call.call_args.kwargs
        assert len(kw["output_data"]["output_preview"]) == 300

    def test_none_input_output(
        self, tracer: AegisAgentTracer, mock_client: MagicMock
    ) -> None:
        tracer.log_tool_call("t")
        kw = mock_client.log_tool_call.call_args.kwargs
        assert kw["input_data"]["tool_input"] == ""
        assert kw["output_data"]["output_length"] == 0

    def test_log_failure_suppressed(
        self, tracer: AegisAgentTracer, mock_client: MagicMock
    ) -> None:
        mock_client.log_tool_call.side_effect = RuntimeError("network")
        # Should not raise
        tracer.log_tool_call("t", input_data="x")


# ---------------------------------------------------------------------------
# Handoff logging
# ---------------------------------------------------------------------------


class TestHandoff:
    def test_logs_handoff(
        self, tracer: AegisAgentTracer, mock_client: MagicMock
    ) -> None:
        tracer.log_handoff("agent_a", "agent_b", reason="Needs specialist")
        mock_client.log_decision.assert_called_once()
        kw = mock_client.log_decision.call_args.kwargs
        assert "agent_a" in kw["reasoning"]
        assert "agent_b" in kw["reasoning"]
        assert kw["input_data"]["from_agent"] == "agent_a"
        assert kw["input_data"]["to_agent"] == "agent_b"

    def test_skipped_when_disabled(self, mock_client: MagicMock) -> None:
        t = AegisAgentTracer(mock_client, log_handoffs=False)
        t.log_handoff("a", "b")
        mock_client.log_decision.assert_not_called()


# ---------------------------------------------------------------------------
# Guardrail logging
# ---------------------------------------------------------------------------


class TestGuardrail:
    def test_logs_guardrail_pass(
        self, tracer: AegisAgentTracer, mock_client: MagicMock
    ) -> None:
        tracer.log_guardrail("content_filter", passed=True, details="Clean")
        mock_client.log_observation.assert_called_once()
        kw = mock_client.log_observation.call_args.kwargs
        assert kw["input_data"]["guardrail"] == "content_filter"
        assert kw["input_data"]["passed"] is True

    def test_logs_guardrail_fail(
        self, tracer: AegisAgentTracer, mock_client: MagicMock
    ) -> None:
        tracer.log_guardrail("pii_check", passed=False, details="PII detected")
        kw = mock_client.log_observation.call_args.kwargs
        assert kw["input_data"]["passed"] is False
        assert kw["output_data"]["details"] == "PII detected"

    def test_skipped_when_disabled(self, mock_client: MagicMock) -> None:
        t = AegisAgentTracer(mock_client, log_guardrails=False)
        t.log_guardrail("check", passed=True)
        mock_client.log_observation.assert_not_called()


# ---------------------------------------------------------------------------
# Explicit error logging
# ---------------------------------------------------------------------------


class TestLogError:
    def test_logs_error(
        self, tracer: AegisAgentTracer, mock_client: MagicMock
    ) -> None:
        tracer.log_error(ValueError("boom"), context="during tool call")
        mock_client.log_error.assert_called_once()
        kw = mock_client.log_error.call_args.kwargs
        assert kw["tool"] == "openai_agents"
        assert isinstance(kw["error"], ValueError)


# ---------------------------------------------------------------------------
# Trace metadata
# ---------------------------------------------------------------------------


class TestTraceMetadata:
    def test_metadata_includes_framework(
        self, tracer: AegisAgentTracer
    ) -> None:
        meta = tracer._trace_metadata()
        assert meta["framework"] == "openai_agents"

    def test_metadata_includes_trace_id_when_active(
        self, tracer: AegisAgentTracer
    ) -> None:
        with tracer.trace(trace_id="abc"):
            meta = tracer._trace_metadata()
            assert meta["trace_id"] == "abc"

    def test_metadata_no_trace_id_when_inactive(
        self, tracer: AegisAgentTracer
    ) -> None:
        meta = tracer._trace_metadata()
        assert "trace_id" not in meta


# ---------------------------------------------------------------------------
# Elapsed timing
# ---------------------------------------------------------------------------


class TestElapsed:
    def test_elapsed_without_start_returns_zero(
        self, tracer: AegisAgentTracer
    ) -> None:
        assert tracer._elapsed("nonexistent") == 0

    def test_elapsed_with_start_returns_positive(
        self, tracer: AegisAgentTracer
    ) -> None:
        tracer._start_times["key"] = 1000
        elapsed = tracer._elapsed("key")
        assert elapsed > 0

    def test_elapsed_pops_key(self, tracer: AegisAgentTracer) -> None:
        tracer._start_times["key"] = 1000
        tracer._elapsed("key")
        assert "key" not in tracer._start_times
