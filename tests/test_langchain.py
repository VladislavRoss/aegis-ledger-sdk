"""Tests for aegis.langchain — LangChain callback handler."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from aegis.langchain import AegisCallbackHandler
from aegis.types import ActionStatus

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_client():
    """Mock AegisClient with all log_* methods."""
    client = MagicMock()
    client.log_decision = MagicMock()
    client.log_tool_call = MagicMock()
    client.log_observation = MagicMock()
    client.log_error = MagicMock()
    return client


@pytest.fixture()
def handler(mock_client):
    return AegisCallbackHandler(mock_client)


@pytest.fixture()
def run_id():
    return uuid4()


# ---------------------------------------------------------------------------
# Init / Config
# ---------------------------------------------------------------------------


class TestInit:
    def test_default_config(self, mock_client):
        h = AegisCallbackHandler(mock_client)
        assert h._log_llm is True
        assert h._log_chains is False
        assert h._log_prompts is False

    def test_custom_config(self, mock_client):
        h = AegisCallbackHandler(
            mock_client, log_llm_calls=False, log_chain_steps=True, log_prompts=True
        )
        assert h._log_llm is False
        assert h._log_chains is True
        assert h._log_prompts is True


# ---------------------------------------------------------------------------
# _elapsed
# ---------------------------------------------------------------------------


class TestElapsed:
    def test_elapsed_without_start_returns_zero(self, handler, run_id):
        assert handler._elapsed(run_id) == 0

    def test_elapsed_with_start_returns_positive(self, handler, run_id):
        handler._start_times[run_id] = 1000
        elapsed = handler._elapsed(run_id)
        assert elapsed > 0

    def test_elapsed_pops_run_id(self, handler, run_id):
        handler._start_times[run_id] = 1000
        handler._elapsed(run_id)
        assert run_id not in handler._start_times


# ---------------------------------------------------------------------------
# LLM callbacks
# ---------------------------------------------------------------------------


class TestLlmStart:
    def test_records_start_time(self, handler, run_id):
        handler.on_llm_start({}, ["prompt"], run_id=run_id)
        assert run_id in handler._start_times
        assert handler._start_times[run_id] > 0


class TestLlmEnd:
    def test_logs_decision(self, handler, mock_client, run_id):
        handler.on_llm_start({}, ["prompt"], run_id=run_id)
        response = SimpleNamespace(
            llm_output={"model_name": "gpt-4", "token_usage": {"total": 100}},
            generations=[[SimpleNamespace(text="Hello world")]],
        )
        handler.on_llm_end(response, run_id=run_id)
        mock_client.log_decision.assert_called_once()
        kw = mock_client.log_decision.call_args.kwargs
        assert "gpt-4" in kw["reasoning"]
        assert kw["confidence"] == 1.0
        assert kw["input_data"]["model"] == "gpt-4"
        assert kw["output_data"]["response_length"] == len("Hello world")

    def test_skipped_when_log_llm_false(self, mock_client, run_id):
        h = AegisCallbackHandler(mock_client, log_llm_calls=False)
        h.on_llm_start({}, ["prompt"], run_id=run_id)
        h.on_llm_end(SimpleNamespace(llm_output=None, generations=[]), run_id=run_id)
        mock_client.log_decision.assert_not_called()

    def test_handles_empty_response(self, handler, mock_client, run_id):
        handler.on_llm_start({}, ["prompt"], run_id=run_id)
        response = SimpleNamespace(llm_output=None, generations=[])
        handler.on_llm_end(response, run_id=run_id)
        mock_client.log_decision.assert_called_once()
        kw = mock_client.log_decision.call_args.kwargs
        assert kw["input_data"]["model"] == ""
        assert kw["output_data"]["response_length"] == 0

    def test_log_prompts_includes_preview(self, mock_client, run_id):
        h = AegisCallbackHandler(mock_client, log_prompts=True)
        h.on_llm_start({}, ["prompt"], run_id=run_id)
        response = SimpleNamespace(
            llm_output=None,
            generations=[[SimpleNamespace(text="A" * 600)]],
        )
        h.on_llm_end(response, run_id=run_id)
        kw = mock_client.log_decision.call_args.kwargs
        assert "response_preview" in kw["output_data"]
        assert len(kw["output_data"]["response_preview"]) == 500

    def test_log_prompts_false_no_preview(self, handler, mock_client, run_id):
        handler.on_llm_start({}, ["prompt"], run_id=run_id)
        response = SimpleNamespace(
            llm_output=None,
            generations=[[SimpleNamespace(text="some text")]],
        )
        handler.on_llm_end(response, run_id=run_id)
        kw = mock_client.log_decision.call_args.kwargs
        assert "response_preview" not in kw["output_data"]

    def test_run_id_in_metadata(self, handler, mock_client, run_id):
        handler.on_llm_start({}, ["prompt"], run_id=run_id)
        handler.on_llm_end(
            SimpleNamespace(llm_output=None, generations=[]), run_id=run_id
        )
        kw = mock_client.log_decision.call_args.kwargs
        assert kw["metadata"]["langchain_run_id"] == str(run_id)


class TestLlmError:
    def test_logs_error(self, handler, mock_client, run_id):
        handler.on_llm_start({}, ["prompt"], run_id=run_id)
        handler.on_llm_error(ValueError("boom"), run_id=run_id)
        mock_client.log_error.assert_called_once()
        kw = mock_client.log_error.call_args.kwargs
        assert kw["tool"] == "llm"
        assert isinstance(kw["error"], Exception)

    def test_base_exception_wrapped(self, handler, mock_client, run_id):
        handler.on_llm_start({}, ["prompt"], run_id=run_id)
        handler.on_llm_error(KeyboardInterrupt("stop"), run_id=run_id)
        kw = mock_client.log_error.call_args.kwargs
        assert isinstance(kw["error"], Exception)


# ---------------------------------------------------------------------------
# Tool callbacks
# ---------------------------------------------------------------------------


class TestToolStart:
    def test_records_start_time(self, handler, run_id):
        handler.on_tool_start({}, "input", run_id=run_id)
        assert run_id in handler._start_times


class TestToolEnd:
    def test_logs_tool_call(self, handler, mock_client, run_id):
        handler.on_tool_start({}, "input", run_id=run_id)
        handler.on_tool_end("result output", run_id=run_id, name="search")
        mock_client.log_tool_call.assert_called_once()
        kw = mock_client.log_tool_call.call_args.kwargs
        assert kw["tool"] == "search"
        assert kw["status"] == ActionStatus.SUCCESS
        assert kw["output_data"]["output_length"] == len("result output")
        assert kw["output_data"]["output_preview"] == "result output"

    def test_output_preview_truncated(self, handler, mock_client, run_id):
        handler.on_tool_start({}, "input", run_id=run_id)
        long_output = "x" * 500
        handler.on_tool_end(long_output, run_id=run_id, name="search")
        kw = mock_client.log_tool_call.call_args.kwargs
        assert len(kw["output_data"]["output_preview"]) == 300

    def test_default_tool_name(self, handler, mock_client, run_id):
        handler.on_tool_start({}, "input", run_id=run_id)
        handler.on_tool_end("output", run_id=run_id)
        kw = mock_client.log_tool_call.call_args.kwargs
        assert kw["tool"] == "unknown_tool"


class TestToolError:
    def test_logs_error_with_tool_name(self, handler, mock_client, run_id):
        handler.on_tool_start({}, "input", run_id=run_id)
        handler.on_tool_error(RuntimeError("fail"), run_id=run_id, name="calculator")
        mock_client.log_error.assert_called_once()
        kw = mock_client.log_error.call_args.kwargs
        assert kw["tool"] == "calculator"

    def test_default_tool_name_on_error(self, handler, mock_client, run_id):
        handler.on_tool_error(RuntimeError("fail"), run_id=run_id)
        kw = mock_client.log_error.call_args.kwargs
        assert kw["tool"] == "unknown_tool"


# ---------------------------------------------------------------------------
# Chain callbacks
# ---------------------------------------------------------------------------


class TestChainStart:
    def test_records_start_time(self, handler, run_id):
        handler.on_chain_start({}, {"input": "x"}, run_id=run_id)
        assert run_id in handler._start_times


class TestChainEnd:
    def test_skipped_by_default(self, handler, mock_client, run_id):
        handler.on_chain_start({}, {"input": "x"}, run_id=run_id)
        handler.on_chain_end({"output": "y"}, run_id=run_id)
        mock_client.log_observation.assert_not_called()

    def test_logs_when_enabled(self, mock_client, run_id):
        h = AegisCallbackHandler(mock_client, log_chain_steps=True)
        h.on_chain_start({}, {"input": "x"}, run_id=run_id)
        h.on_chain_end({"output": "y", "extra": "z"}, run_id=run_id)
        mock_client.log_observation.assert_called_once()
        kw = mock_client.log_observation.call_args.kwargs
        assert set(kw["output_data"]["output_keys"]) == {"output", "extra"}

    def test_handles_empty_outputs(self, mock_client, run_id):
        h = AegisCallbackHandler(mock_client, log_chain_steps=True)
        h.on_chain_start({}, {}, run_id=run_id)
        h.on_chain_end({}, run_id=run_id)
        kw = mock_client.log_observation.call_args.kwargs
        assert kw["output_data"]["output_keys"] == []


class TestChainError:
    def test_logs_error(self, handler, mock_client, run_id):
        handler.on_chain_start({}, {}, run_id=run_id)
        handler.on_chain_error(TypeError("bad"), run_id=run_id)
        mock_client.log_error.assert_called_once()
        kw = mock_client.log_error.call_args.kwargs
        assert kw["tool"] == "chain"


# ---------------------------------------------------------------------------
# Agent callbacks
# ---------------------------------------------------------------------------


class TestAgentAction:
    def test_logs_decision_with_tool_selection(self, handler, mock_client, run_id):
        action = SimpleNamespace(tool="search", tool_input={"q": "test"}, log="Searching...")
        handler.on_agent_action(action, run_id=run_id)
        mock_client.log_decision.assert_called_once()
        kw = mock_client.log_decision.call_args.kwargs
        assert "search" in kw["reasoning"]
        assert kw["confidence"] == 0.0
        assert kw["input_data"]["selected_tool"] == "search"

    def test_handles_missing_attributes(self, handler, mock_client, run_id):
        action = SimpleNamespace()  # no tool, tool_input, log
        handler.on_agent_action(action, run_id=run_id)
        mock_client.log_decision.assert_called_once()
        kw = mock_client.log_decision.call_args.kwargs
        assert "unknown" in kw["reasoning"]

    def test_long_log_truncated(self, handler, mock_client, run_id):
        action = SimpleNamespace(tool="t", tool_input={}, log="A" * 500)
        handler.on_agent_action(action, run_id=run_id)
        kw = mock_client.log_decision.call_args.kwargs
        # log[:200] in reasoning
        assert len(kw["reasoning"]) < 300


class TestAgentFinish:
    def test_logs_decision_with_confidence_1(self, handler, mock_client, run_id):
        finish = SimpleNamespace(return_values={"answer": "42"}, log="Done")
        handler.on_agent_finish(finish, run_id=run_id)
        mock_client.log_decision.assert_called_once()
        kw = mock_client.log_decision.call_args.kwargs
        assert kw["confidence"] == 1.0
        assert "answer" in kw["output_data"]["return_keys"]

    def test_handles_non_dict_return_values(self, handler, mock_client, run_id):
        finish = SimpleNamespace(return_values="just a string", log="")
        handler.on_agent_finish(finish, run_id=run_id)
        kw = mock_client.log_decision.call_args.kwargs
        assert kw["output_data"]["return_keys"] == []

    def test_handles_missing_attributes(self, handler, mock_client, run_id):
        finish = SimpleNamespace()
        handler.on_agent_finish(finish, run_id=run_id)
        mock_client.log_decision.assert_called_once()


# ---------------------------------------------------------------------------
# Timing / elapsed integration
# ---------------------------------------------------------------------------


class TestTimingIntegration:
    def test_duration_passed_to_log_calls(self, handler, mock_client, run_id):
        handler.on_tool_start({}, "input", run_id=run_id)
        handler.on_tool_end("output", run_id=run_id, name="t")
        kw = mock_client.log_tool_call.call_args.kwargs
        assert isinstance(kw["duration_ms"], int)
        assert kw["duration_ms"] >= 0

    def test_no_start_gives_zero_duration(self, handler, mock_client, run_id):
        handler.on_tool_end("output", run_id=run_id, name="t")
        kw = mock_client.log_tool_call.call_args.kwargs
        assert kw["duration_ms"] == 0

    def test_multiple_runs_tracked_independently(self, handler, mock_client):
        r1, r2 = uuid4(), uuid4()
        handler.on_tool_start({}, "a", run_id=r1)
        handler.on_llm_start({}, ["b"], run_id=r2)
        assert r1 in handler._start_times
        assert r2 in handler._start_times
        handler.on_tool_end("a", run_id=r1, name="t1")
        assert r1 not in handler._start_times
        assert r2 in handler._start_times


# ---------------------------------------------------------------------------
# H-1: Memory leak eviction
# ---------------------------------------------------------------------------


class TestMemoryLeakEviction:
    def test_eviction_does_not_trigger_below_threshold(self, handler):
        """_evict_stale_timers should be a no-op below _MAX_PENDING_TIMERS."""
        for _i in range(100):
            handler.on_llm_start({}, ["p"], run_id=uuid4())
        assert len(handler._start_times) == 100

    def test_eviction_removes_stale_entries(self, handler):
        """Entries older than 1h must be evicted when dict exceeds threshold."""
        from aegis.langchain import _MAX_PENDING_TIMERS, _TIMER_TTL_MS

        now = int(__import__("time").time() * 1000)
        # Fill with stale entries (2 hours old)
        for _i in range(_MAX_PENDING_TIMERS + 100):
            handler._start_times[uuid4()] = now - _TIMER_TTL_MS - 1000

        # Add one fresh entry which triggers eviction
        fresh_id = uuid4()
        handler.on_llm_start({}, ["p"], run_id=fresh_id)

        # Stale entries should be evicted, fresh one should remain
        assert fresh_id in handler._start_times
        assert len(handler._start_times) <= 200  # most stale evicted

    def test_fresh_entries_survive_eviction(self, handler):
        """Fresh entries must NOT be evicted even above threshold."""
        from aegis.langchain import _MAX_PENDING_TIMERS

        now = int(__import__("time").time() * 1000)
        # All entries are fresh (within last minute)
        for _i in range(_MAX_PENDING_TIMERS + 50):
            handler._start_times[uuid4()] = now - 1000

        fresh_id = uuid4()
        handler.on_tool_start({}, "x", run_id=fresh_id)

        # All entries are fresh, so none should be evicted
        assert len(handler._start_times) == _MAX_PENDING_TIMERS + 51
