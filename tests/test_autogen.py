"""Tests for aegis.autogen -- AutoGen/AG2 message hook integration."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from aegis.autogen import AegisAutoGenHook
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
def hook(mock_client: MagicMock) -> AegisAutoGenHook:
    return AegisAutoGenHook(mock_client)


# ---------------------------------------------------------------------------
# Init / Config
# ---------------------------------------------------------------------------


class TestInit:
    def test_default_config(self, mock_client: MagicMock) -> None:
        h = AegisAutoGenHook(mock_client)
        assert h._log_messages is True
        assert h._log_tool_calls is True

    def test_custom_config(self, mock_client: MagicMock) -> None:
        h = AegisAutoGenHook(
            mock_client, log_messages=False, log_tool_calls=False,
        )
        assert h._log_messages is False
        assert h._log_tool_calls is False


# ---------------------------------------------------------------------------
# Message sent
# ---------------------------------------------------------------------------


class TestMessageSent:
    def test_logs_observation(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        hook.on_message_sent("user", "assistant", "Hello there")
        mock_client.log_observation.assert_called_once()
        kw = mock_client.log_observation.call_args.kwargs
        assert kw["input_data"]["sender"] == "user"
        assert kw["input_data"]["receiver"] == "assistant"
        assert kw["output_data"]["content_preview"] == "Hello there"
        assert kw["metadata"]["direction"] == "sent"

    def test_skipped_when_disabled(self, mock_client: MagicMock) -> None:
        h = AegisAutoGenHook(mock_client, log_messages=False)
        h.on_message_sent("a", "b", "msg")
        mock_client.log_observation.assert_not_called()

    def test_content_truncated(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        hook.on_message_sent("a", "b", "x" * 500)
        kw = mock_client.log_observation.call_args.kwargs
        assert len(kw["output_data"]["content_preview"]) == 300

    def test_dict_message_extracts_content(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        hook.on_message_sent(
            "a", "b", {"content": "dict message", "role": "user"},
        )
        kw = mock_client.log_observation.call_args.kwargs
        assert kw["output_data"]["content_preview"] == "dict message"

    def test_log_failure_suppressed(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        mock_client.log_observation.side_effect = RuntimeError("network")
        # Should not raise
        hook.on_message_sent("a", "b", "msg")


# ---------------------------------------------------------------------------
# Message received
# ---------------------------------------------------------------------------


class TestMessageReceived:
    def test_logs_observation(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        hook.on_message_received("assistant", "user", "Response")
        mock_client.log_observation.assert_called_once()
        kw = mock_client.log_observation.call_args.kwargs
        assert kw["metadata"]["direction"] == "received"

    def test_skipped_when_disabled(self, mock_client: MagicMock) -> None:
        h = AegisAutoGenHook(mock_client, log_messages=False)
        h.on_message_received("a", "b", "msg")
        mock_client.log_observation.assert_not_called()


# ---------------------------------------------------------------------------
# Tool call / result
# ---------------------------------------------------------------------------


class TestToolCall:
    def test_records_start_time(self, hook: AegisAutoGenHook) -> None:
        hook.on_tool_call("search", arguments={"q": "test"}, caller="assistant")
        assert "assistant:search" in hook._start_times

    def test_logs_tool_result(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        hook.on_tool_call("search", caller="assistant")
        hook.on_tool_result("search", result="found 5 results", caller="assistant")
        mock_client.log_tool_call.assert_called_once()
        kw = mock_client.log_tool_call.call_args.kwargs
        assert kw["tool"] == "search"
        assert kw["status"] == ActionStatus.SUCCESS
        assert "found 5 results" in kw["output_data"]["result_preview"]

    def test_custom_status(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        hook.on_tool_result("t", status=ActionStatus.ERROR)
        kw = mock_client.log_tool_call.call_args.kwargs
        assert kw["status"] == ActionStatus.ERROR

    def test_result_truncated(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        hook.on_tool_result("t", result="y" * 500)
        kw = mock_client.log_tool_call.call_args.kwargs
        assert len(kw["output_data"]["result_preview"]) == 300

    def test_skipped_when_disabled(self, mock_client: MagicMock) -> None:
        h = AegisAutoGenHook(mock_client, log_tool_calls=False)
        h.on_tool_result("t", result="r")
        mock_client.log_tool_call.assert_not_called()

    def test_timing_flows_to_duration(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        hook.on_tool_call("t", caller="c")
        hook.on_tool_result("t", result="r", caller="c")
        kw = mock_client.log_tool_call.call_args.kwargs
        assert isinstance(kw["duration_ms"], int)
        assert kw["duration_ms"] >= 0

    def test_no_start_gives_zero_duration(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        hook.on_tool_result("t", result="r", caller="c")
        kw = mock_client.log_tool_call.call_args.kwargs
        assert kw["duration_ms"] == 0


# ---------------------------------------------------------------------------
# Completion
# ---------------------------------------------------------------------------


class TestCompletion:
    def test_logs_decision(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        hook.on_completion(
            "assistant", summary="Task done", chat_history_length=10,
        )
        mock_client.log_decision.assert_called_once()
        kw = mock_client.log_decision.call_args.kwargs
        assert "assistant" in kw["reasoning"]
        assert kw["confidence"] == 1.0
        assert kw["input_data"]["chat_history_length"] == 10
        assert kw["output_data"]["summary"] == "Task done"

    def test_summary_truncated(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        hook.on_completion("a", summary="s" * 500)
        kw = mock_client.log_decision.call_args.kwargs
        assert len(kw["output_data"]["summary"]) == 300


# ---------------------------------------------------------------------------
# Error logging
# ---------------------------------------------------------------------------


class TestLogError:
    def test_logs_error(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        hook.log_error(
            ValueError("boom"), agent_name="assistant", context="during chat",
        )
        mock_client.log_error.assert_called_once()
        kw = mock_client.log_error.call_args.kwargs
        assert kw["tool"] == "autogen:assistant"
        assert isinstance(kw["error"], ValueError)

    def test_no_agent_name(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        hook.log_error(RuntimeError("fail"))
        kw = mock_client.log_error.call_args.kwargs
        assert kw["tool"] == "autogen"

    def test_log_error_fail_open(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        """log_error() should not raise even if client.log_error() fails."""
        mock_client.log_error.side_effect = RuntimeError("connection lost")
        # Should NOT raise
        hook.log_error(ValueError("original"), agent_name="bot")


# ---------------------------------------------------------------------------
# Extract content
# ---------------------------------------------------------------------------


class TestExtractContent:
    def test_string_message(self) -> None:
        assert AegisAutoGenHook._extract_content("hello") == "hello"

    def test_dict_message(self) -> None:
        assert AegisAutoGenHook._extract_content({"content": "world"}) == "world"

    def test_dict_without_content(self) -> None:
        assert AegisAutoGenHook._extract_content({"role": "user"}) == ""

    def test_other_type_returns_type_name(self) -> None:
        """Non-str/dict types return type name to prevent data leakage."""
        assert AegisAutoGenHook._extract_content(42) == "<int>"
        assert AegisAutoGenHook._extract_content([1, 2, 3]) == "<list>"

    def test_string_truncation(self) -> None:
        """Long strings are truncated at _PREVIEW_MAX."""
        long_msg = "x" * 500
        result = AegisAutoGenHook._extract_content(long_msg)
        assert len(result) == 300  # _PREVIEW_MAX


# ---------------------------------------------------------------------------
# Elapsed timing
# ---------------------------------------------------------------------------


class TestElapsed:
    def test_elapsed_without_start_returns_zero(
        self, hook: AegisAutoGenHook
    ) -> None:
        assert hook._elapsed("nonexistent") == 0

    def test_elapsed_with_start_returns_positive(
        self, hook: AegisAutoGenHook
    ) -> None:
        hook._start_times["key"] = 1000
        elapsed = hook._elapsed("key")
        assert elapsed > 0

    def test_elapsed_pops_key(self, hook: AegisAutoGenHook) -> None:
        hook._start_times["key"] = 1000
        hook._elapsed("key")
        assert "key" not in hook._start_times


# ---------------------------------------------------------------------------
# Batch 7: Edge Cases (Phase 23)
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_concurrent_tool_calls_thread_safe(
        self, mock_client: MagicMock
    ) -> None:
        """10 concurrent on_tool_call invocations must not lose any calls."""
        import threading

        hook = AegisAutoGenHook(mock_client)
        errors: list[Exception] = []

        def call_tool(i: int) -> None:
            try:
                hook.on_tool_call(
                    tool_name=f"tool_{i}",
                    arguments={"idx": i},
                    caller=f"agent_{i}",
                )
                hook.on_tool_result(
                    tool_name=f"tool_{i}",
                    result=f"result_{i}",
                    caller=f"agent_{i}",
                )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=call_tool, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        # All 10 tool calls should have been logged
        assert mock_client.log_tool_call.call_count == 10

    def test_on_tool_result_with_none_result(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        """on_tool_result with result=None should produce empty preview."""
        hook.on_tool_call(tool_name="void_tool", arguments={}, caller="bot")
        hook.on_tool_result(tool_name="void_tool", result=None, caller="bot")

        kw = mock_client.log_tool_call.call_args.kwargs
        assert kw["output_data"]["result_preview"] == ""
        assert kw["output_data"]["result_length"] == 0

    def test_on_completion_without_summary(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        """on_completion with empty summary should still log decision."""
        hook.on_completion(agent_name="bot", summary="")
        mock_client.log_decision.assert_called_once()
        kw = mock_client.log_decision.call_args.kwargs
        assert kw["reasoning"] == "AutoGen conversation completed by bot"
        assert kw["output_data"]["summary"] == ""

    def test_large_message_truncation(
        self, hook: AegisAutoGenHook, mock_client: MagicMock
    ) -> None:
        """Large message body (100KB) should be truncated to _PREVIEW_MAX."""
        large_msg = "x" * 100_000
        hook.on_message_sent("user", "bot", large_msg)
        kw = mock_client.log_observation.call_args.kwargs
        # input_data should be truncated
        assert len(str(kw["input_data"])) <= 300 + 50  # some margin for dict formatting
