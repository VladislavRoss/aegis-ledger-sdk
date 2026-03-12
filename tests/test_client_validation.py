"""Tests for AegisClient constructor validation and parameter guards."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from aegis.types import Environment
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _make_client(**overrides):
    """Create AegisClient with mocked transport, accepting constructor overrides."""
    with (
        patch("aegis.client.load_private_key", return_value=Ed25519PrivateKey.generate()),
        patch("aegis.client.CanisterTransport") as MockTransport,
    ):
        mock_transport = MockTransport.return_value
        mock_transport.call_update.return_value = {"actionId": "act_v123"}
        mock_transport.spill_count = 0
        mock_transport.drain_spill_buffer.return_value = 0

        from aegis.client import AegisClient

        defaults = dict(
            canister_id="test-canister",
            api_key_id="ak_test",
            private_key_path="./fake.pem",
            agent_id="test-agent",
            org_id="test-org",
            environment=Environment(framework="test"),
        )
        defaults.update(overrides)
        return AegisClient(**defaults)


# ---------------------------------------------------------------------------
# Constructor Validation
# ---------------------------------------------------------------------------


class TestConstructorValidation:
    def test_empty_canister_id_raises(self):
        with pytest.raises(ValueError, match="canister_id"):
            _make_client(canister_id="")

    def test_whitespace_canister_id_raises(self):
        with pytest.raises(ValueError, match="canister_id"):
            _make_client(canister_id="   ")

    def test_empty_api_key_id_raises(self):
        with pytest.raises(ValueError, match="api_key_id"):
            _make_client(api_key_id="")

    def test_empty_agent_id_raises(self):
        with pytest.raises(ValueError, match="agent_id"):
            _make_client(agent_id="")

    def test_metadata_non_str_value_raises(self):
        with pytest.raises(TypeError, match="metadata values must be str"):
            _make_client(metadata={"key": 123})

    def test_valid_metadata_accepted(self):
        client = _make_client(metadata={"env": "prod", "version": "1.0"})
        assert client._default_metadata == {"env": "prod", "version": "1.0"}


# ---------------------------------------------------------------------------
# duration_ms / confidence validation
# ---------------------------------------------------------------------------


class TestParameterValidation:
    def test_negative_duration_raises(self):
        client = _make_client()
        with pytest.raises(ValueError, match="duration_ms"):
            client.log_tool_call(
                tool="test",
                input_data={},
                output_data={},
                duration_ms=-1,
            )

    def test_confidence_above_one_raises(self):
        client = _make_client()
        with pytest.raises(ValueError, match="confidence"):
            client.log_decision(
                reasoning="test",
                confidence=1.5,
                input_data={},
            )

    def test_confidence_below_zero_raises(self):
        client = _make_client()
        with pytest.raises(ValueError, match="confidence"):
            client.log_decision(
                reasoning="test",
                confidence=-0.1,
                input_data={},
            )


# ---------------------------------------------------------------------------
# @trace async guard
# ---------------------------------------------------------------------------


class TestTraceAsyncSupport:
    def test_trace_on_async_function_accepted(self):
        """@trace should accept async functions (async support added in Phase 24)."""
        client = _make_client()

        @client.trace()
        async def my_async_tool(x: int) -> int:
            return x * 2

        # Should not raise — async is now supported
        import inspect
        assert inspect.iscoroutinefunction(my_async_tool)


# ---------------------------------------------------------------------------
# Context manager (close)
# ---------------------------------------------------------------------------


class TestContextManager:
    def test_close_drains_spill(self):
        client = _make_client()
        client.close()
        client._transport.drain_spill_buffer.assert_called_once()

    def test_context_manager_calls_close(self):
        client = _make_client()
        with client:
            pass
        client._transport.drain_spill_buffer.assert_called_once()

    def test_context_manager_returns_self(self):
        client = _make_client()
        with client as c:
            assert c is client
