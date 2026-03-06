"""Tests for AegisClient.trace() decorator — core function coverage."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from aegis.types import Environment


@pytest.fixture
def tmp_pem(tmp_path):
    """Create a temporary Ed25519 PEM key file."""
    key = Ed25519PrivateKey.generate()
    pem_path = tmp_path / "test_key.pem"
    pem_path.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    return str(pem_path)


@pytest.fixture
def mock_client(tmp_pem):
    """Create an AegisClient with mocked transport."""
    with patch("aegis.client.CanisterTransport") as MockTransport:
        transport_instance = MagicMock()
        transport_instance.spill_count = 0
        transport_instance.call_update.return_value = {"actionId": "act_test123"}
        MockTransport.return_value = transport_instance

        from aegis.client import AegisClient

        client = AegisClient(
            canister_id="test-canister",
            api_key_id="ak_test",
            private_key_path=tmp_pem,
            agent_id="test-agent",
            org_id="test-org",
            environment=Environment(framework="test"),
        )
        client._transport = transport_instance
        return client


class TestTraceDecorator:
    def test_trace_logs_tool_call(self, mock_client):
        """Decorated function triggers log_tool_call via _log."""

        @mock_client.trace()
        def my_tool(x: int) -> int:
            return x * 2

        result = my_tool(5)
        assert result == 10
        # Transport should have been called (addLedgerEntry)
        assert mock_client._transport.call_update.called

    def test_trace_returns_value(self, mock_client):
        """Return value is passed through unchanged."""

        @mock_client.trace()
        def compute(a: int, b: int) -> dict:
            return {"sum": a + b, "product": a * b}

        result = compute(3, 7)
        assert result == {"sum": 10, "product": 21}

    def test_trace_logs_exception(self, mock_client):
        """Exception is logged as error and re-raised."""

        @mock_client.trace()
        def failing_tool() -> None:
            raise ValueError("API timeout")

        with pytest.raises(ValueError, match="API timeout"):
            failing_tool()

        # Should have been called twice: once for the error log
        # (log_error calls _log internally)
        assert mock_client._transport.call_update.call_count >= 1

    def test_trace_records_duration(self, mock_client):
        """duration_ms is > 0 for a function that takes time."""
        calls = []

        def capture_call(method, args):
            calls.append(args)
            return {"actionId": "act_dur_test"}

        mock_client._transport.call_update = capture_call

        @mock_client.trace()
        def slow_tool() -> str:
            time.sleep(0.05)
            return "done"

        slow_tool()
        # The duration_ms is embedded in the Candid args at position 11
        assert len(calls) == 1
        duration_arg = calls[0][11]  # position 11 = duration_ms
        assert duration_arg["value"] >= 40  # at least 40ms

    def test_trace_custom_tool_name(self, mock_client):
        """Custom tool_name overrides the function's qualname."""
        calls = []

        def capture_call(method, args):
            calls.append(args)
            return {"actionId": "act_custom"}

        mock_client._transport.call_update = capture_call

        @mock_client.trace(tool_name="custom.api.call")
        def generic_function() -> str:
            return "ok"

        generic_function()
        assert len(calls) == 1
        # Position 6 = tool name
        tool_arg = calls[0][6]
        assert tool_arg["value"] == "custom.api.call"

    def test_trace_hashes_input_output(self, mock_client):
        """Input and output are SHA-256 hashed, not stored raw."""
        calls = []

        def capture_call(method, args):
            calls.append(args)
            return {"actionId": "act_hash"}

        mock_client._transport.call_update = capture_call

        @mock_client.trace()
        def my_func(query: str) -> dict:
            return {"results": [1, 2, 3]}

        my_func("sensitive query")
        assert len(calls) == 1
        # Position 7 = input_hash, Position 8 = output_hash
        input_hash = calls[0][7]["value"]
        output_hash = calls[0][8]["value"]
        assert input_hash.startswith("sha256:")
        assert output_hash.startswith("sha256:")
        assert len(input_hash) == 71  # "sha256:" + 64 hex chars
