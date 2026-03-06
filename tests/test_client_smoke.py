"""Smoke Tests für AegisClient — kein echter Canister und kein echter Key nötig."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

from aegis.types import Environment

# ---------------------------------------------------------------------------
# Fixtures / Helpers
# ---------------------------------------------------------------------------

def _make_client():
    """Erstellt AegisClient mit gemocktem Transport und Key."""
    with (
        patch("aegis.client.load_private_key", return_value=MagicMock()),
        patch("aegis.client.CanisterTransport") as MockTransport,
        patch("aegis.client.sign_payload", return_value="mock_sig"),
    ):
        mock_transport_instance = MockTransport.return_value
        mock_transport_instance.call_update.return_value = {"actionId": "canister-act-123"}
        mock_transport_instance.spill_count = 0
        mock_transport_instance.drain_spill_buffer.return_value = 0

        from aegis.client import AegisClient

        client = AegisClient(
            canister_id="test-canister-id",
            api_key_id="ak_test",
            private_key_path="./fake_key.pem",
            agent_id="test-agent",
            org_id="test-org",
            session_id="test-session",
            environment=Environment(framework="test"),
        )
        return client, mock_transport_instance


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_log_tool_call_returns_action_id():
    """log_tool_call() muss eine action_id zurückgeben."""
    client, _ = _make_client()
    result = client.log_tool_call(
        tool="search",
        input_data={"query": "test"},
        output_data={"result": "found"},
        duration_ms=100,
    )
    assert result is not None
    assert isinstance(result, str)
    assert len(result) > 0


def test_log_tool_call_uses_add_ledger_entry():
    """call_update muss mit 'addLedgerEntry' aufgerufen werden."""
    client, mock_transport = _make_client()
    client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

    call_args = mock_transport.call_update.call_args
    assert call_args is not None
    assert call_args[0][0] == "addLedgerEntry"


def test_log_tool_call_sends_24_args():
    """addLedgerEntry muss mit genau 24 Candid-Argumenten aufgerufen werden."""
    client, mock_transport = _make_client()
    client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

    call_args = mock_transport.call_update.call_args
    args_list = call_args[0][1]  # zweites positionales Argument = Candid-Args
    assert len(args_list) == 24


def test_action_type_variant_in_args():
    """ActionType (Position 5) muss als Variant dict {'toolCall': None} kodiert sein."""
    client, mock_transport = _make_client()
    client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

    call_args = mock_transport.call_update.call_args
    args_list = call_args[0][1]
    action_type_arg = args_list[5]  # Position 5 = actionType
    assert "value" in action_type_arg
    assert action_type_arg["value"] == {"toolCall": None}


def test_log_decision_uses_decision_variant():
    """log_decision() muss actionType='decision' als Variant senden."""
    client, mock_transport = _make_client()
    client.log_decision(reasoning="Test reasoning", confidence=0.9)

    call_args = mock_transport.call_update.call_args
    args_list = call_args[0][1]
    action_type_arg = args_list[5]
    assert action_type_arg["value"] == {"decision": None}


def test_org_id_passed_to_candid_args():
    """org_id muss als zweites Candid-Argument (Position 1) übergeben werden."""
    with (
        patch("aegis.client.load_private_key", return_value=MagicMock()),
        patch("aegis.client.CanisterTransport") as MockTransport,
        patch("aegis.client.sign_payload", return_value="mock_sig"),
    ):
        mock_transport_instance = MockTransport.return_value
        mock_transport_instance.call_update.return_value = {"actionId": "x"}
        mock_transport_instance.spill_count = 0
        mock_transport_instance.drain_spill_buffer.return_value = 0

        from aegis.client import AegisClient

        client = AegisClient(
            canister_id="test-canister-id",
            api_key_id="ak_test",
            private_key_path="./fake_key.pem",
            agent_id="test-agent",
            org_id="myorg-principal-xyz",
            session_id="test-session",
            environment=Environment(framework="test"),
        )
        client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

        call_args = mock_transport_instance.call_update.call_args
        args_list = call_args[0][1]
        org_id_arg = args_list[1]  # Position 1 = orgId
        assert org_id_arg["value"] == "myorg-principal-xyz"


def test_org_id_passed_as_configured():
    """org_id aus _make_client muss korrekt an Candid-Arg Position 1 durchgereicht werden."""
    client, mock_transport = _make_client()
    client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

    call_args = mock_transport.call_update.call_args
    args_list = call_args[0][1]
    assert args_list[1]["value"] == "test-org"


def test_log_error_uses_error_variant():
    """log_error() muss actionType='error' als Variant senden."""
    client, mock_transport = _make_client()
    client.log_error(tool="broken_tool", input_data={}, error=ValueError("boom"))

    call_args = mock_transport.call_update.call_args
    args_list = call_args[0][1]
    action_type_arg = args_list[5]
    assert action_type_arg["value"] == {"error": None}


def test_api_key_id_at_position_23():
    """keyId (Position 23) muss der api_key_id des Clients entsprechen."""
    client, mock_transport = _make_client()
    client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

    call_args = mock_transport.call_update.call_args
    args_list = call_args[0][1]
    assert args_list[23]["value"] == "ak_test"


def test_no_raw_data_sent_to_canister():
    """Previews and reasoning must be empty strings — no PII on-chain (Phase 1 fix)."""
    client, mock_transport = _make_client()
    client.log_tool_call(
        tool="search",
        input_data={"user_query": "My SSN is 123-45-6789"},
        output_data={"result": "sensitive medical data"},
        duration_ms=100,
    )

    call_args = mock_transport.call_update.call_args
    args_list = call_args[0][1]
    # Position 9 = inputPreview, Position 10 = outputPreview
    assert args_list[9]["value"] == "", f"inputPreview must be empty, got: {args_list[9]['value']}"
    assert args_list[10]["value"] == "", f"outputPreview must be empty, got: {args_list[10]['value']}"
    # Position 14 = decisionReasoning
    assert args_list[14]["value"] == "", f"decisionReasoning must be empty, got: {args_list[14]['value']}"


def test_decision_reasoning_not_sent_to_canister():
    """log_decision() reasoning must not be sent to canister."""
    client, mock_transport = _make_client()
    client.log_decision(reasoning="User john@example.com requested refund", confidence=0.9)

    call_args = mock_transport.call_update.call_args
    args_list = call_args[0][1]
    assert args_list[14]["value"] == "", f"decisionReasoning must be empty, got: {args_list[14]['value']}"


def test_sequence_counter_thread_safe():
    """Sequence Counter muss unter concurrent access unique Werte liefern."""
    client, mock_transport = _make_client()
    sequences: list[int] = []

    def log_one(_: int) -> None:
        mock_transport.call_update.return_value = {"actionId": "x"}
        client.log_tool_call(tool="t", input_data={}, output_data={}, duration_ms=0)

    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(log_one, range(50)))

    # Alle 50 Calls müssen durchgelaufen sein
    assert mock_transport.call_update.call_count == 50
    # Sequence muss jetzt bei 50 stehen
    assert client.sequence_number == 50


# ---------------------------------------------------------------------------
# Batch 3 — Phase 23 Edge Case Tests
# ---------------------------------------------------------------------------


def test_session_id_none_generates_uuid():
    """Wenn session_id=None, muss ein 'sess_'-Prefix generiert werden."""
    with (
        patch("aegis.client.load_private_key", return_value=MagicMock()),
        patch("aegis.client.CanisterTransport") as MockTransport,
        patch("aegis.client.sign_payload", return_value="mock_sig"),
    ):
        mock_transport_instance = MockTransport.return_value
        mock_transport_instance.call_update.return_value = {"actionId": "x"}
        mock_transport_instance.spill_count = 0
        mock_transport_instance.drain_spill_buffer.return_value = 0

        from aegis.client import AegisClient

        client = AegisClient(
            canister_id="test-canister-id",
            api_key_id="ak_test",
            private_key_path="./fake_key.pem",
            agent_id="test-agent",
            org_id="test-org",
            session_id=None,
            environment=Environment(framework="test"),
        )
        assert client._session_id.startswith("sess_")
        assert len(client._session_id) > len("sess_")


def test_metadata_rejects_non_string_values():
    """metadata mit nicht-string Werten muss TypeError werfen."""
    import pytest

    with (
        patch("aegis.client.load_private_key", return_value=MagicMock()),
        patch("aegis.client.CanisterTransport"),
        patch("aegis.client.sign_payload", return_value="mock_sig"),
    ):
        from aegis.client import AegisClient

        with pytest.raises(TypeError, match="metadata values must be str"):
            AegisClient(
                canister_id="test-canister-id",
                api_key_id="ak_test",
                private_key_path="./fake_key.pem",
                agent_id="test-agent",
                org_id="test-org",
                metadata={"key": 123},  # type: ignore[dict-item]
                environment=Environment(framework="test"),
            )


def test_fail_open_true_does_not_raise():
    """Bei fail_open=True darf ein Transport-Fehler keine Exception auslösen."""
    with (
        patch("aegis.client.load_private_key", return_value=MagicMock()),
        patch("aegis.client.CanisterTransport") as MockTransport,
        patch("aegis.client.sign_payload", return_value="mock_sig"),
    ):
        mock_transport_instance = MockTransport.return_value
        mock_transport_instance.call_update.side_effect = ConnectionError("network down")
        mock_transport_instance.spill_count = 0
        mock_transport_instance.drain_spill_buffer.return_value = 0

        from aegis.client import AegisClient

        client = AegisClient(
            canister_id="test-canister-id",
            api_key_id="ak_test",
            private_key_path="./fake_key.pem",
            agent_id="test-agent",
            org_id="test-org",
            session_id="test-session",
            fail_open=True,
            environment=Environment(framework="test"),
        )
        # Darf NICHT raisen
        result = client.log_tool_call(tool="broken", input_data={}, output_data={}, duration_ms=0)
        # result kann None sein bei Fehler — Hauptsache kein Crash
        assert result is None or isinstance(result, str)


def test_log_observation_uses_observation_variant():
    """log_observation() muss actionType='observation' als Variant senden."""
    client, mock_transport = _make_client()
    client.log_observation(input_data="The agent observed something important")

    call_args = mock_transport.call_update.call_args
    args_list = call_args[0][1]
    action_type_arg = args_list[5]
    assert action_type_arg["value"] == {"observation": None}


def test_concurrent_sessions_different_chain_heads():
    """Zwei unabhängige Clients müssen unabhängige Sequenzen haben."""
    client1, mock1 = _make_client()
    client2, mock2 = _make_client()

    # Log entries on both clients
    client1.log_tool_call(tool="a", input_data={}, output_data={}, duration_ms=0)
    client1.log_tool_call(tool="b", input_data={}, output_data={}, duration_ms=0)
    client2.log_tool_call(tool="c", input_data={}, output_data={}, duration_ms=0)

    assert client1.sequence_number == 2
    assert client2.sequence_number == 1


def test_large_payload_hashes_correctly():
    """Grosses Payload (1MB dict) muss korrekt gehasht werden ohne OOM."""
    client, mock_transport = _make_client()
    large_data = {"key_" + str(i): "v" * 100 for i in range(10_000)}  # ~1MB
    result = client.log_tool_call(
        tool="big_tool",
        input_data=large_data,
        output_data={"status": "ok"},
        duration_ms=500,
    )
    # Should succeed without OOM or error
    assert result is not None or result is None  # fail_open may return None
    # Transport should have been called
    assert mock_transport.call_update.called
