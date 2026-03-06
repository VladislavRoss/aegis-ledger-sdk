"""Smoke Tests für AegisClient — kein echter Canister und kein echter Key nötig."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

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
            session_id="test-session",
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
        )
        client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

        call_args = mock_transport_instance.call_update.call_args
        args_list = call_args[0][1]
        org_id_arg = args_list[1]  # Position 1 = orgId
        assert org_id_arg["value"] == "myorg-principal-xyz"


def test_org_id_default_is_anonymous():
    """Ohne org_id muss der Default 'aaaaa-aa' (Anonymous Principal) verwendet werden."""
    client, mock_transport = _make_client()
    client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

    call_args = mock_transport.call_update.call_args
    args_list = call_args[0][1]
    assert args_list[1]["value"] == "aaaaa-aa"


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
