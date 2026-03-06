"""Tests für transport.py Hilfsfunktionen."""
import pytest
from aegis.transport import _build_add_ledger_entry_args, action_type_to_candid_variant

# --- action_type_to_candid_variant ---

def test_tool_call():
    result = action_type_to_candid_variant("tool_call")
    assert result == {"toolCall": None}


def test_human_override():
    result = action_type_to_candid_variant("human_override")
    assert result == {"humanOverride": None}


def test_decision():
    assert action_type_to_candid_variant("decision") == {"decision": None}


def test_observation():
    assert action_type_to_candid_variant("observation") == {"observation": None}


def test_error():
    assert action_type_to_candid_variant("error") == {"error": None}


def test_unknown_raises():
    with pytest.raises(ValueError, match="Unknown action type"):
        action_type_to_candid_variant("unknown_type")


# --- _build_add_ledger_entry_args ---

_FULL_ARGS = dict(
    action_id="act-123",
    org_id="aaaaa-aa",
    agent_id="agent-1",
    session_id="sess-1",
    sequence_number=1,
    action_type="tool_call",
    tool="search",
    input_hash="abc",
    output_hash="def",
    input_preview="query",
    output_preview="result",
    duration_ms=100,
    status="success",
    parent_action_id="",
    decision_reasoning="",
    confidence_score=0.9,
    framework="langchain",
    model_id="gpt-4",
    client_timestamp_ms=1700000000000,
    payload_signature="sig",
    chain_hash="chain",
    previous_chain_hash="prev",
    key_id="ak_test",
)


def test_build_args_length():
    """Muss genau 24 Argumente zurückgeben (inkl. payloadHex + keyId)."""
    args = _build_add_ledger_entry_args(**_FULL_ARGS)
    assert len(args) == 24


def test_build_args_action_type_variant():
    """ActionType (Position 5) muss als Variant kodiert sein."""
    args = _build_add_ledger_entry_args(**_FULL_ARGS)
    variant_arg = args[5]
    assert "value" in variant_arg
    assert variant_arg["value"] == {"toolCall": None}


def test_build_args_first_field_is_action_id():
    """Erstes Argument muss actionId sein."""
    args = _build_add_ledger_entry_args(**_FULL_ARGS)
    assert args[0]["value"] == "act-123"


def test_build_args_sequence_number_nat():
    """sequenceNumber (Position 4) muss Nat sein."""
    args = _build_add_ledger_entry_args(**_FULL_ARGS)
    assert args[4]["value"] == 1


def test_build_args_key_id_at_position_23():
    """keyId (Position 23) muss als letztes Argument stehen."""
    args = _build_add_ledger_entry_args(**_FULL_ARGS)
    assert args[23]["value"] == "ak_test"
