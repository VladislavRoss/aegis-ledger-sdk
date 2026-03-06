"""Tests für SHA-256 Hash-Chain — compute_chain_hash() und client._chain_heads."""
from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

from aegis.crypto import compute_chain_hash


# ---------------------------------------------------------------------------
# compute_chain_hash()
# ---------------------------------------------------------------------------

def test_compute_chain_hash_returns_64_char_hex():
    """Ergebnis muss 64-char lowercase hex sein (SHA-256)."""
    result = compute_chain_hash("", b"test payload")
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)


def test_compute_chain_hash_first_entry():
    """Erster Eintrag: previous_chain_hash='' → SHA-256(':' + payload)."""
    payload = b"hello world"
    expected = hashlib.sha256(b":" + payload).hexdigest()
    assert compute_chain_hash("", payload) == expected


def test_compute_chain_hash_chained():
    """Zweiter Eintrag: SHA-256(prev_hash + ':' + payload)."""
    prev = "a" * 64
    payload = b"second entry"
    expected = hashlib.sha256(prev.encode("ascii") + b":" + payload).hexdigest()
    assert compute_chain_hash(prev, payload) == expected


def test_compute_chain_hash_deterministic():
    """Gleiche Inputs → gleicher Hash."""
    h1 = compute_chain_hash("abc", b"payload")
    h2 = compute_chain_hash("abc", b"payload")
    assert h1 == h2


def test_compute_chain_hash_sensitive_to_previous():
    """Ändert sich wenn previous_chain_hash anders ist."""
    h1 = compute_chain_hash("prev1", b"same payload")
    h2 = compute_chain_hash("prev2", b"same payload")
    assert h1 != h2


def test_compute_chain_hash_sensitive_to_payload():
    """Ändert sich wenn payload anders ist."""
    h1 = compute_chain_hash("same_prev", b"payload_a")
    h2 = compute_chain_hash("same_prev", b"payload_b")
    assert h1 != h2


def test_chain_is_linked():
    """Drei verkettete Einträge — jeder hängt vom vorherigen ab."""
    p1 = b"entry one"
    p2 = b"entry two"
    p3 = b"entry three"

    h1 = compute_chain_hash("", p1)
    h2 = compute_chain_hash(h1, p2)
    h3 = compute_chain_hash(h2, p3)

    # Wenn h1 sich ändert, ändert sich h2 und h3 zwingend
    h1_tampered = compute_chain_hash("", b"TAMPERED entry one")
    h2_after_tamper = compute_chain_hash(h1_tampered, p2)
    h3_after_tamper = compute_chain_hash(h2_after_tamper, p3)

    assert h2 != h2_after_tamper
    assert h3 != h3_after_tamper


# ---------------------------------------------------------------------------
# client._chain_heads Integration
# ---------------------------------------------------------------------------

def _make_client(session_id: str = "test-session"):
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
            session_id=session_id,
        )
        return client, mock_transport_instance


def test_chain_heads_starts_empty():
    """_chain_heads ist initial leer."""
    client, _ = _make_client()
    assert client._chain_heads == {}


def test_chain_heads_updated_after_successful_log():
    """Nach einem erfolgreichen log_tool_call muss _chain_heads[session_id] gesetzt sein."""
    client, _ = _make_client()
    client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

    assert "test-session" in client._chain_heads
    head = client._chain_heads["test-session"]
    assert len(head) == 64
    assert all(c in "0123456789abcdef" for c in head)


def test_chain_heads_changes_with_each_entry():
    """Jeder Eintrag erzeugt einen neuen chain_hash."""
    client, _ = _make_client()

    client.log_tool_call(tool="first", input_data={}, output_data={}, duration_ms=0)
    head_after_1 = client._chain_heads["test-session"]

    client.log_tool_call(tool="second", input_data={}, output_data={}, duration_ms=0)
    head_after_2 = client._chain_heads["test-session"]

    assert head_after_1 != head_after_2


def test_chain_hash_passed_to_candid_args():
    """chain_hash (Position 20) muss 64-char hex sein (nicht leer)."""
    client, mock_transport = _make_client()
    client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

    args_list = mock_transport.call_update.call_args[0][1]
    chain_hash_arg = args_list[20]  # Position 20 = chainHash
    assert "value" in chain_hash_arg
    chain_hash = chain_hash_arg["value"]
    assert len(chain_hash) == 64
    assert all(c in "0123456789abcdef" for c in chain_hash)


def test_previous_chain_hash_first_entry_is_empty():
    """Erster Eintrag: previousChainHash (Position 21) muss '' sein."""
    client, mock_transport = _make_client()
    client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

    args_list = mock_transport.call_update.call_args[0][1]
    prev_hash_arg = args_list[21]  # Position 21 = previousChainHash
    assert prev_hash_arg["value"] == ""


def test_payload_hex_passed_to_candid_args():
    """payloadHex (Position 22) muss nicht-leerer hex-String sein."""
    client, mock_transport = _make_client()
    client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

    args_list = mock_transport.call_update.call_args[0][1]
    payload_hex_arg = args_list[22]  # Position 22 = payloadHex
    assert "value" in payload_hex_arg
    payload_hex = payload_hex_arg["value"]
    assert len(payload_hex) > 0
    assert all(c in "0123456789abcdef" for c in payload_hex)


def test_previous_chain_hash_second_entry_equals_first_chain_hash():
    """Zweiter Eintrag: previousChainHash muss = chainHash des ersten Eintrags sein."""
    client, mock_transport = _make_client()

    client.log_tool_call(tool="first", input_data={}, output_data={}, duration_ms=0)
    first_args = mock_transport.call_update.call_args[0][1]
    first_chain_hash = first_args[20]["value"]

    client.log_tool_call(tool="second", input_data={}, output_data={}, duration_ms=0)
    second_args = mock_transport.call_update.call_args[0][1]
    second_prev_hash = second_args[21]["value"]

    assert second_prev_hash == first_chain_hash


def test_new_session_resets_chain():
    """new_session() entfernt den Chain-State der aktuellen Session."""
    client, _ = _make_client(session_id="old-session")
    client.log_tool_call(tool="first", input_data={}, output_data={}, duration_ms=0)
    assert "old-session" in client._chain_heads

    client.new_session("old-session")
    # Chain-Head für diese Session wurde entfernt
    assert "old-session" not in client._chain_heads
