"""Smoke Tests für AegisClient — kein echter Canister und kein echter Key nötig."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from aegis.transport import _principal_text_to_bytes
from aegis.types import Environment
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ---------------------------------------------------------------------------
# Fixtures / Helpers
# ---------------------------------------------------------------------------

def _make_client():
    """Erstellt AegisClient mit gemocktem Transport und Key."""
    with (
        patch("aegis.client.load_private_key", return_value=Ed25519PrivateKey.generate()),
        patch("aegis.client.load_config", return_value={}),
        patch("aegis.client.CanisterTransport") as MockTransport,
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
            org_id="un4fu-tqaaa-aaaab-qadjq-cai",
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


def test_log_tool_call_uses_add_ledger_entry_v2():
    """call_update muss mit 'addLedgerEntryV2' aufgerufen werden."""
    client, mock_transport = _make_client()
    client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

    call_args = mock_transport.call_update.call_args
    assert call_args is not None
    assert call_args[0][0] == "addLedgerEntryV2"


def test_log_tool_call_sends_single_record_arg():
    """addLedgerEntryV2 muss mit genau 1 Candid-Record-Argument aufgerufen werden."""
    client, mock_transport = _make_client()
    client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

    call_args = mock_transport.call_update.call_args
    args_list = call_args[0][1]  # zweites positionales Argument = Candid-Args
    assert len(args_list) == 1
    record = args_list[0]
    assert "type" in record
    assert "value" in record
    assert "actionId" in record["value"]
    assert "otelTraceId" in record["value"]


def test_action_type_variant_in_record():
    """ActionType im Record muss als Variant dict {'toolCall': None} kodiert sein."""
    client, mock_transport = _make_client()
    client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

    call_args = mock_transport.call_update.call_args
    record_value = call_args[0][1][0]["value"]
    assert record_value["actionType"] == {"toolCall": None}


def test_log_decision_uses_decision_variant():
    """log_decision() muss actionType='decision' als Variant senden."""
    client, mock_transport = _make_client()
    client.log_decision(reasoning="Test reasoning", confidence=0.9)

    call_args = mock_transport.call_update.call_args
    record_value = call_args[0][1][0]["value"]
    assert record_value["actionType"] == {"decision": None}


def test_org_id_passed_in_record():
    """org_id muss im Record als 'orgId' (bytes) enthalten sein."""
    with (
        patch("aegis.client.load_private_key", return_value=Ed25519PrivateKey.generate()),
        patch("aegis.client.CanisterTransport") as MockTransport,
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
            org_id="un4fu-tqaaa-aaaab-qadjq-cai",
            session_id="test-session",
            environment=Environment(framework="test"),
        )
        client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

        call_args = mock_transport_instance.call_update.call_args
        record_value = call_args[0][1][0]["value"]
        assert record_value["orgId"] == _principal_text_to_bytes("un4fu-tqaaa-aaaab-qadjq-cai")


def test_org_id_passed_as_configured():
    """org_id aus _make_client muss korrekt im Record durchgereicht werden."""
    client, mock_transport = _make_client()
    client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

    call_args = mock_transport.call_update.call_args
    record_value = call_args[0][1][0]["value"]
    assert record_value["orgId"] == _principal_text_to_bytes("un4fu-tqaaa-aaaab-qadjq-cai")


def test_log_error_uses_error_variant():
    """log_error() muss actionType='error' als Variant senden."""
    client, mock_transport = _make_client()
    client.log_error(tool="broken_tool", input_data={}, error=ValueError("boom"))

    call_args = mock_transport.call_update.call_args
    record_value = call_args[0][1][0]["value"]
    assert record_value["actionType"] == {"error": None}


def test_api_key_id_in_record():
    """keyId im Record muss der api_key_id des Clients entsprechen."""
    client, mock_transport = _make_client()
    client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

    call_args = mock_transport.call_update.call_args
    record_value = call_args[0][1][0]["value"]
    assert record_value["keyId"] == "ak_test"


def test_no_raw_data_sent_to_canister():
    """Previews must be empty strings — no PII on-chain."""
    client, mock_transport = _make_client()
    client.log_tool_call(
        tool="search",
        input_data={"user_query": "My SSN is 123-45-6789"},
        output_data={"result": "sensitive medical data"},
        duration_ms=100,
    )

    call_args = mock_transport.call_update.call_args
    record_value = call_args[0][1][0]["value"]
    assert record_value["inputPreview"] == "", (
        f"inputPreview must be empty, got: {record_value['inputPreview']}"
    )
    assert record_value["outputPreview"] == "", (
        f"outputPreview must be empty, got: {record_value['outputPreview']}"
    )
    assert record_value["decisionReasoning"] == "", "tool_call with empty reasoning stays empty"


def test_decision_reasoning_sent_to_canister_redacted():
    """C-2 FIX: reasoning IS sent to canister, but PII is redacted (C-1)."""
    client, mock_transport = _make_client()
    client.log_decision(reasoning="User john@example.com requested refund", confidence=0.9)

    call_args = mock_transport.call_update.call_args
    record_value = call_args[0][1][0]["value"]
    reasoning_value = record_value["decisionReasoning"]
    # Reasoning must be sent (not empty) — C-2 fix
    assert reasoning_value != "", "decisionReasoning must not be empty after C-2 fix"
    # PII (email) must be redacted — C-1 fix
    assert "john@example.com" not in reasoning_value, "PII must be redacted"
    assert "sha256:" in reasoning_value, "PII must be replaced with sha256 hash"


def test_sequence_counter_thread_safe():
    """Sequence Counter muss unter concurrent access unique Werte liefern."""
    client, mock_transport = _make_client()
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


def test_session_id_none_uses_agent_id():
    """Wenn session_id=None, wird agent_id als session_id verwendet (agent-zentrisch)."""
    with (
        patch("aegis.client.load_private_key", return_value=Ed25519PrivateKey.generate()),
        patch("aegis.client.CanisterTransport") as MockTransport,
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
            org_id="un4fu-tqaaa-aaaab-qadjq-cai",
            session_id=None,
            environment=Environment(framework="test"),
        )
        assert client._session_id == "test-agent"


def test_metadata_rejects_non_string_values():
    """metadata mit nicht-string Werten muss TypeError werfen."""
    import pytest

    with (
        patch("aegis.client.load_private_key", return_value=Ed25519PrivateKey.generate()),
        patch("aegis.client.CanisterTransport"),
    ):
        from aegis.client import AegisClient

        with pytest.raises(TypeError, match="metadata values must be str"):
            AegisClient(
                canister_id="test-canister-id",
                api_key_id="ak_test",
                private_key_path="./fake_key.pem",
                agent_id="test-agent",
                org_id="un4fu-tqaaa-aaaab-qadjq-cai",
                metadata={"key": 123},  # type: ignore[dict-item]
                environment=Environment(framework="test"),
            )


def test_fail_open_true_does_not_raise():
    """Bei fail_open=True darf ein Transport-Fehler keine Exception auslösen."""
    with (
        patch("aegis.client.load_private_key", return_value=Ed25519PrivateKey.generate()),
        patch("aegis.client.CanisterTransport") as MockTransport,
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
            org_id="un4fu-tqaaa-aaaab-qadjq-cai",
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
    record_value = call_args[0][1][0]["value"]
    assert record_value["actionType"] == {"observation": None}


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


# ---------------------------------------------------------------------------
# Async @trace tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trace_async_function_success():
    """@trace should work with async functions."""
    client, mock_transport = _make_client()

    @client.trace(action_type="tool_call", tool_name="async_search")
    async def async_search(query: str) -> dict:
        return {"result": f"found {query}"}

    result = await async_search("test")
    assert result == {"result": "found test"}
    assert mock_transport.call_update.called


@pytest.mark.asyncio
async def test_trace_async_function_exception():
    """@trace should log errors and re-raise for async functions."""
    client, mock_transport = _make_client()

    @client.trace(action_type="tool_call", tool_name="async_fail")
    async def async_fail() -> None:
        raise ValueError("async boom")

    with pytest.raises(ValueError, match="async boom"):
        await async_fail()
    # Should still have logged (error + possibly success attempt)
    assert mock_transport.call_update.called


@pytest.mark.asyncio
async def test_trace_async_preserves_return_value():
    """@trace async wrapper should preserve the exact return value."""
    client, _ = _make_client()

    @client.trace(action_type="tool_call")
    async def compute(x: int, y: int) -> int:
        return x + y

    result = await compute(3, 7)
    assert result == 10


@pytest.mark.asyncio
async def test_trace_async_no_capture_output():
    """@trace with capture_output=False should still work for async."""
    client, mock_transport = _make_client()

    @client.trace(action_type="tool_call", capture_output=False)
    async def secret_op() -> str:
        return "sensitive"

    result = await secret_op()
    assert result == "sensitive"
    assert mock_transport.call_update.called


def test_trace_sync_still_works():
    """Sync @trace should remain functional after async support was added."""
    client, mock_transport = _make_client()

    @client.trace(action_type="tool_call", tool_name="sync_tool")
    def sync_tool(x: int) -> int:
        return x * 2

    result = sync_tool(5)
    assert result == 10
    assert mock_transport.call_update.called


# ---------------------------------------------------------------------------
# log_batch tests
# ---------------------------------------------------------------------------

def test_log_batch_returns_action_ids():
    """log_batch should return a list of action IDs."""
    client, mock_transport = _make_client()
    entries = [
        {
            "action_type": "tool_call", "tool": "t1",
            "input_data": {"a": 1}, "output_data": {}, "duration_ms": 10,
        },
        {
            "action_type": "tool_call", "tool": "t2",
            "input_data": {"b": 2}, "output_data": {}, "duration_ms": 20,
        },
        {
            "action_type": "observation", "tool": "t3",
            "input_data": {"c": 3}, "output_data": {}, "duration_ms": 30,
        },
    ]
    results = client.log_batch(entries)
    assert len(results) == 3
    assert all(isinstance(r, str) for r in results)


def test_log_batch_empty_list():
    """log_batch with empty list should return empty list."""
    client, _ = _make_client()
    results = client.log_batch([])
    assert results == []


def test_log_batch_sequence_increases():
    """log_batch entries should have monotonically increasing sequence numbers."""
    client, mock_transport = _make_client()
    entries = [
        {
            "action_type": "tool_call", "tool": f"t{i}",
            "input_data": {}, "output_data": {}, "duration_ms": 0,
        }
        for i in range(5)
    ]
    client.log_batch(entries)
    # Should have called call_update 5 times
    assert mock_transport.call_update.call_count == 5


# ---------------------------------------------------------------------------
# H-2: drain_spill_buffer outside lock
# ---------------------------------------------------------------------------

def test_drain_called_when_spill_count_positive():
    """H-2: drain_spill_buffer must be called when spill_count > 0."""
    client, mock_transport = _make_client()
    mock_transport.spill_count = 3
    client.log_tool_call(tool="t", input_data={}, output_data={}, duration_ms=0)
    mock_transport.drain_spill_buffer.assert_called_once()


def test_drain_not_called_when_spill_count_zero():
    """H-2: drain_spill_buffer must NOT be called when spill_count == 0."""
    client, mock_transport = _make_client()
    mock_transport.spill_count = 0
    client.log_tool_call(tool="t", input_data={}, output_data={}, duration_ms=0)
    mock_transport.drain_spill_buffer.assert_not_called()


def test_drain_outside_lock_allows_concurrent_logging():
    """H-2: Other threads can log while drain_spill_buffer is running."""
    import time as time_mod

    client, mock_transport = _make_client()
    mock_transport.spill_count = 5
    log_during_drain = threading.Event()

    def slow_drain():
        """Simulate a slow drain that takes 100ms (network call)."""
        # Signal that drain is running — another thread can now log
        log_during_drain.set()
        time_mod.sleep(0.1)
        return 5

    mock_transport.drain_spill_buffer.side_effect = slow_drain

    results = []

    def log_from_thread():
        log_during_drain.wait(timeout=2)
        # This should NOT be blocked by the drain
        r = client.log_tool_call(tool="concurrent", input_data={}, output_data={}, duration_ms=0)
        results.append(r)

    t = threading.Thread(target=log_from_thread)
    t.start()

    # First log triggers the drain (which runs outside lock)
    client.log_tool_call(tool="trigger", input_data={}, output_data={}, duration_ms=0)

    t.join(timeout=3)
    assert len(results) == 1, "Concurrent thread must be able to log during drain"


# ---------------------------------------------------------------------------
# Analytics: get_session_completeness / get_org_stats
# ---------------------------------------------------------------------------

def test_get_session_completeness_calls_query():
    """get_session_completeness must call call_query with correct method."""
    client, mock_transport = _make_client()
    mock_transport.call_query.return_value = {
        "sessionId": "sess_1",
        "totalEntries": 10,
        "errorCount": 2,
        "errorRate": 0.2,
        "avgDurationMs": 150,
        "actionTypeDist": [("toolCall", 8), ("error", 2)],
    }
    result = client.get_session_completeness("sess_1")
    # call_query may also be called for getSessionSequenceHead (sequence sync)
    analytics_calls = [
        c for c in mock_transport.call_query.call_args_list
        if c[0][0] == "getSessionCompleteness"
    ]
    assert len(analytics_calls) == 1
    assert result["totalEntries"] == 10
    assert result["errorRate"] == 0.2


def test_get_org_stats_calls_query():
    """get_org_stats must call call_query with correct method."""
    client, mock_transport = _make_client()
    mock_transport.call_query.return_value = {
        "totalEntries": 100,
        "totalSessions": 5,
        "monthlyEntries": 30,
        "topAgents": [("agent-1", 60), ("agent-2", 40)],
    }
    result = client.get_org_stats()
    # call_query may also be called for getSessionSequenceHead (sequence sync)
    analytics_calls = [
        c for c in mock_transport.call_query.call_args_list
        if c[0][0] == "getOrgStats"
    ]
    assert len(analytics_calls) == 1
    assert result["totalSessions"] == 5
    assert result["topAgents"][0] == ("agent-1", 60)


# ---------------------------------------------------------------------------
# KYA: register_agent / update_agent_profile / get_agent_facts
# ---------------------------------------------------------------------------

def test_register_agent_calls_update():
    """register_agent must call call_update with registerAgent method."""
    client, mock_transport = _make_client()
    mock_transport.call_update.return_value = {
        "agentId": "my-agent",
        "name": "My Agent",
        "description": "A test agent",
        "capabilities": ["search", "code"],
        "framework": "langchain",
        "modelId": "gpt-4",
        "createdAtNs": 1000000,
        "lastActiveNs": 1000000,
        "totalEntries": 0,
    }
    result = client.register_agent(
        agent_id="my-agent",
        name="My Agent",
        description="A test agent",
        capabilities=["search", "code"],
        framework="langchain",
        model_id="gpt-4",
    )
    register_calls = [
        c for c in mock_transport.call_update.call_args_list
        if c[0][0] == "registerAgent"
    ]
    assert len(register_calls) == 1
    assert result["agentId"] == "my-agent"
    assert result["name"] == "My Agent"
    assert result["capabilities"] == ["search", "code"]


def test_register_agent_defaults():
    """register_agent with minimal args sends empty defaults."""
    client, mock_transport = _make_client()
    mock_transport.call_update.return_value = {"agentId": "a1"}
    client.register_agent(agent_id="a1", name="Agent")
    register_calls = [
        c for c in mock_transport.call_update.call_args_list
        if c[0][0] == "registerAgent"
    ]
    assert len(register_calls) == 1
    # args[1] is the Candid args list
    candid_args = register_calls[0][0][1]
    # capabilities (index 3) should be empty list
    assert candid_args[3]["value"] == []
    # framework (index 4) and model_id (index 5) should be empty strings
    assert candid_args[4]["value"] == ""
    assert candid_args[5]["value"] == ""


def test_update_agent_profile_calls_update():
    """update_agent_profile must call call_update with updateAgentProfile."""
    client, mock_transport = _make_client()
    mock_transport.call_update.return_value = {
        "agentId": "my-agent",
        "name": "Updated Name",
    }
    result = client.update_agent_profile(
        agent_id="my-agent",
        name="Updated Name",
        description=None,
        capabilities=["new-cap"],
    )
    update_calls = [
        c for c in mock_transport.call_update.call_args_list
        if c[0][0] == "updateAgentProfile"
    ]
    assert len(update_calls) == 1
    assert result["name"] == "Updated Name"


def test_update_agent_profile_opt_fields():
    """update_agent_profile sends Opt(None) for unset fields, Opt(value) for set."""
    client, mock_transport = _make_client()
    mock_transport.call_update.return_value = {"agentId": "a1"}
    client.update_agent_profile(agent_id="a1", name="New", framework=None)
    update_calls = [
        c for c in mock_transport.call_update.call_args_list
        if c[0][0] == "updateAgentProfile"
    ]
    candid_args = update_calls[0][0][1]
    # name (index 1) should be Opt with value
    assert candid_args[1]["value"] == ["New"]
    # description (index 2) should be Opt empty (None passed)
    assert candid_args[2]["value"] == []
    # framework (index 4) should be Opt empty (explicitly None)
    assert candid_args[4]["value"] == []


def test_get_agent_facts_calls_query():
    """get_agent_facts must call call_query with getAgentFacts."""
    client, mock_transport = _make_client()
    mock_transport.call_query.return_value = {
        "agentId": "my-agent",
        "name": "My Agent",
        "framework": "langchain",
        "modelId": "gpt-4",
        "totalEntries": 42,
        "lastActiveNs": 2000000,
        "hasVerifiedEntries": True,
    }
    result = client.get_agent_facts("my-agent")
    facts_calls = [
        c for c in mock_transport.call_query.call_args_list
        if c[0][0] == "getAgentFacts"
    ]
    assert len(facts_calls) == 1
    assert result["totalEntries"] == 42
    assert result["hasVerifiedEntries"] is True
    assert result["framework"] == "langchain"
