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


# ---------------------------------------------------------------------------
# TransportConfig + CanisterError tests (Phase 21 — core coverage)
# ---------------------------------------------------------------------------


class TestTransportConfig:
    def test_defaults(self):
        """TransportConfig has correct default values."""
        from aegis.transport import TransportConfig

        config = TransportConfig(canister_id="test-canister")
        assert config.canister_id == "test-canister"
        assert config.network == "https://icp-api.io"
        assert config.max_retries == 3
        assert config.retry_base_delay_s == 1.0
        assert config.timeout_s == 30.0
        assert str(config.spill_dir).endswith("spill")
        assert config.private_key_path is None

    def test_custom_values(self):
        """TransportConfig accepts custom values."""
        from aegis.transport import TransportConfig

        config = TransportConfig(
            canister_id="custom",
            network="http://localhost:4943",
            max_retries=5,
            retry_base_delay_s=0.5,
            timeout_s=60.0,
            spill_dir="/tmp/spill",
        )
        assert config.max_retries == 5
        assert config.retry_base_delay_s == 0.5
        assert config.spill_dir.name == "spill"


class TestCanisterError:
    def test_error_message_includes_code(self):
        """CanisterError includes error code in message."""
        from aegis.transport import CanisterError

        err = CanisterError("Connection failed", error_code="TRANSPORT_EXHAUSTED")
        assert err.error_code == "TRANSPORT_EXHAUSTED"
        assert "TRANSPORT_EXHAUSTED" in str(err)
        assert "Connection failed" in str(err)

    def test_default_error_code(self):
        """CanisterError defaults to UNKNOWN code."""
        from aegis.transport import CanisterError

        err = CanisterError("Something went wrong")
        assert err.error_code == "UNKNOWN"


class TestSpillBuffer:
    def test_spill_to_disk_creates_file(self, tmp_path):
        """Spill writes a JSONL line to the spill file."""
        from aegis.transport import CanisterTransport, TransportConfig

        config = TransportConfig(
            canister_id="test-spill",
            spill_dir=str(tmp_path),
        )
        # Prevent _init_agent from trying to import ic-py
        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                "aegis.transport.CanisterTransport._init_agent",
                lambda self: setattr(self, "_ic_available", False),
            )
            transport = CanisterTransport(config)

        transport._spill_to_disk("addLedgerEntry", [{"type": "test", "value": "data"}])
        spill_file = tmp_path / "test-spill.jsonl"
        assert spill_file.exists()
        content = spill_file.read_text()
        assert "addLedgerEntry" in content
        assert "test-spill" in content

    def test_spill_count_zero_when_no_file(self, tmp_path):
        """spill_count returns 0 when no spill file exists."""
        from aegis.transport import CanisterTransport, TransportConfig

        config = TransportConfig(canister_id="no-spill", spill_dir=str(tmp_path))
        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                "aegis.transport.CanisterTransport._init_agent",
                lambda self: setattr(self, "_ic_available", False),
            )
            transport = CanisterTransport(config)
        assert transport.spill_count == 0

    def test_spill_buffer_limit_enforced(self, tmp_path):
        """Spill buffer enforces MAX_SPILL_ENTRIES limit."""
        from aegis.transport import _MAX_SPILL_ENTRIES, CanisterTransport, TransportConfig

        config = TransportConfig(canister_id="limit-test", spill_dir=str(tmp_path))
        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                "aegis.transport.CanisterTransport._init_agent",
                lambda self: setattr(self, "_ic_available", False),
            )
            transport = CanisterTransport(config)

        # Write entries up to the limit
        for i in range(_MAX_SPILL_ENTRIES + 5):
            transport._spill_to_disk("addLedgerEntry", [{"value": f"entry_{i}"}])

        # Should have at most _MAX_SPILL_ENTRIES entries
        assert transport.spill_count <= _MAX_SPILL_ENTRIES

    def test_spill_discards_oldest_on_overflow(self, tmp_path):
        """When spill is full, oldest entries are discarded and newest kept."""
        import json

        from aegis.transport import CanisterTransport, TransportConfig

        config = TransportConfig(canister_id="oldest-test", spill_dir=str(tmp_path))
        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                "aegis.transport.CanisterTransport._init_agent",
                lambda self: setattr(self, "_ic_available", False),
            )
            transport = CanisterTransport(config)

        # Pre-fill with fake entries (manually write to bypass normal limit)
        spill_file = tmp_path / "oldest-test.jsonl"
        lines = []
        for i in range(1000):
            lines.append(json.dumps({
                "method": "addLedgerEntry", "args": [{"idx": i}],
                "timestamp_ms": 1000 + i, "canister_id": "oldest-test",
            }))
        spill_file.write_text("\n".join(lines) + "\n")

        # Add one more — should trigger eviction (H-3: args need "value" key)
        transport._spill_to_disk("addLedgerEntry", [{"type": "text", "value": 1000}])

        # Last entry should be the newest (spill_version 2 stores raw_values)
        content = spill_file.read_text().strip().split("\n")
        last_entry = json.loads(content[-1])
        assert last_entry["raw_values"] == [1000]
        assert last_entry["spill_version"] == 2

    # ------------------------------------------------------------------
    # Batch 3: Drain, Retry, Edge Cases
    # ------------------------------------------------------------------

    def test_drain_spill_replays_entries_on_success(self, tmp_path):
        """drain_spill_buffer retries spilled entries and returns drained count."""
        import json

        from aegis.transport import CanisterTransport, TransportConfig

        config = TransportConfig(canister_id="drain-ok", spill_dir=str(tmp_path))
        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                "aegis.transport.CanisterTransport._init_agent",
                lambda self: setattr(self, "_ic_available", True),
            )
            transport = CanisterTransport(config)

        # Pre-fill spill file with 3 v2-format entries
        spill_file = tmp_path / "drain-ok.jsonl"
        import time as _time
        now_ms = int(_time.time() * 1000)
        # Build proper v2 spill entries with 24 raw values
        entries = []
        for i in range(3):
            vals = [
                f"act_{i}", "org-1", "agent-1", "sess-1", i,
                {"toolCall": None}, "search", "sha256:in", "sha256:out",
                "", "", 100, "success", "", "", 0.9, "unknown", "", now_ms,
                "ed25519:abc", "chainabc", "", "payload", "ak_test",
            ]
            entries.append(json.dumps({
                "method": "addLedgerEntry",
                "raw_values": vals,
                "timestamp_ms": now_ms,
                "canister_id": "drain-ok",
                "spill_version": 2,
            }))
        spill_file.write_text("\n".join(entries) + "\n")

        # Mock _do_call to succeed
        with pytest.MonkeyPatch.context() as m:
            m.setattr(transport, "_do_call", lambda method, args, call_type: {"ok": True})
            drained = transport.drain_spill_buffer()

        assert drained == 3
        assert not spill_file.exists()  # All drained → file deleted

    def test_drain_spill_keeps_failed_entries(self, tmp_path):
        """Entries that fail during drain remain in the spill file."""
        import json

        from aegis.transport import CanisterTransport, TransportConfig

        config = TransportConfig(canister_id="drain-fail", spill_dir=str(tmp_path))
        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                "aegis.transport.CanisterTransport._init_agent",
                lambda self: setattr(self, "_ic_available", True),
            )
            transport = CanisterTransport(config)

        import time as _time
        now_ms = int(_time.time() * 1000)
        spill_file = tmp_path / "drain-fail.jsonl"
        _dummy_values = [
            "act_0", "org-1", "agent-1", "sess-1", 0,
            {"toolCall": None}, "search", "sha256:in", "sha256:out",
            "", "", 100, "success", "", "", 0.9, "unknown", "", now_ms,
            "ed25519:abc", "chainabc", "", "payload", "ak_test",
        ]
        entries = []
        for i in range(2):
            vals = list(_dummy_values)
            vals[0] = f"act_{i}"
            vals[4] = i
            entries.append(json.dumps({
                "method": "addLedgerEntry",
                "raw_values": vals,
                "timestamp_ms": now_ms,
                "canister_id": "drain-fail",
                "spill_version": 2,
            }))
        spill_file.write_text("\n".join(entries) + "\n")

        call_count = 0
        def failing_on_second(method, args, call_type):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise ConnectionError("boom")
            return {"ok": True}

        with pytest.MonkeyPatch.context() as m:
            m.setattr(transport, "_do_call", failing_on_second)
            drained = transport.drain_spill_buffer()

        assert drained == 1
        assert spill_file.exists()
        assert transport.spill_count == 1

    def test_drain_spill_returns_zero_when_no_file(self, tmp_path):
        """drain_spill_buffer returns 0 when no spill file exists."""
        from aegis.transport import CanisterTransport, TransportConfig

        config = TransportConfig(canister_id="no-drain", spill_dir=str(tmp_path))
        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                "aegis.transport.CanisterTransport._init_agent",
                lambda self: setattr(self, "_ic_available", False),
            )
            transport = CanisterTransport(config)

        assert transport.drain_spill_buffer() == 0

    def test_drain_spill_handles_empty_file(self, tmp_path):
        """drain_spill_buffer returns 0 for an empty spill file."""
        from aegis.transport import CanisterTransport, TransportConfig

        config = TransportConfig(canister_id="empty-drain", spill_dir=str(tmp_path))
        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                "aegis.transport.CanisterTransport._init_agent",
                lambda self: setattr(self, "_ic_available", False),
            )
            transport = CanisterTransport(config)

        spill_file = tmp_path / "empty-drain.jsonl"
        spill_file.write_text("")
        assert transport.drain_spill_buffer() == 0

    def test_call_update_retries_and_raises_canister_error(self, tmp_path):
        """All retries exhausted → CanisterError with TRANSPORT_EXHAUSTED."""
        from aegis.transport import CanisterError, CanisterTransport, TransportConfig

        config = TransportConfig(
            canister_id="retry-fail", spill_dir=str(tmp_path),
            max_retries=2, retry_base_delay_s=0.0,
        )
        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                "aegis.transport.CanisterTransport._init_agent",
                lambda self: setattr(self, "_ic_available", True),
            )
            transport = CanisterTransport(config)

        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                transport, "_do_call",
                lambda *a, **kw: (_ for _ in ()).throw(
                    ConnectionError("down")
                ),
            )
            with pytest.raises(CanisterError, match="TRANSPORT_EXHAUSTED"):
                # H-3: args must have "value" key for spill serialization
                transport.call_update("addLedgerEntry", [{"type": "text", "value": "test"}])

        # Spill file should have been created
        assert transport.spill_count == 1

    def test_call_update_succeeds_on_second_retry(self, tmp_path):
        """Retry succeeds on second attempt → result returned."""
        from aegis.transport import CanisterTransport, TransportConfig

        config = TransportConfig(
            canister_id="retry-ok", spill_dir=str(tmp_path),
            max_retries=3, retry_base_delay_s=0.0,
        )
        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                "aegis.transport.CanisterTransport._init_agent",
                lambda self: setattr(self, "_ic_available", True),
            )
            transport = CanisterTransport(config)

        attempts = [0]
        def succeed_on_second(method, args, call_type):
            attempts[0] += 1
            if attempts[0] == 1:
                raise ConnectionError("transient")
            return {"actionId": "ok"}

        with pytest.MonkeyPatch.context() as m:
            m.setattr(transport, "_do_call", succeed_on_second)
            result = transport.call_update("addLedgerEntry", [{}])

        assert result == {"actionId": "ok"}
        assert attempts[0] == 2

    def test_call_query_no_retry_no_spill(self, tmp_path):
        """Query failures do NOT create spill files and raise immediately."""
        from aegis.transport import CanisterError, CanisterTransport, TransportConfig

        config = TransportConfig(canister_id="query-fail", spill_dir=str(tmp_path))
        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                "aegis.transport.CanisterTransport._init_agent",
                lambda self: setattr(self, "_ic_available", True),
            )
            transport = CanisterTransport(config)

        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                transport, "_do_call",
                lambda *a, **kw: (_ for _ in ()).throw(
                    CanisterError("no data", "NOT_FOUND")
                ),
            )
            with pytest.raises(CanisterError, match="NOT_FOUND"):
                transport.call_query("getTrace", [{"session": "x"}])

        assert transport.spill_count == 0

    def test_spill_count_ignores_empty_lines(self, tmp_path):
        """spill_count filters out empty lines from malformed files."""
        from aegis.transport import CanisterTransport, TransportConfig

        config = TransportConfig(canister_id="empty-lines", spill_dir=str(tmp_path))
        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                "aegis.transport.CanisterTransport._init_agent",
                lambda self: setattr(self, "_ic_available", False),
            )
            transport = CanisterTransport(config)

        # Write file with empty lines interspersed
        spill_file = tmp_path / "empty-lines.jsonl"
        spill_file.write_text('{"a":1}\n\n{"b":2}\n\n\n{"c":3}\n')
        assert transport.spill_count == 3
