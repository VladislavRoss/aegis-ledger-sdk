"""
End-to-End Workflow Tests — testet komplette User-Journeys über alle Komponenten.

Workflows:
  W-02: Agent-Integration (SDK → Mock-Canister → Verifier)
  W-03: Public Verification
  W-05: Key-Rotation
  W-07: Multi-Agent Multi-Session
  W-08: Rate-Limit Hit
  W-09: Fail-Open + Spill/Drain
  W-10: Compliance Report

Aufruf:
    cd /c/ARBEIT/AegisProtocol
    python -m pytest AEGIS_LEDGER/tests/test_e2e_workflows.py -v
"""
from __future__ import annotations

import json
import threading
import time
from unittest.mock import MagicMock, patch

import pytest
from aegis.crypto import (
    canonical_json,
    compute_chain_hash,
    create_scheme,
)
from aegis.transport import CanisterTransport, TransportConfig
from aegis.types import Environment
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

# ============================================================================
# Fixtures
# ============================================================================

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
def tmp_pem_2(tmp_path):
    """Create a second Ed25519 PEM key file for key rotation."""
    key = Ed25519PrivateKey.generate()
    pem_path = tmp_path / "test_key_2.pem"
    pem_path.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    return str(pem_path)


def _make_mock_transport():
    """Create a mock transport that records all calls."""
    transport = MagicMock()
    transport.call_update.return_value = {"actionId": "act_e2e_001"}
    transport.spill_count = 0
    transport.drain_spill_buffer.return_value = 0
    return transport


def _make_client(
    pem_path, transport=None, session_id="e2e-session",
    org_id="un4fu-tqaaa-aaaab-qadjq-cai",
    fail_open=True, api_key_id="ak_e2e",
):
    """Create AegisClient with mocked/real transport."""
    with (
        patch("aegis.client.CanisterTransport") as MockTransport,
        patch("aegis.client.load_config", return_value={}),
    ):
        mock_transport = transport or _make_mock_transport()
        MockTransport.return_value = mock_transport

        from aegis.client import AegisClient

        client = AegisClient(
            canister_id="toqqq-lqaaa-aaaae-afc2a-cai",
            api_key_id=api_key_id,
            private_key_path=pem_path,
            agent_id="e2e-test-agent",
            org_id=org_id,
            session_id=session_id,
            fail_open=fail_open,
            environment=Environment(framework="e2e-test"),
        )
        return client, mock_transport


# ============================================================================
# W-02: Agent-Integration E2E (KRITISCH)
# ============================================================================

class TestW02AgentIntegration:
    """Kompletter Agent-Integration-Flow: Init → Log → Chain → Verify → PII."""

    def test_full_agent_lifecycle(self, tmp_pem):
        """W-02 Steps 1-9: Complete agent integration from init to chained entries."""
        client, transport = _make_client(tmp_pem)

        # Step 1-3: Client konfiguriert
        assert client._org_id == "un4fu-tqaaa-aaaab-qadjq-cai"
        assert client._api_key_id == "ak_e2e"
        assert client._agent_id == "e2e-test-agent"

        # Step 5: Ersten Trace loggen
        action_id_1 = client.log_tool_call(
            tool="web_search",
            input_data={"query": "aegis e2e test"},
            output_data={"results": ["result1"]},
            duration_ms=42,
        )
        assert action_id_1 is not None
        assert isinstance(action_id_1, str)

        # Step 6: Decision loggen
        action_id_2 = client.log_decision(
            reasoning="Wähle bestes Ergebnis",
            confidence=0.95,
        )
        assert action_id_2 is not None

        # Step 7: Observation loggen
        action_id_3 = client.log_observation(
            input_data="Agent hat Ergebnis verarbeitet",
        )
        assert action_id_3 is not None

        # Step 8: Prüfe Hash-Chain Verkettung
        assert transport.call_update.call_count == 3
        calls = transport.call_update.call_args_list

        # Erster Entry: previousChainHash = ""
        first_rec = calls[0][0][1][0]["value"]
        assert first_rec["previousChainHash"] == "", "First entry previousChainHash must be empty"

        # Zweiter Entry: previousChainHash = chainHash des ersten
        first_chain_hash = first_rec["chainHash"]
        second_rec = calls[1][0][1][0]["value"]
        assert second_rec["previousChainHash"] == first_chain_hash, "Chain linkage broken"

        # Dritter Entry: previousChainHash = chainHash des zweiten
        second_chain_hash = second_rec["chainHash"]
        third_rec = calls[2][0][1][0]["value"]
        assert third_rec["previousChainHash"] == second_chain_hash, "Chain linkage broken"

        # Step 9: Sequenz monoton steigend
        seq1 = first_rec["sequenceNumber"]
        seq2 = second_rec["sequenceNumber"]
        seq3 = third_rec["sequenceNumber"]
        assert seq1 < seq2 < seq3, f"Sequence not monotonic: {seq1}, {seq2}, {seq3}"

    def test_signature_present_and_prefixed(self, tmp_pem):
        """W-02: Ed25519 Signatur muss im Candid-Arg sein."""
        client, transport = _make_client(tmp_pem)
        client.log_tool_call(tool="search", input_data={}, output_data={}, duration_ms=0)

        rec = transport.call_update.call_args[0][1][0]["value"]
        sig = rec["payloadSignature"]
        assert sig.startswith("ed25519:"), f"Signature must have ed25519 prefix, got: {sig[:20]}"
        assert len(sig) > 10, "Signature too short"

    def test_payload_hex_is_canonical_json(self, tmp_pem):
        """W-02: payloadHex muss kanonisches JSON der Payload-Daten sein."""
        client, transport = _make_client(tmp_pem)
        client.log_tool_call(
            tool="my_tool",
            input_data={"b": 2, "a": 1},  # unsortiert
            output_data={"result": "ok"},
            duration_ms=100,
        )

        rec = transport.call_update.call_args[0][1][0]["value"]
        payload_hex = rec["payloadHex"]
        assert len(payload_hex) > 0
        # Decode und prüfe JSON-Sortierung
        payload_bytes = bytes.fromhex(payload_hex)
        payload_dict = json.loads(payload_bytes)
        assert isinstance(payload_dict, dict)
        # Keys müssen sortiert sein (kanonisch)
        keys = list(payload_dict.keys())
        assert keys == sorted(keys), "Payload JSON is not canonical (keys not sorted)"

    def test_pii_redaction_in_full_flow(self, tmp_pem):
        """W-02: PII muss in Previews redacted werden."""
        client, transport = _make_client(tmp_pem)
        client.log_tool_call(
            tool="search",
            input_data={"email": "john@example.com", "ssn": "123-45-6789"},
            output_data={"result": "found"},
            duration_ms=10,
        )

        rec = transport.call_update.call_args[0][1][0]["value"]
        assert rec["inputPreview"] == "", "inputPreview must be empty (PII protection)"
        assert rec["outputPreview"] == "", "outputPreview must be empty (PII protection)"

    def test_chain_hash_deterministic(self, tmp_pem):
        """W-02: Gleiche Payload → gleicher Hash."""
        h1 = compute_chain_hash("", b"test payload")
        h2 = compute_chain_hash("", b"test payload")
        assert h1 == h2

    def test_five_action_types_accepted(self, tmp_pem):
        """W-02: Alle 5 ActionTypes müssen akzeptiert werden."""
        client, transport = _make_client(tmp_pem)

        client.log_tool_call(tool="t", input_data={}, output_data={}, duration_ms=0)
        client.log_decision(reasoning="r", confidence=0.5)
        client.log_observation(input_data="obs")
        client.log_error(tool="t", input_data={}, error=ValueError("err"))

        assert transport.call_update.call_count == 4

        # Prüfe ActionType-Varianten
        expected_types = [
            {"toolCall": None},
            {"decision": None},
            {"observation": None},
            {"error": None},
        ]
        for i, expected in enumerate(expected_types):
            rec = transport.call_update.call_args_list[i][0][1][0]["value"]
            assert rec["actionType"] == expected, f"ActionType mismatch at call {i}"

    def test_trace_decorator_captures_io(self, tmp_pem):
        """W-02: @trace Decorator muss I/O hashen und Ergebnis durchreichen."""
        client, transport = _make_client(tmp_pem)

        @client.trace(action_type="tool_call", tool_name="traced_func")
        def my_func(x: int) -> dict:
            return {"doubled": x * 2}

        result = my_func(21)
        assert result == {"doubled": 42}

        rec = transport.call_update.call_args[0][1][0]["value"]
        assert rec["tool"] == "traced_func"
        assert rec["inputHash"].startswith("sha256:")
        assert rec["outputHash"].startswith("sha256:")


# ============================================================================
# W-03: Public Verification
# ============================================================================

class TestW03PublicVerification:
    """Anonyme Verifikation: Signatur prüfen, Chain-Link prüfen."""

    def test_ed25519_sign_and_verify_roundtrip(self, tmp_pem):
        """W-03: Ed25519-Signatur kann lokal verifiziert werden."""
        from aegis.crypto import load_private_key
        from cryptography.hazmat.primitives.serialization import PublicFormat
        private_key = load_private_key(tmp_pem)
        scheme = create_scheme("ed25519", private_key)
        payload = b"test payload for verification"
        signature = scheme.sign(payload)

        assert signature.startswith("ed25519:")
        pk_bytes = private_key.public_key().public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw,
        )
        assert scheme.verify(payload, signature, pk_bytes)

    def test_tampered_payload_fails_verification(self, tmp_pem):
        """W-03: Manipulation der Payload → Verifikation schlägt fehl."""
        from aegis.crypto import load_private_key
        from cryptography.hazmat.primitives.serialization import PublicFormat
        private_key = load_private_key(tmp_pem)
        scheme = create_scheme("ed25519", private_key)
        payload = b"original payload"
        signature = scheme.sign(payload)

        pk_bytes = private_key.public_key().public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw,
        )
        tampered = b"tampered payload"
        assert not scheme.verify(tampered, signature, pk_bytes)

    def test_chain_integrity_detects_tampering(self):
        """W-03: Chain-Break durch Manipulation wird erkannt."""
        # Baue 3-Entry Chain
        p1, p2, p3 = b"entry1", b"entry2", b"entry3"
        h1 = compute_chain_hash("", p1)
        h2 = compute_chain_hash(h1, p2)
        h3 = compute_chain_hash(h2, p3)

        # Tamper Entry 2 → h2' und h3' müssen anders sein
        h2_tampered = compute_chain_hash(h1, b"TAMPERED entry2")
        h3_from_tampered = compute_chain_hash(h2_tampered, p3)

        assert h2 != h2_tampered, "Tampered entry must produce different hash"
        assert h3 != h3_from_tampered, "Downstream hash must change after tampering"

    def test_wrong_key_fails_verification(self, tmp_pem, tmp_pem_2):
        """W-03: Falscher Public Key → Verifikation schlägt fehl."""
        from aegis.crypto import load_private_key
        from cryptography.hazmat.primitives.serialization import PublicFormat
        pk1 = load_private_key(tmp_pem)
        scheme1 = create_scheme("ed25519", pk1)
        payload = b"signed by key 1"
        signature = scheme1.sign(payload)

        pk2 = load_private_key(tmp_pem_2).public_key()
        pk2_bytes = pk2.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        assert not scheme1.verify(payload, signature, pk2_bytes)


# ============================================================================
# W-05: Key-Rotation
# ============================================================================

class TestW05KeyRotation:
    """Key-Rotation: Alter Key → Revoke → Neuer Key → Chain-Kontinuität."""

    def test_key_rotation_chain_continuity(self, tmp_pem, tmp_pem_2):
        """W-05: Hash-Chain bleibt intakt über Key-Wechsel."""
        # Phase 1: Log mit Key 1
        client1, transport1 = _make_client(tmp_pem, session_id="rotation-session")
        client1.log_tool_call(tool="before_rotation", input_data={}, output_data={}, duration_ms=0)
        first_chain_hash = transport1.call_update.call_args[0][1][0]["value"]["chainHash"]

        # Speichere chain_heads State
        chain_head = client1._chain_heads.get("rotation-session")
        assert chain_head is not None

        # Phase 2: Key-Rotation → neuer Client mit Key 2, gleiche Session
        # In Realität: revokeApiKey(old) + createApiKey(new)
        client2, transport2 = _make_client(
            tmp_pem_2, session_id="rotation-session", api_key_id="ak_rotated"
        )
        # Übertrage Chain-State (in Realität würde der Client das persistieren)
        client2._chain_heads["rotation-session"] = chain_head
        client2._sequence = client1._sequence

        client2.log_tool_call(tool="after_rotation", input_data={}, output_data={}, duration_ms=0)

        # Phase 3: Prüfe Kontinuität
        second_rec = transport2.call_update.call_args[0][1][0]["value"]
        assert second_rec["previousChainHash"] == first_chain_hash, \
            "previousChainHash after rotation must equal last chainHash before rotation"

    def test_different_keys_produce_different_signatures(self, tmp_pem, tmp_pem_2):
        """W-05: Verschiedene Keys → verschiedene Signaturen."""
        from aegis.crypto import load_private_key
        scheme1 = create_scheme("ed25519", load_private_key(tmp_pem))
        scheme2 = create_scheme("ed25519", load_private_key(tmp_pem_2))
        payload = b"same payload"

        sig1 = scheme1.sign(payload)
        sig2 = scheme2.sign(payload)
        assert sig1 != sig2, "Different keys must produce different signatures"

    def test_old_entries_remain_verifiable_with_old_key(self, tmp_pem, tmp_pem_2):
        """W-05: Alte Traces bleiben mit altem Key verifizierbar."""
        from aegis.crypto import load_private_key
        from cryptography.hazmat.primitives.serialization import PublicFormat
        pk1 = load_private_key(tmp_pem)
        scheme1 = create_scheme("ed25519", pk1)
        payload = b"old entry payload"
        signature = scheme1.sign(payload)

        pk1_bytes = pk1.public_key().public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw,
        )
        assert scheme1.verify(payload, signature, pk1_bytes), \
            "Old entries must remain verifiable with old key"


# ============================================================================
# W-07: Multi-Agent Multi-Session
# ============================================================================

class TestW07MultiAgentMultiSession:
    """3 parallele Agents, 3 Sessions, 1 Org — unabhängige Hash-Chains."""

    def test_three_agents_independent_sessions(self, tmp_pem):
        """W-07: 3 Agents mit eigenen Sessions haben unabhängige Chains."""
        clients = []
        transports = []

        for i in range(3):
            c, t = _make_client(
                tmp_pem,
                session_id=f"session_{i}",
                api_key_id=f"ak_agent_{i}",
            )
            clients.append(c)
            transports.append(t)

        # Agent A: 5 Entries
        for j in range(5):
            clients[0].log_tool_call(
                tool=f"tool_a_{j}", input_data={}, output_data={}, duration_ms=0,
            )

        # Agent B: 3 Entries
        for j in range(3):
            clients[1].log_tool_call(
                tool=f"tool_b_{j}", input_data={}, output_data={}, duration_ms=0,
            )

        # Agent C: 7 Entries
        for j in range(7):
            clients[2].log_tool_call(
                tool=f"tool_c_{j}", input_data={}, output_data={}, duration_ms=0,
            )

        # Prüfe: Jede Session hat eigene Sequenz
        assert clients[0].sequence_number == 5
        assert clients[1].sequence_number == 3
        assert clients[2].sequence_number == 7

        # Prüfe: Jede Session hat eigenen Chain-Head
        heads = [
            clients[i]._chain_heads.get(f"session_{i}")
            for i in range(3)
        ]
        assert all(h is not None for h in heads), "All sessions must have chain heads"
        assert len(set(heads)) == 3, "All chain heads must be unique"

    def test_concurrent_agents_thread_safe(self, tmp_pem):
        """W-07: Concurrent logging aus 3 Threads ist thread-safe."""
        client, transport = _make_client(tmp_pem, session_id="concurrent-session")
        errors = []

        def log_from_thread(thread_id: int):
            try:
                for j in range(10):
                    client.log_tool_call(
                        tool=f"thread_{thread_id}_tool_{j}",
                        input_data={}, output_data={}, duration_ms=0,
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=log_from_thread, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Thread errors: {errors}"
        assert client.sequence_number == 30, f"Expected 30, got {client.sequence_number}"
        assert transport.call_update.call_count == 30

    def test_all_agents_same_org(self, tmp_pem):
        """W-07: Alle 3 Agents loggen unter gleicher Org."""
        for i in range(3):
            c, t = _make_client(tmp_pem, session_id=f"org_session_{i}")
            c.log_tool_call(tool="org_test", input_data={}, output_data={}, duration_ms=0)
            rec = t.call_update.call_args[0][1][0]["value"]
            from aegis.transport import _principal_text_to_bytes
            expected = _principal_text_to_bytes("un4fu-tqaaa-aaaab-qadjq-cai")
            assert rec["orgId"] == expected, f"Agent {i} must use same org"


# ============================================================================
# W-08: Rate-Limit Hit
# ============================================================================

class TestW08RateLimit:
    """Rate-Limiting: Spam → Block → Resume."""

    def test_rapid_fire_accepted_with_mock(self, tmp_pem):
        """W-08: 100 schnelle Requests werden vom SDK akzeptiert (Canister limitiert)."""
        client, transport = _make_client(tmp_pem)

        for i in range(100):
            client.log_tool_call(
                tool=f"rapid_tool_{i}",
                input_data={}, output_data={}, duration_ms=0,
            )

        assert transport.call_update.call_count == 100
        assert client.sequence_number == 100

    def test_canister_reject_propagates_as_error(self, tmp_pem):
        """W-08: Canister-Reject (Rate-Limit) wird als Error propagiert."""
        client, transport = _make_client(tmp_pem, fail_open=False)
        transport.call_update.side_effect = Exception("Rate limit exceeded")

        with pytest.raises(Exception, match="Rate limit"):
            client.log_tool_call(
                tool="rate_limited_tool",
                input_data={}, output_data={}, duration_ms=0,
            )

    def test_fail_open_absorbs_rate_limit(self, tmp_pem):
        """W-08: fail_open=True absorbiert Rate-Limit-Fehler."""
        client, transport = _make_client(tmp_pem, fail_open=True)
        transport.call_update.side_effect = ConnectionError("Rate limit")

        result = client.log_tool_call(
            tool="rate_limited_tool",
            input_data={}, output_data={}, duration_ms=0,
        )
        # Muss entweder spilled_* zurückgeben oder None — kein Crash
        assert result is None or isinstance(result, str)


# ============================================================================
# W-09: Fail-Open + Spill/Drain
# ============================================================================

class TestW09FailOpenSpillDrain:
    """Canister down → Spill → Recovery → Drain."""

    def test_full_fail_open_cycle(self, tmp_pem):
        """W-09: Kompletter Zyklus: Success → Canister down → Spill → Recovery."""
        client, transport = _make_client(tmp_pem, session_id="spill-cycle")

        # Phase 1: Normaler Betrieb
        transport.call_update.return_value = {"actionId": "act_ok_1"}
        action_1 = client.log_tool_call(
            tool="normal_1", input_data={}, output_data={}, duration_ms=0,
        )
        assert action_1 is not None
        assert "spill-cycle" in client._chain_heads

        head_before_spill = client._chain_heads["spill-cycle"]

        # Phase 2: Canister down → Spill
        transport.call_update.side_effect = ConnectionError("canister unreachable")
        action_spilled = client.log_tool_call(
            tool="during_outage", input_data={}, output_data={}, duration_ms=0,
        )
        assert action_spilled.startswith("spilled_")

        # Chain-Head darf sich NICHT geändert haben (F-3 Fix)
        assert client._chain_heads["spill-cycle"] == head_before_spill

        # Phase 3: Recovery
        transport.call_update.side_effect = None
        transport.call_update.return_value = {"actionId": "act_ok_2"}
        action_3 = client.log_tool_call(
            tool="after_recovery", input_data={}, output_data={}, duration_ms=0,
        )
        assert action_3 is not None

        # previousChainHash des Recovery-Entries muss = head_before_spill sein
        recovery_rec = transport.call_update.call_args[0][1][0]["value"]
        assert recovery_rec["previousChainHash"] == head_before_spill

    def test_sequence_not_advanced_on_spill(self, tmp_pem):
        """W-09: Sequence darf bei Spill nicht erhöht werden."""
        client, transport = _make_client(tmp_pem, session_id="seq-spill")

        transport.call_update.return_value = {"actionId": "ok"}
        client.log_tool_call(tool="t1", input_data={}, output_data={}, duration_ms=0)
        assert client.sequence_number == 1

        transport.call_update.side_effect = ConnectionError("down")
        client.log_tool_call(tool="spilled", input_data={}, output_data={}, duration_ms=0)
        assert client.sequence_number == 1, "Sequence must NOT advance on spill"

    def test_spill_buffer_persists_to_disk(self, tmp_path):
        """W-09: Spill-Einträge werden auf Disk geschrieben."""
        config = TransportConfig(canister_id="disk-spill", spill_dir=str(tmp_path))
        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                "aegis.transport.CanisterTransport._init_agent",
                lambda self: setattr(self, "_ic_available", False),
            )
            transport = CanisterTransport(config)

        transport._spill_to_disk("addLedgerEntry", [{"type": "text", "value": "spilled_data"}])
        spill_file = tmp_path / "disk-spill.jsonl"
        assert spill_file.exists(), "Spill file must be created"
        assert "addLedgerEntry" in spill_file.read_text()

    def test_drain_replays_all_spilled_entries(self, tmp_path):
        """W-09: Drain muss alle Spill-Einträge replayed haben."""
        import json as _json
        config = TransportConfig(canister_id="drain-all", spill_dir=str(tmp_path))
        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                "aegis.transport.CanisterTransport._init_agent",
                lambda self: setattr(self, "_ic_available", True),
            )
            transport = CanisterTransport(config)

        # Pre-fill 5 spill entries
        spill_file = tmp_path / "drain-all.jsonl"
        now_ms = int(time.time() * 1000)
        entries = []
        for i in range(5):
            vals = [
                f"act_{i}", "rrkah-fqaaa-aaaaa-aaaaq-cai", "agent-1", "sess-1", i,
                {"toolCall": None}, "search", "sha256:in", "sha256:out",
                "", "", 100, "success", "", "", 0.9, "unknown", "", now_ms,
                "ed25519:abc", "chainabc", "", "payload", "ak_test",
            ]
            entries.append(_json.dumps({
                "method": "addLedgerEntry", "raw_values": vals,
                "timestamp_ms": now_ms, "canister_id": "drain-all",
                "spill_version": 2,
            }))
        spill_file.write_text("\n".join(entries) + "\n")

        with pytest.MonkeyPatch.context() as m:
            m.setattr(transport, "_do_call", lambda method, args, call_type: {"ok": True})
            drained = transport.drain_spill_buffer()

        assert drained == 5, f"Expected 5 drained, got {drained}"
        assert not spill_file.exists(), "Spill file should be deleted after full drain"


# ============================================================================
# W-10: Compliance Report
# ============================================================================

class TestW10ComplianceReport:
    """Compliance Report generieren und verifizieren."""

    def test_eu_ai_act_report_generation(self):
        """W-10: EU AI Act Report enthält alle Pflichtfelder."""
        from aegis.report import ReportFormat, generate_report

        stats = {
            "total_actions": 100, "total_agents": 2, "total_sessions": 5,
            "active_api_keys": 1, "revoked_api_keys": 0, "chain_length": 100,
            "latest_chain_hash": "a" * 64,
            "coverage_start": "2026-01-01T00:00:00Z",
            "coverage_end": "2026-03-09T00:00:00Z",
        }
        health = {"status": "healthy", "chain_valid": True, "uptime_seconds": 86400}

        report = generate_report(
            canister_id="toqqq-lqaaa-aaaae-afc2a-cai",
            format=ReportFormat.EU_AI_ACT,
            stats=stats,
            health=health,
        )

        assert report is not None
        assert report.markdown is not None
        assert "EU AI Act" in report.markdown or "eu-ai-act" in report.markdown.lower()
        assert "toqqq-lqaaa-aaaae-afc2a-cai" in report.markdown
        assert "100" in report.markdown  # total_actions

    def test_iso_42001_report_generation(self):
        """W-10: ISO 42001 Report generierbar."""
        from aegis.report import ReportFormat, generate_report

        stats = {
            "total_actions": 50, "total_agents": 1, "total_sessions": 3,
            "active_api_keys": 1, "revoked_api_keys": 0, "chain_length": 50,
            "latest_chain_hash": "b" * 64,
            "coverage_start": "2026-01-01T00:00:00Z",
            "coverage_end": "2026-03-09T00:00:00Z",
        }
        health = {"status": "healthy", "chain_valid": True, "uptime_seconds": 86400}

        report = generate_report(
            canister_id="toqqq-lqaaa-aaaae-afc2a-cai",
            format=ReportFormat.ISO_42001,
            stats=stats,
            health=health,
        )

        assert report is not None
        assert len(report.markdown) > 100

    def test_all_reports_generate_without_error(self):
        """W-10: Alle 3 Report-Formate generieren ohne Exception."""
        from aegis.report import generate_all_reports

        stats = {
            "total_actions": 200, "total_agents": 3, "total_sessions": 10,
            "active_api_keys": 2, "revoked_api_keys": 1, "chain_length": 200,
            "latest_chain_hash": "c" * 64,
            "coverage_start": "2026-02-01T00:00:00Z",
            "coverage_end": "2026-03-09T00:00:00Z",
        }
        health = {"status": "healthy", "chain_valid": True, "uptime_seconds": 172800}

        reports = generate_all_reports(
            canister_id="toqqq-lqaaa-aaaae-afc2a-cai",
            stats=stats,
            health=health,
        )

        assert len(reports) == 3, f"Expected 3 reports, got {len(reports)}"
        for r in reports:
            assert r.markdown is not None
            assert len(r.markdown) > 50

    def test_compliance_score_computed(self):
        """W-10: Compliance Score wird berechnet."""
        from aegis.report import _compute_compliance_score

        stats = {
            "total_actions": 100, "total_agents": 2, "total_sessions": 5,
            "active_api_keys": 1, "revoked_api_keys": 0, "chain_length": 100,
            "latest_chain_hash": "a" * 64,
            "coverage_start": "2026-01-01T00:00:00Z",
            "coverage_end": "2026-03-09T00:00:00Z",
        }
        health = {"status": "healthy", "chain_valid": True, "uptime_seconds": 86400}
        score = _compute_compliance_score(stats, health)
        assert 0.0 <= score <= 1.0


# ============================================================================
# Cross-Workflow: Fehler-Szenarien
# ============================================================================

class TestErrorScenarios:
    """Fehler-Szenarien aus Phase 3 der Skill-Definition."""

    def test_empty_canister_id_rejected(self):
        """Fehler W-01: Leere canister_id muss ValueError werfen."""
        with (
            pytest.raises(ValueError, match="canister_id"),
            patch("aegis.client.load_private_key", return_value=Ed25519PrivateKey.generate()),
            patch("aegis.client.CanisterTransport"),
            patch("aegis.client.load_config", return_value={}),
        ):
                from aegis.client import AegisClient
                AegisClient(
                    canister_id="",
                    api_key_id="ak_test",
                    private_key_path="fake.pem",
                    agent_id="agent",
                    org_id="org",
                )

    def test_negative_duration_rejected(self, tmp_pem):
        """Fehler W-02: Negative duration_ms muss ValueError werfen."""
        client, _ = _make_client(tmp_pem)
        with pytest.raises(ValueError, match="duration_ms"):
            client.log_tool_call(tool="t", input_data={}, output_data={}, duration_ms=-5)

    def test_confidence_out_of_range_rejected(self, tmp_pem):
        """Fehler W-02: confidence > 1.0 muss ValueError werfen."""
        client, _ = _make_client(tmp_pem)
        with pytest.raises(ValueError, match="confidence"):
            client.log_decision(reasoning="r", confidence=1.5)

    def test_fail_open_false_raises_on_network_error(self, tmp_pem):
        """Fehler W-09: fail_open=False muss bei Netzwerkfehler Exception werfen."""
        client, transport = _make_client(tmp_pem, fail_open=False)
        transport.call_update.side_effect = ConnectionError("network down")

        with pytest.raises(ConnectionError, match="network down"):
            client.log_tool_call(tool="t", input_data={}, output_data={}, duration_ms=0)

    def test_context_manager_cleanup(self, tmp_pem):
        """Fehler: close()/context manager muss drain aufrufen."""
        client, transport = _make_client(tmp_pem)
        with client:
            client.log_tool_call(tool="t", input_data={}, output_data={}, duration_ms=0)
        transport.drain_spill_buffer.assert_called_once()


# ============================================================================
# Performance: Time-to-First-Trace
# ============================================================================

class TestPerformance:
    """Performance-Metriken für E2E-Workflows."""

    def test_time_to_first_trace_under_100ms(self, tmp_pem):
        """Performance: Client init + erster Trace muss < 100ms sein (mock)."""
        start = time.time()
        client, _ = _make_client(tmp_pem)
        client.log_tool_call(tool="perf_test", input_data={}, output_data={}, duration_ms=0)
        elapsed_ms = (time.time() - start) * 1000

        assert elapsed_ms < 100, f"Time-to-first-trace too slow: {elapsed_ms:.1f}ms (limit: 100ms)"

    def test_batch_100_entries_under_1s(self, tmp_pem):
        """Performance: 100 Entries müssen < 1s dauern (mock)."""
        client, _ = _make_client(tmp_pem)

        start = time.time()
        for i in range(100):
            client.log_tool_call(tool=f"batch_{i}", input_data={}, output_data={}, duration_ms=0)
        elapsed_ms = (time.time() - start) * 1000

        assert elapsed_ms < 1000, f"100 entries too slow: {elapsed_ms:.1f}ms (limit: 1000ms)"


# ============================================================================
# PQ-E2E: Post-Quantum Workflows (Batch 6-9)
# ============================================================================

class TestPQE2ESignatureSchemes:
    """E2E-Tests für alle 4 Signatur-Algorithmen (PQ-0 bis PQ-2)."""

    def test_ed25519_full_roundtrip(self, tmp_pem):
        """PQ-E2E: Ed25519 Sign → Verify Roundtrip."""
        from aegis.crypto import load_private_key
        from cryptography.hazmat.primitives.serialization import PublicFormat
        pk = load_private_key(tmp_pem)
        scheme = create_scheme("ed25519", pk)

        payload = canonical_json({"action": "test", "tool": "web_search"})
        sig = scheme.sign(payload)
        pk_bytes = pk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        assert sig.startswith("ed25519:")
        assert scheme.verify(payload, sig, pk_bytes)
        assert scheme.algorithm_id == "ed25519"
        assert scheme.public_key_size == 32

    def test_mldsa65_full_roundtrip(self):
        """PQ-E2E: ML-DSA-65 Sign → Verify Roundtrip (FIPS 204)."""
        try:
            from pqcrypto.sign.ml_dsa_65 import generate_keypair  # noqa: F401
        except ImportError:
            pytest.skip("pqcrypto not installed")

        pk_bytes, sk_bytes = generate_keypair()
        from aegis.crypto import MLDSA65Scheme
        scheme = MLDSA65Scheme(sk_bytes)

        payload = canonical_json({"action": "pq_test", "algorithm": "ml-dsa-65"})
        sig = scheme.sign(payload)

        assert sig.startswith("ml-dsa-65:")
        assert scheme.verify(payload, sig, pk_bytes)
        assert scheme.algorithm_id == "ml-dsa-65"
        assert scheme.public_key_size == 1952

    def test_slhdsa128s_full_roundtrip(self):
        """PQ-E2E: SLH-DSA-128s Sign → Verify Roundtrip (FIPS 205, Batch 7)."""
        try:
            from pqcrypto.sign.sphincs_shake_128s_simple import generate_keypair
        except ImportError:
            pytest.skip("pqcrypto not installed")

        pk_bytes, sk_bytes = generate_keypair()
        from aegis.crypto import SLHDSA128sScheme
        scheme = SLHDSA128sScheme(sk_bytes)

        payload = canonical_json({"action": "slh_test", "algorithm": "slh-dsa-128s"})
        sig = scheme.sign(payload)

        assert sig.startswith("slh-dsa-128s:")
        assert scheme.verify(payload, sig, pk_bytes)
        assert scheme.algorithm_id == "slh-dsa-128s"
        assert scheme.public_key_size == 32
        assert scheme.signature_size == 7856

    def test_mldsa87_full_roundtrip(self):
        """PQ-E2E: ML-DSA-87 Sign → Verify Roundtrip (FIPS 204, CNSA 2.0 Level 5)."""
        try:
            from pqcrypto.sign.ml_dsa_87 import generate_keypair
        except ImportError:
            pytest.skip("pqcrypto not installed")

        pk_bytes, sk_bytes = generate_keypair()
        from aegis.crypto import MLDSA87Scheme
        scheme = MLDSA87Scheme(sk_bytes)

        payload = canonical_json({"action": "pq_test", "algorithm": "ml-dsa-87"})
        sig = scheme.sign(payload)

        assert sig.startswith("ml-dsa-87:")
        assert scheme.verify(payload, sig, pk_bytes)
        assert scheme.algorithm_id == "ml-dsa-87"
        assert scheme.public_key_size == 2592
        assert scheme.signature_size == 4627

    def test_hybrid_full_roundtrip(self):
        """PQ-E2E: Hybrid (Ed25519 + ML-DSA-65) Sign → Verify Roundtrip (Batch 4)."""
        try:
            from pqcrypto.sign.ml_dsa_65 import generate_keypair as mldsa_keygen
        except ImportError:
            pytest.skip("pqcrypto not installed")

        ed_key = Ed25519PrivateKey.generate()
        ml_pk, ml_sk = mldsa_keygen()
        scheme = create_scheme("hybrid", (ed_key, ml_sk))

        payload = canonical_json({"action": "hybrid_test"})
        sig = scheme.sign(payload)

        from cryptography.hazmat.primitives.serialization import PublicFormat
        ed_pk_bytes = ed_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        combined_pk = ed_pk_bytes + ml_pk

        assert sig.startswith("hybrid:")
        assert scheme.verify(payload, sig, combined_pk)
        assert scheme.algorithm_id == "hybrid"

    def test_all_five_schemes_in_supported(self):
        """PQ-E2E: SUPPORTED_SCHEMES enthält alle 5 Algorithmen."""
        from aegis.crypto import SUPPORTED_SCHEMES
        expected = {"ed25519", "ml-dsa-65", "ml-dsa-87", "slh-dsa-128s", "hybrid"}
        assert set(SUPPORTED_SCHEMES.keys()) == expected

    def test_cross_scheme_verification_fails(self, tmp_pem):
        """PQ-E2E: Ed25519-Signatur darf NICHT mit ML-DSA-65 verifizierbar sein."""
        from aegis.crypto import load_private_key
        pk = load_private_key(tmp_pem)
        scheme = create_scheme("ed25519", pk)
        payload = b"cross-scheme test"
        sig = scheme.sign(payload)

        # ML-DSA-65 Verify mit Ed25519-Signatur muss fehlschlagen
        try:
            from aegis.crypto import MLDSA65Scheme
            from pqcrypto.sign.ml_dsa_65 import generate_keypair as ml_keygen
            ml_pk, ml_sk = ml_keygen()
            ml_scheme = MLDSA65Scheme(ml_sk)
            assert not ml_scheme.verify(payload, sig, ml_pk)
        except ImportError:
            pytest.skip("pqcrypto not installed")

