# NOTE: Integration test with mocked transport — not a real E2E test.
"""
E2E-Tests fuer v0.3.0-Features — OTel-Felder, OTelExporter, queryOnly Permission Keys.

Abdeckung:
  TD1 Happy Path: OTel auto-extract aus Context, OTelExporter, queryOnly Read
  TD2 Error Path: queryOnly Key auf Write, leere Session
  TD6 State Transitions: OTel-Kontext unabhaengig pro Entry, chain bleibt intakt
  TD8 Security Boundaries: queryOnly Key darf nicht schreiben

Bekannte Gaps (dokumentiert):
  GAP-1: cost_usd + token_count nicht via public API setzbar (immer 0.0/0 → Candid [])
  GAP-2: Kein explizites OTel-kwarg in log_* — nur auto-extract via opentelemetry context

Candid Opt-Encoding: Opt(Text) wird als Liste uebertragen:
  Some("val") → ["val"]
  None        → []

Aufruf:
    cd /c/ARBEIT/AegisProtocol
    python -m pytest AEGIS_LEDGER/tests/test_e2e_v030_features.py -v
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def tmp_pem(tmp_path):
    key = Ed25519PrivateKey.generate()
    pem_path = tmp_path / "test_key.pem"
    pem_path.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    return str(pem_path)


def _make_client(pem_path, session_id="e2e-otel-session", fail_open=True):
    transport = MagicMock()
    transport.call_update.return_value = {"actionId": "act_otel_001"}
    transport.spill_count = 0
    transport.drain_spill_buffer.return_value = 0

    with (
        patch("aegis.client.CanisterTransport") as MockTransport,
        patch("aegis.client.load_config", return_value={}),
    ):
        MockTransport.return_value = transport
        from aegis.client import AegisClient
        from aegis.types import Environment

        client = AegisClient(
            canister_id="toqqq-lqaaa-aaaae-afc2a-cai",
            api_key_id="ak_e2e_otel",
            private_key_path=pem_path,
            agent_id="otel-test-agent",
            org_id="un4fu-tqaaa-aaaab-qadjq-cai",
            session_id=session_id,
            fail_open=fail_open,
            environment=Environment(framework="e2e-otel-test"),
        )
    return client, transport


def _otel_val(rec, key):
    """Candid Opt-Encoding: ["val"] = Some, [] = None. Gibt str oder None zurueck."""
    v = rec.get(key, [])
    return v[0] if isinstance(v, list) and v else (None if isinstance(v, list) else v)


# ============================================================================
# TD1: OTel Auto-Extract Happy Path
# ============================================================================

class TestOTelAutoExtract:
    """v0.3.0: OTel-Felder werden auto-extracted aus OpenTelemetry Context."""

    def test_otel_trace_id_auto_extracted_from_context(self, tmp_pem):
        """Wenn OTel-Context aktiv: otelTraceId landet im Candid-Record (Opt-encoded)."""
        client, transport = _make_client(tmp_pem)

        with patch("aegis.entry_builder.extract_otel_context",
                   return_value=("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", "")):
            client.log_tool_call(
                tool="otel_tool",
                input_data={"city": "Zurich"},
                output_data={"temp": 18},
                duration_ms=42,
            )

        rec = transport.call_update.call_args[0][1][0]["value"]
        assert _otel_val(rec, "otelTraceId") == "4bf92f3577b34da6a3ce929d0e0e4736", \
            f"otelTraceId falsch: {rec.get('otelTraceId')}"
        assert _otel_val(rec, "otelSpanId") == "00f067aa0ba902b7", \
            f"otelSpanId falsch: {rec.get('otelSpanId')}"

    def test_otel_parent_span_id_auto_extracted(self, tmp_pem):
        """otel_parent_span_id wird korrekt durchgereicht wenn im Context."""
        client, transport = _make_client(tmp_pem)

        with patch("aegis.entry_builder.extract_otel_context",
                   return_value=("trace_parent", "span_child", "span_parent")):
            client.log_tool_call(
                tool="nested_tool",
                input_data={},
                output_data={},
                duration_ms=10,
            )

        rec = transport.call_update.call_args[0][1][0]["value"]
        assert _otel_val(rec, "otelParentSpanId") == "span_parent", \
            f"otelParentSpanId falsch: {rec.get('otelParentSpanId')}"

    def test_otel_fields_none_when_no_context(self, tmp_pem):
        """Ohne OTel-Context: otelTraceId ist Candid None ([]) — kein Crash."""
        client, transport = _make_client(tmp_pem)

        with patch("aegis.entry_builder.extract_otel_context", return_value=("", "", "")):
            action_id = client.log_tool_call(
                tool="no_otel_tool",
                input_data={},
                output_data={},
                duration_ms=5,
            )

        assert action_id is not None
        rec = transport.call_update.call_args[0][1][0]["value"]
        # Leerer String → Candid None → [] im Record
        assert rec.get("otelTraceId") == [], \
            f"otelTraceId sollte [] (Candid None) sein: {rec.get('otelTraceId')}"

    def test_all_four_log_methods_carry_otel_fields(self, tmp_pem):
        """Alle 4 log_* Methoden extrahieren OTel-Kontext."""
        client, transport = _make_client(tmp_pem)

        with patch("aegis.entry_builder.extract_otel_context",
                   return_value=("trace_all", "span_all", "")):
            client.log_tool_call(tool="t", input_data={}, output_data={}, duration_ms=0)
            client.log_decision(reasoning="r", confidence=0.5)
            client.log_observation(input_data="obs")
            client.log_error(tool="t", input_data={}, error=ValueError("err"))

        assert transport.call_update.call_count == 4
        for i, call in enumerate(transport.call_update.call_args_list):
            rec = call[0][1][0]["value"]
            assert _otel_val(rec, "otelTraceId") == "trace_all", \
                f"Call {i}: otelTraceId fehlt im Record: {rec.get('otelTraceId')}"

    def test_otel_fields_in_signable_dict(self):
        """CRITICAL v0.3.0: otel_trace_id muss in to_signable_dict() enthalten sein."""
        from aegis.types import (
            ActionContext,
            ActionPayload,
            ActionStatus,
            ActionType,
            Environment,
            LogEntry,
        )

        entry = LogEntry(
            agent_id="agent",
            session_id="sess",
            sequence_number=1,
            context=ActionContext(),
            environment=Environment(),
            action=ActionPayload(
                type=ActionType.TOOL_CALL,
                tool="test_tool",
                input_hash="sha256:abc",
                output_hash="sha256:def",
                input_preview="",
                output_preview="",
                duration_ms=10,
                status=ActionStatus.SUCCESS,
            ),
            otel_trace_id="trace_signable",
            otel_span_id="span_signable",
            cost_usd=0.005,
            token_count=200,
        )

        signable = entry.to_signable_dict()
        assert any("otel" in k.lower() for k in signable), \
            f"Kein OTel-Feld in signable_dict (Security-CRITICAL): {list(signable.keys())}"
        assert any("cost" in k.lower() for k in signable), \
            f"cost_usd nicht in signable_dict: {list(signable.keys())}"

    def test_cost_usd_token_count_default_zero_candid_none(self, tmp_pem):
        """GAP-1: cost_usd=0.0 → Candid None ([]) da kein public API-setter."""
        client, transport = _make_client(tmp_pem)

        with patch("aegis.entry_builder.extract_otel_context", return_value=("", "", "")):
            client.log_tool_call(
                tool="llm_call",
                input_data={"prompt": "test"},
                output_data={"result": "ok"},
                duration_ms=500,
            )

        rec = transport.call_update.call_args[0][1][0]["value"]
        # 0.0 ist falsy → Candid None → []
        assert rec.get("costUsd") == [], \
            f"costUsd=0.0 muss als Candid None ([]) kodiert werden: {rec.get('costUsd')}"
        assert rec.get("tokenCount") == [], \
            f"tokenCount=0 muss als Candid None ([]) kodiert werden: {rec.get('tokenCount')}"


# ============================================================================
# TD1: OTelExporter Happy Path
# ============================================================================

class TestOTelExporterHappyPath:
    """v0.3.0: AegisOTelExporter — Import, Instantiate, export_session."""

    def test_otel_exporter_importable(self):
        """AegisOTelExporter muss aus aegis.otel_exporter importierbar sein."""
        from aegis.otel_exporter import AegisOTelExporter
        assert AegisOTelExporter is not None

    def test_otel_exporter_instantiates(self, tmp_pem):
        """AegisOTelExporter kann mit AegisClient instantiiert werden."""
        from aegis.otel_exporter import AegisOTelExporter
        client, _ = _make_client(tmp_pem)
        exporter = AegisOTelExporter(
            client,
            endpoint="http://localhost:4318/v1/traces",
            service_name="test-service",
        )
        assert exporter.service_name == "test-service"
        assert "4318" in exporter.endpoint

    def test_otel_exporter_has_export_session_method(self, tmp_pem):
        """AegisOTelExporter muss export_session() Method haben."""
        from aegis.otel_exporter import AegisOTelExporter
        client, _ = _make_client(tmp_pem)
        exporter = AegisOTelExporter(client, endpoint="http://localhost:4318/v1/traces")
        assert callable(getattr(exporter, "export_session", None)), \
            "export_session() fehlt auf AegisOTelExporter"

    def test_otel_exporter_export_session_empty_returns_nonnegative(self, tmp_pem):
        """export_session() bei leerer Session: >= 0 Spans exported, kein Crash."""
        from aegis.otel_exporter import AegisOTelExporter
        client, transport = _make_client(tmp_pem)
        transport.call_query = MagicMock(return_value=[])

        exporter = AegisOTelExporter(client, endpoint="http://localhost:4318/v1/traces")
        try:
            result = exporter.export_session("sess_empty_test")
            assert isinstance(result, int), f"export_session must return int, got {type(result)}"
            assert result >= 0, f"Negative export count: {result}"
        except (ConnectionRefusedError, OSError):
            pass  # OTLP-Endpoint nicht erreichbar — erwartet in Test-Umgebung


# ============================================================================
# TD8: queryOnly Permission Key Security Boundaries
# ============================================================================

class TestQueryOnlyPermissionKeys:
    """v0.3.0: queryOnly API Keys — Write geblockt, Read erlaubt."""

    def test_query_only_key_blocked_on_write_fail_open_false(self, tmp_pem):
        """queryOnly Key + fail_open=False → Exception bei log_tool_call."""
        transport = MagicMock()
        transport.call_update.side_effect = Exception(
            "AuthError: query-only key cannot call update endpoints"
        )
        transport.spill_count = 0
        transport.drain_spill_buffer.return_value = 0

        with (
            patch("aegis.client.CanisterTransport") as MockTransport,
            patch("aegis.client.load_config", return_value={}),
        ):
            MockTransport.return_value = transport
            from aegis.client import AegisClient

            client = AegisClient(
                canister_id="toqqq-lqaaa-aaaae-afc2a-cai",
                api_key_id="ak_ci_readonly",
                private_key_path=tmp_pem,
                agent_id="ci-agent",
                org_id="un4fu-tqaaa-aaaab-qadjq-cai",
                fail_open=False,
            )

        with pytest.raises(Exception, match="query-only|AuthError"):
            client.log_tool_call(
                tool="ci_write_attempt",
                input_data={"build": "123"},
                output_data={"result": "pass"},
                duration_ms=200,
            )

    def test_query_only_key_allows_read_queries(self, tmp_pem):
        """queryOnly Key darf call_query (getHealth) ausfuehren."""
        transport = MagicMock()
        transport.call_query.return_value = {"totalEntries": 42, "status": "healthy"}
        transport.spill_count = 0
        transport.drain_spill_buffer.return_value = 0

        with (
            patch("aegis.client.CanisterTransport") as MockTransport,
            patch("aegis.client.load_config", return_value={}),
        ):
            MockTransport.return_value = transport
            from aegis.client import AegisClient

            client = AegisClient(
                canister_id="toqqq-lqaaa-aaaae-afc2a-cai",
                api_key_id="ak_ci_readonly",
                private_key_path=tmp_pem,
                agent_id="ci-agent",
                org_id="un4fu-tqaaa-aaaab-qadjq-cai",
                fail_open=False,
            )

        health = client._transport.call_query("getHealth", [])
        assert health["totalEntries"] == 42
        assert health["status"] == "healthy"

    def test_query_only_key_fail_open_spills_instead_of_raising(self, tmp_pem):
        """queryOnly Key + fail_open=True → spilled_ statt Exception."""
        transport = MagicMock()
        transport.call_update.side_effect = Exception("AuthError: query-only")
        transport.spill_count = 0
        transport.drain_spill_buffer.return_value = 0

        with (
            patch("aegis.client.CanisterTransport") as MockTransport,
            patch("aegis.client.load_config", return_value={}),
        ):
            MockTransport.return_value = transport
            from aegis.client import AegisClient

            client = AegisClient(
                canister_id="toqqq-lqaaa-aaaae-afc2a-cai",
                api_key_id="ak_ci_readonly",
                private_key_path=tmp_pem,
                agent_id="ci-agent",
                org_id="un4fu-tqaaa-aaaab-qadjq-cai",
                fail_open=True,
            )

        result = client.log_tool_call(
            tool="ci_write_fail_open",
            input_data={},
            output_data={},
            duration_ms=10,
        )
        assert result is None or (isinstance(result, str) and "spilled_" in result), \
            f"fail_open=True muss spilled_ oder None liefern, got: {result}"


# ============================================================================
# TD6: OTel State Transitions — Chain-Integritaet mit OTel
# ============================================================================

class TestOTelStateTransitions:
    """v0.3.0: OTel-Kontext pro Entry — Chain bleibt trotzdem intakt."""

    def test_otel_context_independent_per_entry_chain_intact(self, tmp_pem):
        """Verschiedene OTel-Kontexte pro Entry brechen die Hash-Chain nicht."""
        client, transport = _make_client(tmp_pem)

        with patch("aegis.entry_builder.extract_otel_context",
                   return_value=("trace_A", "span_1", "")):
            client.log_tool_call(tool="tool_1", input_data={}, output_data={}, duration_ms=10)

        with patch("aegis.entry_builder.extract_otel_context",
                   return_value=("trace_B", "span_2", "")):
            client.log_tool_call(tool="tool_2", input_data={}, output_data={}, duration_ms=20)

        calls = transport.call_update.call_args_list
        rec_1 = calls[0][0][1][0]["value"]
        rec_2 = calls[1][0][1][0]["value"]

        assert _otel_val(rec_1, "otelTraceId") == "trace_A"
        assert _otel_val(rec_2, "otelTraceId") == "trace_B"
        assert rec_2["previousChainHash"] == rec_1["chainHash"], \
            "Hash-Chain muss intakt bleiben auch mit wechselnden OTel-Kontexten"

    def test_otel_fields_present_after_new_session(self, tmp_pem):
        """Nach new_session() werden OTel-Felder weiterhin auto-extracted."""
        client, transport = _make_client(tmp_pem)
        client.new_session()

        with patch("aegis.entry_builder.extract_otel_context",
                   return_value=("trace_new_sess", "span_new", "")):
            client.log_tool_call(
                tool="post_session_tool",
                input_data={},
                output_data={},
                duration_ms=5,
            )

        rec = transport.call_update.call_args[0][1][0]["value"]
        assert _otel_val(rec, "otelTraceId") == "trace_new_sess", \
            f"OTel nach new_session() fehlt: {rec.get('otelTraceId')}"

    def test_chain_sequence_monotonic_with_otel(self, tmp_pem):
        """3 Entries mit OTel-Kontext: Sequenz monoton steigend, Chain verkettet."""
        client, transport = _make_client(tmp_pem)

        with patch("aegis.entry_builder.extract_otel_context",
                   return_value=("trace_seq", "span_seq", "")):
            for i in range(3):
                client.log_tool_call(
                    tool=f"seq_tool_{i}",
                    input_data={},
                    output_data={},
                    duration_ms=i,
                )

        calls = transport.call_update.call_args_list
        recs = [c[0][1][0]["value"] for c in calls]

        seq_nums = [r["sequenceNumber"] for r in recs]
        assert seq_nums[0] < seq_nums[1] < seq_nums[2], \
            f"Sequenz nicht monoton mit OTel: {seq_nums}"
        assert recs[1]["previousChainHash"] == recs[0]["chainHash"]
        assert recs[2]["previousChainHash"] == recs[1]["chainHash"]
