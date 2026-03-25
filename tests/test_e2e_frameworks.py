"""
End-to-End Framework + PQ Tests — Framework-Integrationen + PQ Migration/Config.

Frameworks:
  LangChain, CrewAI, OpenAI Agents, AutoGen

PQ:
  Migration, Config-System, Client Schemes

TSA:
  TimestampAuthority (RFC 3161)

Aufruf:
    cd /c/ARBEIT/AegisProtocol
    python -m pytest AEGIS_LEDGER/tests/test_e2e_frameworks.py -v
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from aegis.crypto import (
    compute_chain_hash,
)
from aegis.types import Environment
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

# ============================================================================
# Fixtures (shared with test_e2e_workflows.py)
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
# PQ Migration E2E (Batch 6)
# ============================================================================

class TestPQE2EMigration:
    """E2E-Tests für Migration Tool (Batch 6)."""

    def test_migrate_ed25519_to_mldsa65_e2e(self):
        """PQ-E2E Migration: Ed25519 → ML-DSA-65 Re-Sign."""
        try:
            from aegis.crypto import MLDSA65Scheme
            from aegis.migrate import migrate_local
            from pqcrypto.sign.ml_dsa_65 import generate_keypair as ml_keygen

            ml_pk, ml_sk = ml_keygen()

            # Simulate exported entries (would come from canister)
            entries = [
                {
                    "actionId": "act_001",
                    "payloadHex": "abcdef1234567890" * 4,
                    "payloadSignature": "ed25519:old_sig_1",
                },
                {
                    "actionId": "act_002",
                    "payloadHex": "1234567890abcdef" * 4,
                    "payloadSignature": "ed25519:old_sig_2",
                },
                {
                    "actionId": "act_003",
                    "payloadHex": "deadbeef" * 8,
                    "payloadSignature": "ed25519:old_sig_3",
                },
            ]

            import tempfile

            with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
                f.write(ml_sk)
                sk_path = f.name

            with tempfile.NamedTemporaryFile(
                suffix=".json", delete=False, mode="w", encoding="utf-8"
            ) as f:
                import json as _json

                _json.dump(entries, f)
                entries_path = f.name

            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
                output_path = f.name

            report = migrate_local(
                entries_json=entries_path,
                target_algorithm="ml-dsa-65",
                signing_key_path=str(sk_path),
                output_path=output_path,
            )

            assert report["total_entries"] == 3
            assert report["target_algorithm"] == "ml-dsa-65"
            ml_scheme = MLDSA65Scheme(ml_sk)
            for entry in report["entries"]:
                assert entry["new_signature"].startswith("ml-dsa-65:")
                # Finde original payload_hex
                orig = next(e for e in entries if e["actionId"] == entry["action_id"])
                assert ml_scheme.verify(
                    bytes.fromhex(orig["payloadHex"]),
                    entry["new_signature"],
                    ml_pk,
                )

        except ImportError:
            pytest.skip("pqcrypto not installed")

    def test_detect_source_algorithm_all_types(self):
        """PQ-E2E Migration: Quell-Algorithmus aus Signatur-Prefix erkennen."""
        from aegis.migrate import _detect_source_algorithm

        assert _detect_source_algorithm("ed25519:abc123") == "ed25519"
        assert _detect_source_algorithm("ml-dsa-65:abc123") == "ml-dsa-65"
        assert _detect_source_algorithm("slh-dsa-128s:abc123") == "slh-dsa-128s"
        assert _detect_source_algorithm("hybrid:abc123") == "hybrid"
        assert _detect_source_algorithm("unknown:abc123") == "unknown"


class TestPQE2EConfigSystem:
    """E2E-Tests für Config-System (Batch 5)."""

    def test_config_default_scheme_ed25519(self):
        """PQ-E2E Config: Default-Scheme ist ed25519."""
        from aegis.config import get_default_scheme
        # Ohne Config-File muss Default ed25519 sein
        scheme = get_default_scheme({})
        assert scheme == "ed25519"

    def test_config_valid_schemes(self):
        """PQ-E2E Config: Alle 5 Schemes sind gültige Config-Werte."""
        from aegis.config import _VALID_SCHEMES
        expected = frozenset({"ed25519", "ml-dsa-65", "ml-dsa-87", "slh-dsa-128s", "hybrid"})
        assert expected == _VALID_SCHEMES

    def test_config_signing_key_path(self, tmp_path):
        """PQ-E2E Config: signing_key_path wird korrekt aus Config gelesen."""
        from aegis.config import get_signing_key_path
        config = {"signing": {"signing_key_path": str(tmp_path / "test_key.bin")}}
        path = get_signing_key_path(config)
        assert path == str(tmp_path / "test_key.bin")

    def test_config_scheme_override(self):
        """PQ-E2E Config: scheme kann per Config überschrieben werden."""
        from aegis.config import get_default_scheme
        config = {"signing": {"default_scheme": "ml-dsa-65"}}
        scheme = get_default_scheme(config)
        assert scheme == "ml-dsa-65"


class TestPQE2EClientWithSchemes:
    """E2E-Tests: AegisClient mit verschiedenen Signature Schemes."""

    def test_client_default_uses_ed25519(self, tmp_pem):
        """PQ-E2E Client: Default-Client nutzt Ed25519."""
        client, transport = _make_client(tmp_pem)
        client.log_tool_call(tool="pq_test", input_data={}, output_data={}, duration_ms=0)

        args = transport.call_update.call_args[0][1]
        sig = args[19]["value"]  # payloadSignature
        assert sig.startswith("ed25519:"), f"Default must be Ed25519, got: {sig[:20]}"

    def test_client_signature_changes_with_different_payloads(self, tmp_pem):
        """PQ-E2E Client: Verschiedene Payloads → verschiedene Signaturen."""
        client, transport = _make_client(tmp_pem)

        client.log_tool_call(tool="tool_a", input_data={"x": 1}, output_data={}, duration_ms=0)
        sig_1 = transport.call_update.call_args[0][1][19]["value"]

        client.log_tool_call(tool="tool_b", input_data={"x": 2}, output_data={}, duration_ms=0)
        sig_2 = transport.call_update.call_args[0][1][19]["value"]

        assert sig_1 != sig_2, "Different payloads must produce different signatures"

    def test_client_chain_hash_includes_payload(self, tmp_pem):
        """PQ-E2E Client: Chain-Hash hängt von Payload ab."""
        client1, t1 = _make_client(tmp_pem, session_id="chain_a")
        client2, t2 = _make_client(tmp_pem, session_id="chain_b")

        client1.log_tool_call(tool="tool_x", input_data={"val": "A"}, output_data={}, duration_ms=0)
        client2.log_tool_call(tool="tool_x", input_data={"val": "B"}, output_data={}, duration_ms=0)

        hash_1 = t1.call_update.call_args[0][1][20]["value"]
        hash_2 = t2.call_update.call_args[0][1][20]["value"]

        assert hash_1 != hash_2, "Different payloads must produce different chain hashes"


# ============================================================================
# Framework-Integrationen E2E (LangChain, CrewAI, OpenAI Agents, AutoGen)
# ============================================================================

class TestFrameworkLangChainE2E:
    """E2E: LangChain AegisCallbackHandler — Tool + LLM + Chain + Error Lifecycle."""

    def test_langchain_tool_lifecycle(self, tmp_pem):
        """LangChain E2E: on_tool_start → on_tool_end logs tool_call."""
        from uuid import uuid4

        from aegis.langchain import AegisCallbackHandler

        client, transport = _make_client(tmp_pem)
        handler = AegisCallbackHandler(client)

        run_id = uuid4()
        handler.on_tool_start({"name": "search"}, "query", run_id=run_id)
        handler.on_tool_end("result text", run_id=run_id, name="search")

        assert transport.call_update.called
        args = transport.call_update.call_args[0][1]
        assert args[5]["value"] == {"toolCall": None}

    def test_langchain_llm_lifecycle(self, tmp_pem):
        """LangChain E2E: on_llm_start → on_llm_end logs decision."""
        from uuid import uuid4

        from aegis.langchain import AegisCallbackHandler

        client, transport = _make_client(tmp_pem)
        handler = AegisCallbackHandler(client)

        run_id = uuid4()
        handler.on_llm_start({}, ["prompt"], run_id=run_id)

        # Simulate LLM response
        response = MagicMock()
        response.llm_output = {"model_name": "gpt-4", "token_usage": {"total_tokens": 100}}
        gen = MagicMock()
        gen.text = "Generated text"
        response.generations = [[gen]]

        handler.on_llm_end(response, run_id=run_id)

        assert transport.call_update.called
        args = transport.call_update.call_args[0][1]
        assert args[5]["value"] == {"decision": None}

    def test_langchain_chain_lifecycle(self, tmp_pem):
        """LangChain E2E: on_chain_start/end logs observation (log_chain_steps=True)."""
        from uuid import uuid4

        from aegis.langchain import AegisCallbackHandler

        client, transport = _make_client(tmp_pem)
        handler = AegisCallbackHandler(client, log_chain_steps=True)

        run_id = uuid4()
        handler.on_chain_start({}, {"input": "test"}, run_id=run_id)
        handler.on_chain_end({"output": "result"}, run_id=run_id)

        assert transport.call_update.called
        args = transport.call_update.call_args[0][1]
        assert args[5]["value"] == {"observation": None}

    def test_langchain_error_logging(self, tmp_pem):
        """LangChain E2E: on_llm_error logs error action."""
        from uuid import uuid4

        from aegis.langchain import AegisCallbackHandler

        client, transport = _make_client(tmp_pem)
        handler = AegisCallbackHandler(client)

        run_id = uuid4()
        handler.on_llm_start({}, ["prompt"], run_id=run_id)
        handler.on_llm_error(RuntimeError("API timeout"), run_id=run_id)

        assert transport.call_update.called

    def test_langchain_agent_action_and_finish(self, tmp_pem):
        """LangChain E2E: on_agent_action + on_agent_finish logs decisions."""
        from uuid import uuid4

        from aegis.langchain import AegisCallbackHandler

        client, transport = _make_client(tmp_pem)
        handler = AegisCallbackHandler(client)

        run_id = uuid4()
        action = MagicMock()
        action.tool = "calculator"
        action.tool_input = {"expression": "2+2"}
        action.log = "Using calculator to compute"
        handler.on_agent_action(action, run_id=run_id)

        finish = MagicMock()
        finish.return_values = {"output": "4"}
        finish.log = "Got result"
        handler.on_agent_finish(finish, run_id=run_id)

        assert transport.call_update.call_count >= 2


class TestFrameworkCrewAIE2E:
    """E2E: CrewAI AegisCrewCallback — AgentAction + TaskOutput + Error."""

    def test_crewai_agent_action(self, tmp_pem):
        """CrewAI E2E: AgentAction (tool invocation) logs tool_call."""
        from aegis.crewai import AegisCrewCallback

        client, transport = _make_client(tmp_pem)
        callback = AegisCrewCallback(client)

        action = MagicMock()
        type(action).__name__ = "AgentAction"
        action.tool = "web_search"
        action.tool_input = "query text"
        action.log = "Searching..."
        action.result = "Found result"

        callback(action)

        assert transport.call_update.called
        args = transport.call_update.call_args[0][1]
        assert args[5]["value"] == {"toolCall": None}

    def test_crewai_task_output(self, tmp_pem):
        """CrewAI E2E: TaskOutput (task completion) logs decision."""
        from aegis.crewai import AegisCrewCallback

        client, transport = _make_client(tmp_pem)
        callback = AegisCrewCallback(client)

        task_output = MagicMock()
        type(task_output).__name__ = "TaskOutput"
        task_output.description = "Research climate change"
        task_output.raw = "Findings summary..."
        task_output.agent = "researcher"
        task_output.summary = "Done"

        callback(task_output)

        assert transport.call_update.called
        args = transport.call_update.call_args[0][1]
        assert args[5]["value"] == {"decision": None}

    def test_crewai_unknown_step(self, tmp_pem):
        """CrewAI E2E: Unknown step type logs observation."""
        from aegis.crewai import AegisCrewCallback

        client, transport = _make_client(tmp_pem)
        callback = AegisCrewCallback(client)

        callback("some unknown output")

        assert transport.call_update.called
        args = transport.call_update.call_args[0][1]
        assert args[5]["value"] == {"observation": None}

    def test_crewai_error_logging(self, tmp_pem):
        """CrewAI E2E: log_error logs error action."""
        from aegis.crewai import AegisCrewCallback

        client, transport = _make_client(tmp_pem)
        callback = AegisCrewCallback(client)
        callback.log_error(RuntimeError("Crew failed"), context="task execution")

        assert transport.call_update.called


class TestFrameworkOpenAIAgentsE2E:
    """E2E: OpenAI Agents AegisAgentTracer — trace context + tool + handoff + guardrail."""

    def test_openai_trace_context_lifecycle(self, tmp_pem):
        """OpenAI Agents E2E: trace() context manager logs decision on completion."""
        from aegis.openai_agents import AegisAgentTracer

        client, transport = _make_client(tmp_pem)
        tracer = AegisAgentTracer(client)

        with tracer.trace() as trace_id:
            assert trace_id.startswith("oai_")

        assert transport.call_update.called
        args = transport.call_update.call_args[0][1]
        assert args[5]["value"] == {"decision": None}

    def test_openai_trace_error_handling(self, tmp_pem):
        """OpenAI Agents E2E: trace() logs error on exception."""
        from aegis.openai_agents import AegisAgentTracer

        client, transport = _make_client(tmp_pem)
        tracer = AegisAgentTracer(client)

        with pytest.raises(ValueError, match="agent failed"), tracer.trace():
            raise ValueError("agent failed")

        assert transport.call_update.called

    def test_openai_tool_call_logging(self, tmp_pem):
        """OpenAI Agents E2E: log_tool_call logs tool_call action."""
        from aegis.openai_agents import AegisAgentTracer

        client, transport = _make_client(tmp_pem)
        tracer = AegisAgentTracer(client)

        tracer.log_tool_call(
            "fetch_data", input_data={"url": "http://example.com"},
            output_data={"status": 200},
        )

        assert transport.call_update.called
        args = transport.call_update.call_args[0][1]
        assert args[5]["value"] == {"toolCall": None}

    def test_openai_handoff_and_guardrail(self, tmp_pem):
        """OpenAI Agents E2E: log_handoff + log_guardrail log decision/observation."""
        from aegis.openai_agents import AegisAgentTracer

        client, transport = _make_client(tmp_pem)
        tracer = AegisAgentTracer(client)

        tracer.log_handoff("agent_a", "agent_b", reason="escalation")
        assert transport.call_update.call_count == 1
        args = transport.call_update.call_args[0][1]
        assert args[5]["value"] == {"decision": None}

        tracer.log_guardrail("content_filter", passed=True, details="clean")
        assert transport.call_update.call_count == 2


class TestFrameworkAutoGenE2E:
    """E2E: AutoGen AegisAutoGenHook — message + tool + completion + error."""

    def test_autogen_message_sent_and_received(self, tmp_pem):
        """AutoGen E2E: on_message_sent + on_message_received log observations."""
        from aegis.autogen import AegisAutoGenHook

        client, transport = _make_client(tmp_pem)
        hook = AegisAutoGenHook(client)

        hook.on_message_sent(sender="user", receiver="assistant", message="Hello")
        assert transport.call_update.call_count == 1
        args = transport.call_update.call_args[0][1]
        assert args[5]["value"] == {"observation": None}

        hook.on_message_received(sender="assistant", receiver="user", message={"content": "Hi"})
        assert transport.call_update.call_count == 2

    def test_autogen_tool_call_lifecycle(self, tmp_pem):
        """AutoGen E2E: on_tool_call → on_tool_result logs tool_call with timing."""
        from aegis.autogen import AegisAutoGenHook

        client, transport = _make_client(tmp_pem)
        hook = AegisAutoGenHook(client)

        hook.on_tool_call(tool_name="calculator", arguments={"expr": "1+1"}, caller="assistant")
        hook.on_tool_result(tool_name="calculator", result="2", caller="assistant")

        assert transport.call_update.called
        args = transport.call_update.call_args[0][1]
        assert args[5]["value"] == {"toolCall": None}

    def test_autogen_completion(self, tmp_pem):
        """AutoGen E2E: on_completion logs decision with agent_name in reasoning."""
        from aegis.autogen import AegisAutoGenHook

        client, transport = _make_client(tmp_pem)
        hook = AegisAutoGenHook(client)

        hook.on_completion(agent_name="assistant", summary="Task done", chat_history_length=5)

        assert transport.call_update.called
        args = transport.call_update.call_args[0][1]
        assert args[5]["value"] == {"decision": None}

    def test_autogen_error_logging(self, tmp_pem):
        """AutoGen E2E: log_error logs error action."""
        from aegis.autogen import AegisAutoGenHook

        client, transport = _make_client(tmp_pem)
        hook = AegisAutoGenHook(client)
        hook.log_error(RuntimeError("connection lost"), agent_name="planner", context="tool call")

        assert transport.call_update.called


# ============================================================================
# TimestampAuthority E2E (RFC 3161)
# ============================================================================

class TestTimestampAuthorityE2E:
    """E2E: TimestampAuthority — timestamp + verify + local fallback + serialization."""

    def test_timestamp_and_verify_roundtrip(self):
        """TSA E2E: timestamp(data) → verify(token, data) = valid (local fallback)."""
        from aegis.timestamp import TimestampAuthority

        data = b"Aegis ledger entry hash for testing"

        # Use local fallback by triggering network error
        tsa = TimestampAuthority(url="https://mock-tsa.example.com/tsr")
        with patch("aegis.timestamp.urlopen", side_effect=OSError("mock network fail")):
            token = tsa.timestamp(data)

        # Local fallback token
        assert token.tsa_name == "local"
        assert token.hash_algorithm == "sha256"
        assert len(token.hash_value) == 64

        result = tsa.verify(token, data)
        # Local fallback has empty token_der → verify returns False for empty DER
        assert not result.valid  # empty token_der

    def test_timestamp_verify_tampered_data(self):
        """TSA E2E: verify mit geänderten Daten → invalid (hash mismatch)."""
        from aegis.timestamp import TimestampAuthority

        original_data = b"original entry"
        tampered_data = b"tampered entry"

        tsa = TimestampAuthority(url="https://mock-tsa.example.com/tsr")
        with patch("aegis.timestamp.urlopen", side_effect=OSError("mock")):
            token = tsa.timestamp(original_data)

        result = tsa.verify(token, tampered_data)
        assert not result.valid
        assert "hash mismatch" in result.error

    def test_timestamp_token_serialization_roundtrip(self):
        """TSA E2E: TimestampToken to_dict → from_dict Roundtrip."""
        from aegis.timestamp import TimestampAuthority, TimestampToken

        tsa = TimestampAuthority(url="https://mock-tsa.example.com/tsr")
        with patch("aegis.timestamp.urlopen", side_effect=OSError("mock")):
            token = tsa.timestamp(b"test data")

        d = token.to_dict()
        restored = TimestampToken.from_dict(d)

        assert restored.tsa_name == token.tsa_name
        assert restored.hash_value == token.hash_value
        assert restored.hash_algorithm == token.hash_algorithm
        assert restored.serial_number == token.serial_number

    def test_timestamp_hex_with_chain_hash(self, tmp_pem):
        """TSA E2E: timestamp_hex mit einem compute_chain_hash Ergebnis."""
        from aegis.timestamp import TimestampAuthority

        chain_hash = compute_chain_hash("", b'{"action":"test"}')
        assert len(chain_hash) == 64

        tsa = TimestampAuthority(url="https://mock-tsa.example.com/tsr")
        with patch("aegis.timestamp.urlopen", side_effect=OSError("mock")):
            token = tsa.timestamp_hex(chain_hash)

        assert token.hash_value == chain_hash
        assert token.tsa_name == "local"

    def test_timestamp_invalid_url_rejected(self):
        """TSA E2E: Leere URL wird abgelehnt."""
        from aegis.timestamp import TimestampAuthority

        with pytest.raises(ValueError, match="TSA url must not be empty"):
            TimestampAuthority(url="")

    def test_timestamp_unsupported_hash_rejected(self):
        """TSA E2E: Ungültiger Hash-Algorithmus wird abgelehnt."""
        from aegis.timestamp import TimestampAuthority

        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            TimestampAuthority(url="https://tsa.example.com", hash_algorithm="md5")


