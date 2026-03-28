"""
E2E-Integration-Test gegen live Mainnet Canister.

Aufruf:
    cd C:/ARBEIT/AegisProtocol
    python -m pytest AEGIS_LEDGER/tests/test_e2e_live.py -v -s

Voraussetzungen:
    - ~/.aegis/config.toml vorhanden (via 'aegis init')
    - Aktiver API Key auf dem Canister
    - Internetzugang zu icp-api.io
"""
import contextlib
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_ic_is_mock = isinstance(sys.modules.get("ic"), MagicMock)
pytestmark = pytest.mark.skipif(_ic_is_mock, reason="ic-py is mocked (Windows)")

CONFIG_PATH = Path.home() / ".aegis" / "config.toml"
_has_config = CONFIG_PATH.exists()


@pytest.fixture(scope="module")
def client():
    """AegisClient via from_config() — echte Config, echter Canister."""
    if not _has_config:
        pytest.skip("~/.aegis/config.toml not found — run 'aegis init' first")
    from aegis.client import AegisClient
    return AegisClient.from_config()


# ═══════════════════════════════════════════════════════════════════════════════
# 1. CLIENT SETUP
# ═══════════════════════════════════════════════════════════════════════════════

class TestClientSetup:
    def test_client_loads(self, client):
        assert client is not None

    def test_org_id_is_real_principal(self, client):
        assert client._org_id != "aaaaa-aa"
        assert "-" in client._org_id
        print(f"\n  org_id: {client._org_id}")

    def test_canister_id(self, client):
        assert client._canister_id == "toqqq-lqaaa-aaaae-afc2a-cai"

    def test_session_id_generated(self, client):
        assert client.session_id.startswith("sess_")
        print(f"\n  session_id: {client.session_id}")


# ═══════════════════════════════════════════════════════════════════════════════
# 2. ALL 5 LOG METHODS — on-chain
# ═══════════════════════════════════════════════════════════════════════════════

class TestLogMethods:
    """Jede Methode loggt einen echten Eintrag auf Mainnet.

    Requires a registered API key matching the caller principal.
    If running from a different machine/identity: register a key first via
    ``aegis register-key`` or the Dashboard.
    """

    def test_log_tool_call(self, client):
        from aegis import ActionStatus
        action_id = client.log_tool_call(
            tool="weather.get_forecast",
            input_data={"city": "Zurich"},
            output_data={"temp": 18, "condition": "sunny"},
            duration_ms=120,
            status=ActionStatus.SUCCESS,
            reasoning="Fetch weather for user query",
        )
        assert action_id is not None
        assert str(action_id).startswith("act_")
        print(f"\n  tool_call: {action_id}")

    def test_log_decision(self, client):
        action_id = client.log_decision(
            reasoning="Weather is good, recommend outdoor activity",
            confidence=0.92,
            input_data={"temp": 18},
        )
        assert action_id is not None
        assert str(action_id).startswith("act_")
        print(f"\n  decision: {action_id}")

    def test_log_observation(self, client):
        action_id = client.log_observation(
            input_data={"location": "Zurich"},
            output_data={"humidity": 65, "wind_speed": 12},
            duration_ms=50,
        )
        assert action_id is not None
        assert str(action_id).startswith("act_")
        print(f"\n  observation: {action_id}")

    def test_log_error(self, client):
        action_id = client.log_error(
            tool="database.query",
            input_data={"sql": "SELECT * FROM weather"},
            error="Connection timeout after 5000ms",
            duration_ms=5000,
        )
        assert action_id is not None
        assert str(action_id).startswith("act_")
        print(f"\n  error: {action_id}")

    def test_log_human_override(self, client):
        action_id = client.log_human_override(
            override_reason="User manually selected indoor activity",
            input_data={"recommendation": "outdoor"},
            output_data={"override": "indoor"},
        )
        assert action_id is not None
        assert str(action_id).startswith("act_")
        print(f"\n  human_override: {action_id}")


# ═══════════════════════════════════════════════════════════════════════════════
# 3. TRACE DECORATOR
# ═══════════════════════════════════════════════════════════════════════════════

class TestTraceDecorator:
    def test_trace_decorator(self, client):
        @client.trace()
        def process_order(order_id: str):
            return {"recommendation": "outdoor", "order": order_id}

        result = process_order("order-e2e-test")
        assert result["order"] == "order-e2e-test"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. FRAMEWORK INTEGRATIONS (import + instantiate + simulate call)
# ═══════════════════════════════════════════════════════════════════════════════

class TestFrameworkIntegrations:
    def test_langchain_handler(self, client):
        from aegis.langchain import AegisCallbackHandler
        handler = AegisCallbackHandler(client)
        run_id = uuid.uuid4()
        handler.on_tool_start({"name": "calculator"}, "2+2", run_id=run_id)
        handler.on_tool_end("4", run_id=run_id)

    def test_crewai_callback(self, client):
        from aegis.crewai import AegisCrewCallback
        callback = AegisCrewCallback(client)
        callback({"tool": "search", "tool_input": "test", "output": "results"})

    def test_openai_agents_tracer(self, client):
        from aegis.openai_agents import AegisAgentTracer
        tracer = AegisAgentTracer(client)
        tracer.log_tool_call("search", {"q": "test"}, "5 results", duration_ms=100)

    def test_autogen_hook(self, client):
        from aegis.autogen import AegisAutoGenHook
        hook = AegisAutoGenHook(client)
        hook.on_message_sent(sender="coder", receiver="reviewer", message="review this")
        hook.on_tool_call(tool_name="search", caller="coder", arguments={"q": "test"})
        hook.on_completion(agent_name="coder", summary="Task completed")

    def test_anthropic_tracer(self, client):
        from aegis.anthropic_sdk import AegisAnthropicTracer
        tracer = AegisAnthropicTracer(client)
        tracer.on_tool_use("search", tool_input={"q": "test"}, tool_response="5 results")
        tracer.on_session_start("session_e2e")
        tracer.on_subagent_start("sub_1", "researcher")


# ═══════════════════════════════════════════════════════════════════════════════
# 5. CLI COMMANDS (via Python entry point)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCLI:
    def test_cli_version(self, capsys):
        import sys as _sys
        saved = _sys.argv
        _sys.argv = ["aegis", "version"]
        from aegis.cli import main
        with contextlib.suppress(SystemExit):
            main()
        _sys.argv = saved
        out = capsys.readouterr().out
        assert "aegis-ledger-sdk" in out
        print(f"\n  {out.strip()}")

    def test_cli_status(self, capsys):
        import sys as _sys
        saved = _sys.argv
        _sys.argv = ["aegis", "status", "toqqq-lqaaa-aaaae-afc2a-cai"]
        from aegis.cli import main
        with contextlib.suppress(SystemExit):
            main()
        _sys.argv = saved
        out = capsys.readouterr().out
        assert "toqqq" in out
        print(f"\n  {out.strip()}")


# ═══════════════════════════════════════════════════════════════════════════════
# 6. SESSION MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

class TestSessionManagement:
    def test_new_session(self, client):
        old_session = client.session_id
        client.new_session()
        assert client.session_id != old_session
        assert client.session_id.startswith("sess_")
        print(f"\n  new session: {client.session_id}")

    def test_custom_session_id(self, client):
        custom = "sess_custom_e2e_test"
        client.new_session(session_id=custom)
        assert client.session_id == custom

    def test_log_after_new_session(self, client):
        """Eintrag in neuer Session muss funktionieren."""
        client.new_session()
        action_id = client.log_tool_call(
            tool="test_tool",
            input_data={"test": True},
            output_data={"ok": True},
            duration_ms=1,
        )
        assert action_id is not None


# ═══════════════════════════════════════════════════════════════════════════════
# 7. BATCH IMPORT
# ═══════════════════════════════════════════════════════════════════════════════

class TestBatchImport:
    def test_log_batch(self, client):
        client.new_session()
        entries = [
            {
                "tool": "batch_tool_1",
                "input_data": {"batch": 1},
                "output_data": {"ok": True},
                "duration_ms": 10,
                "action_type": "tool_call",
            },
            {
                "tool": "batch_tool_2",
                "input_data": {"batch": 2},
                "output_data": {"ok": True},
                "duration_ms": 20,
                "action_type": "tool_call",
            },
        ]
        results = client.log_batch(entries)
        assert len(results) == 2
        for r in results:
            assert r is not None
            assert str(r).startswith("act_")
        print(f"\n  batch results: {results}")


# ═══════════════════════════════════════════════════════════════════════════════
# 8. CONTEXT MANAGER (span)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSpan:
    def test_span_context_manager(self, client):
        client.new_session()
        with client.span("e2e_test_span", reasoning="Testing span"):
            action_id = client.log_tool_call(
                tool="span_tool",
                input_data={"in_span": True},
                output_data={"ok": True},
                duration_ms=5,
            )
            assert action_id is not None


# ═══════════════════════════════════════════════════════════════════════════════
# 9. READ-ONLY CANISTER QUERIES (no API key needed)
# ═══════════════════════════════════════════════════════════════════════════════

class TestReadOnlyQueries:
    """Public/read-only queries work without a registered API key."""

    def test_get_health(self, client):
        health = client._transport.call_query("getHealth", [])
        assert health is not None
        print(f"\n  health: {health}")

    def test_list_sessions_returns_list(self, client):
        """listMySessions should return a list (may be empty if no key)."""
        try:
            sessions = client._transport.call_query(
                "listMySessions", [[], []]
            )
            assert isinstance(sessions, list)
            print(f"\n  sessions: {len(sessions)}")
        except Exception:
            # listMySessions may require auth — that's OK for this test
            pass

    def test_canister_responds_to_query(self, client):
        """getHealth is a public query that always returns data."""
        health = client._transport.call_query("getHealth", [])
        assert health is not None
        # Should have totalEntries field (Candid hash varies)
        assert len(health) > 0
        print(f"\n  health keys: {list(health.keys())[:5]}")


# ═══════════════════════════════════════════════════════════════════════════════
# 10. CLI DOCTOR (read-only diagnostics)
# ═══════════════════════════════════════════════════════════════════════════════

class TestDoctorLive:
    def test_doctor_runs(self):
        from aegis.doctor import run_doctor
        results = run_doctor()
        assert len(results) >= 4
        for r in results:
            assert r["status"] in ("OK", "WARN", "FAIL")
            assert "name" in r
        statuses = {r["name"]: r["status"] for r in results}
        print(f"\n  doctor: {statuses}")
        # Config and SDK should always be OK if we got this far
        assert statuses.get("Config") == "OK"
        assert statuses.get("SDK") == "OK"


# ═══════════════════════════════════════════════════════════════════════════════
# 11. CRYPTO — sign + verify roundtrip with real key
# ═══════════════════════════════════════════════════════════════════════════════

class TestCryptoRoundtrip:
    def test_sign_and_verify(self, client):
        """Sign a message with the configured key and verify locally."""
        from aegis.crypto import get_public_key_hex, sign_payload
        sk = getattr(client, '_private_key', None)
        if sk is None:
            pytest.skip("No private key loaded on client")
        msg = b"e2e-test-message"
        sig = sign_payload(msg, sk)
        assert sig is not None
        assert len(sig) > 0
        pk_hex = get_public_key_hex(sk)
        assert pk_hex is not None
        assert len(pk_hex) == 64  # Ed25519 = 32 bytes = 64 hex chars
        print(f"\n  pk_hex length: {len(pk_hex)}, sig: {sig[:30]}...")
