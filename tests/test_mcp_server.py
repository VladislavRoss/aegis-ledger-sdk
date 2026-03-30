"""Tests for aegis.mcp_server — MCP tools, resources, prompts, and singletons.

All tests mock _get_client() and _get_transport() to avoid real canister calls.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest

mcp_mod = pytest.importorskip("mcp", reason="mcp package not installed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_client(
    action_id: str = "act_test_123",
    session_id: str = "sess_abc",
    sequence_number: int = 5,
    pending_spill_count: int = 0,
) -> MagicMock:
    client = MagicMock()
    client.log_tool_call.return_value = action_id
    client.log_decision.return_value = action_id
    client.log_observation.return_value = action_id
    client.log_error.return_value = action_id
    client.new_session.return_value = session_id
    client.session_id = session_id
    client.sequence_number = sequence_number
    client.pending_spill_count = pending_spill_count
    client._agent_id = "mcp-agent"
    client._canister_id = "toqqq-lqaaa-aaaae-afc2a-cai"
    return client


def _make_mock_transport(health: dict | None = None) -> MagicMock:
    transport = MagicMock()
    _health = health or {"status": "healthy", "totalEntries": 42}

    def call_query(method: str, args: list) -> dict:
        if method == "getHealth":
            return _health
        if method == "verifyEntry":
            return {
                "isValid": True,
                "storedChainHash": "sha256:abc",
                "message": "verified",
                "previousChainHash": "sha256:000",
                "sequenceNumber": 3,
            }
        return {}

    transport.call_query.side_effect = call_query
    return transport


def _run(coro):
    """Run a coroutine in a fresh event loop."""
    return asyncio.new_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Reset module-level singletons between tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset _client, _transport, and _client_error globals between tests."""
    import aegis.mcp_server as ms
    ms._client = None
    ms._transport = None
    ms._client_error = None
    ms._bg_queue.clear()
    ms._bg_stop.set()  # stop any running bg worker
    yield
    ms._client = None
    ms._transport = None
    ms._client_error = None
    ms._bg_queue.clear()
    ms._bg_stop.set()


# ---------------------------------------------------------------------------
# Lazy singleton tests
# ---------------------------------------------------------------------------


class TestLazySingletons:
    def test_get_client_raises_without_api_key(self, monkeypatch):
        """_init_client raises ValueError when AEGIS_API_KEY_ID is not set."""
        import aegis.mcp_server as ms
        monkeypatch.delenv("AEGIS_API_KEY_ID", raising=False)
        monkeypatch.delenv("AEGIS_PRIVATE_KEY_PATH", raising=False)

        with patch("aegis.mcp_server._get_config", return_value={
            "canister_id": "test-cid", "api_key_id": "",
            "private_key_path": "", "agent_id": "mcp-agent",
            "org_id": "", "network": "https://icp-api.io",
        }), pytest.raises(ValueError, match="AEGIS_API_KEY_ID"):
            ms._init_client()

    def test_get_client_raises_without_private_key(self):
        """_init_client raises ValueError when AEGIS_PRIVATE_KEY_PATH is not set."""
        import aegis.mcp_server as ms

        with patch("aegis.mcp_server._get_config", return_value={
            "canister_id": "test-cid", "api_key_id": "ak_test",
            "private_key_path": "", "agent_id": "mcp-agent",
            "org_id": "", "network": "https://icp-api.io",
        }), pytest.raises(ValueError, match="AEGIS_PRIVATE_KEY_PATH"):
            ms._init_client()

    def test_get_client_returns_singleton(self):
        """_get_client returns the same instance on repeated calls."""
        import aegis.mcp_server as ms
        mock_client = _make_mock_client()
        ms._client = mock_client

        c1 = _run(ms._get_client())
        c2 = _run(ms._get_client())
        assert c1 is c2

    def test_get_transport_returns_singleton(self):
        """_get_transport returns the same instance on repeated calls."""
        import aegis.mcp_server as ms
        mock_transport = _make_mock_transport()
        ms._transport = mock_transport

        t1 = _run(ms._get_transport())
        t2 = _run(ms._get_transport())
        assert t1 is t2

    def test_get_transport_set_singleton_cached(self):
        """_get_transport returns the cached singleton without re-creating."""
        import aegis.mcp_server as ms
        mock_t = _make_mock_transport()
        ms._transport = mock_t
        result = _run(ms._get_transport())
        assert result is mock_t


# ---------------------------------------------------------------------------
# Tool: aegis_log_tool_call
# ---------------------------------------------------------------------------


class TestLogToolCall:
    def _call(self, mock_client: MagicMock, **kwargs) -> dict:
        import aegis.mcp_server as ms
        ms._client = mock_client
        result = _run(ms.aegis_log_tool_call(**{
            "tool": "web_search",
            "input_data": '{"query": "test"}',
            "output_data": '{"result": "found"}',
            "duration_ms": 150,
            "status": "success",
            "reasoning": "needed info",
            "confidence": 0.9,
            **kwargs,
        }))
        return json.loads(result)

    def test_returns_queued_status(self):
        client = _make_mock_client()
        result = self._call(client)
        assert result["status"] == "queued"
        assert result["queue_depth"] >= 1

    def test_queues_tool_name(self):
        import aegis.mcp_server as ms
        client = _make_mock_client()
        self._call(client, tool="db_query")
        assert len(ms._bg_queue) == 1
        method, args, kwargs = ms._bg_queue[0]
        assert method == "log_tool_call"
        assert kwargs["tool"] == "db_query"

    def test_parses_json_input(self):
        import aegis.mcp_server as ms
        client = _make_mock_client()
        self._call(client, input_data='{"key": "value"}')
        _, _, kwargs = ms._bg_queue[0]
        assert kwargs["input_data"] == {"key": "value"}

    def test_raw_string_fallback_on_invalid_json(self):
        import aegis.mcp_server as ms
        client = _make_mock_client()
        self._call(client, input_data="not-json")
        _, _, kwargs = ms._bg_queue[0]
        assert kwargs["input_data"] == "not-json"

    def test_queues_duration_and_status(self):
        import aegis.mcp_server as ms
        client = _make_mock_client()
        self._call(client, duration_ms=500, status="error")
        _, _, kwargs = ms._bg_queue[0]
        assert kwargs["duration_ms"] == 500
        assert kwargs["status"] == "error"

    def test_raises_when_client_not_configured(self):
        import aegis.mcp_server as ms
        with patch("aegis.mcp_server._get_config", return_value={
            "canister_id": "c", "api_key_id": "", "private_key_path": "",
            "agent_id": "mcp-agent", "org_id": "", "network": "https://icp-api.io",
        }), pytest.raises(ValueError, match="AEGIS_API_KEY_ID"):
            _run(ms.aegis_log_tool_call(
                tool="t", input_data="{}", output_data="{}"
            ))


# ---------------------------------------------------------------------------
# Tool: aegis_log_decision
# ---------------------------------------------------------------------------


class TestLogDecision:
    def _call(self, mock_client: MagicMock, **kwargs) -> dict:
        import aegis.mcp_server as ms
        ms._client = mock_client
        result = _run(ms.aegis_log_decision(**{
            "reasoning": "chose path A",
            "confidence": 0.85,
            "input_data": "{}",
            "output_data": "{}",
            "duration_ms": 50,
            **kwargs,
        }))
        return json.loads(result)

    def test_returns_queued_status(self):
        client = _make_mock_client()
        result = self._call(client)
        assert result["status"] == "queued"

    def test_queues_reasoning(self):
        import aegis.mcp_server as ms
        client = _make_mock_client()
        self._call(client, reasoning="chose path B")
        _, _, kwargs = ms._bg_queue[0]
        assert kwargs["reasoning"] == "chose path B"

    def test_queues_confidence(self):
        import aegis.mcp_server as ms
        client = _make_mock_client()
        self._call(client, confidence=0.42)
        _, _, kwargs = ms._bg_queue[0]
        assert kwargs["confidence"] == 0.42

    def test_parses_json_output(self):
        import aegis.mcp_server as ms
        client = _make_mock_client()
        self._call(client, output_data='{"decision": "approve"}')
        _, _, kwargs = ms._bg_queue[0]
        assert kwargs["output_data"] == {"decision": "approve"}


# ---------------------------------------------------------------------------
# Tool: aegis_log_observation
# ---------------------------------------------------------------------------


class TestLogObservation:
    def test_returns_queued_status(self):
        import aegis.mcp_server as ms
        client = _make_mock_client()
        ms._client = client
        result = json.loads(_run(ms.aegis_log_observation(
            input_data='{"sensor": "temp", "value": 42}',
        )))
        assert result["status"] == "queued"

    def test_queues_input_data(self):
        import aegis.mcp_server as ms
        client = _make_mock_client()
        ms._client = client
        _run(ms.aegis_log_observation(input_data='{"x": 1}', output_data='{"y": 2}'))
        _, _, kwargs = ms._bg_queue[0]
        assert kwargs["input_data"] == {"x": 1}
        assert kwargs["output_data"] == {"y": 2}


# ---------------------------------------------------------------------------
# Tool: aegis_log_error
# ---------------------------------------------------------------------------


class TestLogError:
    def test_returns_queued_status(self):
        import aegis.mcp_server as ms
        client = _make_mock_client()
        ms._client = client
        result = json.loads(_run(ms.aegis_log_error(
            tool="broken_api",
            input_data='{"url": "http://fail"}',
            error="Connection refused",
            duration_ms=100,
        )))
        assert result["status"] == "queued"

    def test_queues_error_message(self):
        import aegis.mcp_server as ms
        client = _make_mock_client()
        ms._client = client
        _run(ms.aegis_log_error(tool="t", input_data="{}", error="BOOM", duration_ms=0))
        _, _, kwargs = ms._bg_queue[0]
        assert kwargs["error"] == "BOOM"


# ---------------------------------------------------------------------------
# Tool: aegis_verify_entry
# ---------------------------------------------------------------------------


class TestVerifyEntry:
    def test_returns_verification_result(self):
        import aegis.mcp_server as ms
        transport = _make_mock_transport()
        ms._transport = transport
        result = json.loads(_run(ms.aegis_verify_entry("act_abc_456")))
        assert result["is_valid"] is True
        assert result["action_id"] == "act_abc_456"
        assert result["stored_chain_hash"] == "sha256:abc"
        assert result["message"] == "verified"
        assert result["sequence_number"] == 3

    def test_calls_verify_entry_method(self):
        import aegis.mcp_server as ms
        transport = _make_mock_transport()
        ms._transport = transport
        _run(ms.aegis_verify_entry("act_test"))
        transport.call_query.assert_called_once()
        args = transport.call_query.call_args[0]
        assert args[0] == "verifyEntry"

    def test_handles_invalid_entry(self):
        import aegis.mcp_server as ms
        transport = MagicMock()
        transport.call_query.return_value = {
            "isValid": False,
            "storedChainHash": "",
            "message": "not found",
            "previousChainHash": "",
            "sequenceNumber": 0,
        }
        ms._transport = transport
        result = json.loads(_run(ms.aegis_verify_entry("bad_id")))
        assert result["is_valid"] is False
        assert result["message"] == "not found"


# ---------------------------------------------------------------------------
# Tool: aegis_get_health
# ---------------------------------------------------------------------------


class TestGetHealth:
    def test_returns_health_json(self):
        import aegis.mcp_server as ms
        transport = _make_mock_transport({"status": "healthy", "totalEntries": 99})
        ms._transport = transport
        result = json.loads(_run(ms.aegis_get_health()))
        assert result["status"] == "healthy"
        assert result["totalEntries"] == 99

    def test_calls_get_health_query(self):
        import aegis.mcp_server as ms
        transport = _make_mock_transport()
        ms._transport = transport
        _run(ms.aegis_get_health())
        transport.call_query.assert_called_once_with("getHealth", [])


# ---------------------------------------------------------------------------
# Tool: aegis_generate_report
# ---------------------------------------------------------------------------


class TestGenerateReport:
    def test_returns_markdown_string(self):
        import aegis.mcp_server as ms
        mock_report = MagicMock()
        mock_report.markdown = "# EU AI Act Compliance Report\n..."
        with patch("aegis.report.generate_report", return_value=mock_report), \
             patch("aegis.mcp_server._get_config", return_value={
                "canister_id": "toqqq-lqaaa-aaaae-afc2a-cai",
                "api_key_id": "ak_test", "private_key_path": "k.pem",
                "agent_id": "mcp-agent", "org_id": "", "network": "https://icp-api.io",
             }):
            result = _run(ms.aegis_generate_report(format="eu-ai-act"))
        assert "EU AI Act" in result

    def test_passes_format_to_report_generator(self):
        import aegis.mcp_server as ms
        mock_report = MagicMock()
        mock_report.markdown = "# ISO 42001 Report"
        with patch("aegis.report.generate_report", return_value=mock_report) as mock_gen, \
             patch("aegis.mcp_server._get_config", return_value={
                "canister_id": "c", "api_key_id": "k", "private_key_path": "p",
                "agent_id": "a", "org_id": "", "network": "n",
             }):
            _run(ms.aegis_generate_report(format="iso-42001"))
        mock_gen.assert_called_once()


# ---------------------------------------------------------------------------
# Tool: aegis_new_session
# ---------------------------------------------------------------------------


class TestNewSession:
    def test_returns_session_id(self):
        import aegis.mcp_server as ms
        client = _make_mock_client(session_id="sess_new_xyz")
        ms._client = client
        result = json.loads(_run(ms.aegis_new_session(session_id="my-session")))
        assert result["session_id"] == "sess_new_xyz"

    def test_passes_custom_session_id(self):
        import aegis.mcp_server as ms
        client = _make_mock_client()
        ms._client = client
        _run(ms.aegis_new_session(session_id="custom-id"))
        client.new_session.assert_called_once_with(session_id="custom-id")

    def test_empty_session_id_defaults_to_agent_id(self):
        import aegis.mcp_server as ms
        client = _make_mock_client()
        ms._client = client
        _run(ms.aegis_new_session(session_id=""))
        client.new_session.assert_called_once_with(session_id="mcp-agent")


# ---------------------------------------------------------------------------
# Resource: aegis://health
# ---------------------------------------------------------------------------


class TestResourceHealth:
    def test_returns_health_json(self):
        import aegis.mcp_server as ms
        transport = _make_mock_transport({"status": "healthy", "heapBytes": 1024})
        ms._transport = transport
        result_str = ms.resource_health()
        result = json.loads(result_str)
        assert result["status"] == "healthy"

    def test_health_resource_via_mcp(self):
        import aegis.mcp_server as ms
        transport = _make_mock_transport({"status": "ok"})
        ms._transport = transport
        contents = _run(ms.mcp.read_resource("aegis://health"))
        assert len(contents) >= 1
        data = json.loads(contents[0].content)
        assert data["status"] == "ok"


# ---------------------------------------------------------------------------
# Resource: aegis://session/{session_id}
# ---------------------------------------------------------------------------


class TestResourceSession:
    def test_returns_session_info(self):
        import aegis.mcp_server as ms
        client = _make_mock_client(session_id="sess_xyz", sequence_number=7)
        ms._client = client
        result = json.loads(ms.resource_session("sess_xyz"))
        assert result["session_id"] == "sess_xyz"
        assert result["sequence_number"] == 7
        assert result["agent_id"] == "mcp-agent"

    def test_returns_requested_session_id(self):
        import aegis.mcp_server as ms
        client = _make_mock_client()
        ms._client = client
        result = json.loads(ms.resource_session("requested-sid"))
        assert result["requested_session_id"] == "requested-sid"

    def test_error_response_on_unconfigured_client(self):
        import aegis.mcp_server as ms
        # _client is None, resource_session handles it gracefully
        result = json.loads(ms.resource_session("sess_123"))
        assert result["session_id"] == "(not initialized)"
        assert result["requested_session_id"] == "sess_123"


# ---------------------------------------------------------------------------
# Prompt: audit_session
# ---------------------------------------------------------------------------


class TestAuditSessionPrompt:
    def test_returns_string(self):
        import aegis.mcp_server as ms
        result = ms.audit_session(session_id="sess_audit")
        assert isinstance(result, str)
        assert len(result) > 50

    def test_contains_session_id(self):
        import aegis.mcp_server as ms
        result = ms.audit_session(session_id="sess_abc123")
        assert "sess_abc123" in result

    def test_default_session_placeholder(self):
        import aegis.mcp_server as ms
        result = ms.audit_session(session_id="")
        assert "(current session)" in result

    def test_contains_required_steps(self):
        import aegis.mcp_server as ms
        result = ms.audit_session(session_id="s1")
        assert "aegis_get_health" in result
        assert "aegis_verify_entry" in result
        assert "aegis_generate_report" in result

    def test_prompt_accessible_via_mcp(self):
        import aegis.mcp_server as ms
        msg = _run(ms.mcp.get_prompt("audit_session", {"session_id": "sess_mcp"}))
        assert msg is not None
        text = msg.messages[0].content.text
        assert "sess_mcp" in text


# ---------------------------------------------------------------------------
# Prompt: compliance_check
# ---------------------------------------------------------------------------


class TestComplianceCheckPrompt:
    def test_returns_string(self):
        import aegis.mcp_server as ms
        result = ms.compliance_check(framework="eu-ai-act")
        assert isinstance(result, str)
        assert len(result) > 50

    def test_contains_framework(self):
        import aegis.mcp_server as ms
        result = ms.compliance_check(framework="iso-42001")
        assert "iso-42001" in result

    def test_contains_required_steps(self):
        import aegis.mcp_server as ms
        result = ms.compliance_check(framework="aiuc-1")
        assert "aegis_get_health" in result
        assert "aegis_generate_report" in result

    def test_default_framework_eu_ai_act(self):
        import aegis.mcp_server as ms
        result = ms.compliance_check()
        assert "eu-ai-act" in result

    def test_prompt_accessible_via_mcp(self):
        import aegis.mcp_server as ms
        msg = _run(ms.mcp.get_prompt("compliance_check", {"framework": "iso-42001"}))
        assert msg is not None
        text = msg.messages[0].content.text
        assert "iso-42001" in text


# ---------------------------------------------------------------------------
# Helper: _parse_json
# ---------------------------------------------------------------------------


class TestParseJson:
    def test_valid_json_dict(self):
        from aegis.mcp_server import _parse_json
        assert _parse_json('{"a": 1}') == {"a": 1}

    def test_valid_json_list(self):
        from aegis.mcp_server import _parse_json
        assert _parse_json("[1, 2, 3]") == [1, 2, 3]

    def test_invalid_json_returns_raw(self):
        from aegis.mcp_server import _parse_json
        assert _parse_json("not-json") == "not-json"

    def test_none_returns_none(self):
        from aegis.mcp_server import _parse_json
        assert _parse_json(None) is None  # type: ignore[arg-type]

    def test_empty_string_returns_empty(self):
        from aegis.mcp_server import _parse_json
        assert _parse_json("") == ""


# ---------------------------------------------------------------------------
# Transport error handling
# ---------------------------------------------------------------------------


class TestTransportErrors:
    def test_verify_entry_propagates_transport_error(self):
        import aegis.mcp_server as ms
        transport = MagicMock()
        transport.call_query.side_effect = ConnectionError("canister down")
        ms._transport = transport
        with pytest.raises(ConnectionError, match="canister down"):
            _run(ms.aegis_verify_entry("act_123"))

    def test_get_health_propagates_transport_error(self):
        import aegis.mcp_server as ms
        transport = MagicMock()
        transport.call_query.side_effect = RuntimeError("network error")
        ms._transport = transport
        with pytest.raises(RuntimeError, match="network error"):
            _run(ms.aegis_get_health())
