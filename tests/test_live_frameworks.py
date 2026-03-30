"""
Live End-to-End Framework Integration Test.

Tests that REAL endusers can log to the Aegis Ledger canister on ICP mainnet
via each framework integration — no mocks, no fakes.

Requirements:
  - ~/.aegis/config.toml configured (aegis init)
  - Active API key on mainnet canister
  - ic-py working

Run:
    python -m pytest AEGIS_LEDGER/tests/test_live_frameworks.py -v -s --no-header
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Undo ic-py mocking from conftest.py — we need real canister access.
# Must happen before any aegis import.
# ---------------------------------------------------------------------------
import sys

_IC_MOCK_KEYS = ["ic", "ic.candid", "ic.identity", "ic.agent", "ic.client"]
for _k in _IC_MOCK_KEYS:
    mod = sys.modules.get(_k)
    if mod is not None and type(mod).__name__ == "MagicMock":
        del sys.modules[_k]

import time  # noqa: E402
import uuid  # noqa: E402
from unittest.mock import MagicMock  # noqa: E402

import pytest  # noqa: E402

# ---------------------------------------------------------------------------
# Skip entire module if canister is unreachable
# ---------------------------------------------------------------------------

def _make_client():
    """Create a real AegisClient from ~/.aegis/config.toml."""
    from aegis import AegisClient
    return AegisClient.from_config()


def _verify_entry(client, action_id: str) -> dict:
    """Verify an entry on-chain via the transport layer."""
    from aegis.config import get_client_config, load_config
    from aegis.transport import CanisterTransport, TransportConfig
    from ic.candid import Types  # type: ignore[import-untyped]

    cfg = load_config()
    cc = get_client_config(cfg)
    tc = TransportConfig(
        canister_id=cc["canister_id"],
        network=cc.get("network", "https://icp-api.io"),
        private_key_path=cc["private_key_path"],
    )
    transport = CanisterTransport(tc)
    result = transport.call_query(
        "verifyEntry", [{"type": Types.Text, "value": action_id}]
    )
    return result


@pytest.fixture(scope="module")
def live_client():
    """Module-scoped live client — skips all tests if canister unreachable."""
    try:
        client = _make_client()
        # Smoke test: log a minimal entry — must reach canister (act_*), not spill (local_*)
        result = client.log_observation(
            input_data={"test": "connectivity"},
            output_data={"status": "ok"},
        )
        if result is None:
            pytest.skip("log_observation returned None — canister unreachable")
        if isinstance(result, str) and result.startswith("local_"):
            pytest.skip(
                f"Entries spilling to disk ({result}) — canister transport "
                f"not working. ic-py may be mocked or network unavailable."
            )
        return client
    except Exception as e:
        pytest.skip(f"Live canister unreachable: {e}")


# =========================================================================
# 1. CORE SDK — Direct API
# =========================================================================

class TestCoreSdkLive:
    """Test that the core SDK methods work end-to-end."""

    def test_log_tool_call(self, live_client):
        r = live_client.log_tool_call(
            tool="test_search_api",
            input_data={"query": "live framework test"},
            output_data={"results": 42},
            duration_ms=123,
        )
        assert isinstance(r, str) and r.startswith("act_")

    def test_log_decision(self, live_client):
        r = live_client.log_decision(
            reasoning="Live test: agent chose optimal path",
            confidence=0.95,
            input_data={"options": ["A", "B"]},
            output_data={"selected": "A"},
        )
        assert isinstance(r, str) and r.startswith("act_")

    def test_log_error(self, live_client):
        r = live_client.log_error(
            tool="flaky_api",
            input_data={"endpoint": "/test"},
            error=RuntimeError("simulated timeout"),
            duration_ms=5000,
        )
        assert isinstance(r, str) and r.startswith("act_")

    def test_log_observation(self, live_client):
        r = live_client.log_observation(
            input_data={"sensor": "temperature"},
            output_data={"value": 22.5, "unit": "C"},
            duration_ms=50,
        )
        assert isinstance(r, str) and r.startswith("act_")

    def test_log_human_override(self, live_client):
        r = live_client.log_human_override(
            override_reason="User corrected agent output",
            input_data={"original": "wrong"},
            output_data={"corrected": "right"},
        )
        assert isinstance(r, str) and r.startswith("act_")

    def test_verify_on_chain(self, live_client):
        """Log an entry and verify it on-chain."""
        r = live_client.log_tool_call(
            tool="verify_roundtrip_test",
            input_data={"test": True},
            output_data={"verified": True},
            duration_ms=10,
        )
        assert isinstance(r, str) and r.startswith("act_")
        time.sleep(1)
        v = _verify_entry(live_client, r)
        assert v is not None


# =========================================================================
# 2. LANGCHAIN Integration
# =========================================================================

class TestLangChainLive:
    """Test LangChain callback handler against live canister."""

    def test_tool_callback(self, live_client):
        from aegis.langchain import AegisCallbackHandler
        handler = AegisCallbackHandler(live_client)

        run_id = uuid.uuid4()

        # Simulate: tool starts
        handler.on_tool_start(
            serialized={"name": "web_search"},
            input_str="What is Aegis Protocol?",
            run_id=run_id,
        )

        time.sleep(0.05)  # simulate tool execution

        # Simulate: tool ends
        handler.on_tool_end(
            output="Aegis Protocol is a tamper-evident execution ledger.",
            run_id=run_id,
            name="web_search",
        )

    def test_llm_callback(self, live_client):
        from aegis.langchain import AegisCallbackHandler
        handler = AegisCallbackHandler(live_client, log_llm_calls=True)

        run_id = uuid.uuid4()

        handler.on_llm_start(
            serialized={"name": "gpt-4"},
            prompts=["Hello, world!"],
            run_id=run_id,
        )

        time.sleep(0.05)

        # Build a mock LLM response
        mock_response = MagicMock()
        mock_response.llm_output = {"model_name": "gpt-4", "token_usage": {"total_tokens": 50}}
        mock_gen = MagicMock()
        mock_gen.text = "Hello from the LLM!"
        mock_response.generations = [[mock_gen]]

        handler.on_llm_end(response=mock_response, run_id=run_id)

    def test_error_callback(self, live_client):
        from aegis.langchain import AegisCallbackHandler
        handler = AegisCallbackHandler(live_client)

        run_id = uuid.uuid4()
        handler.on_tool_start(
            serialized={}, input_str="bad input", run_id=run_id,
        )
        handler.on_tool_error(
            error=ValueError("tool failed"),
            run_id=run_id,
            name="broken_tool",
        )

    def test_agent_action_and_finish(self, live_client):
        from aegis.langchain import AegisCallbackHandler
        handler = AegisCallbackHandler(live_client)

        run_id = uuid.uuid4()

        # Simulate agent selecting a tool
        mock_action = MagicMock()
        mock_action.tool = "calculator"
        mock_action.tool_input = {"expression": "2+2"}
        mock_action.log = "I need to calculate 2+2"
        handler.on_agent_action(action=mock_action, run_id=run_id)

        # Simulate agent finishing
        mock_finish = MagicMock()
        mock_finish.return_values = {"output": "4"}
        mock_finish.log = "The answer is 4"
        handler.on_agent_finish(finish=mock_finish, run_id=run_id)


# =========================================================================
# 3. CREWAI Integration
# =========================================================================

class TestCrewAILive:
    """Test CrewAI step callback against live canister."""

    def test_agent_action_step(self, live_client):
        from aegis.crewai import AegisCrewCallback
        callback = AegisCrewCallback(live_client)

        mock_action = MagicMock()
        type(mock_action).__name__ = "AgentAction"
        mock_action.tool = "web_scraper"
        mock_action.tool_input = "https://example.com"
        mock_action.log = "Scraping example.com for data"
        mock_action.result = "<html>...</html>"

        callback(mock_action)  # __call__

    def test_task_output_step(self, live_client):
        from aegis.crewai import AegisCrewCallback
        callback = AegisCrewCallback(live_client)

        callback.start_task("Summarize the article")

        mock_task = MagicMock()
        type(mock_task).__name__ = "TaskOutput"
        mock_task.description = "Summarize the article"
        mock_task.raw = "The article discusses AI safety frameworks."
        mock_task.agent = "summarizer_agent"
        mock_task.summary = "AI safety summary"

        time.sleep(0.05)
        callback(mock_task)

    def test_unknown_step_type(self, live_client):
        from aegis.crewai import AegisCrewCallback
        callback = AegisCrewCallback(live_client)

        # Something neither AgentAction nor TaskOutput
        callback("unexpected string output")

    def test_error_logging(self, live_client):
        from aegis.crewai import AegisCrewCallback
        callback = AegisCrewCallback(live_client)
        callback.log_error(
            RuntimeError("CrewAI agent crashed"),
            context="During task execution",
        )


# =========================================================================
# 4. OPENAI AGENTS SDK Integration
# =========================================================================

class TestOpenAIAgentsLive:
    """Test OpenAI Agents SDK integration against live canister."""

    def test_manual_tracer(self, live_client):
        from aegis.openai_agents import AegisAgentTracer
        tracer = AegisAgentTracer(live_client)

        with tracer.trace() as tid:
            assert tid.startswith("oai_")

            tracer.log_tool_call(
                tool_name="code_interpreter",
                input_data={"code": "print(2+2)"},
                output_data={"stdout": "4"},
                duration_ms=200,
            )

            tracer.log_handoff(
                from_agent="coordinator",
                to_agent="specialist",
                reason="needs domain expertise",
            )

            tracer.log_guardrail(
                guardrail_name="content_filter",
                passed=True,
                details="No violations detected",
            )

    def test_tracer_error_handling(self, live_client):
        from aegis.openai_agents import AegisAgentTracer
        tracer = AegisAgentTracer(live_client)

        with pytest.raises(ValueError, match="intentional"), tracer.trace():
            tracer.log_tool_call("some_tool", {"x": 1}, {"y": 2})
            raise ValueError("intentional test error")

    def test_run_hooks_tool_cycle(self, live_client):
        """Test the RunHooks subclass (what users actually use)."""
        import asyncio

        from aegis.openai_agents import AegisRunHooks
        hooks = AegisRunHooks(live_client)

        mock_ctx = MagicMock()
        mock_agent = MagicMock()
        mock_agent.name = "test_agent"
        mock_tool = MagicMock()
        mock_tool.name = "file_reader"

        async def _run():
            await hooks.on_agent_start(mock_ctx, mock_agent)
            await hooks.on_tool_start(mock_ctx, mock_agent, mock_tool)
            time.sleep(0.05)
            await hooks.on_tool_end(mock_ctx, mock_agent, mock_tool, "file contents here")
            await hooks.on_agent_end(mock_ctx, mock_agent, "Final answer")

        asyncio.run(_run())

    def test_run_hooks_handoff(self, live_client):
        import asyncio

        from aegis.openai_agents import AegisRunHooks

        hooks = AegisRunHooks(live_client)

        mock_ctx = MagicMock()
        mock_from = MagicMock()
        mock_from.name = "router"
        mock_to = MagicMock()
        mock_to.name = "expert"

        async def _run():
            await hooks.on_handoff(mock_ctx, mock_from, mock_to)

        asyncio.run(_run())


# =========================================================================
# 5. ANTHROPIC SDK (Claude Agent SDK) Integration
# =========================================================================

class TestAnthropicSdkLive:
    """Test Anthropic Agent SDK integration against live canister."""

    def test_manual_tracer_full_lifecycle(self, live_client):
        from aegis.anthropic_sdk import AegisAnthropicTracer
        tracer = AegisAnthropicTracer(live_client)

        session_id = f"test_{uuid.uuid4().hex[:8]}"

        tracer.on_session_start(session_id=session_id)

        tracer.on_tool_use(
            tool_name="Read",
            tool_input={"file_path": "/tmp/test.py"},
            tool_response={"content": "print('hello')"},
            tool_use_id=f"tu_{uuid.uuid4().hex[:8]}",
            duration_ms=150,
        )

        tracer.on_subagent_start(
            agent_id="sub_001",
            agent_type="code_reviewer",
        )
        tracer.on_subagent_end(
            agent_id="sub_001",
            agent_type="code_reviewer",
        )

        tracer.on_session_end(session_id=session_id)

    def test_tracer_error_logging(self, live_client):
        from aegis.anthropic_sdk import AegisAnthropicTracer
        tracer = AegisAnthropicTracer(live_client)
        tracer.log_error(
            RuntimeError("Claude agent hit rate limit"),
            context="During tool execution",
        )

    def test_aegis_hooks_factory(self, live_client):
        """Test the aegis_hooks() factory that produces ClaudeAgentOptions hooks."""
        import asyncio

        from aegis.anthropic_sdk import aegis_hooks

        hooks = aegis_hooks(live_client)

        assert "PostToolUse" in hooks
        assert "SessionStart" in hooks
        assert "Stop" in hooks

        async def _run():
            # Simulate SessionStart
            await hooks["SessionStart"][0](
                {"session_id": "hook_test_001"},
                None,
                MagicMock(),
            )
            # Simulate PostToolUse
            await hooks["PostToolUse"][0](
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "ls"},
                    "tool_output": {"stdout": "file1.py\nfile2.py"},
                },
                "tu_hook_001",
                MagicMock(),
            )
            # Simulate Stop
            await hooks["Stop"][0](
                {"session_id": "hook_test_001", "summary": "Test complete"},
                None,
                MagicMock(),
            )

        asyncio.run(_run())


# =========================================================================
# 6. DECORATOR Integration (@client.trace)
# =========================================================================

class TestDecoratorLive:
    """Test the @client.trace decorator against live canister."""

    def test_trace_decorator_success(self, live_client):
        @live_client.trace(action_type="tool_call")
        def search_database(query: str) -> dict:
            time.sleep(0.05)
            return {"results": [{"id": 1, "title": "Aegis Protocol"}]}

        result = search_database("aegis")
        assert result["results"][0]["title"] == "Aegis Protocol"

    def test_trace_decorator_error(self, live_client):
        @live_client.trace(action_type="tool_call")
        def failing_tool(x: int) -> int:
            raise ZeroDivisionError("division by zero")

        with pytest.raises(ZeroDivisionError):
            failing_tool(42)


# =========================================================================
# 7. BATCH Import
# =========================================================================

class TestBatchLive:
    """Test batch import against live canister."""

    def test_log_batch(self, live_client):
        entries = [
            {
                "action_type": "tool_call",
                "tool": f"batch_tool_{i}",
                "input_data": {"i": i},
                "output_data": {"result": i * 2},
                "duration_ms": 10 + i,
                "status": "success",
            }
            for i in range(3)
        ]

        results = live_client.log_batch(entries)
        assert len(results) == 3
        for r in results:
            assert isinstance(r, str) and r.startswith("act_")


# =========================================================================
# 8. MCP Server Tools (programmatic, not stdio)
# =========================================================================

class TestMcpToolsLive:
    """Test MCP server tools programmatically against live canister.

    Uses _init_client() (sync) directly since _get_client() is async.
    This tests the same code path the MCP server uses internally.
    """

    @pytest.fixture(autouse=True)
    def _mcp_client(self):
        from aegis.mcp_server import _init_client
        try:
            self.client = _init_client()
        except Exception as e:
            pytest.skip(f"MCP client init failed: {e}")

    def test_mcp_log_tool_call(self):
        r = self.client.log_tool_call(
            tool="mcp_test_tool",
            input_data={"via": "mcp_server"},
            output_data={"status": "logged"},
            duration_ms=77,
        )
        assert isinstance(r, str) and r.startswith("act_")

    def test_mcp_log_decision(self):
        r = self.client.log_decision(
            reasoning="MCP agent decided to proceed",
            confidence=0.88,
        )
        assert isinstance(r, str) and r.startswith("act_")

    def test_mcp_log_error(self):
        r = self.client.log_error(
            tool="mcp_broken_tool",
            input_data={"attempt": 1},
            error=ConnectionError("canister timeout simulation"),
        )
        assert isinstance(r, str) and r.startswith("act_")


# =========================================================================
# 9. SUMMARY — Full Agent Workflow Simulation
# =========================================================================

class TestFullAgentWorkflow:
    """
    Simulate a complete agent workflow as an enduser would experience it:
    1. Agent starts session
    2. Makes tool calls (logged via framework)
    3. Makes decisions
    4. Handles errors gracefully
    5. All entries land on-chain
    """

    def test_complete_workflow(self, live_client):
        """A realistic multi-step agent workflow."""
        # Fresh session avoids sequence collisions from earlier tests
        live_client.new_session()
        results = []

        # Step 1: Agent decides which tool to use
        r = live_client.log_decision(
            reasoning="User asked about Swiss tax law. Selecting legal_search tool.",
            confidence=0.92,
            input_data={"user_query": "What are Swiss corporate tax rates?"},
        )
        results.append(r)

        # Step 2: Agent calls a search tool
        r = live_client.log_tool_call(
            tool="legal_search",
            input_data={"query": "Swiss corporate tax rates 2026", "jurisdiction": "CH"},
            output_data={"results": 15, "top_result": "Federal tax: 8.5%"},
            duration_ms=450,
        )
        results.append(r)

        # Step 3: Agent processes results (observation)
        r = live_client.log_observation(
            input_data={"raw_results": 15},
            output_data={"filtered": 3, "relevant": True},
            duration_ms=20,
        )
        results.append(r)

        # Step 4: Agent encounters a transient error
        r = live_client.log_error(
            tool="citation_checker",
            input_data={"url": "https://example.ch/tax"},
            error=TimeoutError("DNS resolution failed"),
            duration_ms=3000,
        )
        results.append(r)

        # Step 5: Agent retries and succeeds
        r = live_client.log_tool_call(
            tool="citation_checker",
            input_data={"url": "https://example.ch/tax"},
            output_data={"valid": True, "last_updated": "2026-01-15"},
            duration_ms=800,
        )
        results.append(r)

        # Step 6: Agent delivers final answer
        r = live_client.log_decision(
            reasoning="Compiled answer from 3 sources. Confidence high.",
            confidence=0.97,
            output_data={"answer_length": 450, "sources": 3},
        )
        results.append(r)

        # Verify ALL entries logged successfully
        assert len(results) == 6
        for r in results:
            assert isinstance(r, str) and r.startswith("act_")

        print(f"\n  Workflow: {len(results)} entries logged successfully")
        print(f"  Action IDs: {results}")
