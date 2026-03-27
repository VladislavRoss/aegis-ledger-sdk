"""
aegis.mcp_server -- Model Context Protocol server for Aegis Ledger.

Exposes the Aegis SDK as MCP tools, resources, and prompts so any
MCP-compatible AI agent can log actions to the tamper-evident ledger.

Supports 5 signature algorithms via ``default_scheme`` config:
Ed25519, ML-DSA-65, ML-DSA-87 (CNSA 2.0 Level 5), SLH-DSA-128s, Hybrid.

Start via CLI:
    aegis-mcp              # stdio transport (default)

Or programmatically:
    from aegis.mcp_server import main
    main()
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("aegis.mcp")

# ---------------------------------------------------------------------------
# Candid hash-key mapping (ic-py returns field hashes, not names)
# ---------------------------------------------------------------------------

_HEALTH_HASH_MAP: dict[str, str] = {
    "_576569836": "totalEntries",
    "_1673630680": "totalKeys",
    "_1718631411": "totalOrgs",
    "_492408735": "heapBytes",
    "_3726629775": "cyclesBalance",
    "_4170640857": "deferredVerifications",
    "_3342846017": "totalSessions",
}

_VERIFY_HASH_MAP: dict[str, str] = {
    "_3776271665": "actionId",
    "_3460176050": "isValid",
    "_1390137228": "storedChainHash",
    "_2601806392": "previousChainHash",
    "_3248078826": "sequenceNumber",
    "_2584819143": "message",
}


def _map_candid_keys(raw: dict, hash_map: dict[str, str]) -> dict:
    """Map Candid field-hash keys to human-readable names."""
    return {hash_map.get(str(k), str(k)): v for k, v in raw.items()}


# ---------------------------------------------------------------------------
# MCP server instance
# ---------------------------------------------------------------------------

mcp = FastMCP("aegis-ledger")

# ---------------------------------------------------------------------------
# Lazy client singleton
# ---------------------------------------------------------------------------

_client: Any = None
_transport: Any = None


def _get_config() -> dict[str, str]:
    """Read config from env vars, falling back to ~/.aegis/config.toml."""
    cfg: dict[str, str] = {}

    # Try config.toml first for defaults
    try:
        from aegis.config import load_config
        toml_cfg = load_config()
        signing = toml_cfg.get("signing", {})
        client_section = toml_cfg.get("client", {})
        cfg["canister_id"] = client_section.get("canister_id", "")
        cfg["api_key_id"] = client_section.get("api_key_id", "")
        cfg["private_key_path"] = client_section.get("private_key_path", "")
        cfg["agent_id"] = client_section.get("agent_id", "")
        cfg["org_id"] = client_section.get("org_id", "")
        cfg["network"] = client_section.get("network", "")
        cfg["signature_scheme"] = signing.get("default_scheme", "")
    except Exception:
        pass

    # Env vars override config.toml
    _default_canister = "toqqq-lqaaa-aaaae-afc2a-cai"
    cfg["canister_id"] = (
        os.environ.get("AEGIS_CANISTER_ID", cfg.get("canister_id", ""))
        or _default_canister
    )
    cfg["api_key_id"] = os.environ.get(
        "AEGIS_API_KEY_ID", cfg.get("api_key_id", ""),
    )
    cfg["private_key_path"] = os.environ.get(
        "AEGIS_PRIVATE_KEY_PATH", cfg.get("private_key_path", ""),
    )
    cfg["agent_id"] = os.environ.get("AEGIS_AGENT_ID", cfg.get("agent_id", "")) or "mcp-agent"
    cfg["org_id"] = os.environ.get("AEGIS_ORG_ID", cfg.get("org_id", ""))
    cfg["network"] = os.environ.get("AEGIS_NETWORK", cfg.get("network", "")) or "https://icp-api.io"

    return cfg


def _get_client() -> Any:
    """Lazy-init the AegisClient singleton."""
    global _client
    if _client is not None:
        return _client

    from aegis import AegisClient

    cfg = _get_config()
    if not cfg["api_key_id"]:
        raise ValueError(
            "AEGIS_API_KEY_ID is required. Set it as an environment variable "
            "or in ~/.aegis/config.toml [client] api_key_id."
        )
    if not cfg["private_key_path"]:
        raise ValueError(
            "AEGIS_PRIVATE_KEY_PATH is required. Set it as an environment variable "
            "or in ~/.aegis/config.toml [client] private_key_path."
        )

    kwargs: dict[str, Any] = {
        "canister_id": cfg["canister_id"],
        "api_key_id": cfg["api_key_id"],
        "private_key_path": cfg["private_key_path"],
        "agent_id": cfg["agent_id"],
        "network": cfg["network"],
        "fail_open": True,
        "redact_pii": True,
    }
    if cfg.get("org_id"):
        kwargs["org_id"] = cfg["org_id"]

    _client = AegisClient(**kwargs)
    return _client


def _get_transport() -> Any:
    """Lazy-init a read-only transport for queries (health, verify)."""
    global _transport
    if _transport is not None:
        return _transport

    from aegis.transport import CanisterTransport, TransportConfig

    cfg = _get_config()
    _transport = CanisterTransport(TransportConfig(
        canister_id=cfg["canister_id"],
        network=cfg["network"],
    ))
    return _transport


# ---------------------------------------------------------------------------
# Tools (8)
# ---------------------------------------------------------------------------


@mcp.tool()
def aegis_log_tool_call(
    tool: str,
    input_data: str,
    output_data: str,
    duration_ms: int = 0,
    status: str = "success",
    reasoning: str = "",
    confidence: float = 0.0,
) -> str:
    """Log a tool/API call to the tamper-evident Aegis Ledger.

    Args:
        tool: Name of the tool or API called (e.g. "web_search", "db.query").
        input_data: JSON string of the input arguments.
        output_data: JSON string of the tool output.
        duration_ms: Execution time in milliseconds.
        status: "success", "error", or "timeout".
        reasoning: Why this tool was called.
        confidence: Confidence score between 0.0 and 1.0.

    Returns:
        The action_id assigned by the on-chain ledger.
    """
    client = _get_client()
    action_id = client.log_tool_call(
        tool=tool,
        input_data=_parse_json(input_data),
        output_data=_parse_json(output_data),
        duration_ms=duration_ms,
        status=status,
        reasoning=reasoning,
        confidence=confidence,
    )
    return json.dumps({"action_id": action_id})


@mcp.tool()
def aegis_log_decision(
    reasoning: str,
    confidence: float,
    input_data: str = "{}",
    output_data: str = "{}",
    duration_ms: int = 0,
) -> str:
    """Log a decision/reasoning step to the tamper-evident Aegis Ledger.

    Args:
        reasoning: The decision reasoning text.
        confidence: Confidence score between 0.0 and 1.0.
        input_data: JSON string of context that led to the decision.
        output_data: JSON string of the decision output.
        duration_ms: Time spent on the decision in milliseconds.

    Returns:
        The action_id assigned by the on-chain ledger.
    """
    client = _get_client()
    action_id = client.log_decision(
        reasoning=reasoning,
        confidence=confidence,
        input_data=_parse_json(input_data),
        output_data=_parse_json(output_data),
        duration_ms=duration_ms,
    )
    return json.dumps({"action_id": action_id})


@mcp.tool()
def aegis_log_observation(
    input_data: str,
    output_data: str = "{}",
    duration_ms: int = 0,
) -> str:
    """Log an observation (sensor data, API response, etc.) to the Aegis Ledger.

    Args:
        input_data: JSON string of the observation data.
        output_data: JSON string of processed observation output.
        duration_ms: Time spent processing in milliseconds.

    Returns:
        The action_id assigned by the on-chain ledger.
    """
    client = _get_client()
    action_id = client.log_observation(
        input_data=_parse_json(input_data),
        output_data=_parse_json(output_data),
        duration_ms=duration_ms,
    )
    return json.dumps({"action_id": action_id})


@mcp.tool()
def aegis_log_error(
    tool: str,
    input_data: str,
    error: str,
    duration_ms: int = 0,
) -> str:
    """Log an error encountered during agent execution to the Aegis Ledger.

    Args:
        tool: Name of the tool that failed.
        input_data: JSON string of the input that caused the error.
        error: Error message string.
        duration_ms: Time elapsed before the error in milliseconds.

    Returns:
        The action_id assigned by the on-chain ledger.
    """
    client = _get_client()
    action_id = client.log_error(
        tool=tool,
        input_data=_parse_json(input_data),
        error=error,
        duration_ms=duration_ms,
    )
    return json.dumps({"action_id": action_id})


@mcp.tool()
def aegis_verify_entry(action_id: str) -> str:
    """Verify a ledger entry on-chain via cryptographic hash-chain verification.

    Args:
        action_id: The action_id to verify.

    Returns:
        JSON with is_valid, stored_chain_hash, message, previous_chain_hash,
        sequence_number, and action_id.
    """
    from ic.candid import Types  # type: ignore[import-untyped]

    transport = _get_transport()
    raw = transport.call_query(
        "verifyEntry", [{"type": Types.Text, "value": action_id}]
    )
    result = _map_candid_keys(raw, _VERIFY_HASH_MAP)
    return json.dumps({
        "is_valid": result.get("isValid", False),
        "stored_chain_hash": result.get("storedChainHash", ""),
        "message": result.get("message", ""),
        "previous_chain_hash": result.get("previousChainHash", ""),
        "sequence_number": result.get("sequenceNumber", 0),
        "action_id": action_id,
    })


@mcp.tool()
def aegis_get_health() -> str:
    """Get live health info from the Aegis canister on ICP.

    Returns:
        JSON with totalEntries, totalKeys, totalOrgs, heapBytes, etc.
    """
    transport = _get_transport()
    raw = transport.call_query("getHealth", [])
    health = _map_candid_keys(raw, _HEALTH_HASH_MAP)
    return json.dumps(health, default=str)


@mcp.tool()
def aegis_generate_report(format: str = "eu-ai-act") -> str:
    """Generate a compliance report from live canister data.

    Args:
        format: Report framework — "eu-ai-act", "iso-42001", or "aiuc-1".

    Returns:
        The generated Markdown compliance report text.
    """
    from aegis.report import ReportFormat, generate_report

    cfg = _get_config()
    fmt = ReportFormat(format)
    report = generate_report(canister_id=cfg["canister_id"], format=fmt)
    return report.markdown


@mcp.tool()
def aegis_new_session(session_id: str = "") -> str:
    """Start a new logging session, resetting the sequence counter.

    Args:
        session_id: Custom session ID. Auto-generated if empty.

    Returns:
        JSON with the new session_id.
    """
    client = _get_client()
    new_id = client.new_session(session_id=session_id or None)
    return json.dumps({"session_id": new_id})


# ---------------------------------------------------------------------------
# Resources (2)
# ---------------------------------------------------------------------------


@mcp.resource("aegis://health")
def resource_health() -> str:
    """Live canister health status as JSON."""
    transport = _get_transport()
    raw = transport.call_query("getHealth", [])
    health = _map_candid_keys(raw, _HEALTH_HASH_MAP)
    return json.dumps(health, default=str)


@mcp.resource("aegis://session/{session_id}")
def resource_session(session_id: str) -> str:
    """Session info for the current client."""
    try:
        client = _get_client()
        return json.dumps({
            "session_id": client.session_id,
            "requested_session_id": session_id,
            "sequence_number": client.sequence_number,
            "pending_spill_count": client.pending_spill_count,
            "agent_id": client._agent_id,
            "canister_id": client._canister_id,
        })
    except Exception as exc:
        return json.dumps({"error": str(exc), "requested_session_id": session_id})


# ---------------------------------------------------------------------------
# Prompts (2)
# ---------------------------------------------------------------------------


@mcp.prompt()
def audit_session(session_id: str = "") -> str:
    """Pre-built prompt for auditing an Aegis session trace.

    Args:
        session_id: The session ID to audit. Leave empty for the current session.
    """
    sid = session_id or "(current session)"
    return (
        f"Analyze the Aegis Ledger session '{sid}' for compliance and integrity.\n\n"
        "Steps:\n"
        "1. Call aegis_get_health() to verify the canister is operational.\n"
        "2. Review the session's logged actions for completeness — every tool call,\n"
        "   decision, and observation should be recorded.\n"
        "3. For each action_id, call aegis_verify_entry() to confirm hash-chain\n"
        "   integrity.\n"
        "4. Check that sequence numbers are monotonically increasing with no gaps.\n"
        "5. Flag any anomalies: missing entries, broken chains, or error spikes.\n"
        "6. Generate a compliance report with aegis_generate_report('eu-ai-act').\n\n"
        "Provide a structured summary with:\n"
        "- Total actions logged\n"
        "- Chain integrity status (all verified / N broken)\n"
        "- Compliance score\n"
        "- Recommendations for remediation (if any)"
    )


@mcp.prompt()
def compliance_check(framework: str = "eu-ai-act") -> str:
    """Pre-built prompt for running a compliance assessment.

    Args:
        framework: Compliance framework — "eu-ai-act", "iso-42001", or "aiuc-1".
    """
    return (
        f"Perform a compliance assessment against the '{framework}' framework.\n\n"
        "Steps:\n"
        "1. Call aegis_get_health() to get current canister statistics.\n"
        "2. Call aegis_generate_report('" + framework + "') for the detailed report.\n"
        "3. Analyze the compliance score and identify gaps.\n"
        "4. For critical findings, verify individual entries with aegis_verify_entry().\n"
        "5. Cross-reference the report against the framework requirements:\n"
        "   - EU AI Act: Art. 12 (logging), Art. 14 (human oversight)\n"
        "   - ISO 42001: A.6.2.6, A.8.4, A.9.3\n"
        "   - AIUC-1: Continuous logging, chain integrity, incident detection\n\n"
        "Deliver:\n"
        "- Overall compliance score with pass/fail per criterion\n"
        "- Evidence references (action_ids, chain hashes)\n"
        "- Prioritized remediation roadmap"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_json(raw: str) -> Any:
    """Parse a JSON string, returning the raw string as-is if parsing fails."""
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the Aegis MCP server with stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
