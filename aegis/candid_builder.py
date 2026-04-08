"""
aegis.candid_builder -- Candid argument builders for ICP canister calls.

Pure functions that construct ic-py Candid argument lists for
addLedgerEntry (v1, 24 positional) and addLedgerEntryV2 (1 Record).
"""

from __future__ import annotations

from typing import Any

from aegis.errors import CanisterError

_ACTION_TYPE_MAP: dict[str, str] = {
    "tool_call": "toolCall",
    "decision": "decision",
    "observation": "observation",
    "error": "error",
    "human_override": "humanOverride",
}

_REVERSE_ACTION_TYPE_MAP: dict[str, str] = {v: k for k, v in _ACTION_TYPE_MAP.items()}


def _opt(rec: dict, key: str, default: Any) -> Any:
    """Extract first element from Candid Opt list, or default."""
    v = rec.get(key)
    return v[0] if v else default


def _principal_text_to_bytes(text: str) -> bytes:
    """Convert a Principal text (e.g. 'xxxxx-xxxxx-...') to raw bytes.

    Self-contained implementation — does NOT monkey-patch ic-py.
    ic-py 1.0.1 has ``raise "string"`` (Python 2 syntax) in Principal.from_str
    which crashes on Python 3.13. This function replaces that entirely.
    """
    import base64
    import math

    if isinstance(text, bytes):
        return text

    crc_len = 4
    s1 = text.replace("-", "")
    pad_len = math.ceil(len(s1) / 8) * 8 - len(s1)
    try:
        b = base64.b32decode(s1.upper().encode() + b"=" * pad_len)
    except Exception as exc:
        raise ValueError(f"Invalid principal text: {text!r}") from exc
    if len(b) < crc_len:
        raise ValueError(f"Principal too short: {text!r}")
    return b[crc_len:]


def action_type_to_candid_variant(action_type: str) -> dict[str, None]:
    """Konvertiert Python ActionType-String zu Candid Variant dict."""
    if action_type not in _ACTION_TYPE_MAP:
        raise ValueError(
            f"Unknown action type: {action_type!r}. Expected one of: {list(_ACTION_TYPE_MAP)}"
        )
    return {_ACTION_TYPE_MAP[action_type]: None}


def _build_add_ledger_entry_args(
    *,
    action_id: str,
    org_id: str,
    agent_id: str,
    session_id: str,
    sequence_number: int,
    action_type: str,
    tool: str,
    input_hash: str,
    output_hash: str,
    input_preview: str,
    output_preview: str,
    duration_ms: int,
    status: str,
    parent_action_id: str,
    decision_reasoning: str,
    confidence_score: float,
    framework: str,
    model_id: str,
    client_timestamp_ms: int,
    payload_signature: str,
    chain_hash: str,
    previous_chain_hash: str,
    payload_hex: str = "",
    key_id: str = "",
) -> list[dict[str, Any]]:
    """Baut die 24 Candid-Positionalargumente für addLedgerEntry."""
    try:
        from ic.candid import Types  # type: ignore[import-untyped]
    except ImportError as e:
        raise CanisterError(
            "ic-py not installed — cannot build Candid args. "
            "Fix: pip install ic-py",
            error_code="NO_IC_PY",
        ) from e

    _action_type_variant = Types.Variant({
        "toolCall": Types.Null,
        "decision": Types.Null,
        "observation": Types.Null,
        "error": Types.Null,
        "humanOverride": Types.Null,
    })

    return [
        {"type": Types.Text,           "value": action_id},
        {"type": Types.Principal,      "value": _principal_text_to_bytes(org_id)},
        {"type": Types.Text,           "value": agent_id},
        {"type": Types.Text,           "value": session_id},
        {"type": Types.Nat,            "value": sequence_number},
        {"type": _action_type_variant, "value": action_type_to_candid_variant(action_type)},
        {"type": Types.Text,      "value": tool},
        {"type": Types.Text,      "value": input_hash},
        {"type": Types.Text,      "value": output_hash},
        {"type": Types.Text,      "value": input_preview},
        {"type": Types.Text,      "value": output_preview},
        {"type": Types.Nat,       "value": duration_ms},
        {"type": Types.Text,      "value": status},
        {"type": Types.Text,      "value": parent_action_id},
        {"type": Types.Text,      "value": decision_reasoning},
        {"type": Types.Float64,   "value": confidence_score},
        {"type": Types.Text,      "value": framework},
        {"type": Types.Text,      "value": model_id},
        {"type": Types.Int,       "value": client_timestamp_ms},
        {"type": Types.Text,      "value": payload_signature},
        {"type": Types.Text,      "value": chain_hash},
        {"type": Types.Text,      "value": previous_chain_hash},
        {"type": Types.Text,      "value": payload_hex},
        {"type": Types.Text,      "value": key_id},
    ]


def _build_add_ledger_entry_v2_args(
    *,
    action_id: str,
    org_id: str,
    agent_id: str,
    session_id: str,
    sequence_number: int,
    action_type: str,
    tool: str,
    input_hash: str,
    output_hash: str,
    input_preview: str,
    output_preview: str,
    duration_ms: int,
    status: str,
    parent_action_id: str,
    decision_reasoning: str,
    confidence_score: float,
    framework: str,
    model_id: str,
    client_timestamp_ms: int,
    payload_signature: str,
    chain_hash: str,
    previous_chain_hash: str,
    payload_hex: str = "",
    key_id: str = "",
    metadata: str = "",
    sdk_version: str = "",
    schema_version: int = 2,
    otel_trace_id: str = "",
    otel_span_id: str = "",
    otel_parent_span_id: str = "",
    cost_usd: float = 0.0,
    token_count: int = 0,
    parent_session_id: str = "",
) -> list[dict[str, Any]]:
    """Build a single Candid Record argument for addLedgerEntryV2."""
    try:
        from ic.candid import Types  # type: ignore[import-untyped]
    except ImportError as e:
        raise CanisterError(
            "ic-py not installed — cannot build Candid args. Fix: pip install ic-py",
            error_code="NO_IC_PY",
        ) from e

    _action_type_variant = Types.Variant({
        "toolCall": Types.Null,
        "decision": Types.Null,
        "observation": Types.Null,
        "error": Types.Null,
        "humanOverride": Types.Null,
    })

    record_type = Types.Record({
        "actionId": Types.Text,
        "orgId": Types.Principal,
        "agentId": Types.Text,
        "sessionId": Types.Text,
        "sequenceNumber": Types.Nat,
        "actionType": _action_type_variant,
        "tool": Types.Text,
        "inputHash": Types.Text,
        "outputHash": Types.Text,
        "inputPreview": Types.Text,
        "outputPreview": Types.Text,
        "durationMs": Types.Nat,
        "status": Types.Text,
        "parentActionId": Types.Text,
        "decisionReasoning": Types.Text,
        "confidenceScore": Types.Float64,
        "framework": Types.Text,
        "modelId": Types.Text,
        "clientTimestampMs": Types.Int,
        "payloadSignature": Types.Text,
        "chainHash": Types.Text,
        "previousChainHash": Types.Text,
        "payloadHex": Types.Text,
        "keyId": Types.Text,
        "metadata": Types.Opt(Types.Text),
        "sdkVersion": Types.Opt(Types.Text),
        "schemaVersion": Types.Opt(Types.Nat),
        "otelTraceId": Types.Opt(Types.Text),
        "otelSpanId": Types.Opt(Types.Text),
        "otelParentSpanId": Types.Opt(Types.Text),
        "costUsd": Types.Opt(Types.Float64),
        "tokenCount": Types.Opt(Types.Nat),
        "parentSessionId": Types.Opt(Types.Text),
    })

    record_value = {
        "actionId": action_id,
        "orgId": org_id if isinstance(org_id, bytes) else _principal_text_to_bytes(org_id),
        "agentId": agent_id,
        "sessionId": session_id,
        "sequenceNumber": sequence_number,
        "actionType": action_type_to_candid_variant(action_type),
        "tool": tool,
        "inputHash": input_hash,
        "outputHash": output_hash,
        "inputPreview": input_preview,
        "outputPreview": output_preview,
        "durationMs": duration_ms,
        "status": status,
        "parentActionId": parent_action_id,
        "decisionReasoning": decision_reasoning,
        "confidenceScore": confidence_score,
        "framework": framework,
        "modelId": model_id,
        "clientTimestampMs": client_timestamp_ms,
        "payloadSignature": payload_signature,
        "chainHash": chain_hash,
        "previousChainHash": previous_chain_hash,
        "payloadHex": payload_hex,
        "keyId": key_id,
        "metadata": [metadata] if metadata else [],
        "sdkVersion": [sdk_version] if sdk_version else [],
        "schemaVersion": [schema_version],
        "otelTraceId": [otel_trace_id] if otel_trace_id else [],
        "otelSpanId": [otel_span_id] if otel_span_id else [],
        "otelParentSpanId": [otel_parent_span_id] if otel_parent_span_id else [],
        "costUsd": [cost_usd] if cost_usd > 0.0 else [],
        "tokenCount": [token_count] if token_count > 0 else [],
        "parentSessionId": [parent_session_id] if parent_session_id else [],
    }

    return [{"type": record_type, "value": record_value}]
