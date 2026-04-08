"""aegis.entry_builder — LogEntry construction and Candid arg building.

Extracted from client.py to reduce god-file size. Pure functions
that take explicit parameters — no class dependency.
"""

from __future__ import annotations

from typing import Any

from aegis.crypto import (
    extract_otel_context,
    sha256_json,
    truncate_preview,
)
from aegis.transport import _build_add_ledger_entry_v2_args
from aegis.types import (
    ActionContext,
    ActionPayload,
    ActionStatus,
    ActionType,
    Environment,
    JsonValue,
    LogEntry,
)


def prepare_entry(
    *,
    agent_id: str,
    session_id: str,
    sequence_number: int,
    action_type: ActionType,
    tool: str,
    input_data: JsonValue,
    output_data: JsonValue,
    duration_ms: int,
    status: ActionStatus,
    reasoning: str,
    confidence: float,
    merged_metadata: dict[str, str],
    now_ms: int,
    parent_id: str,
    environment: Environment,
    sdk_version: str,
    api_key_id: str,
    parent_session_id: str,
) -> LogEntry:
    """Build a LogEntry from validated, PII-redacted inputs."""
    otel_trace_id, otel_span_id, otel_parent_span_id = extract_otel_context()
    return LogEntry(
        agent_id=agent_id,
        session_id=session_id,
        sequence_number=sequence_number,
        action=ActionPayload(
            type=action_type,
            tool=tool,
            input_hash=sha256_json(input_data),
            output_hash=sha256_json(output_data),
            input_preview=truncate_preview(input_data),
            output_preview=truncate_preview(output_data),
            duration_ms=duration_ms,
            status=status,
        ),
        context=ActionContext(
            parent_action_id=parent_id,
            decision_reasoning=reasoning,
            confidence_score=confidence,
        ),
        environment=environment,
        metadata=merged_metadata,
        client_timestamp_ms=now_ms,
        sdk_version=sdk_version,
        api_key_id=api_key_id,
        otel_trace_id=otel_trace_id,
        otel_span_id=otel_span_id,
        otel_parent_span_id=otel_parent_span_id,
        parent_session_id=parent_session_id,
    )


def build_candid_args(
    *,
    entry: LogEntry,
    chain_hash: str,
    previous_chain_hash: str,
    action_id: str,
    payload_bytes: bytes,
    org_id: str,
    api_key_id: str,
) -> list[Any]:
    """Build a single Candid Record argument for addLedgerEntryV2."""
    metadata_json = ""
    if entry.metadata:
        import json as _json
        metadata_json = _json.dumps(entry.metadata, sort_keys=True)
    return _build_add_ledger_entry_v2_args(
        action_id=action_id,
        org_id=org_id,
        agent_id=entry.agent_id,
        session_id=entry.session_id,
        sequence_number=entry.sequence_number,
        action_type=entry.action.type.value,
        tool=entry.action.tool,
        input_hash=entry.action.input_hash,
        output_hash=entry.action.output_hash,
        input_preview="",
        output_preview="",
        duration_ms=entry.action.duration_ms,
        status=entry.action.status.value,
        parent_action_id=entry.context.parent_action_id,
        decision_reasoning=entry.context.decision_reasoning,
        confidence_score=entry.context.confidence_score,
        framework=entry.environment.framework,
        model_id=entry.environment.model_id,
        client_timestamp_ms=entry.client_timestamp_ms,
        payload_signature=entry.payload_signature,
        chain_hash=chain_hash,
        previous_chain_hash=previous_chain_hash,
        payload_hex=payload_bytes.hex(),
        key_id=api_key_id,
        metadata=metadata_json,
        sdk_version=entry.sdk_version,
        otel_trace_id=entry.otel_trace_id,
        otel_span_id=entry.otel_span_id,
        otel_parent_span_id=entry.otel_parent_span_id,
        cost_usd=entry.cost_usd,
        token_count=entry.token_count,
        parent_session_id=entry.parent_session_id,
    )
