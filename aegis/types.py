"""
aegis.types — Canonical type definitions for the Aegis Ledger SDK.

These mirror the Motoko canister's LedgerEntry schema exactly.
Any drift between these types and the canister schema is a bug.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class ActionType(enum.Enum):
    """The five canonical action types recognized by the Aegis ledger."""

    TOOL_CALL = "tool_call"
    DECISION = "decision"
    OBSERVATION = "observation"
    ERROR = "error"
    HUMAN_OVERRIDE = "human_override"


class ActionStatus(enum.Enum):
    """Outcome status of an agent action."""

    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ActionPayload:
    """The inner action block sent to the canister."""

    type: ActionType
    tool: str
    input_hash: str
    output_hash: str
    input_preview: str
    output_preview: str
    duration_ms: int
    status: ActionStatus


@dataclass(frozen=True, slots=True)
class ActionContext:
    """Causal chain and reasoning metadata."""

    parent_action_id: str = ""
    decision_reasoning: str = ""
    confidence_score: float = 0.0


@dataclass(frozen=True, slots=True)
class Environment:
    """Runtime environment fingerprint."""

    framework: str = "unknown"
    framework_version: str = "0.0.0"
    model_provider: str = ""
    model_id: str = ""
    runtime: str = ""


@dataclass(slots=True)
class LogEntry:
    """
    Complete log entry sent to the canister's log_action endpoint.

    Fields are ordered to match the canister's canonical serialization.
    The `payload_signature` is computed by the SDK after all other
    fields are populated — it is excluded from its own hash input.
    """

    agent_id: str
    session_id: str
    sequence_number: int
    action: ActionPayload
    context: ActionContext
    environment: Environment
    metadata: dict[str, str] = field(default_factory=dict)
    client_timestamp_ms: int = 0
    sdk_version: str = ""
    api_key_id: str = ""
    payload_signature: str = ""

    def to_signable_dict(self) -> dict:
        """
        Produce the deterministic dict for canonical JSON serialization.

        CRITICAL: This excludes `payload_signature` because the signature
        is computed OVER this output. Including it would create a circular
        dependency.
        """
        return {
            "action": {
                "duration_ms": self.action.duration_ms,
                "input_hash": self.action.input_hash,
                "output_hash": self.action.output_hash,
                "status": self.action.status.value,
                "tool": self.action.tool,
                "type": self.action.type.value,
            },
            "agent_id": self.agent_id,
            "api_key_id": self.api_key_id,
            "client_timestamp_ms": self.client_timestamp_ms,
            "context": {
                "confidence_score": self.context.confidence_score,
                "decision_reasoning": self.context.decision_reasoning,
                "parent_action_id": self.context.parent_action_id,
            },
            "environment": {
                "framework": self.environment.framework,
                "framework_version": self.environment.framework_version,
                "model_id": self.environment.model_id,
                "model_provider": self.environment.model_provider,
                "runtime": self.environment.runtime,
            },
            "metadata": dict(sorted(self.metadata.items())),
            "sdk_version": self.sdk_version,
            "sequence_number": self.sequence_number,
            "session_id": self.session_id,
        }

    def to_submission_dict(self) -> dict:
        """Full payload including signature, ready for canister submission."""
        d = self.to_signable_dict()
        d["payload_signature"] = self.payload_signature
        return d


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Response from the canister's verifyEntry endpoint.

    Field names match the Candid interface (snake_case of camelCase originals).
    """

    is_valid: bool
    stored_chain_hash: str
    message: str
    previous_chain_hash: str
    sequence_number: int
    action_id: str
