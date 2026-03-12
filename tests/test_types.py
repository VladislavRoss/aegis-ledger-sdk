"""Tests for aegis.types — core type definitions and serialization."""

from __future__ import annotations

import pytest
from aegis.types import (
    ActionContext,
    ActionPayload,
    ActionStatus,
    ActionType,
    Environment,
    LogEntry,
    VerificationResult,
)


class TestActionTypeEnum:
    def test_all_five_values(self) -> None:
        """ActionType has exactly 5 canonical values."""
        assert len(ActionType) == 5
        expected = {"tool_call", "decision", "observation", "error", "human_override"}
        assert {at.value for at in ActionType} == expected

    def test_from_string(self) -> None:
        """ActionType can be constructed from string value."""
        assert ActionType("tool_call") == ActionType.TOOL_CALL
        assert ActionType("human_override") == ActionType.HUMAN_OVERRIDE


class TestActionStatusEnum:
    def test_all_four_values(self) -> None:
        """ActionStatus has SUCCESS, FAILURE, TIMEOUT, ERROR."""
        assert len(ActionStatus) == 4
        expected = {"success", "failure", "timeout", "error"}
        assert {s.value for s in ActionStatus} == expected


class TestLogEntrySignableDict:
    def _make_entry(self) -> LogEntry:
        return LogEntry(
            agent_id="agent-1",
            session_id="sess-1",
            sequence_number=42,
            action=ActionPayload(
                type=ActionType.TOOL_CALL,
                tool="stripe.charge",
                input_hash="sha256:aaa",
                output_hash="sha256:bbb",
                input_preview='{"amount": 5000}',
                output_preview='{"id": "ch_xxx"}',
                duration_ms=250,
                status=ActionStatus.SUCCESS,
            ),
            context=ActionContext(
                parent_action_id="act_parent",
                decision_reasoning="User requested refund",
                confidence_score=0.85,
            ),
            environment=Environment(
                framework="langchain",
                framework_version="0.3.0",
                model_provider="openai",
                model_id="gpt-4",
                runtime="python3.12",
            ),
            metadata={"team": "billing", "env": "prod"},
            client_timestamp_ms=1700000000000,
            sdk_version="0.1.0",
            api_key_id="ak_test",
            payload_signature="ed25519:abc123",
        )

    def test_excludes_toxic_fields(self) -> None:
        """Signable dict must NOT contain preview fields or signature."""
        entry = self._make_entry()
        signable = entry.to_signable_dict()
        # Preview fields carry raw data / PII — must be excluded
        assert "input_preview" not in signable.get("action", {})
        assert "output_preview" not in signable.get("action", {})
        assert "payload_signature" not in signable
        # C-2 FIX: decision_reasoning IS now signed (integrity protection)
        assert "decision_reasoning" in signable.get("context", {})

    def test_contains_required_fields(self) -> None:
        """Signable dict has all required canister fields."""
        entry = self._make_entry()
        signable = entry.to_signable_dict()
        assert signable["agent_id"] == "agent-1"
        assert signable["session_id"] == "sess-1"
        assert signable["sequence_number"] == 42
        assert signable["action"]["tool"] == "stripe.charge"
        assert signable["action"]["input_hash"] == "sha256:aaa"
        assert signable["action"]["output_hash"] == "sha256:bbb"
        assert signable["action"]["duration_ms"] == 250
        assert signable["action"]["status"] == "success"
        assert signable["action"]["type"] == "tool_call"
        assert signable["context"]["confidence_score"] == 0.85
        assert signable["environment"]["framework"] == "langchain"
        assert signable["sdk_version"] == "0.1.0"
        assert signable["api_key_id"] == "ak_test"

    def test_submission_dict_includes_signature(self) -> None:
        """to_submission_dict() includes the payload_signature."""
        entry = self._make_entry()
        submission = entry.to_submission_dict()
        assert submission["payload_signature"] == "ed25519:abc123"
        # Should also have all signable fields
        assert submission["agent_id"] == "agent-1"

    def test_metadata_sorted(self) -> None:
        """Metadata keys are sorted for canonical serialization."""
        entry = self._make_entry()
        signable = entry.to_signable_dict()
        keys = list(signable["metadata"].keys())
        assert keys == sorted(keys)


class TestEnvironmentDefaults:
    def test_defaults(self) -> None:
        """Environment has sensible defaults for all fields."""
        env = Environment()
        assert env.framework == "unknown"
        assert env.framework_version == "0.0.0"
        assert env.model_provider == ""
        assert env.model_id == ""
        assert env.runtime == ""

    def test_frozen(self) -> None:
        """Environment is frozen (immutable)."""
        env = Environment()
        with pytest.raises(AttributeError):
            env.framework = "crewai"  # type: ignore[misc]


class TestVerificationResult:
    def test_fields(self) -> None:
        vr = VerificationResult(
            is_valid=True,
            stored_chain_hash="abc",
            message="Chain hash verified",
            previous_chain_hash="prev",
            sequence_number=42,
            action_id="act_test123",
        )
        assert vr.is_valid is True
        assert vr.stored_chain_hash == "abc"
        assert vr.action_id == "act_test123"

    def test_frozen(self) -> None:
        vr = VerificationResult(
            is_valid=False,
            stored_chain_hash="x",
            message="mismatch",
            previous_chain_hash="z",
            sequence_number=0,
            action_id="act_fail",
        )
        with pytest.raises(AttributeError):
            vr.is_valid = True  # type: ignore[misc]
