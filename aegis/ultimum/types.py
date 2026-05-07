"""
aegis.ultimum.types — Candid type mirrors for the ULTIMUM validator_engine.

Mirror of `aegis-protocol/ultimum/canisters/validator_engine/validator_engine.did`:

    type Verdict           = variant { Allow; Deny; Escalate; Defer };
    type SensitivityLabel  = variant { Public; Internal; Confidential;
                                       Secret : record { compartment : text };
                                       Personal; Health; Financial; Legal };
    type TierResult        = record { passed : bool; matched_rules : vec text;
                                      risk_score : nat32 };
    type SignedActionRequest = record { action_id : blob; agent_did : text;
                                        intent_hash : blob; tool : text;
                                        args_cbor : blob;
                                        ifc_labels : vec SensitivityLabel;
                                        prev_chain_hash : blob;
                                        pq_sig : blob; classical_sig : blob;
                                        timestamp_ns : nat64 };
    type ValidatorDecision = record { action_id : blob; policy_version : nat64;
                                      tier1_result : TierResult;
                                      tier2_result : TierResult;
                                      tier3_result : opt TierResult;
                                      tier4_result : opt TierResult;
                                      verdict : Verdict; reason_cbor : blob;
                                      validator_sig : blob; decided_at_ns : nat64 };

Pure stdlib (dataclasses + enum) — no Pydantic dependency. Hash sizes are NOT
enforced beyond the 32-byte SHA-256 convention used by the canister; oversize
inputs are rejected at the canister boundary, not here, to keep this module
deterministic and side-effect-free.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = [
    "PolicyViolation",
    "SecretLabel",
    "SensitivityLabel",
    "SensitivityTag",
    "SignedActionRequest",
    "TierResult",
    "ValidatorDecision",
    "Verdict",
]


class Verdict(Enum):
    """ULTIMUM validator outcome (1:1 with Candid `variant { Allow; Deny; Escalate; Defer }`)."""

    ALLOW = "Allow"
    DENY = "Deny"
    ESCALATE = "Escalate"
    DEFER = "Defer"

    @classmethod
    def from_candid(cls, raw: str | dict) -> Verdict:
        """Parse Candid variant tag (string or single-key dict) into ``Verdict``."""
        if isinstance(raw, dict):
            if len(raw) != 1:
                raise ValueError(f"Verdict variant must have exactly one key, got {raw!r}")
            tag = next(iter(raw))
        else:
            tag = raw
        for member in cls:
            if member.value == tag or member.name == tag.upper():
                return member
        raise ValueError(f"Unknown Verdict variant: {tag!r}")


@dataclass(frozen=True, slots=True)
class SecretLabel:
    """Payload for the ``Secret`` SensitivityLabel variant."""

    compartment: str

    def __post_init__(self) -> None:
        if not isinstance(self.compartment, str) or not self.compartment:
            raise ValueError("SecretLabel.compartment must be a non-empty string")


class SensitivityTag(Enum):
    """Tag-only SensitivityLabel variants (everything except ``Secret``)."""

    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    PERSONAL = "Personal"
    HEALTH = "Health"
    FINANCIAL = "Financial"
    LEGAL = "Legal"


SensitivityLabel = SensitivityTag | SecretLabel


def _sensitivity_from_candid(raw: str | dict) -> SensitivityLabel:
    """Decode one Candid SensitivityLabel variant entry."""
    if isinstance(raw, dict):
        if len(raw) != 1:
            raise ValueError(
                f"SensitivityLabel variant must have exactly one key, got {raw!r}"
            )
        tag, payload = next(iter(raw.items()))
        if tag == "Secret":
            comp = payload.get("compartment") if isinstance(payload, dict) else None
            if not isinstance(comp, str):
                raise ValueError("Secret variant requires record { compartment : text }")
            return SecretLabel(compartment=comp)
    else:
        tag = raw
    for member in SensitivityTag:
        if member.value == tag:
            return member
    raise ValueError(f"Unknown SensitivityLabel variant: {raw!r}")


@dataclass(frozen=True, slots=True)
class TierResult:
    """Per-tier evaluation outcome."""

    passed: bool
    matched_rules: tuple[str, ...] = ()
    risk_score: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.passed, bool):
            raise TypeError("TierResult.passed must be bool")
        if self.risk_score < 0 or self.risk_score > 0xFFFF_FFFF:
            raise ValueError("TierResult.risk_score must fit nat32")
        for rule in self.matched_rules:
            if not isinstance(rule, str):
                raise TypeError("TierResult.matched_rules entries must be str")

    @classmethod
    def from_candid(cls, raw: dict) -> TierResult:
        return cls(
            passed=bool(raw["passed"]),
            matched_rules=tuple(raw.get("matched_rules") or ()),
            risk_score=int(raw.get("risk_score") or 0),
        )


@dataclass(frozen=True, slots=True)
class SignedActionRequest:
    """Pre-execution action submitted to the validator for adjudication."""

    action_id: bytes
    agent_did: str
    intent_hash: bytes
    tool: str
    args_cbor: bytes
    ifc_labels: tuple[SensitivityLabel, ...] = ()
    prev_chain_hash: bytes = b""
    pq_sig: bytes = b""
    classical_sig: bytes = b""
    timestamp_ns: int = 0

    def __post_init__(self) -> None:
        for name in ("action_id", "intent_hash", "args_cbor",
                     "prev_chain_hash", "pq_sig", "classical_sig"):
            value = getattr(self, name)
            if not isinstance(value, (bytes, bytearray)):
                raise TypeError(f"SignedActionRequest.{name} must be bytes-like")
        if not isinstance(self.agent_did, str) or not self.agent_did:
            raise ValueError("SignedActionRequest.agent_did must be a non-empty string")
        if not isinstance(self.tool, str) or not self.tool:
            raise ValueError("SignedActionRequest.tool must be a non-empty string")
        if self.timestamp_ns < 0 or self.timestamp_ns > 0xFFFF_FFFF_FFFF_FFFF:
            raise ValueError("SignedActionRequest.timestamp_ns must fit nat64")

    def to_candid(self) -> dict:
        """Convert to ic-py update-call argument shape (Candid record)."""
        return {
            "action_id": bytes(self.action_id),
            "agent_did": self.agent_did,
            "intent_hash": bytes(self.intent_hash),
            "tool": self.tool,
            "args_cbor": bytes(self.args_cbor),
            "ifc_labels": [_label_to_candid(lbl) for lbl in self.ifc_labels],
            "prev_chain_hash": bytes(self.prev_chain_hash),
            "pq_sig": bytes(self.pq_sig),
            "classical_sig": bytes(self.classical_sig),
            "timestamp_ns": int(self.timestamp_ns),
        }


def _label_to_candid(label: SensitivityLabel) -> dict:
    if isinstance(label, SecretLabel):
        return {"Secret": {"compartment": label.compartment}}
    return {label.value: None}


@dataclass(frozen=True, slots=True)
class ValidatorDecision:
    """Canister verdict for a SignedActionRequest."""

    action_id: bytes
    policy_version: int
    tier1_result: TierResult
    tier2_result: TierResult
    verdict: Verdict
    reason_cbor: bytes = b""
    validator_sig: bytes = b""
    decided_at_ns: int = 0
    tier3_result: TierResult | None = None
    tier4_result: TierResult | None = None

    @classmethod
    def from_candid(cls, raw: dict) -> ValidatorDecision:
        return cls(
            action_id=bytes(raw["action_id"]),
            policy_version=int(raw["policy_version"]),
            tier1_result=TierResult.from_candid(raw["tier1_result"]),
            tier2_result=TierResult.from_candid(raw["tier2_result"]),
            tier3_result=_opt_tier(raw.get("tier3_result")),
            tier4_result=_opt_tier(raw.get("tier4_result")),
            verdict=Verdict.from_candid(raw["verdict"]),
            reason_cbor=bytes(raw.get("reason_cbor") or b""),
            validator_sig=bytes(raw.get("validator_sig") or b""),
            decided_at_ns=int(raw.get("decided_at_ns") or 0),
        )


def _opt_tier(value: object) -> TierResult | None:
    if value in (None, [], (), {}):
        return None
    if isinstance(value, list):
        return TierResult.from_candid(value[0]) if value else None
    if isinstance(value, dict):
        return TierResult.from_candid(value)
    raise TypeError(f"Unsupported opt TierResult shape: {type(value).__name__}")


class PolicyViolation(Exception):  # noqa: N818
    """Raised by ``evaluate_or_raise`` when verdict is not ``Allow``.

    The ``Error``-suffix naming convention (N818) is intentionally waived: this
    name is part of the public ULTIMUM SDK contract documented in
    ``NEW_TECH/phases/02-phase0-validator-wedge.md`` (U6 spec).
    """

    def __init__(self, decision: ValidatorDecision):
        self.decision = decision
        super().__init__(
            f"ULTIMUM verdict={decision.verdict.value} "
            f"(policy_version={decision.policy_version}, "
            f"tier1_passed={decision.tier1_result.passed}, "
            f"tier2_passed={decision.tier2_result.passed})"
        )
