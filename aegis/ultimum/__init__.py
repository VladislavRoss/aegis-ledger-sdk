"""
aegis.ultimum — Optional ULTIMUM validator integration.

Subpackage activated via `pip install "aegis-ledger-sdk[ultimum]"`. Wraps the
ULTIMUM `validator_engine` canister Candid endpoint
``evaluate : (SignedActionRequest) -> (ValidatorDecision)``.

Quickstart::

    from aegis.ultimum import UltimumValidator, SignedActionRequest, Verdict

    validator = UltimumValidator(
        validator_principal="aaaaa-aa",
        network="https://icp-api.io",
    )
    decision = validator.evaluate_or_raise(action)
    if decision.verdict is Verdict.ALLOW:
        ...

The wait-for-verdict pattern is synchronous: ``evaluate()`` blocks until the
canister returns a ``ValidatorDecision``. Real ic-py update-call is wired via
:class:`UltimumTransport`; a stub transport is provided for offline tests.
"""

# Mirrors the parent-SDK __version__ literally so the pre-commit sync-gate
# (basename-keyed `__init__.py` comparison) sees both files in lockstep.
# scripts/release.py bumps this together with AEGIS_LEDGER/__init__.py.
__version__ = "0.3.5"

from aegis.ultimum.client_ext import UltimumTransport, UltimumValidator, evaluate
from aegis.ultimum.types import (
    PolicyViolation,
    SecretLabel,
    SensitivityLabel,
    SensitivityTag,
    SignedActionRequest,
    TierResult,
    ValidatorDecision,
    Verdict,
)

__all__ = [
    "PolicyViolation",
    "SecretLabel",
    "SensitivityLabel",
    "SensitivityTag",
    "SignedActionRequest",
    "TierResult",
    "UltimumTransport",
    "UltimumValidator",
    "ValidatorDecision",
    "Verdict",
    "evaluate",
]
