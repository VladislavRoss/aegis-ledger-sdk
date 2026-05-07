"""
aegis.ultimum.client_ext — UltimumValidator wrapper around `validator_engine`.

Synchronous wait-for-verdict client. Update-call shape:

    method   : "evaluate"
    arg_type : SignedActionRequest (record)
    ret_type : ValidatorDecision   (record)

Real ic-py runtime is loaded lazily; tests inject a stub via the
``transport`` constructor argument so the SDK works without a live replica.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable

from aegis.ultimum.types import (
    PolicyViolation,
    SignedActionRequest,
    ValidatorDecision,
    Verdict,
)

__all__ = [
    "UltimumTransport",
    "UltimumValidator",
    "evaluate",
]

logger = logging.getLogger("aegis.ultimum")

DEFAULT_NETWORK = "https://icp-api.io"
EVALUATE_METHOD = "evaluate"


class UltimumTransport(Protocol):
    """Minimal interface required for issuing the ``evaluate`` update-call.

    Implementations:
      - ``IcPyTransport`` — production, requires the optional ``ic-py`` extra.
      - ``StubTransport`` — test/offline transport returning a pre-canned dict.
    """

    def update(self, canister_id: str, method: str, candid_arg: dict) -> dict:
        ...


class IcPyTransport:
    """ic-py-backed transport. Imports ``ic`` lazily so tests stay lightweight."""

    def __init__(self, network: str = DEFAULT_NETWORK):
        if not network or not isinstance(network, str):
            raise ValueError("network must be a non-empty URL string")
        self._network = network
        self._agent = None

    def _ensure_agent(self):
        if self._agent is not None:
            return self._agent
        try:
            from ic.agent import Agent  # type: ignore[import-not-found]
            from ic.client import Client  # type: ignore[import-not-found]
            from ic.identity import Identity  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "UltimumValidator requires the 'ultimum' extra: "
                "pip install 'aegis-ledger-sdk[ultimum]'"
            ) from exc
        client = Client(url=self._network)
        identity = Identity()
        self._agent = Agent(identity, client)
        return self._agent

    def update(self, canister_id: str, method: str, candid_arg: dict) -> dict:
        agent = self._ensure_agent()
        # ic-py: agent.update_raw(canister_id, method, encoded_args)
        # Real candid encoding via ic-py Candid module is performed at call site.
        from ic.candid import Types, encode  # type: ignore[import-not-found]

        encoded = encode([{"type": Types.Record({}), "value": candid_arg}])
        raw = agent.update_raw(canister_id, method, encoded)
        if not isinstance(raw, list) or not raw:
            raise RuntimeError(f"validator_engine.{method} returned malformed payload")
        return raw[0].get("value", raw[0])


class StubTransport:
    """In-memory transport for tests. Returns whatever the resolver yields."""

    def __init__(self, resolver: Callable[[dict], dict]):
        if not callable(resolver):
            raise TypeError("StubTransport resolver must be callable")
        self._resolver = resolver
        self.calls: list[tuple[str, str, dict]] = []

    def update(self, canister_id: str, method: str, candid_arg: dict) -> dict:
        self.calls.append((canister_id, method, candid_arg))
        return self._resolver(candid_arg)


class UltimumValidator:
    """
    Synchronous wrapper for the ``validator_engine.evaluate`` update-call.

    Parameters
    ----------
    validator_principal : str
        Canister principal of the deployed validator_engine.
    network : str
        IC HTTP endpoint (default mainnet ``https://icp-api.io``).
    transport : UltimumTransport | None
        Override the default ``IcPyTransport``. Tests inject ``StubTransport``.
    """

    def __init__(
        self,
        validator_principal: str,
        network: str = DEFAULT_NETWORK,
        transport: UltimumTransport | None = None,
    ):
        if not validator_principal or not isinstance(validator_principal, str):
            raise ValueError("validator_principal must be a non-empty string")
        self._principal = validator_principal
        self._network = network
        self._transport: UltimumTransport = transport or IcPyTransport(network=network)

    @property
    def validator_principal(self) -> str:
        return self._principal

    @property
    def network(self) -> str:
        return self._network

    def evaluate(self, action: SignedActionRequest) -> ValidatorDecision:
        """Submit ``action`` to ``validator_engine.evaluate`` and return the verdict."""
        if not isinstance(action, SignedActionRequest):
            raise TypeError(
                f"evaluate(action) requires SignedActionRequest, got {type(action).__name__}"
            )
        candid_arg = action.to_candid()
        logger.debug(
            "ULTIMUM evaluate: canister=%s tool=%s action_id=%s",
            self._principal, action.tool, action.action_id.hex(),
        )
        raw = self._transport.update(self._principal, EVALUATE_METHOD, candid_arg)
        if not isinstance(raw, dict):
            raise RuntimeError(
                f"validator_engine.{EVALUATE_METHOD} returned non-record payload: "
                f"{type(raw).__name__}"
            )
        decision = ValidatorDecision.from_candid(raw)
        if decision.action_id != bytes(action.action_id):
            raise RuntimeError(
                "ValidatorDecision.action_id mismatches request action_id "
                "(replay or canister bug)"
            )
        return decision

    def evaluate_or_raise(self, action: SignedActionRequest) -> ValidatorDecision:
        """Like :meth:`evaluate` but raises :class:`PolicyViolation` on non-Allow verdicts."""
        decision = self.evaluate(action)
        if decision.verdict is not Verdict.ALLOW:
            raise PolicyViolation(decision)
        return decision


def evaluate(
    action: SignedActionRequest,
    *,
    validator_principal: str,
    network: str = DEFAULT_NETWORK,
    transport: UltimumTransport | None = None,
) -> ValidatorDecision:
    """Module-level convenience wrapper. Constructs a one-shot validator client."""
    return UltimumValidator(
        validator_principal=validator_principal,
        network=network,
        transport=transport,
    ).evaluate(action)
