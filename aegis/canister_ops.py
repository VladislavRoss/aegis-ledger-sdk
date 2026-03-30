"""
aegis.canister_ops — Self-service and KYA canister operations.

Mixin class for AegisClient providing thin transport wrappers for
self-service key management, session purge, and KYA (Know Your Agent).
"""

from __future__ import annotations

from typing import Any


class CanisterOpsMixin:
    """Mixin: self-service key mgmt, session purge, KYA agent registry."""

    _transport: Any  # CanisterTransport — set by AegisClient.__init__

    # -- Self-service key management ------------------------------------

    def _api_key_map(self, raw: object) -> dict:
        from .integrity import API_KEY_HASH_MAP, map_candid_keys
        return map_candid_keys(raw, API_KEY_HASH_MAP) if isinstance(raw, dict) else raw

    def reactivate_api_key(self, key_id: str) -> dict:
        """Reactivate a revoked API key. Owner only."""
        from ic.candid import Types  # type: ignore[import-untyped]
        raw = self._transport.call_update(
            "reactivateApiKey",
            [{"type": Types.Text, "value": key_id}],
        )
        return self._api_key_map(raw)

    def delete_api_key(self, key_id: str) -> None:
        """Permanently delete a revoked API key. Owner only."""
        from ic.candid import Types  # type: ignore[import-untyped]
        self._transport.call_update(
            "deleteApiKey",
            [{"type": Types.Text, "value": key_id}],
        )

    def update_api_key_description(
        self, key_id: str, description: str,
    ) -> dict:
        """Update the description of an API key. Owner only."""
        from ic.candid import Types  # type: ignore[import-untyped]
        raw = self._transport.call_update(
            "updateApiKeyDescription",
            [
                {"type": Types.Text, "value": key_id},
                {"type": Types.Text, "value": description},
            ],
        )
        return self._api_key_map(raw)

    def purge_session(
        self, session_id: str, batch_limit: int | None = None,
    ) -> int:
        """Purge all entries from a session. Owner + Admin."""
        from ic.candid import Types  # type: ignore[import-untyped]
        args = [{"type": Types.Text, "value": session_id}]
        if batch_limit is not None:
            args.append({"type": Types.Opt(Types.Nat), "value": [batch_limit]})
        else:
            args.append({"type": Types.Opt(Types.Nat), "value": []})
        result = self._transport.call_update("purgeSession", args)
        return int(result) if result is not None else 0

    # -- KYA (Know Your Agent) ------------------------------------------

    def register_agent(
        self, agent_id: str, name: str, description: str = "",
        capabilities: list[str] | None = None,
        framework: str = "", model_id: str = "",
    ) -> dict:
        """Register an agent profile on-chain (KYA)."""
        from ic.candid import Types  # type: ignore[import-untyped]
        return self._transport.call_update("registerAgent", [
            {"type": Types.Text, "value": agent_id},
            {"type": Types.Text, "value": name},
            {"type": Types.Text, "value": description},
            {"type": Types.Vec(Types.Text), "value": capabilities or []},
            {"type": Types.Text, "value": framework},
            {"type": Types.Text, "value": model_id},
        ])

    def update_agent_profile(
        self, agent_id: str, name: str | None = None,
        description: str | None = None,
        capabilities: list[str] | None = None,
        framework: str | None = None, model_id: str | None = None,
    ) -> dict:
        """Update an existing agent profile (owner only)."""
        from ic.candid import Types  # type: ignore[import-untyped]
        _o = lambda v: [v] if v is not None else []  # noqa: E731
        return self._transport.call_update("updateAgentProfile", [
            {"type": Types.Text, "value": agent_id},
            {"type": Types.Opt(Types.Text), "value": _o(name)},
            {"type": Types.Opt(Types.Text), "value": _o(description)},
            {"type": Types.Opt(Types.Vec(Types.Text)),
             "value": _o(capabilities)},
            {"type": Types.Opt(Types.Text), "value": _o(framework)},
            {"type": Types.Opt(Types.Text), "value": _o(model_id)},
        ])

    def get_agent_facts(self, agent_id: str) -> dict:
        """Get public agent facts (no auth, like verifyEntry)."""
        from ic.candid import Types  # type: ignore[import-untyped]
        return self._transport.call_query("getAgentFacts", [
            {"type": Types.Text, "value": agent_id},
        ])
