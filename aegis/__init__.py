"""
Aegis Ledger SDK — Tamperproof execution ledger for AI agents.

Quickstart:
    from aegis import AegisClient

    client = AegisClient(
        canister_id="toqqq-lqaaa-aaaae-afc2a-cai",
        api_key_id="ak_3f8a9b2c1d4e5f60",
        private_key_path="./agent_key.pem",
        agent_id="agent_billing_v2",
    )

    @client.trace()
    def search_web(query: str) -> dict:
        return {"results": [...]}

    # Every call to search_web is now tamperproof-logged.

Full documentation: https://www.aegis-ledger.com/docs
"""

from aegis.client import AegisClient
from aegis.crypto import generate_keypair, sha256_hex, sha256_json
from aegis.types import (
    ActionContext,
    ActionPayload,
    ActionStatus,
    ActionType,
    Environment,
    LogEntry,
    VerificationResult,
)

__version__ = "0.3.0"

__all__ = [
    "AegisClient",
    "ActionContext",
    "ActionPayload",
    "ActionStatus",
    "ActionType",
    "Environment",
    "LogEntry",
    "VerificationResult",
    "generate_keypair",
    "sha256_hex",
    "sha256_json",
]
