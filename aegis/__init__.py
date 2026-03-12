"""
Aegis Ledger SDK — Tamper-evident execution ledger for AI agents.

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

    # Every call to search_web is now tamper-evident logged.

Full documentation: https://www.aegis-ledger.com/docs
"""

__version__ = "0.1.0"

from aegis.client import AegisClient
from aegis.config import get_default_scheme, get_signing_key_path, load_config
from aegis.crypto import generate_keypair, sha256_hex, sha256_json
from aegis.report import (
    ComplianceReport,
    ReportFormat,
    ReportGenerationError,
    generate_all_reports,
    generate_pdf,
    generate_report,
)
from aegis.timestamp import (
    TimestampAuthority,
    TimestampError,
    TimestampToken,
    TimestampVerification,
)
from aegis.transport import AegisError, CanisterError
from aegis.types import (
    ActionContext,
    ActionPayload,
    ActionStatus,
    ActionType,
    Environment,
    LogEntry,
    VerificationResult,
)

__all__ = [
    "AegisClient",
    "AegisError",
    "ActionContext",
    "ActionPayload",
    "ActionStatus",
    "ActionType",
    "CanisterError",
    "ComplianceReport",
    "Environment",
    "LogEntry",
    "ReportFormat",
    "ReportGenerationError",
    "TimestampAuthority",
    "TimestampError",
    "TimestampToken",
    "TimestampVerification",
    "VerificationResult",
    "get_default_scheme",
    "get_signing_key_path",
    "generate_all_reports",
    "generate_keypair",
    "load_config",
    "generate_pdf",
    "generate_report",
    "sha256_hex",
    "sha256_json",
]
