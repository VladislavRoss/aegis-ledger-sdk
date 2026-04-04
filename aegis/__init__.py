"""
Aegis Ledger SDK — Tamper-evident execution ledger for AI agents.

Quickstart (after ``aegis init``)::

    from aegis import AegisClient
    client = AegisClient.from_config()

    @client.trace()
    def search_web(query: str) -> dict:
        return {"results": [...]}

    # Every call to search_web is now tamper-evident logged.

Full documentation: https://www.aegis-ledger.com/docs
"""

__version__ = "0.3.2"

from aegis.auto import auto
from aegis.client import AegisClient
from aegis.config import (
    get_client_config,
    get_default_scheme,
    get_signing_key_path,
    load_config,
    write_config,
)
from aegis.crypto import (
    generate_keypair,
    generate_mldsa65_keypair,
    generate_mldsa87_keypair,
    generate_slhdsa128s_keypair,
    load_mldsa65_private_key,
    load_mldsa87_private_key,
    load_slhdsa128s_private_key,
    sha256_hex,
    sha256_json,
)
from aegis.errors import (
    AegisAuthError,
    AegisConfigError,
    AegisError,
    AegisTransportError,
    CanisterError,
)
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
from aegis.types import (
    ActionContext,
    ActionPayload,
    ActionStatus,
    ActionType,
    Environment,
    LogEntry,
    VerificationResult,
)
from aegis.verify import verify_chain

__all__ = [
    "AegisClient",
    "AegisAuthError",
    "AegisConfigError",
    "AegisError",
    "AegisTransportError",
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
    "get_client_config",
    "get_default_scheme",
    "get_signing_key_path",
    "write_config",
    "generate_all_reports",
    "generate_keypair",
    "generate_mldsa65_keypair",
    "generate_mldsa87_keypair",
    "generate_slhdsa128s_keypair",
    "load_mldsa65_private_key",
    "load_mldsa87_private_key",
    "load_slhdsa128s_private_key",
    "load_config",
    "generate_pdf",
    "generate_report",
    "sha256_hex",
    "sha256_json",
    "auto",
    "verify_chain",
]

# AEGIS_AUTO env trigger -- zero-config instrumentation
import os as _os

if _os.environ.get("AEGIS_AUTO", "").strip() in ("1", "true", "yes"):
    from aegis.auto import auto as _auto

    _auto()
    del _auto
del _os
