"""
aegis.errors — Typed exceptions with human-readable, actionable messages.

Maps raw canister error strings to specific exception classes with
guidance on how to fix the issue. Unknown errors are truncated to
prevent leaking canister internals.
"""

from __future__ import annotations


class AegisError(Exception):
    """Base exception for all Aegis SDK errors."""


class CanisterError(AegisError):
    """Raised when the canister returns an error response."""

    def __init__(self, message: str, error_code: str = "UNKNOWN"):
        self.error_code = error_code
        super().__init__(f"[{error_code}] {message}")


class AegisConfigError(AegisError):
    """Config file missing, unparsable, or incomplete."""


class AegisAuthError(AegisError):
    """Authentication or API key problems."""


class AegisTransportError(AegisError):
    """Network or canister communication problems."""


# Alias for backward compatibility and consistency
TransportError = AegisTransportError

# For compatibility with transport.py
ConfigError = AegisConfigError


_MAX_DETAIL_LEN = 50

# Order matters: more specific patterns FIRST (translate_error matches first hit).
_ERROR_MAP: dict[str, tuple[type[AegisError], str]] = {
    "Key not found": (
        AegisAuthError,
        "API key '{key_id}' not registered. Run: aegis doctor",
    ),
    "Key revoked": (
        AegisAuthError,
        "API key '{key_id}' has been revoked. Create a new key: aegis keys create",
    ),
    "per-key rate limit": (
        AegisTransportError,
        "Per-key rate limit hit. Entries are buffered and auto-retried.",
    ),
    "rate limit": (
        AegisTransportError,
        "Agent sends too fast (limit: 100/s per org, 10/s per caller). "
        "Entries are buffered and auto-retried.",
    ),
    "sequence": (
        AegisTransportError,
        "Concurrent write on same session. Entry will be resubmitted with new sequence number.",
    ),
    "anonymous caller": (
        AegisAuthError,
        "No identity configured. Run: aegis init",
    ),
    "dpa not accepted": (
        AegisAuthError,
        "Data Processing Agreement not accepted. Accept in Dashboard first.",
    ),
    "monthly limit": (
        AegisTransportError,
        "Monthly entry limit reached for your tier. Upgrade at aegis-ledger.com.",
    ),
}


def translate_error(raw_error: str, *, key_id: str = "") -> AegisError:
    """Translate a raw canister error into a typed, human-readable exception.

    Known patterns are mapped to specific exception classes.
    Unknown errors get a generic message truncated to 50 chars.
    """
    for pattern, (exc_cls, template) in _ERROR_MAP.items():
        if pattern.lower() in raw_error.lower():
            msg = template.format(key_id=key_id)
            return exc_cls(msg)

    detail = raw_error[:_MAX_DETAIL_LEN]
    if len(raw_error) > _MAX_DETAIL_LEN:
        detail += "..."
    return AegisError(
        f"Canister error. Run 'aegis doctor' for diagnostics. Details: {detail}"
    )
