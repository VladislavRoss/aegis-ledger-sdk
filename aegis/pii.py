"""
aegis.pii — PII detection and redaction for ledger payloads.

Scans text for personal identifiable information (AHV numbers, emails,
phone numbers, IP addresses, SSNs, credit card numbers) and replaces
matches with SHA-256 hashes to prevent accidental PII leakage into
the tamper-evident ledger.
"""

from __future__ import annotations

import hashlib
import os
import re
import warnings
from typing import Any, overload

# Swiss AHV number: 756.XXXX.XXXX.XX (13 digits, Luhn check)
_AHV_PATTERN = re.compile(r"756[.\s-]?\d{4}[.\s-]?\d{4}[.\s-]?\d{2}")

# Common PII patterns
_EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)
_PHONE_PATTERN = re.compile(
    r"(?<!\d)(?:\+[1-9]\d{0,2}[\s\-]?)?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}(?!\d)"
)
_IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)
# US SSN
_SSN_PATTERN = re.compile(r"\b\d{3}[.\-\s]\d{2}[.\-\s]\d{4}\b")
# Credit card (13-19 digits with optional separators)
_CC_PATTERN = re.compile(r"\b(?:\d[.\-\s]?){13,19}\b")


_PII_PATTERNS: dict[str, tuple[re.Pattern[str], str]] = {
    "ahv": (_AHV_PATTERN, "AHV/social security number"),
    "email": (_EMAIL_PATTERN, "Email address"),
    "phone": (_PHONE_PATTERN, "Phone number"),
    "ip": (_IP_PATTERN, "IP address"),
    "ssn": (_SSN_PATTERN, "SSN"),
}

# Default for PII redaction warnings — controllable via AEGIS_PII_WARN env var
_PII_WARN_DEFAULT: bool = os.environ.get("AEGIS_PII_WARN", "1") == "1"


def _luhn_check(digits: str) -> bool:
    """Luhn algorithm for credit card / AHV validation."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def detect_pii(text: str) -> list[str]:
    """
    Scan text for potential PII patterns.

    Returns a list of pattern names found (e.g., ['email', 'ahv']).
    Does NOT modify the text — use redact_pii() for that.
    """
    found: list[str] = []

    # Early-exit: skip expensive regex if text lacks basic indicators
    has_at = "@" in text
    has_dot_digits = any(c.isdigit() for c in text)

    for name, (pattern, _label) in _PII_PATTERNS.items():
        # Skip email regex if no '@' present
        if name == "email" and not has_at:
            continue
        # Skip digit-heavy patterns if no digits present
        if name in ("ahv", "phone", "ip", "ssn") and not has_dot_digits:
            continue
        if pattern.search(text):
            found.append(name)

    # Credit card: only flag if Luhn-valid (needs digits)
    if has_dot_digits:
        for m in _CC_PATTERN.finditer(text):
            digits = re.sub(r"[^\d]", "", m.group())
            if len(digits) >= 13 and _luhn_check(digits):
                found.append("credit_card")
                break

    return found


def redact_pii(text: str, warn: bool = _PII_WARN_DEFAULT) -> str:
    """
    Replace detected PII patterns with SHA-256 hashes.

    When warn=True (default, controlled by AEGIS_PII_WARN env var),
    emits a Python warning for each detection so developers notice
    accidental PII leakage during development.
    """
    detections = detect_pii(text)
    if not detections:
        return text

    result = text
    detection_set = set(detections)

    def _hash_match(m: re.Match[str]) -> str:
        return "sha256:" + hashlib.sha256(m.group().encode()).hexdigest()[:32]

    # Only scan+replace patterns that were actually detected
    for name, (pattern, label) in _PII_PATTERNS.items():
        if name not in detection_set:
            continue
        if warn:
            warnings.warn(
                f"{label} detected in payload — auto-hashing",
                UserWarning,
                stacklevel=2,
            )
        result = pattern.sub(_hash_match, result)

    # Credit card: hash only Luhn-valid sequences
    if "credit_card" in detection_set:
        _cc_warn_emitted = False

        def _cc_hash(m: re.Match[str]) -> str:
            nonlocal _cc_warn_emitted
            digits = re.sub(r"[^\d]", "", m.group())
            if len(digits) >= 13 and _luhn_check(digits):
                if warn and not _cc_warn_emitted:
                    warnings.warn(
                        "Credit card number detected in payload — auto-hashing",
                        UserWarning,
                        stacklevel=2,
                    )
                    _cc_warn_emitted = True
                return "sha256:" + hashlib.sha256(m.group().encode()).hexdigest()[:32]
            return m.group()

        result = _CC_PATTERN.sub(_cc_hash, result)

    return result


@overload
def redact_pii_data(obj: str, warn: bool = True) -> str: ...


@overload
def redact_pii_data(obj: dict[str, Any], warn: bool = True) -> dict[str, Any]: ...


@overload
def redact_pii_data(obj: list[Any], warn: bool = True) -> list[Any]: ...


@overload
def redact_pii_data(obj: object, warn: bool = True) -> object: ...


def redact_pii_data(obj: object, warn: bool = True) -> object:
    """
    Recursively apply PII redaction to all string values in a data structure.

    Walks dicts, lists, and applies redact_pii() to every string leaf.
    Non-string, non-container values are returned as-is.
    """
    if isinstance(obj, str):
        return redact_pii(obj, warn=warn)
    if isinstance(obj, dict):
        return {k: redact_pii_data(v, warn=warn) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_pii_data(item, warn=warn) for item in obj]
    return obj
