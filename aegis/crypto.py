"""
aegis.crypto — Cryptographic primitives for payload signing.

Handles:
  1. Deterministic canonical JSON serialization (sorted keys, no whitespace).
  2. SHA-256 hashing of arbitrary payloads (for input_hash / output_hash).
  3. Ed25519 signature generation over canonical JSON.
  4. Ed25519 private key loading from PEM files.
  5. ML-DSA-65 (FIPS 204) post-quantum signatures (optional, requires pqcrypto).
  6. SLH-DSA-128s (FIPS 205) stateless hash-based signatures.
  7. Hybrid Ed25519 + ML-DSA-65 composite signatures.

The canonical JSON format is the security-critical serialization used
to produce the `payload_signature`. Any deviation in key ordering,
whitespace, or numeric formatting between the SDK and the canister's
verifier will cause signature verification failures.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import warnings
from pathlib import Path
from typing import Any, Protocol, overload, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    """
    Load an Ed25519 private key from a PEM file.

    Raises FileNotFoundError if path doesn't exist.
    Raises ValueError if the file contains a non-Ed25519 key.
    """
    key_path = Path(path)
    if not key_path.exists():
        raise FileNotFoundError(
            f"Private key not found: {key_path}\n"
            f"Generate one with: aegis keygen {key_path}"
        )

    try:
        from aegis.config import validate_key_permissions
        validate_key_permissions(key_path)
    except ImportError:
        pass
    raw = key_path.read_bytes()
    key = load_pem_private_key(raw, password=None)

    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(
            f"Expected Ed25519 private key, got {type(key).__name__}. "
            f"Generate a compatible key with: aegis keygen {key_path}"
        )

    return key


def get_public_key_hex(private_key: Ed25519PrivateKey) -> str:
    """Extract the hex-encoded public key from a private key."""
    pub = private_key.public_key()
    raw_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return raw_bytes.hex()


def generate_keypair(path: str | Path) -> tuple[Ed25519PrivateKey, str]:
    """
    Generate a new Ed25519 keypair and save the private key to a PEM file.
    Returns (private_key, public_key_hex).
    """
    private_key = Ed25519PrivateKey.generate()
    key_path = Path(path)
    if key_path.exists():
        raise FileExistsError(
            f"Key already exists at {key_path}. "
            "Delete it first, or specify a different path."
        )
    key_path.parent.mkdir(parents=True, exist_ok=True)

    pem_bytes = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    key_path.write_bytes(pem_bytes)
    key_path.chmod(0o600)  # Owner read/write only

    pub_hex = get_public_key_hex(private_key)

    # Also write the public key to a .pub file for convenience
    pub_path = key_path.with_suffix(".pub")
    pub_path.write_text(pub_hex + "\n")

    return private_key, pub_hex


def canonical_json(obj: dict) -> bytes:
    """
    Serialize a dict to canonical JSON bytes.

    Rules (must match the canister's verifier exactly):
      - Keys sorted lexicographically at all nesting levels
      - No whitespace between tokens
      - No trailing newline
      - UTF-8 encoding
      - Floats serialized without trailing zeros (Python's default)
      - Booleans as true/false (Python's json default with ensure_ascii)

    This is the ONLY serialization function that should be used for
    producing signable payloads. Using json.dumps() directly anywhere
    else in the SDK is a bug.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    """SHA-256 hash of arbitrary data, returned as hex string."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_json(obj: object) -> str:
    """
    SHA-256 hash of the canonical JSON representation of any object.

    Used to compute input_hash and output_hash from arbitrary Python
    objects (dicts, lists, strings, etc.) that agents pass as tool
    inputs and outputs.
    """
    serialized = json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(serialized).hexdigest()}"


def sign_payload(payload_bytes: bytes, private_key: Ed25519PrivateKey) -> str:
    """
    Sign canonical JSON bytes with Ed25519, return hex-encoded signature.

    The signature format is: "ed25519:<hex_signature>"
    This prefix enables future support for other signing algorithms
    without breaking the verification protocol.
    """
    signature = private_key.sign(payload_bytes)
    return f"ed25519:{signature.hex()}"


def verify_signature(
    payload_bytes: bytes, signature_hex: str, public_key: Ed25519PublicKey
) -> bool:
    """Verify an Ed25519 signature. Returns True if valid, False otherwise."""
    if not signature_hex.startswith("ed25519:"):
        return False

    try:
        sig_bytes = bytes.fromhex(signature_hex[len("ed25519:") :])
    except ValueError:
        return False
    try:
        public_key.verify(sig_bytes, payload_bytes)
        return True
    except InvalidSignature:
        return False


def compute_chain_hash(previous_chain_hash: str, payload_bytes: bytes) -> str:
    """
    SHA-256(previous_chain_hash + ":" + payload_bytes) → 64-char hex.

    payload_bytes = canonical_json(entry.to_signable_dict()) — gleiche Bytes wie beim Signing.
    Erster Eintrag einer Session: previous_chain_hash = "".
    """
    h = hashlib.sha256()
    h.update(previous_chain_hash.encode("ascii"))
    h.update(b":")
    h.update(payload_bytes)
    return h.hexdigest()



# ── Signature Scheme Protocol (PQ-0: Crypto-Agility) ────────────────────────


@runtime_checkable
class SignatureScheme(Protocol):
    """
    Protocol for pluggable cryptographic signature schemes.

    Enables crypto-agility: Ed25519 (classical), ML-DSA-65 (post-quantum,
    PQ-1), and hybrid Ed25519+ML-DSA-65 (PQ-2) without changing the core
    logging pipeline. Each instance is bound to a private key.
    """

    @property
    def algorithm_id(self) -> str:
        """Algorithm identifier used as signature prefix (e.g., 'ed25519')."""
        ...

    def sign(self, payload: bytes) -> str:
        """Sign payload, returning '<algorithm_id>:<hex_signature>'."""
        ...

    def verify(self, payload: bytes, signature: str, public_key_bytes: bytes) -> bool:
        """Verify a prefixed signature against raw public key bytes."""
        ...

    @property
    def public_key_size(self) -> int:
        """Expected public key size in bytes (32 for Ed25519, 1952 for ML-DSA-65)."""
        ...

    @property
    def signature_size(self) -> int:
        """Expected raw signature size in bytes (64 for Ed25519, 3309 for ML-DSA-65)."""
        ...


class Ed25519Scheme:
    """Ed25519 signature scheme — wraps existing cryptographic primitives."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    @property
    def algorithm_id(self) -> str:
        return "ed25519"

    def sign(self, payload: bytes) -> str:
        signature = self._private_key.sign(payload)
        return f"ed25519:{signature.hex()}"

    def verify(self, payload: bytes, signature: str, public_key_bytes: bytes) -> bool:
        if not signature.startswith("ed25519:"):
            return False
        try:
            sig_bytes = bytes.fromhex(signature[len("ed25519:") :])
        except ValueError:
            return False
        try:
            pk = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pk.verify(sig_bytes, payload)
            return True
        except (InvalidSignature, ValueError):
            return False

    @property
    def public_key_size(self) -> int:
        return 32

    @property
    def signature_size(self) -> int:
        return 64


class MLDSA65Scheme:
    """ML-DSA-65 (FIPS 204) post-quantum signature scheme.

    Requires the ``pqcrypto`` package: ``pip install pqcrypto``
    or ``pip install aegis-ledger-sdk[pq]``.
    """

    def __init__(self, private_key_bytes: bytes) -> None:
        try:
            from pqcrypto.sign.ml_dsa_65 import sign as _sign  # type: ignore[import-untyped]
            from pqcrypto.sign.ml_dsa_65 import verify as _verify
        except ImportError as exc:
            raise ImportError(
                "ML-DSA-65 requires the pqcrypto package. "
                "Install it with: pip install pqcrypto"
            ) from exc
        if len(private_key_bytes) != 4032:
            raise ValueError(
                f"ML-DSA-65 secret key must be 4032 bytes, got {len(private_key_bytes)}"
            )
        self._sk = private_key_bytes
        self._sign = _sign
        self._verify = _verify

    @property
    def algorithm_id(self) -> str:
        return "ml-dsa-65"

    def sign(self, payload: bytes) -> str:
        sig = self._sign(self._sk, payload)
        return f"ml-dsa-65:{sig.hex()}"

    def verify(self, payload: bytes, signature: str, public_key_bytes: bytes) -> bool:
        if not signature.startswith("ml-dsa-65:"):
            return False
        try:
            sig_bytes = bytes.fromhex(signature[len("ml-dsa-65:"):])
        except ValueError:
            return False
        try:
            return bool(self._verify(public_key_bytes, payload, sig_bytes))
        except Exception:
            return False

    @property
    def public_key_size(self) -> int:
        return 1952

    @property
    def signature_size(self) -> int:
        return 3309


class SLHDSA128sScheme:
    """SLH-DSA-SHAKE-128s (FIPS 205) stateless hash-based signature scheme.

    Quantum-resistant fallback that relies only on hash security (no lattice
    assumptions). Larger signatures (~7856 bytes) but extremely conservative
    security guarantees.

    Requires the ``pqcrypto`` package: ``pip install pqcrypto``
    or ``pip install aegis-ledger-sdk[pq]``.
    """

    def __init__(self, private_key_bytes: bytes) -> None:
        try:
            from pqcrypto.sign.sphincs_shake_128s_simple import (  # type: ignore[import-untyped]
                sign as _sign,
            )
            from pqcrypto.sign.sphincs_shake_128s_simple import (
                verify as _verify,
            )
        except ImportError as exc:
            raise ImportError(
                "SLH-DSA-128s requires the pqcrypto package. "
                "Install it with: pip install pqcrypto"
            ) from exc
        if len(private_key_bytes) != 64:
            raise ValueError(
                f"SLH-DSA-128s secret key must be 64 bytes, got {len(private_key_bytes)}"
            )
        self._sk = private_key_bytes
        self._sign = _sign
        self._verify = _verify

    @property
    def algorithm_id(self) -> str:
        return "slh-dsa-128s"

    def sign(self, payload: bytes) -> str:
        sig = self._sign(self._sk, payload)
        return f"slh-dsa-128s:{sig.hex()}"

    def verify(self, payload: bytes, signature: str, public_key_bytes: bytes) -> bool:
        if not signature.startswith("slh-dsa-128s:"):
            return False
        try:
            sig_bytes = bytes.fromhex(signature[len("slh-dsa-128s:"):])
        except ValueError:
            return False
        try:
            return bool(self._verify(public_key_bytes, payload, sig_bytes))
        except Exception:
            return False

    @property
    def public_key_size(self) -> int:
        return 32

    @property
    def signature_size(self) -> int:
        return 7856


class HybridScheme:
    """Hybrid Ed25519 + ML-DSA-65 signature scheme (PQ-2).

    Both algorithms sign the same payload independently.
    Verification requires BOTH signatures to be valid.
    Format: ``"hybrid:<128 hex ed25519>:<6618 hex ml-dsa-65>"``
    """

    def __init__(
        self, ed25519_key: Ed25519PrivateKey, mldsa65_sk: bytes
    ) -> None:
        self._ed25519 = Ed25519Scheme(ed25519_key)
        self._mldsa65 = MLDSA65Scheme(mldsa65_sk)

    @property
    def algorithm_id(self) -> str:
        return "hybrid"

    def sign(self, payload: bytes) -> str:
        ed_sig = self._ed25519.sign(payload)
        ml_sig = self._mldsa65.sign(payload)
        ed_hex = ed_sig[len("ed25519:"):]
        ml_hex = ml_sig[len("ml-dsa-65:"):]
        return f"hybrid:{ed_hex}:{ml_hex}"

    def verify(self, payload: bytes, signature: str, public_key_bytes: bytes) -> bool:
        if not signature.startswith("hybrid:"):
            return False
        inner = signature[len("hybrid:"):]
        # Expected: 128 hex ed25519 + ":" + 6618 hex ml-dsa-65
        if len(inner) != 128 + 1 + 6618:
            return False
        ed_hex = inner[:128]
        if inner[128] != ":":
            return False
        ml_hex = inner[129:]
        # Split PK: 32 bytes Ed25519 + 1952 bytes ML-DSA-65
        if len(public_key_bytes) != 1984:
            return False
        ed_pk = public_key_bytes[:32]
        ml_pk = public_key_bytes[32:]
        ed_valid = self._ed25519.verify(payload, f"ed25519:{ed_hex}", ed_pk)
        ml_valid = self._mldsa65.verify(payload, f"ml-dsa-65:{ml_hex}", ml_pk)
        return ed_valid and ml_valid

    @property
    def public_key_size(self) -> int:
        return 1984  # 32 + 1952

    @property
    def signature_size(self) -> int:
        return 3373  # 64 + 3309


def generate_mldsa65_keypair(path: str | Path) -> tuple[bytes, str]:
    """Generate an ML-DSA-65 keypair and save the secret key to a raw file.

    Returns (secret_key_bytes, public_key_hex).
    The secret key is saved as raw bytes to ``path``.
    The public key is saved as hex to ``path.pub``.
    """
    try:
        from pqcrypto.sign.ml_dsa_65 import generate_keypair as _mldsa_keygen
    except ImportError as exc:
        raise ImportError(
            "ML-DSA-65 requires the pqcrypto package. "
            "Install it with: pip install pqcrypto"
        ) from exc

    key_path = Path(path)
    if key_path.exists():
        raise FileExistsError(
            f"Key already exists at {key_path}. "
            "Delete it first, or specify a different path."
        )
    key_path.parent.mkdir(parents=True, exist_ok=True)

    pk, sk = _mldsa_keygen()

    key_path.write_bytes(sk)
    key_path.chmod(0o600)

    pub_hex = pk.hex()
    pub_path = key_path.with_suffix(".pub")
    pub_path.write_text(pub_hex + "\n")

    return sk, pub_hex


def load_mldsa65_private_key(path: str | Path) -> bytes:
    """Load an ML-DSA-65 secret key from a raw bytes file.

    Raises FileNotFoundError if path doesn't exist.
    Raises ValueError if the file size is wrong.
    """
    key_path = Path(path)
    if not key_path.exists():
        raise FileNotFoundError(
            f"ML-DSA-65 secret key not found: {key_path}\n"
            f"Generate one with: aegis keygen {key_path} --algorithm ml-dsa-65"
        )
    raw = key_path.read_bytes()
    if len(raw) != 4032:
        raise ValueError(
            f"ML-DSA-65 secret key must be 4032 bytes, got {len(raw)}. "
            f"File may be corrupt or not an ML-DSA-65 key."
        )
    return raw


def generate_slhdsa128s_keypair(path: str | Path) -> tuple[bytes, str]:
    """Generate an SLH-DSA-SHAKE-128s keypair and save the secret key.

    Returns (secret_key_bytes, public_key_hex).
    The secret key is saved as raw bytes to ``path``.
    The public key is saved as hex to ``path.pub``.
    """
    try:
        from pqcrypto.sign.sphincs_shake_128s_simple import (  # type: ignore[import-untyped]
            generate_keypair as _slh_keygen,
        )
    except ImportError as exc:
        raise ImportError(
            "SLH-DSA-128s requires the pqcrypto package. "
            "Install it with: pip install pqcrypto"
        ) from exc

    key_path = Path(path)
    if key_path.exists():
        raise FileExistsError(
            f"Key already exists at {key_path}. "
            "Delete it first, or specify a different path."
        )
    key_path.parent.mkdir(parents=True, exist_ok=True)

    pk, sk = _slh_keygen()

    key_path.write_bytes(sk)
    key_path.chmod(0o600)

    pub_hex = pk.hex()
    pub_path = key_path.with_suffix(".pub")
    pub_path.write_text(pub_hex + "\n")

    return sk, pub_hex


def load_slhdsa128s_private_key(path: str | Path) -> bytes:
    """Load an SLH-DSA-128s secret key from a raw bytes file.

    Raises FileNotFoundError if path doesn't exist.
    Raises ValueError if the file size is wrong.
    """
    key_path = Path(path)
    if not key_path.exists():
        raise FileNotFoundError(
            f"SLH-DSA-128s secret key not found: {key_path}\n"
            f"Generate one with: aegis keygen {key_path} --algorithm slh-dsa-128s"
        )
    raw = key_path.read_bytes()
    if len(raw) != 64:
        raise ValueError(
            f"SLH-DSA-128s secret key must be 64 bytes, got {len(raw)}. "
            f"File may be corrupt or not an SLH-DSA-128s key."
        )
    return raw


def generate_hybrid_keypair(
    path: str | Path,
) -> tuple[Ed25519PrivateKey, bytes, str]:
    """Generate a hybrid keypair: Ed25519 PEM + ML-DSA-65 raw bytes.

    Creates three files:
      - ``<path>.pem``        — Ed25519 private key (PEM)
      - ``<path>.mldsa65``    — ML-DSA-65 secret key (raw bytes)
      - ``<path>.hybrid.pub`` — combined public key hex (3968 hex)

    Returns (ed25519_private_key, mldsa65_sk_bytes, hybrid_public_key_hex).
    """
    key_path = Path(path)
    pem_path = key_path.with_suffix(".pem")
    mldsa_path = key_path.with_suffix(".mldsa65")

    ed_key, ed_pub_hex = generate_keypair(pem_path)
    ml_sk, ml_pub_hex = generate_mldsa65_keypair(mldsa_path)

    # Clean up stray .pub files from sub-generators (both write <name>.pub)
    for stray in (pem_path.with_suffix(".pub"), mldsa_path.with_suffix(".pub")):
        if stray.exists():
            stray.unlink()

    hybrid_pub_hex = ed_pub_hex + ml_pub_hex  # 64 + 3904 = 3968 hex
    pub_path = key_path.with_suffix(".hybrid.pub")
    pub_path.write_text(hybrid_pub_hex + "\n")

    return ed_key, ml_sk, hybrid_pub_hex


SUPPORTED_SCHEMES: dict[str, type] = {
    "ed25519": Ed25519Scheme,
    "ml-dsa-65": MLDSA65Scheme,
    "slh-dsa-128s": SLHDSA128sScheme,
    "hybrid": HybridScheme,
}


def create_scheme(
    algorithm_id: str,
    private_key: Ed25519PrivateKey | bytes | tuple[Ed25519PrivateKey, bytes],
) -> Ed25519Scheme | MLDSA65Scheme | SLHDSA128sScheme | HybridScheme:
    """Create a signature scheme instance bound to the given private key.

    For Ed25519, pass an ``Ed25519PrivateKey``.
    For ML-DSA-65, pass raw secret key bytes (4032 bytes).
    For Hybrid, pass a tuple ``(Ed25519PrivateKey, mldsa65_sk_bytes)``.

    Raises ValueError if the algorithm is not supported.
    """
    if algorithm_id == "ed25519":
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("Ed25519 requires an Ed25519PrivateKey instance")
        return Ed25519Scheme(private_key)
    if algorithm_id == "ml-dsa-65":
        if not isinstance(private_key, bytes):
            raise TypeError("ML-DSA-65 requires raw secret key bytes (4032 bytes)")
        return MLDSA65Scheme(private_key)
    if algorithm_id == "slh-dsa-128s":
        if not isinstance(private_key, bytes):
            raise TypeError("SLH-DSA-128s requires raw secret key bytes (64 bytes)")
        return SLHDSA128sScheme(private_key)
    if algorithm_id == "hybrid":
        if not isinstance(private_key, tuple) or len(private_key) != 2:
            raise TypeError(
                "Hybrid requires a tuple (Ed25519PrivateKey, mldsa65_sk_bytes)"
            )
        ed_key, ml_sk = private_key
        if not isinstance(ed_key, Ed25519PrivateKey):
            raise TypeError("Hybrid tuple[0] must be an Ed25519PrivateKey")
        if not isinstance(ml_sk, bytes):
            raise TypeError("Hybrid tuple[1] must be raw ML-DSA-65 secret key bytes")
        return HybridScheme(ed_key, ml_sk)
    raise ValueError(
        f"Unsupported signature scheme: {algorithm_id!r}. "
        f"Supported: {sorted(SUPPORTED_SCHEMES.keys())}"
    )


def truncate_preview(obj: object, max_length: int = 200) -> str:
    """
    Produce a truncated string preview of an object for the ledger.

    Sensitive-looking values (keys containing 'key', 'secret', 'token',
    'password', 'auth', 'credential') are redacted to '***'.
    """
    if obj is None:
        return ""

    sensitive_keys = (
        "key", "secret", "token", "password", "auth", "credential",
        "ssn", "dob", "birth", "phone", "address", "email",
    )
    sensitive_str_prefixes = ("Bearer ", "-----BEGIN", "sk-", "eyJ")

    def _redact(d: object) -> object:
        if isinstance(d, dict):
            return {
                k: "***"
                if any(s in k.lower() for s in sensitive_keys)
                else _redact(v)
                for k, v in d.items()
            }
        if isinstance(d, list):
            return [_redact(item) for item in d]
        if isinstance(d, str) and any(p in d for p in sensitive_str_prefixes):
            return "***"
        return d

    redacted = _redact(obj)
    serialized = json.dumps(redacted, default=str, ensure_ascii=False)

    if len(serialized) <= max_length:
        return serialized

    return serialized[: max_length - 3] + "..."


# ── PII Detection & Sanitization ─────────────────────────────────────────

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
