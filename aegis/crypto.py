"""
aegis.crypto — Cryptographic primitives for payload signing.

Handles:
  1. Deterministic canonical JSON serialization (sorted keys, no whitespace).
  2. SHA-256 hashing of arbitrary payloads (for input_hash / output_hash).
  3. Ed25519 signature generation over canonical JSON.
  4. Ed25519 private key loading from PEM files.

The canonical JSON format is the security-critical serialization used
to produce the `payload_signature`. Any deviation in key ordering,
whitespace, or numeric formatting between the SDK and the canister's
verifier will cause signature verification failures.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

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


def truncate_preview(obj: object, max_length: int = 200) -> str:
    """
    Produce a truncated string preview of an object for the ledger.

    Sensitive-looking values (keys containing 'key', 'secret', 'token',
    'password', 'auth', 'credential') are redacted to '***'.
    """
    if obj is None:
        return ""

    sensitive_keys = ("key", "secret", "token", "password", "auth", "credential")
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
