"""
aegis.schemes — Pluggable signature scheme implementations.

Provides crypto-agility via the ``SignatureScheme`` protocol:
  - Ed25519 (classical, FIPS 186-5)
  - ML-DSA-65 (FIPS 204, post-quantum Level 3)
  - ML-DSA-87 (FIPS 204, CNSA 2.0 Level 5)
  - SLH-DSA-128s (FIPS 205, hash-based)
  - Hybrid Ed25519 + ML-DSA-65

Each scheme is bound to a private key at construction time and exposes
``sign()`` / ``verify()`` with algorithm-prefixed signatures.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# ── Protocol ─────────────────────────────────────────────────────────────


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


# ── Ed25519 ──────────────────────────────────────────────────────────────


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


# ── ML-DSA-65 ────────────────────────────────────────────────────────────


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
        except (ValueError, TypeError):
            return False

    @property
    def public_key_size(self) -> int:
        return 1952

    @property
    def signature_size(self) -> int:
        return 3309


# ── SLH-DSA-128s ─────────────────────────────────────────────────────────


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
        except (ValueError, TypeError):
            return False

    @property
    def public_key_size(self) -> int:
        return 32

    @property
    def signature_size(self) -> int:
        return 7856


# ── ML-DSA-87 ────────────────────────────────────────────────────────────


class MLDSA87Scheme:
    """ML-DSA-87 (FIPS 204, CNSA 2.0 Level 5) post-quantum signature scheme.

    Higher security level than ML-DSA-65 — required for CNSA 2.0 compliance
    starting January 2027. Larger keys (PK=2592B, SK=4896B) and signatures
    (4627B) but provides NIST Security Level 5.

    Requires the ``pqcrypto`` package: ``pip install pqcrypto``
    or ``pip install aegis-ledger-sdk[pq]``.
    """

    def __init__(self, private_key_bytes: bytes) -> None:
        try:
            from pqcrypto.sign.ml_dsa_87 import sign as _sign  # type: ignore[import-untyped]
            from pqcrypto.sign.ml_dsa_87 import verify as _verify
        except ImportError as exc:
            raise ImportError(
                "ML-DSA-87 requires the pqcrypto package. "
                "Install it with: pip install pqcrypto"
            ) from exc
        if len(private_key_bytes) != 4896:
            raise ValueError(
                f"ML-DSA-87 secret key must be 4896 bytes, got {len(private_key_bytes)}"
            )
        self._sk = private_key_bytes
        self._sign = _sign
        self._verify = _verify

    @property
    def algorithm_id(self) -> str:
        return "ml-dsa-87"

    def sign(self, payload: bytes) -> str:
        sig = self._sign(self._sk, payload)
        return f"ml-dsa-87:{sig.hex()}"

    def verify(self, payload: bytes, signature: str, public_key_bytes: bytes) -> bool:
        if not signature.startswith("ml-dsa-87:"):
            return False
        try:
            sig_bytes = bytes.fromhex(signature[len("ml-dsa-87:"):])
        except ValueError:
            return False
        try:
            return bool(self._verify(public_key_bytes, payload, sig_bytes))
        except (ValueError, TypeError):
            return False

    @property
    def public_key_size(self) -> int:
        return 2592

    @property
    def signature_size(self) -> int:
        return 4627


# ── Hybrid ───────────────────────────────────────────────────────────────


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


# ── Key generation / loading ─────────────────────────────────────────────


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
    pub_path = key_path.parent / (key_path.name + ".pub")
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


def generate_mldsa87_keypair(path: str | Path) -> tuple[bytes, str]:
    """Generate an ML-DSA-87 keypair and save the secret key to a raw file.

    Returns (secret_key_bytes, public_key_hex).
    The secret key is saved as raw bytes to ``path``.
    The public key is saved as hex to ``path.pub``.
    """
    try:
        from pqcrypto.sign.ml_dsa_87 import (
            generate_keypair as _mldsa87_keygen,  # type: ignore[import-untyped]
        )
    except ImportError as exc:
        raise ImportError(
            "ML-DSA-87 requires the pqcrypto package. "
            "Install it with: pip install pqcrypto"
        ) from exc

    key_path = Path(path)
    if key_path.exists():
        raise FileExistsError(
            f"Key already exists at {key_path}. "
            "Delete it first, or specify a different path."
        )
    key_path.parent.mkdir(parents=True, exist_ok=True)

    pk, sk = _mldsa87_keygen()

    key_path.write_bytes(sk)
    key_path.chmod(0o600)

    pub_hex = pk.hex()
    pub_path = key_path.parent / (key_path.name + ".pub")
    pub_path.write_text(pub_hex + "\n")

    return sk, pub_hex


def load_mldsa87_private_key(path: str | Path) -> bytes:
    """Load an ML-DSA-87 secret key from a raw bytes file.

    Raises FileNotFoundError if path doesn't exist.
    Raises ValueError if the file size is wrong.
    """
    key_path = Path(path)
    if not key_path.exists():
        raise FileNotFoundError(
            f"ML-DSA-87 secret key not found: {key_path}\n"
            f"Generate one with: aegis keygen {key_path} --algorithm ml-dsa-87"
        )
    raw = key_path.read_bytes()
    if len(raw) != 4896:
        raise ValueError(
            f"ML-DSA-87 secret key must be 4896 bytes, got {len(raw)}. "
            f"File may be corrupt or not an ML-DSA-87 key."
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
    pub_path = key_path.parent / (key_path.name + ".pub")
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
      - ``<path>.pem``        -- Ed25519 private key (PEM)
      - ``<path>.mldsa65``    -- ML-DSA-65 secret key (raw bytes)
      - ``<path>.hybrid.pub`` -- combined public key hex (3968 hex)

    Returns (ed25519_private_key, mldsa65_sk_bytes, hybrid_public_key_hex).
    """
    from .crypto import generate_keypair

    key_path = Path(path)
    pem_path = key_path.with_suffix(".pem")
    mldsa_path = key_path.with_suffix(".mldsa65")

    ed_key, ed_pub_hex = generate_keypair(pem_path)
    ml_sk, ml_pub_hex = generate_mldsa65_keypair(mldsa_path)

    # Clean up stray .pub files from sub-generators
    for stray in (
        pem_path.with_suffix(".pub"),                       # Ed25519: agent_key.pub
        pem_path.parent / (pem_path.name + ".pub"),         # Ed25519: agent_key.pem.pub (unlikely)
    ):
        if stray.exists():
            stray.unlink()
    # Keep agent_key.mldsa65.pub — needed for hybrid pub derivation

    hybrid_pub_hex = ed_pub_hex + ml_pub_hex  # 64 + 3904 = 3968 hex
    pub_path = key_path.with_suffix(".hybrid.pub")
    pub_path.write_text(hybrid_pub_hex + "\n")

    return ed_key, ml_sk, hybrid_pub_hex


# ── Registry ─────────────────────────────────────────────────────────────


SUPPORTED_SCHEMES: dict[str, type] = {
    "ed25519": Ed25519Scheme,
    "ml-dsa-65": MLDSA65Scheme,
    "ml-dsa-87": MLDSA87Scheme,
    "slh-dsa-128s": SLHDSA128sScheme,
    "hybrid": HybridScheme,
}


def create_scheme(
    algorithm_id: str,
    private_key: Ed25519PrivateKey | bytes | tuple[Ed25519PrivateKey, bytes],
) -> Ed25519Scheme | MLDSA65Scheme | MLDSA87Scheme | SLHDSA128sScheme | HybridScheme:
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
    if algorithm_id == "ml-dsa-87":
        if not isinstance(private_key, bytes):
            raise TypeError("ML-DSA-87 requires raw secret key bytes (4896 bytes)")
        return MLDSA87Scheme(private_key)
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
