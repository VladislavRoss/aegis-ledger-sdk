"""Tests for SignatureScheme Protocol: Ed25519, ML-DSA-65, SLH-DSA-128s, Hybrid."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from AEGIS_LEDGER.crypto import (
    Ed25519Scheme,
    HybridScheme,
    MLDSA65Scheme,
    SignatureScheme,
    SLHDSA128sScheme,
    canonical_json,
    create_scheme,
    sign_payload,
    verify_signature,
)

# ── Helpers ──────────────────────────────────────────────────────────────

def _mldsa65_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-DSA-65 keypair via pqcrypto."""
    from pqcrypto.sign.ml_dsa_65 import generate_keypair  # type: ignore[import-untyped]
    return generate_keypair()  # (pk, sk)


def _slhdsa128s_keypair() -> tuple[bytes, bytes]:
    """Generate an SLH-DSA-128s keypair via pqcrypto."""
    from pqcrypto.sign.sphincs_shake_128s_simple import (
        generate_keypair,  # type: ignore[import-untyped]
    )
    return generate_keypair()  # (pk, sk)


def _hybrid_keys() -> tuple[Ed25519PrivateKey, bytes, bytes, bytes]:
    """Generate both keypairs for HybridScheme.

    Returns (ed25519_private, mldsa65_sk, ed25519_pk_bytes, mldsa65_pk_bytes).
    """
    ed_key = Ed25519PrivateKey.generate()
    ed_pk = ed_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ml_pk, ml_sk = _mldsa65_keypair()
    return ed_key, ml_sk, ed_pk, ml_pk


# ── Ed25519 Protocol Tests ──────────────────────────────────────────────


class TestSignatureSchemeProtocol:
    """Verify Ed25519Scheme satisfies the SignatureScheme protocol."""

    def test_ed25519_is_signature_scheme(self):
        key = Ed25519PrivateKey.generate()
        scheme = Ed25519Scheme(key)
        assert isinstance(scheme, SignatureScheme)

    def test_algorithm_id(self):
        key = Ed25519PrivateKey.generate()
        scheme = Ed25519Scheme(key)
        assert scheme.algorithm_id == "ed25519"

    def test_public_key_size(self):
        key = Ed25519PrivateKey.generate()
        scheme = Ed25519Scheme(key)
        assert scheme.public_key_size == 32

    def test_signature_size(self):
        key = Ed25519PrivateKey.generate()
        scheme = Ed25519Scheme(key)
        assert scheme.signature_size == 64


class TestEd25519Scheme:
    """Test Ed25519Scheme sign/verify operations."""

    @pytest.fixture()
    def scheme(self):
        key = Ed25519PrivateKey.generate()
        return Ed25519Scheme(key), key

    def test_sign_returns_prefixed_hex(self, scheme):
        ed_scheme, _ = scheme
        payload = canonical_json({"action": "test"})
        sig = ed_scheme.sign(payload)
        assert sig.startswith("ed25519:")
        hex_part = sig[len("ed25519:") :]
        assert len(hex_part) == 128
        bytes.fromhex(hex_part)  # should not raise

    def test_sign_verify_roundtrip(self, scheme):
        ed_scheme, key = scheme
        payload = canonical_json({"action": "test", "seq": 0})
        sig = ed_scheme.sign(payload)
        pk_bytes = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert ed_scheme.verify(payload, sig, pk_bytes)

    def test_verify_wrong_payload(self, scheme):
        ed_scheme, key = scheme
        payload = canonical_json({"action": "test"})
        sig = ed_scheme.sign(payload)
        wrong = canonical_json({"action": "tampered"})
        pk_bytes = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert not ed_scheme.verify(wrong, sig, pk_bytes)

    def test_verify_wrong_key(self, scheme):
        ed_scheme, _ = scheme
        payload = canonical_json({"action": "test"})
        sig = ed_scheme.sign(payload)
        other_key = Ed25519PrivateKey.generate()
        other_pk = other_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert not ed_scheme.verify(payload, sig, other_pk)

    def test_verify_bad_prefix(self, scheme):
        ed_scheme, key = scheme
        pk_bytes = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert not ed_scheme.verify(b"data", "rsa:abcdef", pk_bytes)

    def test_verify_bad_hex(self, scheme):
        ed_scheme, key = scheme
        pk_bytes = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert not ed_scheme.verify(b"data", "ed25519:not_hex!", pk_bytes)

    def test_verify_bad_pk_bytes(self, scheme):
        ed_scheme, _ = scheme
        payload = canonical_json({"action": "test"})
        sig = ed_scheme.sign(payload)
        assert not ed_scheme.verify(payload, sig, b"short")

    def test_compatible_with_legacy_sign_payload(self, scheme):
        """Ed25519Scheme produces signatures verifiable by legacy verify_signature."""
        ed_scheme, key = scheme
        payload = canonical_json({"action": "compat_test"})
        sig = ed_scheme.sign(payload)
        assert verify_signature(payload, sig, key.public_key())

    def test_compatible_with_legacy_verify(self, scheme):
        """Signatures from legacy sign_payload are verifiable by Ed25519Scheme."""
        ed_scheme, key = scheme
        payload = canonical_json({"action": "compat_test"})
        sig = sign_payload(payload, key)
        pk_bytes = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert ed_scheme.verify(payload, sig, pk_bytes)


# ── ML-DSA-65 Tests ─────────────────────────────────────────────────────


class TestMLDSA65SchemeProtocol:
    """Verify MLDSA65Scheme satisfies the SignatureScheme protocol."""

    def test_mldsa65_is_signature_scheme(self):
        _, sk = _mldsa65_keypair()
        scheme = MLDSA65Scheme(sk)
        assert isinstance(scheme, SignatureScheme)

    def test_mldsa65_algorithm_id(self):
        _, sk = _mldsa65_keypair()
        scheme = MLDSA65Scheme(sk)
        assert scheme.algorithm_id == "ml-dsa-65"

    def test_mldsa65_public_key_size(self):
        _, sk = _mldsa65_keypair()
        scheme = MLDSA65Scheme(sk)
        assert scheme.public_key_size == 1952

    def test_mldsa65_signature_size(self):
        _, sk = _mldsa65_keypair()
        scheme = MLDSA65Scheme(sk)
        assert scheme.signature_size == 3309


class TestMLDSA65Scheme:
    """Test MLDSA65Scheme sign/verify operations."""

    @pytest.fixture()
    def keypair(self):
        pk, sk = _mldsa65_keypair()
        return MLDSA65Scheme(sk), pk, sk

    def test_sign_returns_prefixed(self, keypair):
        scheme, _, _ = keypair
        payload = canonical_json({"action": "pq_test"})
        sig = scheme.sign(payload)
        assert sig.startswith("ml-dsa-65:")
        hex_part = sig[len("ml-dsa-65:"):]
        assert len(hex_part) == 3309 * 2  # hex encoding doubles byte count
        bytes.fromhex(hex_part)

    def test_sign_verify_roundtrip(self, keypair):
        scheme, pk, _ = keypair
        payload = canonical_json({"action": "pq_test", "seq": 0})
        sig = scheme.sign(payload)
        assert scheme.verify(payload, sig, pk)

    def test_verify_wrong_payload(self, keypair):
        scheme, pk, _ = keypair
        payload = canonical_json({"action": "pq_test"})
        sig = scheme.sign(payload)
        wrong = canonical_json({"action": "tampered"})
        assert not scheme.verify(wrong, sig, pk)

    def test_verify_wrong_key(self, keypair):
        scheme, _, _ = keypair
        payload = canonical_json({"action": "pq_test"})
        sig = scheme.sign(payload)
        other_pk, _ = _mldsa65_keypair()
        assert not scheme.verify(payload, sig, other_pk)

    def test_verify_bad_prefix(self, keypair):
        scheme, pk, _ = keypair
        assert not scheme.verify(b"data", "ed25519:abcdef", pk)

    def test_verify_bad_hex(self, keypair):
        scheme, pk, _ = keypair
        assert not scheme.verify(b"data", "ml-dsa-65:not_hex!", pk)

    def test_randomized_signing(self, keypair):
        """ML-DSA-65 per FIPS 204 uses randomized signing — two signatures differ."""
        scheme, pk, _ = keypair
        payload = canonical_json({"action": "determinism_test"})
        sig1 = scheme.sign(payload)
        sig2 = scheme.sign(payload)
        # Both must verify
        assert scheme.verify(payload, sig1, pk)
        assert scheme.verify(payload, sig2, pk)
        # FIPS 204 randomized signing: signatures should differ
        assert sig1 != sig2

    def test_different_payloads(self, keypair):
        scheme, pk, _ = keypair
        sig_a = scheme.sign(canonical_json({"x": 1}))
        sig_b = scheme.sign(canonical_json({"x": 2}))
        assert sig_a != sig_b
        assert scheme.verify(canonical_json({"x": 1}), sig_a, pk)
        assert scheme.verify(canonical_json({"x": 2}), sig_b, pk)

    def test_bad_sk_size_rejected(self):
        with pytest.raises(ValueError, match="4032 bytes"):
            MLDSA65Scheme(b"too_short")

    def test_cross_algorithm_reject(self, keypair):
        """Ed25519 signature must fail under ML-DSA-65 verifier."""
        mldsa_scheme, pk, _ = keypair
        ed_key = Ed25519PrivateKey.generate()
        ed_scheme = Ed25519Scheme(ed_key)
        payload = canonical_json({"action": "cross"})
        ed_sig = ed_scheme.sign(payload)
        assert not mldsa_scheme.verify(payload, ed_sig, pk)

    def test_cross_algorithm_reject_reverse(self, keypair):
        """ML-DSA-65 signature must fail under Ed25519 verifier."""
        mldsa_scheme, _, _ = keypair
        ed_key = Ed25519PrivateKey.generate()
        ed_scheme = Ed25519Scheme(ed_key)
        payload = canonical_json({"action": "cross_reverse"})
        mldsa_sig = mldsa_scheme.sign(payload)
        ed_pk = ed_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert not ed_scheme.verify(payload, mldsa_sig, ed_pk)


# ── SLH-DSA-128s Tests ─────────────────────────────────────────────────


class TestSLHDSA128sSchemeProtocol:
    """Verify SLHDSA128sScheme satisfies the SignatureScheme protocol."""

    def test_is_signature_scheme(self):
        _, sk = _slhdsa128s_keypair()
        scheme = SLHDSA128sScheme(sk)
        assert isinstance(scheme, SignatureScheme)

    def test_algorithm_id(self):
        _, sk = _slhdsa128s_keypair()
        scheme = SLHDSA128sScheme(sk)
        assert scheme.algorithm_id == "slh-dsa-128s"

    def test_public_key_size(self):
        _, sk = _slhdsa128s_keypair()
        scheme = SLHDSA128sScheme(sk)
        assert scheme.public_key_size == 32

    def test_signature_size(self):
        _, sk = _slhdsa128s_keypair()
        scheme = SLHDSA128sScheme(sk)
        assert scheme.signature_size == 7856


class TestSLHDSA128sScheme:
    """Test SLHDSA128sScheme sign/verify operations."""

    @pytest.fixture()
    def keypair(self):
        pk, sk = _slhdsa128s_keypair()
        return SLHDSA128sScheme(sk), pk, sk

    def test_sign_returns_prefixed(self, keypair):
        scheme, _, _ = keypair
        payload = canonical_json({"action": "slh_test"})
        sig = scheme.sign(payload)
        assert sig.startswith("slh-dsa-128s:")
        hex_part = sig[len("slh-dsa-128s:"):]
        assert len(hex_part) == 7856 * 2
        bytes.fromhex(hex_part)

    def test_sign_verify_roundtrip(self, keypair):
        scheme, pk, _ = keypair
        payload = canonical_json({"action": "slh_test", "seq": 0})
        sig = scheme.sign(payload)
        assert scheme.verify(payload, sig, pk)

    def test_verify_wrong_payload(self, keypair):
        scheme, pk, _ = keypair
        payload = canonical_json({"action": "slh_test"})
        sig = scheme.sign(payload)
        wrong = canonical_json({"action": "tampered"})
        assert not scheme.verify(wrong, sig, pk)

    def test_verify_wrong_key(self, keypair):
        scheme, _, _ = keypair
        payload = canonical_json({"action": "slh_test"})
        sig = scheme.sign(payload)
        other_pk, _ = _slhdsa128s_keypair()
        assert not scheme.verify(payload, sig, other_pk)

    def test_verify_bad_prefix(self, keypair):
        scheme, pk, _ = keypair
        assert not scheme.verify(b"data", "ed25519:abcdef", pk)

    def test_verify_bad_hex(self, keypair):
        scheme, pk, _ = keypair
        assert not scheme.verify(b"data", "slh-dsa-128s:not_hex!", pk)

    def test_bad_sk_size_rejected(self):
        with pytest.raises(ValueError, match="64 bytes"):
            SLHDSA128sScheme(b"too_short")

    def test_cross_algorithm_reject_ed25519(self, keypair):
        """Ed25519 signature must fail under SLH-DSA-128s verifier."""
        slh_scheme, pk, _ = keypair
        ed_key = Ed25519PrivateKey.generate()
        ed_scheme = Ed25519Scheme(ed_key)
        payload = canonical_json({"cross": "test"})
        ed_sig = ed_scheme.sign(payload)
        assert not slh_scheme.verify(payload, ed_sig, pk)

    def test_cross_algorithm_reject_mldsa65(self, keypair):
        """ML-DSA-65 signature must fail under SLH-DSA-128s verifier."""
        slh_scheme, pk, _ = keypair
        _, ml_sk = _mldsa65_keypair()
        ml_scheme = MLDSA65Scheme(ml_sk)
        payload = canonical_json({"cross": "mldsa"})
        ml_sig = ml_scheme.sign(payload)
        assert not slh_scheme.verify(payload, ml_sig, pk)


class TestSLHDSA128sKeygen:
    """Test SLH-DSA-128s keypair generation and loading."""

    def test_generate_and_load(self, tmp_path):
        from AEGIS_LEDGER.crypto import generate_slhdsa128s_keypair, load_slhdsa128s_private_key

        key_file = tmp_path / "test.slh"
        sk, pub_hex = generate_slhdsa128s_keypair(key_file)
        assert len(sk) == 64
        assert len(pub_hex) == 32 * 2  # hex

        loaded_sk = load_slhdsa128s_private_key(key_file)
        assert loaded_sk == sk

    def test_generate_writes_pub_file(self, tmp_path):
        from AEGIS_LEDGER.crypto import generate_slhdsa128s_keypair

        key_file = tmp_path / "test.slh"
        _, pub_hex = generate_slhdsa128s_keypair(key_file)
        pub_file = key_file.with_suffix(".pub")
        assert pub_file.exists()
        assert pub_file.read_text().strip() == pub_hex

    def test_generate_existing_raises(self, tmp_path):
        from AEGIS_LEDGER.crypto import generate_slhdsa128s_keypair

        key_file = tmp_path / "test.slh"
        generate_slhdsa128s_keypair(key_file)
        with pytest.raises(FileExistsError):
            generate_slhdsa128s_keypair(key_file)

    def test_load_missing_raises(self, tmp_path):
        from AEGIS_LEDGER.crypto import load_slhdsa128s_private_key

        with pytest.raises(FileNotFoundError):
            load_slhdsa128s_private_key(tmp_path / "nonexistent.slh")

    def test_load_wrong_size_raises(self, tmp_path):
        from AEGIS_LEDGER.crypto import load_slhdsa128s_private_key

        bad_file = tmp_path / "bad.slh"
        bad_file.write_bytes(b"wrong_size_data_here")
        with pytest.raises(ValueError, match="64 bytes"):
            load_slhdsa128s_private_key(bad_file)

    def test_generated_key_signs_and_verifies(self, tmp_path):
        from AEGIS_LEDGER.crypto import generate_slhdsa128s_keypair

        key_file = tmp_path / "test.slh"
        sk, pub_hex = generate_slhdsa128s_keypair(key_file)

        scheme = SLHDSA128sScheme(sk)
        payload = canonical_json({"keygen": "slh_test"})
        sig = scheme.sign(payload)

        pk_bytes = bytes.fromhex(pub_hex)
        assert scheme.verify(payload, sig, pk_bytes)


# ── create_scheme Factory Tests ──────────────────────────────────────────


class TestCreateScheme:
    """Test the create_scheme factory function."""

    def test_create_ed25519(self):
        key = Ed25519PrivateKey.generate()
        scheme = create_scheme("ed25519", key)
        assert scheme.algorithm_id == "ed25519"
        assert isinstance(scheme, Ed25519Scheme)

    def test_create_unsupported_raises(self):
        key = Ed25519PrivateKey.generate()
        with pytest.raises(ValueError, match="Unsupported"):
            create_scheme("rsa", key)

    def test_create_mldsa65(self):
        _, sk = _mldsa65_keypair()
        scheme = create_scheme("ml-dsa-65", sk)
        assert scheme.algorithm_id == "ml-dsa-65"
        assert isinstance(scheme, MLDSA65Scheme)

    def test_create_mldsa65_signs_and_verifies(self):
        pk, sk = _mldsa65_keypair()
        scheme = create_scheme("ml-dsa-65", sk)
        payload = canonical_json({"test": True})
        sig = scheme.sign(payload)
        assert sig.startswith("ml-dsa-65:")
        assert scheme.verify(payload, sig, pk)

    def test_create_ed25519_with_bytes_raises(self):
        with pytest.raises(TypeError, match="Ed25519PrivateKey"):
            create_scheme("ed25519", b"not_a_key")

    def test_create_slhdsa128s(self):
        _, sk = _slhdsa128s_keypair()
        scheme = create_scheme("slh-dsa-128s", sk)
        assert scheme.algorithm_id == "slh-dsa-128s"
        assert isinstance(scheme, SLHDSA128sScheme)

    def test_create_slhdsa128s_signs_and_verifies(self):
        pk, sk = _slhdsa128s_keypair()
        scheme = create_scheme("slh-dsa-128s", sk)
        payload = canonical_json({"test": True})
        sig = scheme.sign(payload)
        assert sig.startswith("slh-dsa-128s:")
        assert scheme.verify(payload, sig, pk)

    def test_create_mldsa65_with_ed25519_key_raises(self):
        key = Ed25519PrivateKey.generate()
        with pytest.raises(TypeError, match="raw secret key bytes"):
            create_scheme("ml-dsa-65", key)

    def test_created_scheme_signs(self):
        key = Ed25519PrivateKey.generate()
        scheme = create_scheme("ed25519", key)
        payload = canonical_json({"test": True})
        sig = scheme.sign(payload)
        assert sig.startswith("ed25519:")

    def test_created_scheme_verifies(self):
        key = Ed25519PrivateKey.generate()
        scheme = create_scheme("ed25519", key)
        payload = canonical_json({"test": True})
        sig = scheme.sign(payload)
        pk_bytes = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert scheme.verify(payload, sig, pk_bytes)


class TestSupportedSchemes:
    """Test the SUPPORTED_SCHEMES registry."""

    def test_ed25519_registered(self):
        from AEGIS_LEDGER.crypto import SUPPORTED_SCHEMES

        assert "ed25519" in SUPPORTED_SCHEMES
        assert SUPPORTED_SCHEMES["ed25519"] is Ed25519Scheme

    def test_mldsa65_registered(self):
        from AEGIS_LEDGER.crypto import SUPPORTED_SCHEMES

        assert "ml-dsa-65" in SUPPORTED_SCHEMES
        assert SUPPORTED_SCHEMES["ml-dsa-65"] is MLDSA65Scheme

    def test_slhdsa128s_registered(self):
        from AEGIS_LEDGER.crypto import SUPPORTED_SCHEMES

        assert "slh-dsa-128s" in SUPPORTED_SCHEMES
        assert SUPPORTED_SCHEMES["slh-dsa-128s"] is SLHDSA128sScheme

    def test_hybrid_registered(self):
        from AEGIS_LEDGER.crypto import SUPPORTED_SCHEMES

        assert "hybrid" in SUPPORTED_SCHEMES
        assert SUPPORTED_SCHEMES["hybrid"] is HybridScheme

    def test_four_schemes_registered(self):
        from AEGIS_LEDGER.crypto import SUPPORTED_SCHEMES

        assert sorted(SUPPORTED_SCHEMES.keys()) == [
            "ed25519", "hybrid", "ml-dsa-65", "slh-dsa-128s",
        ]


# ── Keygen Tests ─────────────────────────────────────────────────────────


class TestMLDSA65Keygen:
    """Test ML-DSA-65 keypair generation and loading."""

    def test_generate_and_load(self, tmp_path):
        from AEGIS_LEDGER.crypto import generate_mldsa65_keypair, load_mldsa65_private_key

        key_file = tmp_path / "test.mldsa65"
        sk, pub_hex = generate_mldsa65_keypair(key_file)
        assert len(sk) == 4032
        assert len(pub_hex) == 1952 * 2  # hex

        loaded_sk = load_mldsa65_private_key(key_file)
        assert loaded_sk == sk

    def test_generate_writes_pub_file(self, tmp_path):
        from AEGIS_LEDGER.crypto import generate_mldsa65_keypair

        key_file = tmp_path / "test.mldsa65"
        _, pub_hex = generate_mldsa65_keypair(key_file)
        pub_file = key_file.with_suffix(".pub")
        assert pub_file.exists()
        assert pub_file.read_text().strip() == pub_hex

    def test_generate_existing_raises(self, tmp_path):
        from AEGIS_LEDGER.crypto import generate_mldsa65_keypair

        key_file = tmp_path / "test.mldsa65"
        generate_mldsa65_keypair(key_file)
        with pytest.raises(FileExistsError):
            generate_mldsa65_keypair(key_file)

    def test_load_missing_raises(self, tmp_path):
        from AEGIS_LEDGER.crypto import load_mldsa65_private_key

        with pytest.raises(FileNotFoundError):
            load_mldsa65_private_key(tmp_path / "nonexistent.mldsa65")

    def test_load_wrong_size_raises(self, tmp_path):
        from AEGIS_LEDGER.crypto import load_mldsa65_private_key

        bad_file = tmp_path / "bad.mldsa65"
        bad_file.write_bytes(b"wrong_size")
        with pytest.raises(ValueError, match="4032 bytes"):
            load_mldsa65_private_key(bad_file)

    def test_generated_key_signs_and_verifies(self, tmp_path):
        from AEGIS_LEDGER.crypto import generate_mldsa65_keypair

        key_file = tmp_path / "test.mldsa65"
        sk, pub_hex = generate_mldsa65_keypair(key_file)

        scheme = MLDSA65Scheme(sk)
        payload = canonical_json({"keygen": "test"})
        sig = scheme.sign(payload)

        pk_bytes = bytes.fromhex(pub_hex)
        assert scheme.verify(payload, sig, pk_bytes)


# ── Hybrid Scheme Protocol Tests ────────────────────────────────────────


class TestHybridSchemeProtocol:
    """Test that HybridScheme satisfies the SignatureScheme protocol."""

    def test_hybrid_is_signature_scheme(self):
        ed_key, ml_sk, _, _ = _hybrid_keys()
        scheme = HybridScheme(ed_key, ml_sk)
        assert isinstance(scheme, SignatureScheme)

    def test_hybrid_algorithm_id(self):
        ed_key, ml_sk, _, _ = _hybrid_keys()
        scheme = HybridScheme(ed_key, ml_sk)
        assert scheme.algorithm_id == "hybrid"

    def test_hybrid_public_key_size(self):
        ed_key, ml_sk, _, _ = _hybrid_keys()
        scheme = HybridScheme(ed_key, ml_sk)
        assert scheme.public_key_size == 1984

    def test_hybrid_signature_size(self):
        ed_key, ml_sk, _, _ = _hybrid_keys()
        scheme = HybridScheme(ed_key, ml_sk)
        assert scheme.signature_size == 3373


# ── Hybrid Scheme Functional Tests ──────────────────────────────────────


class TestHybridScheme:
    """Test HybridScheme sign/verify behavior."""

    def test_sign_format(self):
        ed_key, ml_sk, _, _ = _hybrid_keys()
        scheme = HybridScheme(ed_key, ml_sk)
        payload = canonical_json({"hybrid": True})
        sig = scheme.sign(payload)
        assert sig.startswith("hybrid:")

    def test_sign_length(self):
        ed_key, ml_sk, _, _ = _hybrid_keys()
        scheme = HybridScheme(ed_key, ml_sk)
        payload = canonical_json({"hybrid": True})
        sig = scheme.sign(payload)
        assert len(sig) == 6754  # 7 + 128 + 1 + 6618

    def test_sign_verify_roundtrip(self):
        ed_key, ml_sk, ed_pk, ml_pk = _hybrid_keys()
        scheme = HybridScheme(ed_key, ml_sk)
        payload = canonical_json({"roundtrip": "test"})
        sig = scheme.sign(payload)
        combined_pk = ed_pk + ml_pk
        assert scheme.verify(payload, sig, combined_pk)

    def test_verify_wrong_payload(self):
        ed_key, ml_sk, ed_pk, ml_pk = _hybrid_keys()
        scheme = HybridScheme(ed_key, ml_sk)
        payload = canonical_json({"original": True})
        sig = scheme.sign(payload)
        tampered = canonical_json({"original": False})
        combined_pk = ed_pk + ml_pk
        assert not scheme.verify(tampered, sig, combined_pk)

    def test_verify_wrong_ed25519_key(self):
        ed_key, ml_sk, _, ml_pk = _hybrid_keys()
        scheme = HybridScheme(ed_key, ml_sk)
        payload = canonical_json({"test": 1})
        sig = scheme.sign(payload)
        # Use a different Ed25519 key
        wrong_ed_pk = Ed25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        combined_pk = wrong_ed_pk + ml_pk
        assert not scheme.verify(payload, sig, combined_pk)

    def test_verify_wrong_mldsa65_key(self):
        ed_key, ml_sk, ed_pk, _ = _hybrid_keys()
        scheme = HybridScheme(ed_key, ml_sk)
        payload = canonical_json({"test": 2})
        sig = scheme.sign(payload)
        # Use a different ML-DSA-65 key
        wrong_ml_pk, _ = _mldsa65_keypair()
        combined_pk = ed_pk + wrong_ml_pk
        assert not scheme.verify(payload, sig, combined_pk)

    def test_verify_bad_prefix(self):
        ed_key, ml_sk, ed_pk, ml_pk = _hybrid_keys()
        scheme = HybridScheme(ed_key, ml_sk)
        payload = canonical_json({"test": 3})
        # Use an Ed25519 signature with hybrid verifier
        ed_scheme = Ed25519Scheme(ed_key)
        ed_sig = ed_scheme.sign(payload)
        combined_pk = ed_pk + ml_pk
        assert not scheme.verify(payload, ed_sig, combined_pk)

    def test_verify_bad_inner_format(self):
        ed_key, ml_sk, ed_pk, ml_pk = _hybrid_keys()
        scheme = HybridScheme(ed_key, ml_sk)
        payload = canonical_json({"test": 4})
        # Signature with wrong inner format (no separator)
        bad_sig = "hybrid:" + "a" * (128 + 1 + 6618)  # all 'a', no colon at 128
        combined_pk = ed_pk + ml_pk
        assert not scheme.verify(payload, bad_sig, combined_pk)

    def test_verify_bad_pk_size(self):
        ed_key, ml_sk, ed_pk, _ = _hybrid_keys()
        scheme = HybridScheme(ed_key, ml_sk)
        payload = canonical_json({"test": 5})
        sig = scheme.sign(payload)
        # Only Ed25519 PK (32 bytes) — too short for hybrid
        assert not scheme.verify(payload, sig, ed_pk)

    def test_contains_valid_ed25519(self):
        """Ed25519 portion of hybrid sig should independently verify."""
        ed_key, ml_sk, ed_pk, _ = _hybrid_keys()
        scheme = HybridScheme(ed_key, ml_sk)
        payload = canonical_json({"extract": "ed25519"})
        sig = scheme.sign(payload)
        inner = sig[len("hybrid:"):]
        ed_hex = inner[:128]
        ed_sig = f"ed25519:{ed_hex}"
        ed_scheme = Ed25519Scheme(ed_key)
        assert ed_scheme.verify(payload, ed_sig, ed_pk)

    def test_contains_valid_mldsa65(self):
        """ML-DSA-65 portion of hybrid sig should independently verify."""
        ed_key, ml_sk, _, ml_pk = _hybrid_keys()
        scheme = HybridScheme(ed_key, ml_sk)
        payload = canonical_json({"extract": "mldsa65"})
        sig = scheme.sign(payload)
        inner = sig[len("hybrid:"):]
        ml_hex = inner[129:]
        ml_sig = f"ml-dsa-65:{ml_hex}"
        ml_scheme = MLDSA65Scheme(ml_sk)
        assert ml_scheme.verify(payload, ml_sig, ml_pk)

    def test_cross_hybrid_ed25519_reject(self):
        """Hybrid sig must fail when verified as Ed25519."""
        ed_key, ml_sk, ed_pk, ml_pk = _hybrid_keys()
        scheme = HybridScheme(ed_key, ml_sk)
        payload = canonical_json({"cross": "test"})
        sig = scheme.sign(payload)
        ed_scheme = Ed25519Scheme(ed_key)
        assert not ed_scheme.verify(payload, sig, ed_pk)

    def test_cross_hybrid_mldsa65_reject(self):
        """Hybrid sig must fail when verified as ML-DSA-65."""
        ed_key, ml_sk, _, ml_pk = _hybrid_keys()
        scheme = HybridScheme(ed_key, ml_sk)
        payload = canonical_json({"cross": "test2"})
        sig = scheme.sign(payload)
        ml_scheme = MLDSA65Scheme(ml_sk)
        assert not ml_scheme.verify(payload, sig, ml_pk)


# ── Hybrid create_scheme + keygen Tests ─────────────────────────────────


class TestCreateSchemeHybrid:
    """Test create_scheme() with hybrid algorithm."""

    def test_create_hybrid(self):
        ed_key, ml_sk, _, _ = _hybrid_keys()
        scheme = create_scheme("hybrid", (ed_key, ml_sk))
        assert isinstance(scheme, HybridScheme)
        assert scheme.algorithm_id == "hybrid"

    def test_create_hybrid_signs_and_verifies(self):
        ed_key, ml_sk, ed_pk, ml_pk = _hybrid_keys()
        scheme = create_scheme("hybrid", (ed_key, ml_sk))
        payload = canonical_json({"factory": "test"})
        sig = scheme.sign(payload)
        combined_pk = ed_pk + ml_pk
        assert scheme.verify(payload, sig, combined_pk)

    def test_create_hybrid_wrong_type_raises(self):
        with pytest.raises(TypeError, match="tuple"):
            create_scheme("hybrid", b"not_a_tuple")

    def test_create_hybrid_bad_tuple_raises(self):
        with pytest.raises(TypeError, match="Ed25519PrivateKey"):
            create_scheme("hybrid", (b"not_ed25519", b"not_mldsa65"))


class TestHybridKeygen:
    """Test hybrid keypair generation."""

    def test_generate_hybrid(self, tmp_path):
        from AEGIS_LEDGER.crypto import generate_hybrid_keypair

        key_base = tmp_path / "agent"
        ed_key, ml_sk, pub_hex = generate_hybrid_keypair(key_base)
        assert len(pub_hex) == 3968  # 64 + 3904

    def test_generate_hybrid_files(self, tmp_path):
        from AEGIS_LEDGER.crypto import generate_hybrid_keypair

        key_base = tmp_path / "agent"
        generate_hybrid_keypair(key_base)
        assert (key_base.with_suffix(".pem")).exists()
        assert (key_base.with_suffix(".mldsa65")).exists()
        assert (key_base.with_suffix(".hybrid.pub")).exists()

    def test_generate_hybrid_pub_content(self, tmp_path):
        from AEGIS_LEDGER.crypto import generate_hybrid_keypair

        key_base = tmp_path / "agent"
        _, _, pub_hex = generate_hybrid_keypair(key_base)
        pub_content = key_base.with_suffix(".hybrid.pub").read_text().strip()
        assert pub_content == pub_hex

    def test_generate_hybrid_sign_verify(self, tmp_path):
        from AEGIS_LEDGER.crypto import generate_hybrid_keypair

        key_base = tmp_path / "agent"
        ed_key, ml_sk, pub_hex = generate_hybrid_keypair(key_base)
        scheme = HybridScheme(ed_key, ml_sk)
        payload = canonical_json({"keygen": "hybrid_test"})
        sig = scheme.sign(payload)
        pk_bytes = bytes.fromhex(pub_hex)
        assert scheme.verify(payload, sig, pk_bytes)

    def test_generate_hybrid_exists_raises(self, tmp_path):
        """Second generate on same base path must raise FileExistsError."""
        from AEGIS_LEDGER.crypto import generate_hybrid_keypair

        key_base = tmp_path / "agent"
        generate_hybrid_keypair(key_base)
        with pytest.raises(FileExistsError):
            generate_hybrid_keypair(key_base)

    def test_generate_hybrid_no_stray_pub_files(self, tmp_path):
        """Only .hybrid.pub should exist, no stray .pem.pub or .mldsa65.pub."""
        from AEGIS_LEDGER.crypto import generate_hybrid_keypair

        key_base = tmp_path / "agent"
        generate_hybrid_keypair(key_base)
        stray_pem_pub = key_base.with_suffix(".pub")
        assert not stray_pem_pub.exists(), f"Stray file found: {stray_pem_pub}"
        # Only these files should exist
        expected = {
            key_base.with_suffix(".pem"),
            key_base.with_suffix(".mldsa65"),
            key_base.with_suffix(".hybrid.pub"),
        }
        actual = set(tmp_path.iterdir())
        assert actual == expected


class TestCreateSchemeEdgeCases:
    """Edge cases for create_scheme factory."""

    def test_create_hybrid_wrong_tuple_length_raises(self):
        """Tuple with 3 elements must raise TypeError."""
        ed_key = Ed25519PrivateKey.generate()
        with pytest.raises(TypeError, match="tuple"):
            create_scheme("hybrid", (ed_key, b"a", b"b"))  # type: ignore[arg-type]

    def test_create_hybrid_wrong_sk_type_in_tuple_raises(self):
        """Tuple with non-bytes ML-DSA-65 SK must raise TypeError."""
        ed_key = Ed25519PrivateKey.generate()
        with pytest.raises(TypeError, match="raw ML-DSA-65"):
            create_scheme("hybrid", (ed_key, 12345))  # type: ignore[arg-type]
