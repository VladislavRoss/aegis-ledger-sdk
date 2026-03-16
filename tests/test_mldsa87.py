"""Tests for MLDSA87Scheme — ML-DSA-87 (FIPS 204, CNSA 2.0 Level 5)."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from AEGIS_LEDGER.crypto import (
    Ed25519Scheme,
    MLDSA65Scheme,
    MLDSA87Scheme,
    SignatureScheme,
    canonical_json,
    create_scheme,
)


def _mldsa87_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-DSA-87 keypair via pqcrypto."""
    from pqcrypto.sign.ml_dsa_87 import generate_keypair  # type: ignore[import-untyped]
    return generate_keypair()  # (pk, sk)


def _mldsa65_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-DSA-65 keypair via pqcrypto."""
    from pqcrypto.sign.ml_dsa_65 import generate_keypair  # type: ignore[import-untyped]
    return generate_keypair()  # (pk, sk)


# ── ML-DSA-87 Protocol Tests ──────────────────────────────────────────


class TestMLDSA87SchemeProtocol:
    """Verify MLDSA87Scheme satisfies the SignatureScheme protocol."""

    def test_is_signature_scheme(self):
        _, sk = _mldsa87_keypair()
        scheme = MLDSA87Scheme(sk)
        assert isinstance(scheme, SignatureScheme)

    def test_algorithm_id(self):
        _, sk = _mldsa87_keypair()
        scheme = MLDSA87Scheme(sk)
        assert scheme.algorithm_id == "ml-dsa-87"

    def test_public_key_size(self):
        _, sk = _mldsa87_keypair()
        scheme = MLDSA87Scheme(sk)
        assert scheme.public_key_size == 2592

    def test_signature_size(self):
        _, sk = _mldsa87_keypair()
        scheme = MLDSA87Scheme(sk)
        assert scheme.signature_size == 4627


class TestMLDSA87Scheme:
    """Test MLDSA87Scheme sign/verify operations."""

    @pytest.fixture()
    def keypair(self):
        pk, sk = _mldsa87_keypair()
        return MLDSA87Scheme(sk), pk, sk

    def test_sign_returns_prefixed(self, keypair):
        scheme, _, _ = keypair
        payload = canonical_json({"action": "mldsa87_test"})
        sig = scheme.sign(payload)
        assert sig.startswith("ml-dsa-87:")
        hex_part = sig[len("ml-dsa-87:"):]
        assert len(hex_part) == 4627 * 2
        bytes.fromhex(hex_part)

    def test_sign_verify_roundtrip(self, keypair):
        scheme, pk, _ = keypair
        payload = canonical_json({"action": "mldsa87_test", "seq": 0})
        sig = scheme.sign(payload)
        assert scheme.verify(payload, sig, pk)

    def test_verify_wrong_payload(self, keypair):
        scheme, pk, _ = keypair
        payload = canonical_json({"action": "mldsa87_test"})
        sig = scheme.sign(payload)
        wrong = canonical_json({"action": "tampered"})
        assert not scheme.verify(wrong, sig, pk)

    def test_verify_wrong_key(self, keypair):
        scheme, _, _ = keypair
        payload = canonical_json({"action": "mldsa87_test"})
        sig = scheme.sign(payload)
        other_pk, _ = _mldsa87_keypair()
        assert not scheme.verify(payload, sig, other_pk)

    def test_verify_bad_prefix(self, keypair):
        scheme, pk, _ = keypair
        assert not scheme.verify(b"data", "ed25519:abcdef", pk)

    def test_verify_bad_hex(self, keypair):
        scheme, pk, _ = keypair
        assert not scheme.verify(b"data", "ml-dsa-87:not_hex!", pk)

    def test_bad_sk_size_rejected(self):
        with pytest.raises(ValueError, match="4896 bytes"):
            MLDSA87Scheme(b"too_short")

    def test_cross_algorithm_reject_ed25519(self, keypair):
        """Ed25519 signature must fail under ML-DSA-87 verifier."""
        mldsa87_scheme, pk, _ = keypair
        ed_key = Ed25519PrivateKey.generate()
        ed_scheme = Ed25519Scheme(ed_key)
        payload = canonical_json({"cross": "test"})
        ed_sig = ed_scheme.sign(payload)
        assert not mldsa87_scheme.verify(payload, ed_sig, pk)

    def test_cross_algorithm_reject_mldsa65(self, keypair):
        """ML-DSA-65 signature must fail under ML-DSA-87 verifier."""
        mldsa87_scheme, pk, _ = keypair
        _, ml65_sk = _mldsa65_keypair()
        ml65_scheme = MLDSA65Scheme(ml65_sk)
        payload = canonical_json({"cross": "mldsa65"})
        ml65_sig = ml65_scheme.sign(payload)
        assert not mldsa87_scheme.verify(payload, ml65_sig, pk)


class TestMLDSA87Keygen:
    """Test ML-DSA-87 keypair generation and loading."""

    def test_generate_and_load(self, tmp_path):
        from AEGIS_LEDGER.crypto import (
            generate_mldsa87_keypair,
            load_mldsa87_private_key,
        )

        key_file = tmp_path / "test.mldsa87"
        sk, pub_hex = generate_mldsa87_keypair(key_file)
        assert len(sk) == 4896
        assert len(pub_hex) == 2592 * 2

        loaded_sk = load_mldsa87_private_key(key_file)
        assert loaded_sk == sk

    def test_generate_writes_pub_file(self, tmp_path):
        from AEGIS_LEDGER.crypto import generate_mldsa87_keypair

        key_file = tmp_path / "test.mldsa87"
        _, pub_hex = generate_mldsa87_keypair(key_file)
        pub_file = key_file.with_suffix(".pub")
        assert pub_file.exists()
        assert pub_file.read_text().strip() == pub_hex

    def test_generate_existing_raises(self, tmp_path):
        from AEGIS_LEDGER.crypto import generate_mldsa87_keypair

        key_file = tmp_path / "test.mldsa87"
        generate_mldsa87_keypair(key_file)
        with pytest.raises(FileExistsError):
            generate_mldsa87_keypair(key_file)

    def test_load_missing_raises(self, tmp_path):
        from AEGIS_LEDGER.crypto import load_mldsa87_private_key

        with pytest.raises(FileNotFoundError):
            load_mldsa87_private_key(tmp_path / "nonexistent.mldsa87")

    def test_load_wrong_size_raises(self, tmp_path):
        from AEGIS_LEDGER.crypto import load_mldsa87_private_key

        bad_file = tmp_path / "bad.mldsa87"
        bad_file.write_bytes(b"wrong_size_data")
        with pytest.raises(ValueError, match="4896 bytes"):
            load_mldsa87_private_key(bad_file)

    def test_generated_key_signs_and_verifies(self, tmp_path):
        from AEGIS_LEDGER.crypto import generate_mldsa87_keypair

        key_file = tmp_path / "test.mldsa87"
        sk, pub_hex = generate_mldsa87_keypair(key_file)

        scheme = MLDSA87Scheme(sk)
        payload = canonical_json({"keygen": "mldsa87_test"})
        sig = scheme.sign(payload)

        pk_bytes = bytes.fromhex(pub_hex)
        assert scheme.verify(payload, sig, pk_bytes)


class TestCreateSchemeMLDSA87:
    """Test create_scheme factory for ML-DSA-87."""

    def test_create_mldsa87(self):
        _, sk = _mldsa87_keypair()
        scheme = create_scheme("ml-dsa-87", sk)
        assert scheme.algorithm_id == "ml-dsa-87"
        assert isinstance(scheme, MLDSA87Scheme)

    def test_create_mldsa87_signs_and_verifies(self):
        pk, sk = _mldsa87_keypair()
        scheme = create_scheme("ml-dsa-87", sk)
        payload = canonical_json({"test": True})
        sig = scheme.sign(payload)
        assert sig.startswith("ml-dsa-87:")
        assert scheme.verify(payload, sig, pk)
