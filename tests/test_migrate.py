"""Tests for aegis.migrate — re-sign entries with new algorithms."""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from AEGIS_LEDGER.crypto import (
    Ed25519Scheme,
    HybridScheme,
    MLDSA65Scheme,
    MLDSA87Scheme,
    SLHDSA128sScheme,
    canonical_json,
    generate_keypair,
    generate_mldsa65_keypair,
    generate_mldsa87_keypair,
    generate_slhdsa128s_keypair,
)
from AEGIS_LEDGER.migrate import (
    _detect_source_algorithm,
    migrate_local,
    re_sign_payload_hex,
)

# ── Helpers ──────────────────────────────────────────────────────────────


def _mldsa65_keypair() -> tuple[bytes, bytes]:
    from pqcrypto.sign.ml_dsa_65 import generate_keypair as _keygen  # type: ignore[import-untyped]

    return _keygen()


def _mldsa87_keypair() -> tuple[bytes, bytes]:
    from pqcrypto.sign.ml_dsa_87 import generate_keypair as _keygen  # type: ignore[import-untyped]

    return _keygen()


def _slhdsa128s_keypair() -> tuple[bytes, bytes]:
    from pqcrypto.sign.sphincs_shake_128s_simple import (  # type: ignore[import-untyped]
        generate_keypair as _keygen,
    )

    return _keygen()


# ── re_sign_payload_hex Tests ────────────────────────────────────────────


class TestReSignPayloadHex:
    """Test single-entry re-signing."""

    def test_ed25519_to_mldsa65(self):
        ed_key = Ed25519PrivateKey.generate()
        ed_scheme = Ed25519Scheme(ed_key)
        payload = canonical_json({"action": "test"})
        original_sig = ed_scheme.sign(payload)

        ml_pk, ml_sk = _mldsa65_keypair()
        ml_scheme = MLDSA65Scheme(ml_sk)

        result = re_sign_payload_hex(payload.hex(), original_sig, ml_scheme)
        assert result["original_signature"] == original_sig
        assert result["new_signature"].startswith("ml-dsa-65:")
        assert result["algorithm"] == "ml-dsa-65"
        assert ml_scheme.verify(payload, result["new_signature"], ml_pk)

    def test_ed25519_to_slhdsa128s(self):
        ed_key = Ed25519PrivateKey.generate()
        ed_scheme = Ed25519Scheme(ed_key)
        payload = canonical_json({"action": "test_slh"})
        original_sig = ed_scheme.sign(payload)

        slh_pk, slh_sk = _slhdsa128s_keypair()
        slh_scheme = SLHDSA128sScheme(slh_sk)

        result = re_sign_payload_hex(payload.hex(), original_sig, slh_scheme)
        assert result["new_signature"].startswith("slh-dsa-128s:")
        assert slh_scheme.verify(payload, result["new_signature"], slh_pk)

    def test_ed25519_to_mldsa87(self):
        ed_key = Ed25519PrivateKey.generate()
        ed_scheme = Ed25519Scheme(ed_key)
        payload = canonical_json({"action": "test_mldsa87"})
        original_sig = ed_scheme.sign(payload)

        ml87_pk, ml87_sk = _mldsa87_keypair()
        ml87_scheme = MLDSA87Scheme(ml87_sk)

        result = re_sign_payload_hex(payload.hex(), original_sig, ml87_scheme)
        assert result["original_signature"] == original_sig
        assert result["new_signature"].startswith("ml-dsa-87:")
        assert result["algorithm"] == "ml-dsa-87"
        assert ml87_scheme.verify(payload, result["new_signature"], ml87_pk)

    def test_ed25519_to_hybrid(self):
        ed_key = Ed25519PrivateKey.generate()
        ed_scheme = Ed25519Scheme(ed_key)
        payload = canonical_json({"action": "hybrid_test"})
        original_sig = ed_scheme.sign(payload)

        ml_pk, ml_sk = _mldsa65_keypair()
        hybrid_scheme = HybridScheme(ed_key, ml_sk)
        ed_pk = ed_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        result = re_sign_payload_hex(payload.hex(), original_sig, hybrid_scheme)
        assert result["new_signature"].startswith("hybrid:")
        combined_pk = ed_pk + ml_pk
        assert hybrid_scheme.verify(payload, result["new_signature"], combined_pk)


# ── _detect_source_algorithm Tests ───────────────────────────────────────


class TestDetectSourceAlgorithm:
    def test_ed25519(self):
        assert _detect_source_algorithm("ed25519:aabbcc") == "ed25519"

    def test_mldsa65(self):
        assert _detect_source_algorithm("ml-dsa-65:aabbcc") == "ml-dsa-65"

    def test_mldsa87(self):
        assert _detect_source_algorithm("ml-dsa-87:aabbcc") == "ml-dsa-87"

    def test_slhdsa128s(self):
        assert _detect_source_algorithm("slh-dsa-128s:aabbcc") == "slh-dsa-128s"

    def test_hybrid(self):
        assert _detect_source_algorithm("hybrid:aabbcc") == "hybrid"

    def test_unknown(self):
        assert _detect_source_algorithm("rsa:aabbcc") == "unknown"


# ── migrate_local Tests ──────────────────────────────────────────────────


class TestMigrateLocal:
    """Test local (offline) migration from exported entries."""

    def test_migrate_ed25519_to_mldsa65(self, tmp_path):
        ed_key = Ed25519PrivateKey.generate()
        ed_scheme = Ed25519Scheme(ed_key)

        entries = []
        for i in range(3):
            payload = canonical_json({"seq": i, "action": "test"})
            sig = ed_scheme.sign(payload)
            entries.append({
                "actionId": f"act_{i}",
                "payloadHex": payload.hex(),
                "payloadSignature": sig,
            })

        entries_file = tmp_path / "entries.json"
        entries_file.write_text(json.dumps(entries), encoding="utf-8")

        ml_key_file = tmp_path / "test.mldsa65"
        generate_mldsa65_keypair(ml_key_file)

        output_file = tmp_path / "migration.json"
        report = migrate_local(
            entries_json=str(entries_file),
            target_algorithm="ml-dsa-65",
            signing_key_path=str(ml_key_file),
            output_path=str(output_file),
        )

        assert report["total_entries"] == 3
        assert report["source_algorithm"] == "ed25519"
        assert report["target_algorithm"] == "ml-dsa-65"
        assert output_file.exists()

        saved = json.loads(output_file.read_text(encoding="utf-8"))
        assert len(saved["entries"]) == 3
        for entry in saved["entries"]:
            assert entry["new_signature"].startswith("ml-dsa-65:")

    def test_migrate_ed25519_to_slhdsa128s(self, tmp_path):
        ed_key = Ed25519PrivateKey.generate()
        ed_scheme = Ed25519Scheme(ed_key)

        payload = canonical_json({"action": "slh_migrate"})
        sig = ed_scheme.sign(payload)
        entries = [{"actionId": "act_0", "payloadHex": payload.hex(), "payloadSignature": sig}]

        entries_file = tmp_path / "entries.json"
        entries_file.write_text(json.dumps(entries), encoding="utf-8")

        slh_key_file = tmp_path / "test.slh"
        generate_slhdsa128s_keypair(slh_key_file)

        output_file = tmp_path / "migration_slh.json"
        report = migrate_local(
            entries_json=str(entries_file),
            target_algorithm="slh-dsa-128s",
            signing_key_path=str(slh_key_file),
            output_path=str(output_file),
        )

        assert report["total_entries"] == 1
        assert report["target_algorithm"] == "slh-dsa-128s"

    def test_migrate_ed25519_to_mldsa87(self, tmp_path):
        ed_key = Ed25519PrivateKey.generate()
        ed_scheme = Ed25519Scheme(ed_key)

        entries = []
        for i in range(3):
            payload = canonical_json({"seq": i, "action": "test_ml87"})
            sig = ed_scheme.sign(payload)
            entries.append({
                "actionId": f"act_{i}",
                "payloadHex": payload.hex(),
                "payloadSignature": sig,
            })

        entries_file = tmp_path / "entries.json"
        entries_file.write_text(json.dumps(entries), encoding="utf-8")

        ml87_key_file = tmp_path / "test.mldsa87"
        generate_mldsa87_keypair(ml87_key_file)

        output_file = tmp_path / "migration_ml87.json"
        report = migrate_local(
            entries_json=str(entries_file),
            target_algorithm="ml-dsa-87",
            signing_key_path=str(ml87_key_file),
            output_path=str(output_file),
        )

        assert report["total_entries"] == 3
        assert report["source_algorithm"] == "ed25519"
        assert report["target_algorithm"] == "ml-dsa-87"
        assert output_file.exists()

        saved = json.loads(output_file.read_text(encoding="utf-8"))
        assert len(saved["entries"]) == 3
        for entry in saved["entries"]:
            assert entry["new_signature"].startswith("ml-dsa-87:")

    def test_migrate_to_hybrid(self, tmp_path):
        ed_key = Ed25519PrivateKey.generate()
        ed_scheme = Ed25519Scheme(ed_key)

        payload = canonical_json({"action": "hybrid_migrate"})
        sig = ed_scheme.sign(payload)
        entries = [{"actionId": "act_0", "payloadHex": payload.hex(), "payloadSignature": sig}]

        entries_file = tmp_path / "entries.json"
        entries_file.write_text(json.dumps(entries), encoding="utf-8")

        pem_file = tmp_path / "key.pem"
        generate_keypair(pem_file)

        ml_key_file = tmp_path / "key.mldsa65"
        generate_mldsa65_keypair(ml_key_file)

        output_file = tmp_path / "migration_hybrid.json"
        report = migrate_local(
            entries_json=str(entries_file),
            target_algorithm="hybrid",
            pem_path=str(pem_file),
            signing_key_path=str(ml_key_file),
            output_path=str(output_file),
        )

        assert report["total_entries"] == 1
        assert report["target_algorithm"] == "hybrid"
        saved = json.loads(output_file.read_text(encoding="utf-8"))
        assert saved["entries"][0]["new_signature"].startswith("hybrid:")

    def test_migrate_dict_format(self, tmp_path):
        """Entries wrapped in {"entries": [...]} should work."""
        payload = canonical_json({"x": 1})
        entries_file = tmp_path / "wrapped.json"
        entries_file.write_text(
            json.dumps({"entries": [
                {"payloadHex": payload.hex(), "payloadSignature": "ed25519:aa" * 64},
            ]}),
            encoding="utf-8",
        )

        slh_key = tmp_path / "key.slh"
        generate_slhdsa128s_keypair(slh_key)

        report = migrate_local(
            entries_json=str(entries_file),
            target_algorithm="slh-dsa-128s",
            signing_key_path=str(slh_key),
            output_path=str(tmp_path / "out.json"),
        )
        assert report["total_entries"] == 1

    def test_missing_signing_key_raises(self, tmp_path):
        entries_file = tmp_path / "e.json"
        entries_file.write_text("[]", encoding="utf-8")
        with pytest.raises(ValueError, match="--signing-key"):
            migrate_local(
                entries_json=str(entries_file),
                target_algorithm="ml-dsa-65",
                output_path=str(tmp_path / "out.json"),
            )

    def test_unknown_algorithm_raises(self, tmp_path):
        entries_file = tmp_path / "e.json"
        entries_file.write_text("[]", encoding="utf-8")
        with pytest.raises(ValueError, match="Unknown"):
            migrate_local(
                entries_json=str(entries_file),
                target_algorithm="rsa-4096",
                output_path=str(tmp_path / "out.json"),
            )
