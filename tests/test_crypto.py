"""Tests for aegis.crypto — canonical JSON, hashing, signing, chain hash."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Import from the package path used by the project
from AEGIS_LEDGER.crypto import (
    canonical_json,
    compute_chain_hash,
    sha256_hex,
    sha256_json,
    sign_payload,
    truncate_preview,
    verify_signature,
)


class TestCanonicalJson:
    def test_sorted_keys(self):
        result = canonical_json({"z": 1, "a": 2, "m": 3})
        assert result == b'{"a":2,"m":3,"z":1}'

    def test_nested_objects_sorted(self):
        result = canonical_json({"b": {"z": 1, "a": 2}, "a": 1})
        assert result == b'{"a":1,"b":{"a":2,"z":1}}'

    def test_no_whitespace(self):
        result = canonical_json({"key": "value", "num": 42})
        assert b" " not in result
        assert b"\n" not in result

    def test_utf8_encoding(self):
        result = canonical_json({"name": "Zürich"})
        assert "Zürich".encode("utf-8") in result

    def test_empty_dict(self):
        assert canonical_json({}) == b"{}"

    def test_arrays_preserved(self):
        result = canonical_json({"items": [3, 1, 2]})
        assert result == b'{"items":[3,1,2]}'


class TestSha256:
    def test_hex_bytes(self):
        result = sha256_hex(b"hello")
        assert len(result) == 64
        assert result == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_hex_string(self):
        assert sha256_hex("hello") == sha256_hex(b"hello")

    def test_json_prefix(self):
        result = sha256_json({"key": "value"})
        assert result.startswith("sha256:")
        assert len(result) == 7 + 64  # "sha256:" + 64 hex chars


class TestEd25519SignVerify:
    @pytest.fixture
    def keypair(self):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    def test_sign_verify_roundtrip(self, keypair):
        private_key, public_key = keypair
        payload = canonical_json({"action": "test", "tool": "search"})
        signature = sign_payload(payload, private_key)
        assert signature.startswith("ed25519:")
        assert verify_signature(payload, signature, public_key)

    def test_verify_wrong_payload(self, keypair):
        private_key, public_key = keypair
        payload = canonical_json({"action": "test"})
        signature = sign_payload(payload, private_key)
        wrong_payload = canonical_json({"action": "tampered"})
        assert not verify_signature(wrong_payload, signature, public_key)

    def test_verify_invalid_prefix(self, keypair):
        _, public_key = keypair
        assert not verify_signature(b"data", "rsa:abc123", public_key)

    def test_verify_invalid_hex(self, keypair):
        _, public_key = keypair
        assert not verify_signature(b"data", "ed25519:not_hex!", public_key)


class TestChainHash:
    def test_first_entry_empty_previous(self):
        payload = canonical_json({"seq": 0})
        result = compute_chain_hash("", payload)
        assert len(result) == 64

    def test_chain_continuity(self):
        p1 = canonical_json({"seq": 0})
        h1 = compute_chain_hash("", p1)
        p2 = canonical_json({"seq": 1})
        h2 = compute_chain_hash(h1, p2)
        assert h1 != h2
        assert len(h2) == 64

    def test_deterministic(self):
        payload = canonical_json({"test": "data"})
        h1 = compute_chain_hash("abc", payload)
        h2 = compute_chain_hash("abc", payload)
        assert h1 == h2

    def test_different_previous_different_hash(self):
        payload = canonical_json({"test": "data"})
        h1 = compute_chain_hash("aaa", payload)
        h2 = compute_chain_hash("bbb", payload)
        assert h1 != h2


class TestTruncatePreview:
    def test_redacts_sensitive_keys(self):
        obj = {"api_key": "sk-secret123", "data": "safe"}
        result = truncate_preview(obj)
        assert "sk-secret123" not in result
        assert "***" in result
        assert "safe" in result

    def test_redacts_bearer_tokens(self):
        obj = {"header": "Bearer eyJabc123"}
        result = truncate_preview(obj)
        assert "Bearer" not in result
        assert "***" in result

    def test_truncates_long_output(self):
        obj = {"data": "x" * 500}
        result = truncate_preview(obj, max_length=50)
        assert len(result) <= 50
        assert result.endswith("...")

    def test_none_returns_empty(self):
        assert truncate_preview(None) == ""
