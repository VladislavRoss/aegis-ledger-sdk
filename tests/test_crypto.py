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


class TestSignableDictNoToxicData:
    """Verify that to_signable_dict() contains NO raw data fields (Phase 1 Toxic Data fix)."""

    def _make_entry(self):
        from AEGIS_LEDGER.types import (
            ActionContext,
            ActionPayload,
            ActionStatus,
            ActionType,
            Environment,
            LogEntry,
        )

        return LogEntry(
            agent_id="test-agent",
            session_id="test-session",
            sequence_number=0,
            action=ActionPayload(
                type=ActionType.TOOL_CALL,
                tool="search",
                input_hash="sha256:abc123",
                output_hash="sha256:def456",
                input_preview='{"user_query":"My SSN is 123-45-6789"}',
                output_preview='{"result":"sensitive data"}',
                duration_ms=100,
                status=ActionStatus.SUCCESS,
            ),
            context=ActionContext(
                parent_action_id="",
                decision_reasoning="User john@example.com requested a refund",
                confidence_score=0.95,
            ),
            environment=Environment(framework="langchain"),
            client_timestamp_ms=1234567890,
            sdk_version="0.3.0",
            api_key_id="ak_test",
        )

    def test_no_input_preview_in_signable_dict(self):
        entry = self._make_entry()
        signable = entry.to_signable_dict()
        assert "input_preview" not in signable["action"]

    def test_no_output_preview_in_signable_dict(self):
        entry = self._make_entry()
        signable = entry.to_signable_dict()
        assert "output_preview" not in signable["action"]

    def test_no_decision_reasoning_in_signable_dict(self):
        entry = self._make_entry()
        signable = entry.to_signable_dict()
        assert "decision_reasoning" not in signable["context"]

    def test_hashes_still_present(self):
        entry = self._make_entry()
        signable = entry.to_signable_dict()
        assert signable["action"]["input_hash"] == "sha256:abc123"
        assert signable["action"]["output_hash"] == "sha256:def456"

    def test_canonical_json_has_no_pii(self):
        entry = self._make_entry()
        signable = entry.to_signable_dict()
        payload = canonical_json(signable)
        payload_str = payload.decode("utf-8")
        assert "SSN" not in payload_str
        assert "123-45-6789" not in payload_str
        assert "john@example.com" not in payload_str
        assert "sensitive data" not in payload_str


# ---------------------------------------------------------------------------
# Edge-case tests (Phase 21 — security hardening)
# ---------------------------------------------------------------------------


class TestChainHashSecurity:
    def test_reordering_attack_detected(self):
        """Swapping two entries produces different chain hashes (reordering attack)."""
        p1 = canonical_json({"seq": 0, "tool": "search"})
        p2 = canonical_json({"seq": 1, "tool": "refund"})

        # Forward order: "" → h1, h1 → h2
        h1_fwd = compute_chain_hash("", p1)
        h2_fwd = compute_chain_hash(h1_fwd, p2)

        # Reversed order: "" → h1r, h1r → h2r
        h1_rev = compute_chain_hash("", p2)
        h2_rev = compute_chain_hash(h1_rev, p1)

        # Final hashes MUST differ (reordering must be detectable)
        assert h2_fwd != h2_rev

    def test_empty_payload_sign_verify(self):
        """Empty payload can be signed and verified."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        payload = canonical_json({})
        signature = sign_payload(payload, private_key)
        assert verify_signature(payload, signature, public_key)

    def test_signature_length_128_hex(self):
        """Ed25519 signature is exactly 64 bytes = 128 hex chars."""
        private_key = Ed25519PrivateKey.generate()
        payload = canonical_json({"test": "data"})
        signature = sign_payload(payload, private_key)
        # Format: "ed25519:<128 hex chars>"
        hex_part = signature.split(":")[1]
        assert len(hex_part) == 128

    def test_unicode_normalization(self):
        """Composed and decomposed Unicode produce the same canonical JSON hash."""
        # NFC: é as single codepoint (U+00E9)
        composed = canonical_json({"name": "\u00e9"})
        # NFD: e + combining acute accent (U+0065 U+0301)
        decomposed = canonical_json({"name": "e\u0301"})

        hash_composed = sha256_hex(composed)
        hash_decomposed = sha256_hex(decomposed)

        # canonical_json uses json.dumps which preserves Unicode as-is,
        # so these SHOULD differ (canonical JSON does NOT normalize Unicode).
        # This test documents the behavior — callers must normalize before hashing.
        assert hash_composed != hash_decomposed


# ---------------------------------------------------------------------------
# Core function gap tests (Phase 21)
# ---------------------------------------------------------------------------


class TestGetPublicKeyHex:
    def test_hex_format_64_chars(self):
        """Ed25519 public key is 32 bytes = 64 hex chars."""
        from AEGIS_LEDGER.crypto import get_public_key_hex

        private_key = Ed25519PrivateKey.generate()
        hex_key = get_public_key_hex(private_key)
        assert len(hex_key) == 64
        # Must be valid hex
        int(hex_key, 16)

    def test_deterministic(self):
        """Same private key always produces the same public key hex."""
        from AEGIS_LEDGER.crypto import get_public_key_hex

        private_key = Ed25519PrivateKey.generate()
        assert get_public_key_hex(private_key) == get_public_key_hex(private_key)


class TestLoadPrivateKey:
    def test_file_not_found(self, tmp_path):
        """FileNotFoundError with helpful message when key file missing."""
        from AEGIS_LEDGER.crypto import load_private_key

        with pytest.raises(FileNotFoundError, match="Private key not found"):
            load_private_key(tmp_path / "nonexistent.pem")

    def test_invalid_pem_raises(self, tmp_path):
        """ValueError or similar for non-PEM content."""
        from AEGIS_LEDGER.crypto import load_private_key

        bad_pem = tmp_path / "bad.pem"
        bad_pem.write_text("this is not a PEM file")
        with pytest.raises(Exception):
            load_private_key(bad_pem)

    def test_valid_pem_loads(self, tmp_path):
        """Valid Ed25519 PEM loads successfully."""
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

        from AEGIS_LEDGER.crypto import load_private_key

        key = Ed25519PrivateKey.generate()
        pem_path = tmp_path / "valid.pem"
        pem_path.write_bytes(
            key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        )
        loaded = load_private_key(pem_path)
        assert isinstance(loaded, Ed25519PrivateKey)
