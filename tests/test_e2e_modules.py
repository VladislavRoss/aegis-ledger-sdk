"""
End-to-End Module Tests — CLI, Keygen, LogEntry, Crypto Helpers, Batch, Transport.

Aufruf:
    cd /c/ARBEIT/AegisProtocol
    python -m pytest AEGIS_LEDGER/tests/test_e2e_modules.py -v
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from aegis.crypto import (
    canonical_json,
    sha256_json,
)
from aegis.transport import CanisterTransport, TransportConfig
from aegis.types import ActionType, Environment
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

# ============================================================================
# Fixtures (shared with test_e2e_workflows.py)
# ============================================================================

@pytest.fixture
def tmp_pem(tmp_path):
    """Create a temporary Ed25519 PEM key file."""
    key = Ed25519PrivateKey.generate()
    pem_path = tmp_path / "test_key.pem"
    pem_path.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    return str(pem_path)


@pytest.fixture
def tmp_pem_2(tmp_path):
    """Create a second Ed25519 PEM key file for key rotation."""
    key = Ed25519PrivateKey.generate()
    pem_path = tmp_path / "test_key_2.pem"
    pem_path.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    return str(pem_path)


def _make_mock_transport():
    """Create a mock transport that records all calls."""
    transport = MagicMock()
    transport.call_update.return_value = {"actionId": "act_e2e_001"}
    transport.spill_count = 0
    transport.drain_spill_buffer.return_value = 0
    return transport


def _make_client(
    pem_path, transport=None, session_id="e2e-session",
    org_id="un4fu-tqaaa-aaaab-qadjq-cai",
    fail_open=True, api_key_id="ak_e2e",
):


    """Create AegisClient with mocked/real transport."""
    with (
        patch("aegis.client.CanisterTransport") as MockTransport,
        patch("aegis.client.load_config", return_value={}),
    ):
        mock_transport = transport or _make_mock_transport()
        MockTransport.return_value = mock_transport

        from aegis.client import AegisClient

        client = AegisClient(
            canister_id="toqqq-lqaaa-aaaae-afc2a-cai",
            api_key_id=api_key_id,
            private_key_path=pem_path,
            agent_id="e2e-test-agent",
            org_id=org_id,
            session_id=session_id,
            fail_open=fail_open,
            environment=Environment(framework="e2e-test"),
        )
        return client, mock_transport


# ============================================================================
# CLI Commands E2E
# ============================================================================

class TestCLICommandsE2E:
    """E2E: CLI Commands — keygen (alle 5 Algos), verify, status, report, migrate."""

    def test_cli_keygen_ed25519(self, tmp_path):
        """CLI E2E: aegis keygen erzeugt Ed25519 PEM + .pub Datei."""
        import sys

        from aegis.cli import main

        key_path = str(tmp_path / "test_ed25519.pem")
        with patch.object(sys, "argv", ["aegis", "keygen", key_path]):
            main()

        assert Path(key_path).exists()
        # .with_suffix(".pub") replaces .pem → .pub
        pub_path = Path(key_path).with_suffix(".pub")
        assert pub_path.exists()
        pub_hex = pub_path.read_text().strip()
        assert len(pub_hex) == 64

    def test_cli_keygen_mldsa65(self, tmp_path):
        """CLI E2E: aegis keygen --algorithm ml-dsa-65 erzeugt ML-DSA-65 Keypair."""
        try:
            import pqcrypto.sign.ml_dsa_65  # noqa: F401
        except ImportError:
            pytest.skip("pqcrypto not installed")

        import sys

        from aegis.cli import main

        key_path = str(tmp_path / "test_mldsa.bin")
        with patch.object(sys, "argv", ["aegis", "keygen", key_path, "--algorithm", "ml-dsa-65"]):
            main()

        assert Path(key_path).exists()
        # Algo-specific pub: <name>.bin.pub (not <name>.pub)
        pub_path = Path(key_path).parent / (Path(key_path).name + ".pub")
        assert pub_path.exists()
        pub_hex = pub_path.read_text().strip()
        assert len(pub_hex) == 3904  # 1952 bytes * 2

    def test_cli_keygen_mldsa87(self, tmp_path):
        """CLI E2E: aegis keygen --algorithm ml-dsa-87 erzeugt ML-DSA-87 Keypair."""
        try:
            import pqcrypto.sign.ml_dsa_87  # noqa: F401
        except ImportError:
            pytest.skip("pqcrypto not installed")

        import sys

        from aegis.cli import main

        key_path = str(tmp_path / "test_mldsa87.bin")
        argv = ["aegis", "keygen", key_path, "--algorithm", "ml-dsa-87"]
        with patch.object(sys, "argv", argv):
            main()

        assert Path(key_path).exists()
        pub_path = Path(key_path).parent / (Path(key_path).name + ".pub")
        assert pub_path.exists()
        pub_hex = pub_path.read_text().strip()
        assert len(pub_hex) == 5184  # 2592 bytes * 2

    def test_cli_keygen_slhdsa128s(self, tmp_path):
        """CLI E2E: aegis keygen --algorithm slh-dsa-128s erzeugt SLH-DSA Keypair."""
        try:
            import pqcrypto.sign.sphincs_shake_128s_simple  # noqa: F401
        except ImportError:
            pytest.skip("pqcrypto not installed")

        import sys

        from aegis.cli import main

        key_path = str(tmp_path / "test_slh.bin")
        argv = ["aegis", "keygen", key_path, "--algorithm", "slh-dsa-128s"]
        with patch.object(sys, "argv", argv):
            main()

        assert Path(key_path).exists()
        pub_path = Path(key_path).parent / (Path(key_path).name + ".pub")
        assert pub_path.exists()

    def test_cli_keygen_hybrid(self, tmp_path):
        """CLI E2E: aegis keygen --algorithm hybrid erzeugt Hybrid Keypair (3 Dateien)."""
        try:
            import pqcrypto.sign.ml_dsa_65  # noqa: F401
        except ImportError:
            pytest.skip("pqcrypto not installed")

        import sys

        from aegis.cli import main

        key_path = str(tmp_path / "test_hybrid")
        with patch.object(sys, "argv", ["aegis", "keygen", key_path, "--algorithm", "hybrid"]):
            main()

        assert Path(key_path + ".pem").exists()
        assert Path(key_path + ".mldsa65").exists()
        assert Path(key_path + ".hybrid.pub").exists()
        pub_hex = Path(key_path + ".hybrid.pub").read_text().strip()
        assert len(pub_hex) == 3968  # 64 (Ed25519) + 3904 (ML-DSA-65)

    def test_cli_keygen_duplicate_rejected(self, tmp_path):
        """CLI E2E: keygen auf existierende Datei → FileExistsError → exit(1)."""
        import sys

        from aegis.cli import main

        key_path = str(tmp_path / "existing.pem")
        Path(key_path).write_text("existing")

        with (
            pytest.raises(SystemExit),
            patch.object(sys, "argv", ["aegis", "keygen", key_path]),
        ):
            main()

    def test_cli_version(self, capsys):
        """CLI E2E: aegis version gibt Version aus."""
        import sys

        from aegis.cli import main

        with patch.object(sys, "argv", ["aegis", "version"]), \
             patch.dict("sys.modules", {"aegis": MagicMock(__version__="0.1.0")}):
            main()

        captured = capsys.readouterr()
        assert "aegis-ledger-sdk" in captured.out

    def test_cli_help(self, capsys):
        """CLI E2E: aegis --help gibt Hilfetext aus."""
        import sys

        from aegis.cli import main

        with patch.object(sys, "argv", ["aegis", "--help"]):
            main()

        captured = capsys.readouterr()
        assert "keygen" in captured.out
        assert "verify" in captured.out
        assert "status" in captured.out

    def test_cli_unknown_command(self):
        """CLI E2E: Unbekannter Command → exit(1)."""
        import sys

        from aegis.cli import main

        with pytest.raises(SystemExit), patch.object(sys, "argv", ["aegis", "nonexistent"]):
            main()


# ============================================================================
# Keygen Functions E2E (alle 5 Algorithmen)
# ============================================================================

class TestKeygenFunctionsE2E:
    """E2E: generate_keypair, generate_mldsa65/slhdsa128s/hybrid_keypair."""

    def test_generate_keypair_ed25519(self, tmp_path):
        """Keygen E2E: generate_keypair erzeugt valides Ed25519 Keypair."""
        from aegis.crypto import generate_keypair, get_public_key_hex, load_private_key

        path = tmp_path / "ed25519.pem"
        private_key, pub_hex = generate_keypair(path)

        assert isinstance(private_key, Ed25519PrivateKey)
        assert len(pub_hex) == 64
        assert path.exists()
        assert path.with_suffix(".pub").exists()

        # Verify we can load the key back and get the same public key
        loaded = load_private_key(path)
        assert get_public_key_hex(loaded) == pub_hex

    def test_generate_mldsa65_keypair(self, tmp_path):
        """Keygen E2E: generate_mldsa65_keypair erzeugt ML-DSA-65 Keypair."""
        try:
            import pqcrypto.sign.ml_dsa_65  # noqa: F401
        except ImportError:
            pytest.skip("pqcrypto not installed")

        from aegis.crypto import generate_mldsa65_keypair

        path = tmp_path / "mldsa.bin"
        sk_bytes, pub_hex = generate_mldsa65_keypair(path)

        assert isinstance(sk_bytes, bytes)
        assert len(pub_hex) == 3904
        assert path.exists()
        assert (path.parent / (path.name + ".pub")).exists()

    def test_generate_mldsa87_keypair(self, tmp_path):
        """Keygen E2E: generate_mldsa87_keypair erzeugt ML-DSA-87 Keypair."""
        try:
            import pqcrypto.sign.ml_dsa_87  # noqa: F401
        except ImportError:
            pytest.skip("pqcrypto not installed")

        from aegis.crypto import generate_mldsa87_keypair

        path = tmp_path / "mldsa87.bin"
        sk_bytes, pub_hex = generate_mldsa87_keypair(path)

        assert isinstance(sk_bytes, bytes)
        assert len(sk_bytes) == 4896
        assert len(pub_hex) == 5184  # 2592 bytes * 2
        assert path.exists()
        assert (path.parent / (path.name + ".pub")).exists()

    def test_generate_slhdsa128s_keypair(self, tmp_path):
        """Keygen E2E: generate_slhdsa128s_keypair erzeugt SLH-DSA-128s Keypair."""
        try:
            import pqcrypto.sign.sphincs_shake_128s_simple  # noqa: F401
        except ImportError:
            pytest.skip("pqcrypto not installed")

        from aegis.crypto import generate_slhdsa128s_keypair

        path = tmp_path / "slh.bin"
        sk_bytes, pub_hex = generate_slhdsa128s_keypair(path)

        assert isinstance(sk_bytes, bytes)
        assert len(pub_hex) == 64  # 32 bytes = 64 hex
        assert path.exists()
        assert (path.parent / (path.name + ".pub")).exists()

    def test_generate_hybrid_keypair(self, tmp_path):
        """Keygen E2E: generate_hybrid_keypair erzeugt 3 Dateien."""
        try:
            import pqcrypto.sign.ml_dsa_65  # noqa: F401
        except ImportError:
            pytest.skip("pqcrypto not installed")

        from aegis.crypto import generate_hybrid_keypair

        base = tmp_path / "hybrid"
        result = generate_hybrid_keypair(str(base))

        # Returns (ed25519_key, ml_sk_bytes, combined_pub_hex)
        assert len(result) == 3
        ed_key, ml_sk, pub_hex = result
        assert isinstance(ed_key, Ed25519PrivateKey)
        assert isinstance(ml_sk, bytes)
        assert len(pub_hex) == 3968

        assert Path(str(base) + ".pem").exists()
        assert Path(str(base) + ".mldsa65").exists()
        assert Path(str(base) + ".hybrid.pub").exists()


# ============================================================================
# LogEntry E2E (to_signable_dict, to_submission_dict)
# ============================================================================

class TestLogEntryE2E:
    """E2E: LogEntry — Signable-Dict Determinismus + Submission-Dict Vollständigkeit."""

    def test_to_signable_dict_excludes_signature(self):
        """LogEntry E2E: to_signable_dict enthält KEINE payload_signature."""
        from aegis.types import ActionContext, ActionPayload, ActionStatus, LogEntry

        entry = LogEntry(
            agent_id="test-agent",
            session_id="sess-1",
            sequence_number=1,
            action=ActionPayload(
                type=ActionType.TOOL_CALL,
                tool="search",
                input_hash="abc123",
                output_hash="def456",
                input_preview="query",
                output_preview="result",
                status=ActionStatus.SUCCESS,
                duration_ms=42,
            ),
            context=ActionContext(
                confidence_score=0.95,
                decision_reasoning="Testing",
                parent_action_id="",
            ),
            environment=Environment(framework="pytest"),
            metadata={"key": "value"},
            client_timestamp_ms=1709942400000,
            sdk_version="0.1.0",
            api_key_id="ak_test",
            payload_signature="ed25519:SHOULD_NOT_APPEAR",
        )

        signable = entry.to_signable_dict()
        assert "payload_signature" not in signable
        assert signable["agent_id"] == "test-agent"
        assert signable["sequence_number"] == 1
        assert signable["action"]["type"] == "tool_call"

    def test_to_submission_dict_includes_signature(self):
        """LogEntry E2E: to_submission_dict enthält payload_signature."""
        from aegis.types import ActionContext, ActionPayload, ActionStatus, LogEntry

        entry = LogEntry(
            agent_id="test-agent",
            session_id="sess-1",
            sequence_number=1,
            action=ActionPayload(
                type=ActionType.TOOL_CALL,
                tool="search",
                input_hash="a",
                output_hash="b",
                input_preview="in",
                output_preview="out",
                status=ActionStatus.SUCCESS,
                duration_ms=10,
            ),
            context=ActionContext(confidence_score=1.0, decision_reasoning="", parent_action_id=""),
            environment=Environment(framework="test"),
            payload_signature="ed25519:abc123",
        )

        submission = entry.to_submission_dict()
        assert submission["payload_signature"] == "ed25519:abc123"
        assert submission["agent_id"] == "test-agent"

    def test_signable_dict_deterministic(self):
        """LogEntry E2E: Zwei gleiche Entries → identischer signable_dict."""
        from aegis.types import ActionContext, ActionPayload, ActionStatus, LogEntry

        def make_entry():
            return LogEntry(
                agent_id="det-test",
                session_id="s1",
                sequence_number=5,
                action=ActionPayload(
                    type=ActionType.DECISION,
                    tool="llm",
                    input_hash="h1",
                    output_hash="h2",
                    input_preview="inp",
                    output_preview="outp",
                    status=ActionStatus.SUCCESS,
                    duration_ms=100,
                ),
                context=ActionContext(
                    confidence_score=0.9, decision_reasoning="test",
                    parent_action_id="",
                ),
                environment=Environment(framework="pytest"),
                metadata={"b": "2", "a": "1"},
            )

        e1 = make_entry()
        e2 = make_entry()
        assert canonical_json(e1.to_signable_dict()) == canonical_json(e2.to_signable_dict())


# ============================================================================
# Crypto Helpers E2E (get_public_key_hex, sha256_hex, detect_pii, redact_pii, truncate_preview)
# ============================================================================

class TestCryptoHelpersE2E:
    """E2E: Crypto utility functions — End-to-End durch die komplette Pipeline."""

    def test_get_public_key_hex(self):
        """Crypto E2E: get_public_key_hex extrahiert 64-Char Hex aus Private Key."""
        from aegis.crypto import get_public_key_hex

        key = Ed25519PrivateKey.generate()
        pub_hex = get_public_key_hex(key)
        assert len(pub_hex) == 64
        assert all(c in "0123456789abcdef" for c in pub_hex)

    def test_sha256_hex_deterministic(self):
        """Crypto E2E: sha256_hex ist deterministisch für gleichen Input."""
        from aegis.crypto import sha256_hex

        assert sha256_hex(b"test") == sha256_hex(b"test")
        assert sha256_hex("test") == sha256_hex("test")
        assert sha256_hex(b"test") != sha256_hex(b"other")
        assert len(sha256_hex(b"test")) == 64

    def test_detect_pii_finds_patterns(self):
        """Crypto E2E: detect_pii erkennt SSN, E-Mail, Telefon."""
        from aegis.crypto import detect_pii

        # SSN pattern
        pii = detect_pii("User SSN is 123-45-6789")
        assert len(pii) > 0

        # Email
        pii = detect_pii("Email: user@example.com")
        assert len(pii) > 0

        # No PII
        pii = detect_pii("Normal text without PII")
        assert len(pii) == 0

    def test_redact_pii_replaces_sensitive_data(self):
        """Crypto E2E: redact_pii ersetzt PII mit sha256-Hash."""
        from aegis.crypto import redact_pii

        text = "Contact: user@example.com"
        redacted = redact_pii(text, warn=False)
        assert "user@example.com" not in redacted
        assert "sha256:" in redacted

    def test_truncate_preview_limits_length(self):
        """Crypto E2E: truncate_preview kürzt lange Objekte auf repr-Format."""
        from aegis.crypto import truncate_preview

        # truncate_preview uses repr() internally
        short = truncate_preview("hello", max_length=100)
        assert "hello" in short

        long_text = "x" * 500
        truncated = truncate_preview(long_text, max_length=50)
        assert len(truncated) <= 53  # 50 + "..."

    def test_sha256_json_pipeline(self):
        """Crypto E2E: sha256_json über canonical_json — Pipeline-Integration."""
        data = {"b": 2, "a": 1}
        h1 = sha256_json(data)
        h2 = sha256_json({"a": 1, "b": 2})
        assert h1 == h2  # canonical_json sortiert Keys
        assert h1.startswith("sha256:")
        assert len(h1) == 71  # "sha256:" (7) + 64 hex


# ============================================================================
# log_batch E2E
# ============================================================================

class TestLogBatchE2E:
    """E2E: AegisClient.log_batch — Batch-Logging mit Chain-Integrität."""

    def test_log_batch_multiple_entries(self, tmp_pem):
        """Batch E2E: 5 Entries → 5 action_ids, monotone Sequenz."""
        # Use side_effect to return unique action_ids per call
        counter = [0]
        def side_effect(*args, **kwargs):
            counter[0] += 1
            return {"actionId": f"act_batch_{counter[0]}"}

        mock_transport = _make_mock_transport()
        mock_transport.call_update.side_effect = side_effect
        client, transport = _make_client(tmp_pem, transport=mock_transport)

        entries = [
            {"tool": f"tool_{i}", "input_data": {"step": i},
             "output_data": {}, "duration_ms": i * 10}
            for i in range(5)
        ]

        action_ids = client.log_batch(entries)

        assert len(action_ids) == 5
        assert len(set(action_ids)) == 5  # All unique
        assert transport.call_update.call_count == 5

        # Verify sequence numbers are monotonically increasing
        seqs = []
        for call in transport.call_update.call_args_list:
            record = call[0][1][0]["value"]
            seqs.append(record["sequenceNumber"])  # V2 Record format
        assert seqs == sorted(seqs)

    def test_log_batch_empty(self, tmp_pem):
        """Batch E2E: Leere Batch-Liste → keine Calls."""
        client, transport = _make_client(tmp_pem)
        result = client.log_batch([])
        assert result == []
        assert not transport.call_update.called

    def test_log_batch_chain_integrity(self, tmp_pem):
        """Batch E2E: Chain-Hashes sind korrekt verkettet über Batch."""
        client, transport = _make_client(tmp_pem)

        entries = [
            {"tool": "t1", "input_data": {"x": 1}, "output_data": {}, "duration_ms": 0},
            {"tool": "t2", "input_data": {"x": 2}, "output_data": {}, "duration_ms": 0},
            {"tool": "t3", "input_data": {"x": 3}, "output_data": {}, "duration_ms": 0},
        ]

        client.log_batch(entries)

        # Verify chain hashes are all different (each includes previous)
        chain_hashes = []
        for call in transport.call_update.call_args_list:
            record = call[0][1][0]["value"]
            chain_hashes.append(record["chainHash"])

        assert len(chain_hashes) == 3
        assert len(set(chain_hashes)) == 3  # All unique (different payloads)


# ============================================================================
# Transport Details E2E (AegisError, spill_count)
# ============================================================================

class TestTransportDetailsE2E:
    """E2E: Transport-Layer — AegisError, spill_count Property, pending_spill_count."""

    def test_aegis_error_hierarchy(self):
        """Transport E2E: AegisError ist Exception-Subclass."""
        from aegis.transport import AegisError, CanisterError

        assert issubclass(AegisError, Exception)
        assert issubclass(CanisterError, AegisError)

        err = CanisterError("test error", error_code="E500")
        assert "test error" in str(err)
        assert err.error_code == "E500"

    def test_spill_count_property(self, tmp_path):
        """Transport E2E: spill_count reflektiert Anzahl Zeilen in der Spill-Datei."""
        config = TransportConfig(
            canister_id="test-canister",
            spill_dir=str(tmp_path / "spill"),
        )
        with patch("aegis.transport.Agent", create=True), \
             patch("aegis.transport.Client", create=True), \
             patch("aegis.transport.Identity", create=True):
            transport = CanisterTransport(config)

        assert transport.spill_count == 0

        # Write to the actual spill file path (canister_id.jsonl)
        spill_dir = Path(str(tmp_path / "spill"))
        spill_dir.mkdir(parents=True, exist_ok=True)
        spill_file = spill_dir / "test-canister.jsonl"
        spill_file.write_text('{"test": true}\n{"test": false}\n')

        # Reset cache to force re-read
        transport._cached_spill_count = -1
        assert transport.spill_count == 2

    def test_client_pending_spill_count(self, tmp_pem):
        """Transport E2E: client.pending_spill_count delegiert an Transport."""
        client, transport = _make_client(tmp_pem)
        type(transport).spill_count = property(lambda self: 3)

        assert client.pending_spill_count == 3
