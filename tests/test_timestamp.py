"""Tests for aegis.timestamp -- RFC 3161 TSA client and eIDAS timestamp support."""

from __future__ import annotations

import hashlib
import threading
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from AEGIS_LEDGER.timestamp import (
    TimestampAuthority,
    TimestampError,
    TimestampToken,
    TimestampVerification,
    _build_timestamp_request,
    _der_integer,
    _der_length,
    _der_sequence,
    _extract_status_from_tsr,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tsa() -> TimestampAuthority:
    """Default TimestampAuthority pointed at freetsa.org."""
    return TimestampAuthority(url="https://freetsa.org/tsr")


@pytest.fixture
def sample_hash() -> bytes:
    """A valid SHA-256 digest (32 bytes)."""
    return hashlib.sha256(b"test-ledger-entry").digest()


@pytest.fixture
def sample_hex_hash() -> str:
    """A valid SHA-256 hex hash (64 chars)."""
    return hashlib.sha256(b"test-ledger-entry").hexdigest()


def _make_granted_tsr() -> bytes:
    """Build a minimal DER-encoded TimeStampResp with PKIStatus=0 (granted)."""
    # PKIStatus INTEGER 0
    status_int = _der_integer(0)
    # PKIStatusInfo SEQUENCE { status }
    status_info = _der_sequence(status_int)
    # Fake timeStampToken: a SEQUENCE with some padding bytes
    fake_token_content = _der_sequence(b"\x02\x01\x01" + b"\x04\x10" + b"\xab" * 16)
    # TimeStampResp SEQUENCE { statusInfo, timeStampToken }
    return _der_sequence(status_info + fake_token_content)


def _make_rejected_tsr() -> bytes:
    """Build a minimal DER-encoded TimeStampResp with PKIStatus=2 (rejection)."""
    status_int = _der_integer(2)
    status_info = _der_sequence(status_int)
    return _der_sequence(status_info)


# ---------------------------------------------------------------------------
# TimestampAuthority creation
# ---------------------------------------------------------------------------

class TestTimestampAuthorityInit:
    def test_default_config(self) -> None:
        tsa = TimestampAuthority(url="https://freetsa.org/tsr")
        assert tsa.url == "https://freetsa.org/tsr"
        assert tsa.hash_algorithm == "sha256"

    def test_custom_config(self) -> None:
        tsa = TimestampAuthority(
            url="https://timestamp.evidency.com",
            api_key="test-key-123",
            hash_algorithm="sha384",
            timeout_seconds=30,
            cert_path="/tmp/ca-bundle.pem",
        )
        assert tsa.url == "https://timestamp.evidency.com"
        assert tsa.hash_algorithm == "sha384"

    def test_empty_url_raises(self) -> None:
        with pytest.raises(ValueError, match="url must not be empty"):
            TimestampAuthority(url="")

    def test_unsupported_hash_algorithm_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            TimestampAuthority(url="https://freetsa.org/tsr", hash_algorithm="md5")


# ---------------------------------------------------------------------------
# DER encoding helpers
# ---------------------------------------------------------------------------

class TestDerHelpers:
    def test_der_length_short(self) -> None:
        assert _der_length(5) == b"\x05"
        assert _der_length(127) == b"\x7f"

    def test_der_length_medium(self) -> None:
        assert _der_length(128) == b"\x81\x80"
        assert _der_length(255) == b"\x81\xff"

    def test_der_length_long(self) -> None:
        result = _der_length(256)
        assert result[0:1] == b"\x82"
        assert len(result) == 3

    def test_der_integer_zero(self) -> None:
        assert _der_integer(0) == b"\x02\x01\x00"

    def test_der_integer_positive(self) -> None:
        result = _der_integer(1)
        assert result[0:1] == b"\x02"  # INTEGER tag
        assert result[-1] == 1

    def test_der_sequence_wraps(self) -> None:
        inner = b"\x02\x01\x01"  # INTEGER 1
        result = _der_sequence(inner)
        assert result[0:1] == b"\x30"  # SEQUENCE tag
        assert result[2:] == inner


# ---------------------------------------------------------------------------
# TimeStampReq building
# ---------------------------------------------------------------------------

class TestBuildTimestampRequest:
    def test_builds_valid_der(self, sample_hash: bytes) -> None:
        tsq = _build_timestamp_request(
            digest=sample_hash,
            hash_algorithm="sha256",
            nonce=12345,
        )
        # Must start with SEQUENCE tag
        assert tsq[0] == 0x30
        # Must be non-trivial length
        assert len(tsq) > 40

    def test_wrong_digest_length_raises(self) -> None:
        with pytest.raises(ValueError, match="Digest length"):
            _build_timestamp_request(
                digest=b"\x00" * 16,  # too short for sha256
                hash_algorithm="sha256",
                nonce=1,
            )

    def test_unsupported_algorithm_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            _build_timestamp_request(
                digest=b"\x00" * 32,
                hash_algorithm="md5",
                nonce=1,
            )


# ---------------------------------------------------------------------------
# TSR parsing
# ---------------------------------------------------------------------------

class TestExtractStatus:
    def test_granted_status(self) -> None:
        tsr = _make_granted_tsr()
        assert _extract_status_from_tsr(tsr) == 0

    def test_rejected_status(self) -> None:
        tsr = _make_rejected_tsr()
        assert _extract_status_from_tsr(tsr) == 2

    def test_invalid_der_raises(self) -> None:
        with pytest.raises(TimestampError):
            _extract_status_from_tsr(b"\x00\x00")

    def test_empty_data_raises(self) -> None:
        with pytest.raises(TimestampError):
            _extract_status_from_tsr(b"")


# ---------------------------------------------------------------------------
# timestamp() with mocked HTTP
# ---------------------------------------------------------------------------

class TestTimestamp:
    @patch("AEGIS_LEDGER.timestamp.urlopen")
    def test_success(self, mock_urlopen: MagicMock, tsa: TimestampAuthority) -> None:
        tsr = _make_granted_tsr()
        mock_resp = MagicMock()
        mock_resp.read.return_value = tsr
        mock_resp.headers = {"Content-Type": "application/timestamp-reply"}
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        token = tsa.timestamp(b"test-data")
        assert token.tsa_name == "https://freetsa.org/tsr"
        assert token.hash_algorithm == "sha256"
        assert token.hash_value == hashlib.sha256(b"test-data").hexdigest()
        assert len(token.token_der) > 0
        assert isinstance(token.timestamp_utc, datetime)

    @patch("AEGIS_LEDGER.timestamp.urlopen")
    def test_network_failure_returns_local_fallback(
        self, mock_urlopen: MagicMock, tsa: TimestampAuthority
    ) -> None:
        from urllib.error import URLError

        mock_urlopen.side_effect = URLError("Connection refused")

        token = tsa.timestamp(b"test-data")
        assert token.tsa_name == "local"
        assert token.serial_number == "local"
        assert token.token_der == b""

    @patch("AEGIS_LEDGER.timestamp.urlopen")
    def test_timeout_returns_local_fallback(
        self, mock_urlopen: MagicMock, tsa: TimestampAuthority
    ) -> None:
        mock_urlopen.side_effect = TimeoutError("timed out")

        token = tsa.timestamp(b"test-data")
        assert token.tsa_name == "local"

    @patch("AEGIS_LEDGER.timestamp.urlopen")
    def test_rejection_raises_error(
        self, mock_urlopen: MagicMock, tsa: TimestampAuthority
    ) -> None:
        tsr = _make_rejected_tsr()
        mock_resp = MagicMock()
        mock_resp.read.return_value = tsr
        mock_resp.headers = {"Content-Type": "application/timestamp-reply"}
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        with pytest.raises(TimestampError, match="rejected"):
            tsa.timestamp(b"test-data")

    @patch("AEGIS_LEDGER.timestamp.urlopen")
    def test_empty_response_raises_error(
        self, mock_urlopen: MagicMock, tsa: TimestampAuthority
    ) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_resp.headers = {"Content-Type": "application/timestamp-reply"}
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        with pytest.raises(TimestampError, match="empty or too-short"):
            tsa.timestamp(b"test-data")


# ---------------------------------------------------------------------------
# timestamp_hex() convenience method
# ---------------------------------------------------------------------------

class TestTimestampHex:
    @patch("AEGIS_LEDGER.timestamp.urlopen")
    def test_valid_hex_hash(
        self, mock_urlopen: MagicMock, tsa: TimestampAuthority, sample_hex_hash: str
    ) -> None:
        tsr = _make_granted_tsr()
        mock_resp = MagicMock()
        mock_resp.read.return_value = tsr
        mock_resp.headers = {"Content-Type": "application/timestamp-reply"}
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        token = tsa.timestamp_hex(sample_hex_hash)
        assert token.hash_value == sample_hex_hash
        assert token.tsa_name == "https://freetsa.org/tsr"

    def test_invalid_hex_raises(self, tsa: TimestampAuthority) -> None:
        with pytest.raises(ValueError, match="Invalid hex hash"):
            tsa.timestamp_hex("not-valid-hex-zzz")

    def test_wrong_length_hex_raises(self, tsa: TimestampAuthority) -> None:
        with pytest.raises(ValueError, match="Hex hash length"):
            tsa.timestamp_hex("abcd1234")  # too short for sha256

    @patch("AEGIS_LEDGER.timestamp.urlopen")
    def test_network_failure_returns_local(
        self, mock_urlopen: MagicMock, tsa: TimestampAuthority, sample_hex_hash: str
    ) -> None:
        from urllib.error import URLError

        mock_urlopen.side_effect = URLError("unreachable")

        token = tsa.timestamp_hex(sample_hex_hash)
        assert token.tsa_name == "local"
        assert token.hash_value == sample_hex_hash


# ---------------------------------------------------------------------------
# verify()
# ---------------------------------------------------------------------------

class TestVerify:
    def test_valid_verification(self, tsa: TimestampAuthority) -> None:
        data = b"original-data"
        token = TimestampToken(
            timestamp_utc=datetime.now(timezone.utc),
            serial_number="12345",
            tsa_name="https://freetsa.org/tsr",
            hash_algorithm="sha256",
            hash_value=hashlib.sha256(data).hexdigest(),
            token_der=b"\x30\x03\x02\x01\x00",  # minimal valid DER
        )

        result = tsa.verify(token, data)
        assert result.valid is True
        assert result.error == ""
        assert result.tsa_name == "https://freetsa.org/tsr"

    def test_hash_mismatch(self, tsa: TimestampAuthority) -> None:
        token = TimestampToken(
            timestamp_utc=datetime.now(timezone.utc),
            serial_number="12345",
            tsa_name="https://freetsa.org/tsr",
            hash_algorithm="sha256",
            hash_value="0000000000000000000000000000000000000000000000000000000000000000",
            token_der=b"\x30\x03\x02\x01\x00",
        )

        result = tsa.verify(token, b"different-data")
        assert result.valid is False
        assert "hash mismatch" in result.error

    def test_empty_token_der(self, tsa: TimestampAuthority) -> None:
        data = b"test"
        token = TimestampToken(
            timestamp_utc=datetime.now(timezone.utc),
            serial_number="local",
            tsa_name="local",
            hash_algorithm="sha256",
            hash_value=hashlib.sha256(data).hexdigest(),
            token_der=b"",
        )

        result = tsa.verify(token, data)
        assert result.valid is False
        assert "empty token_der" in result.error


# ---------------------------------------------------------------------------
# TimestampToken serialization
# ---------------------------------------------------------------------------

class TestTimestampTokenSerialization:
    def test_to_dict_roundtrip(self) -> None:
        now = datetime.now(timezone.utc)
        token = TimestampToken(
            timestamp_utc=now,
            serial_number="nonce-99999",
            tsa_name="https://freetsa.org/tsr",
            hash_algorithm="sha256",
            hash_value="abcd" * 16,
            token_der=b"\x30\x80\x00\x00",
        )

        d = token.to_dict()
        assert isinstance(d["token_der_b64"], str)
        assert d["tsa_name"] == "https://freetsa.org/tsr"
        assert d["hash_algorithm"] == "sha256"

        restored = TimestampToken.from_dict(d)
        assert restored.serial_number == token.serial_number
        assert restored.tsa_name == token.tsa_name
        assert restored.hash_value == token.hash_value
        assert restored.token_der == token.token_der

    def test_to_dict_contains_all_keys(self) -> None:
        token = TimestampToken(
            timestamp_utc=datetime(2026, 1, 1, tzinfo=timezone.utc),
            serial_number="42",
            tsa_name="test-tsa",
            hash_algorithm="sha256",
            hash_value="ff" * 32,
            token_der=b"\x00",
        )
        d = token.to_dict()
        expected_keys = {
            "timestamp_utc", "serial_number", "tsa_name",
            "hash_algorithm", "hash_value", "token_der_b64",
        }
        assert set(d.keys()) == expected_keys


# ---------------------------------------------------------------------------
# TimestampVerification dataclass
# ---------------------------------------------------------------------------

class TestTimestampVerification:
    def test_valid_result(self) -> None:
        v = TimestampVerification(
            valid=True,
            timestamp_utc=datetime.now(timezone.utc),
            tsa_name="https://freetsa.org/tsr",
        )
        assert v.valid is True
        assert v.error == ""

    def test_error_result(self) -> None:
        v = TimestampVerification(
            valid=False,
            timestamp_utc=None,
            tsa_name="local",
            error="something went wrong",
        )
        assert v.valid is False
        assert v.timestamp_utc is None
        assert "something went wrong" in v.error


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

class TestThreadSafety:
    @patch("AEGIS_LEDGER.timestamp.urlopen")
    def test_concurrent_timestamps(self, mock_urlopen: MagicMock) -> None:
        """Multiple threads can call timestamp() concurrently without errors."""
        tsr = _make_granted_tsr()
        mock_resp = MagicMock()
        mock_resp.read.return_value = tsr
        mock_resp.headers = {"Content-Type": "application/timestamp-reply"}
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        tsa = TimestampAuthority(url="https://freetsa.org/tsr")
        results: list[TimestampToken] = []
        errors: list[Exception] = []

        def worker(i: int) -> None:
            try:
                token = tsa.timestamp(f"thread-{i}".encode())
                results.append(token)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert len(errors) == 0
        assert len(results) == 10
        # Each thread should get a unique hash value
        hash_values = {r.hash_value for r in results}
        assert len(hash_values) == 10
