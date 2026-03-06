"""
aegis.timestamp -- eIDAS Qualified Timestamps via RFC 3161 TSA.

eIDAS-qualified timestamps have full legal standing before all EU courts
(Art. 41.2 eIDAS Regulation). This gives Aegis traces legal evidence weight
that no competitor (LangSmith, Traceprompt, Datadog) can match.

Usage:
    from aegis.timestamp import TimestampAuthority

    tsa = TimestampAuthority(
        url="https://freetsa.org/tsr",           # TSA endpoint
        # For qualified timestamps (paid):
        # url="https://timestamp.evidency.com",
        # api_key="your-evidency-api-key",
    )

    # Get a qualified timestamp for any data
    ts_token = tsa.timestamp(b"sha256-hash-of-ledger-entry")

    # Verify a timestamp
    result = tsa.verify(ts_token, b"sha256-hash-of-ledger-entry")
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import ssl
import struct
from base64 import b64decode, b64encode
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger("aegis.timestamp")

# ---------------------------------------------------------------------------
# OID constants (DER-encoded)
# ---------------------------------------------------------------------------
_OID_SHA256 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01"
_OID_SHA384 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02"
_OID_SHA512 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03"

_HASH_OIDS: dict[str, bytes] = {
    "sha256": _OID_SHA256,
    "sha384": _OID_SHA384,
    "sha512": _OID_SHA512,
}

_HASH_LENGTHS: dict[str, int] = {
    "sha256": 32,
    "sha384": 48,
    "sha512": 64,
}

_CONTENT_TYPE_TSQ = "application/timestamp-query"
_CONTENT_TYPE_TSR = "application/timestamp-reply"


class TimestampError(Exception):
    """Raised when TSA interaction fails in an unrecoverable way."""


# ---------------------------------------------------------------------------
# ASN.1 DER helpers (minimal, no external deps beyond stdlib)
# ---------------------------------------------------------------------------

def _der_length(length: int) -> bytes:
    """Encode an ASN.1 DER length field."""
    if length < 0x80:
        return bytes([length])
    if length < 0x100:
        return b"\x81" + bytes([length])
    if length < 0x10000:
        return b"\x82" + struct.pack(">H", length)
    return b"\x83" + struct.pack(">I", length)[1:]  # 3-byte length


def _der_sequence(contents: bytes) -> bytes:
    """Wrap contents in a SEQUENCE tag (0x30)."""
    return b"\x30" + _der_length(len(contents)) + contents


def _der_octet_string(data: bytes) -> bytes:
    """Wrap data in an OCTET STRING tag (0x04)."""
    return b"\x04" + _der_length(len(data)) + data


def _der_integer(value: int) -> bytes:
    """Encode a non-negative integer in DER."""
    if value == 0:
        return b"\x02\x01\x00"
    result = value.to_bytes((value.bit_length() + 8) // 8, byteorder="big")
    return b"\x02" + _der_length(len(result)) + result


def _der_boolean(value: bool) -> bytes:
    """Encode a BOOLEAN in DER."""
    return b"\x01\x01" + (b"\xff" if value else b"\x00")


# ---------------------------------------------------------------------------
# RFC 3161 TimeStampReq builder
# ---------------------------------------------------------------------------

def _build_timestamp_request(
    digest: bytes,
    hash_algorithm: str,
    nonce: int,
    cert_req: bool = True,
) -> bytes:
    """
    Build an RFC 3161 TimeStampReq in DER format.

    Structure (RFC 3161, Section 2.4.1):
        TimeStampReq ::= SEQUENCE {
            version         INTEGER { v1(1) },
            messageImprint  MessageImprint,
            nonce           INTEGER OPTIONAL,
            certReq         BOOLEAN DEFAULT FALSE
        }

        MessageImprint ::= SEQUENCE {
            hashAlgorithm   AlgorithmIdentifier,
            hashedMessage    OCTET STRING
        }

        AlgorithmIdentifier ::= SEQUENCE {
            algorithm   OBJECT IDENTIFIER,
            parameters  NULL  (0x05 0x00)
        }
    """
    oid = _HASH_OIDS.get(hash_algorithm)
    if oid is None:
        raise ValueError(
            f"Unsupported hash algorithm: {hash_algorithm!r}. "
            f"Supported: {', '.join(sorted(_HASH_OIDS))}"
        )

    expected_len = _HASH_LENGTHS[hash_algorithm]
    if len(digest) != expected_len:
        raise ValueError(
            f"Digest length {len(digest)} does not match {hash_algorithm} "
            f"(expected {expected_len})"
        )

    # AlgorithmIdentifier: SEQUENCE { OID, NULL }
    alg_id = _der_sequence(oid + b"\x05\x00")

    # MessageImprint: SEQUENCE { AlgorithmIdentifier, OCTET STRING }
    message_imprint = _der_sequence(alg_id + _der_octet_string(digest))

    # TimeStampReq body
    body = _der_integer(1)  # version = 1
    body += message_imprint
    body += _der_integer(nonce)
    body += _der_boolean(cert_req)

    return _der_sequence(body)


# ---------------------------------------------------------------------------
# ASN.1 DER parser (minimal, for reading TSA responses)
# ---------------------------------------------------------------------------

def _parse_der_tag(data: bytes, offset: int) -> tuple[int, int, int]:
    """
    Parse a DER tag+length at the given offset.
    Returns (tag, content_start, content_end).
    """
    if offset >= len(data):
        raise TimestampError("DER parse error: unexpected end of data")

    tag = data[offset]
    offset += 1

    if offset >= len(data):
        raise TimestampError("DER parse error: missing length byte")

    length_byte = data[offset]
    offset += 1

    if length_byte < 0x80:
        length = length_byte
    elif length_byte == 0x81:
        if offset >= len(data):
            raise TimestampError("DER parse error: truncated length")
        length = data[offset]
        offset += 1
    elif length_byte == 0x82:
        if offset + 1 >= len(data):
            raise TimestampError("DER parse error: truncated length")
        length = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2
    elif length_byte == 0x83:
        if offset + 2 >= len(data):
            raise TimestampError("DER parse error: truncated length")
        length = struct.unpack(">I", b"\x00" + data[offset : offset + 3])[0]
        offset += 3
    else:
        raise TimestampError(f"DER parse error: unsupported length encoding 0x{length_byte:02x}")

    return tag, offset, offset + length


def _extract_status_from_tsr(data: bytes) -> int:
    """
    Extract the PKIStatus from a TimeStampResp.

    TimeStampResp ::= SEQUENCE {
        status          PKIStatusInfo,
        timeStampToken  ContentInfo OPTIONAL
    }

    PKIStatusInfo ::= SEQUENCE {
        status     PKIStatus,    -- INTEGER
        ...
    }

    PKIStatus: 0=granted, 1=grantedWithMods, 2=rejection, ...
    """
    # Outer SEQUENCE
    tag, start, end = _parse_der_tag(data, 0)
    if tag != 0x30:
        raise TimestampError(f"TSR: expected SEQUENCE, got 0x{tag:02x}")

    # PKIStatusInfo SEQUENCE
    tag, start2, end2 = _parse_der_tag(data, start)
    if tag != 0x30:
        raise TimestampError(f"TSR: expected PKIStatusInfo SEQUENCE, got 0x{tag:02x}")

    # PKIStatus INTEGER
    tag, start3, end3 = _parse_der_tag(data, start2)
    if tag != 0x02:
        raise TimestampError(f"TSR: expected INTEGER for status, got 0x{tag:02x}")

    status_value = int.from_bytes(data[start3:end3], byteorder="big")
    return status_value


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class TimestampToken:
    """
    A timestamp token from a TSA.

    For eIDAS-qualified timestamps (from a QTSP like Evidency or SwissSign),
    the token_der field contains the full CMS/PKCS#7 SignedData structure
    that can be presented as evidence in EU courts.

    For local fallback timestamps (tsa_name="local"), the token is not
    legally qualified but still provides a best-effort time reference.
    """

    timestamp_utc: datetime
    serial_number: str
    tsa_name: str
    hash_algorithm: str
    hash_value: str  # hex
    token_der: bytes  # raw DER-encoded token for storage/verification

    def to_dict(self) -> dict[str, str]:
        """Serialize for JSON storage (base64-encode the DER token)."""
        return {
            "timestamp_utc": self.timestamp_utc.isoformat(),
            "serial_number": self.serial_number,
            "tsa_name": self.tsa_name,
            "hash_algorithm": self.hash_algorithm,
            "hash_value": self.hash_value,
            "token_der_b64": b64encode(self.token_der).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> TimestampToken:
        """Deserialize from JSON dict."""
        return cls(
            timestamp_utc=datetime.fromisoformat(data["timestamp_utc"]),
            serial_number=data["serial_number"],
            tsa_name=data["tsa_name"],
            hash_algorithm=data["hash_algorithm"],
            hash_value=data["hash_value"],
            token_der=b64decode(data["token_der_b64"]),
        )


@dataclass(frozen=True, slots=True)
class TimestampVerification:
    """Result of timestamp verification."""

    valid: bool
    timestamp_utc: datetime | None
    tsa_name: str
    error: str = ""


# ---------------------------------------------------------------------------
# TimestampAuthority
# ---------------------------------------------------------------------------

class TimestampAuthority:
    """
    RFC 3161 Timestamp Authority client.

    Supports any RFC 3161-compliant TSA. For eIDAS-qualified timestamps,
    use a Qualified Trust Service Provider (QTSP) like:
    - Evidency (https://evidency.com) -- approx. EUR 0.001/timestamp
    - DigiCert Timestamp Authority
    - SwissSign

    Thread-safe: all instance state is read-only after __init__.
    """

    def __init__(
        self,
        url: str,
        api_key: str = "",
        hash_algorithm: str = "sha256",
        timeout_seconds: int = 10,
        cert_path: str = "",
    ) -> None:
        """
        Initialize a TimestampAuthority client.

        Args:
            url: The TSA endpoint URL (must support HTTP POST with
                 application/timestamp-query content type).
            api_key: Optional API key for paid QTSP services. Sent as
                     Authorization: Bearer header.
            hash_algorithm: Hash algorithm for the timestamp request.
                           Must be one of: sha256, sha384, sha512.
            timeout_seconds: HTTP request timeout in seconds.
            cert_path: Optional path to a CA certificate bundle for
                       TSA TLS verification.
        """
        if not url:
            raise ValueError("TSA url must not be empty")
        if hash_algorithm not in _HASH_OIDS:
            raise ValueError(
                f"Unsupported hash algorithm: {hash_algorithm!r}. "
                f"Supported: {', '.join(sorted(_HASH_OIDS))}"
            )

        self._url: str = url
        self._api_key: str = api_key
        self._hash_algorithm: str = hash_algorithm
        self._timeout: int = timeout_seconds
        self._cert_path: str = cert_path

    @property
    def url(self) -> str:
        """The configured TSA endpoint URL."""
        return self._url

    @property
    def hash_algorithm(self) -> str:
        """The configured hash algorithm."""
        return self._hash_algorithm

    def timestamp(self, data: bytes) -> TimestampToken:
        """
        Request a timestamp for the given data.

        The data is hashed with the configured algorithm before being sent
        to the TSA. The TSA never sees the original data -- only the hash.

        On network failure or timeout, returns a local (non-qualified)
        fallback timestamp with tsa_name="local".

        Args:
            data: Arbitrary bytes to timestamp. Will be hashed before
                  sending to the TSA.

        Returns:
            A TimestampToken containing the TSA's response (or a local
            fallback if the TSA is unreachable).

        Raises:
            TimestampError: If the TSA returns an invalid or rejection
                           response (not a network error).
        """
        h = hashlib.new(self._hash_algorithm)
        h.update(data)
        digest = h.digest()
        hex_hash = h.hexdigest()

        nonce = secrets.randbits(64)
        tsq = _build_timestamp_request(
            digest=digest,
            hash_algorithm=self._hash_algorithm,
            nonce=nonce,
            cert_req=True,
        )

        try:
            tsr_bytes = self._send_request(tsq)
        except (URLError, OSError, TimeoutError) as exc:
            logger.warning("TSA request failed (%s), using local fallback: %s", self._url, exc)
            return self._local_fallback(hex_hash)

        return self._parse_response(tsr_bytes, hex_hash, nonce)

    def timestamp_hex(self, hex_hash: str) -> TimestampToken:
        """
        Convenience: timestamp a hex-encoded hash string.

        The hex string is decoded to bytes and sent directly as the
        message imprint (not double-hashed). This is useful when you
        already have a chain_hash from AegisClient.

        Args:
            hex_hash: A hex-encoded hash (e.g., from compute_chain_hash).

        Returns:
            A TimestampToken.
        """
        try:
            digest = bytes.fromhex(hex_hash)
        except ValueError as exc:
            raise ValueError(f"Invalid hex hash: {hex_hash!r}") from exc

        expected_len = _HASH_LENGTHS.get(self._hash_algorithm, 32)
        if len(digest) != expected_len:
            raise ValueError(
                f"Hex hash length {len(digest)} does not match {self._hash_algorithm} "
                f"(expected {expected_len} bytes / {expected_len * 2} hex chars)"
            )

        nonce = secrets.randbits(64)
        tsq = _build_timestamp_request(
            digest=digest,
            hash_algorithm=self._hash_algorithm,
            nonce=nonce,
            cert_req=True,
        )

        try:
            tsr_bytes = self._send_request(tsq)
        except (URLError, OSError, TimeoutError) as exc:
            logger.warning("TSA request failed (%s), using local fallback: %s", self._url, exc)
            return self._local_fallback(hex_hash)

        return self._parse_response(tsr_bytes, hex_hash, nonce)

    def verify(self, token: TimestampToken, data: bytes) -> TimestampVerification:
        """
        Verify a timestamp token against the original data.

        Checks that:
        1. The hash of the data matches the hash_value in the token.
        2. The token has a valid structure (non-empty DER).

        Note: Full cryptographic verification of the TSA signature requires
        the TSA's certificate chain, which is TSA-specific. This method
        performs data-integrity verification. For full chain-of-trust
        verification, use OpenSSL or a dedicated PKI library.

        Args:
            token: The TimestampToken to verify.
            data: The original data that was timestamped.

        Returns:
            A TimestampVerification result.
        """
        h = hashlib.new(token.hash_algorithm)
        h.update(data)
        computed_hash = h.hexdigest()

        if computed_hash != token.hash_value:
            return TimestampVerification(
                valid=False,
                timestamp_utc=token.timestamp_utc,
                tsa_name=token.tsa_name,
                error=(
                    f"hash mismatch: computed {computed_hash} "
                    f"!= token {token.hash_value}"
                ),
            )

        if not token.token_der:
            return TimestampVerification(
                valid=False,
                timestamp_utc=token.timestamp_utc,
                tsa_name=token.tsa_name,
                error="empty token_der",
            )

        return TimestampVerification(
            valid=True,
            timestamp_utc=token.timestamp_utc,
            tsa_name=token.tsa_name,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _send_request(self, tsq: bytes) -> bytes:
        """Send a TimeStampReq to the TSA and return the raw response."""
        headers: dict[str, str] = {
            "Content-Type": _CONTENT_TYPE_TSQ,
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        req = Request(
            self._url,
            data=tsq,
            headers=headers,
            method="POST",
        )

        context: ssl.SSLContext | None = None
        if self._cert_path and os.path.isfile(self._cert_path):
            context = ssl.create_default_context(cafile=self._cert_path)

        with urlopen(req, timeout=self._timeout, context=context) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if _CONTENT_TYPE_TSR not in content_type:
                logger.warning(
                    "TSA returned unexpected Content-Type: %s (expected %s)",
                    content_type,
                    _CONTENT_TYPE_TSR,
                )
            return resp.read()  # type: ignore[no-any-return]

    def _parse_response(
        self,
        tsr_bytes: bytes,
        hex_hash: str,
        nonce: int,
    ) -> TimestampToken:
        """Parse a TimeStampResp DER blob into a TimestampToken."""
        if not tsr_bytes or len(tsr_bytes) < 5:
            raise TimestampError("TSA returned empty or too-short response")

        status = _extract_status_from_tsr(tsr_bytes)
        if status not in (0, 1):
            raise TimestampError(
                f"TSA rejected the request (PKIStatus={status}). "
                "Status 0=granted, 1=grantedWithMods, 2=rejection, "
                "3=waiting, 4=revocationWarning, 5=revocationNotification"
            )

        # For a full implementation, we would parse the TSTInfo from the
        # embedded CMS SignedData to extract the exact genTime and serial.
        # The DER structure is deeply nested:
        #   TimeStampResp > timeStampToken (ContentInfo) > content (SignedData)
        #   > encapContentInfo > eContent (TSTInfo) > genTime, serialNumber
        #
        # For now, we store the full TSR as-is (legally sufficient as evidence)
        # and record UTC now as a close approximation. The actual genTime is
        # inside the DER and can be extracted by OpenSSL for court proceedings.

        return TimestampToken(
            timestamp_utc=datetime.now(timezone.utc),
            serial_number=f"nonce-{nonce}",
            tsa_name=self._url,
            hash_algorithm=self._hash_algorithm,
            hash_value=hex_hash,
            token_der=tsr_bytes,
        )

    def _local_fallback(self, hex_hash: str) -> TimestampToken:
        """
        Create a non-qualified local timestamp as fallback.

        This is used when the TSA is unreachable. The timestamp has no
        legal standing but preserves the intent and local system time.
        """
        logger.info("Using local fallback timestamp (non-qualified)")
        return TimestampToken(
            timestamp_utc=datetime.now(timezone.utc),
            serial_number="local",
            tsa_name="local",
            hash_algorithm=self._hash_algorithm,
            hash_value=hex_hash,
            token_der=b"",
        )
