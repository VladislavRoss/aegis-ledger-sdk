"""Tests for PII detection and redaction (Phase 24 — Audit Fix)."""

import re

import pytest
from aegis.crypto import detect_pii, redact_pii


class TestDetectPii:
    def test_detect_email(self) -> None:
        assert "email" in detect_pii("contact alice@example.com now")

    def test_detect_phone(self) -> None:
        assert "phone" in detect_pii("call +41791234567")

    def test_detect_ip(self) -> None:
        assert "ip" in detect_pii("server at 192.168.1.100")

    def test_detect_ssn(self) -> None:
        assert "ssn" in detect_pii("ssn is 123-45-6789")

    def test_detect_ahv(self) -> None:
        # Valid AHV with Luhn: 756.1234.5678.97
        assert "ahv" in detect_pii("AHV: 756.1234.5678.97")

    def test_detect_credit_card(self) -> None:
        # Visa test card (Luhn-valid)
        assert "credit_card" in detect_pii("card 4111111111111111")

    def test_detect_nothing(self) -> None:
        assert detect_pii("hello world 42") == []

    def test_detect_multiple(self) -> None:
        hits = detect_pii("email alice@test.com ip 10.0.0.1")
        assert "email" in hits
        assert "ip" in hits


class TestRedactPii:
    def test_hash_length_is_32_hex(self) -> None:
        result = redact_pii("alice@example.com", warn=False)
        match = re.search(r"sha256:([0-9a-f]+)", result)
        assert match is not None
        assert len(match.group(1)) == 32  # 128-bit

    def test_redact_email(self) -> None:
        result = redact_pii("mail alice@example.com end", warn=False)
        assert "alice@example.com" not in result
        assert "sha256:" in result

    def test_redact_phone(self) -> None:
        result = redact_pii("call +41791234567", warn=False)
        assert "sha256:" in result

    def test_redact_ip(self) -> None:
        result = redact_pii("ip 192.168.1.100 ok", warn=False)
        assert "192.168.1.100" not in result
        assert "sha256:" in result

    def test_redact_ssn(self) -> None:
        result = redact_pii("ssn 123-45-6789", warn=False)
        assert "123-45-6789" not in result
        assert "sha256:" in result

    def test_redact_ahv(self) -> None:
        result = redact_pii("756.1234.5678.97", warn=False)
        assert "756.1234.5678.97" not in result
        assert "sha256:" in result

    def test_redact_credit_card(self) -> None:
        result = redact_pii("card 4111111111111111", warn=False)
        assert "4111111111111111" not in result
        assert "sha256:" in result

    def test_no_pii_returns_unchanged(self) -> None:
        text = "just normal text 42"
        assert redact_pii(text, warn=False) == text

    def test_deterministic(self) -> None:
        r1 = redact_pii("alice@example.com", warn=False)
        r2 = redact_pii("alice@example.com", warn=False)
        assert r1 == r2

    def test_different_emails_different_hashes(self) -> None:
        r1 = redact_pii("alice@example.com", warn=False)
        r2 = redact_pii("bob@example.com", warn=False)
        assert r1 != r2

    def test_warns_by_default(self) -> None:
        with pytest.warns(UserWarning):
            redact_pii("alice@example.com")
