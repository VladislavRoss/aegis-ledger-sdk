"""Tests for aegis.errors — error translation and typed exceptions."""

from __future__ import annotations

from unittest.mock import patch

from aegis.errors import (
    AegisAuthError,
    AegisConfigError,
    AegisError,
    AegisTransportError,
    CanisterError,
    translate_error,
)


class TestTranslateError:
    """Test translate_error() maps known patterns to typed exceptions."""

    def test_key_not_found(self):
        err = translate_error("Key not found", key_id="ak_test123")
        assert isinstance(err, AegisAuthError)
        assert "ak_test123" in str(err)
        assert "aegis doctor" in str(err)

    def test_key_revoked(self):
        err = translate_error("Key revoked for org xyz", key_id="ak_old")
        assert isinstance(err, AegisAuthError)
        assert "ak_old" in str(err)
        assert "Dashboard" in str(err)

    def test_rate_limited(self):
        err = translate_error("Rate limited: too many calls")
        assert isinstance(err, AegisTransportError)
        assert "100/s" in str(err)

    def test_anonymous_caller(self):
        err = translate_error("Anonymous caller not allowed")
        assert isinstance(err, AegisAuthError)
        assert "aegis init" in str(err)

    def test_dpa_not_accepted(self):
        err = translate_error("DPA not accepted for this org")
        assert isinstance(err, AegisAuthError)
        assert "Dashboard" in str(err)

    def test_monthly_limit(self):
        err = translate_error("Monthly limit exceeded")
        assert isinstance(err, AegisTransportError)
        assert "aegis-ledger.com" in str(err)

    def test_unknown_error_truncated(self):
        long_msg = "x" * 100
        err = translate_error(long_msg)
        assert isinstance(err, AegisError)
        assert not isinstance(err, (AegisAuthError, AegisTransportError, AegisConfigError))
        assert "aegis doctor" in str(err)
        # Must be truncated to 50 chars + "..."
        assert "x" * 50 in str(err)
        assert "x" * 51 not in str(err)
        assert "..." in str(err)

    def test_unknown_error_short(self):
        err = translate_error("Something broke")
        assert isinstance(err, AegisError)
        assert "Something broke" in str(err)
        assert "..." not in str(err)

    def test_case_insensitive_matching(self):
        err = translate_error("KEY NOT FOUND", key_id="ak_upper")
        assert isinstance(err, AegisAuthError)


class TestAutoSession:
    """Test that from_config() always provides a session_id."""

    def test_auto_session_from_config(self, tmp_path):
        """from_config() without session_id => auto-generated sess_ prefix."""
        config_toml = tmp_path / "config.toml"
        config_toml.write_text(
            '[client]\n'
            'canister_id = "toqqq-lqaaa-aaaae-afc2a-cai"\n'
            'api_key_id = "ak_test"\n'
            f'private_key_path = "{(tmp_path / "key.pem").as_posix()}"\n'
            'agent_id = "test-agent"\n'
            'org_id = "aaaaa-aa"\n'
        )
        # Create a dummy PEM key
        from aegis.crypto import generate_keypair
        pk_path = tmp_path / "key.pem"
        generate_keypair(str(pk_path))

        # Mock transport to avoid real IC calls
        with patch("aegis.client.CanisterTransport"):
            from aegis.client import AegisClient
            client = AegisClient.from_config(config_path=str(config_toml))
            assert client.session_id is not None
            assert client.session_id.startswith("sess_")
            assert len(client.session_id) > 5

    def test_auto_session_explicit_override(self, tmp_path):
        """Explicit session_id overrides auto-generation."""
        config_toml = tmp_path / "config.toml"
        config_toml.write_text(
            '[client]\n'
            'canister_id = "toqqq-lqaaa-aaaae-afc2a-cai"\n'
            'api_key_id = "ak_test"\n'
            f'private_key_path = "{(tmp_path / "key.pem").as_posix()}"\n'
            'agent_id = "test-agent"\n'
            'org_id = "aaaaa-aa"\n'
        )
        from aegis.crypto import generate_keypair
        pk_path = tmp_path / "key.pem"
        generate_keypair(str(pk_path))

        with patch("aegis.client.CanisterTransport"):
            from aegis.client import AegisClient
            client = AegisClient.from_config(
                config_path=str(config_toml),
                session_id="ses_custom_123",
            )
            assert client.session_id == "ses_custom_123"

    def test_constructor_auto_session(self, tmp_path):
        """AegisClient() with session_id=None auto-generates."""
        from aegis.crypto import generate_keypair
        pk_path = tmp_path / "key.pem"
        generate_keypair(str(pk_path))

        with patch("aegis.client.CanisterTransport"):
            from aegis.client import AegisClient
            client = AegisClient(
                canister_id="toqqq-lqaaa-aaaae-afc2a-cai",
                api_key_id="ak_test",
                private_key_path=str(pk_path),
                agent_id="test-agent",
            )
            assert client.session_id.startswith("sess_")


class TestErrorInheritance:
    """Ensure exception hierarchy is correct."""

    def test_auth_error_is_aegis_error(self):
        assert issubclass(AegisAuthError, AegisError)

    def test_config_error_is_aegis_error(self):
        assert issubclass(AegisConfigError, AegisError)

    def test_transport_error_is_aegis_error(self):
        assert issubclass(AegisTransportError, AegisError)

    def test_canister_error_is_aegis_error(self):
        assert issubclass(CanisterError, AegisError)

    def test_canister_error_has_code(self):
        err = CanisterError("test", error_code="TEST_CODE")
        assert err.error_code == "TEST_CODE"
        assert "TEST_CODE" in str(err)


class TestBackwardCompat:
    """Ensure existing imports still work."""

    def test_import_from_transport(self):
        from aegis.transport import AegisError as AegisErr
        from aegis.transport import CanisterError as CanErr
        assert AegisErr is AegisError
        assert CanErr is CanisterError

    def test_import_from_init(self):
        from aegis import AegisError as AegisErr
        from aegis import CanisterError as CanErr
        assert AegisErr is AegisError
        assert CanErr is CanisterError
