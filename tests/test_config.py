"""Tests for aegis.config — user-level configuration."""

from AEGIS_LEDGER.config import (
    _VALID_SCHEMES,
    get_default_scheme,
    get_signing_key_path,
    load_config,
)


class TestLoadConfig:
    """Test load_config()."""

    def test_missing_file_returns_empty(self, tmp_path):
        cfg = load_config(config_path=tmp_path / "nonexistent.toml")
        assert cfg == {}

    def test_valid_toml(self, tmp_path):
        f = tmp_path / "config.toml"
        f.write_text('[signing]\ndefault_scheme = "hybrid"\n', encoding="utf-8")
        cfg = load_config(config_path=f)
        assert cfg["signing"]["default_scheme"] == "hybrid"

    def test_invalid_toml_returns_empty(self, tmp_path):
        f = tmp_path / "config.toml"
        f.write_text("this is not valid toml {{{{", encoding="utf-8")
        cfg = load_config(config_path=f)
        assert cfg == {}

    def test_empty_file_returns_empty(self, tmp_path):
        f = tmp_path / "config.toml"
        f.write_text("", encoding="utf-8")
        cfg = load_config(config_path=f)
        assert cfg == {}


class TestGetDefaultScheme:
    """Test get_default_scheme()."""

    def test_no_config_returns_ed25519(self):
        assert get_default_scheme({}) == "ed25519"

    def test_ed25519_explicit(self):
        cfg = {"signing": {"default_scheme": "ed25519"}}
        assert get_default_scheme(cfg) == "ed25519"

    def test_hybrid(self):
        cfg = {"signing": {"default_scheme": "hybrid"}}
        assert get_default_scheme(cfg) == "hybrid"

    def test_mldsa65(self):
        cfg = {"signing": {"default_scheme": "ml-dsa-65"}}
        assert get_default_scheme(cfg) == "ml-dsa-65"

    def test_invalid_scheme_falls_back_to_ed25519(self):
        cfg = {"signing": {"default_scheme": "rsa-4096"}}
        assert get_default_scheme(cfg) == "ed25519"

    def test_missing_signing_section(self):
        cfg = {"other": {"key": "value"}}
        assert get_default_scheme(cfg) == "ed25519"

    def test_signing_not_dict_falls_back(self):
        cfg = {"signing": "invalid"}
        assert get_default_scheme(cfg) == "ed25519"

    def test_from_file(self, tmp_path):
        f = tmp_path / "config.toml"
        f.write_text('[signing]\ndefault_scheme = "hybrid"\n', encoding="utf-8")
        cfg = load_config(config_path=f)
        assert get_default_scheme(cfg) == "hybrid"


class TestGetSigningKeyPath:
    """Test get_signing_key_path()."""

    def test_no_config_returns_none(self):
        assert get_signing_key_path({}) is None

    def test_path_present(self):
        cfg = {"signing": {"signing_key_path": "./keys/agent.mldsa65"}}
        assert get_signing_key_path(cfg) == "./keys/agent.mldsa65"

    def test_missing_key_returns_none(self):
        cfg = {"signing": {"default_scheme": "hybrid"}}
        assert get_signing_key_path(cfg) is None

    def test_signing_not_dict_returns_none(self):
        cfg = {"signing": 42}
        assert get_signing_key_path(cfg) is None


class TestValidSchemes:
    """Test _VALID_SCHEMES constant."""

    def test_all_five_schemes(self):
        assert {"ed25519", "ml-dsa-65", "ml-dsa-87", "slh-dsa-128s", "hybrid"} == _VALID_SCHEMES


class TestClientConfigIntegration:
    """Test that AegisClient respects config file defaults."""

    def test_client_default_still_ed25519_without_config(self, tmp_path, monkeypatch):
        """Without config file, default stays ed25519."""
        import AEGIS_LEDGER.config as config_mod

        monkeypatch.setattr(config_mod, "_CONFIG_FILE", tmp_path / "nope.toml")
        try:
            import aegis.config as aegis_config_mod

            monkeypatch.setattr(
                aegis_config_mod, "_CONFIG_FILE", tmp_path / "nope.toml"
            )
        except ImportError:
            pass
        from AEGIS_LEDGER.crypto import generate_keypair

        pem = tmp_path / "key.pem"
        generate_keypair(pem)

        from AEGIS_LEDGER.client import AegisClient

        client = AegisClient(
            canister_id="aaaaa-aa",
            api_key_id="ak_test",
            private_key_path=str(pem),
            agent_id="test_agent",
        )
        assert client._scheme.algorithm_id == "ed25519"

    def test_client_reads_hybrid_from_config(self, tmp_path, monkeypatch):
        """Config file default_scheme=hybrid is picked up by AegisClient."""
        from AEGIS_LEDGER.crypto import generate_keypair, generate_mldsa65_keypair

        pem = tmp_path / "key.pem"
        generate_keypair(pem)

        mldsa = tmp_path / "key.mldsa65"
        generate_mldsa65_keypair(mldsa)

        cfg_file = tmp_path / "config.toml"
        # Use forward slashes to avoid TOML backslash escaping
        mldsa_posix = str(mldsa).replace("\\", "/")
        cfg_file.write_text(
            f'[signing]\ndefault_scheme = "hybrid"\n'
            f'signing_key_path = "{mldsa_posix}"\n',
            encoding="utf-8",
        )

        # Patch _CONFIG_FILE on both module references (aegis.* and AEGIS_LEDGER.*)
        import AEGIS_LEDGER.config as config_mod

        monkeypatch.setattr(config_mod, "_CONFIG_FILE", cfg_file)
        try:
            import aegis.config as aegis_config_mod

            monkeypatch.setattr(aegis_config_mod, "_CONFIG_FILE", cfg_file)
        except ImportError:
            pass

        from AEGIS_LEDGER.client import AegisClient

        client = AegisClient(
            canister_id="aaaaa-aa",
            api_key_id="ak_test",
            private_key_path=str(pem),
            agent_id="test_agent",
        )
        assert client._scheme.algorithm_id == "hybrid"

    def test_explicit_scheme_overrides_config(self, tmp_path, monkeypatch):
        """Explicit signature_scheme= always wins over config."""
        import AEGIS_LEDGER.config as config_mod

        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text(
            '[signing]\ndefault_scheme = "hybrid"\n', encoding="utf-8"
        )
        monkeypatch.setattr(config_mod, "_CONFIG_FILE", cfg_file)
        try:
            import aegis.config as aegis_config_mod

            monkeypatch.setattr(aegis_config_mod, "_CONFIG_FILE", cfg_file)
        except ImportError:
            pass

        from AEGIS_LEDGER.crypto import generate_keypair

        pem = tmp_path / "key.pem"
        generate_keypair(pem)

        from AEGIS_LEDGER.client import AegisClient

        client = AegisClient(
            canister_id="aaaaa-aa",
            api_key_id="ak_test",
            private_key_path=str(pem),
            agent_id="test_agent",
            signature_scheme="ed25519",
        )
        assert client._scheme.algorithm_id == "ed25519"

    def test_explicit_ed25519_skips_config_read(self, tmp_path):
        """Explicit signature_scheme='ed25519' must not read config at all."""
        from unittest.mock import patch

        from AEGIS_LEDGER.crypto import generate_keypair

        pem = tmp_path / "key.pem"
        generate_keypair(pem)

        with patch("aegis.client.load_config") as mock_cfg:
            from AEGIS_LEDGER.client import AegisClient

            AegisClient(
                canister_id="aaaaa-aa",
                api_key_id="ak_test",
                private_key_path=str(pem),
                agent_id="test_agent",
                signature_scheme="ed25519",
            )
            mock_cfg.assert_not_called()
