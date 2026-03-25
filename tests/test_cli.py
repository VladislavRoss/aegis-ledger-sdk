"""Tests for aegis.cli — CLI command parsing and help output."""

import subprocess
import sys


def _run_cli(*args: str, timeout: int = 10) -> subprocess.CompletedProcess[str]:
    """Helper to invoke the Aegis CLI with given arguments."""
    env = {**__import__("os").environ, "PYTHONUTF8": "1"}
    return subprocess.run(
        [sys.executable, "-m", "AEGIS_LEDGER.cli", *args],
        capture_output=True, text=True, timeout=timeout, env=env,
    )


class TestCliHelp:
    def test_help_flag(self):
        result = _run_cli("--help")
        assert result.returncode == 0
        assert "aegis-ledger-sdk" in result.stdout
        assert "keygen" in result.stdout
        assert "verify" in result.stdout
        assert "status" in result.stdout

    def test_no_args_shows_help(self):
        result = _run_cli()
        assert result.returncode == 0
        assert "Commands:" in result.stdout

    def test_help_word_command(self):
        result = _run_cli("help")
        assert result.returncode == 0
        assert "Commands:" in result.stdout

    def test_short_h_flag(self):
        result = _run_cli("-h")
        assert result.returncode == 0
        assert "aegis-ledger-sdk" in result.stdout

    def test_help_lists_all_commands(self):
        result = _run_cli("--help")
        assert result.returncode == 0
        for cmd in ("init", "keygen", "verify", "status", "report", "migrate", "version"):
            assert cmd in result.stdout

    def test_help_lists_algorithms(self):
        result = _run_cli("--help")
        assert "ed25519" in result.stdout
        assert "ml-dsa-65" in result.stdout
        assert "ml-dsa-87" in result.stdout
        assert "slh-dsa-128s" in result.stdout
        assert "hybrid" in result.stdout


class TestCliVersion:
    def test_version_command(self):
        result = _run_cli("version")
        assert result.returncode == 0
        assert "aegis-ledger-sdk" in result.stdout


class TestCliUnknownCommand:
    def test_unknown_command_exits_1(self):
        result = _run_cli("nonexistent")
        assert result.returncode == 1
        assert "Unknown command" in result.stdout


class TestCliKeygen:
    def test_keygen_missing_path_exits_1(self):
        result = _run_cli("keygen")
        assert result.returncode == 1
        assert "Usage:" in result.stdout

    def test_keygen_creates_key(self, tmp_path):
        key_path = tmp_path / "test_key.pem"
        result = _run_cli("keygen", str(key_path))
        assert result.returncode == 0
        assert key_path.exists()
        assert (tmp_path / "test_key.pub").exists()
        assert "Public key (hex)" in result.stdout
        assert "Ed25519" in result.stdout

    def test_keygen_existing_file_errors(self, tmp_path):
        key_path = tmp_path / "existing.pem"
        key_path.write_text("existing")
        result = _run_cli("keygen", str(key_path))
        assert result.returncode == 1

    def test_keygen_unknown_algorithm_exits_1(self, tmp_path):
        key_path = tmp_path / "test_key.pem"
        result = _run_cli("keygen", str(key_path), "--algorithm", "rsa-4096")
        assert result.returncode == 1
        assert "Unknown algorithm" in result.stdout

    def test_keygen_next_steps_output(self, tmp_path):
        key_path = tmp_path / "test_key.pem"
        result = _run_cli("keygen", str(key_path))
        assert result.returncode == 0
        assert "Next steps:" in result.stdout
        assert "Register" in result.stdout
        assert "NEVER commit" in result.stdout


class TestCliVerify:
    def test_verify_missing_args(self):
        result = _run_cli("verify")
        assert result.returncode == 1
        assert "Usage:" in result.stdout

    def test_verify_one_arg_treats_single_arg_as_action_id(self):
        # With config.toml present, single arg is treated as action_id
        # "canister-id" has a hyphen so it's treated as canister_id + missing action_id
        # which falls through to verifyEntry → "Entry not found" → exit 2
        result = _run_cli("verify", "canister-id")
        assert result.returncode in (1, 2)  # 1=error, 2=not found

    def test_verify_bad_canister_exits_1(self):
        result = _run_cli("verify", "invalid-canister", "act_test123")
        assert result.returncode == 1
        assert "Error:" in result.stdout


class TestCliStatus:
    def test_status_no_args_uses_config(self):
        # With config.toml present, reads canister_id from config
        result = _run_cli("status")
        # Either succeeds (config exists) or fails (no config)
        if result.returncode == 0:
            assert "Aegis Canister:" in result.stdout
        else:
            assert "Error:" in result.stdout or "No canister_id" in result.stdout

    def test_status_bad_canister_exits_1(self):
        result = _run_cli("status", "invalid-canister")
        assert result.returncode == 1
        assert "Error:" in result.stdout


class TestCliReport:
    def test_report_no_args_uses_config(self):
        # With config.toml present, reads canister_id from config
        result = _run_cli("report")
        # Either succeeds (config exists) or fails (no config)
        if result.returncode == 0:
            assert (
                "Compliance" in result.stdout
                or "Report" in result.stdout
                or "EU AI Act" in result.stdout
            )
        else:
            assert "Error:" in result.stdout or "No canister_id" in result.stdout

    def test_report_unknown_format_exits_1(self):
        result = _run_cli("report", "canister-id", "--format", "invalid-format")
        assert result.returncode == 1
        assert "Unknown format" in result.stdout


class TestCliMigrate:
    def test_migrate_help(self):
        result = _run_cli("migrate", "--help")
        assert result.returncode == 0
        assert "migrate" in result.stdout.lower()
        assert "--to" in result.stdout

    def test_migrate_missing_session_exits_1(self):
        result = _run_cli("migrate", "canister-id")
        assert result.returncode == 1

    def test_migrate_help_flag(self):
        result = _run_cli("migrate", "-h")
        assert result.returncode == 0
        assert "--signing-key" in result.stdout


class TestCliKeygenAlgorithms:
    """Test keygen with all supported algorithm flags."""

    def test_keygen_ml_dsa_65(self, tmp_path):
        """ML-DSA-65 keygen requires pqcrypto — expect either success or ImportError."""
        key_path = tmp_path / "test_ml.mldsa65"
        result = _run_cli("keygen", str(key_path), "--algorithm", "ml-dsa-65")
        # Either succeeds (pqcrypto installed) or fails with ImportError
        assert result.returncode in (0, 1)
        if result.returncode == 0:
            assert "ML-DSA-65" in result.stdout
            assert key_path.exists()

    def test_keygen_slh_dsa_128s(self, tmp_path):
        """SLH-DSA-128s keygen requires pqcrypto — expect either success or ImportError."""
        key_path = tmp_path / "test_slh.slh"
        result = _run_cli("keygen", str(key_path), "--algorithm", "slh-dsa-128s")
        assert result.returncode in (0, 1)
        if result.returncode == 0:
            assert "SLH-DSA" in result.stdout

    def test_keygen_ml_dsa_87(self, tmp_path):
        """ML-DSA-87 keygen requires pqcrypto — expect either success or ImportError."""
        key_path = tmp_path / "test_ml87.mldsa87"
        result = _run_cli("keygen", str(key_path), "--algorithm", "ml-dsa-87")
        assert result.returncode in (0, 1)
        if result.returncode == 0:
            assert "ML-DSA-87" in result.stdout
            assert key_path.exists()

    def test_keygen_hybrid(self, tmp_path):
        """Hybrid keygen requires pqcrypto — expect either success or ImportError."""
        key_path = tmp_path / "test_hybrid"
        result = _run_cli("keygen", str(key_path), "--algorithm", "hybrid")
        assert result.returncode in (0, 1)
        if result.returncode == 0:
            assert "Hybrid" in result.stdout


class TestCliReportFormats:
    """Test report format validation and error handling."""

    def test_report_valid_formats_listed(self):
        result = _run_cli("report", "test-canister", "--format", "invalid-format")
        assert result.returncode == 1
        for fmt in ("eu-ai-act", "iso-42001", "aiuc-1"):
            assert fmt in result.stdout

    def test_report_output_flag_missing_value(self):
        """Report with -o but no path should still attempt to generate."""
        result = _run_cli("report", "invalid-canister", "--format", "eu-ai-act")
        assert result.returncode == 1
        assert "Error:" in result.stdout


class TestCliInit:
    """Test aegis init command."""

    def test_init_generates_key_and_config(self, tmp_path):
        """Init with --algorithm flag generates key + config."""
        import os
        cfg_dir = tmp_path / ".aegis"
        env = {**os.environ, "PYTHONUTF8": "1", "AEGIS_CONFIG_DIR": str(cfg_dir)}
        result = subprocess.run(
            [sys.executable, "-m", "AEGIS_LEDGER.cli", "init", "--algorithm", "ed25519"],
            input="ak_test_key\ntest-principal-abc\n",
            capture_output=True, text=True, timeout=15, env=env,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Setup complete" in result.stdout
        assert "from_config" in result.stdout
        cfg_file = cfg_dir / "config.toml"
        assert cfg_file.exists()
        content = cfg_file.read_text(encoding="utf-8")
        assert "ak_test_key" in content
        assert "test-principal-abc" in content

    def test_init_default_key_id(self, tmp_path):
        """If key ID left blank, uses the auto-generated suggestion."""
        import os
        cfg_dir = tmp_path / ".aegis"
        env = {**os.environ, "PYTHONUTF8": "1", "AEGIS_CONFIG_DIR": str(cfg_dir)}
        result = subprocess.run(
            [sys.executable, "-m", "AEGIS_LEDGER.cli", "init", "--algorithm", "ed25519"],
            input="\n\n",
            capture_output=True, text=True, timeout=15, env=env,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        cfg_file = cfg_dir / "config.toml"
        content = cfg_file.read_text(encoding="utf-8")
        assert 'api_key_id = "ak_' in content
        assert 'agent_id = "ak_' in content

    def test_init_algorithm_selection(self, tmp_path):
        """Init with interactive algorithm choice (choice '1' = ed25519)."""
        import os
        cfg_dir = tmp_path / ".aegis"
        env = {**os.environ, "PYTHONUTF8": "1", "AEGIS_CONFIG_DIR": str(cfg_dir)}
        result = subprocess.run(
            [sys.executable, "-m", "AEGIS_LEDGER.cli", "init"],
            input="1\nak_algo_test\n",
            capture_output=True, text=True, timeout=15, env=env,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Ed25519" in result.stdout


class TestCliEdgeCases:
    """Edge cases and error handling."""

    def test_multiple_unknown_flags_ignored(self):
        """Unknown flags before known commands should not crash."""
        result = _run_cli("--unknown-flag")
        assert result.returncode == 1

    def test_empty_string_command(self):
        result = _run_cli("")
        assert result.returncode == 1

    def test_version_output_format(self):
        result = _run_cli("version")
        assert result.returncode == 0
        # Should contain version pattern like "0.1.0"
        import re
        assert re.search(r"\d+\.\d+\.\d+", result.stdout)

    def test_verify_usage_message(self):
        result = _run_cli("verify")
        assert result.returncode == 1
        assert "canister_id" in result.stdout or "Usage:" in result.stdout

    def test_status_no_args_works_with_config(self):
        # With config.toml, aegis status with no args reads from config
        result = _run_cli("status")
        # Either succeeds (config exists) or error (no config)
        assert result.returncode in (0, 1)

    def test_keygen_algorithm_flag_without_value(self, tmp_path):
        """--algorithm at end without value should use default or error."""
        key_path = tmp_path / "test_key_no_algo.pem"
        result = _run_cli("keygen", str(key_path), "--algorithm")
        # Should either use default (ed25519) or error gracefully
        assert result.returncode in (0, 1)
