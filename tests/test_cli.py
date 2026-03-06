"""Tests for aegis.cli — CLI command parsing and help output."""

import subprocess
import sys

import pytest


class TestCliHelp:
    def test_help_flag(self):
        result = subprocess.run(
            [sys.executable, "-m", "AEGIS_LEDGER.cli", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "aegis-ledger-sdk" in result.stdout
        assert "keygen" in result.stdout
        assert "verify" in result.stdout
        assert "status" in result.stdout

    def test_no_args_shows_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "AEGIS_LEDGER.cli"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "Commands:" in result.stdout


class TestCliUnknownCommand:
    def test_unknown_command_exits_1(self):
        result = subprocess.run(
            [sys.executable, "-m", "AEGIS_LEDGER.cli", "nonexistent"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 1
        assert "Unknown command" in result.stdout


class TestCliKeygen:
    def test_keygen_missing_path_exits_1(self):
        result = subprocess.run(
            [sys.executable, "-m", "AEGIS_LEDGER.cli", "keygen"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 1
        assert "Usage:" in result.stdout

    def test_keygen_creates_key(self, tmp_path):
        key_path = tmp_path / "test_key.pem"
        env = {**__import__("os").environ, "PYTHONUTF8": "1"}
        result = subprocess.run(
            [sys.executable, "-m", "AEGIS_LEDGER.cli", "keygen", str(key_path)],
            capture_output=True, text=True, timeout=10, env=env,
        )
        assert result.returncode == 0
        assert key_path.exists()
        assert (tmp_path / "test_key.pub").exists()
        assert "Public key (hex)" in result.stdout

    def test_keygen_existing_file_errors(self, tmp_path):
        key_path = tmp_path / "existing.pem"
        key_path.write_text("existing")
        result = subprocess.run(
            [sys.executable, "-m", "AEGIS_LEDGER.cli", "keygen", str(key_path)],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 1


class TestCliVerify:
    def test_verify_missing_args(self):
        result = subprocess.run(
            [sys.executable, "-m", "AEGIS_LEDGER.cli", "verify"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 1
        assert "Usage:" in result.stdout

    def test_verify_one_arg_missing(self):
        result = subprocess.run(
            [sys.executable, "-m", "AEGIS_LEDGER.cli", "verify", "canister-id"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 1


class TestCliStatus:
    def test_status_missing_args(self):
        result = subprocess.run(
            [sys.executable, "-m", "AEGIS_LEDGER.cli", "status"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 1
        assert "Usage:" in result.stdout
