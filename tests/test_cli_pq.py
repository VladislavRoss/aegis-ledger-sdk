"""Tests for aegis register-key and revoke CLI commands."""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest


def _run_cli(*args: str) -> None:
    """Invoke aegis CLI main() with given args."""
    from aegis.cli import main
    with patch.object(sys, 'argv', ['aegis', *args]):
        main()


class TestRegisterKey:
    """Tests for aegis register-key."""

    def test_register_key_missing_args(self):
        with pytest.raises(SystemExit, match="1"):
            _run_cli('register-key')

    def test_register_key_missing_key_file(self):
        with pytest.raises(SystemExit, match="1"):
            _run_cli('register-key', 'ak_test')

    def test_register_key_file_not_found(self):
        with pytest.raises(SystemExit, match="1"):
            _run_cli('register-key', 'ak_test', '--key-file', '/nonexistent/key.pem')

    def test_register_key_ed25519(self, tmp_path):
        """Ed25519 key file with PoP computed, registered headlessly."""
        from aegis.crypto import generate_keypair
        key_path = tmp_path / "agent.pem"
        generate_keypair(str(key_path))

        with patch('aegis.cli_init._derive_principal_from_pem', return_value='test-principal'), \
             patch('aegis.cli_init._call_accept_dpa', return_value=None), \
             patch('aegis.cli_init._call_create_api_key', return_value={}):
            _run_cli('register-key', 'ak_test_ed', '--key-file', str(key_path))

    def test_register_key_algo_mismatch(self, tmp_path):
        """PEM file + --algorithm ml-dsa-65 results in error."""
        from aegis.crypto import generate_keypair
        key_path = tmp_path / "agent.pem"
        generate_keypair(str(key_path))

        with pytest.raises(SystemExit, match="1"):
            _run_cli(
                'register-key', 'ak_test',
                '--key-file', str(key_path), '--algorithm', 'ml-dsa-65',
            )

    def test_register_key_auto_detect_algo(self, tmp_path):
        """Extension .pem auto-detects ed25519."""
        from aegis.crypto import generate_keypair
        key_path = tmp_path / "agent.pem"
        generate_keypair(str(key_path))

        with patch('aegis.cli_init._derive_principal_from_pem', return_value='test-principal'), \
             patch('aegis.cli_init._call_accept_dpa', return_value=None), \
             patch('aegis.cli_init._call_create_api_key', return_value={}):
            _run_cli('register-key', 'ak_auto', '--key-file', str(key_path))

    def test_register_key_pub_missing(self, tmp_path):
        """Key file exists but .pub missing results in error."""
        key_path = tmp_path / "agent.pem"
        key_path.write_text("fake key")

        with pytest.raises(SystemExit, match="1"):
            _run_cli('register-key', 'ak_nopub', '--key-file', str(key_path))


class TestRevoke:
    """Tests for aegis revoke."""

    def test_revoke_missing_args(self):
        with pytest.raises(SystemExit, match="1"):
            _run_cli('revoke')

    def test_revoke_with_confirm(self):
        """Input 'yes' opens dashboard."""
        with patch('builtins.input', return_value='yes'), \
             patch('webbrowser.open') as wb_open:
            _run_cli('revoke', 'ak_old_key')
            wb_open.assert_called_once()

    def test_revoke_abort(self, capsys):
        """Input 'no' aborts without opening browser."""
        with patch('builtins.input', return_value='no'), \
             patch('webbrowser.open') as wb_open:
            _run_cli('revoke', 'ak_keep')
            wb_open.assert_not_called()
            out = capsys.readouterr().out
            assert 'Aborted' in out

    def test_revoke_empty_input(self, capsys):
        """Empty input aborts."""
        with patch('builtins.input', return_value=''), \
             patch('webbrowser.open') as wb_open:
            _run_cli('revoke', 'ak_empty')
            wb_open.assert_not_called()
