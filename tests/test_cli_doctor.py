"""Tests for aegis doctor command and aegis init --quickstart."""

from __future__ import annotations

import subprocess
import sys
from typing import TYPE_CHECKING
from unittest.mock import patch

if TYPE_CHECKING:
    from pathlib import Path


def _run_cli(*args: str, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    """Helper to invoke the Aegis CLI with given arguments."""
    env = {**__import__("os").environ, "PYTHONUTF8": "1"}
    return subprocess.run(
        [sys.executable, "-m", "aegis.cli", *args],
        capture_output=True, text=True, timeout=timeout, env=env,
    )


# ── aegis doctor (CLI integration) ─────────────────────────────────────────


class TestDoctorCli:
    def test_doctor_help_listed(self):
        result = _run_cli("--help")
        assert "doctor" in result.stdout

    def test_doctor_runs_without_crash(self):
        result = _run_cli("doctor")
        assert "Aegis SDK Health Check" in result.stdout
        assert "SDK" in result.stdout


# ── doctor.run_doctor (unit tests with mocks) ─────────────────────────────


class TestRunDoctor:
    def test_config_ok(self, tmp_path: Path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            '[client]\ncanister_id = "test-cid"\napi_key_id = "ak_test"\n'
            'private_key_path = "fake.pem"\n',
            encoding="utf-8",
        )
        with patch("aegis.config._CONFIG_FILE", config_file), \
             patch("aegis.config._CONFIG_DIR", tmp_path):
            from aegis.doctor import run_doctor
            results = run_doctor()

        config_r = next(r for r in results if r["name"] == "Config")
        assert config_r["status"] == "OK"
        assert "test-cid" in config_r["detail"]

    def test_config_missing(self, tmp_path: Path):
        config_file = tmp_path / "nonexistent.toml"
        with patch("aegis.config._CONFIG_FILE", config_file), \
             patch("aegis.config._CONFIG_DIR", tmp_path):
            from aegis.doctor import run_doctor
            results = run_doctor()

        config_r = next(r for r in results if r["name"] == "Config")
        assert config_r["status"] == "FAIL"
        assert "missing" in config_r["detail"].lower() or "empty" in config_r["detail"].lower()

    def test_key_exists(self, tmp_path: Path):
        key_file = tmp_path / "agent_key.pem"
        key_file.write_text("fake-pem-content", encoding="utf-8")
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            f'[client]\ncanister_id = "cid"\napi_key_id = "ak"\n'
            f'private_key_path = "{key_file.as_posix()}"\n',
            encoding="utf-8",
        )
        with patch("aegis.config._CONFIG_FILE", config_file), \
             patch("aegis.config._CONFIG_DIR", tmp_path):
            from aegis.doctor import run_doctor
            results = run_doctor()

        key_r = next(r for r in results if r["name"] == "Private Key")
        assert key_r["status"] == "OK"

    def test_key_missing(self, tmp_path: Path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            '[client]\ncanister_id = "cid"\napi_key_id = "ak"\n'
            'private_key_path = "/nonexistent/key.pem"\n',
            encoding="utf-8",
        )
        with patch("aegis.config._CONFIG_FILE", config_file), \
             patch("aegis.config._CONFIG_DIR", tmp_path):
            from aegis.doctor import run_doctor
            results = run_doctor()

        key_r = next(r for r in results if r["name"] == "Private Key")
        assert key_r["status"] == "FAIL"
        assert "not found" in key_r["detail"].lower()

    def test_canister_unreachable(self, tmp_path: Path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            '[client]\ncanister_id = "fake-cid"\napi_key_id = "ak"\n'
            'private_key_path = "fake.pem"\n',
            encoding="utf-8",
        )
        with (
            patch("aegis.config._CONFIG_FILE", config_file),
            patch("aegis.config._CONFIG_DIR", tmp_path),
            patch("aegis.transport.CanisterTransport.call_query",
                  side_effect=Exception("timeout")),
        ):
            from aegis.doctor import run_doctor
            results = run_doctor()

        canister_r = next(r for r in results if r["name"] == "Canister")
        assert canister_r["status"] == "WARN"
        detail = canister_r["detail"].lower()
        assert "timeout" in detail or "unreachable" in detail

    def test_spill_pending(self, tmp_path: Path):
        spill_dir = tmp_path / "spill"
        spill_dir.mkdir()
        (spill_dir / "entry1.jsonl").write_text("{}", encoding="utf-8")
        (spill_dir / "entry2.jsonl").write_text("{}", encoding="utf-8")
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            '[client]\ncanister_id = "cid"\napi_key_id = "ak"\n'
            'private_key_path = "fake.pem"\n',
            encoding="utf-8",
        )
        with patch("aegis.config._CONFIG_FILE", config_file), \
             patch("aegis.config._CONFIG_DIR", tmp_path):
            from aegis.doctor import run_doctor
            results = run_doctor()

        spill_r = next(r for r in results if r["name"] == "Spill")
        assert spill_r["status"] == "WARN"
        assert "2" in spill_r["detail"]

    def test_sdk_version_present(self, tmp_path: Path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            '[client]\ncanister_id = "cid"\napi_key_id = "ak"\n'
            'private_key_path = "fake.pem"\n',
            encoding="utf-8",
        )
        with patch("aegis.config._CONFIG_FILE", config_file), \
             patch("aegis.config._CONFIG_DIR", tmp_path):
            from aegis.doctor import run_doctor
            results = run_doctor()

        sdk_r = next(r for r in results if r["name"] == "SDK")
        assert sdk_r["status"] == "OK"
        assert sdk_r["detail"].startswith("v")

    def test_doctor_no_secrets_in_output(self, tmp_path: Path):
        """SECURITY: doctor output must not contain private key content."""
        key_file = tmp_path / "agent_key.pem"
        pem = "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----"
        key_file.write_text(pem, encoding="utf-8")
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            f'[client]\ncanister_id = "cid"\napi_key_id = "ak"\n'
            f'private_key_path = "{key_file.as_posix()}"\n',
            encoding="utf-8",
        )
        with patch("aegis.config._CONFIG_FILE", config_file), \
             patch("aegis.config._CONFIG_DIR", tmp_path):
            from aegis.doctor import run_doctor
            results = run_doctor()

        all_output = " ".join(r["detail"] for r in results)
        assert "PRIVATE KEY" not in all_output
        assert "SECRET" not in all_output


# ── doctor --fix auto-repair ──────────────────────────────────────────────


class TestDoctorFix:
    def test_fix_creates_config_when_missing(self, tmp_path: Path):
        """P47-B2: --fix auto-creates minimal config.toml when missing."""
        config_file = tmp_path / "config.toml"
        assert not config_file.exists()
        with patch("aegis.config._CONFIG_FILE", config_file), \
             patch("aegis.config._CONFIG_DIR", tmp_path):
            from aegis.doctor import run_doctor
            results = run_doctor(fix=True)

        assert config_file.exists(), "config.toml should be auto-created"
        config_r = next(r for r in results if r["name"] == "Config")
        assert config_r["status"] == "OK"
        assert "auto-created" in config_r["detail"].lower()
        content = config_file.read_text(encoding="utf-8")
        assert "toqqq-lqaaa-aaaae-afc2a-cai" in content
        assert "ak_" in content

    def test_no_fix_leaves_missing_config_failed(self, tmp_path: Path):
        """Without --fix, missing config stays FAIL and hints at --fix."""
        config_file = tmp_path / "config.toml"
        with patch("aegis.config._CONFIG_FILE", config_file), \
             patch("aegis.config._CONFIG_DIR", tmp_path):
            from aegis.doctor import run_doctor
            results = run_doctor(fix=False)

        config_r = next(r for r in results if r["name"] == "Config")
        assert config_r["status"] == "FAIL"
        assert "--fix" in config_r["detail"]
        assert not config_file.exists()

    def test_fix_generates_key_when_missing(self, tmp_path: Path):
        """P47-B2: --fix auto-generates Ed25519 key when file missing."""
        key_file = tmp_path / "agent_key.pem"
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            f'[client]\ncanister_id = "cid"\napi_key_id = "ak"\n'
            f'private_key_path = "{key_file.as_posix()}"\n',
            encoding="utf-8",
        )
        assert not key_file.exists()
        with patch("aegis.config._CONFIG_FILE", config_file), \
             patch("aegis.config._CONFIG_DIR", tmp_path):
            from aegis.doctor import run_doctor
            results = run_doctor(fix=True)

        assert key_file.exists(), "key file should be auto-generated"
        key_r = next(r for r in results if r["name"] == "Private Key")
        assert key_r["status"] == "OK"
        assert "auto-generated" in key_r["detail"].lower()
        # PEM header sanity
        content = key_file.read_text(encoding="utf-8")
        assert "PRIVATE KEY" in content

    def test_no_fix_leaves_missing_key_failed(self, tmp_path: Path):
        """Without --fix, missing key stays FAIL and hints at --fix."""
        key_file = tmp_path / "nonexistent.pem"
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            f'[client]\ncanister_id = "cid"\napi_key_id = "ak"\n'
            f'private_key_path = "{key_file.as_posix()}"\n',
            encoding="utf-8",
        )
        with patch("aegis.config._CONFIG_FILE", config_file), \
             patch("aegis.config._CONFIG_DIR", tmp_path):
            from aegis.doctor import run_doctor
            results = run_doctor(fix=False)

        key_r = next(r for r in results if r["name"] == "Private Key")
        assert key_r["status"] == "FAIL"
        assert not key_file.exists()


# ── doctor MCP queue check ────────────────────────────────────────────────


class TestDoctorMcpQueue:
    def test_mcp_queue_empty(self, tmp_path: Path):
        """No mcp_queue_*.jsonl files → 0 pending."""
        key_file = tmp_path / "agent_key.pem"
        key_file.write_text("fake-pem-content", encoding="utf-8")
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            f'[client]\ncanister_id = "cid"\napi_key_id = "ak"\n'
            f'private_key_path = "{key_file.as_posix()}"\n',
            encoding="utf-8",
        )
        with patch("aegis.config._CONFIG_FILE", config_file), \
             patch("aegis.config._CONFIG_DIR", tmp_path):
            from aegis.doctor import run_doctor
            results = run_doctor()

        mcp_r = next(r for r in results if r["name"] == "MCP Queue")
        assert mcp_r["status"] == "OK"
        assert "0 pending" in mcp_r["detail"]

    def test_mcp_queue_detects_orphans(self, tmp_path: Path):
        """P47-B2: dead-PID queue files show as orphan WARN."""
        # PID 1 is init on Unix, and on Windows it's the System Idle Process.
        # We use a very high PID that is almost certainly not running.
        dead_pid = 999999
        orphan = tmp_path / f"mcp_queue_{dead_pid}.jsonl"
        orphan.write_text('{"a":1}\n{"a":2}\n', encoding="utf-8")
        key_file = tmp_path / "agent_key.pem"
        key_file.write_text("fake-pem-content", encoding="utf-8")
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            f'[client]\ncanister_id = "cid"\napi_key_id = "ak"\n'
            f'private_key_path = "{key_file.as_posix()}"\n',
            encoding="utf-8",
        )
        with patch("aegis.config._CONFIG_FILE", config_file), \
             patch("aegis.config._CONFIG_DIR", tmp_path):
            from aegis.doctor import run_doctor
            results = run_doctor(fix=False)

        mcp_r = next(r for r in results if r["name"] == "MCP Queue")
        assert mcp_r["status"] == "WARN"
        assert "orphan" in mcp_r["detail"].lower()
        assert "--fix" in mcp_r["detail"]
        # orphan file should still exist (no fix)
        assert orphan.exists()

    def test_mcp_queue_fix_adopts_orphans(self, tmp_path: Path):
        """P47-B2: --fix merges orphan queues into mcp_queue_recovered.jsonl."""
        dead_pid = 999999
        orphan = tmp_path / f"mcp_queue_{dead_pid}.jsonl"
        orphan.write_text('{"a":1}\n{"a":2}\n{"a":3}\n', encoding="utf-8")
        key_file = tmp_path / "agent_key.pem"
        key_file.write_text("fake-pem-content", encoding="utf-8")
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            f'[client]\ncanister_id = "cid"\napi_key_id = "ak"\n'
            f'private_key_path = "{key_file.as_posix()}"\n',
            encoding="utf-8",
        )
        with patch("aegis.config._CONFIG_FILE", config_file), \
             patch("aegis.config._CONFIG_DIR", tmp_path):
            from aegis.doctor import run_doctor
            results = run_doctor(fix=True)

        mcp_r = next(r for r in results if r["name"] == "MCP Queue")
        assert mcp_r["status"] == "OK"
        assert "adopted" in mcp_r["detail"].lower()
        # orphan file gone, recovered file contains entries
        assert not orphan.exists()
        recovered = tmp_path / "mcp_queue_recovered.jsonl"
        assert recovered.exists()
        content = recovered.read_text(encoding="utf-8").strip()
        assert content.count("\n") + 1 == 3


# ── aegis init --quickstart ────────────────────────────────────────────────


class TestInitQuickstart:
    def test_quickstart_no_input_required(self, tmp_path: Path):
        """--quickstart must not call input() — runs with /dev/null stdin."""
        result = subprocess.run(
            [sys.executable, "-m", "aegis.cli", "init", "--quickstart"],
            capture_output=True, text=True, timeout=30,
            env={
                **__import__("os").environ,
                "PYTHONUTF8": "1",
                "AEGIS_CONFIG_DIR": str(tmp_path),
            },
            stdin=subprocess.DEVNULL,
        )
        # Should not hang or crash due to missing stdin
        assert "Aegis SDK Setup" in result.stdout
        assert "quickstart" in result.stdout.lower()

    def test_quickstart_writes_config(self, tmp_path: Path):
        """--quickstart must write config.toml."""
        subprocess.run(
            [sys.executable, "-m", "aegis.cli", "init", "--quickstart"],
            capture_output=True, text=True, timeout=30,
            env={
                **__import__("os").environ,
                "PYTHONUTF8": "1",
                "AEGIS_CONFIG_DIR": str(tmp_path),
            },
            stdin=subprocess.DEVNULL,
        )
        config_path = tmp_path / "config.toml"
        assert config_path.exists(), "config.toml should be created"
        content = config_path.read_text(encoding="utf-8")
        assert "canister_id" in content
        assert "api_key_id" in content
