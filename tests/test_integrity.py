"""Tests for client-side integrity snapshots and verify_integrity()."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

from aegis.types import Environment
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

if TYPE_CHECKING:
    from pathlib import Path


def _make_client(tmp_path: Path):
    """Create AegisClient with mocked transport, snapshot dir in tmp_path."""
    spill_dir = tmp_path / "spill"
    spill_dir.mkdir()

    with (
        patch("aegis.client.load_private_key", return_value=Ed25519PrivateKey.generate()),
        patch("aegis.client.load_config", return_value={}),
        patch("aegis.client.CanisterTransport") as MockTransport,
    ):
        mock_transport = MockTransport.return_value
        mock_transport.call_update.return_value = {"actionId": "act_test123"}
        mock_transport.spill_count = 0
        mock_transport.drain_spill_buffer.return_value = 0
        mock_transport._config = MagicMock()
        mock_transport._config.spill_dir = spill_dir

        from aegis.client import AegisClient

        client = AegisClient(
            canister_id="test-canister-id",
            api_key_id="ak_test",
            private_key_path="./fake_key.pem",
            agent_id="test-agent",
            org_id="un4fu-tqaaa-aaaab-qadjq-cai",
            session_id="test-session",
            environment=Environment(framework="test"),
        )
        return client, mock_transport


class TestSnapshotWrite:
    def test_snapshot_written_after_log(self, tmp_path):
        client, _ = _make_client(tmp_path)
        client.log_tool_call("search", {"q": "test"}, {"r": "ok"}, 100)

        snapshot_path = tmp_path / "snapshots" / "test-canister-id.jsonl"
        assert snapshot_path.exists()
        lines = snapshot_path.read_text().strip().splitlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["action_id"] == "act_test123"
        assert "chain_hash" in data
        assert data["session_id"] == "test-session"
        assert "ts" in data

    def test_multiple_logs_append(self, tmp_path):
        client, mock = _make_client(tmp_path)
        mock.call_update.side_effect = [
            {"actionId": "act_first"},
            {"actionId": "act_second"},
        ]
        client.log_tool_call("a", {}, {}, 10)
        client.log_tool_call("b", {}, {}, 20)

        snapshot_path = tmp_path / "snapshots" / "test-canister-id.jsonl"
        lines = snapshot_path.read_text().strip().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["action_id"] == "act_first"
        assert json.loads(lines[1])["action_id"] == "act_second"

    def test_snapshot_fail_open(self, tmp_path):
        client, _ = _make_client(tmp_path)
        # Make snapshots dir a file so mkdir fails
        bad_path = tmp_path / "snapshots"
        bad_path.mkdir(parents=True, exist_ok=True)
        marker = bad_path / "test-canister-id.jsonl"
        marker.mkdir()  # dir instead of file — write will fail

        # Should not raise
        result = client.log_tool_call("tool", {}, {}, 50)
        assert result == "act_test123"


class TestVerifyIntegrity:
    def _seed_snapshots(self, tmp_path, entries):
        snap_dir = tmp_path / "snapshots"
        snap_dir.mkdir(parents=True, exist_ok=True)
        p = snap_dir / "test-canister-id.jsonl"
        with open(p, "w") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

    def test_empty_snapshots(self, tmp_path):
        client, _ = _make_client(tmp_path)
        result = client.verify_integrity()
        assert result["total"] == 0
        assert result["sampled"] == 0

    def test_all_valid(self, tmp_path):
        client, mock = _make_client(tmp_path)
        entries = [
            {"action_id": f"act_{i}", "chain_hash": f"hash_{i}", "session_id": "s", "ts": i}
            for i in range(5)
        ]
        self._seed_snapshots(tmp_path, entries)

        def mock_query(method, args):
            aid = args[0]["value"]
            idx = int(aid.split("_")[1])
            return {"isValid": True, "storedChainHash": f"hash_{idx}"}

        mock.call_query = mock_query

        result = client.verify_integrity(sample_size=5)
        assert result["total"] == 5
        assert result["sampled"] == 5
        assert result["valid"] == 5
        assert result["mismatches"] == []
        assert result["missing"] == []

    def test_mismatch_detected(self, tmp_path):
        client, mock = _make_client(tmp_path)
        self._seed_snapshots(tmp_path, [
            {"action_id": "act_a", "chain_hash": "local_hash", "session_id": "s", "ts": 1},
        ])

        mock.call_query = lambda m, a: {"isValid": True, "storedChainHash": "DIFFERENT_hash"}

        result = client.verify_integrity(sample_size=1)
        assert result["valid"] == 0
        assert len(result["mismatches"]) == 1
        assert result["mismatches"][0]["local"] == "local_hash"
        assert result["mismatches"][0]["canister"] == "DIFFERENT_hash"

    def test_missing_entry_detected(self, tmp_path):
        client, mock = _make_client(tmp_path)
        self._seed_snapshots(tmp_path, [
            {"action_id": "act_gone", "chain_hash": "h", "session_id": "s", "ts": 1},
        ])

        mock.call_query = lambda m, a: {
            "isValid": False, "storedChainHash": "", "message": "not found",
        }

        result = client.verify_integrity(sample_size=1)
        assert result["valid"] == 0
        assert "act_gone" in result["missing"]

    def test_transport_error_counts_as_missing(self, tmp_path):
        client, mock = _make_client(tmp_path)
        self._seed_snapshots(tmp_path, [
            {"action_id": "act_err", "chain_hash": "h", "session_id": "s", "ts": 1},
        ])

        mock.call_query = MagicMock(side_effect=ConnectionError("offline"))

        result = client.verify_integrity(sample_size=1)
        assert result["valid"] == 0
        assert "act_err" in result["missing"]
