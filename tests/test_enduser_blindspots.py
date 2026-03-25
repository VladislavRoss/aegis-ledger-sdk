"""End-User Blind-Spot Tests — Szenarien die ein echter Nutzer trifft.

Covers:
  P1: _principal_text_to_bytes CRC, span() exception cleanup,
      spill corruption recovery, fail_open=False, large payloads
  P2: Unicode edge cases, truncate_preview edge cases, PII env var,
      from_config error paths, concurrent new_session
"""
from __future__ import annotations

import json
import threading
import time
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client(fail_open: bool = True):
    """AegisClient mit gemocktem Transport."""
    with (
        patch("aegis.client.load_private_key", return_value=Ed25519PrivateKey.generate()),
        patch("aegis.client.load_config", return_value={}),
        patch("aegis.client.CanisterTransport") as MockTransport,
    ):
        mock = MockTransport.return_value
        mock.call_update.return_value = {"actionId": "canister-act-test"}
        mock.spill_count = 0
        mock.drain_spill_buffer.return_value = 0

        from aegis.client import AegisClient
        client = AegisClient(
            canister_id="test-canister",
            api_key_id="ak_test",
            private_key_path="/dev/null",
            agent_id="test-agent",
            org_id="un4fu-tqaaa-aaaab-qadjq-cai",
            fail_open=fail_open,
        )
        client._transport = mock
        return client


# ═══════════════════════════════════════════════════════════════════════════
# P1: _principal_text_to_bytes — CRC + edge cases
# ═══════════════════════════════════════════════════════════════════════════

class TestPrincipalTextToBytes:
    """Verifies the standalone Principal parser (no ic-py dependency)."""

    def test_valid_canister_principal(self):
        from aegis.transport import _principal_text_to_bytes
        result = _principal_text_to_bytes("un4fu-tqaaa-aaaab-qadjq-cai")
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_valid_user_principal(self):
        from aegis.transport import _principal_text_to_bytes
        result = _principal_text_to_bytes("rrkah-fqaaa-aaaaa-aaaaq-cai")
        assert isinstance(result, bytes)

    def test_anonymous_principal(self):
        from aegis.transport import _principal_text_to_bytes
        result = _principal_text_to_bytes("2vxsx-fae")
        assert isinstance(result, bytes)
        assert result == b"\x04"  # Anonymous principal = 0x04

    def test_management_canister(self):
        from aegis.transport import _principal_text_to_bytes
        result = _principal_text_to_bytes("aaaaa-aa")
        assert isinstance(result, bytes)

    def test_bytes_passthrough(self):
        from aegis.transport import _principal_text_to_bytes
        raw = b"\x01\x02\x03"
        assert _principal_text_to_bytes(raw) is raw

    def test_invalid_base32_raises(self):
        from aegis.transport import _principal_text_to_bytes
        with pytest.raises(ValueError, match="Invalid principal"):
            _principal_text_to_bytes("!!!invalid!!!")

    def test_too_short_raises(self):
        from aegis.transport import _principal_text_to_bytes
        with pytest.raises(ValueError, match="(Invalid|too short)"):
            _principal_text_to_bytes("a")

    def test_empty_string_raises(self):
        from aegis.transport import _principal_text_to_bytes
        with pytest.raises(ValueError):
            _principal_text_to_bytes("")

    def test_real_mainnet_principal(self):
        """The actual Aegis canister Principal."""
        from aegis.transport import _principal_text_to_bytes
        result = _principal_text_to_bytes("toqqq-lqaaa-aaaae-afc2a-cai")
        assert isinstance(result, bytes)
        assert len(result) == 10  # Canister principals are 10 bytes


# ═══════════════════════════════════════════════════════════════════════════
# P1: span() with exceptions — cleanup must happen
# ═══════════════════════════════════════════════════════════════════════════

class TestSpanExceptionCleanup:
    def test_span_cleans_up_on_exception(self):
        """Action stack must be restored after exception inside span."""
        client = _make_client()
        stack_before = len(client._action_stack)

        with pytest.raises(RuntimeError, match="deliberate"), client.span("test_span"):
            raise RuntimeError("deliberate failure inside span")

        assert len(client._action_stack) == stack_before

    def test_span_nested_cleanup(self):
        """Nested spans both clean up after inner exception."""
        client = _make_client()

        with client.span("outer"):
            assert len(client._action_stack) == 1
            with pytest.raises(ValueError), client.span("inner"):
                assert len(client._action_stack) == 2
                raise ValueError("inner fail")
            assert len(client._action_stack) == 1

        assert len(client._action_stack) == 0

    def test_span_yields_action_id_before_exception(self):
        """span should yield action_id even if body later raises."""
        client = _make_client()
        captured_id = None

        with pytest.raises(RuntimeError), client.span("capture") as span_id:
            captured_id = span_id
            raise RuntimeError("after capture")

        assert captured_id is not None
        # Mock returns "canister-act-test" — just verify we got a non-empty string
        assert len(str(captured_id)) > 0


# ═══════════════════════════════════════════════════════════════════════════
# P1: fail_open=False — exceptions must propagate
# ═══════════════════════════════════════════════════════════════════════════

class TestFailClosed:
    def test_fail_open_false_raises_on_transport_error(self):
        """With fail_open=False, transport errors propagate to caller."""
        client = _make_client(fail_open=False)
        client._transport.call_update.side_effect = ConnectionError("canister down")

        with pytest.raises(ConnectionError, match="canister down"):
            client.log_tool_call(
                tool="test",
                input_data={"x": 1},
                output_data={"y": 2},
                duration_ms=10,
            )

    def test_fail_open_true_returns_spilled_id(self):
        """With fail_open=True (default), transport errors return spilled_xxx."""
        client = _make_client(fail_open=True)
        client._transport.call_update.side_effect = ConnectionError("canister down")

        result = client.log_tool_call(
            tool="test",
            input_data={"x": 1},
            output_data={"y": 2},
            duration_ms=10,
        )
        assert result.startswith("spilled_")

    def test_fail_open_true_does_not_advance_chain(self):
        """Failed log must NOT advance sequence or chain hash."""
        client = _make_client(fail_open=True)
        seq_before = client._sequence
        session_id = client.session_id
        chain_before = client._chain_heads.get(session_id, "")

        client._transport.call_update.side_effect = ConnectionError("down")
        client.log_tool_call(tool="fail", input_data={}, output_data={}, duration_ms=0)

        assert client._sequence == seq_before
        assert client._chain_heads.get(session_id, "") == chain_before


# ═══════════════════════════════════════════════════════════════════════════
# P1: Spill buffer — corruption recovery
# ═══════════════════════════════════════════════════════════════════════════

class TestSpillCorruption:
    def _make_transport(self, tmp_path, canister_id="corrupt-test"):
        from aegis.transport import CanisterTransport, TransportConfig
        config = TransportConfig(canister_id=canister_id, spill_dir=str(tmp_path))
        with pytest.MonkeyPatch.context() as m:
            m.setattr(
                "aegis.transport.CanisterTransport._init_agent",
                lambda self: setattr(self, "_ic_available", True),
            )
            return CanisterTransport(config)

    def test_corrupt_json_line_skipped_during_drain(self, tmp_path):
        """Corrupt JSON lines in spill file are silently skipped."""
        transport = self._make_transport(tmp_path)
        spill_file = tmp_path / "corrupt-test.jsonl"

        now_ms = int(time.time() * 1000)
        good_entry = json.dumps({
            "method": "addLedgerEntry",
            "raw_values": [
                "act_good", "rrkah-fqaaa-aaaaa-aaaaq-cai", "agent", "sess", 0,
                {"toolCall": None}, "tool", "ih", "oh", "", "", 100, "success",
                "", "", 0.9, "unknown", "", now_ms, "sig", "ch", "", "ph", "ak",
            ],
            "timestamp_ms": now_ms,
            "canister_id": "corrupt-test",
            "spill_version": 2,
        })
        spill_file.write_text(
            "this is not valid json\n"
            + good_entry + "\n"
            + '{"incomplete": true\n'
        )

        with pytest.MonkeyPatch.context() as m:
            m.setattr(transport, "_do_call", lambda *a, **kw: {"ok": True})
            drained = transport.drain_spill_buffer()

        # Good entry drained, corrupt lines go to failed (kept in file)
        assert drained == 1

    def test_spill_ttl_expired_entries_discarded(self, tmp_path):
        """Entries older than AEGIS_SPILL_TTL_DAYS are discarded during drain."""
        transport = self._make_transport(tmp_path, "ttl-test")
        spill_file = tmp_path / "ttl-test.jsonl"

        old_ts = int(time.time() * 1000) - 40 * 24 * 60 * 60 * 1000  # 40 days ago
        entry = json.dumps({
            "method": "addLedgerEntry",
            "raw_values": [
                "act_old", "rrkah-fqaaa-aaaaa-aaaaq-cai", "agent", "sess", 0,
                {"toolCall": None}, "tool", "ih", "oh", "", "", 100, "success",
                "", "", 0.9, "unknown", "", old_ts, "sig", "ch", "", "ph", "ak",
            ],
            "timestamp_ms": old_ts,
            "canister_id": "ttl-test",
            "spill_version": 2,
        })
        spill_file.write_text(entry + "\n")

        with pytest.MonkeyPatch.context() as m:
            m.setattr(transport, "_do_call", lambda *a, **kw: {"ok": True})
            drained = transport.drain_spill_buffer()

        assert drained == 0
        assert not spill_file.exists()  # Discarded, not replayed

    def test_spill_disallowed_method_discarded(self, tmp_path):
        """Non-addLedgerEntry methods are never replayed."""
        transport = self._make_transport(tmp_path, "method-test")
        spill_file = tmp_path / "method-test.jsonl"

        now_ms = int(time.time() * 1000)
        entry = json.dumps({
            "method": "deleteAllData",
            "raw_values": ["dangerous"],
            "timestamp_ms": now_ms,
            "canister_id": "method-test",
            "spill_version": 2,
        })
        spill_file.write_text(entry + "\n")

        call_count = [0]
        def track_calls(*a, **kw):
            call_count[0] += 1
            return {"ok": True}

        with pytest.MonkeyPatch.context() as m:
            m.setattr(transport, "_do_call", track_calls)
            drained = transport.drain_spill_buffer()

        assert drained == 0
        assert call_count[0] == 0  # _do_call was never invoked

    def test_spill_legacy_v1_discarded(self, tmp_path):
        """Legacy v1 spill entries (without spill_version=2) are discarded."""
        transport = self._make_transport(tmp_path, "v1-test")
        spill_file = tmp_path / "v1-test.jsonl"

        now_ms = int(time.time() * 1000)
        entry = json.dumps({
            "method": "addLedgerEntry",
            "args": [{"type": "Types.Text", "value": "corrupted"}],
            "timestamp_ms": now_ms,
            "canister_id": "v1-test",
        })
        spill_file.write_text(entry + "\n")

        with pytest.MonkeyPatch.context() as m:
            m.setattr(transport, "_do_call", lambda *a, **kw: {"ok": True})
            drained = transport.drain_spill_buffer()

        assert drained == 0


# ═══════════════════════════════════════════════════════════════════════════
# P1: Large payload handling (32KB canister inspect limit)
# ═══════════════════════════════════════════════════════════════════════════

class TestLargePayloads:
    def test_large_input_data_truncated_in_preview(self):
        """Large input_data gets truncated in preview, not in hash."""
        from aegis.crypto import sha256_json, truncate_preview

        large_data = {"items": ["x" * 500 for _ in range(100)]}  # ~50KB
        preview = truncate_preview(large_data)
        full_hash = sha256_json(large_data)

        assert len(preview) <= 200
        assert preview.endswith("...")
        # sha256_json returns "sha256:<64 hex chars>" = 71 chars
        assert full_hash.startswith("sha256:")
        assert len(full_hash) == 71

    def test_log_with_large_data_succeeds(self):
        """Logging large payloads works (truncation + hashing)."""
        client = _make_client()
        large_input = {"records": [{"id": i, "data": "x" * 200} for i in range(50)]}

        action_id = client.log_tool_call(
            tool="big_query",
            input_data=large_input,
            output_data={"count": 50, "status": "ok"},
            duration_ms=500,
        )
        assert action_id is not None

    def test_truncate_preview_exact_boundary(self):
        """Data exactly at 200 chars is NOT truncated."""
        from aegis.crypto import truncate_preview

        # JSON representation of this string is exactly 200 chars with quotes
        data = "a" * 198  # '"' + 198*'a' + '"' = 200 chars
        result = truncate_preview(data)
        assert "..." not in result
        assert len(result) == 200

    def test_truncate_preview_none(self):
        from aegis.crypto import truncate_preview
        assert truncate_preview(None) == ""

    def test_truncate_preview_redacts_bearer_token(self):
        from aegis.crypto import truncate_preview
        data = {"headers": {"Authorization": "Bearer sk-abc123secret"}}
        result = truncate_preview(data)
        assert "sk-abc123" not in result
        assert "***" in result

    def test_truncate_preview_redacts_pem_key(self):
        from aegis.crypto import truncate_preview
        data = "-----BEGIN PRIVATE KEY----- MIIEvgIBADANBg..."
        result = truncate_preview(data)
        assert result == '"***"'


# ═══════════════════════════════════════════════════════════════════════════
# P2: Unicode edge cases
# ═══════════════════════════════════════════════════════════════════════════

class TestUnicodeEdgeCases:
    def test_emoji_in_tool_output(self):
        """Emoji in tool names and output data must survive hashing."""
        client = _make_client()
        action_id = client.log_tool_call(
            tool="weather.get_forecast",
            input_data={"city": "Zürich"},
            output_data={"condition": "sunny", "icon": "☀️🌤️"},
            duration_ms=50,
        )
        assert action_id is not None

    def test_unicode_in_canonical_json(self):
        """canonical_json preserves Unicode (no ensure_ascii)."""
        from aegis.crypto import canonical_json
        data = {"name": "Zürich", "emoji": "🔐", "arabic": "مرحبا"}
        result = canonical_json(data)
        # canonical_json returns bytes (UTF-8 encoded)
        assert isinstance(result, bytes)
        text = result.decode("utf-8")
        assert "Zürich" in text
        assert "🔐" in text
        assert "مرحبا" in text

    def test_unicode_in_sha256(self):
        """SHA-256 handles Unicode consistently."""
        from aegis.crypto import sha256_json
        h1 = sha256_json({"x": "Ü"})
        h2 = sha256_json({"x": "Ü"})
        assert h1 == h2
        assert h1.startswith("sha256:")
        assert len(h1) == 71  # "sha256:" + 64 hex chars

    def test_null_bytes_in_data(self):
        """Null bytes don't crash logging."""
        client = _make_client()
        action_id = client.log_tool_call(
            tool="binary_tool",
            input_data={"raw": "hello\x00world"},
            output_data={"ok": True},
            duration_ms=1,
        )
        assert action_id is not None

    def test_empty_strings_everywhere(self):
        """All-empty inputs don't crash."""
        client = _make_client()
        action_id = client.log_tool_call(
            tool="",
            input_data="",
            output_data="",
            duration_ms=0,
        )
        assert action_id is not None


# ═══════════════════════════════════════════════════════════════════════════
# P2: PII env var toggle
# ═══════════════════════════════════════════════════════════════════════════

class TestPIIEnvVar:
    def test_pii_warn_disabled(self, monkeypatch):
        """AEGIS_PII_WARN=0 suppresses PII warnings."""
        monkeypatch.setenv("AEGIS_PII_WARN", "0")
        # Force re-evaluation by reimporting
        import importlib

        import aegis.pii
        importlib.reload(aegis.pii)
        try:
            assert aegis.pii._PII_WARN_DEFAULT is False
        finally:
            monkeypatch.delenv("AEGIS_PII_WARN", raising=False)
            importlib.reload(aegis.pii)

    def test_pii_warn_enabled_by_default(self):
        """Without AEGIS_PII_WARN, warnings are enabled."""
        from aegis.pii import _PII_WARN_DEFAULT
        assert _PII_WARN_DEFAULT is True


# ═══════════════════════════════════════════════════════════════════════════
# P2: from_config error paths
# ═══════════════════════════════════════════════════════════════════════════

class TestFromConfigErrors:
    def test_missing_config_file_raises(self, tmp_path):
        """from_config with non-existent config raises."""
        from aegis.client import AegisClient
        with pytest.raises((FileNotFoundError, ValueError)):
            AegisClient.from_config(config_path=tmp_path / "nonexistent.toml")

    def test_empty_config_file_raises(self, tmp_path):
        """from_config with empty config file raises (treated as no config)."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("")

        from aegis.client import AegisClient
        # Empty file → load_config returns {} → from_config raises FileNotFoundError
        with pytest.raises((FileNotFoundError, KeyError, ValueError)):
            AegisClient.from_config(config_path=config_file)


# ═══════════════════════════════════════════════════════════════════════════
# P2: Concurrent session isolation
# ═══════════════════════════════════════════════════════════════════════════

class TestConcurrentSessions:
    def test_concurrent_logging_thread_safety(self):
        """Multiple threads logging concurrently don't corrupt sequence."""
        client = _make_client()
        errors = []
        results = []

        def log_entries(thread_id):
            try:
                for i in range(20):
                    aid = client.log_tool_call(
                        tool=f"thread_{thread_id}",
                        input_data={"i": i},
                        output_data={"ok": True},
                        duration_ms=1,
                    )
                    results.append(aid)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=log_entries, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0, f"Thread errors: {errors}"
        assert len(results) == 100  # 5 threads × 20 entries

    def test_new_session_during_logging(self):
        """new_session() mid-logging resets sequence correctly."""
        client = _make_client()

        client.log_tool_call(tool="before", input_data={}, output_data={}, duration_ms=1)
        seq_before = client._sequence

        client.new_session()
        seq_after = client._sequence

        assert seq_after == 0
        assert seq_before > 0

        client.log_tool_call(tool="after", input_data={}, output_data={}, duration_ms=1)
        assert client._sequence == 1


# ═══════════════════════════════════════════════════════════════════════════
# P1: Snapshot integrity — symlink protection
# ═══════════════════════════════════════════════════════════════════════════

class TestSnapshotSymlinkProtection:
    def test_write_snapshot_skips_symlink_parent(self, tmp_path):
        """write_snapshot refuses to write if parent is a symlink."""
        from aegis.integrity import write_snapshot

        real_dir = tmp_path / "real"
        real_dir.mkdir()
        try:
            link = tmp_path / "link"
            link.symlink_to(real_dir)
            snap_file = link / "test.jsonl"

            write_snapshot(snap_file, "act_1", "hash1", "sess_1", 123)
            assert not snap_file.exists()
        except OSError:
            pytest.skip("symlink creation not supported")

    def test_write_snapshot_normal_dir_works(self, tmp_path):
        """write_snapshot writes normally to a real directory."""
        from aegis.integrity import write_snapshot

        snap_file = tmp_path / "snapshots" / "test.jsonl"
        write_snapshot(snap_file, "act_1", "hash1", "sess_1", 123)
        assert snap_file.exists()
        content = json.loads(snap_file.read_text().strip())
        assert content["action_id"] == "act_1"
        assert content["chain_hash"] == "hash1"


# ═══════════════════════════════════════════════════════════════════════════
# P1: Context manager (with ... as client)
# ═══════════════════════════════════════════════════════════════════════════

class TestContextManager:
    def test_context_manager_calls_close(self):
        """Exiting `with` block calls close() which drains spill buffer."""
        client = _make_client()
        with client:
            client.log_tool_call(tool="cm_test", input_data={}, output_data={}, duration_ms=1)

        client._transport.drain_spill_buffer.assert_called()

    def test_context_manager_on_exception_still_closes(self):
        """Even on exception, close() is called."""
        client = _make_client()
        with pytest.raises(ValueError), client:
            raise ValueError("test")

        client._transport.drain_spill_buffer.assert_called()
