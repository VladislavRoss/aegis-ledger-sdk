"""
aegis.doctor — SDK health diagnostics.

Checks config, keys, canister connectivity, API key status, and spill queue.
When --fix is enabled, auto-repairs: config, keys, spill drain, deferred verify, MCP orphan queues.
"""

from __future__ import annotations

import contextlib
import os
import secrets
from pathlib import Path
from typing import Any

_MAINNET_BACKEND = "toqqq-lqaaa-aaaae-afc2a-cai"


def _auto_create_config() -> str:
    """Write a minimal config.toml (mainnet backend, default key path, new api_key_id).

    Returns the short detail string about what was created.
    """
    from aegis.config import _CONFIG_DIR, write_config

    api_key_id = "ak_" + secrets.token_hex(3)
    key_path = _CONFIG_DIR / "agent_key.pem"
    write_config(
        canister_id=_MAINNET_BACKEND,
        api_key_id=api_key_id,
        agent_id=api_key_id,
        private_key_path=str(key_path),
    )
    return f"Auto-created (canister: {_MAINNET_BACKEND[:12]}..., key: {api_key_id})"


def _auto_generate_key(pk_path: Path) -> str:
    """Generate an Ed25519 keypair at *pk_path*. Returns a short detail string."""
    from aegis.crypto import generate_keypair

    pk_path.parent.mkdir(parents=True, exist_ok=True)
    _, _pub_hex = generate_keypair(pk_path)
    size = pk_path.stat().st_size if pk_path.is_file() else 0
    return f"Auto-generated Ed25519 key at {pk_path} ({size} bytes)"


def _scan_mcp_queues(aegis_dir: Path) -> tuple[int, int, list[Path]]:
    """Return (own_depth, orphan_count, orphan_files).

    own_depth: line count of own PID queue (mcp_queue_<pid>.jsonl)
    orphan_count: line count across queues from dead PIDs
    orphan_files: list of orphan queue paths (dead-PID owned)
    """
    if not aegis_dir.is_dir():
        return 0, 0, []
    my_pid = str(os.getpid())
    own_depth = 0
    orphan_count = 0
    orphan_files: list[Path] = []
    for qfile in aegis_dir.glob("mcp_queue_*.jsonl"):
        pid_str = qfile.stem.replace("mcp_queue_", "")
        try:
            content = qfile.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        depth = len(content.split("\n")) if content else 0
        if pid_str == my_pid:
            own_depth += depth
            continue
        # Check if PID is alive
        alive = False
        try:
            os.kill(int(pid_str), 0)  # existence check (signal 0)
            alive = True
        except (OSError, ValueError):
            alive = False
        if alive:
            # Live peer queue — count as own-family pending
            own_depth += depth
        else:
            orphan_count += depth
            orphan_files.append(qfile)
    return own_depth, orphan_count, orphan_files


def _adopt_orphan_queues(orphan_files: list[Path], aegis_dir: Path) -> int:
    """Merge orphan queue contents into a single recovery file, remove originals.

    Uses a dedicated recovery file (mcp_queue_recovered.jsonl) instead of
    injecting into a live PID queue. Returns number of adopted entries.
    """
    if not orphan_files:
        return 0
    recovery_path = aegis_dir / "mcp_queue_recovered.jsonl"
    adopted = 0
    fd = os.open(str(recovery_path), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        for qfile in orphan_files:
            try:
                content = qfile.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if content:
                os.write(fd, (content + "\n").encode("utf-8"))
                adopted += content.count("\n") + 1
            with contextlib.suppress(OSError):
                qfile.unlink()
    finally:
        os.close(fd)
    return adopted


def run_doctor(
    canister_id: str | None = None,
    verbose: bool = False,
    fix: bool = False,
) -> list[dict[str, Any]]:
    """Run all diagnostic checks and return results.

    Each result: {"name": str, "status": "OK"|"WARN"|"FAIL", "detail": str}
    When *fix=True*, auto-repairs fixable issues (config, key, spill, deferred, MCP orphans).
    """
    results: list[dict[str, Any]] = []
    _transport = None

    # 1. Config
    from aegis.config import _CONFIG_DIR, _CONFIG_FILE, get_client_config, load_config

    try:
        cfg = load_config()
        client_cfg = get_client_config(cfg)
        if not client_cfg:
            if fix:
                try:
                    detail = _auto_create_config()
                    # Re-load after auto-create
                    cfg = load_config()
                    client_cfg = get_client_config(cfg)
                    results.append({"name": "Config", "status": "OK", "detail": detail})
                except Exception as exc:
                    msg = f"Auto-create failed: {str(exc)[:60]}"
                    results.append({"name": "Config", "status": "FAIL", "detail": msg})
                    return results
            else:
                results.append({"name": "Config", "status": "FAIL",
                                "detail": f"{_CONFIG_FILE} missing or empty — run: aegis init"
                                          " (or: aegis doctor --fix)"})
                return results  # can't continue without config
        else:
            cid = client_cfg.get("canister_id", "?")
            kid = client_cfg.get("api_key_id", "?")
            results.append({"name": "Config", "status": "OK",
                            "detail": f"{_CONFIG_FILE} (canister: {cid[:12]}..., key: {kid})"})
    except Exception as exc:
        msg = f"Parse error: {str(exc)[:60]}"
        results.append({"name": "Config", "status": "FAIL", "detail": msg})
        return results  # can't continue without config

    # 2. Private Key
    pk_path_str = client_cfg.get("private_key_path", "")
    if pk_path_str:
        pk_path = Path(pk_path_str).expanduser()
        if pk_path.is_file():
            size = pk_path.stat().st_size
            results.append({"name": "Private Key", "status": "OK",
                            "detail": f"{pk_path} ({size} bytes)"})
        elif fix:
            try:
                detail = _auto_generate_key(pk_path)
                results.append({"name": "Private Key", "status": "OK", "detail": detail})
            except Exception as exc:
                msg = f"Auto-keygen failed: {str(exc)[:60]}"
                results.append({"name": "Private Key", "status": "FAIL", "detail": msg})
        else:
            candidates = _find_key_candidates(pk_path.parent)
            detail = f"{pk_path} not found"
            if candidates:
                detail += f" — found nearby: {', '.join(c.name for c in candidates[:3])}"
            else:
                detail += " — use --fix to auto-generate"
            results.append({"name": "Private Key", "status": "FAIL", "detail": detail})
    else:
        results.append({"name": "Private Key", "status": "FAIL",
                        "detail": "No private_key_path in config — run: aegis init"})

    # 3. Canister connectivity
    cid = canister_id or client_cfg.get("canister_id", "")
    deferred_count = 0
    if cid:
        try:
            from aegis.transport import CanisterTransport, TransportConfig

            config = TransportConfig(canister_id=cid, private_key_path=pk_path_str or None)
            _transport = CanisterTransport(config)
            health = _transport.call_query("getHealth", [])
            entries = health.get("totalEntries", health.get("_576569836", "?"))
            cycles_raw = health.get("cyclesBalance", health.get("_3726629775", "?"))
            deferred = health.get("deferredVerifications", health.get("_1854872925", 0))
            deferred_count = int(deferred) if isinstance(deferred, (int, float)) else 0
            if isinstance(cycles_raw, int):
                cycles_t = cycles_raw / 1_000_000_000_000
                status = "OK" if cycles_t >= 2.0 else ("WARN" if cycles_t >= 0.5 else "FAIL")
                cycles_str = f"{cycles_t:.1f}T"
            else:
                status, cycles_str = "OK", str(cycles_raw)
            detail = f"{entries} entries, {cycles_str} cycles"
            if deferred_count > 0:
                detail += f", {deferred_count} deferred"
            results.append({"name": "Canister", "status": status, "detail": detail})
        except Exception as exc:
            msg = f"Unreachable: {str(exc)[:50]} — offline OK (spill)"
            results.append({"name": "Canister", "status": "WARN", "detail": msg})
    else:
        results.append({"name": "Canister", "status": "FAIL",
                        "detail": "No canister_id configured — run: aegis init"})

    # 4. Spill queue
    spill_dir = _CONFIG_DIR / "spill"
    spill_entry_count = 0
    if spill_dir.is_dir():
        for sf in spill_dir.glob("*.jsonl"):
            try:
                spill_entry_count += sum(1 for _ in sf.open(encoding="utf-8"))
            except OSError:
                spill_entry_count += 1

    if spill_entry_count == 0:
        results.append({"name": "Spill", "status": "OK", "detail": "0 pending entries"})
    elif fix and _transport:
        drained = _transport.drain_spill_buffer(max_entries=50)
        remaining = max(0, spill_entry_count - drained)
        st = "OK" if remaining == 0 else "WARN"
        results.append({"name": "Spill", "status": st,
                        "detail": f"Drained {drained}, {remaining} remaining"})
    else:
        results.append({"name": "Spill", "status": "WARN",
                        "detail": f"{spill_entry_count} pending entries — use --fix to drain"})

    # 5. MCP queue (per-PID + orphan detection)
    own_depth, orphan_count, orphan_files = _scan_mcp_queues(_CONFIG_DIR)
    total_mcp = own_depth + orphan_count
    if total_mcp == 0:
        results.append({"name": "MCP Queue", "status": "OK", "detail": "0 pending entries"})
    elif orphan_count > 0 and fix:
        adopted = _adopt_orphan_queues(orphan_files, _CONFIG_DIR)
        remaining = own_depth  # adopted goes to recovery file, counts as own-family
        detail = f"Adopted {adopted} orphan entries, {remaining} live-queue pending"
        results.append({"name": "MCP Queue", "status": "OK", "detail": detail})
    elif orphan_count > 0:
        detail = (f"{total_mcp} pending ({orphan_count} orphan from "
                  f"{len(orphan_files)} dead PIDs) — use --fix to adopt")
        results.append({"name": "MCP Queue", "status": "WARN", "detail": detail})
    else:
        results.append({"name": "MCP Queue", "status": "OK",
                        "detail": f"{own_depth} pending in live queue(s)"})

    # 6. Deferred verifications
    if deferred_count > 0:
        if fix and _transport:
            try:
                _transport.call_update("batchVerifyDeferred", [10])
                results.append({"name": "Deferred", "status": "OK",
                                "detail": "Triggered batchVerifyDeferred (up to 10)"})
            except Exception as exc:
                results.append({"name": "Deferred", "status": "WARN",
                                "detail": f"Could not trigger: {str(exc)[:50]}"})
        else:
            detail = f"{deferred_count} pending — use --fix to trigger batch verify"
            results.append({"name": "Deferred", "status": "WARN", "detail": detail})

    # 7. SDK version
    try:
        from aegis import __version__
        results.append({"name": "SDK", "status": "OK", "detail": f"v{__version__}"})
    except ImportError:
        results.append({"name": "SDK", "status": "FAIL", "detail": "Cannot import aegis"})

    return results


def _find_key_candidates(directory: Path) -> list[Path]:
    """Search for key files near the expected location."""
    if not directory.is_dir():
        directory = Path.home() / ".aegis"
    if not directory.is_dir():
        return []
    candidates: list[Path] = []
    for ext in ("*.pem", "*.mldsa65", "*.mldsa87", "*.slh"):
        candidates.extend(directory.glob(ext))
    return sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True)[:5]


def print_doctor(results: list[dict[str, Any]]) -> None:
    """Print doctor results in a formatted table."""
    status_labels = {"OK": "[OK]  ", "WARN": "[WARN]", "FAIL": "[FAIL]"}
    for r in results:
        label = status_labels.get(r["status"], "[??]  ")
        print(f"  {label} {r['name']:<14} {r['detail']}")


def doctor_main(
    canister_id: str | None = None,
    verbose: bool = False,
    fix: bool = False,
) -> int:
    """Run doctor and print results. Returns 0 if all OK, 1 if any FAIL."""
    print()
    title = "=== Aegis SDK Health Check (--fix) ===" if fix else "=== Aegis SDK Health Check ==="
    print(title)
    print()
    results = run_doctor(canister_id=canister_id, verbose=verbose, fix=fix)
    print_doctor(results)
    print()
    has_fail = any(r["status"] == "FAIL" for r in results)
    if has_fail:
        print("  Some checks failed. Fix the issues above and re-run: aegis doctor")
    else:
        has_warn = any(r["status"] == "WARN" for r in results)
        if has_warn:
            print("  Warnings found, but SDK is operational.")
        else:
            print("  All checks passed.")
    print()
    return 1 if has_fail else 0
