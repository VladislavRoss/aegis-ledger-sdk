"""
aegis.doctor — SDK health diagnostics.

Checks config, keys, canister connectivity, API key status, and spill queue.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def run_doctor(
    canister_id: str | None = None,
    verbose: bool = False,
    fix: bool = False,
) -> list[dict[str, Any]]:
    """Run all diagnostic checks and return results.

    Each result: {"name": str, "status": "OK"|"WARN"|"FAIL", "detail": str}
    When *fix=True*, auto-repairs fixable issues (spill drain, deferred verify).
    """
    results: list[dict[str, Any]] = []
    _transport = None

    # 1. Config
    try:
        from aegis.config import _CONFIG_FILE, get_client_config, load_config

        cfg = load_config()
        client_cfg = get_client_config(cfg)
        if not client_cfg:
            results.append({"name": "Config", "status": "FAIL",
                            "detail": f"{_CONFIG_FILE} missing or empty — run: aegis init"})
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
        else:
            candidates = _find_key_candidates(pk_path.parent)
            detail = f"{pk_path} not found"
            if candidates:
                detail += f" — found nearby: {', '.join(c.name for c in candidates[:3])}"
            else:
                detail += f" — run: aegis keygen {pk_path}"
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
    from aegis.config import _CONFIG_DIR

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

    # 5. Deferred verifications
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

    # 6. SDK version
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
