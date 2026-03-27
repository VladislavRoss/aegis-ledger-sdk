"""
aegis.doctor — SDK health diagnostics.

Checks config, keys, canister connectivity, API key status, and spill queue.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def run_doctor(canister_id: str | None = None, verbose: bool = False) -> list[dict[str, Any]]:
    """Run all diagnostic checks and return results.

    Each result: {"name": str, "status": "OK"|"WARN"|"FAIL", "detail": str}
    """
    results: list[dict[str, Any]] = []

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
            results.append({"name": "Private Key", "status": "FAIL",
                            "detail": f"{pk_path} not found — run: aegis keygen {pk_path}"})
    else:
        results.append({"name": "Private Key", "status": "FAIL",
                        "detail": "No private_key_path in config — run: aegis init"})

    # 3. Canister connectivity
    cid = canister_id or client_cfg.get("canister_id", "")
    if cid:
        try:
            from aegis.transport import CanisterTransport, TransportConfig

            config = TransportConfig(canister_id=cid)
            transport = CanisterTransport(config)
            health = transport.call_query("getHealth", [])
            entries = health.get("totalEntries", health.get("_576569836", "?"))
            cycles = health.get("cyclesBalance", health.get("_3726629775", "?"))
            if isinstance(cycles, int):
                cycles = f"{cycles / 1_000_000_000_000:.1f}T"
            results.append({"name": "Canister", "status": "OK",
                            "detail": f"{entries} entries, {cycles} cycles"})
        except Exception as exc:
            msg = f"Unreachable: {str(exc)[:50]} — offline OK (spill)"
            results.append({"name": "Canister", "status": "WARN", "detail": msg})
    else:
        results.append({"name": "Canister", "status": "FAIL",
                        "detail": "No canister_id configured — run: aegis init"})

    # 4. Spill queue
    from aegis.config import _CONFIG_DIR

    spill_dir = _CONFIG_DIR / "spill"
    if spill_dir.is_dir():
        spill_files = list(spill_dir.glob("*.jsonl"))
        count = len(spill_files)
        if count == 0:
            results.append({"name": "Spill", "status": "OK", "detail": "0 pending entries"})
        else:
            msg = f"{count} pending — drains on next call"
            results.append({"name": "Spill", "status": "WARN", "detail": msg})
    else:
        results.append({"name": "Spill", "status": "OK", "detail": "0 pending entries"})

    # 5. SDK version
    try:
        from aegis import __version__
        results.append({"name": "SDK", "status": "OK", "detail": f"v{__version__}"})
    except ImportError:
        results.append({"name": "SDK", "status": "FAIL", "detail": "Cannot import aegis"})

    return results


def print_doctor(results: list[dict[str, Any]]) -> None:
    """Print doctor results in a formatted table."""
    status_labels = {"OK": "[OK]  ", "WARN": "[WARN]", "FAIL": "[FAIL]"}
    for r in results:
        label = status_labels.get(r["status"], "[??]  ")
        print(f"  {label} {r['name']:<14} {r['detail']}")


def doctor_main(canister_id: str | None = None, verbose: bool = False) -> int:
    """Run doctor and print results. Returns 0 if all OK, 1 if any FAIL."""
    print()
    print("=== Aegis SDK Health Check ===")
    print()
    results = run_doctor(canister_id=canister_id, verbose=verbose)
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
