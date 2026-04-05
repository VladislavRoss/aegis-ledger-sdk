"""aegis.cli_ops -- Operational CLI commands (deploy-check, doctor, profiles)."""

from __future__ import annotations

import sys
import time


def _cmd_doctor(args: list[str]) -> None:
    """Run SDK health diagnostics."""
    from aegis.doctor import doctor_main

    fix = "--fix" in args
    filtered = [a for a in args if a != "--fix"]
    canister_id = filtered[0] if filtered else None
    code = doctor_main(canister_id=canister_id, fix=fix)
    sys.exit(code)


def _cmd_profiles(args: list[str]) -> None:
    """List configured profiles and show the active one.

    Usage:
        aegis profiles              List all profiles, mark the active one
        aegis profiles --active     Print only the active profile name (CI-friendly)
    """
    import os

    from aegis.config import (
        _CONFIG_FILE,
        _get_active_profile,
        _load_toml,
        get_client_config,
        list_profiles,
        load_config,
    )

    # --active: machine-readable single-line output
    if "--active" in args:
        active = _get_active_profile()
        print(active or "")
        return

    raw = _load_toml(_CONFIG_FILE)
    profiles = list_profiles(raw)
    active = _get_active_profile()

    print()
    print("=== Aegis Profiles ===")
    print()
    print(f"  Config file:     {_CONFIG_FILE}")
    print(f"  Active profile:  {active or '(none — using top-level [client])'}")
    if os.environ.get("AEGIS_PROFILE"):
        print(f"  AEGIS_PROFILE:   {os.environ['AEGIS_PROFILE']}")
    print()

    top_client = get_client_config(raw)
    if top_client:
        top_cid = top_client.get("canister_id", "?")
        top_key = top_client.get("api_key_id", "?")
        marker = "*" if not active else " "
        print(f"  {marker} (default)     canister={top_cid[:12]}..., key={top_key}")

    if not profiles:
        print("  (no [profiles.*] sections defined)")
    else:
        for name in profiles:
            merged = load_config(profile=name)
            client = get_client_config(merged)
            cid = client.get("canister_id", "?")
            kid = client.get("api_key_id", "?")
            marker = "*" if name == active else " "
            print(f"  {marker} {name:<12} canister={cid[:12]}..., key={kid}")
    print()
    print("  Set via env:  export AEGIS_PROFILE=<name>")
    print()


def _cmd_deploy_check(args: list[str]) -> None:
    """Post-deployment verification: getHealth + test entry + verify."""
    from aegis.cli import _transport_from_config
    from aegis.integrity import VERIFY_HASH_MAP as _VERIFY_HASH_MAP
    from aegis.integrity import map_candid_keys as _map_candid_keys

    canister_id = args[0] if args else None
    max_retries = 3
    timeout_s = 60

    print()
    print("=== Aegis Deploy Check ===")
    print()

    transport, cid = _transport_from_config(canister_id)

    # Step 1: getHealth
    print("  [1/3] Checking canister health...")
    start = time.monotonic()
    health = None
    for attempt in range(1, max_retries + 1):
        try:
            health = transport.call_query("getHealth", [])
            break
        except Exception as exc:
            if time.monotonic() - start > timeout_s:
                print(f"  [FAIL] Timeout after {timeout_s}s: {exc}")
                sys.exit(1)
            if attempt < max_retries:
                wait = 2 ** attempt
                print(f"  Retry {attempt}/{max_retries} in {wait}s...")
                time.sleep(wait)
            else:
                print(f"  [FAIL] getHealth failed after {max_retries} attempts: {exc}")
                sys.exit(1)

    entries = health.get("totalEntries", health.get("_576569836", "?"))
    cycles = health.get("cyclesBalance", health.get("_3726629775", "?"))
    if isinstance(cycles, int):
        cycles = f"{cycles / 1_000_000_000_000:.1f}T"
    version = health.get("canisterVersion", health.get("_3855169950", "?"))
    if isinstance(version, list):
        version = version[0] if version else "?"
    print(f"  [OK]   {entries} entries, {cycles} cycles, v{version}")

    # Step 2: Send test entry
    print("  [2/3] Sending test entry...")
    try:
        from aegis.client import AegisClient

        client = AegisClient.from_config()
        result = client.log_tool_call(
            "aegis.deploy-check",
            {"check": True, "canister": cid},
            {"status": "ok"},
            duration_ms=0,
        )
        action_id = result.get("action_id", "") if result else ""
        client.close()
        if not action_id:
            print("  [FAIL] No action_id returned")
            sys.exit(1)
        print(f"  [OK]   Entry logged: {action_id[:24]}...")
    except Exception as exc:
        print(f"  [FAIL] Could not log entry: {exc}")
        sys.exit(1)

    # Step 3: Verify on-chain
    print("  [3/3] Verifying on-chain...")
    try:
        raw = transport.call_query("verifyEntry", [action_id])
        mapped = _map_candid_keys(raw, _VERIFY_HASH_MAP)
        is_valid = mapped.get("isValid", False)
        if is_valid:
            print("  [OK]   Chain hash verified")
        else:
            print(f"  [FAIL] Verification failed: {mapped}")
            sys.exit(1)
    except Exception as exc:
        print(f"  [FAIL] Verification error: {exc}")
        sys.exit(1)

    print()
    print("  Deploy check passed.")
    print()
    sys.exit(0)
