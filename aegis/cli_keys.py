"""
aegis.cli_keys — CLI commands for API key lifecycle (register-key, revoke).

Separated from cli.py to keep modules under 500 lines.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

logger = logging.getLogger("aegis")


def _prompt(text: str) -> str:
    """Read a line from stdin, handling EOF gracefully."""
    try:
        return input(text)
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)


def cmd_register_key(args: list[str]) -> None:
    """Register a new API key directly on canister (headless, no browser)."""
    from aegis.crypto import load_private_key

    if not args:
        print("Usage: aegis register-key <key_id> --key-file <path> [--algorithm <algo>]")
        sys.exit(1)

    key_id = args[0]
    key_file = ""
    algorithm = ""
    permission = "full"

    if "--key-file" in args:
        idx = args.index("--key-file")
        if idx + 1 < len(args):
            key_file = args[idx + 1]
    if "--algorithm" in args:
        idx = args.index("--algorithm")
        if idx + 1 < len(args):
            algorithm = args[idx + 1]
    if "--permission" in args:
        idx = args.index("--permission")
        if idx + 1 < len(args):
            perm_val = args[idx + 1]
            if perm_val not in ("full", "query-only"):
                print("Error: --permission must be 'full' or 'query-only'")
                sys.exit(1)
            permission = "queryOnly" if perm_val == "query-only" else "full"

    if not key_file:
        print("Error: --key-file is required")
        sys.exit(1)

    kf = Path(key_file)
    if not kf.exists():
        print(f"Error: Key file not found: {key_file}")
        sys.exit(1)

    # Auto-detect algorithm from extension if not specified
    if not algorithm:
        ext_map = {
            ".pem": "ed25519",
            ".mldsa65": "ml-dsa-65",
            ".mldsa87": "ml-dsa-87",
            ".slh": "slh-dsa-128s",
        }
        algorithm = ext_map.get(kf.suffix, "")
        if not algorithm:
            print(f"Error: Cannot detect algorithm from extension '{kf.suffix}'. Use --algorithm.")
            sys.exit(1)

    # Validate algorithm-extension consistency
    valid_exts = {
        "ed25519": [".pem"],
        "ml-dsa-65": [".mldsa65"],
        "ml-dsa-87": [".mldsa87"],
        "slh-dsa-128s": [".slh"],
        "hybrid": [".pem"],
    }
    if algorithm in valid_exts and kf.suffix not in valid_exts[algorithm]:
        print(f"Error: Extension '{kf.suffix}' does not match algorithm '{algorithm}'.")
        print(f"  Expected: {', '.join(valid_exts[algorithm])}")
        sys.exit(1)

    # Read public key (generate_keypair uses .with_suffix(".pub"))
    pub_path = kf.with_suffix(".pub")
    if not pub_path.exists():
        print(f"Error: Public key not found: {pub_path}")
        print("  Run 'aegis keygen' first to generate a keypair.")
        sys.exit(1)
    pub_hex = pub_path.read_text(encoding="utf-8").strip()

    # Compute PoP signature
    pop_sig = ""
    pop_msg = f"aegis-pop:{key_id}".encode()
    try:
        if algorithm == "ed25519":
            sk = load_private_key(str(kf))
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            if isinstance(sk, Ed25519PrivateKey):
                pop_sig = sk.sign(pop_msg).hex()
        elif algorithm == "hybrid":
            from aegis.config import load_config

            cfg = load_config()
            sk_path = cfg.get("signing", {}).get("signing_key_path", "")
            if sk_path:
                from aegis.schemes import create_scheme

                ed_sk = load_private_key(str(kf))
                ml_sk_bytes = Path(sk_path).read_bytes()
                scheme = create_scheme("hybrid", (ed_sk, ml_sk_bytes))
                pop_sig = scheme.sign(pop_msg)
        else:
            from aegis.schemes import create_scheme

            sk_bytes = kf.read_bytes()
            scheme = create_scheme(algorithm, sk_bytes)
            pop_sig = scheme.sign(pop_msg)
        print(f"  [OK] PoP computed for {key_id} ({algorithm})")
    except Exception as e:
        print(f"  [WARN] Could not compute PoP: {e}")

    # Register key directly on canister (headless)
    from aegis.cli_init import _call_accept_dpa, _call_create_api_key, _derive_principal_from_pem

    pem_path = kf if algorithm == "ed25519" else kf.parent / "agent_key.pem"
    if not pem_path.exists():
        print(f"  Error: Transport key not found: {pem_path}")
        sys.exit(1)

    try:
        org_id = _derive_principal_from_pem(pem_path)
        print(f"  [OK] Principal: {org_id}")
    except Exception as e:
        print(f"  [FAIL] Could not derive principal: {e}")
        sys.exit(1)

    from aegis.transport import CanisterTransport, TransportConfig

    canister = "toqqq-lqaaa-aaaae-afc2a-cai"
    try:
        from aegis.config import get_client_config, load_config

        cfg = load_config()
        canister = get_client_config(cfg).get("canister_id", canister)
    except Exception:
        logger.debug("Config load failed, using defaults", exc_info=True)

    transport = CanisterTransport(
        TransportConfig(canister_id=canister, private_key_path=str(pem_path))
    )

    try:
        _call_accept_dpa(transport)
        print("  [OK] DPA accepted")
        _call_create_api_key(
            transport,
            key_id,
            org_id,
            key_id,
            pub_hex,
            algorithm,
            pop_sig,
            "Registered via aegis register-key",
            permission,
        )
        print(f"  [OK] Key {key_id} registered on-chain ({algorithm})")
    except Exception as e:
        err = str(e)
        if "already" in err.lower():
            print(f"  [OK] Key {key_id} already registered")
        else:
            print(f"  [FAIL] Registration failed: {err}")
            sys.exit(1)


def cmd_rotate_key(args: list[str]) -> None:
    """Rotate an API key: generate new → register → verify → update config → revoke old."""
    from aegis.config import get_client_config, load_config, write_config

    cfg = load_config()
    client_cfg = get_client_config(cfg)
    if not client_cfg:
        print("Error: No config found. Run: aegis init")
        sys.exit(1)

    old_key_id = client_cfg.get("api_key_id", "")
    old_pk_path = client_cfg.get("private_key_path", "")
    canister_id = client_cfg.get("canister_id", "")
    org_id = client_cfg.get("org_id", "")

    if not old_key_id:
        print("Error: No api_key_id in config — nothing to rotate.")
        sys.exit(1)

    # Parse args
    algorithm = ""
    for i, a in enumerate(args):
        if a == "--algorithm" and i + 1 < len(args):
            algorithm = args[i + 1]

    if not algorithm:
        algorithm = cfg.get("signing", {}).get("default_scheme", "ed25519")

    ext_map = {"ed25519": ".pem", "ml-dsa-65": ".mldsa65", "ml-dsa-87": ".mldsa87",
               "slh-dsa-128s": ".slh", "hybrid": ".pem"}
    ext = ext_map.get(algorithm, ".pem")

    # Step 1: Generate new key
    import secrets

    new_key_id = f"ak_{secrets.token_hex(3)}"
    aegis_dir = Path.home() / ".aegis"
    new_key_path = aegis_dir / f"{new_key_id}{ext}"

    print()
    print(f"=== Aegis Key Rotation: {old_key_id} → {new_key_id} ===")
    print()
    print(f"  Algorithm: {algorithm}")
    print(f"  New key:   {new_key_path}")
    print()

    confirm = _prompt("  Proceed with rotation? Type 'yes': ").strip().lower()
    if confirm != "yes":
        print("  Aborted.")
        return

    print()
    from aegis.crypto import generate_keypair

    generate_keypair(str(new_key_path), algorithm=algorithm)
    print(f"  [1/5] Keypair generated: {new_key_path}")

    # Step 2: Register new key
    try:
        cmd_register_key([
            new_key_id,
            "--key-file", str(new_key_path),
            "--algorithm", algorithm,
        ])
        print(f"  [2/5] Key {new_key_id} registered on-chain")
    except SystemExit:
        print("  [FAIL] Registration failed — aborting rotation.")
        print(f"  Old key {old_key_id} is still active. No changes made.")
        return

    # Step 3: Verify new key works
    print("  [3/5] Verifying new key...")
    try:
        from aegis.client import AegisClient

        test_client = AegisClient(
            canister_id=canister_id,
            org_id=org_id,
            api_key_id=new_key_id,
            private_key_path=str(new_key_path),
        )
        result = test_client.log_tool_call(
            "aegis.rotate.verify", {"rotation": True},
            {"status": "ok"}, duration_ms=0,
        )
        test_client.close()
        if result:
            print(f"  [3/5] Verification passed (action: {result[:16]}...)")
        else:
            print("  [3/5] Verification passed")
    except Exception as exc:
        print(f"  [FAIL] Verification failed: {exc}")
        print(f"  Rollback: old key {old_key_id} is still active.")
        print(f"  New key {new_key_id} was registered but config NOT updated.")
        return

    # Step 4: Update config
    signing_key_path = cfg.get("signing", {}).get("signing_key_path")
    write_config(
        canister_id=canister_id,
        api_key_id=new_key_id,
        agent_id=client_cfg.get("agent_id", ""),
        private_key_path=str(new_key_path),
        org_id=org_id,
        signing_scheme=algorithm,
        signing_key_path=signing_key_path,
    )
    print(f"  [4/5] Config updated → {new_key_id}")

    # Step 5: Revoke old key (best-effort, non-fatal)
    print(f"  [5/5] Revoking old key {old_key_id}...")
    try:
        from aegis.transport import CanisterTransport, TransportConfig

        transport = CanisterTransport(
            TransportConfig(canister_id=canister_id, private_key_path=old_pk_path)
        )
        transport.call_update("revokeApiKey", [old_key_id])
        print(f"  [5/5] Old key {old_key_id} revoked")
    except Exception as exc:
        print(f"  [WARN] Could not revoke old key: {exc}")
        print(f"  Revoke manually: aegis revoke {old_key_id}")

    print()
    print(f"  Rotation complete: {old_key_id} → {new_key_id}")
    print()


def cmd_revoke(args: list[str]) -> None:
    """Revoke an API key (requires confirmation)."""
    if not args:
        print("Usage: aegis revoke <key_id>")
        sys.exit(1)

    key_id = args[0]

    # Confirmation prompt — ALWAYS required, not bypassable
    print()
    print(f"  Revoke key {key_id}? This cannot be undone.")
    confirm = _prompt("  Type 'yes' to confirm: ").strip().lower()
    if confirm != "yes":
        print("  Aborted.")
        return

    print()
    print("  Opening Dashboard to revoke key...")
    print("  Sign in, go to Keys tab, and click Revoke on the key.")
    try:
        import webbrowser

        webbrowser.open("https://www.aegis-ledger.com/dashboard")
        print("  [OK] Browser opened")
    except Exception:
        print("  Open: https://www.aegis-ledger.com/dashboard")
    print()
    print(f"  Revoke {key_id} in the Dashboard Keys panel.")
