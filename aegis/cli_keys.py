"""
aegis.cli_keys — CLI commands for API key lifecycle (register-key, revoke).

Separated from cli.py to keep modules under 500 lines.
"""

from __future__ import annotations

import sys
from pathlib import Path


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

    if "--key-file" in args:
        idx = args.index("--key-file")
        if idx + 1 < len(args):
            key_file = args[idx + 1]
    if "--algorithm" in args:
        idx = args.index("--algorithm")
        if idx + 1 < len(args):
            algorithm = args[idx + 1]

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
            ".pem": "ed25519", ".mldsa65": "ml-dsa-65",
            ".mldsa87": "ml-dsa-87", ".slh": "slh-dsa-128s",
        }
        algorithm = ext_map.get(kf.suffix, "")
        if not algorithm:
            print(f"Error: Cannot detect algorithm from extension '{kf.suffix}'. Use --algorithm.")
            sys.exit(1)

    # Validate algorithm-extension consistency
    valid_exts = {"ed25519": [".pem"], "ml-dsa-65": [".mldsa65"], "ml-dsa-87": [".mldsa87"],
                  "slh-dsa-128s": [".slh"], "hybrid": [".pem"]}
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
        pass

    transport = CanisterTransport(
        TransportConfig(canister_id=canister, private_key_path=str(pem_path))
    )

    try:
        _call_accept_dpa(transport)
        print("  [OK] DPA accepted")
        _call_create_api_key(
            transport, key_id, org_id, key_id, pub_hex,
            algorithm, pop_sig, "Registered via aegis register-key",
        )
        print(f"  [OK] Key {key_id} registered on-chain ({algorithm})")
    except Exception as e:
        err = str(e)
        if "already" in err.lower():
            print(f"  [OK] Key {key_id} already registered")
        else:
            print(f"  [FAIL] Registration failed: {err}")
            sys.exit(1)


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
