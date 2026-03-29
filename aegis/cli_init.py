"""
aegis.cli_init -- Interactive setup wizard for Aegis SDK.

Headless flow (B6.5):
  Step 1: Name & signing algorithm (interactive or --quickstart)
  Step 2: Key generation (Ed25519/ML-DSA-65/87/SLH-DSA/Hybrid)
  Step 3: On-chain registration (acceptDpa + createApiKey — no browser needed)
  Post:   Backup warning + auto-test + principal display
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _prompt(text: str) -> str:
    try:
        return input(text)
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)


def _check_update() -> None:
    """Check PyPI for newer SDK version, offer to update."""
    if os.environ.get("AEGIS_SKIP_UPDATE_CHECK"):
        return

    from aegis import __version__

    try:
        import json
        import urllib.request

        with urllib.request.urlopen(
            "https://pypi.org/pypi/aegis-ledger-sdk/json", timeout=3
        ) as resp:
            data = json.loads(resp.read())
            latest = data["info"]["version"]
    except Exception:
        return

    if latest == __version__:
        return

    def _ver(v: str) -> tuple[int, ...]:
        return tuple(int(x) for x in v.split(".") if x.isdigit())

    if _ver(latest) <= _ver(__version__):
        return

    print(f"  Update available: {__version__} -> {latest}")
    choice = _prompt("  Update now? [Y/n]: ").strip().lower()
    if choice in ("", "y", "yes", "j", "ja"):
        import subprocess

        print("  Updating...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "aegis-ledger-sdk"],
            check=False,
        )
        print(f"  [OK] Updated to {latest}. Please re-run 'aegis init'.")
        sys.exit(0)
    print()


ALGO_NAMES = {
    "ed25519": "Ed25519 (classical)",
    "ml-dsa-65": "ML-DSA-65 (FIPS 204, post-quantum)",
    "ml-dsa-87": "ML-DSA-87 (FIPS 204, CNSA 2.0)",
    "slh-dsa-128s": "SLH-DSA-128s (FIPS 205, EXPERIMENTAL)",
    "hybrid": "Hybrid (Ed25519 + ML-DSA-65)",
}


def cmd_init(args: list[str]) -> None:
    """Interactive setup wizard: keygen + on-chain registration (headless)."""
    import secrets

    from aegis.config import _CONFIG_DIR, write_config

    quickstart = "--quickstart" in args
    canister = "toqqq-lqaaa-aaaae-afc2a-cai"

    # Parse --algorithm flag (new default: ml-dsa-65)
    algorithm = "ml-dsa-65"
    if "--algorithm" in args:
        idx = args.index("--algorithm")
        if idx + 1 < len(args):
            algorithm = args[idx + 1]
            if algorithm not in ALGO_NAMES:
                print(f"Error: Unknown algorithm '{algorithm}'.")
                print(f"Available: {', '.join(ALGO_NAMES)}")
                sys.exit(1)

    print()
    print("=== Aegis SDK Setup ===")
    if quickstart:
        print("  (quickstart mode — using defaults, no prompts)")
    print()

    # --- Version check ---
    if not quickstart:
        _check_update()

    # --- Step 1: Key handling + Algo selection ---
    key_dir = _CONFIG_DIR / "keys"
    existing_keys = _detect_existing_keys(key_dir)

    use_existing_algo = ""
    if existing_keys and not quickstart:
        print("Step 1/3: Choose signing key")
        print()
        print("  Existing keys detected:")
        for i, (algo, _ext, _path) in enumerate(existing_keys, 1):
            label = ALGO_NAMES.get(algo, algo)
            print(f"    [{i}] {label}")
        print("    [+] Create new key")
        print()
        pick = _prompt("  Use existing or create new? [+]: ").strip()
        if pick.isdigit() and 1 <= int(pick) <= len(existing_keys):
            use_existing_algo = existing_keys[int(pick) - 1][0]
            algorithm = use_existing_algo
            print(f"  [OK] Using existing {ALGO_NAMES[algorithm]} key")
            print()
        else:
            print()

    # Agent name
    suggested_id = "ak_" + secrets.token_hex(3)
    if quickstart:
        api_key_id = suggested_id
    else:
        if not existing_keys:
            print("Step 1/3: Name & signing algorithm")
            print()
        api_key_id = _prompt(f"  Agent name [{suggested_id}]: ").strip()
        if not api_key_id:
            api_key_id = suggested_id
        print()

    # Algo selection (skip if --algorithm flag or existing key reused)
    if use_existing_algo:
        pass
    elif not quickstart and "--algorithm" not in args:
        print("  Choose signing algorithm:")
        print()
        print("  [1] Ed25519        — Standard, fast, widely supported")
        print("  [2] ML-DSA-65      — Post-Quantum (NIST FIPS 204) <- RECOMMENDED")
        print("  [3] ML-DSA-87      — Post-Quantum, highest security (CNSA 2.0)")
        print("  [4] SLH-DSA-128s   — Post-Quantum, hash-based (EXPERIMENTAL)")
        print("  [5] Hybrid         — Ed25519 + ML-DSA-65 combined")
        print()
        choice = _prompt("  Choice [2]: ").strip()
        algo_map = {
            "": "ml-dsa-65", "1": "ed25519", "2": "ml-dsa-65",
            "3": "ml-dsa-87", "4": "slh-dsa-128s", "5": "hybrid",
        }
        algorithm = algo_map.get(choice, "")
        if not algorithm:
            print(f"  Error: Invalid choice '{choice}'.")
            sys.exit(1)
    print(f"  [OK] {ALGO_NAMES[algorithm]}")
    print()

    # --- Key generation ---
    key_dir.mkdir(parents=True, exist_ok=True)
    signing_key_path = ""

    if algorithm == "ed25519":
        key_path, pub_hex = _gen_ed25519(key_dir)
    elif algorithm == "hybrid":
        key_path, signing_key_path, pub_hex = _gen_hybrid(key_dir)
    elif algorithm in ("ml-dsa-65", "ml-dsa-87", "slh-dsa-128s"):
        key_path, signing_key_path, pub_hex = _gen_pq(key_dir, algorithm)
    else:
        print(f"  Error: Unhandled algorithm '{algorithm}'.")
        sys.exit(1)

    if len(pub_hex) <= 64:
        print(f"  [OK] Public key: {pub_hex}")
    else:
        print(f"  [OK] Public key: {pub_hex[:32]}...{pub_hex[-8:]} ({len(pub_hex)} hex)")
    print()

    # --- Step 2/3: Key generation (printed by _gen_* helpers above) ---

    # --- Step 3/3: On-chain registration (headless, no browser) ---
    pop_sig = _compute_pop(algorithm, api_key_id, key_path, signing_key_path)

    if not quickstart:
        print("Step 3/3: Registering on-chain")
    print()

    # Derive principal from PEM (this IS the caller identity for canister calls)
    org_id = ""
    try:
        org_id = _derive_principal_from_pem(key_path if algorithm == "ed25519"
                                            else key_dir / "agent_key.pem")
        print(f"  [OK] Principal: {org_id}")
    except Exception as e:
        print(f"  [WARN] Could not derive principal: {e}")
        print("  (Requires ic-py: pip install ic-py)")

    # Accept DPA + Register key on canister (headless)
    if org_id:
        try:
            from aegis.transport import CanisterTransport, TransportConfig

            pem_path = key_path if algorithm == "ed25519" else key_dir / "agent_key.pem"
            config = TransportConfig(
                canister_id=canister, private_key_path=str(pem_path)
            )
            transport = CanisterTransport(config)

            # Accept DPA (idempotent)
            _call_accept_dpa(transport)
            print("  [OK] DPA accepted")

            # Register API key with PoP
            _call_create_api_key(
                transport, api_key_id, org_id, api_key_id, pub_hex,
                algorithm, pop_sig, "Created by aegis init",
            )
            print(f"  [OK] Key \"{api_key_id}\" registered (free tier: 3 keys, 10k events/mo)")
        except Exception as e:
            err = str(e)
            if "already" in err.lower():
                print(f"  [OK] Key \"{api_key_id}\" already registered")
            else:
                print(f"  [WARN] On-chain registration failed: {err}")
                print("  Key will be registered on first 'aegis test' call.")
    print()

    # --- Write config ---
    project_aegis = Path.cwd() / ".aegis"
    is_project_local = project_aegis.is_dir()
    if not is_project_local and not quickstart:
        local_q = "  Save config to project (.aegis/) or global (~/.aegis/)? [g]: "
        local_choice = _prompt(local_q).strip().lower()
        if local_choice in ("p", "project", "local", "l"):
            is_project_local = True

    print("  Saving config...")
    cfg_path = write_config(
        canister_id=canister,
        api_key_id=api_key_id,
        agent_id=api_key_id,
        private_key_path=str(key_path),
        org_id=org_id,
        signing_scheme=algorithm if algorithm != "ed25519" else "",
        signing_key_path=signing_key_path,
        project_local=is_project_local,
    )
    print(f"  [OK] Config: {cfg_path}")
    if is_project_local:
        print("       (project-local — add .aegis/ to .gitignore!)")
    print()

    # --- Backup warning ---
    print("  BACKUP: Private key sicher aufbewahren!")
    print("  Ohne Key kein Zugang — Wiederherstellung ist NICHT moeglich.")
    print()

    # --- Auto-test ---
    print("  Testing connection...")
    try:
        from aegis.transport import CanisterTransport, TransportConfig

        tc = TransportConfig(
            canister_id=canister, private_key_path=str(
                key_path if algorithm == "ed25519" else key_dir / "agent_key.pem"
            )
        )
        transport = CanisterTransport(tc)
        health = transport.call_query("getHealth", [])
        entries = health.get("totalEntries", "?")
        print(f"  [OK] Canister online — {entries} entries on-chain")
    except Exception as e:
        print(f"  [WARN] Could not reach canister: {e}")
        print("  (The SDK works offline with spill-to-disk)")

    print()
    print("=== Setup complete ===")
    print()
    if org_id:
        print(f"  Your Principal: {org_id}")
        print("  To link with Dashboard: sign in and use 'Link CLI Key'.")
    print("  Next step:    aegis test")
    print("  Functions:    log_tool_call, log_decision, log_observation, log_error")
    print("  Frameworks:   Anthropic, OpenAI, LangChain, CrewAI, AutoGen + MCP")
    print("  All commands: aegis --help")
    print("  Docs:         https://www.aegis-ledger.com/docs")


# --- Canister Registration Helpers (B6.5: headless, no browser) ---


def _derive_principal_from_pem(pem_path: Path) -> str:
    """Derive ICP principal text from an Ed25519 PEM file."""
    from ic.identity import Identity  # type: ignore[import-untyped]

    pem_str = pem_path.read_text(encoding="utf-8")
    identity = Identity.from_pem(pem_str)
    return str(identity.sender())


def _call_accept_dpa(transport: object) -> int | None:
    """Call acceptDpa() on the canister. Idempotent — safe to call if already accepted."""
    try:
        result = transport._do_call("acceptDpa", [], call_type="update")  # type: ignore[attr-defined]
        # Returns timestamp (int) on success, or dict with raw value
        if isinstance(result, dict):
            raw = result.get("raw", result)
            return int(raw) if isinstance(raw, (int, float)) else None
        return int(result) if isinstance(result, (int, float)) else None
    except Exception as e:
        err = str(e).lower()
        if "grace period" in err or "7 days" in err or "cooldown" in err:
            print("  [FAIL] DPA was recently withdrawn. Wait 7 days.")
            sys.exit(1)
        if "already accepted" in err:
            return None  # Idempotent — already accepted
        raise


def _call_create_api_key(
    transport: object,
    key_id: str,
    org_id: str,
    prefix: str,
    pub_hex: str,
    algorithm: str,
    pop_sig: str,
    description: str = "",
) -> dict:
    """Register API key directly on canister via createApiKey()."""
    from ic.candid import Types  # type: ignore[import-untyped]

    args = [
        {"type": Types.Text, "value": key_id},
        {"type": Types.Principal, "value": org_id},
        {"type": Types.Text, "value": prefix},
        {"type": Types.Text, "value": pub_hex},
        {"type": Types.Opt(Types.Text), "value": [algorithm] if algorithm else []},
        {"type": Types.Opt(Types.Text), "value": [pop_sig] if pop_sig else []},
        {"type": Types.Opt(Types.Int), "value": []},  # no expiry
        {
            "type": Types.Opt(Types.Text),
            "value": [description] if description else [],
        },
    ]
    # Use _do_call directly — createApiKey must NEVER be spilled or retried.
    # Spilling admin calls causes poison entries that drain forever (14 GB RAM leak).
    return transport._do_call("createApiKey", args, call_type="update")  # type: ignore[attr-defined]


# --- Key Detection Helpers ---


def _detect_existing_keys(key_dir: Path) -> list[tuple[str, str, str]]:
    """Detect existing keys in key_dir. Returns [(algo, ext, path)]."""
    ext_to_algo = {
        ".pem": "ed25519", ".mldsa65": "ml-dsa-65",
        ".mldsa87": "ml-dsa-87", ".slh": "slh-dsa-128s",
    }
    existing: list[tuple[str, str, str]] = []
    if not key_dir.is_dir():
        return existing
    for ext, algo in ext_to_algo.items():
        kf = key_dir / ("agent_key" + ext)
        if kf.exists():
            existing.append((algo, ext, str(kf)))
    if (key_dir / "agent_key.hybrid.pub").exists():
        existing.append(("hybrid", ".hybrid", str(key_dir / "agent_key.pem")))
    return existing


def _gen_ed25519(key_dir: Path) -> tuple[Path, str]:
    """Generate or reuse Ed25519 key. Returns (key_path, pub_hex)."""
    key_path = key_dir / "agent_key.pem"
    if key_path.exists():
        print(f"  [OK] Key already exists: {key_path}")
        from aegis.crypto import get_public_key_hex, load_private_key

        pub_hex = get_public_key_hex(load_private_key(str(key_path)))
    else:
        print("  Generating Ed25519 keypair...")
        from aegis.crypto import generate_keypair

        try:
            _, pub_hex = generate_keypair(str(key_path))
        except FileExistsError:
            from aegis.crypto import get_public_key_hex, load_private_key

            pub_hex = get_public_key_hex(load_private_key(str(key_path)))
        print(f"  [OK] Private key: {key_path}")
    return key_path, pub_hex


def _gen_hybrid(key_dir: Path) -> tuple[Path, str, str]:
    """Generate or reuse Hybrid key. Returns (pem_path, signing_key_path, pub_hex)."""
    base_path = key_dir / "agent_key"
    key_path = base_path.with_suffix(".pem")
    pub_path = base_path.with_suffix(".hybrid.pub")
    sk_path = base_path.with_suffix(".mldsa65")
    ml_pub_path = sk_path.parent / (sk_path.name + ".pub")

    if key_path.exists() and sk_path.exists():
        print(f"  [OK] Keys already exist: {key_path}")
        if pub_path.exists():
            pub_hex = pub_path.read_text(encoding="utf-8").strip()
        elif ml_pub_path.exists():
            from aegis.crypto import get_public_key_hex, load_private_key

            ed_pub = get_public_key_hex(load_private_key(str(key_path)))
            ml_pub = ml_pub_path.read_text(encoding="utf-8").strip()
            pub_hex = ed_pub + ml_pub
            pub_path.write_text(pub_hex + "\n")
        else:
            pub_hex = "???"
    else:
        print("  Generating Hybrid (Ed25519 + ML-DSA-65) keypair...")
        if key_path.exists():
            from aegis.crypto import get_public_key_hex, load_private_key

            ed_key = load_private_key(str(key_path))
            ed_pub_hex = get_public_key_hex(ed_key)
            print(f"  [OK] Reusing transport key: {key_path}")
            from aegis.crypto import generate_mldsa65_keypair

            try:
                _, ml_pub_hex = generate_mldsa65_keypair(str(sk_path))
            except FileExistsError:
                ml_pub_hex = "???"
                if ml_pub_path.exists():
                    ml_pub_hex = ml_pub_path.read_text(encoding="utf-8").strip()
            pub_hex = ed_pub_hex + ml_pub_hex
            pub_path.write_text(pub_hex + "\n")
        else:
            from aegis.crypto import generate_hybrid_keypair

            try:
                _, _, pub_hex = generate_hybrid_keypair(str(base_path))
            except (FileExistsError, ImportError) as e:
                print(f"  Error: {e}")
                sys.exit(1)
        print(f"  [OK] Ed25519 key: {key_path}")
        print(f"  [OK] ML-DSA-65 key: {sk_path}")
    return key_path, str(sk_path), pub_hex


def _gen_pq(key_dir: Path, algorithm: str) -> tuple[Path, str, str]:
    """Generate or reuse PQ key. Returns (pem_path, signing_key_path, pub_hex)."""
    ext = {
        "ml-dsa-65": ".mldsa65", "ml-dsa-87": ".mldsa87",
        "slh-dsa-128s": ".slh",
    }[algorithm]
    key_path = key_dir / ("agent_key" + ext)
    pub_path = key_path.parent / (key_path.name + ".pub")
    pem_path = key_dir / "agent_key.pem"

    if not pem_path.exists():
        print("  Generating Ed25519 transport key...")
        from aegis.crypto import generate_keypair

        generate_keypair(str(pem_path))
        print(f"  [OK] Transport key: {pem_path}")

    if key_path.exists():
        print(f"  [OK] PQ key already exists: {key_path}")
        pub_hex = (
            pub_path.read_text(encoding="utf-8").strip()
            if pub_path.exists()
            else "???"
        )
    else:
        gen_fn_name = {
            "ml-dsa-65": "generate_mldsa65_keypair",
            "ml-dsa-87": "generate_mldsa87_keypair",
            "slh-dsa-128s": "generate_slhdsa128s_keypair",
        }[algorithm]
        print(f"  Generating {algorithm} keypair...")
        import aegis.crypto as _crypto

        try:
            gen_fn = getattr(_crypto, gen_fn_name)
            _, pub_hex = gen_fn(str(key_path))
        except (FileExistsError, ImportError) as e:
            print(f"  Error: {e}")
            sys.exit(1)
        print(f"  [OK] PQ key: {key_path}")
    return pem_path, str(key_path), pub_hex


def _compute_pop(
    algorithm: str, key_id: str, key_path: Path, signing_key_path: str,
) -> str:
    """Compute Proof of Possession signature for the given key ID."""
    pop_msg = f"aegis-pop:{key_id}".encode()
    try:
        if algorithm == "ed25519":
            from aegis.crypto import load_private_key, sign_payload

            sk = load_private_key(key_path)
            pop_sig = sign_payload(pop_msg, sk)
        elif algorithm == "hybrid":
            from aegis.crypto import load_private_key
            from aegis.schemes import create_scheme

            ed_sk = load_private_key(key_path)
            ml_sk_bytes = Path(signing_key_path).read_bytes()
            scheme = create_scheme("hybrid", (ed_sk, ml_sk_bytes))
            pop_sig = scheme.sign(pop_msg)
        else:
            from aegis.schemes import create_scheme

            sk_bytes = Path(signing_key_path).read_bytes()
            scheme = create_scheme(algorithm, sk_bytes)
            pop_sig = scheme.sign(pop_msg)
        print(f"  [OK] Proof of Possession computed for {key_id}")
        return pop_sig
    except Exception as e:
        print(f"  [WARN] Could not compute PoP: {e}")
        return ""
