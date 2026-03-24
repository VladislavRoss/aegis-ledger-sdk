"""
aegis.cli -- Command-line utilities for Aegis SDK setup.

Commands:
    aegis init                         Interactive setup wizard (recommended)
    aegis keygen ./my_agent_key.pem    Generate an Ed25519 keypair
    aegis verify <canister_id> <action_id>  Verify a single ledger entry
    aegis verify-chain <canister_id> <session_id>  Verify full session chain offline
    aegis status <canister_id>          Check canister health
    aegis report <canister_id>          Generate compliance report
"""

from __future__ import annotations

import sys


def main() -> None:
    """Entry point for the `aegis` CLI command."""
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help", "help"):
        _print_help()
        return

    command = args[0]

    if command == "init":
        _cmd_init(args[1:])
    elif command == "test":
        _cmd_test(args[1:])
    elif command == "keygen":
        _cmd_keygen(args[1:])
    elif command == "verify":
        _cmd_verify(args[1:])
    elif command == "verify-chain":
        _cmd_verify_chain(args[1:])
    elif command == "status":
        _cmd_status(args[1:])
    elif command == "report":
        _cmd_report(args[1:])
    elif command == "migrate":
        _cmd_migrate(args[1:])
    elif command == "version":
        from aegis import __version__

        print(f"aegis-ledger-sdk {__version__}")
    else:
        print(f"Unknown command: {command}")
        _print_help()
        sys.exit(1)


def _print_help() -> None:
    print(
        """
aegis-ledger-sdk -- Tamper-evident execution ledger for AI agents

Commands:
  init [--algorithm ALG]            Setup wizard (generates key + config)
  test                              Send a test entry and verify on-chain
  keygen <path> [--algorithm ALG]   Generate keypair for agent signing
  verify <canister_id> <action_id>  Verify a ledger entry's chain hash
  verify-chain <canister_id> <sid>  Verify full session chain offline
  status <canister_id>              Check canister health and chain stats
  report <canister_id> [--format F] Generate compliance report
  migrate [options]                 Re-sign entries with a new algorithm
  version                           Print SDK version

Algorithms (keygen):
  ed25519       Ed25519 (default, classical)
  ml-dsa-65     ML-DSA-65 / FIPS 204 (post-quantum, requires pqcrypto)
  ml-dsa-87     ML-DSA-87 / FIPS 204 CNSA 2.0 Level 5 (requires pqcrypto)
  slh-dsa-128s  SLH-DSA-SHAKE-128s / FIPS 205 (hash-based PQ fallback)
  hybrid        Ed25519 + ML-DSA-65 combined (requires pqcrypto)

Report Formats:
  eu-ai-act   EU AI Act Article 12 (default)
  iso-42001   ISO/IEC 42001 AI Management System
  aiuc-1      AIUC-1 Insurance Underwriting Criteria
  all         Generate all formats

Examples:
  aegis keygen ./keys/my_agent.pem
  aegis keygen ./keys/my_agent.mldsa65 --algorithm ml-dsa-65
  aegis keygen ./keys/my_agent.mldsa87 --algorithm ml-dsa-87
  aegis keygen ./keys/my_agent.slh --algorithm slh-dsa-128s
  aegis keygen ./keys/my_agent --algorithm hybrid
  aegis verify toqqq-lqaaa-aaaae-afc2a-cai act_a7f3b2c19e4d
  aegis report toqqq-lqaaa-aaaae-afc2a-cai --format eu-ai-act
  aegis report toqqq-lqaaa-aaaae-afc2a-cai --format all -o ./reports/
        """.strip()
    )


def _cmd_init(args: list[str]) -> None:
    """Interactive setup wizard: keygen + config + dashboard link."""
    import secrets
    from pathlib import Path
    from urllib.parse import quote

    from aegis.config import _CONFIG_DIR, write_config

    canister = "toqqq-lqaaa-aaaae-afc2a-cai"
    dash_base = "https://www.aegis-ledger.com/dashboard"
    algo_names = {
        "ed25519": "Ed25519 (classical, default)",
        "ml-dsa-65": "ML-DSA-65 (FIPS 204, post-quantum)",
        "ml-dsa-87": "ML-DSA-87 (FIPS 204, CNSA 2.0 Level 5)",
        "slh-dsa-128s": "SLH-DSA-128s (FIPS 205, hash-based PQ)",
        "hybrid": "Hybrid (Ed25519 + ML-DSA-65)",
    }

    # Parse --algorithm flag
    algorithm = "ed25519"
    if "--algorithm" in args:
        idx = args.index("--algorithm")
        if idx + 1 < len(args):
            algorithm = args[idx + 1]
            if algorithm not in algo_names:
                print(f"Error: Unknown algorithm '{algorithm}'.")
                print(f"Available: {', '.join(algo_names)}")
                sys.exit(1)

    print()
    print("=== Aegis SDK Setup ===")
    print()

    # --- Step 1: Algorithm selection (interactive if not passed via flag) ---
    if "--algorithm" not in args:
        print("Step 1/4: Choose signature algorithm")
        print()
        print("  [1] Ed25519          — fast, classical (default)")
        print("  [2] ML-DSA-65        — FIPS 204 post-quantum")
        print("  [3] ML-DSA-87        — CNSA 2.0 Level 5")
        print("  [4] SLH-DSA-128s     — hash-based PQ fallback")
        print("  [5] Hybrid           — Ed25519 + ML-DSA-65 combined")
        print()
        choice = _prompt("  Choice [1]: ").strip()
        algo_map = {"": "ed25519", "1": "ed25519", "2": "ml-dsa-65", "3": "ml-dsa-87",
                     "4": "slh-dsa-128s", "5": "hybrid"}
        algorithm = algo_map.get(choice, "")
        if not algorithm:
            print(f"  Error: Invalid choice '{choice}'.")
            sys.exit(1)
    print(f"  [OK] Algorithm: {algo_names[algorithm]}")
    print()

    # --- Step 2: Key generation ---
    key_dir = _CONFIG_DIR / "keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    signing_key_path = ""

    if algorithm == "ed25519":
        key_path = key_dir / "agent_key.pem"
        pub_path = Path(str(key_path) + ".pub")
        if key_path.exists():
            print(f"  [OK] Key already exists: {key_path}")
            pub_hex = pub_path.read_text(encoding="utf-8").strip() if pub_path.exists() else "???"
        else:
            print("  Generating Ed25519 keypair...")
            from aegis.crypto import generate_keypair
            try:
                _, pub_hex = generate_keypair(str(key_path))
            except FileExistsError:
                pub_hex = pub_path.read_text(encoding="utf-8").strip() if pub_path.exists() else "?"
            print(f"  [OK] Private key: {key_path}")
    elif algorithm == "hybrid":
        base_path = key_dir / "agent_key"
        key_path = Path(str(base_path) + ".pem")
        pub_path = Path(str(base_path) + ".hybrid.pub")
        sk_path = Path(str(base_path) + ".mldsa65")
        if key_path.exists() and sk_path.exists():
            print(f"  [OK] Keys already exist: {key_path}")
            pub_hex = pub_path.read_text(encoding="utf-8").strip() if pub_path.exists() else "???"
        else:
            print("  Generating Hybrid (Ed25519 + ML-DSA-65) keypair...")
            from aegis.crypto import generate_hybrid_keypair
            try:
                _, _, pub_hex = generate_hybrid_keypair(str(base_path))
            except (FileExistsError, ImportError) as e:
                print(f"  Error: {e}")
                sys.exit(1)
            print(f"  [OK] Ed25519 key: {key_path}")
            print(f"  [OK] ML-DSA-65 key: {sk_path}")
        signing_key_path = str(sk_path)
    elif algorithm in ("ml-dsa-65", "ml-dsa-87", "slh-dsa-128s"):
        ext = {"ml-dsa-65": ".mldsa65", "ml-dsa-87": ".mldsa87", "slh-dsa-128s": ".slh"}[algorithm]
        key_path = key_dir / ("agent_key" + ext)
        pub_path = Path(str(key_path) + ".pub")
        # PQ algorithms still need a PEM for IC transport
        pem_path = key_dir / "agent_key.pem"
        if not pem_path.exists():
            print("  Generating Ed25519 transport key...")
            from aegis.crypto import generate_keypair
            generate_keypair(str(pem_path))
            print(f"  [OK] Transport key: {pem_path}")
        if key_path.exists():
            print(f"  [OK] PQ key already exists: {key_path}")
            pub_hex = pub_path.read_text(encoding="utf-8").strip() if pub_path.exists() else "???"
        else:
            gen_fn_name = {"ml-dsa-65": "generate_mldsa65_keypair",
                           "ml-dsa-87": "generate_mldsa87_keypair",
                           "slh-dsa-128s": "generate_slhdsa128s_keypair"}[algorithm]
            print(f"  Generating {algorithm} keypair...")
            import aegis.crypto as _crypto
            try:
                gen_fn = getattr(_crypto, gen_fn_name)
                _, pub_hex = gen_fn(str(key_path))
            except (FileExistsError, ImportError) as e:
                print(f"  Error: {e}")
                sys.exit(1)
            print(f"  [OK] PQ key: {key_path}")
        key_path = pem_path  # config.toml stores the PEM path for IC transport
        signing_key_path = str(key_dir / ("agent_key" + ext))
    else:
        print(f"  Error: Unhandled algorithm '{algorithm}'.")
        sys.exit(1)

    print(f"  [OK] Public key: {pub_hex[:32]}{'...' if len(pub_hex) > 64 else ''}")
    print()

    # --- Step 3: Open Dashboard with pre-filled URL + PoP ---
    suggested_id = "ak_" + secrets.token_hex(3)

    # Compute Proof of Possession signature
    pop_msg = f"aegis-pop:{suggested_id}".encode()
    pop_sig = ""
    try:
        if algorithm == "ed25519":
            from aegis.crypto import load_private_key, sign_payload
            sk = load_private_key(key_path)
            pop_sig = sign_payload(pop_msg, sk)
        elif algorithm == "hybrid":
            from aegis.crypto import load_private_key
            from aegis.schemes import create_scheme, HybridScheme
            ed_sk = load_private_key(key_path)
            ml_sk_bytes = Path(signing_key_path).read_bytes()
            scheme = create_scheme("hybrid", (ed_sk, ml_sk_bytes))
            pop_sig = scheme.sign(pop_msg)
        else:
            from aegis.schemes import create_scheme
            sk_bytes = Path(signing_key_path).read_bytes()
            scheme = create_scheme(algorithm, sk_bytes)
            pop_sig = scheme.sign(pop_msg)
        print(f"  [OK] Proof of Possession computed")
    except Exception as e:
        print(f"  [WARN] Could not compute PoP: {e}")
        print(f"  You may need to paste the PoP manually in the Dashboard.")

    dash_url = (
        f"{dash_base}"
        f"?pubkey={quote(pub_hex)}"
        f"&keyid={quote(suggested_id)}"
        f"&prefix={quote(suggested_id)}"
        + (f"&pop={quote(pop_sig)}" if pop_sig else "")
    )

    print("Step 3/4: Register key in Dashboard")
    print()
    print("  Dashboard opens with all fields pre-filled (incl. PoP).")
    print("  Sign in, accept the DPA, then click ISSUE KEY.")
    print()

    try:
        import webbrowser
        webbrowser.open(dash_url)
        print("  [OK] Browser opened")
    except Exception:
        print(f"  Open this URL: {dash_url}")

    print()
    print(f"  Suggested Key ID: {suggested_id}")
    api_key_id = _prompt(f"  Enter Key ID from Dashboard [{suggested_id}]: ").strip()
    if not api_key_id:
        api_key_id = suggested_id

    print()

    # --- Step 4: Write config ---
    print("Step 4/4: Writing config...")
    cfg_path = write_config(
        canister_id=canister,
        api_key_id=api_key_id,
        agent_id=api_key_id,
        private_key_path=str(key_path),
        signing_scheme=algorithm if algorithm != "ed25519" else "",
        signing_key_path=signing_key_path,
    )
    print(f"  [OK] Config saved: {cfg_path}")
    print()

    print("  from aegis import AegisClient")
    print("  client = AegisClient.from_config()")
    print()

    # --- Auto-test ---
    print("  Testing connection...")
    try:
        from aegis.transport import CanisterTransport, TransportConfig

        config = TransportConfig(canister_id=canister)
        transport = CanisterTransport(config)
        health = transport.call_query("getHealth", [])
        entries = health.get("totalEntries", "?")
        print(f"  [OK] Canister online — {entries} entries on-chain")
    except Exception as e:
        print(f"  [WARN] Could not reach canister: {e}")
        print("  (The SDK works offline with spill-to-disk)")

    print()
    print("=== Setup complete ===")


def _prompt(text: str) -> str:
    """Read a line from stdin, handling EOF gracefully."""
    try:
        return input(text)
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)


def _cmd_test(args: list[str]) -> None:
    """Send a real test entry via from_config() and verify it on-chain."""
    print()
    print("=== Aegis Connection Test ===")
    print()
    try:
        from aegis.client import AegisClient

        print("  Loading config...")
        client = AegisClient.from_config()
        print(f"  [OK] Client: canister={client._canister_id} key={client._api_key_id}")
        print(f"  [OK] Agent: {client._agent_id} session={client._session_id}")
        print(f"  [OK] Algorithm: {client._scheme.algorithm_id}")
        print()

        print("  Sending test entry to canister...")
        action_id = client.log_tool_call(
            tool="aegis.test",
            input_data={"test": True, "source": "aegis test CLI"},
            output_data={"status": "ok"},
            duration_ms=0,
        )
        print(f"  [OK] Entry logged: {action_id}")
        print()

        print("  Verifying on-chain...")
        from aegis.transport import CanisterTransport, TransportConfig
        from ic.candid import Types  # type: ignore[import-untyped]

        config = TransportConfig(
            canister_id=client._canister_id,
            private_key_path=client._transport._config.private_key_path,
        )
        transport = CanisterTransport(config)
        result = transport.call_query(
            "verifyEntry", [{"type": Types.Text, "value": action_id}]
        )
        if result.get("isValid"):
            print("  [OK] VERIFIED — hash chain valid, signature on-chain")
        else:
            print(f"  [FAIL] Verification failed: {result.get('message', '?')}")
            sys.exit(2)

    except FileNotFoundError as e:
        print(f"  Error: {e}")
        print("  Run 'aegis init' first.")
        sys.exit(1)
    except Exception as e:
        print(f"  Error: {e}")
        sys.exit(1)

    print()
    print("=== All checks passed ===")


def _cmd_keygen(args: list[str]) -> None:
    """Generate a keypair (Ed25519, ML-DSA-65, or Hybrid)."""
    if not args:
        print("Usage: aegis keygen <output_path> [--algorithm ed25519|ml-dsa-65|hybrid]")
        print("Example: aegis keygen ./agent_key.pem")
        print("Example: aegis keygen ./agent_key.mldsa65 --algorithm ml-dsa-65")
        print("Example: aegis keygen ./agent --algorithm hybrid")
        sys.exit(1)

    algorithm = "ed25519"
    path = args[0]

    if "--algorithm" in args:
        idx = args.index("--algorithm")
        if idx + 1 < len(args):
            algorithm = args[idx + 1]
            if algorithm not in ("ed25519", "ml-dsa-65", "ml-dsa-87", "slh-dsa-128s", "hybrid"):
                print(
                    f"Error: Unknown algorithm '{algorithm}'. "
                    "Use 'ed25519', 'ml-dsa-65', 'ml-dsa-87', 'slh-dsa-128s', or 'hybrid'."
                )
                sys.exit(1)

    try:
        if algorithm == "hybrid":
            from aegis.crypto import generate_hybrid_keypair

            _, _, pub_hex = generate_hybrid_keypair(path)
            print("[OK] Algorithm:            Hybrid (Ed25519 + ML-DSA-65)")
            print(f"[OK] Ed25519 key:          {path}.pem")
            print(f"[OK] ML-DSA-65 key:        {path}.mldsa65")
            print(f"[OK] Combined public key:  {path}.hybrid.pub")
            print(f"[OK] Public key (hex):     {pub_hex[:32]}...{pub_hex[-32:]}")
            print(f"[OK] Public key length:    {len(pub_hex)} hex chars (3968)")
        elif algorithm == "slh-dsa-128s":
            from aegis.crypto import generate_slhdsa128s_keypair

            _, pub_hex = generate_slhdsa128s_keypair(path)
            print("[OK] Algorithm:            SLH-DSA-SHAKE-128s (FIPS 205, hash-based PQ)")
            print(f"[OK] Private key saved to: {path}")
            print(f"[OK] Public key saved to:  {path}.pub")
            print(f"[OK] Public key (hex):     {pub_hex}")
        elif algorithm == "ml-dsa-87":
            from aegis.crypto import generate_mldsa87_keypair

            _, pub_hex = generate_mldsa87_keypair(path)
            print("[OK] Algorithm:            ML-DSA-87 (FIPS 204, CNSA 2.0 Level 5)")
            print(f"[OK] Private key saved to: {path}")
            print(f"[OK] Public key saved to:  {path}.pub")
            print(f"[OK] Public key (hex):     {pub_hex[:32]}...{pub_hex[-32:]}")
        elif algorithm == "ml-dsa-65":
            from aegis.crypto import generate_mldsa65_keypair

            _, pub_hex = generate_mldsa65_keypair(path)
            print("[OK] Algorithm:            ML-DSA-65 (FIPS 204, post-quantum)")
            print(f"[OK] Private key saved to: {path}")
            print(f"[OK] Public key saved to:  {path}.pub")
            print(f"[OK] Public key (hex):     {pub_hex[:32]}...{pub_hex[-32:]}")
        else:
            from aegis.crypto import generate_keypair

            _, pub_hex = generate_keypair(path)
            print("[OK] Algorithm:            Ed25519 (classical)")
            print(f"[OK] Private key saved to: {path}")
            print(f"[OK] Public key saved to:  {path}.pub")
            print(f"[OK] Public key (hex):     {pub_hex}")
    except FileExistsError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except ImportError as e:
        print(f"Error: {e}")
        sys.exit(1)
    print()
    print("Next steps:")
    print("  1. Register the public key in the Aegis dashboard")
    print("  2. Use the key path(s) in your AegisClient config")
    print(f"  3. NEVER commit {path}* to version control")


def _cmd_verify(args: list[str]) -> None:
    """Verify a ledger entry via on-chain verifyEntry query."""
    if len(args) < 2:
        print("Usage: aegis verify <canister_id> <action_id>")
        sys.exit(1)

    canister_id, action_id = args[0], args[1]

    try:
        from aegis.transport import CanisterTransport, TransportConfig
        from ic.candid import Types  # type: ignore[import-untyped]

        config = TransportConfig(canister_id=canister_id)
        transport = CanisterTransport(config)
        result = transport.call_query(
            "verifyEntry", [{"type": Types.Text, "value": action_id}]
        )

        if result.get("isValid"):
            print(f"[OK] VERIFIED — Entry {action_id} chain hash is valid")
            print(f"  Chain hash: {result.get('storedChainHash', 'N/A')}")
            print(f"  Previous:   {result.get('previousChainHash', 'N/A')}")
            print(f"  Sequence:   {result.get('sequenceNumber', 'N/A')}")
        else:
            print(f"[FAIL] INVALID — Entry {action_id}")
            msg = result.get("message", "unknown reason")
            print(f"  Reason:     {msg}")
            print(f"  Chain hash: {result.get('storedChainHash', 'N/A')}")
            sys.exit(2)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def _cmd_verify_chain(args: list[str]) -> None:
    """Verify full session hash-chain offline via replay."""
    if len(args) < 2:
        print("Usage: aegis verify-chain <canister_id> <session_id>")
        print()
        print("Fetches all entries for a session and re-computes every")
        print("chain hash locally. No trust in the canister required.")
        sys.exit(1)

    canister_id, session_id = args[0], args[1]

    try:
        from aegis.transport import CanisterTransport, TransportConfig
        from aegis.verify import verify_chain
        from ic.candid import Types  # type: ignore[import-untyped]

        config = TransportConfig(canister_id=canister_id)
        transport = CanisterTransport(config)
        entries = transport.call_query(
            "getTrace", [{"type": Types.Text, "value": session_id}]
        )

        if not entries or not isinstance(entries, list):
            print(f"No entries found for session {session_id}")
            sys.exit(2)

        result = verify_chain(entries)

        if result["valid"]:
            print(f"[OK] CHAIN VALID — {result['verified']}/{result['total']} entries verified")
        else:
            print(f"[FAIL] CHAIN BROKEN — {result['verified']}/{result['total']} entries valid")
            for f in result["failures"]:
                print(f"  [FAIL] seq={f['seq']} {f['action_id']}: {f['reason']}")

        if result["sequence_gaps"]:
            print(f"  Sequence gaps: {len(result['sequence_gaps'])}")
            for g in result["sequence_gaps"]:
                print(f"    gap after seq {g['after_seq']} -> got {g['got_seq']}")

        if not result["valid"]:
            sys.exit(2)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def _cmd_status(args: list[str]) -> None:
    """Check canister health via on-chain getHealth query."""
    if not args:
        print("Usage: aegis status <canister_id>")
        sys.exit(1)

    canister_id = args[0]

    try:
        from aegis.transport import CanisterTransport, TransportConfig

        config = TransportConfig(canister_id=canister_id)
        transport = CanisterTransport(config)
        health = transport.call_query("getHealth", [])

        print(f"Aegis Canister: {canister_id}")
        print(f"  Total entries:    {health.get('totalEntries', 'N/A')}")
        print(f"  API keys:         {health.get('totalKeys', 'N/A')}")
        print(f"  Organizations:    {health.get('totalOrgs', 'N/A')}")
        print(f"  Heap bytes:       {health.get('heapBytes', 'N/A')}")
        print(f"  Cycles balance:   {health.get('cyclesBalance', 'N/A')}")
        deferred = health.get("deferredVerifications", 0)
        if deferred:
            print(f"  Deferred verif.:  {deferred}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def _cmd_report(args: list[str]) -> None:
    """Generate compliance report."""
    if not args:
        print("Usage: aegis report <canister_id> [--format eu-ai-act|iso-42001|aiuc-1|all]")
        print()
        print("Options:")
        print("  --format F   Report format (default: eu-ai-act)")
        print("  -o PATH      Output file or directory (for --format all)")
        sys.exit(1)

    canister_id = args[0]
    format_str = "eu-ai-act"
    output_path = ""

    if "--format" in args:
        idx = args.index("--format")
        if idx + 1 < len(args):
            format_str = args[idx + 1]

    if "-o" in args:
        idx = args.index("-o")
        if idx + 1 < len(args):
            output_path = args[idx + 1]

    try:
        from aegis.report import ReportFormat, generate_all_reports, generate_report

        valid_formats = {f.value for f in ReportFormat}

        if format_str == "all":
            reports = generate_all_reports(
                canister_id=canister_id,
                output_dir=output_path,
            )
            for r in reports:
                print(f"--- {r.format.value} (score: {int(r.summary.compliance_score * 100)}%) ---")
                if not output_path:
                    print(r.markdown)
                else:
                    print(f"  Written to: {output_path}/aegis-{r.format.value}-report.md")
                print()
        elif format_str in valid_formats:
            fmt = ReportFormat(format_str)
            report = generate_report(
                canister_id=canister_id,
                format=fmt,
                output_path=output_path,
            )
            if output_path:
                print(f"Report written to: {output_path}")
                print(f"Compliance score: {int(report.summary.compliance_score * 100)}%")
            else:
                print(report.markdown)
        else:
            print(f"Unknown format: {format_str}")
            print(f"Valid formats: {', '.join(sorted(valid_formats))}, all")
            sys.exit(1)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def _cmd_migrate(args: list[str]) -> None:
    """Re-sign entries from a canister session with a new algorithm."""
    if not args or args[0] in ("-h", "--help"):
        print(
            """
Usage: aegis migrate <canister_id> <session_id> [options]

Re-sign ledger entries with a different signature algorithm,
producing a migration proof JSON file.

Options:
  --to ALG            Target algorithm (ml-dsa-65, slh-dsa-128s, hybrid)
  --pem PATH          Ed25519 PEM key (for hybrid)
  --signing-key PATH  PQ secret key file
  -o PATH             Output file (default: migration_<session>.json)

Examples:
  aegis migrate toqqq-... sess_abc --to hybrid --pem ./key.pem --signing-key ./key.mldsa65
  aegis migrate toqqq-... sess_abc --to slh-dsa-128s --signing-key ./key.slh
            """.strip()
        )
        sys.exit(0)

    if len(args) < 2:
        print("Error: canister_id and session_id required.")
        sys.exit(1)

    canister_id, session_id = args[0], args[1]
    target_algo = "hybrid"
    pem_path = ""
    signing_key_path = ""
    output_path = ""

    i = 2
    while i < len(args):
        if args[i] == "--to" and i + 1 < len(args):
            target_algo = args[i + 1]
            i += 2
        elif args[i] == "--pem" and i + 1 < len(args):
            pem_path = args[i + 1]
            i += 2
        elif args[i] == "--signing-key" and i + 1 < len(args):
            signing_key_path = args[i + 1]
            i += 2
        elif args[i] == "-o" and i + 1 < len(args):
            output_path = args[i + 1]
            i += 2
        else:
            i += 1

    try:
        from aegis.migrate import migrate_session

        report = migrate_session(
            canister_id=canister_id,
            session_id=session_id,
            target_algorithm=target_algo,
            pem_path=pem_path or None,
            signing_key_path=signing_key_path or None,
            output_path=output_path or None,
        )

        print(f"Migration complete: {report['total_entries']} entries re-signed")
        print(f"  Algorithm: {report['source_algorithm']} -> {report['target_algorithm']}")
        print(f"  Output:    {report['output_file']}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
