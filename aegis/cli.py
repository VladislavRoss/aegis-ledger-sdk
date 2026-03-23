"""
aegis.cli -- Command-line utilities for Aegis SDK setup.

Commands:
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

    if command == "keygen":
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
            print("✓ Algorithm:            Hybrid (Ed25519 + ML-DSA-65)")
            print(f"✓ Ed25519 key:          {path}.pem")
            print(f"✓ ML-DSA-65 key:        {path}.mldsa65")
            print(f"✓ Combined public key:  {path}.hybrid.pub")
            print(f"✓ Public key (hex):     {pub_hex[:32]}...{pub_hex[-32:]}")
            print(f"✓ Public key length:    {len(pub_hex)} hex chars (3968)")
        elif algorithm == "slh-dsa-128s":
            from aegis.crypto import generate_slhdsa128s_keypair

            _, pub_hex = generate_slhdsa128s_keypair(path)
            print("✓ Algorithm:            SLH-DSA-SHAKE-128s (FIPS 205, hash-based PQ)")
            print(f"✓ Private key saved to: {path}")
            print(f"✓ Public key saved to:  {path}.pub")
            print(f"✓ Public key (hex):     {pub_hex}")
        elif algorithm == "ml-dsa-87":
            from aegis.crypto import generate_mldsa87_keypair

            _, pub_hex = generate_mldsa87_keypair(path)
            print("✓ Algorithm:            ML-DSA-87 (FIPS 204, CNSA 2.0 Level 5)")
            print(f"✓ Private key saved to: {path}")
            print(f"✓ Public key saved to:  {path}.pub")
            print(f"✓ Public key (hex):     {pub_hex[:32]}...{pub_hex[-32:]}")
        elif algorithm == "ml-dsa-65":
            from aegis.crypto import generate_mldsa65_keypair

            _, pub_hex = generate_mldsa65_keypair(path)
            print("✓ Algorithm:            ML-DSA-65 (FIPS 204, post-quantum)")
            print(f"✓ Private key saved to: {path}")
            print(f"✓ Public key saved to:  {path}.pub")
            print(f"✓ Public key (hex):     {pub_hex[:32]}...{pub_hex[-32:]}")
        else:
            from aegis.crypto import generate_keypair

            _, pub_hex = generate_keypair(path)
            print("✓ Algorithm:            Ed25519 (classical)")
            print(f"✓ Private key saved to: {path}")
            print(f"✓ Public key saved to:  {path}.pub")
            print(f"✓ Public key (hex):     {pub_hex}")
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
            print(f"✓ VERIFIED — Entry {action_id} chain hash is valid")
            print(f"  Chain hash: {result.get('storedChainHash', 'N/A')}")
            print(f"  Previous:   {result.get('previousChainHash', 'N/A')}")
            print(f"  Sequence:   {result.get('sequenceNumber', 'N/A')}")
        else:
            print(f"✗ INVALID — Entry {action_id}")
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
            print(f"✓ CHAIN VALID — {result['verified']}/{result['total']} entries verified")
        else:
            print(f"✗ CHAIN BROKEN — {result['verified']}/{result['total']} entries valid")
            for f in result["failures"]:
                print(f"  ✗ seq={f['seq']} {f['action_id']}: {f['reason']}")

        if result["sequence_gaps"]:
            print(f"  Sequence gaps: {len(result['sequence_gaps'])}")
            for g in result["sequence_gaps"]:
                print(f"    gap after seq {g['after_seq']} → got {g['got_seq']}")

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
