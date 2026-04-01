"""
aegis.cli -- Command-line utilities for Aegis SDK setup.

Commands:
    aegis init                         Interactive setup wizard (recommended)
    aegis keygen ./my_agent_key.pem    Generate an Ed25519 keypair
    aegis verify <canister_id> <action_id>  Verify a single ledger entry
    aegis verify-chain <canister_id> <session_id>  Verify full session chain offline
    aegis status [canister_id]          Check canister health
    aegis report [canister_id]          Generate compliance report
"""

from __future__ import annotations

import sys

from aegis.integrity import HEALTH_HASH_MAP as _HEALTH_HASH_MAP
from aegis.integrity import ORG_STATS_HASH_MAP as _ORG_STATS_HASH_MAP
from aegis.integrity import SESSION_COMPLETENESS_HASH_MAP as _SC_HASH_MAP
from aegis.integrity import VERIFY_HASH_MAP as _VERIFY_HASH_MAP
from aegis.integrity import map_candid_keys as _map_candid_keys


def _transport_from_config(canister_id: str | None = None):
    """Create a CanisterTransport using config.toml identity.

    Falls back to the provided canister_id, or reads it from config.
    """
    from aegis.config import get_client_config, load_config
    from aegis.transport import CanisterTransport, TransportConfig

    cfg = load_config()
    client_cfg = get_client_config(cfg)
    pk_path = client_cfg.get("private_key_path")
    cid = canister_id or client_cfg.get("canister_id", "")

    if not cid:
        print("Error: No canister_id provided and none found in ~/.aegis/config.toml")
        sys.exit(1)

    config = TransportConfig(canister_id=cid, private_key_path=pk_path)
    return CanisterTransport(config), cid


def main() -> None:
    """Entry point for the `aegis` CLI command."""
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help", "help"):
        _print_help()
        return

    command = args[0]

    if command == "init":
        from aegis.cli_init import cmd_init

        cmd_init(args[1:])
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
    elif command == "spill-status":
        _cmd_spill_status()
    elif command == "list-sessions":
        _cmd_list_sessions(args[1:])
    elif command == "doctor":
        _cmd_doctor(args[1:])
    elif command == "register-key":
        from aegis.cli_keys import cmd_register_key

        cmd_register_key(args[1:])
    elif command == "revoke":
        from aegis.cli_keys import cmd_revoke

        cmd_revoke(args[1:])
    elif command == "reactivate-key":
        from aegis.cli_selfservice import cmd_reactivate_key

        cmd_reactivate_key(args[1:])
    elif command == "delete-key":
        from aegis.cli_selfservice import cmd_delete_key

        cmd_delete_key(args[1:])
    elif command == "update-key-desc":
        from aegis.cli_selfservice import cmd_update_key_desc

        cmd_update_key_desc(args[1:])
    elif command == "purge-session":
        from aegis.cli_selfservice import cmd_purge_session

        cmd_purge_session(args[1:])
    elif command == "session-analytics":
        _cmd_session_analytics(args[1:])
    elif command == "org-stats":
        _cmd_org_stats(args[1:])
    elif command == "export-otel":
        _cmd_export_otel(args[1:])
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
  verify [canister_id] <action_id>  Verify a ledger entry's chain hash
  verify-chain [canister_id] <sid>  Verify full session chain offline
  status [canister_id]              Check canister health and chain stats
  report [canister_id] [--format F] Generate compliance report
  migrate [options]                 Re-sign entries with a new algorithm
  spill-status                      Show pending spill entries (offline buffer)
  list-sessions [canister_id]       List your sessions on the canister
  doctor                            Check SDK health (config, keys, canister)
  register-key <id> --key-file <f>  Register a new API key via Dashboard
  revoke <key_id>                   Revoke an API key (confirmation required)
  reactivate-key <key_id>           Reactivate a revoked key (owner only)
  delete-key <key_id>               Permanently delete a revoked key
  update-key-desc <id> <desc>       Update key description (max 256 chars)
  purge-session <sid> [--batch-limit N]  Purge session entries (owner/admin)
  session-analytics <sid>           Session error rate, duration, action types
  org-stats [canister_id]           Aggregated org statistics (entries, agents)
  export-otel <sid> [--endpoint URL] Export session as OTel spans
  version                           Print SDK version

Algorithms (keygen/init):
  ed25519       Ed25519 (classical)
  ml-dsa-65     ML-DSA-65 / FIPS 204 (post-quantum, RECOMMENDED)
  ml-dsa-87     ML-DSA-87 / FIPS 204 CNSA 2.0 Level 5
  slh-dsa-128s  SLH-DSA-SHAKE-128s / FIPS 205 (EXPERIMENTAL)
  hybrid        Ed25519 + ML-DSA-65 combined

Report Formats:
  eu-ai-act   EU AI Act Article 12 (default)
  iso-42001   ISO/IEC 42001 AI Management System
  aiuc-1      AIUC-1 Insurance Underwriting Criteria
  all         Generate all formats

Examples:
  aegis init
  aegis keygen ./keys/my_agent.pem
  aegis keygen ./keys/my_agent.mldsa65 --algorithm ml-dsa-65
  aegis verify toqqq-lqaaa-aaaae-afc2a-cai act_a7f3b2c19e4d
  aegis report toqqq-lqaaa-aaaae-afc2a-cai --format eu-ai-act
        """.strip()
    )


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
        raw = transport.call_query("verifyEntry", [{"type": Types.Text, "value": action_id}])
        result = _map_candid_keys(raw, _VERIFY_HASH_MAP) if isinstance(raw, dict) else raw
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
    print()
    print(f"  Entry {action_id} is verified on-chain.")
    print("  View in dashboard: https://www.aegis-ledger.com/dashboard")
    print("  List all sessions: aegis list-sessions")


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
    if len(args) < 1:
        print("Usage: aegis verify [canister_id] <action_id>")
        print("  canister_id is optional if configured in ~/.aegis/config.toml")
        sys.exit(1)

    # Support both: aegis verify <action_id>  and  aegis verify <canister_id> <action_id>
    if len(args) >= 2 and "-" in args[0]:
        canister_id_arg, action_id = args[0], args[1]
    else:
        canister_id_arg, action_id = None, args[0]

    try:
        from ic.candid import Types  # type: ignore[import-untyped]

        transport, canister_id = _transport_from_config(canister_id_arg)
        raw = transport.call_query("verifyEntry", [{"type": Types.Text, "value": action_id}])
        result = _map_candid_keys(raw, _VERIFY_HASH_MAP) if isinstance(raw, dict) else raw

        if result.get("isValid"):
            print(f"[OK] VERIFIED — Entry {action_id} chain hash is valid")
            print(f"  Chain hash: {result.get('storedChainHash', 'N/A')}")
            print(f"  Previous:   {result.get('previousChainHash', 'N/A')}")
            print(f"  Sequence:   {result.get('sequenceNumber', 'N/A')}")
            msg = result.get("message", "")
            if msg:
                print(f"  Detail:     {msg}")
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
    if len(args) < 1:
        print("Usage: aegis verify-chain [canister_id] <session_id>")
        print()
        print("Fetches all entries for a session and re-computes every")
        print("chain hash locally. No trust in the canister required.")
        print("canister_id is optional if configured in ~/.aegis/config.toml")
        sys.exit(1)

    # Support both: aegis verify-chain <session_id>
    # and: aegis verify-chain <canister_id> <session_id>
    if len(args) >= 2 and "-" in args[0]:
        canister_id_arg, session_id = args[0], args[1]
    else:
        canister_id_arg, session_id = None, args[0]

    try:
        from aegis.verify import verify_chain
        from ic.candid import Types  # type: ignore[import-untyped]

        transport, canister_id = _transport_from_config(canister_id_arg)
        result = transport.call_query(
            "getTrace",
            [
                {"type": Types.Text, "value": session_id},
                {"type": Types.Null, "value": None},
                {"type": Types.Null, "value": None},
            ],
        )
        entries = result.get("raw", result) if isinstance(result, dict) else result

        if not entries or not isinstance(entries, list):
            print(f"No entries found for session {session_id}")
            sys.exit(2)

        from aegis.integrity import LEDGER_ENTRY_HASH_MAP

        entries = [_map_candid_keys(e, LEDGER_ENTRY_HASH_MAP) for e in entries]
        # payloadHex comes as list with single hex string
        for e in entries:
            ph = e.get("payloadHex")
            if isinstance(ph, list) and ph:
                e["payloadHex"] = ph[0]

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
    canister_id_arg = args[0] if args else None

    try:
        transport, canister_id = _transport_from_config(canister_id_arg)
        raw = transport.call_query("getHealth", [])
        health = _map_candid_keys(raw, _HEALTH_HASH_MAP) if isinstance(raw, dict) else raw

        print(f"Aegis Canister: {canister_id}")
        print(f"  Total entries:    {health.get('totalEntries', 'N/A')}")
        print(f"  API keys:         {health.get('totalKeys', 'N/A')}")
        print(f"  Organizations:    {health.get('totalOrgs', 'N/A')}")
        heap = health.get("heapBytes", "N/A")
        if isinstance(heap, (int, float)) and heap > 0:
            print(f"  Heap:             {heap:,} bytes ({heap / 1_048_576:.1f} MB)")
        else:
            print(f"  Heap bytes:       {heap}")
        cycles = health.get("cyclesBalance", "N/A")
        if isinstance(cycles, (int, float)) and cycles > 0:
            print(f"  Cycles balance:   {cycles:,.0f} ({cycles / 1_000_000_000_000:.2f} T)")
        else:
            print(f"  Cycles balance:   {cycles}")
        deferred = health.get("deferredVerifications", 0)
        if deferred:
            print(f"  Deferred verif.:  {deferred}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def _cmd_report(args: list[str]) -> None:
    """Generate compliance report."""
    # canister_id is optional — read from config if not provided
    canister_id_arg: str | None = None
    if args and not args[0].startswith("-"):
        canister_id_arg = args[0]
        args = args[1:]
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
        from aegis.config import get_client_config, load_config
        from aegis.report import ReportFormat, generate_all_reports, generate_report

        # Resolve canister_id from config if not provided
        canister_id = canister_id_arg
        if not canister_id:
            cfg = load_config()
            canister_id = get_client_config(cfg).get("canister_id", "")
        if not canister_id:
            print("Error: No canister_id provided and none found in ~/.aegis/config.toml")
            sys.exit(1)

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


_LIST_SESSIONS_HASH_MAP: dict[str, str] = {
    "_3142408401": "sessionId",
    "_793140989": "entryCount",
    "_3430636010": "lastActivityNs",
    "_146711460": "chainIntact",
    "_2213923415": "signatureAlgorithm",
}


def _cmd_spill_status() -> None:
    """Show pending spill entries (offline buffer)."""
    from pathlib import Path

    spill_dir = Path.home() / ".aegis" / "spill"
    if not spill_dir.exists():
        print("No pending entries. All synced.")
        return

    jsonl_files = list(spill_dir.glob("*.jsonl"))
    if not jsonl_files:
        print("No pending entries. All synced.")
        return

    import json
    from datetime import datetime, timezone

    total_entries = 0
    total_bytes = 0
    oldest_ts: float | None = None

    for f in jsonl_files:
        size = f.stat().st_size
        total_bytes += size
        lines = [line for line in f.read_text(encoding="utf-8").strip().split("\n") if line]
        total_entries += len(lines)
        for line in lines:
            try:
                entry = json.loads(line)
                ts = entry.get("timestamp_ms", 0)
                if ts and (oldest_ts is None or ts < oldest_ts):
                    oldest_ts = ts
            except json.JSONDecodeError:
                continue

    if total_entries == 0:
        return print("No pending entries. All synced.")
    kb = total_bytes / 1024
    print(f"Pending spill entries: {total_entries} ({len(jsonl_files)} files, {kb:.1f} KB)")
    if oldest_ts:
        age = datetime.now(timezone.utc) - datetime.fromtimestamp(oldest_ts / 1000, tz=timezone.utc)
        print(f"  Oldest:  {age.days}d {age.seconds // 3600}h ago")
    print("  Run 'aegis test' to retry flushing.")


def _cmd_list_sessions(args: list[str]) -> None:
    """List sessions via listMySessions canister query."""
    canister_id = args[0] if args else None

    try:
        transport, _ = _transport_from_config(canister_id)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    try:
        from ic.candid import Types  # type: ignore[import-untyped]

        result = transport.call_query(
            "listMySessions",
            [
                {"type": Types.Null, "value": None},
                {"type": Types.Null, "value": None},
            ],
        )
        raw = result.get("raw", result) if isinstance(result, dict) else result
        sessions = raw if isinstance(raw, list) else []

        if not sessions:
            print("No sessions found. Log your first action with @client.trace().")
            return

        print(f"{'SESSION ID':<44}  ENTRIES")
        print("-" * 56)
        for s in sessions:
            raw = s if isinstance(s, dict) else {}
            mapped = _map_candid_keys(raw, _LIST_SESSIONS_HASH_MAP)
            sid = mapped.get("sessionId", str(s) if not isinstance(s, dict) else "?")
            count = mapped.get("entryCount", "?")
            print(f"{sid:<44}  {count}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def _cmd_session_analytics(args: list[str]) -> None:
    """Show analytics for a session."""
    if not args:
        print("Usage: aegis session-analytics <session-id> [canister-id]")
        sys.exit(1)
    session_id = args[0]
    canister_id = args[1] if len(args) > 1 else None
    try:
        from ic.candid import Types  # type: ignore[import-untyped]

        transport, _ = _transport_from_config(canister_id)
        args_c = [{"type": Types.Text, "value": session_id}]
        raw = transport.call_query("getSessionCompleteness", args_c)
        result = _map_candid_keys(raw, _SC_HASH_MAP) if isinstance(raw, dict) else raw
        print(f"Session: {session_id}")
        print(f"  Entries:      {result.get('totalEntries', '?')}")
        print(f"  Errors:       {result.get('errorCount', '?')}")
        er = result.get("errorRate")
        if isinstance(er, (int, float)):
            print(f"  Error Rate:   {er:.1%}")
        else:
            print(f"  Error Rate:   {er}")
        print(f"  Avg Duration: {result.get('avgDurationMs', '?')} ms")
        dist = result.get("actionTypeDist", [])
        if dist:
            print("  Action Types:")
            for name, count in dist:
                print(f"    {name}: {count}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def _cmd_org_stats(args: list[str]) -> None:
    """Show aggregated org statistics."""
    canister_id = args[0] if args else None
    try:
        transport, _ = _transport_from_config(canister_id)
        raw = transport.call_query("getOrgStats", [])
        result = _map_candid_keys(raw, _ORG_STATS_HASH_MAP) if isinstance(raw, dict) else raw
        print("Org Statistics:")
        print(f"  Total Entries:   {result.get('totalEntries', '?')}")
        print(f"  Total Sessions:  {result.get('totalSessions', '?')}")
        print(f"  Monthly Entries: {result.get('monthlyEntries', '?')}")
        agents = result.get("topAgents", [])
        if agents:
            print("  Top Agents:")
            for name, count in agents:
                print(f"    {name}: {count}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def _cmd_doctor(args: list[str]) -> None:
    """Run SDK health diagnostics."""
    from aegis.doctor import doctor_main

    canister_id = args[0] if args else None
    code = doctor_main(canister_id=canister_id)
    sys.exit(code)


def _cmd_export_otel(args: list[str]) -> None:
    """Export session traces to OTel-compatible endpoint."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Export Aegis session traces as OpenTelemetry spans",
    )
    parser.add_argument("session_id", help="Session ID to export")
    parser.add_argument(
        "--endpoint",
        default="http://localhost:4318/v1/traces",
        help="OTLP HTTP endpoint (default: http://localhost:4318/v1/traces)",
    )
    parser.add_argument(
        "--service-name",
        default="aegis-ledger",
        help="OTel service.name attribute",
    )
    parser.add_argument(
        "--canister-id",
        default=None,
        help="Canister ID (default: from config)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show span count without sending",
    )
    parsed = parser.parse_args(args)

    try:
        from aegis.client import AegisClient
        from aegis.otel_exporter import AegisOTelExporter

        client = AegisClient.from_config()
        if parsed.canister_id:
            client._canister_id = parsed.canister_id

        exporter = AegisOTelExporter(
            client,
            endpoint=parsed.endpoint,
            service_name=parsed.service_name,
        )

        if parsed.dry_run:
            # Fetch entries without sending
            entries = exporter._get_session_entries(parsed.session_id)
            print(f"Session: {parsed.session_id}")
            print(f"Entries found: {len(entries)}")
            if entries:
                spans = [exporter._entry_to_span(e) for e in entries]
                print(f"Spans to export: {len(spans)}")
                print(f"Endpoint: {parsed.endpoint}")
            return

        count = exporter.export_session(parsed.session_id)
        print(f"Exported {count} spans from session {parsed.session_id}")
        print(f"Endpoint: {parsed.endpoint}")

    except ImportError:
        print("Error: otel_exporter module not available")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
