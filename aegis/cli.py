"""
aegis.cli — Command-line utilities for Aegis SDK setup.

Commands:
    aegis keygen ./my_agent_key.pem    Generate an Ed25519 keypair
    aegis verify <canister_id> <action_id>  Verify a single ledger entry
    aegis status <canister_id>          Check canister health
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
    elif command == "status":
        _cmd_status(args[1:])
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
aegis-ledger-sdk — Tamperproof execution ledger for AI agents

Commands:
  keygen <path>                  Generate Ed25519 keypair for agent signing
  verify <canister_id> <action_id>  Verify a ledger entry's chain hash
  status <canister_id>           Check canister health and chain stats
  version                        Print SDK version

Examples:
  aegis keygen ./keys/my_agent.pem
  aegis verify toqqq-lqaaa-aaaae-afc2a-cai act_a7f3b2c19e4d
        """.strip()
    )


def _cmd_keygen(args: list[str]) -> None:
    """Generate an Ed25519 keypair."""
    if not args:
        print("Usage: aegis keygen <output_path>")
        print("Example: aegis keygen ./agent_key.pem")
        sys.exit(1)

    from aegis.crypto import generate_keypair

    path = args[0]
    try:
        _, pub_hex = generate_keypair(path)
    except FileExistsError as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"✓ Private key saved to: {path}")
    print(f"✓ Public key saved to:  {path}.pub")
    print(f"✓ Public key (hex):     {pub_hex}")
    print()
    print("Next steps:")
    print("  1. Register this public key in the Aegis dashboard")
    print("  2. Use the private key path in your AegisClient config")
    print(f"  3. NEVER commit {path} to version control")


def _cmd_verify(args: list[str]) -> None:
    """Verify a ledger entry."""
    if len(args) < 2:
        print("Usage: aegis verify <canister_id> <action_id>")
        sys.exit(1)

    canister_id, action_id = args[0], args[1]

    try:
        from aegis.transport import CanisterTransport, TransportConfig

        config = TransportConfig(canister_id=canister_id)
        transport = CanisterTransport(config)
        result = transport.call_query("verify_entry", [{"action_id": action_id}])

        if result.get("valid"):
            print(f"✓ VERIFIED — Entry {action_id} chain hash is valid")
            print(f"  Hash:     {result.get('computed_hash', 'N/A')}")
            print(f"  Previous: {result.get('previous_hash', 'N/A')}")
        else:
            print(f"✗ INVALID — Entry {action_id} chain hash mismatch!")
            print(f"  Stored:   {result.get('stored_hash', 'N/A')}")
            print(f"  Computed: {result.get('computed_hash', 'N/A')}")
            sys.exit(2)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def _cmd_status(args: list[str]) -> None:
    """Check canister health."""
    if not args:
        print("Usage: aegis status <canister_id>")
        sys.exit(1)

    canister_id = args[0]

    try:
        from aegis.transport import CanisterTransport, TransportConfig

        config = TransportConfig(canister_id=canister_id)
        transport = CanisterTransport(config)
        stats = transport.call_query("get_org_stats", [{}])

        print(f"Aegis Canister: {canister_id}")
        print(f"  Total actions:    {stats.get('total_actions', 'N/A')}")
        print(f"  Active agents:    {stats.get('total_agents', 'N/A')}")
        print(f"  Sessions:         {stats.get('total_sessions', 'N/A')}")
        print(f"  API keys:         {stats.get('active_api_keys', 'N/A')}")
        print(f"  Chain length:     {stats.get('chain_length', 'N/A')}")
        print(f"  Latest hash:      {stats.get('latest_chain_hash', 'N/A')[:16]}...")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
