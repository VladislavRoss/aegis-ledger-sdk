"""
aegis.cli_selfservice — CLI commands for self-service operations.

reactivate-key, delete-key, update-key-desc, purge-session.
Dashboard-UI (B6) is the primary interface — these are for power users / automation.
"""

from __future__ import annotations

import sys


def _prompt(text: str) -> str:
    try:
        return input(text)
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)


def _get_client():
    """Create AegisClient from config for self-service operations."""
    from aegis.client import AegisClient

    return AegisClient.from_config()


def cmd_reactivate_key(args: list[str]) -> None:
    """Reactivate a revoked API key."""
    if not args:
        print("Usage: aegis reactivate-key <key_id>")
        sys.exit(1)
    key_id = args[0]
    try:
        client = _get_client()
        result = client.reactivate_api_key(key_id)
        status = result.get("status", "?")
        print(f"  [OK] Key {key_id} reactivated (status: {status})")
    except Exception as e:
        print(f"  [FAIL] {e}")
        sys.exit(1)


def cmd_delete_key(args: list[str]) -> None:
    """Permanently delete a revoked API key (requires confirmation)."""
    if not args:
        print("Usage: aegis delete-key <key_id>")
        sys.exit(1)
    key_id = args[0]
    print(f"\n  Delete key {key_id}? This is PERMANENT and cannot be undone.")
    print("  Only revoked keys can be deleted.")
    confirm = _prompt("  Type 'yes' to confirm: ").strip().lower()
    if confirm != "yes":
        print("  Aborted.")
        return
    try:
        client = _get_client()
        client.delete_api_key(key_id)
        print(f"  [OK] Key {key_id} permanently deleted.")
    except Exception as e:
        print(f"  [FAIL] {e}")
        sys.exit(1)


def cmd_update_key_desc(args: list[str]) -> None:
    """Update the description of an API key."""
    if len(args) < 2:
        print("Usage: aegis update-key-desc <key_id> <description>")
        sys.exit(1)
    key_id = args[0]
    description = " ".join(args[1:])
    if len(description) > 256:
        print("  Error: description must be <= 256 characters.")
        sys.exit(1)
    try:
        client = _get_client()
        result = client.update_api_key_description(key_id, description)
        print(f"  [OK] Key {key_id} description updated: {result.get('description', '?')}")
    except Exception as e:
        print(f"  [FAIL] {e}")
        sys.exit(1)


def cmd_purge_session(args: list[str]) -> None:
    """Purge all entries from a session (requires confirmation)."""
    if not args:
        print("Usage: aegis purge-session <session_id> [--batch-limit N]")
        sys.exit(1)
    session_id = args[0]
    batch_limit = None
    if "--batch-limit" in args:
        idx = args.index("--batch-limit")
        if idx + 1 < len(args):
            batch_limit = int(args[idx + 1])
    print(f"\n  Purge session {session_id}? All entries will be deleted.")
    confirm = _prompt("  Type 'yes' to confirm: ").strip().lower()
    if confirm != "yes":
        print("  Aborted.")
        return
    try:
        client = _get_client()
        deleted = client.purge_session(session_id, batch_limit)
        print(f"  [OK] Purged {deleted} entries from session {session_id}.")
    except Exception as e:
        print(f"  [FAIL] {e}")
        sys.exit(1)
