"""
aegis.cli_export -- tail and export commands for the Aegis CLI.

Commands:
    aegis tail <session_id>  Live-poll new entries
    aegis export <session_id> [--format jsonl|json|csv] [--output path]
"""

from __future__ import annotations

import csv
import io
import json
import signal
import sys
import time

from aegis.integrity import LEDGER_ENTRY_HASH_MAP, map_candid_keys


def _cmd_tail(args: list[str]) -> None:
    """Live-poll new entries for a session, printing as they appear."""
    if not args or args[0] in ("-h", "--help"):
        print("Usage: aegis tail <session_id> [--format json] [--interval N]")
        print("  --format json    Machine-readable JSON per line")
        print("  --interval N     Poll interval in seconds (default: 2)")
        sys.exit(0)

    session_id = args[0]
    fmt = "text"
    interval = 2.0

    i = 1
    while i < len(args):
        if args[i] == "--format" and i + 1 < len(args):
            fmt = args[i + 1]
            i += 2
        elif args[i] == "--interval" and i + 1 < len(args):
            interval = max(0.5, float(args[i + 1]))
            i += 2
        else:
            i += 1

    from aegis.cli import _transport_from_config

    transport, canister_id = _transport_from_config()
    last_seq = -1
    running = True

    def _stop(*_a: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _stop)

    if fmt != "json":
        print(f"Tailing session {session_id} on {canister_id} (Ctrl+C to stop)")
        print()

    while running:
        try:
            from ic.candid import Types  # type: ignore[import-untyped]

            raw = transport.call_query(
                "getTrace",
                [
                    {"type": Types.Text, "value": session_id},
                    {"type": Types.Null, "value": None},
                    {"type": Types.Null, "value": None},
                ],
            )
            entries = (
                raw
                if isinstance(raw, list)
                else raw.get("raw", [])
                if isinstance(raw, dict)
                else []
            )
            mapped = [
                map_candid_keys(e, LEDGER_ENTRY_HASH_MAP)
                for e in entries
                if isinstance(e, dict)
            ]

            for entry in mapped:
                seq = entry.get("sequenceNumber", 0)
                if isinstance(seq, list) and seq:
                    seq = seq[0]
                seq = int(seq) if seq else 0
                if seq > last_seq:
                    last_seq = seq
                    _print_entry(entry, fmt)

        except Exception as e:
            if running:
                msg = str(e)
                if fmt == "json":
                    print(json.dumps({"error": msg}), flush=True)
                else:
                    print(f"  [error] {msg}", file=sys.stderr)

        if running:
            time.sleep(interval)

    if fmt != "json":
        print("\nStopped.")


def _print_entry(entry: dict, fmt: str) -> None:
    """Print a single entry in text or json format."""
    if fmt == "json":
        print(json.dumps(entry, default=str), flush=True)
        return

    seq = entry.get("sequenceNumber", "?")
    action_type = entry.get("actionType", "?")
    tool = entry.get("tool", "")
    status = entry.get("status", "")
    duration = entry.get("durationMs", 0)

    colors = {
        "tool_call": "\033[36m",
        "error": "\033[31m",
        "decision": "\033[33m",
        "observation": "\033[34m",
        "human_override": "\033[35m",
    }
    reset = "\033[0m"
    color = colors.get(str(action_type), "")

    print(
        f"  {color}#{seq} {action_type}{reset}"
        f"  {tool}  [{status}]  {duration}ms",
        flush=True,
    )


def _cmd_export(args: list[str]) -> None:
    """Export a session's entries to local file or stdout."""
    if not args or args[0] in ("-h", "--help"):
        print("Usage: aegis export <session_id> [options]")
        print("  --format jsonl|json|csv   Output format (default: jsonl)")
        print("  --output <path>           Write to file (default: stdout)")
        sys.exit(0)

    session_id = args[0]
    fmt = "jsonl"
    output_path = ""

    i = 1
    while i < len(args):
        if args[i] == "--format" and i + 1 < len(args):
            fmt = args[i + 1]
            i += 2
        elif args[i] in ("--output", "-o") and i + 1 < len(args):
            output_path = args[i + 1]
            i += 2
        else:
            i += 1

    if fmt not in ("jsonl", "json", "csv"):
        print(f"Error: Unknown format '{fmt}'. Use jsonl, json, or csv.")
        sys.exit(1)

    entries = _fetch_all_entries(session_id)
    if not entries:
        print(f"No entries found for session {session_id}", file=sys.stderr)
        sys.exit(2)

    output = _format_entries(entries, fmt)

    if output_path:
        from pathlib import Path

        Path(output_path).write_text(output, encoding="utf-8")
        print(
            f"Exported {len(entries)} entries to {output_path}",
            file=sys.stderr,
        )
    else:
        print(output)


def _fetch_all_entries(session_id: str) -> list[dict]:
    """Paginate through getTrace to fetch all entries."""
    from aegis.cli import _transport_from_config

    transport, _ = _transport_from_config()
    all_entries: list[dict] = []
    offset = 0
    page_size = 500

    while True:
        from ic.candid import Types  # type: ignore[import-untyped]

        raw = transport.call_query(
            "getTrace",
            [
                {"type": Types.Text, "value": session_id},
                {"type": Types.Opt, "value": {"type": Types.Nat, "value": offset}},
                {"type": Types.Opt, "value": {"type": Types.Nat, "value": page_size}},
            ],
        )
        entries = (
            raw
            if isinstance(raw, list)
            else raw.get("raw", [])
            if isinstance(raw, dict)
            else []
        )
        mapped = [
            map_candid_keys(e, LEDGER_ENTRY_HASH_MAP)
            for e in entries
            if isinstance(e, dict)
        ]
        all_entries.extend(mapped)

        if len(entries) < page_size:
            break
        offset += page_size

    return all_entries


def _format_entries(entries: list[dict], fmt: str) -> str:
    """Format entries as JSONL, JSON array, or CSV."""
    if fmt == "json":
        return json.dumps(entries, indent=2, default=str)

    if fmt == "jsonl":
        return "\n".join(json.dumps(e, default=str) for e in entries)

    # CSV
    if not entries:
        return ""
    keys = list(entries[0].keys())
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=keys, extrasaction="ignore")
    writer.writeheader()
    for e in entries:
        flat = {
            k: json.dumps(v, default=str) if isinstance(v, (dict, list)) else v
            for k, v in e.items()
        }
        writer.writerow(flat)
    return buf.getvalue()
