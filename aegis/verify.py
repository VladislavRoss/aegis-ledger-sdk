"""
aegis.verify — Offline hash-chain replay verification.

Verifies that a sequence of trace entries forms a valid hash chain
without trusting the canister. Uses only local SHA-256 computation.

Usage (programmatic):
    from aegis.verify import verify_chain
    result = verify_chain(entries_from_get_trace)

Usage (CLI):
    aegis verify-chain toqqq-lqaaa-aaaae-afc2a-cai sess_abc123
"""

from __future__ import annotations

from aegis.crypto import compute_chain_hash


def _get(entry: dict, key: str, alt_key: str = "") -> str:
    """Get field from entry, handling ic-py's alternate key names."""
    val = entry.get(key)
    if val is None and alt_key:
        val = entry.get(alt_key)
    return str(val) if val is not None else ""


def verify_chain(entries: list[dict]) -> dict:
    """
    Verify hash-chain integrity of trace entries offline.

    Args:
        entries: list of dicts from getTrace() canister response.
            Each entry needs: payloadHex, chainHash, previousChainHash,
            sequenceNumber, actionId.

    Returns:
        dict with keys:
            valid: bool — True if entire chain is intact
            total: int — number of entries checked
            verified: int — entries with correct chain hash
            failures: list[dict] — entries that failed verification
            sequence_gaps: list[dict] — gaps in sequence numbering
    """
    if not entries:
        return {
            "valid": True,
            "total": 0,
            "verified": 0,
            "failures": [],
            "sequence_gaps": [],
        }

    sorted_entries = sorted(
        entries,
        key=lambda e: int(_get(e, "sequenceNumber", "_sequenceNumber") or 0),
    )

    failures: list[dict] = []
    sequence_gaps: list[dict] = []
    prev_seq: int | None = None

    for entry in sorted_entries:
        payload_hex = _get(entry, "payloadHex", "_payloadHex")
        chain_hash = _get(entry, "chainHash", "_chainHash")
        prev_chain = _get(entry, "previousChainHash", "_previousChainHash")
        seq = int(_get(entry, "sequenceNumber", "_sequenceNumber") or 0)
        action_id = _get(entry, "actionId", "_3776271665")

        if prev_seq is not None and seq != prev_seq + 1:
            sequence_gaps.append({
                "after_seq": prev_seq,
                "got_seq": seq,
                "action_id": action_id,
            })
        prev_seq = seq

        if not payload_hex:
            failures.append({
                "action_id": action_id,
                "seq": seq,
                "reason": "missing payloadHex",
            })
            continue

        payload_bytes = bytes.fromhex(payload_hex)
        expected = compute_chain_hash(prev_chain, payload_bytes)

        if expected != chain_hash:
            failures.append({
                "action_id": action_id,
                "seq": seq,
                "reason": "chain hash mismatch",
                "expected": expected,
                "stored": chain_hash,
            })

    total = len(sorted_entries)
    return {
        "valid": len(failures) == 0,
        "total": total,
        "verified": total - len(failures),
        "failures": failures,
        "sequence_gaps": sequence_gaps,
    }
