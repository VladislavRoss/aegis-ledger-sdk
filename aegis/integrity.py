"""Integrity Snapshot — local chain-hash cache for tamper detection."""
from __future__ import annotations

import json
import logging
import random
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    from .transport import AegisTransport

logger = logging.getLogger("aegis")


def snapshot_path(spill_dir: Path, canister_id: str) -> Path:
    base = spill_dir.parent / "snapshots"
    return base / f"{canister_id}.jsonl"


def write_snapshot(
    path: Path, action_id: str, chain_hash: str, session_id: str, ts_ms: int,
) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.parent.is_symlink():
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "action_id": action_id,
                    "chain_hash": chain_hash,
                    "session_id": session_id,
                    "ts": ts_ms,
                }) + "\n")
    except Exception:
        logger.debug("Snapshot write failed (non-fatal)", exc_info=True)


def verify_integrity(
    path: Path, transport: AegisTransport, sample_size: int = 10,
) -> dict[str, Any]:
    """Verify canister entries against locally stored chain-hash snapshots.

    Reads the local snapshot file, samples *sample_size* entries, calls
    ``verifyEntry`` on each, and compares the stored chain hash.

    Returns a dict::

        {"total": N, "sampled": M, "valid": K,
         "mismatches": [...], "missing": [...]}
    """
    from ic.candid import Types  # type: ignore[import-untyped]

    if not path.exists():
        return {"total": 0, "sampled": 0, "valid": 0, "mismatches": [], "missing": []}

    snapshots = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            snapshots.append(json.loads(line))

    total = len(snapshots)
    sample = random.sample(snapshots, min(sample_size, total))
    valid: int = 0
    mismatches: list[dict[str, str]] = []
    missing: list[str] = []

    for snap in sample:
        aid = snap["action_id"]
        try:
            result = transport.call_query(
                "verifyEntry", [{"type": Types.Text, "value": aid}],
            )
            stored_hash = result.get("storedChainHash", result.get("_1835832718", ""))
            is_valid = result.get("isValid", result.get("_2397498270", False))
            if not is_valid:
                missing.append(aid)
            elif stored_hash != snap["chain_hash"]:
                mismatches.append({
                    "action_id": aid,
                    "local": snap["chain_hash"],
                    "canister": stored_hash,
                })
            else:
                valid += 1
        except Exception as e:
            logger.warning("verify_integrity: verifyEntry(%s) failed: %s", aid, e)
            missing.append(aid)

    return {
        "total": total,
        "sampled": len(sample),
        "valid": valid,
        "mismatches": mismatches,
        "missing": missing,
    }
