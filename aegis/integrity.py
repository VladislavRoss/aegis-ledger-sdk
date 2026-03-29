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

# ── Candid field-hash maps (ic-py returns hashes, not names) ─────────────

HEALTH_HASH_MAP: dict[str, str] = {
    "_576569836": "totalEntries",
    "_1673630680": "totalKeys",
    "_1718631411": "totalOrgs",
    "_492408735": "heapBytes",
    "_3726629775": "cyclesBalance",
    "_4170640857": "deferredVerifications",
    "_3342846017": "totalSessions",
    "_3244729591": "schemaVersion",
    "_1389760433": "canisterVersion",
    "_4029786842": "activeKeys",
}

VERIFY_HASH_MAP: dict[str, str] = {
    "_3776271665": "actionId",
    "_3460176050": "isValid",
    "_1390137228": "storedChainHash",
    "_2601806392": "previousChainHash",
    "_3248078826": "sequenceNumber",
    "_2584819143": "message",
    "_2213923415": "signatureAlgorithm",
    "_613449444": "signatureValid",
    "_735126595": "deferredReason",
    "_2933681001": "entryTimestampNs",
}

LEDGER_ENTRY_HASH_MAP: dict[str, str] = {
    "_3776271665": "actionId",
    "_532604909": "payloadHex",
    "_317326703": "chainHash",
    "_2601806392": "previousChainHash",
    "_3248078826": "sequenceNumber",
    "_891494111": "orgId",
    "_1625980416": "keyId",
    "_3142408401": "sessionId",
    "_1291934552": "tool",
    "_100394802": "status",
    "_874996106": "payloadSignature",
    "_78284984": "serverTimestampNs",
    "_346465617": "clientTimestampMs",
    "_2039288168": "confidenceScore",
    "_749554439": "decisionReasoning",
    "_204664056": "inputHash",
    "_2801565551": "outputHash",
    "_3752841178": "durationMs",
    "_1369740414": "framework",
    "_2274208491": "signatureAlgorithm",
    "_309830882": "modelId",
    "_2834124923": "parentActionId",
    "_3557243166": "modelProvider",
    "_3982974948": "sdkVersion",
}

API_KEY_HASH_MAP: dict[str, str] = {
    "_3741232986": "keyId",
    "_891494111": "orgId",
    "_1613253554": "agentIdPrefix",
    "_1118656517": "publicKeyHex",
    "_1240611067": "createdAt",
    "_3774262195": "lastUsed",
    "_100394802": "status",
    "_3567307894": "rateLimitPerSecond",
    "_351186031": "algorithm",
    "_478735815": "expiresAt",
    "_3956820977": "revokedAt",
    "_1595738364": "description",
}

SESSION_SUMMARY_HASH_MAP: dict[str, str] = {
    "_3142408401": "sessionId",
    "_793140989": "entryCount",
    "_3430636010": "lastActivityNs",
    "_146711460": "chainIntact",
    "_2213923415": "signatureAlgorithm",
}

SEQUENCE_HEAD_HASH_MAP: dict[str, str] = {
    "_96741377": "sequenceHead",
    "_317326703": "chainHash",
}


def map_candid_keys(raw: dict[str, Any], hash_map: dict[str, str]) -> dict[str, Any]:
    """Map Candid field-hash keys to human-readable names."""
    return {hash_map.get(str(k), str(k)): v for k, v in raw.items()}


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
            stored_hash = result.get("storedChainHash", result.get("_1390137228", ""))
            is_valid = result.get("isValid", result.get("_3460176050", False))
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
            from .transport import CanisterError
            if isinstance(e, CanisterError) and e.error_code in (
                "UNAUTHORIZED", "AUTH", "FORBIDDEN",
            ):
                raise
            logger.warning("verify_integrity: verifyEntry(%s) failed: %s", aid, e)
            missing.append(aid)

    return {
        "total": total,
        "sampled": len(sample),
        "valid": valid,
        "mismatches": mismatches,
        "missing": missing,
    }
