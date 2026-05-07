"""
aegis.migrate — Re-sign ledger entries with a new cryptographic algorithm.

Produces a migration proof: a JSON file containing the original entry
metadata plus new signatures under the target algorithm. The on-chain
entries remain unchanged on-chain; the migration proof demonstrates that the
same key holder endorses the entries under a quantum-resistant scheme.

Usage:
    from aegis.migrate import migrate_session

    report = migrate_session(
        canister_id="toqqq-lqaaa-aaaae-afc2a-cai",
        session_id="sess_abc123",
        target_algorithm="hybrid",
        pem_path="./agent_key.pem",
        signing_key_path="./agent_key.mldsa65",
    )
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


def re_sign_payload_hex(
    payload_hex: str,
    original_signature: str,
    scheme: Any,
) -> dict[str, str]:
    """Re-sign a single payload with a new scheme.

    Args:
        payload_hex: Hex-encoded canonical JSON payload (from canister).
        original_signature: The original signature string.
        scheme: A SignatureScheme instance bound to a private key.

    Returns:
        Dict with original_signature, new_signature, algorithm.
    """
    payload_bytes = bytes.fromhex(payload_hex)
    new_sig = scheme.sign(payload_bytes)
    return {
        "original_signature": original_signature,
        "new_signature": new_sig,
        "algorithm": scheme.algorithm_id,
    }


def _build_scheme(
    target_algorithm: str,
    pem_path: str | None,
    signing_key_path: str | None,
) -> Any:
    """Build a SignatureScheme for the target algorithm."""
    from aegis.crypto import (
        create_scheme,
        load_mldsa65_private_key,
        load_mldsa87_private_key,
        load_private_key,
        load_slhdsa128s_private_key,
    )

    if target_algorithm == "ed25519":
        if not pem_path:
            raise ValueError("--pem required for ed25519")
        key = load_private_key(pem_path)
        return create_scheme("ed25519", key)

    if target_algorithm == "ml-dsa-65":
        if not signing_key_path:
            raise ValueError("--signing-key required for ml-dsa-65")
        sk = load_mldsa65_private_key(signing_key_path)
        return create_scheme("ml-dsa-65", sk)

    if target_algorithm == "ml-dsa-87":
        if not signing_key_path:
            raise ValueError("--signing-key required for ml-dsa-87")
        sk = load_mldsa87_private_key(signing_key_path)
        return create_scheme("ml-dsa-87", sk)

    if target_algorithm == "slh-dsa-128s":
        if not signing_key_path:
            raise ValueError("--signing-key required for slh-dsa-128s")
        sk = load_slhdsa128s_private_key(signing_key_path)
        return create_scheme("slh-dsa-128s", sk)

    if target_algorithm == "hybrid":
        if not pem_path:
            raise ValueError("--pem required for hybrid")
        if not signing_key_path:
            raise ValueError("--signing-key required for hybrid")
        ed_key = load_private_key(pem_path)
        ml_sk = load_mldsa65_private_key(signing_key_path)
        return create_scheme("hybrid", (ed_key, ml_sk))

    raise ValueError(f"Unknown target algorithm: {target_algorithm}")


def _detect_source_algorithm(signature: str) -> str:
    """Detect the algorithm from a signature prefix."""
    for prefix in ("hybrid:", "ml-dsa-87:", "ml-dsa-65:", "slh-dsa-128s:", "ed25519:"):
        if signature.startswith(prefix):
            return prefix.rstrip(":")
    return "unknown"


def migrate_session(
    canister_id: str,
    session_id: str,
    target_algorithm: str,
    pem_path: str | None = None,
    signing_key_path: str | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Fetch a session's entries from the canister and re-sign them.

    Args:
        canister_id: ICP canister ID.
        session_id: Session to migrate.
        target_algorithm: Target signature algorithm.
        pem_path: Path to Ed25519 PEM key.
        signing_key_path: Path to PQ secret key.
        output_path: Output JSON file path.

    Returns:
        Migration report dict.
    """
    from ic.candid import Types  # type: ignore[import-untyped]

    from aegis.transport import CanisterTransport, TransportConfig

    scheme = _build_scheme(target_algorithm, pem_path, signing_key_path)

    config = TransportConfig(canister_id=canister_id)
    transport = CanisterTransport(config)
    entries = transport.call_query(
        "getTrace", [{"type": Types.Text, "value": session_id}]
    )

    if not entries or not isinstance(entries, list):
        raise ValueError(f"No entries found for session {session_id}")

    source_algo = "unknown"
    migrated: list[dict[str, Any]] = []

    for entry in entries:
        action_id = entry.get("actionId", entry.get("_3776271665", ""))
        payload_hex = entry.get("payloadHex", entry.get("_payloadHex", ""))
        original_sig = entry.get("payloadSignature", entry.get("_payloadSignature", ""))

        if not payload_hex:
            continue

        if source_algo == "unknown":
            source_algo = _detect_source_algorithm(original_sig)

        result = re_sign_payload_hex(payload_hex, original_sig, scheme)
        result["action_id"] = action_id
        migrated.append(result)

    if not output_path:
        output_path = f"migration_{session_id}.json"

    report: dict[str, Any] = {
        "canister_id": canister_id,
        "session_id": session_id,
        "source_algorithm": source_algo,
        "target_algorithm": target_algorithm,
        "total_entries": len(migrated),
        "migrated_at": int(time.time()),
        "entries": migrated,
    }

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report["output_file"] = str(out)

    return report


def migrate_local(
    entries_json: str | Path,
    target_algorithm: str,
    pem_path: str | None = None,
    signing_key_path: str | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Re-sign entries from a local JSON export (offline migration).

    Args:
        entries_json: Path to JSON file with entries (each must have payloadHex).
        target_algorithm: Target signature algorithm.
        pem_path: Path to Ed25519 PEM key.
        signing_key_path: Path to PQ secret key.
        output_path: Output JSON file path.

    Returns:
        Migration report dict.
    """
    scheme = _build_scheme(target_algorithm, pem_path, signing_key_path)

    data = json.loads(Path(entries_json).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "entries" in data:
        raw_entries = data["entries"]
    elif isinstance(data, list):
        raw_entries = data
    else:
        raise ValueError("Expected a list of entries or {entries: [...]}")

    source_algo = "unknown"
    migrated: list[dict[str, Any]] = []

    for entry in raw_entries:
        payload_hex = entry.get("payloadHex", entry.get("payload_hex", ""))
        original_sig = entry.get("payloadSignature", entry.get("original_signature", ""))
        action_id = entry.get("actionId", entry.get("action_id", ""))

        if not payload_hex:
            continue

        if source_algo == "unknown" and original_sig:
            source_algo = _detect_source_algorithm(original_sig)

        result = re_sign_payload_hex(payload_hex, original_sig, scheme)
        result["action_id"] = action_id
        migrated.append(result)

    if not output_path:
        output_path = f"migration_local_{int(time.time())}.json"

    report: dict[str, Any] = {
        "source_file": str(entries_json),
        "source_algorithm": source_algo,
        "target_algorithm": target_algorithm,
        "total_entries": len(migrated),
        "migrated_at": int(time.time()),
        "entries": migrated,
    }

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report["output_file"] = str(out)

    return report
