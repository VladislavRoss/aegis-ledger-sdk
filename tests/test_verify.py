"""Tests for aegis.verify — offline hash-chain replay verification."""

from aegis.crypto import canonical_json, compute_chain_hash
from aegis.verify import verify_chain


def _make_entry(seq: int, prev_chain: str, payload_dict: dict) -> dict:
    """Build a fake trace entry with correct chain hash."""
    payload_bytes = canonical_json(payload_dict)
    chain_hash = compute_chain_hash(prev_chain, payload_bytes)
    return {
        "actionId": f"act_{seq:04d}",
        "sequenceNumber": seq,
        "payloadHex": payload_bytes.hex(),
        "chainHash": chain_hash,
        "previousChainHash": prev_chain,
        "payloadSignature": "ed25519:aabbcc",
    }


def _build_chain(n: int) -> list[dict]:
    """Build a valid chain of n entries."""
    entries = []
    prev = ""
    for i in range(n):
        entry = _make_entry(i, prev, {"seq": i, "data": f"entry_{i}"})
        prev = entry["chainHash"]
        entries.append(entry)
    return entries


class TestVerifyChain:
    def test_empty_entries(self) -> None:
        result = verify_chain([])
        assert result["valid"] is True
        assert result["total"] == 0

    def test_single_entry_valid(self) -> None:
        entries = _build_chain(1)
        result = verify_chain(entries)
        assert result["valid"] is True
        assert result["total"] == 1
        assert result["verified"] == 1
        assert result["failures"] == []

    def test_three_entry_chain_valid(self) -> None:
        entries = _build_chain(3)
        result = verify_chain(entries)
        assert result["valid"] is True
        assert result["total"] == 3
        assert result["verified"] == 3

    def test_tampered_chain_hash_detected(self) -> None:
        entries = _build_chain(3)
        entries[1]["chainHash"] = "deadbeef" * 8
        result = verify_chain(entries)
        assert result["valid"] is False
        assert result["verified"] == 2
        assert len(result["failures"]) == 1
        assert result["failures"][0]["seq"] == 1
        assert result["failures"][0]["reason"] == "chain hash mismatch"

    def test_tampered_payload_detected(self) -> None:
        entries = _build_chain(3)
        # Tamper the payload of entry 2
        fake_payload = canonical_json({"seq": 2, "data": "TAMPERED"})
        entries[2]["payloadHex"] = fake_payload.hex()
        result = verify_chain(entries)
        assert result["valid"] is False
        assert len(result["failures"]) == 1
        assert result["failures"][0]["seq"] == 2

    def test_missing_payload_hex(self) -> None:
        entries = _build_chain(2)
        entries[1]["payloadHex"] = ""
        result = verify_chain(entries)
        assert result["valid"] is False
        assert result["failures"][0]["reason"] == "missing payloadHex"

    def test_sequence_gap_detected(self) -> None:
        entries = _build_chain(3)
        # Skip seq 1 — deliver 0 and 2 only
        del entries[1]
        result = verify_chain(entries)
        assert len(result["sequence_gaps"]) == 1
        assert result["sequence_gaps"][0]["after_seq"] == 0
        assert result["sequence_gaps"][0]["got_seq"] == 2

    def test_out_of_order_entries_sorted(self) -> None:
        entries = _build_chain(3)
        # Shuffle order
        shuffled = [entries[2], entries[0], entries[1]]
        result = verify_chain(shuffled)
        assert result["valid"] is True
        assert result["total"] == 3

    def test_ten_entry_chain(self) -> None:
        entries = _build_chain(10)
        result = verify_chain(entries)
        assert result["valid"] is True
        assert result["total"] == 10
        assert result["verified"] == 10
        assert result["sequence_gaps"] == []

    def test_first_entry_tampered(self) -> None:
        entries = _build_chain(3)
        entries[0]["chainHash"] = "0" * 64
        result = verify_chain(entries)
        assert result["valid"] is False
        assert result["failures"][0]["seq"] == 0

    def test_ic_py_alternate_keys(self) -> None:
        """ic-py sometimes returns fields with numeric/underscore keys."""
        entries = _build_chain(2)
        # Simulate ic-py alternate key names
        for e in entries:
            e["_sequenceNumber"] = e.pop("sequenceNumber")
            e["_chainHash"] = e.pop("chainHash")
            e["_previousChainHash"] = e.pop("previousChainHash")
            e["_payloadHex"] = e.pop("payloadHex")
            e["_3776271665"] = e.pop("actionId")
        result = verify_chain(entries)
        assert result["valid"] is True
        assert result["total"] == 2
