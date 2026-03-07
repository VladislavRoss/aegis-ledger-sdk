"""
E2E-Integration-Test gegen live Mainnet Canister.

Aufruf:
    python -m pytest tests/test_e2e_live.py -v -s

Voraussetzungen:
    - ic-py installiert (pip install ic-py)
    - Internetzugang zu icp-api.io
    - /tmp/test_integration.pem existiert (wird im Test erzeugt)
"""
import sys

import pytest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from unittest.mock import MagicMock

# Skip entire module when ic-py is mocked (Windows WMI hang workaround)
_ic_is_mock = isinstance(sys.modules.get("ic"), MagicMock)
pytestmark = pytest.mark.skipif(_ic_is_mock, reason="ic-py is mocked (Windows)")

CANISTER_ID = "toqqq-lqaaa-aaaae-afc2a-cai"
PEM_PATH = Path("/tmp/aegis_e2e_test.pem")


@pytest.fixture(scope="module")
def pem_key():
    """Generiert einen frischen Ed25519-Key und speichert ihn als PEM."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    PEM_PATH.write_text(pem)
    yield PEM_PATH
    # Cleanup nach Tests
    if PEM_PATH.exists():
        PEM_PATH.unlink()


@pytest.fixture(scope="module")
def client(pem_key):
    """Initialisiert AegisClient gegen Mainnet."""
    from aegis.client import AegisClient
    return AegisClient(
        canister_id=CANISTER_ID,
        api_key_id="e2e_test_key",
        agent_id="e2e-test-agent",
        private_key_path=str(pem_key),
        network="https://icp-api.io",
    )


def test_org_id_derived_from_pem(client):
    """org_id muss vom PEM abgeleitet sein (nicht 'aaaaa-aa')."""
    assert client._org_id != "aaaaa-aa", "org_id darf nicht Default sein"
    assert "-" in client._org_id, f"Kein gültiger Principal: {client._org_id}"
    print(f"\n  org_id (Principal): {client._org_id}")


def test_log_tool_call_live(client):
    """Schreibt einen echten Ledger-Eintrag auf den Mainnet-Canister."""
    action_id = client.log_tool_call(
        tool="web_search",
        input_data={"query": "aegis e2e test"},
        output_data={"results": ["ok"]},
        duration_ms=42,
    )

    assert action_id is not None, "Kein action_id zurückbekommen"
    assert len(str(action_id)) > 0, "action_id ist leer"
    print(f"\n  action_id: {action_id}")
    print(f"  session_id: {client.session_id}")


def test_log_decision_live(client):
    """Schreibt einen Decision-Eintrag."""
    action_id = client.log_decision(
        reasoning="E2E-Test: Entscheidung getroffen",
        confidence=0.95,
    )

    assert action_id is not None
    print(f"\n  decision action_id: {action_id}")
