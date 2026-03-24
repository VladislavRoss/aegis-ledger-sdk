"""Root conftest — test compatibility for standalone SDK repo.

In the main monorepo, tests import from `AEGIS_LEDGER.*` (directory import).
In this standalone repo, source lives in `aegis/`. This conftest maps
`AEGIS_LEDGER.*` → `aegis.*` so all tests work in both contexts.
"""
from __future__ import annotations

import os
import sys
import types
from unittest.mock import MagicMock

# ic-py hangs on Windows (WMI/COM). Pre-mock so tests don't hang.
if "ic" not in sys.modules:
    _ic = MagicMock()
    sys.modules["ic"] = _ic
    sys.modules["ic.candid"] = _ic.candid
    sys.modules["ic.identity"] = _ic.identity
    sys.modules["ic.agent"] = _ic.agent
    sys.modules["ic.client"] = _ic.client

# Map AEGIS_LEDGER.* → aegis/* so monorepo-style imports resolve here.
_root = os.path.dirname(os.path.abspath(__file__))
_aegis_path = os.path.join(_root, "aegis")
if _root not in sys.path:
    sys.path.insert(0, _root)

if "AEGIS_LEDGER" not in sys.modules:
    _pkg = types.ModuleType("AEGIS_LEDGER")
    _pkg.__path__ = [_aegis_path]
    _pkg.__package__ = "AEGIS_LEDGER"
    sys.modules["AEGIS_LEDGER"] = _pkg
