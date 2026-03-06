"""Shared test configuration — mock ic-py to prevent Windows WMI hang."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

# ic-py (the Internet Computer Python SDK) hangs on Windows during import
# because it triggers WMI/COM calls. Pre-populate sys.modules with mocks
# so that `from ic.candid import Types` and `from ic.identity import Identity`
# resolve immediately without importing the real package.
#
# Tests that need real ic-py behavior should run in CI (Linux), not locally.

if "ic" not in sys.modules:
    _ic_mock = MagicMock()
    sys.modules["ic"] = _ic_mock
    sys.modules["ic.candid"] = _ic_mock.candid
    sys.modules["ic.identity"] = _ic_mock.identity
    sys.modules["ic.agent"] = _ic_mock.agent
    sys.modules["ic.client"] = _ic_mock.client
