"""
aegis.config — User-level configuration for the Aegis SDK.

Reads ``~/.aegis/config.toml`` (if it exists) and exposes typed helpers.

Supported keys::

    [signing]
    default_scheme = "hybrid"        # ed25519 | ml-dsa-65 | ml-dsa-87 | slh-dsa-128s | hybrid
    signing_key_path = "./agent.mldsa65"  # path to ML-DSA-65 SK (for hybrid/ml-dsa-65)
"""

from __future__ import annotations

import os
import stat
import sys
import warnings
from pathlib import Path
from typing import Any

_VALID_SCHEMES = frozenset({"ed25519", "ml-dsa-65", "ml-dsa-87", "slh-dsa-128s", "hybrid"})

_CONFIG_DIR = Path(os.environ.get("AEGIS_CONFIG_DIR", "~/.aegis")).expanduser()
_CONFIG_FILE = _CONFIG_DIR / "config.toml"


def _load_toml(path: Path) -> dict[str, Any]:
    """Load a TOML file, returning {} if missing or unparseable."""
    if not path.is_file():
        return {}
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:  # pragma: no cover
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ModuleNotFoundError:
            warnings.warn(
                "Neither tomllib nor tomli installed; config.toml ignored. "
                "Install with: pip install tomli",
                stacklevel=2,
            )
            return {}
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        warnings.warn(
            f"Failed to parse {path}: {exc}. Falling back to defaults.",
            stacklevel=2,
        )
        return {}


def load_config(*, config_path: Path | None = None) -> dict[str, Any]:
    """Load and validate the Aegis config file.

    Args:
        config_path: Override the default ``~/.aegis/config.toml``.

    Returns:
        Parsed config dict (may be empty if file doesn't exist).
    """
    path = config_path or _CONFIG_FILE
    return _load_toml(path)


def get_default_scheme(config: dict[str, Any] | None = None) -> str:
    """Return the configured default signature scheme.

    Falls back to ``"ed25519"`` if not configured or invalid.
    """
    if config is None:
        config = load_config()
    signing = config.get("signing", {})
    if not isinstance(signing, dict):
        return "ed25519"
    scheme = signing.get("default_scheme", "ed25519")
    if scheme not in _VALID_SCHEMES:
        return "ed25519"
    return str(scheme)


def get_signing_key_path(config: dict[str, Any] | None = None) -> str | None:
    """Return the configured signing_key_path, or None."""
    if config is None:
        config = load_config()
    signing = config.get("signing", {})
    if not isinstance(signing, dict):
        return None
    path = signing.get("signing_key_path")
    if path is not None:
        return str(path)
    return None


def validate_key_permissions(path: Path) -> None:
    """Warn if a private key file has overly permissive permissions.

    On Unix, checks that group/other have no access (mode & 0o077 == 0).
    On Windows, this check is skipped (NTFS ACLs are not inspectable via stat).
    """
    if sys.platform == "win32":
        return
    try:
        mode = path.stat().st_mode
        if mode & stat.S_IRWXG or mode & stat.S_IRWXO:
            warnings.warn(
                f"Private key {path} has overly permissive permissions "
                f"(mode {oct(mode)}). Run: chmod 600 {path}",
                UserWarning,
                stacklevel=2,
            )
    except OSError:
        pass
