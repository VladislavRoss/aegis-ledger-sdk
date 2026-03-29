"""
aegis.config — User-level configuration for the Aegis SDK.

Reads ``~/.aegis/config.toml`` (if it exists) and exposes typed helpers.

Supported keys::

    [client]
    canister_id = "toqqq-lqaaa-aaaae-afc2a-cai"
    api_key_id = "ak_my_key"
    agent_id = "my-agent"
    private_key_path = "~/.aegis/agent_key.pem"
    org_id = "xxxxx-xxxxx-..."  # Your II Principal (from Dashboard)

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


def _find_project_config() -> Path | None:
    """Find .aegis/config.toml in the current directory or parents.

    Returns the path if found, None otherwise. Does NOT create it.
    """
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        candidate = parent / ".aegis" / "config.toml"
        if candidate.is_file():
            return candidate
        # Stop at filesystem root or home
        if parent == Path.home() or parent == parent.parent:
            break
    return None


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


def get_client_config(config: dict[str, Any] | None = None) -> dict[str, str]:
    """Return the [client] section as a flat dict.

    Keys: canister_id, api_key_id, agent_id, private_key_path.
    Missing keys are omitted (not set to empty string).
    """
    if config is None:
        config = load_config()
    client = config.get("client", {})
    if not isinstance(client, dict):
        return {}
    result: dict[str, str] = {}
    for key in ("canister_id", "api_key_id", "agent_id", "private_key_path", "org_id"):
        val = client.get(key)
        if val is not None:
            result[key] = str(val)
    return result


def write_config(
    *,
    canister_id: str = "",
    api_key_id: str = "",
    agent_id: str = "",
    private_key_path: str = "",
    org_id: str = "",
    signing_scheme: str = "",
    signing_key_path: str = "",
    config_path: Path | None = None,
    project_local: bool = False,
) -> Path:
    """Write or update config.toml with the given values.

    If ``project_local`` is True, writes to ``.aegis/config.toml`` in the
    current working directory (creates ``.aegis/`` if needed).
    Otherwise writes to ``~/.aegis/config.toml`` (global).

    Preserves existing values not overwritten.
    Returns the path to the written config file.
    """
    if config_path:
        path = config_path
    elif project_local:
        path = Path.cwd() / ".aegis" / "config.toml"
    else:
        path = _CONFIG_FILE
    path.parent.mkdir(parents=True, exist_ok=True)

    existing = _load_toml(path)
    client = existing.get("client", {})
    if not isinstance(client, dict):
        client = {}
    signing = existing.get("signing", {})
    if not isinstance(signing, dict):
        signing = {}

    if canister_id:
        client["canister_id"] = canister_id
    if api_key_id:
        client["api_key_id"] = api_key_id
    if agent_id:
        client["agent_id"] = agent_id
    if private_key_path:
        client["private_key_path"] = private_key_path
    if org_id:
        client["org_id"] = org_id

    if signing_scheme:
        signing["default_scheme"] = signing_scheme
    if signing_key_path:
        signing["signing_key_path"] = signing_key_path

    lines: list[str] = ["# Aegis SDK Configuration", "# Generated by: aegis init", ""]
    if client:
        lines.append("[client]")
        for k, v in client.items():
            # Forward slashes for TOML compatibility (backslashes are escape chars)
            safe_v = v.replace("\\", "/") if "path" in k else v
            lines.append(f'{k} = "{safe_v}"')
        lines.append("")
    if signing:
        lines.append("[signing]")
        for k, v in signing.items():
            safe_v = v.replace("\\", "/") if "path" in k else v
            lines.append(f'{k} = "{safe_v}"')
        lines.append("")

    # GR-7: Atomic write — tmp + replace to prevent corruption on crash
    tmp = path.with_suffix(".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(path)
    return path


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
