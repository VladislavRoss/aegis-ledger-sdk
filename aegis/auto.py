"""aegis.auto -- Zero-config auto-instrumentation for AI agent frameworks.

Usage::

    import aegis
    aegis.auto()  # Detects framework, installs hooks, done.

Or via environment variable::

    AEGIS_AUTO=1 python my_agent.py

Supported frameworks (auto-detected):
  - **LangChain** -- fully automatic via ``set_handler()``
  - **OpenAI Agents SDK** -- hook stored as ``client._openai_hooks``
  - **CrewAI** -- callback stored as ``client._crewai_callback``
  - **AutoGen / AG2** -- hook stored as ``client._autogen_hook``
  - **Anthropic Agent SDK** -- tracer stored as ``client._anthropic_tracer``

Frameworks that don't support global hooks expose their hook objects on the
returned ``AegisClient`` instance so the caller can wire them manually with
a single attribute access.
"""

from __future__ import annotations

import atexit
import logging
import warnings
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from aegis.client import AegisClient

logger = logging.getLogger("aegis.auto")

# Module-level reference for later inspection / teardown.
_auto_client: AegisClient | None = None

# Framework registry: (import_probe, framework_label)
# import_probe is the module name used to check if the framework is installed.
_FRAMEWORKS: list[tuple[str, str]] = [
    ("langchain_core", "langchain"),
    ("openai", "openai_agents"),
    ("crewai", "crewai"),
    ("autogen", "autogen"),
    ("claude_agent_sdk", "anthropic_sdk"),
]


def _is_available(module_name: str) -> bool:
    """Return True if *module_name* can be imported."""
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False


def _install_langchain(client: AegisClient) -> bool:
    """Install AegisCallbackHandler as the global LangChain handler.

    Returns True on success, False if the required API is missing.
    """
    try:
        from langchain_core.callbacks import set_handler  # type: ignore[import-untyped]

        from aegis.langchain import AegisCallbackHandler

        handler = AegisCallbackHandler(client)
        set_handler(handler)
        return True
    except (ImportError, AttributeError):
        # set_handler might not exist in older langchain_core versions.
        # Fall back to storing the handler on the client.
        try:
            from aegis.langchain import AegisCallbackHandler

            client._langchain_handler = AegisCallbackHandler(client)  # type: ignore[attr-defined]
            logger.info(
                "LangChain detected but set_handler unavailable. "
                "Use client._langchain_handler in your chain config."
            )
            return True
        except ImportError:
            return False


def _install_openai_agents(client: AegisClient) -> bool:
    """Create AegisRunHooks and store on the client."""
    try:
        from aegis.openai_agents import AegisRunHooks

        client._openai_hooks = AegisRunHooks(client)  # type: ignore[attr-defined]
        logger.info(
            "OpenAI Agents SDK detected. "
            "Pass client._openai_hooks as hooks= to Runner.run()."
        )
        return True
    except ImportError:
        return False


def _install_crewai(client: AegisClient) -> bool:
    """Create AegisCrewCallback and store on the client."""
    try:
        from aegis.crewai import AegisCrewCallback

        client._crewai_callback = AegisCrewCallback(client)  # type: ignore[attr-defined]
        logger.info(
            "CrewAI detected. "
            "Pass client._crewai_callback as step_callback= to Crew()."
        )
        return True
    except ImportError:
        return False


def _install_autogen(client: AegisClient) -> bool:
    """Create AegisAutoGenHook and store on the client."""
    try:
        from aegis.autogen import AegisAutoGenHook

        client._autogen_hook = AegisAutoGenHook(client)  # type: ignore[attr-defined]
        logger.info(
            "AutoGen detected. "
            "Use client._autogen_hook for message/tool logging."
        )
        return True
    except ImportError:
        return False


def _install_anthropic_sdk(client: AegisClient) -> bool:
    """Create AegisAnthropicTracer and store on the client."""
    try:
        from aegis.anthropic_sdk import AegisAnthropicTracer

        client._anthropic_tracer = AegisAnthropicTracer(client)  # type: ignore[attr-defined]
        logger.info(
            "Anthropic Agent SDK detected. "
            "Use client._anthropic_tracer or aegis.anthropic_sdk.aegis_hooks()."
        )
        return True
    except ImportError:
        return False


# Map framework labels to their installer functions.
_INSTALLERS: dict[str, object] = {
    "langchain": _install_langchain,
    "openai_agents": _install_openai_agents,
    "crewai": _install_crewai,
    "autogen": _install_autogen,
    "anthropic_sdk": _install_anthropic_sdk,
}


def auto(*, exclude: Sequence[str] | None = None) -> AegisClient:
    """Zero-config auto-instrumentation entry point.

    Detects installed AI agent frameworks, creates an :class:`AegisClient`
    via ``from_config()``, and installs the appropriate hooks.

    Args:
        exclude: Framework labels to skip (e.g. ``["langchain", "crewai"]``).
            Valid labels: ``langchain``, ``openai_agents``, ``crewai``,
            ``autogen``, ``anthropic_sdk``.

    Returns:
        The configured :class:`AegisClient` instance with hooks attached.
    """
    global _auto_client  # noqa: PLW0603

    from aegis.client import AegisClient

    client = AegisClient.from_config()

    excluded = set(exclude or [])
    installed: list[str] = []

    for probe_module, label in _FRAMEWORKS:
        if label in excluded:
            logger.debug("Skipping %s (excluded)", label)
            continue

        if not _is_available(probe_module):
            continue

        installer = _INSTALLERS.get(label)
        if callable(installer) and installer(client):
            installed.append(label)

    if installed:
        logger.info("Aegis auto-instrumented: %s", ", ".join(installed))
    else:
        warnings.warn(
            "No supported framework detected. "
            "Use @client.trace() decorator or MCP tools.",
            stacklevel=2,
        )

    atexit.register(client.close)
    _auto_client = client
    return client
