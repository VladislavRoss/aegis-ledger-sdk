"""
aegis.mcp_server -- Model Context Protocol server for Aegis Ledger.

Exposes the Aegis SDK as MCP tools, resources, and prompts so any
MCP-compatible AI agent can log actions to the tamper-evident ledger.

Supports 5 signature algorithms via ``default_scheme`` config:
Ed25519, ML-DSA-65, ML-DSA-87 (CNSA 2.0 Level 5), SLH-DSA-128s, Hybrid.

Start via CLI:
    aegis-mcp              # stdio transport (default)

Or programmatically:
    from aegis.mcp_server import main
    main()
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import threading
import uuid
from pathlib import Path
from typing import Any

from aegis.integrity import (
    HEALTH_HASH_MAP as _HEALTH_HASH_MAP,
)
from aegis.integrity import (
    VERIFY_HASH_MAP as _VERIFY_HASH_MAP,
)
from aegis.integrity import (
    map_candid_keys as _map_candid_keys,
)
from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("aegis.mcp")

# Maximum seconds before a tool call is aborted (prevents infinite hangs)
_TOOL_TIMEOUT = 30

# Chain state persistence (shared with flush hook)
_CHAIN_STATE_PATH = Path.home() / ".aegis" / "agent_chain_state.json"
_chain_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Spill-First background worker — entries are persisted to disk BEFORE ICP
# submission so MCP tools return instantly (<1ms) and no data is lost on crash.
# BG worker batch-coalesces entries for efficient ICP submission.
# ---------------------------------------------------------------------------

_AEGIS_DIR = Path.home() / ".aegis"
_MCP_QUEUE_PATH = _AEGIS_DIR / f"mcp_queue_{os.getpid()}.jsonl"
_BATCH_SIZE = 10
_BATCH_WAIT_S = 5.0

_bg_thread: threading.Thread | None = None
_bg_stop = threading.Event()
_bg_started = threading.Event()


def _adopt_orphan_queues() -> None:
    """Adopt queue files from dead processes (crash recovery for multi-agent).

    On startup, scan for mcp_queue_*.jsonl files whose PID is no longer alive.
    Append their contents to our queue so entries are never lost.
    """
    if not _AEGIS_DIR.exists():
        return
    my_pid = str(os.getpid())
    for qfile in _AEGIS_DIR.glob("mcp_queue_*.jsonl"):
        pid_str = qfile.stem.replace("mcp_queue_", "")
        if pid_str == my_pid:
            continue
        # Check if the PID is still alive
        try:
            os.kill(int(pid_str), 0)  # signal 0 = existence check
            continue  # process alive, don't touch
        except (OSError, ValueError):
            pass  # process dead or invalid PID — adopt its entries
        try:
            content = qfile.read_text(encoding="utf-8").strip()
            if content:
                fd = os.open(str(_MCP_QUEUE_PATH), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
                try:
                    os.write(fd, (content + "\n").encode("utf-8"))
                finally:
                    os.close(fd)
                n = content.count("\n") + 1
                logger.info("Adopted %d orphan entries from %s", n, qfile.name)
            qfile.unlink()
        except OSError:
            logger.debug("Could not adopt orphan queue %s", qfile.name, exc_info=True)


def _spill_entry(entry: dict[str, Any]) -> None:
    """Persist a log entry to disk (Spill-First: data safe before ICP submission)."""
    _MCP_QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
    # S-4: Harden directory permissions (0o700) — matches transport.py spill_dir
    with contextlib.suppress(OSError):
        _MCP_QUEUE_PATH.parent.chmod(0o700)
    # S-5: PII redaction BEFORE disk write (prevents pre-redaction PII leak)
    from aegis.pii import redact_pii_data
    for field in ("input_data", "output_data", "reasoning"):
        if field in entry:
            entry[field] = redact_pii_data(entry[field], warn=False)
    line = json.dumps(entry, default=str) + "\n"
    fd = os.open(str(_MCP_QUEUE_PATH), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)


def _queue_depth() -> int:
    """Return current queue depth from persistent file."""
    if not _MCP_QUEUE_PATH.exists():
        return 0
    try:
        content = _MCP_QUEUE_PATH.read_text(encoding="utf-8").strip()
        return len(content.split("\n")) if content else 0
    except OSError:
        return 0


def _peek_queue(max_entries: int) -> tuple[list[dict[str, Any]], int]:
    """Read up to max_entries from the persistent queue without removing them."""
    if not _MCP_QUEUE_PATH.exists():
        return [], 0
    try:
        content = _MCP_QUEUE_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        return [], 0
    if not content:
        return [], 0
    lines = content.split("\n")
    entries: list[dict[str, Any]] = []
    count = 0
    for line in lines[:max_entries]:
        count += 1
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries, count


def _consume_queue(count: int) -> None:
    """Remove the first ``count`` lines from the persistent queue (GR-7: atomic write)."""
    if not _MCP_QUEUE_PATH.exists():
        return
    try:
        lines = _MCP_QUEUE_PATH.read_text(encoding="utf-8").strip().split("\n")
    except OSError:
        return
    remaining = lines[count:]
    if remaining and remaining != [""]:
        tmp = _MCP_QUEUE_PATH.with_suffix(".tmp")
        tmp.write_text("\n".join(remaining) + "\n", encoding="utf-8")
        tmp.replace(_MCP_QUEUE_PATH)
    else:
        with contextlib.suppress(OSError):
            _MCP_QUEUE_PATH.unlink()


def _bg_worker() -> None:
    """Background daemon: reads persistent queue, batch-submits to ICP.

    Lazy-initializes the AegisClient on first batch — this keeps
    MCP tool calls instant (<1ms) because _spill_entry() needs no client.
    """
    global _client
    _adopt_orphan_queues()
    _bg_started.set()
    while not _bg_stop.is_set():
        entries, line_count = _peek_queue(_BATCH_SIZE)
        if not entries:
            _bg_stop.wait(timeout=_BATCH_WAIT_S)
            continue
        if _client is None:
            try:
                _client = _init_client()
                logger.debug("BG worker: client initialized lazily")
            except Exception:
                logger.warning("BG worker: client init failed, retry in 5s",
                               exc_info=True)
                _bg_stop.wait(timeout=5.0)
                continue
        # Batch-coalesce: wait briefly for more entries if batch is small
        if line_count < _BATCH_SIZE:
            _bg_stop.wait(timeout=min(_BATCH_WAIT_S, 2.0))
            entries, line_count = _peek_queue(_BATCH_SIZE)
            if not entries:
                continue
        try:
            _client.log_batch(entries)
            _persist_client_state()
            _consume_queue(line_count)
            logger.debug("BG batch: %d entries submitted", len(entries))
        except Exception:
            logger.warning("BG batch submit failed (entries remain in queue)", exc_info=True)
            _persist_client_state()
            _bg_stop.wait(timeout=2.0)


def _ensure_bg_worker() -> None:
    """Start the background worker thread if not already running."""
    global _bg_thread
    if _bg_thread is not None and _bg_thread.is_alive():
        return
    _bg_stop.clear()
    _bg_started.clear()
    _bg_thread = threading.Thread(target=_bg_worker, daemon=True, name="aegis-bg")
    _bg_thread.start()
    _bg_started.wait(timeout=2.0)

# ---------------------------------------------------------------------------
# Candid hash-key mapping — single source of truth in integrity.py
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# MCP server instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "aegis-ledger",
    instructions=(
        "Aegis Ledger — tamper-evident AI execution logging.\n\n"
        "IMPORTANT: After EVERY tool call you make, log it with aegis_log_tool_call(). "
        "This creates a cryptographically signed, hash-chained audit trail on the "
        "Internet Computer blockchain. Include the tool name, input, output, and "
        "duration. For decisions, use aegis_log_decision(). For errors, use "
        "aegis_log_error(). This logging is required for EU AI Act (Art. 12) "
        "compliance and provides tamper-evident proof of AI agent behavior."
    ),
)

# ---------------------------------------------------------------------------
# Lazy client singleton
# ---------------------------------------------------------------------------

_client: Any = None
_transport: Any = None  # lightweight read-only (no private key)


def _load_chain_state(agent_id: str) -> dict[str, Any]:
    """Load persisted chain state for an agent (shared with flush hook)."""
    if not _CHAIN_STATE_PATH.exists():
        return {"sequence": 0, "chain_hash": ""}
    try:
        data = json.loads(_CHAIN_STATE_PATH.read_text(encoding="utf-8"))
        return data.get(agent_id, {"sequence": 0, "chain_hash": ""})
    except (json.JSONDecodeError, OSError):
        return {"sequence": 0, "chain_hash": ""}


def _save_chain_state(agent_id: str, sequence: int, chain_hash: str) -> None:
    """Persist chain state for an agent (atomic write, shared with flush hook)."""
    with _chain_lock:
        all_state: dict[str, Any] = {}
        if _CHAIN_STATE_PATH.exists():
            with contextlib.suppress(json.JSONDecodeError, OSError):
                all_state = json.loads(
                    _CHAIN_STATE_PATH.read_text(encoding="utf-8")
                )
        all_state[agent_id] = {"sequence": sequence, "chain_hash": chain_hash}
        tmp = _CHAIN_STATE_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(all_state, indent=2), encoding="utf-8")
        tmp.replace(_CHAIN_STATE_PATH)


def _get_config() -> dict[str, str]:
    """Read config from env vars, falling back to ~/.aegis/config.toml."""
    cfg: dict[str, str] = {}

    # Try config.toml first for defaults
    try:
        from aegis.config import load_config
        toml_cfg = load_config()
        signing = toml_cfg.get("signing", {})
        client_section = toml_cfg.get("client", {})
        cfg["canister_id"] = client_section.get("canister_id", "")
        cfg["api_key_id"] = client_section.get("api_key_id", "")
        cfg["private_key_path"] = client_section.get("private_key_path", "")
        cfg["agent_id"] = client_section.get("agent_id", "")
        cfg["org_id"] = client_section.get("org_id", "")
        cfg["network"] = client_section.get("network", "")
        cfg["signature_scheme"] = signing.get("default_scheme", "")
        cfg["signing_key_path"] = signing.get("signing_key_path", "")
    except ImportError:
        logger.debug("aegis.config not available, using env vars only")
    except Exception:
        logger.warning("Failed to load config.toml, using env vars only",
                       exc_info=True)

    # Env vars override config.toml
    _default_canister = "toqqq-lqaaa-aaaae-afc2a-cai"
    cfg["canister_id"] = (
        os.environ.get("AEGIS_CANISTER_ID", cfg.get("canister_id", ""))
        or _default_canister
    )
    cfg["api_key_id"] = os.environ.get(
        "AEGIS_API_KEY_ID", cfg.get("api_key_id", ""),
    )
    cfg["private_key_path"] = os.environ.get(
        "AEGIS_PRIVATE_KEY_PATH", cfg.get("private_key_path", ""),
    )
    cfg["agent_id"] = os.environ.get("AEGIS_AGENT_ID", cfg.get("agent_id", "")) or "mcp-agent"
    cfg["org_id"] = os.environ.get("AEGIS_ORG_ID", cfg.get("org_id", ""))
    cfg["network"] = os.environ.get("AEGIS_NETWORK", cfg.get("network", "")) or "https://icp-api.io"

    return cfg


def _init_client() -> Any:
    """Initialize the AegisClient (blocking, call from thread).

    Reuses the global _transport for sequence sync instead of creating
    a third transport object.
    """
    import gc  # noqa: E402

    from aegis import AegisClient

    cfg = _get_config()
    if not cfg["api_key_id"]:
        raise ValueError(
            "AEGIS_API_KEY_ID is required. Set it as an environment variable "
            "or in ~/.aegis/config.toml [client] api_key_id."
        )
    if not cfg["private_key_path"]:
        raise ValueError(
            "AEGIS_PRIVATE_KEY_PATH is required. Set it as an environment variable "
            "or in ~/.aegis/config.toml [client] private_key_path."
        )

    # Unique session_id per MCP process — allows parallel agents without
    # sequence-number conflicts on the canister.  agent_id stays shared.
    agent_id = cfg["agent_id"]
    session_id = f"{agent_id}-{uuid.uuid4().hex[:8]}"
    kwargs: dict[str, Any] = {
        "canister_id": cfg["canister_id"],
        "api_key_id": cfg["api_key_id"],
        "private_key_path": cfg["private_key_path"],
        "agent_id": agent_id,
        "session_id": session_id,
        "network": cfg["network"],
        "fail_open": True,
        "redact_pii": True,
    }
    if cfg.get("org_id"):
        kwargs["org_id"] = cfg["org_id"]
    if cfg.get("signature_scheme"):
        kwargs["signature_scheme"] = cfg["signature_scheme"]
    if cfg.get("signing_key_path"):
        kwargs["signing_key_path"] = cfg["signing_key_path"]

    client = AegisClient(**kwargs)

    # Fresh session per process — no chain state restore needed (seq starts at 0).
    # Auto-recovery: sync with canister in case session_id was reused (unlikely).
    global _transport
    try:
        if _transport is None:
            _transport = _init_transport()
        canister_state = _sync_sequence_from_canister(_transport, session_id=session_id)
        if canister_state is not None:
            canister_seq, canister_hash = canister_state
            canister_next = canister_seq + 1
            if canister_next > client._sequence:
                client._sequence = canister_next
                if canister_hash:
                    client._chain_heads[session_id] = canister_hash
    except Exception:
        logger.debug("Canister sync skipped (offline or no admin access)")

    logger.info(
        "MCP client initialized: agent=%s session=%s seq=%d",
        agent_id, session_id, client._sequence,
    )
    gc.collect()
    return client


def _sync_sequence_from_canister(
    transport: Any, *, session_id: str,
) -> tuple[int, str] | None:
    """Query canister for the actual sequence head of a session.

    Uses the provided transport (no extra allocation) and the public
    ``getSessionSequenceHead`` endpoint — no auth needed.
    """
    from ic.candid import Types  # type: ignore[import-untyped]

    raw = transport.call_query(
        "getSessionSequenceHead",
        [{"type": Types.Text, "value": session_id}],
    )
    if not isinstance(raw, dict):
        return None

    seq_head = None
    chain_hash = ""
    for _k, v in raw.items():
        if isinstance(v, list) and len(v) == 1 and isinstance(v[0], int):
            seq_head = v[0]
        elif isinstance(v, list) and len(v) == 0:
            seq_head = None
        elif isinstance(v, str):
            chain_hash = v

    if seq_head is None:
        return None
    return (seq_head, chain_hash)


async def _get_client() -> Any:
    """Lazy-init the AegisClient singleton (non-blocking)."""
    global _client
    if _client is not None:
        return _client

    _client = await asyncio.wait_for(
        asyncio.to_thread(_init_client),
        timeout=_TOOL_TIMEOUT,
    )
    return _client


def _persist_client_state() -> None:
    """Save current client chain state after a successful log call."""
    if _client is None:
        return
    try:
        sid = getattr(_client, "_session_id", "")
        if not sid or not isinstance(sid, str):
            return
        seq = getattr(_client, "_sequence", 0)
        if not isinstance(seq, int):
            return
        heads = getattr(_client, "_chain_heads", {})
        chain_hash = heads.get(sid, "")
        if not isinstance(chain_hash, str):
            chain_hash = ""
        _save_chain_state(sid, seq, chain_hash)
    except Exception:
        logger.debug("Failed to persist client state", exc_info=True)


def _init_transport() -> Any:
    """Initialize a lightweight read-only transport (no private key).

    Used for public queries (getHealth, verifyEntry, getSessionSequenceHead).
    No crypto loaded — keeps memory low until a write is needed.
    """
    from aegis.transport import CanisterTransport, TransportConfig

    cfg = _get_config()
    return CanisterTransport(TransportConfig(
        canister_id=cfg["canister_id"],
        network=cfg["network"],
    ))


async def _get_transport() -> Any:
    """Lazy-init the read-only transport singleton (non-blocking)."""
    global _transport
    if _transport is not None:
        return _transport

    _transport = await asyncio.wait_for(
        asyncio.to_thread(_init_transport),
        timeout=_TOOL_TIMEOUT,
    )
    return _transport


async def _run_with_timeout(fn: Any, *args: Any) -> Any:
    """Run a blocking function in a thread with timeout."""
    return await asyncio.wait_for(
        asyncio.to_thread(fn, *args),
        timeout=_TOOL_TIMEOUT,
    )


# ---------------------------------------------------------------------------
# Tools (8) — all async to avoid blocking the MCP event loop
# ---------------------------------------------------------------------------


@mcp.tool()
async def aegis_log_tool_call(
    tool: str,
    input_data: str,
    output_data: str,
    duration_ms: int = 0,
    status: str = "success",
    reasoning: str = "",
    confidence: float = 0.0,
) -> str:
    """Log a tool/API call to the tamper-evident Aegis Ledger.

    Fire-and-forget: returns instantly, ICP submission happens in background.

    Args:
        tool: Name of the tool or API called (e.g. "web_search", "db.query").
        input_data: JSON string of the input arguments.
        output_data: JSON string of the tool output.
        duration_ms: Execution time in milliseconds.
        status: "success", "error", or "timeout".
        reasoning: Why this tool was called.
        confidence: Confidence score between 0.0 and 1.0.

    Returns:
        JSON with queued status and queue depth.
    """
    _ensure_bg_worker()
    _spill_entry({
        "action_type": "tool_call",
        "tool": tool,
        "input_data": _parse_json(input_data),
        "output_data": _parse_json(output_data),
        "duration_ms": duration_ms,
        "status": status,
        "reasoning": reasoning,
        "confidence": confidence,
    })
    return json.dumps({"status": "queued", "queue_depth": _queue_depth()})


@mcp.tool()
async def aegis_log_decision(
    reasoning: str,
    confidence: float,
    input_data: str = "{}",
    output_data: str = "{}",
    duration_ms: int = 0,
) -> str:
    """Log a decision/reasoning step to the tamper-evident Aegis Ledger.

    Fire-and-forget: returns instantly, ICP submission happens in background.

    Args:
        reasoning: The decision reasoning text.
        confidence: Confidence score between 0.0 and 1.0.
        input_data: JSON string of context that led to the decision.
        output_data: JSON string of the decision output.
        duration_ms: Time spent on the decision in milliseconds.

    Returns:
        JSON with queued status and queue depth.
    """
    _ensure_bg_worker()
    _spill_entry({
        "action_type": "decision",
        "tool": "decision",
        "input_data": _parse_json(input_data),
        "output_data": _parse_json(output_data),
        "duration_ms": duration_ms,
        "status": "success",
        "reasoning": reasoning,
        "confidence": confidence,
    })
    return json.dumps({"status": "queued", "queue_depth": _queue_depth()})


@mcp.tool()
async def aegis_log_observation(
    input_data: str,
    output_data: str = "{}",
    duration_ms: int = 0,
) -> str:
    """Log an observation (sensor data, API response, etc.) to the Aegis Ledger.

    Fire-and-forget: returns instantly, ICP submission happens in background.

    Args:
        input_data: JSON string of the observation data.
        output_data: JSON string of processed observation output.
        duration_ms: Time spent processing in milliseconds.

    Returns:
        JSON with queued status and queue depth.
    """
    _ensure_bg_worker()
    _spill_entry({
        "action_type": "observation",
        "tool": "observation",
        "input_data": _parse_json(input_data),
        "output_data": _parse_json(output_data),
        "duration_ms": duration_ms,
        "status": "success",
    })
    return json.dumps({"status": "queued", "queue_depth": _queue_depth()})


@mcp.tool()
async def aegis_log_error(
    tool: str,
    input_data: str,
    error: str,
    duration_ms: int = 0,
) -> str:
    """Log an error encountered during agent execution to the Aegis Ledger.

    Fire-and-forget: returns instantly, ICP submission happens in background.

    Args:
        tool: Name of the tool that failed.
        input_data: JSON string of the input that caused the error.
        error: Error message string.
        duration_ms: Time elapsed before the error in milliseconds.

    Returns:
        JSON with queued status and queue depth.
    """
    _ensure_bg_worker()
    _spill_entry({
        "action_type": "tool_call",
        "tool": tool,
        "input_data": _parse_json(input_data),
        "output_data": {"error": error},
        "duration_ms": duration_ms,
        "status": "error",
    })
    return json.dumps({"status": "queued", "queue_depth": _queue_depth()})


@mcp.tool()
async def aegis_verify_entry(action_id: str) -> str:
    """Verify a ledger entry on-chain via cryptographic hash-chain verification.

    Args:
        action_id: The action_id to verify.

    Returns:
        JSON with is_valid, stored_chain_hash, message, previous_chain_hash,
        sequence_number, and action_id.
    """
    transport = await _get_transport()

    def _call() -> str:
        from ic.candid import Types  # type: ignore[import-untyped]

        raw = transport.call_query(
            "verifyEntry", [{"type": Types.Text, "value": action_id}]
        )
        result = _map_candid_keys(raw, _VERIFY_HASH_MAP)
        return json.dumps({
            "is_valid": result.get("isValid", False),
            "stored_chain_hash": result.get("storedChainHash", ""),
            "message": result.get("message", ""),
            "previous_chain_hash": result.get("previousChainHash", ""),
            "sequence_number": result.get("sequenceNumber", 0),
            "action_id": action_id,
        })

    return await _run_with_timeout(_call)


@mcp.tool()
async def aegis_get_health() -> str:
    """Get live health info from the Aegis canister on ICP.

    Returns:
        JSON with totalEntries, totalKeys, totalOrgs, heapBytes, etc.
    """
    transport = await _get_transport()

    def _call() -> str:
        raw = transport.call_query("getHealth", [])
        health = _map_candid_keys(raw, _HEALTH_HASH_MAP)
        return json.dumps(health, default=str)

    return await _run_with_timeout(_call)


@mcp.tool()
async def aegis_generate_report(format: str = "eu-ai-act") -> str:
    """Generate a compliance report from live canister data.

    Args:
        format: Report framework — "eu-ai-act", "iso-42001", or "aiuc-1".

    Returns:
        The generated Markdown compliance report text.
    """
    def _call() -> str:
        from aegis.report import ReportFormat, generate_report

        cfg = _get_config()
        fmt = ReportFormat(format)
        report = generate_report(canister_id=cfg["canister_id"], format=fmt)
        return report.markdown

    return await _run_with_timeout(_call)


@mcp.tool()
async def aegis_flush_queue(max_entries: int = 50) -> str:
    """Flush the local hook queue to the on-chain ledger in one batch.

    The PostToolUse hook captures tool calls to ~/.aegis/hook_queue.jsonl.
    This tool reads pending entries, sends them as a single batch call,
    and truncates the queue. Much cheaper than individual log calls.

    Args:
        max_entries: Maximum entries to flush per call (default 50).

    Returns:
        JSON with flushed count and action_ids.
    """
    queue_path = Path.home() / ".aegis" / "hook_queue.jsonl"
    if not queue_path.exists():
        return json.dumps({"flushed": 0, "message": "Queue empty"})

    lines = queue_path.read_text(encoding="utf-8").strip().splitlines()
    if not lines:
        return json.dumps({"flushed": 0, "message": "Queue empty"})

    # Parse up to max_entries
    entries: list[dict[str, Any]] = []
    for line in lines[:max_entries]:
        try:
            entry = json.loads(line)
            entries.append({
                "action_type": "tool_call",
                "tool": entry.get("tool", "unknown"),
                "input_data": _parse_json(entry.get("input_data", "{}")),
                "output_data": _parse_json(entry.get("output_data", "{}")),
                "status": "success",
            })
        except json.JSONDecodeError:
            continue

    if not entries:
        return json.dumps({"flushed": 0, "message": "No valid entries"})

    client = await _get_client()

    def _call() -> str:
        result = client.log_batch(entries)
        _persist_client_state()
        return json.dumps({
            "flushed": len(entries),
            "action_ids": result if isinstance(result, list) else [],
            "remaining": max(0, len(lines) - max_entries),
        })

    response = await _run_with_timeout(_call)

    # Truncate flushed entries from queue (atomic write)
    remaining_lines = lines[max_entries:]
    tmp = queue_path.with_suffix(".tmp")
    tmp.write_text(
        "\n".join(remaining_lines) + ("\n" if remaining_lines else ""),
        encoding="utf-8",
    )
    tmp.replace(queue_path)

    return response


@mcp.tool()
async def aegis_new_session(session_id: str = "") -> str:
    """Start a new logging session, resetting the sequence counter.

    Args:
        session_id: Custom session ID. Defaults to agent_id for agent-centric logging.

    Returns:
        JSON with the new session_id.
    """
    client = await _get_client()
    # Default to agent_id — agent-centric logging, not random sessions
    effective_id = session_id or client._agent_id
    new_id = client.new_session(session_id=effective_id)
    return json.dumps({"session_id": new_id})


# ---------------------------------------------------------------------------
# Resources (2)
# ---------------------------------------------------------------------------


@mcp.resource("aegis://health")
def resource_health() -> str:
    """Live canister health status as JSON."""
    if _transport is None:
        return json.dumps({"error": "transport not initialized — call a tool first"})
    raw = _transport.call_query("getHealth", [])
    health = _map_candid_keys(raw, _HEALTH_HASH_MAP)
    return json.dumps(health, default=str)


@mcp.resource("aegis://session/{session_id}")
def resource_session(session_id: str) -> str:
    """Session info for the current client."""
    try:
        return json.dumps({
            "session_id": _client.session_id if _client else "(not initialized)",
            "requested_session_id": session_id,
            "sequence_number": _client.sequence_number if _client else 0,
            "pending_spill_count": _client.pending_spill_count if _client else 0,
            "agent_id": _client._agent_id if _client else "(not initialized)",
            "canister_id": _client._canister_id if _client else "(not initialized)",
        })
    except Exception as exc:
        return json.dumps({"error": str(exc), "requested_session_id": session_id})


# ---------------------------------------------------------------------------
# Prompts (2)
# ---------------------------------------------------------------------------


@mcp.prompt()
def audit_session(session_id: str = "") -> str:
    """Pre-built prompt for auditing an Aegis session trace.

    Args:
        session_id: The session ID to audit. Leave empty for the current session.
    """
    sid = session_id or "(current session)"
    return (
        f"Analyze the Aegis Ledger session '{sid}' for compliance and integrity.\n\n"
        "Steps:\n"
        "1. Call aegis_get_health() to verify the canister is operational.\n"
        "2. Review the session's logged actions for completeness — every tool call,\n"
        "   decision, and observation should be recorded.\n"
        "3. For each action_id, call aegis_verify_entry() to confirm hash-chain\n"
        "   integrity.\n"
        "4. Check that sequence numbers are monotonically increasing with no gaps.\n"
        "5. Flag any anomalies: missing entries, broken chains, or error spikes.\n"
        "6. Generate a compliance report with aegis_generate_report('eu-ai-act').\n\n"
        "Provide a structured summary with:\n"
        "- Total actions logged\n"
        "- Chain integrity status (all verified / N broken)\n"
        "- Compliance score\n"
        "- Recommendations for remediation (if any)"
    )


@mcp.prompt()
def compliance_check(framework: str = "eu-ai-act") -> str:
    """Pre-built prompt for running a compliance assessment.

    Args:
        framework: Compliance framework — "eu-ai-act", "iso-42001", or "aiuc-1".
    """
    return (
        f"Perform a compliance assessment against the '{framework}' framework.\n\n"
        "Steps:\n"
        "1. Call aegis_get_health() to get current canister statistics.\n"
        "2. Call aegis_generate_report('" + framework + "') for the detailed report.\n"
        "3. Analyze the compliance score and identify gaps.\n"
        "4. For critical findings, verify individual entries with aegis_verify_entry().\n"
        "5. Cross-reference the report against the framework requirements:\n"
        "   - EU AI Act: Art. 12 (logging), Art. 14 (human oversight)\n"
        "   - ISO 42001: A.6.2.6, A.8.4, A.9.3\n"
        "   - AIUC-1: Continuous logging, chain integrity, incident detection\n\n"
        "Deliver:\n"
        "- Overall compliance score with pass/fail per criterion\n"
        "- Evidence references (action_ids, chain hashes)\n"
        "- Prioritized remediation roadmap"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_json(raw: str) -> Any:
    """Parse a JSON string, returning the raw string as-is if parsing fails."""
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the Aegis MCP server with stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
