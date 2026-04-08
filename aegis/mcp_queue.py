"""
aegis.mcp_queue -- Spill-first persistent queue for MCP server.

Entries are persisted to disk BEFORE ICP submission so MCP tools return
instantly (<1ms) and no data is lost on crash.  A background thread
batch-coalesces entries for efficient ICP submission.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger("aegis.mcp")

_AEGIS_DIR = Path.home() / ".aegis"
_MCP_QUEUE_PATH = _AEGIS_DIR / f"mcp_queue_{os.getpid()}.jsonl"
_BATCH_SIZE = 5
_BATCH_WAIT_S = 1.0

_bg_thread: threading.Thread | None = None
_bg_stop = threading.Event()
_bg_started = threading.Event()


# ---------------------------------------------------------------------------
# Queue file operations
# ---------------------------------------------------------------------------


def adopt_orphan_queues() -> None:
    """Adopt queue files from dead processes and hook_queue.jsonl.

    On startup, scan for mcp_queue_*.jsonl files whose PID is no longer alive
    AND the shared hook_queue.jsonl (written by claude-code hooks without
    spawning any subprocess). Append their contents to our queue.
    """
    if not _AEGIS_DIR.exists():
        return
    my_pid = str(os.getpid())

    # 1. Adopt orphan MCP queues from dead processes
    for qfile in _AEGIS_DIR.glob("mcp_queue_*.jsonl"):
        pid_str = qfile.stem.replace("mcp_queue_", "")
        if pid_str == my_pid:
            continue
        try:
            os.kill(int(pid_str), 0)
            continue
        except (OSError, ValueError):
            pass
        _adopt_file(qfile, remove=True)

    # 2. Drain hook_queue.jsonl (lightweight hook entries → our queue)
    hook_queue = _AEGIS_DIR / "hook_queue.jsonl"
    _adopt_file(hook_queue, remove=True)


def _adopt_file(qfile: Path, *, remove: bool = True) -> None:
    """Move entries from *qfile* into our MCP queue, optionally removing it."""
    try:
        content = qfile.read_text(encoding="utf-8").strip()
    except OSError:
        return
    if not content:
        if remove:
            with contextlib.suppress(OSError):
                qfile.unlink()
        return
    fd = os.open(str(_MCP_QUEUE_PATH), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        os.write(fd, (content + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    n = content.count("\n") + 1
    logger.info("Adopted %d entries from %s", n, qfile.name)
    if remove:
        with contextlib.suppress(OSError):
            qfile.unlink()


def spill_entry(entry: dict[str, Any]) -> None:
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


def queue_depth() -> int:
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


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------


def _bg_worker(
    init_client_fn: Callable[[], Any],
    persist_fn: Callable[[], None],
) -> None:
    """Background daemon: reads persistent queue, batch-submits to ICP.

    Lazy-initializes the AegisClient on first batch — this keeps
    MCP tool calls instant (<1ms) because spill_entry() needs no client.
    """
    client = None
    adopt_orphan_queues()
    _bg_started.set()
    drain_counter = 0
    while not _bg_stop.is_set():
        # Periodically drain hook_queue.jsonl into our queue (every ~5 cycles)
        drain_counter += 1
        if drain_counter >= 5:
            drain_counter = 0
            hook_queue = _AEGIS_DIR / "hook_queue.jsonl"
            if hook_queue.exists():
                _adopt_file(hook_queue, remove=True)
        entries, line_count = _peek_queue(_BATCH_SIZE)
        if not entries:
            _bg_stop.wait(timeout=_BATCH_WAIT_S)
            continue
        if client is None:
            try:
                client = init_client_fn()
                logger.debug("BG worker: client initialized lazily")
            except Exception:
                logger.warning("BG worker: client init failed, retry in 5s",
                               exc_info=True)
                _bg_stop.wait(timeout=5.0)
                continue
        # No batch coalescing delay — submit immediately to minimize latency
        try:
            client.log_batch(entries)
            persist_fn()
            _consume_queue(line_count)
            logger.debug("BG batch: %d entries submitted", len(entries))
        except Exception:
            logger.warning("BG batch submit failed (entries remain in queue)", exc_info=True)
            persist_fn()
            _bg_stop.wait(timeout=2.0)


def ensure_bg_worker(
    init_client_fn: Callable[[], Any],
    persist_fn: Callable[[], None],
) -> None:
    """Start the background worker thread if not already running."""
    global _bg_thread
    if _bg_thread is not None and _bg_thread.is_alive():
        return
    _bg_stop.clear()
    _bg_started.clear()
    _bg_thread = threading.Thread(
        target=_bg_worker, args=(init_client_fn, persist_fn),
        daemon=True, name="aegis-bg",
    )
    _bg_thread.start()
    _bg_started.wait(timeout=2.0)
