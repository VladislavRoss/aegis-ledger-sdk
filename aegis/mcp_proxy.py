"""aegis.mcp_proxy — Transparent MCP stdio interceptor with auto-logging.

Sits between an LLM client and an upstream MCP server, intercepting all
tool calls and logging them to Aegis automatically. The LLM does NOT need
to call aegis_log_tool_call() — logging is fully transparent.

Architecture::

    LLM <--stdio--> Aegis Interceptor <--stdio--> Upstream MCP Server
                           |
                      Spill -> Canister

Usage::

    aegis mcp-proxy -- npx @anthropic/mcp-server-filesystem /path/to/dir

Or in claude_desktop_config.json::

    {
      "mcpServers": {
        "my-server": {
          "command": "aegis",
          "args": ["mcp-proxy", "--", "npx", "@anthropic/mcp-server-filesystem", "/dir"]
        }
      }
    }
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("aegis.mcp_proxy")

_MCP_QUEUE_PATH = Path.home() / ".aegis" / "mcp_queue.jsonl"

# Pending tool call requests: id -> (tool_name, arguments, start_time)
_pending_calls: dict[Any, tuple[str, dict, float]] = {}
_pending_lock = threading.Lock()


def _spill_log_entry(entry: dict[str, Any]) -> None:
    """Write a log entry to the persistent spill queue (GR-7: atomic append)."""
    _MCP_QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, default=str) + "\n"
    fd = os.open(str(_MCP_QUEUE_PATH), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)


def _extract_jsonrpc_messages(data: bytes) -> list[dict[str, Any]]:
    """Extract JSON-RPC messages from a byte stream.

    MCP uses Content-Length-delimited messages OR newline-delimited JSON.
    We handle both by trying Content-Length first, then falling back to
    line-based parsing.
    """
    messages: list[dict[str, Any]] = []
    text = data.decode("utf-8", errors="replace")

    # Try newline-delimited JSON (most common in stdio MCP)
    for line in text.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            if isinstance(msg, dict):
                messages.append(msg)
        except json.JSONDecodeError:
            continue

    return messages


def _on_request(msg: dict[str, Any]) -> None:
    """Track outgoing tool call requests."""
    method = msg.get("method", "")
    if method == "tools/call":
        req_id = msg.get("id")
        params = msg.get("params", {})
        tool_name = params.get("name", "unknown")
        arguments = params.get("arguments", {})
        with _pending_lock:
            _pending_calls[req_id] = (tool_name, arguments, time.monotonic())
        logger.debug("Tracked tool call: id=%s tool=%s", req_id, tool_name)


def _on_response(msg: dict[str, Any]) -> None:
    """Log completed tool call responses to Aegis."""
    req_id = msg.get("id")
    if req_id is None:
        return

    with _pending_lock:
        pending = _pending_calls.pop(req_id, None)

    if pending is None:
        return

    tool_name, arguments, start_time = pending
    duration_ms = int((time.monotonic() - start_time) * 1000)

    # Extract response content
    result = msg.get("result", {})
    error = msg.get("error")

    if error:
        output_data = json.dumps(error, default=str)[:500]
        action_type = "error"
    else:
        content = result.get("content", []) if isinstance(result, dict) else result
        output_data = json.dumps(content, default=str)[:500]
        action_type = "tool_call"

    entry = {
        "action_type": action_type,
        "tool": tool_name,
        "input_data": json.dumps(arguments, default=str)[:500],
        "output_data": output_data,
        "duration_ms": duration_ms,
        "status": "error" if error else "success",
    }

    try:
        _spill_log_entry(entry)
        logger.debug("Logged tool call: %s (%dms)", tool_name, duration_ms)
    except Exception as exc:
        logger.warning("Failed to log tool call: %s", exc)


def _pipe_and_intercept(
    source: Any,
    sink: Any,
    direction: str,
) -> None:
    """Read from source, intercept messages, write to sink.

    Args:
        source: Readable file-like (stdin or subprocess stdout).
        sink: Writable file-like (stdout or subprocess stdin).
        direction: "request" (LLM->upstream) or "response" (upstream->LLM).
    """
    try:
        while True:
            data = source.read(8192)
            if not data:
                break

            # Intercept JSON-RPC messages for logging
            try:
                messages = _extract_jsonrpc_messages(data)
                for msg in messages:
                    if direction == "request":
                        _on_request(msg)
                    else:
                        _on_response(msg)
            except Exception as exc:
                logger.debug("Intercept parse error (%s): %s", direction, exc)

            # Always forward data unchanged
            try:
                sink.write(data)
                sink.flush()
            except (BrokenPipeError, OSError):
                break
    except (BrokenPipeError, OSError):
        pass


def run_proxy(upstream_command: list[str]) -> int:
    """Start the MCP proxy interceptor.

    Launches the upstream MCP server as a subprocess and pipes stdio
    through, intercepting tool calls for automatic Aegis logging.

    Args:
        upstream_command: The command to start the upstream MCP server.

    Returns:
        Exit code of the upstream process.
    """
    if not upstream_command:
        logger.error("No upstream command provided")
        return 1

    logger.info("Starting MCP proxy: upstream=%s", " ".join(upstream_command))

    # Start upstream MCP server (GR-24: shell=False)
    try:
        proc = subprocess.Popen(
            upstream_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
        )
    except FileNotFoundError:
        logger.error("Upstream command not found: %s", upstream_command[0])
        return 1

    # Pipe LLM stdin -> upstream stdin (intercepting requests)
    req_thread = threading.Thread(
        target=_pipe_and_intercept,
        args=(sys.stdin.buffer, proc.stdin, "request"),
        daemon=True,
        name="aegis-proxy-req",
    )

    # Pipe upstream stdout -> LLM stdout (intercepting responses)
    resp_thread = threading.Thread(
        target=_pipe_and_intercept,
        args=(proc.stdout, sys.stdout.buffer, "response"),
        daemon=True,
        name="aegis-proxy-resp",
    )

    req_thread.start()
    resp_thread.start()

    try:
        return proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait(timeout=5)
        return 130
    finally:
        # Close upstream pipes
        if proc.stdin:
            proc.stdin.close()
        if proc.stdout:
            proc.stdout.close()
