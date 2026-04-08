"""aegis.trace — @trace decorator and span context manager (TraceMixin).

Extracted from client.py to reduce god-file size. Mixed into AegisClient.
"""

from __future__ import annotations

import functools
import inspect
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from aegis.types import ActionType

from aegis.types import ActionStatus as _ActionStatus
from aegis.types import ActionType as _ActionType

F = TypeVar("F", bound=Callable[..., Any])


class TraceMixin:
    """Mixin providing the @trace decorator and span() context manager.

    Requires host class to provide:
      - _log(action_type, tool, input_data, output_data, ...)
      - log_error(tool, input_data, error, duration_ms, metadata)
      - log_decision(reasoning, confidence, input_data, metadata)
      - _lock (threading.RLock)
      - _action_stack (list[str])
    """

    def trace(
        self,
        action_type: str | ActionType = _ActionType.TOOL_CALL,
        tool_name: str | None = None,
        capture_output: bool = True,
        metadata: dict[str, str] | None = None,
    ) -> Callable[[F], F]:
        """
        Decorator that automatically logs function execution to Aegis.

        Usage:
            @client.trace()
            def search_database(query: str) -> list[dict]:
                return db.search(query)

            @client.trace(action_type="decision", tool_name="route_selector")
            def pick_next_action(state: dict) -> str:
                return "search" if state["needs_data"] else "respond"

        The decorator:
          1. Captures all function arguments as the input payload.
          2. Captures the return value as the output payload.
          3. Measures wall-clock execution time.
          4. Catches and re-raises exceptions (logging them as errors).
          5. Maintains parent-child relationships when traced functions
             call other traced functions.

        Args:
            action_type: The action type category. String or ActionType enum.
            tool_name: Override the tool name. Defaults to the function's
                       qualified name.
            capture_output: If False, output is logged as {} (useful for
                           functions returning sensitive data).
            metadata: Additional metadata for this specific trace.
        """
        if isinstance(action_type, str):
            action_type = _ActionType(action_type)

        def decorator(func: F) -> F:
            resolved_tool = tool_name or func.__qualname__

            def _build_input(func_: Any, args: Any, kwargs: Any) -> dict[str, Any]:
                sig = inspect.signature(func_)
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                return dict(bound.arguments)

            def _log_success(
                input_data: dict[str, Any], result: Any, elapsed: int,
            ) -> None:
                output_data = result if capture_output else {}
                self._log(  # type: ignore[attr-defined]
                    action_type=action_type,
                    tool=resolved_tool,
                    input_data=input_data,
                    output_data=output_data,
                    duration_ms=elapsed,
                    status=_ActionStatus.SUCCESS,
                    reasoning="",
                    confidence=0.0,
                    metadata=metadata,
                )

            def _log_failure(
                input_data: dict[str, Any], error: Exception, elapsed: int,
            ) -> None:
                self.log_error(  # type: ignore[attr-defined]
                    tool=resolved_tool,
                    input_data=input_data,
                    error=error,
                    duration_ms=elapsed,
                    metadata=metadata,
                )

            if inspect.iscoroutinefunction(func):
                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    input_data = _build_input(func, args, kwargs)
                    start_ms = int(time.time() * 1000)
                    try:
                        result = await func(*args, **kwargs)
                        _log_success(input_data, result, int(time.time() * 1000) - start_ms)
                        return result
                    except Exception as e:
                        _log_failure(input_data, e, int(time.time() * 1000) - start_ms)
                        raise

                return async_wrapper  # type: ignore[return-value]

            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                input_data = _build_input(func, args, kwargs)
                start_ms = int(time.time() * 1000)
                try:
                    result = func(*args, **kwargs)
                    _log_success(input_data, result, int(time.time() * 1000) - start_ms)
                    return result
                except Exception as e:
                    _log_failure(input_data, e, int(time.time() * 1000) - start_ms)
                    raise  # Always re-raise — we observe, never interfere

            return wrapper  # type: ignore[return-value]

        return decorator

    @contextmanager
    def span(
        self,
        name: str,
        action_type: ActionType = _ActionType.DECISION,
        reasoning: str = "",
        metadata: dict[str, str] | None = None,
    ) -> Generator[str, None, None]:
        """
        Context manager that groups nested actions under a parent.

        Usage:
            with client.span("process_order", reasoning="Customer checkout flow") as span_id:
                client.log_tool_call("inventory.check", ...)
                client.log_tool_call("payment.charge", ...)
                # Both calls have parent_action_id = span_id

        Yields the action_id of the span's own log entry.
        """
        action_id = self.log_decision(  # type: ignore[attr-defined]
            reasoning=reasoning or f"Entering span: {name}",
            confidence=1.0,
            input_data={"span_name": name},
            metadata=metadata,
        )

        with self._lock:  # type: ignore[attr-defined]
            self._action_stack.append(action_id)  # type: ignore[attr-defined]
        try:
            yield action_id
        finally:
            with self._lock:  # type: ignore[attr-defined]
                self._action_stack.pop()  # type: ignore[attr-defined]
