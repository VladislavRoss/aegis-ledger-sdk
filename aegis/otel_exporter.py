"""
aegis.otel_exporter — Export Aegis Traces as OpenTelemetry Spans.

Exports Aegis ledger entries to any OTLP-compatible backend (Jaeger,
Zipkin, Honeycomb, Grafana Tempo, etc.).

Usage::

    from aegis import AegisClient
    from aegis.otel_exporter import AegisOTelExporter

    client = AegisClient.from_config()
    exporter = AegisOTelExporter(client, endpoint="http://localhost:4318")
    exported = exporter.export_session("sess_abc123")
    print(f"Exported {exported} spans")
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

# Soft dependency — only needed if using the OTel SDK exporter
try:
    from opentelemetry.attributes import BoundedAttributes
    from opentelemetry.sdk.trace import ReadableSpan, SpanContext, TraceFlags
    from opentelemetry.trace import SpanKind, StatusCode

    OTTEL_AVAILABLE = True
except ImportError:
    OTTEL_AVAILABLE = False


class AegisOTelExporter:
    """Export Aegis ledger entries as OpenTelemetry spans.

    Supports two modes:
    1. **OTLP HTTP** — direct POST to any OTLP endpoint (no OTel SDK needed)
    2. **OTel SDK** — returns ReadableSpan objects for use with OTel exporters
    """

    def __init__(
        self,
        client: Any,
        endpoint: str = "http://localhost:4318/v1/traces",
        service_name: str = "aegis-ledger",
    ) -> None:
        self.client = client
        self.endpoint = endpoint.rstrip("/")
        self.service_name = service_name

    def export_session(
        self,
        session_id: str,
        *,
        use_otlp: bool = True,
    ) -> int:
        """Export all entries of a session as OTel spans.

        Args:
            session_id: The session to export.
            use_otlp: If True, send via OTLP HTTP. If False, return span dicts.

        Returns:
            Number of spans exported.
        """
        # Fetch session entries via client
        entries = self._get_session_entries(session_id)
        if not entries:
            logger.warning("No entries found for session %s", session_id)
            return 0

        spans = [self._entry_to_span(e) for e in entries]

        if use_otlp:
            return self._send_otlp(spans)
        return len(spans)

    def export_to_otlp(
        self,
        entries: list[dict[str, Any]],
    ) -> int:
        """Export raw entry dicts to OTLP endpoint.

        Args:
            entries: List of entry dicts (from get_trace or similar).

        Returns:
            Number of spans sent.
        """
        spans = [self._entry_to_span(e) for e in entries]
        return self._send_otlp(spans)

    def to_readable_spans(
        self,
        entries: list[dict[str, Any]],
    ) -> list:
        """Convert entries to OTel SDK ReadableSpan objects.

        Requires the ``opentelemetry-sdk`` package.

        Args:
            entries: List of entry dicts.

        Returns:
            List of ReadableSpan objects.
        """
        if not OTTEL_AVAILABLE:
            raise ImportError(
                "opentelemetry-sdk is required. Install with: pip install aegis-ledger-sdk[otel]"
            )
        return [self._entry_to_readable_span(e) for e in entries]

    # ── Internal ──────────────────────────────────────────────────────────

    def _get_session_entries(self, session_id: str) -> list[dict[str, Any]]:
        """Fetch all entries for a session from the canister."""
        try:
            result = self.client.transport.call(
                "getTrace",
                [session_id, [], []],  # sessionId, offset, limit
            )
            if result and "entries" in result:
                return result["entries"]
            return []
        except Exception as exc:
            logger.error("Failed to fetch session %s: %s", session_id, exc)
            return []

    def _entry_to_span(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Convert a single Aegis entry to an OTLP span dict."""
        action_type = self._get_action_type(entry)
        tool = entry.get("tool", "") or entry.get("actionId", "")[:32]
        duration_ns = int(entry.get("durationMs", 0)) * 1_000_000

        # Build OTel span
        span = {
            "traceId": self._hex_to_base64(entry.get("otelTraceId", "")),
            "spanId": self._hex_to_base64(entry.get("otelSpanId", "")),
            "parentSpanId": self._hex_to_base64(entry.get("otelParentSpanId", "")),
            "name": f"aegis.{action_type}.{tool}" if tool else f"aegis.{action_type}",
            "kind": self._action_to_span_kind(action_type),
            "startTimeUnixNano": str(self._start_time_ns(entry, duration_ns)),
            "endTimeUnixNano": str(self._end_time_ns(entry)),
            "attributes": self._build_attributes(entry),
            "status": self._build_status(entry),
        }

        # Generate traceId/spanId if not present
        if not span["traceId"]:
            import hashlib

            h = hashlib.sha256(entry["actionId"].encode()).hexdigest()
            span["traceId"] = self._hex_to_base64(h[:32])
        if not span["spanId"]:
            import hashlib

            h = hashlib.sha256(entry["actionId"].encode()).hexdigest()
            span["spanId"] = self._hex_to_base64(h[:16])

        return span

    def _entry_to_readable_span(self, entry: dict[str, Any]):
        """Convert entry to OTel SDK ReadableSpan (requires opentelemetry-sdk)."""
        action_type = self._get_action_type(entry)
        tool = entry.get("tool", "") or entry.get("actionId", "")[:32]
        duration_ns = int(entry.get("durationMs", 0)) * 1_000_000
        start_ns = self._start_time_ns(entry, duration_ns)
        end_ns = self._end_time_ns(entry)

        # Generate deterministic trace/span IDs from actionId
        import hashlib

        h = hashlib.sha256(entry["actionId"].encode()).hexdigest()
        trace_id = int(h[:32], 16) if entry.get("otelTraceId") else int(h[:32], 16)
        span_id = int(h[32:48], 16)

        ctx = SpanContext(
            trace_id=trace_id,
            span_id=span_id,
            is_remote=True,
            trace_flags=TraceFlags.SAMPLED,
        )

        attrs = self._build_attributes(entry)
        bounded = BoundedAttributes(
            max_len=128,
            attributes=attrs,
            immutable=False,
        )

        span = ReadableSpan(
            name=f"aegis.{action_type}.{tool}" if tool else f"aegis.{action_type}",
            context=ctx,
            parent=None,
            resource=None,  # Would need Resource SDK import
            kind=self._action_to_span_kind_otel(action_type),
            start_time=start_ns,
            end_time=end_ns,
            attributes=bounded,
            events=[],
            links=[],
            status=self._build_status_otel(entry),
        )
        return span

    def _send_otlp(self, spans: list[dict[str, Any]]) -> int:
        """Send spans to OTLP HTTP endpoint."""
        if not spans:
            return 0

        payload = json.dumps(
            {
                "resourceSpans": [
                    {
                        "resource": {
                            "attributes": [
                                {
                                    "key": "service.name",
                                    "value": {"stringValue": self.service_name},
                                },
                            ],
                        },
                        "scopeSpans": [
                            {
                                "scope": {"name": "aegis-ledger-sdk"},
                                "spans": spans,
                            }
                        ],
                    }
                ],
            }
        ).encode("utf-8")

        req = urllib.request.Request(
            self.endpoint,
            data=payload,
            headers={
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status == 200:
                    logger.info("Exported %d spans to %s", len(spans), self.endpoint)
                    return len(spans)
                logger.warning("OTLP returned %d: %s", resp.status, resp.read()[:200])
                return 0
        except urllib.error.HTTPError as exc:
            logger.error("OTLP HTTP error %d: %s", exc.code, exc.read()[:200])
            return 0
        except urllib.error.URLError as exc:
            logger.error("OTLP connection failed: %s", exc.reason)
            return 0

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _get_action_type(entry: dict[str, Any]) -> str:
        at = entry.get("actionType", {})
        if isinstance(at, dict):
            return next(iter(at), "unknown")
        return str(at)

    @staticmethod
    def _hex_to_base64(hex_str: str) -> str:
        """Convert hex string to base64 (OTLP format)."""
        import base64

        if not hex_str:
            return ""
        # Remove any prefix
        clean = hex_str.replace("0x", "")
        try:
            return base64.b64encode(bytes.fromhex(clean)).decode("ascii")
        except (ValueError, TypeError):
            return ""

    @staticmethod
    def _action_to_span_kind(action_type: str) -> int:
        """OTLP span kind: 1=INTERNAL, 2=SERVER, 3=CLIENT, 4=PRODUCER, 5=CONSUMER."""
        if action_type in ("toolCall", "observation"):
            return 3  # CLIENT
        if action_type == "error":
            return 1  # INTERNAL
        return 1  # INTERNAL

    @staticmethod
    def _action_to_span_kind_otel(action_type: str):
        """OTel SDK SpanKind enum value."""
        if not OTTEL_AVAILABLE:
            return SpanKind.INTERNAL
        if action_type in ("toolCall", "observation"):
            return SpanKind.CLIENT
        return SpanKind.INTERNAL

    @staticmethod
    def _start_time_ns(entry: dict[str, Any], duration_ns: int) -> int:
        """Calculate start time from server timestamp."""
        ts_ns = entry.get("serverTimestampNs", 0)
        if ts_ns:
            return int(ts_ns) - duration_ns
        # Fallback: use client timestamp
        ts_ms = entry.get("clientTimestampMs", 0)
        if ts_ms:
            return int(ts_ms) * 1_000_000 - duration_ns
        return 0

    @staticmethod
    def _end_time_ns(entry: dict[str, Any]) -> int:
        """Get end time from server timestamp."""
        ts_ns = entry.get("serverTimestampNs", 0)
        if ts_ns:
            return int(ts_ns)
        ts_ms = entry.get("clientTimestampMs", 0)
        if ts_ms:
            return int(ts_ms) * 1_000_000
        return 0

    @staticmethod
    def _build_attributes(entry: dict[str, Any]) -> dict[str, Any]:
        """Build OTel span attributes from Aegis entry."""
        attrs: dict[str, Any] = {
            "aegis.action_id": entry.get("actionId", ""),
            "aegis.session_id": entry.get("sessionId", ""),
            "aegis.agent_id": entry.get("agentId", ""),
            "aegis.action_type": AegisOTelExporter._get_action_type(entry),
            "aegis.sequence_number": int(entry.get("sequenceNumber", 0)),
        }

        tool = entry.get("tool")
        if tool:
            attrs["aegis.tool"] = tool

        status = entry.get("status", "")
        if status:
            attrs["aegis.status"] = status

        duration = entry.get("durationMs")
        if duration is not None:
            attrs["aegis.duration_ms"] = int(duration)

        model = entry.get("modelId")
        if model:
            attrs["aegis.model_id"] = model

        framework = entry.get("framework")
        if framework:
            attrs["aegis.framework"] = framework

        # OTel fields
        otel_trace = entry.get("otelTraceId")
        if otel_trace:
            attrs["aegis.otel_trace_id"] = otel_trace

        cost = entry.get("costUsd")
        if cost:
            attrs["aegis.cost_usd"] = float(cost)

        tokens = entry.get("tokenCount")
        if tokens is not None:
            attrs["aegis.token_count"] = int(tokens)

        # Input/Output previews
        inp = entry.get("inputPreview")
        if inp:
            attrs["aegis.input_preview"] = inp

        out = entry.get("outputPreview")
        if out:
            attrs["aegis.output_preview"] = out

        return attrs

    @staticmethod
    def _build_status(entry: dict[str, Any]) -> dict[str, Any]:
        """Build OTLP status object."""
        status = entry.get("status", "")
        if status == "error":
            return {"code": 2, "message": entry.get("status", "error")}  # ERROR
        return {"code": 1}  # OK

    @staticmethod
    def _build_status_otel(entry: dict[str, Any]):
        """Build OTel SDK Status object."""
        if not OTTEL_AVAILABLE:
            return None
        status = entry.get("status", "")
        if status == "error":
            return (StatusCode.ERROR, entry.get("status", "error"))
        return (StatusCode.OK, "")
