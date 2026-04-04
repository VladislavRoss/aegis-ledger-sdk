"""aegis.alerting — Webhook-based alerting for health monitor."""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.monitor import HealthStatus

logger = logging.getLogger("aegis.alerting")


class WebhookAlerter:
    """Sends Slack-compatible webhook alerts with cooldown-based deduplication."""

    def __init__(self, webhook_url: str, cooldown_s: int = 300) -> None:
        if not webhook_url or not webhook_url.strip():
            raise ValueError("webhook_url must not be empty")
        self._webhook_url = webhook_url
        self._cooldown_s = max(0, cooldown_s)
        self._last_alert_ts: float = 0.0
        self._last_alert_key: str = ""

    def send_alert(self, status: HealthStatus) -> bool:
        """Send a webhook alert for the given HealthStatus.

        Deduplicates: if the same status+warnings were sent within cooldown_s,
        the alert is skipped and False is returned.

        Returns True if the alert was sent, False if skipped or failed.
        """
        import httpx

        alert_key = f"{status.status}|{','.join(sorted(status.warnings + status.errors))}"
        now = time.monotonic()

        if alert_key == self._last_alert_key and (now - self._last_alert_ts) < self._cooldown_s:
            logger.debug(
                "Alert suppressed (cooldown %ds not elapsed). key=%s",
                self._cooldown_s,
                alert_key[:80],
            )
            return False

        payload = self._build_payload(status)

        try:
            resp = httpx.post(self._webhook_url, json=payload, timeout=10.0)
            resp.raise_for_status()
            self._last_alert_ts = now
            self._last_alert_key = alert_key
            logger.info(
                "Alert sent: status=%s http=%d",
                status.status,
                resp.status_code,
            )
            return True
        except Exception as exc:
            logger.warning("Webhook alert failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_payload(self, status: HealthStatus) -> dict[str, Any]:
        """Build a Slack-compatible Block Kit payload."""
        level_emoji = {"healthy": "green_circle", "warning": "warning", "critical": "red_circle"}
        emoji = level_emoji.get(status.status, "white_circle")

        cycles_t = status.cycles / 1_000_000_000_000 if status.cycles else 0.0
        detail_lines = [
            f"*Status:* :{emoji}: `{status.status.upper()}`",
            f"*Cycles:* {cycles_t:.2f}T",
            f"*Entries:* {status.entries:,}",
            f"*Sessions:* {status.sessions:,}",
            f"*Spill pending:* {status.spill_pending}",
            f"*Timestamp:* {status.timestamp}",
        ]

        if status.warnings:
            detail_lines.append("*Warnings:*")
            for w in status.warnings:
                detail_lines.append(f"  • {w}")

        if status.errors:
            detail_lines.append("*Errors:*")
            for e in status.errors:
                detail_lines.append(f"  • {e}")

        if status.api_version:
            detail_lines.append(f"*API version:* {status.api_version}")

        return {
            "text": f"Aegis Health Alert: {status.status.upper()}",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "Aegis Health Alert",
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "\n".join(detail_lines),
                    },
                },
            ],
        }


def create_alerter(config: dict[str, Any]) -> WebhookAlerter | None:
    """Create a WebhookAlerter from an alerting config dict.

    Reads keys:
        webhook_url  (required — if absent, returns None)
        cooldown_s   (optional, default 300)

    Returns None if no webhook_url is configured.
    """
    if not isinstance(config, dict):
        return None

    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return None

    cooldown_s = int(config.get("cooldown_s", 300))
    return WebhookAlerter(webhook_url=webhook_url, cooldown_s=cooldown_s)
