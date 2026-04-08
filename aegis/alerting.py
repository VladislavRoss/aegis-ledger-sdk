"""aegis.alerting — Multi-channel alerting for health monitor.

Supported channels:
    - Webhook (Slack-compatible)
    - Telegram Bot
    - Email (SMTP)
"""

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


class TelegramAlerter:
    """Sends alerts via Telegram Bot API with cooldown deduplication."""

    def __init__(self, bot_token: str, chat_id: str, cooldown_s: int = 300) -> None:
        if not bot_token or not chat_id:
            raise ValueError("bot_token and chat_id must not be empty")
        self._bot_token = bot_token
        self._chat_id = chat_id
        self._cooldown_s = max(0, cooldown_s)
        self._last_alert_ts: float = 0.0
        self._last_alert_key: str = ""

    def send_alert(self, status: HealthStatus) -> bool:
        import httpx

        alert_key = f"{status.status}|{','.join(sorted(status.warnings + status.errors))}"
        now = time.monotonic()

        if alert_key == self._last_alert_key and (now - self._last_alert_ts) < self._cooldown_s:
            return False

        text = self._format_message(status)
        url = f"https://api.telegram.org/bot{self._bot_token}/sendMessage"

        try:
            resp = httpx.post(url, json={
                "chat_id": self._chat_id,
                "text": text,
                "parse_mode": "HTML",
            }, timeout=10.0)
            resp.raise_for_status()
            self._last_alert_ts = now
            self._last_alert_key = alert_key
            logger.info("Telegram alert sent: status=%s", status.status)
            return True
        except Exception as exc:
            logger.warning("Telegram alert failed: %s", exc)
            return False

    @staticmethod
    def _format_message(status: HealthStatus) -> str:
        emoji = {"healthy": "\u2705", "warning": "\u26A0\uFE0F", "critical": "\u274C"}
        e = emoji.get(status.status, "\u2753")
        cycles_t = status.cycles / 1_000_000_000_000 if status.cycles else 0.0

        lines = [
            f"{e} <b>Aegis Health: {status.status.upper()}</b>",
            f"Cycles: <code>{cycles_t:.2f}T</code>",
            f"Entries: {status.entries:,} | Sessions: {status.sessions:,}",
            f"Spill: {status.spill_pending} | {status.timestamp}",
        ]
        for w in status.warnings:
            lines.append(f"\u26A0 {w}")
        for err in status.errors:
            lines.append(f"\u274C {err}")
        return "\n".join(lines)


class EmailAlerter:
    """Sends alerts via SMTP with cooldown deduplication."""

    def __init__(
        self, smtp_host: str, smtp_port: int, username: str,
        password: str, sender: str, recipient: str,
        cooldown_s: int = 300, use_tls: bool = True,
    ) -> None:
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port
        self._username = username
        self._password = password
        self._sender = sender
        self._recipient = recipient
        self._use_tls = use_tls
        self._cooldown_s = max(0, cooldown_s)
        self._last_alert_ts: float = 0.0
        self._last_alert_key: str = ""

    def send_alert(self, status: HealthStatus) -> bool:
        import smtplib
        from email.mime.text import MIMEText

        alert_key = f"{status.status}|{','.join(sorted(status.warnings + status.errors))}"
        now = time.monotonic()

        if alert_key == self._last_alert_key and (now - self._last_alert_ts) < self._cooldown_s:
            return False

        subject = f"Aegis Health Alert: {status.status.upper()}"
        body = self._format_body(status)
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = self._sender
        msg["To"] = self._recipient

        try:
            if self._use_tls:
                server = smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=10)
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(self._smtp_host, self._smtp_port, timeout=10)
            server.login(self._username, self._password)
            server.sendmail(self._sender, [self._recipient], msg.as_string())
            server.quit()
            self._last_alert_ts = now
            self._last_alert_key = alert_key
            logger.info("Email alert sent: status=%s to=%s", status.status, self._recipient)
            return True
        except Exception as exc:
            logger.warning("Email alert failed: %s", exc)
            return False

    @staticmethod
    def _format_body(status: HealthStatus) -> str:
        cycles_t = status.cycles / 1_000_000_000_000 if status.cycles else 0.0
        lines = [
            f"Status:   {status.status.upper()}",
            f"Cycles:   {cycles_t:.2f}T",
            f"Entries:  {status.entries:,}",
            f"Sessions: {status.sessions:,}",
            f"Spill:    {status.spill_pending}",
            f"Time:     {status.timestamp}",
            "",
        ]
        for w in status.warnings:
            lines.append(f"  WARNING: {w}")
        for err in status.errors:
            lines.append(f"  ERROR:   {err}")
        return "\n".join(lines)


class MultiAlerter:
    """Dispatches alerts to multiple channels."""

    def __init__(self) -> None:
        self._alerters: list[WebhookAlerter | TelegramAlerter | EmailAlerter] = []

    def add(self, alerter: WebhookAlerter | TelegramAlerter | EmailAlerter) -> None:
        self._alerters.append(alerter)

    def send_alert(self, status: HealthStatus) -> bool:
        sent = False
        for alerter in self._alerters:
            try:
                if alerter.send_alert(status):
                    sent = True
            except Exception as exc:
                logger.warning("Alerter %s failed: %s", type(alerter).__name__, exc)
        return sent

    def __len__(self) -> int:
        return len(self._alerters)


def create_alerter(config: dict[str, Any]) -> MultiAlerter | None:
    """Create alerter(s) from config dict.

    Reads keys:
        webhook_url    → WebhookAlerter (Slack)
        telegram_token + telegram_chat_id → TelegramAlerter
        email_smtp_host + email_recipient → EmailAlerter
        cooldown_s     (optional, default 300, shared)
    """
    if not isinstance(config, dict):
        return None

    multi = MultiAlerter()
    cooldown_s = int(config.get("cooldown_s", 300))

    # Webhook (Slack)
    webhook_url = config.get("webhook_url", "")
    if webhook_url:
        multi.add(WebhookAlerter(webhook_url=webhook_url, cooldown_s=cooldown_s))

    # Telegram
    tg_token = config.get("telegram_token", "")
    tg_chat = config.get("telegram_chat_id", "")
    if tg_token and tg_chat:
        multi.add(TelegramAlerter(bot_token=tg_token, chat_id=tg_chat, cooldown_s=cooldown_s))

    # Email
    smtp_host = config.get("email_smtp_host", "")
    recipient = config.get("email_recipient", "")
    if smtp_host and recipient:
        multi.add(EmailAlerter(
            smtp_host=smtp_host,
            smtp_port=int(config.get("email_smtp_port", 587)),
            username=config.get("email_username", ""),
            password=config.get("email_password", ""),
            sender=config.get("email_sender", config.get("email_username", "")),
            recipient=recipient,
            cooldown_s=cooldown_s,
            use_tls=config.get("email_use_tls", True),
        ))

    return multi if len(multi) > 0 else None
