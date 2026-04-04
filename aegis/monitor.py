"""aegis.monitor — Health monitoring daemon for the Aegis Ledger.

Polls canister health at configurable intervals, checks thresholds,
triggers alerts, and auto-drains spill buffers.

Usage:
    aegis monitor                    # default 5min interval
    aegis monitor --interval 60      # every 60 seconds
    aegis monitor --once             # single check, exit
"""

from __future__ import annotations

import dataclasses
import logging
import os
import signal
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

from aegis.config import get_client_config, load_config
from aegis.integrity import HEALTH_HASH_MAP, map_candid_keys
from aegis.transport import CanisterTransport, TransportConfig

logger = logging.getLogger("aegis.monitor")

_PID_FILE = Path.home() / ".aegis" / "monitor.pid"

# Default thresholds — can be overridden via config.toml [monitor] section
_DEFAULT_CYCLES_WARN: int = 5_000_000_000_000      # 5 T
_DEFAULT_CYCLES_CRITICAL: int = 2_000_000_000_000  # 2 T
_DEFAULT_SPILL_WARN: int = 50
_DEFAULT_SPILL_CRITICAL: int = 200
_STALE_TIMER_WARN_H: float = 12.0  # hours


@dataclasses.dataclass
class HealthStatus:
    """Result of a single health check against the Aegis canister."""

    status: str          # "healthy" | "warning" | "critical"
    cycles: int
    entries: int
    sessions: int
    spill_pending: int
    timer_age_s: float
    api_version: str
    warnings: list[str]
    errors: list[str]
    timestamp: str


class HealthMonitor:
    """Periodically polls canister health, applies threshold rules, and alerts."""

    def __init__(
        self,
        config_path: str | Path | None = None,
        interval_s: int = 300,
        alert_handler: Callable[[HealthStatus], Any] | None = None,
    ) -> None:
        from pathlib import Path as _Path

        self._interval_s = max(1, interval_s)
        self._alert_handler = alert_handler
        self._stopped = False

        cfg = load_config(config_path=_Path(config_path) if config_path else None)
        client_cfg = get_client_config(cfg)
        monitor_cfg = cfg.get("monitor", {}) if isinstance(cfg.get("monitor"), dict) else {}

        # Resolve thresholds from config or defaults
        self._cycles_warn: int = int(
            monitor_cfg.get("cycles_warn", _DEFAULT_CYCLES_WARN)
        )
        self._cycles_critical: int = int(
            monitor_cfg.get("cycles_critical", _DEFAULT_CYCLES_CRITICAL)
        )
        self._spill_warn: int = int(
            monitor_cfg.get("spill_warn", _DEFAULT_SPILL_WARN)
        )
        self._spill_critical: int = int(
            monitor_cfg.get("spill_critical", _DEFAULT_SPILL_CRITICAL)
        )

        canister_id = client_cfg.get("canister_id", "")
        if not canister_id:
            raise ValueError(
                "No canister_id in config. Run 'aegis init' or set [client] canister_id."
            )

        pk_path = client_cfg.get("private_key_path")
        transport_config = TransportConfig(
            canister_id=canister_id,
            private_key_path=pk_path,
        )
        self._transport = CanisterTransport(transport_config)
        logger.info(
            "HealthMonitor initialized: canister=%s interval=%ds",
            canister_id,
            self._interval_s,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_health(self) -> HealthStatus:
        """Perform a single health check against the canister.

        Returns a HealthStatus dataclass with status, metrics, and alerts.
        """
        warnings: list[str] = []
        errors: list[str] = []
        now_ts = datetime.now(timezone.utc).isoformat()

        cycles = 0
        entries = 0
        sessions = 0
        api_version = ""
        timer_age_s = 0.0

        try:
            raw = self._transport.call_query("getHealth", [])
            health = map_candid_keys(raw, HEALTH_HASH_MAP) if isinstance(raw, dict) else {}

            # Unwrap Candid Opt fields (ic-py returns ?T as [value] or [])
            cycles = _unwrap_opt(health.get("cyclesBalance", 0), 0)
            entries = _unwrap_opt(health.get("totalEntries", 0), 0)
            sessions = _unwrap_opt(health.get("totalSessions", 0), 0)
            api_ver_raw = health.get("apiVersion")
            api_version = _unwrap_opt(api_ver_raw, "") if api_ver_raw is not None else ""

            # Timer check: lastTimerCheck is nanoseconds since epoch (optional field)
            last_timer_ns = _unwrap_opt(health.get("lastTimerCheck"), None)
            if last_timer_ns is not None:
                now_ns = int(time.time() * 1_000_000_000)
                timer_age_s = (now_ns - int(last_timer_ns)) / 1_000_000_000
                stale_threshold_s = _STALE_TIMER_WARN_H * 3600
                if timer_age_s > stale_threshold_s:
                    age_h = timer_age_s / 3600
                    warnings.append(
                        f"Timer stale: last check {age_h:.1f}h ago "
                        f"(threshold {_STALE_TIMER_WARN_H:.0f}h)"
                    )

        except Exception as exc:
            error_msg = f"Canister unreachable: {exc}"
            logger.error(error_msg)
            errors.append(error_msg)
            return HealthStatus(
                status="critical",
                cycles=0,
                entries=entries,
                sessions=sessions,
                spill_pending=self._transport.spill_count,
                timer_age_s=timer_age_s,
                api_version=api_version,
                warnings=warnings,
                errors=errors,
                timestamp=now_ts,
            )

        # Cycles threshold checks
        if cycles < self._cycles_critical:
            tc = self._cycles_critical / 1_000_000_000_000
            errors.append(
                f"CRITICAL: cycles balance {cycles / 1_000_000_000_000:.2f}T "
                f"below critical threshold {tc:.1f}T"
            )
        elif cycles < self._cycles_warn:
            tw = self._cycles_warn / 1_000_000_000_000
            warnings.append(
                f"Cycles balance {cycles / 1_000_000_000_000:.2f}T "
                f"below warning threshold {tw:.1f}T"
            )

        # Spill queue depth checks
        spill_pending = self._transport.spill_count
        if spill_pending >= self._spill_critical:
            errors.append(
                f"CRITICAL: spill queue {spill_pending} entries "
                f">= critical threshold {self._spill_critical}"
            )
        elif spill_pending >= self._spill_warn:
            warnings.append(
                f"Spill queue {spill_pending} entries "
                f">= warning threshold {self._spill_warn}"
            )

        # Determine overall status
        if errors:
            status = "critical"
        elif warnings:
            status = "warning"
        else:
            status = "healthy"

        hs = HealthStatus(
            status=status,
            cycles=cycles,
            entries=entries,
            sessions=sessions,
            spill_pending=spill_pending,
            timer_age_s=timer_age_s,
            api_version=api_version,
            warnings=warnings,
            errors=errors,
            timestamp=now_ts,
        )
        logger.info(
            "Health check: status=%s cycles=%.2fT entries=%d sessions=%d spill=%d",
            status,
            cycles / 1_000_000_000_000,
            entries,
            sessions,
            spill_pending,
        )
        return hs

    def run(self) -> None:
        """Start the long-running monitoring loop.

        Writes a PID file to ~/.aegis/monitor.pid on start and removes it on exit.
        Installs SIGTERM/SIGINT handlers for graceful shutdown.
        """
        self._stopped = False
        self._install_signal_handlers()
        self._write_pid_file()

        logger.info(
            "Health monitor started (interval=%ds). PID=%d. "
            "Send SIGTERM/SIGINT to stop.",
            self._interval_s,
            os.getpid(),
        )

        try:
            while not self._stopped:
                try:
                    status = self.check_health()

                    if status.status in ("warning", "critical") and self._alert_handler:
                        try:
                            self._alert_handler(status)
                        except Exception as exc:
                            logger.warning("Alert handler failed: %s", exc)

                    # Auto-drain spill buffer after each check
                    try:
                        drained = self._transport.drain_spill_buffer()
                        if drained > 0:
                            logger.info("Auto-drained %d spilled entries", drained)
                    except Exception as exc:
                        logger.warning("Spill drain failed: %s", exc)

                except Exception as exc:
                    logger.error("Health check loop error: %s", exc)

                # Interruptible sleep: check _stopped flag every second
                for _ in range(self._interval_s):
                    if self._stopped:
                        break
                    time.sleep(1)

        finally:
            self._remove_pid_file()
            logger.info("Health monitor stopped.")

    def stop(self) -> None:
        """Signal the monitoring loop to exit gracefully."""
        self._stopped = True
        logger.info("Health monitor stop requested.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _install_signal_handlers(self) -> None:
        """Install SIGTERM and SIGINT handlers for graceful shutdown."""
        def _handler(signum: int, frame: Any) -> None:
            logger.info("Received signal %d — stopping monitor.", signum)
            self.stop()

        try:
            signal.signal(signal.SIGTERM, _handler)
            signal.signal(signal.SIGINT, _handler)
        except (OSError, ValueError):
            # May fail in non-main threads or restricted environments
            logger.warning("Could not install signal handlers.")

    def _write_pid_file(self) -> None:
        """Write current PID to ~/.aegis/monitor.pid."""
        try:
            _PID_FILE.parent.mkdir(parents=True, exist_ok=True)
            _PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
        except OSError as exc:
            logger.warning("Could not write PID file: %s", exc)

    def _remove_pid_file(self) -> None:
        """Remove PID file on clean shutdown."""
        try:
            _PID_FILE.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning("Could not remove PID file: %s", exc)


# ------------------------------------------------------------------
# Module-level helper
# ------------------------------------------------------------------

def _unwrap_opt(value: Any, default: Any) -> Any:
    """Unwrap Candid Opt: ic-py returns ?T as [value] or [] — extract first or default."""
    if isinstance(value, list):
        return value[0] if value else default
    return value if value is not None else default
