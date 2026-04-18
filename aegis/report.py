"""
aegis.report -- Compliance report generator for audit evidence.

Generates Markdown reports from canister data, proving regulatory compliance.

Usage:
    # CLI:
    aegis report <canister_id> --format eu-ai-act
    aegis report <canister_id> --format iso-42001
    aegis report <canister_id> --format aiuc-1
    aegis report <canister_id> --format all

    # Python API:
    from aegis.report import generate_report, ReportFormat

    report = generate_report(
        canister_id="toqqq-lqaaa-aaaae-afc2a-cai",
        format=ReportFormat.EU_AI_ACT,
    )
    print(report.markdown)
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from aegis import __version__

logger = logging.getLogger("aegis.report")

SDK_VERSION = __version__


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


class ReportFormat(enum.Enum):
    """Supported compliance report frameworks."""

    EU_AI_ACT = "eu-ai-act"
    ISO_42001 = "iso-42001"
    AIUC_1 = "aiuc-1"


@dataclass(frozen=True, slots=True)
class ReportSummary:
    """Quick summary stats for the report."""

    total_actions: int
    total_sessions: int
    total_agents: int
    chain_intact: bool
    coverage_start: str  # ISO 8601
    coverage_end: str  # ISO 8601
    compliance_score: float  # 0.0 - 1.0


@dataclass
class ComplianceReport:
    """A generated compliance report."""

    format: ReportFormat
    canister_id: str
    generated_at: str  # ISO 8601
    markdown: str
    summary: ReportSummary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pass_fail(condition: bool) -> str:
    """Return a Markdown pass/fail indicator."""
    return "[PASS]" if condition else "[FAIL]"


def _compute_compliance_score(
    stats: dict[str, Any],
    health: dict[str, Any],
) -> float:
    """
    Compute a 0.0-1.0 compliance score from canister data.

    Scoring criteria (equal weight, 5 categories = 0.2 each):
      1. Logging active (total_actions > 0)
      2. Chain integrity (chain_valid from health)
      3. Agent monitoring (total_agents > 0)
      4. Session tracking (total_sessions > 0)
      5. API key management (active_api_keys > 0)
    """
    score = 0.0

    if stats.get("total_actions", 0) > 0:
        score += 0.2
    if health.get("chain_valid", False):
        score += 0.2
    if stats.get("total_agents", 0) > 0:
        score += 0.2
    if stats.get("total_sessions", 0) > 0:
        score += 0.2
    if stats.get("active_api_keys", 0) > 0:
        score += 0.2

    return round(score, 2)


def _build_summary(
    stats: dict[str, Any],
    health: dict[str, Any],
    generated_at: str,
) -> ReportSummary:
    """Build a ReportSummary from raw canister data."""
    total_actions = stats.get("total_actions", 0)
    total_sessions = stats.get("total_sessions", 0)
    total_agents = stats.get("total_agents", 0)
    chain_intact = bool(health.get("chain_valid", False))
    score = _compute_compliance_score(stats, health)

    # Coverage period: use provided timestamps or default to generated_at
    coverage_start = stats.get("coverage_start", generated_at)
    coverage_end = stats.get("coverage_end", generated_at)

    return ReportSummary(
        total_actions=total_actions,
        total_sessions=total_sessions,
        total_agents=total_agents,
        chain_intact=chain_intact,
        coverage_start=coverage_start,
        coverage_end=coverage_end,
        compliance_score=score,
    )


class ReportGenerationError(Exception):
    """Raised when report generation fails due to canister communication issues."""


def _fetch_canister_data(
    canister_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Fetch stats and health from a live canister via getHealth endpoint."""
    from aegis.config import load_config
    from aegis.transport import CanisterTransport, TransportConfig

    # Read config for private_key_path (needed for authenticated queries)
    cfg = load_config()
    pk_path = cfg.get("private_key_path")

    try:
        config = TransportConfig(canister_id=canister_id, private_key_path=pk_path)
        transport = CanisterTransport(config)

        raw = transport.call_query("getHealth", [])
    except Exception as exc:
        raise ReportGenerationError(
            f"Failed to fetch canister data from {canister_id}: {exc}"
        ) from exc

    # ic-py returns Candid field hashes instead of names.
    # Map known hashes to field names for HealthInfo record.
    health_hash_map = {
        "_576569836": "totalEntries",
        "_1673630680": "totalKeys",
        "_1718631411": "totalOrgs",
        "_492408735": "heapBytes",
        "_3726629775": "cyclesBalance",
        "_4170640857": "deferredVerifications",
    }

    mapped: dict[str, Any] = {}
    raw_dict = raw.get("raw", raw) if isinstance(raw, dict) else raw
    if isinstance(raw_dict, dict):
        for k, v in raw_dict.items():
            name = health_hash_map.get(str(k), str(k))
            mapped[name] = v

    total_entries = mapped.get("totalEntries", 0)
    total_keys = mapped.get("totalKeys", 0)
    total_orgs = mapped.get("totalOrgs", 0)
    deferred = mapped.get("deferredVerifications", 0)
    if isinstance(deferred, list):
        deferred = deferred[0] if deferred else 0
    if not isinstance(deferred, int):
        deferred = 0

    generated_at = _now_iso()
    stats: dict[str, Any] = {
        "total_actions": total_entries,
        "chain_length": total_entries,
        "active_api_keys": total_keys,
        "total_agents": total_orgs,
        "total_sessions": 0,
        "revoked_api_keys": 0,
        "latest_chain_hash": "N/A",
        "coverage_start": generated_at,
        "coverage_end": generated_at,
        "deferred_verifications": deferred,
    }
    # M-4 FIX: chain_valid now requires zero deferred signature verifications
    # in addition to entries existing. True end-to-end integrity still requires
    # AegisClient.verify_integrity() — this report surfaces the canister's own
    # deferred-queue signal rather than trivially returning True for any entry.
    health: dict[str, Any] = {
        "chain_valid": total_entries > 0 and deferred == 0,
        "status": "healthy" if deferred == 0 else "degraded",
        "uptime_seconds": 0,
    }
    return stats, health


# Builders extracted to report_builders.py



# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_report(
    canister_id: str,
    format: ReportFormat = ReportFormat.EU_AI_ACT,
    output_path: str = "",
    *,
    stats: dict[str, Any] | None = None,
    health: dict[str, Any] | None = None,
) -> ComplianceReport:
    """
    Generate a compliance report from canister data.

    Args:
        canister_id: The ICP canister ID to report on.
        format: Which compliance framework to generate for.
        output_path: If non-empty, write the Markdown to this file path.
        stats: Pre-fetched org stats dict (for testing / offline use).
        health: Pre-fetched health dict (for testing / offline use).

    Returns:
        A ComplianceReport with the generated Markdown and summary.
    """
    if not isinstance(format, ReportFormat):
        raise ValueError(
            f"format must be a ReportFormat enum, got {type(format).__name__}. "
            f"Valid values: {[f.value for f in ReportFormat]}"
        )

    # Fetch data from canister if not provided
    if stats is None or health is None:
        fetched_stats, fetched_health = _fetch_canister_data(canister_id)
        if stats is None:
            stats = fetched_stats
        if health is None:
            health = fetched_health

    generated_at = _now_iso()
    summary = _build_summary(stats, health, generated_at)

    from aegis.report_builders import BUILDERS
    builder = BUILDERS[format]
    markdown = builder(canister_id, generated_at, summary, stats, health)

    report = ComplianceReport(
        format=format,
        canister_id=canister_id,
        generated_at=generated_at,
        markdown=markdown,
        summary=summary,
    )

    if output_path:
        from pathlib import Path

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown, encoding="utf-8")
        logger.info("Report written to %s", out)

    return report


def generate_pdf(
    report: ComplianceReport,
    output_path: str,
) -> str:
    """
    Export a ComplianceReport to a verifiable PDF (ISO 32000).

    Requires the ``pdf`` extra: ``pip install aegis-ledger-sdk[pdf]``

    Args:
        report: A previously generated ComplianceReport.
        output_path: File path for the PDF output.

    Returns:
        The absolute path of the written PDF file.
    """
    try:
        from fpdf import FPDF  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError(
            "PDF export requires fpdf2. Install with: pip install aegis-ledger-sdk[pdf]"
        ) from exc

    from pathlib import Path

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # --- Metadata (ISO 32000 document info) ---
    pdf.set_title(f"Aegis Compliance Report — {report.format.value.upper()}")
    pdf.set_author("aegis-ledger-sdk")
    pdf.set_subject(f"Compliance report for canister {report.canister_id}")
    pdf.set_creator(f"aegis-ledger-sdk v{SDK_VERSION}")
    pdf.set_creation_date(
        datetime.strptime(report.generated_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    )

    # --- Render Markdown as structured PDF ---
    line_height = 5
    for line in report.markdown.splitlines():
        stripped = line.strip()

        # Headings
        if stripped.startswith("# "):
            pdf.set_font("Helvetica", "B", 16)
            pdf.cell(0, 10, stripped[2:], new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
        elif stripped.startswith("## "):
            pdf.set_font("Helvetica", "B", 13)
            pdf.cell(0, 8, stripped[3:], new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)
        elif stripped.startswith("### "):
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 7, stripped[4:], new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)
        elif stripped.startswith("---"):
            pdf.ln(2)
            pdf.set_draw_color(180, 180, 180)
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
            pdf.ln(4)
        elif stripped.startswith("|") and "---|" in stripped:
            # Table separator row — skip
            continue
        elif stripped.startswith("|"):
            # Table row
            pdf.set_font("Courier", "", 8)
            # Clean markdown table formatting
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            text = "  |  ".join(cells)
            pdf.cell(0, line_height, text, new_x="LMARGIN", new_y="NEXT")
        elif stripped.startswith("- "):
            pdf.set_font("Helvetica", "", 9)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, line_height, "  " + stripped[2:])
        elif stripped.startswith("```"):
            continue
        elif stripped.startswith("**") and stripped.endswith("**"):
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, line_height, stripped.strip("*"))
        elif stripped == "":
            pdf.ln(3)
        else:
            pdf.set_font("Helvetica", "", 9)
            clean = stripped.replace("**", "").replace("`", "")
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, line_height, clean)

    # --- Footer on every page ---
    pdf.set_font("Helvetica", "I", 7)
    pdf.set_y(-15)
    pdf.cell(
        0, 10,
        f"Generated by aegis-ledger-sdk v{SDK_VERSION} | {report.generated_at}",
        align="C",
    )

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(out))
    logger.info("PDF report written to %s", out)
    return str(out.resolve())


def generate_all_reports(
    canister_id: str,
    output_dir: str = "",
    *,
    stats: dict[str, Any] | None = None,
    health: dict[str, Any] | None = None,
) -> list[ComplianceReport]:
    """
    Generate compliance reports for all supported frameworks.

    Args:
        canister_id: The ICP canister ID to report on.
        output_dir: If non-empty, write each report to this directory.
        stats: Pre-fetched org stats dict (for testing / offline use).
        health: Pre-fetched health dict (for testing / offline use).

    Returns:
        A list of ComplianceReport objects, one per framework.
    """
    # Fetch once, share across all reports
    if stats is None or health is None:
        fetched_stats, fetched_health = _fetch_canister_data(canister_id)
        if stats is None:
            stats = fetched_stats
        if health is None:
            health = fetched_health

    reports: list[ComplianceReport] = []
    for fmt in ReportFormat:
        output_path = ""
        if output_dir:
            from pathlib import Path

            output_path = str(Path(output_dir) / f"aegis-{fmt.value}-report.md")

        report = generate_report(
            canister_id=canister_id,
            format=fmt,
            output_path=output_path,
            stats=stats,
            health=health,
        )
        reports.append(report)

    return reports
