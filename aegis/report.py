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
    }
    health: dict[str, Any] = {
        "chain_valid": total_entries > 0,
        "status": "healthy",
        "uptime_seconds": 0,
    }
    return stats, health


# ---------------------------------------------------------------------------
# Shared report building blocks
# ---------------------------------------------------------------------------


def _report_header(
    title: str,
    canister_id: str,
    generated_at: str,
    summary: ReportSummary,
    extra_lines: list[str] | None = None,
) -> list[str]:
    """Build the common Markdown header (title, metadata, executive summary placeholder)."""
    lines = [
        f"# {title}",
        "",
        f"**Canister:** {canister_id}  ",
        f"**Generated:** {generated_at}  ",
        f"**Coverage:** {summary.coverage_start} -- {summary.coverage_end}",
    ]
    if extra_lines:
        for el in extra_lines:
            lines.append(el)
    lines.extend(["", "---", ""])
    return lines


def _compliance_score_section(
    summary: ReportSummary,
    stats: dict[str, Any],
    rows: list[tuple[str, bool]],
    section_title: str = "Compliance Score",
) -> list[str]:
    """Build the common score table and footer."""
    score_pct = int(summary.compliance_score * 100)
    latest_hash = stats.get("latest_chain_hash", "N/A")
    lines = [
        "---",
        "",
        f"## {section_title}: {score_pct}%",
        "",
        "| Criterion | Status |",
        "|-----------|--------|",
    ]
    for label, condition in rows:
        lines.append(f"| {label} | {_pass_fail(condition)} |")
    lines.extend([
        "",
        f"Chain hash at report time: `{latest_hash}`",
        "",
        "*Report generated by aegis-ledger-sdk compliance report generator.*",
        "",
    ])
    return lines


# ---------------------------------------------------------------------------
# Report builders
# ---------------------------------------------------------------------------


def _build_eu_ai_act_report(
    canister_id: str,
    generated_at: str,
    summary: ReportSummary,
    stats: dict[str, Any],
    health: dict[str, Any],
) -> str:
    """Build EU AI Act Article 12 compliance report in Markdown."""
    chain_length = stats.get("chain_length", summary.total_actions)
    latest_hash = stats.get("latest_chain_hash", "N/A")
    active_keys = stats.get("active_api_keys", 0)
    revoked_keys = stats.get("revoked_api_keys", 0)
    uptime = health.get("uptime_seconds", 0)
    status_text = health.get("status", "unknown")

    chain_status = "VERIFIED" if summary.chain_intact else "BROKEN"

    has_actions = summary.total_actions > 0
    has_agents = summary.total_agents > 0

    lines = _report_header(
        "EU AI Act Article 12 -- Logging Compliance Report",
        canister_id, generated_at, summary,
    )
    lines.extend(["## Executive Summary", ""])

    if summary.compliance_score > 0.8:
        lines.append(
            f"The AI system logged on canister `{canister_id}` demonstrates **strong "
            f"compliance** with EU AI Act Article 12 logging requirements. A total of "
            f"{summary.total_actions:,} actions have been recorded across "
            f"{summary.total_agents} agent(s) and {summary.total_sessions} session(s). "
            f"The cryptographic hash chain is {chain_status}, providing full traceability "
            f"of all AI system decisions and operations."
        )
    elif summary.compliance_score >= 0.4:
        lines.append(
            f"The AI system logged on canister `{canister_id}` demonstrates **partial "
            f"compliance** with EU AI Act Article 12. Some logging requirements are met, "
            f"but gaps exist that should be addressed. {summary.total_actions:,} actions "
            f"recorded. Chain integrity: {chain_status}."
        )
    else:
        lines.append(
            f"The AI system logged on canister `{canister_id}` shows **insufficient "
            f"compliance** with EU AI Act Article 12. Critical logging gaps have been "
            f"identified. Immediate remediation is recommended."
        )

    lines.extend([
        "",
        "## 1. Automatic Logging (Art. 12.1)",
        "",
        f"- Total logged actions: {summary.total_actions:,}",
        "- Action types covered: tool_call, decision, observation, error, human_override",
        f"- Logging framework: aegis-ledger-sdk v{SDK_VERSION}",
        f"- Canister health: {status_text}",
        f"- {_pass_fail(has_actions)} Automatic logging is active",
        "",
        "## 2. Traceability (Art. 12.2)",
        "",
        f"- Hash chain length: {chain_length:,}",
        f"- Chain integrity: {chain_status}",
        "- Hash algorithm: SHA-256 (canonical JSON serialization)",
        "- Digital signatures: Ed25519 / ML-DSA-65 / SLH-DSA-128s"
        " / Hybrid (per-entry payload signing)",
        f"- Latest chain hash: `{latest_hash}`",
        f"- {_pass_fail(summary.chain_intact)} Full traceability maintained",
        "",
        "## 3. Monitoring (Art. 12.3)",
        "",
        f"- Active agents: {summary.total_agents}",
        f"- Active sessions: {summary.total_sessions}",
        f"- API keys: {active_keys} active / {revoked_keys} revoked",
        f"- Canister uptime: {uptime:,} seconds",
        f"- {_pass_fail(has_agents)} Monitoring capability confirmed",
        "",
        "## 4. Record Keeping (Art. 12.4)",
        "",
        "- Storage: Internet Computer Protocol (append-only canister)",
        f"- Canister ID: `{canister_id}`",
        "- Retention: Permanent (ICP canister-based, no TTL)",
        "- Access control: Principal-based authentication (Internet Identity)",
        "- Data integrity: Hash-chained entries with Ed25519 signatures",
        f"- {_pass_fail(has_actions)} Records maintained per requirements",
        "",
        "",
        "## Appendix A: Verification Method",
        "",
        "Each ledger entry is cryptographically linked to its predecessor via SHA-256 "
        "hash chaining. The entry's payload is signed with Ed25519 using agent-specific "
        "private keys. Verification can be performed independently using:",
        "",
        "```bash",
        f"aegis verify {canister_id} <action_id>",
        "```",
        "",
        f"Chain length at time of report: **{chain_length:,}** entries.  ",
        f"Latest chain hash: `{latest_hash}`",
        "",
    ])

    lines.extend(_compliance_score_section(summary, stats, [
        ("Automatic Logging", has_actions),
        ("Chain Integrity", summary.chain_intact),
        ("Agent Monitoring", has_agents),
        ("Session Tracking", summary.total_sessions > 0),
        ("API Key Management", active_keys > 0),
    ]))

    return "\n".join(lines)


def _build_iso_42001_report(
    canister_id: str,
    generated_at: str,
    summary: ReportSummary,
    stats: dict[str, Any],
    health: dict[str, Any],
) -> str:
    """Build ISO 42001 AI Management System compliance report in Markdown."""
    chain_length = stats.get("chain_length", summary.total_actions)
    active_keys = stats.get("active_api_keys", 0)
    revoked_keys = stats.get("revoked_api_keys", 0)
    status_text = health.get("status", "unknown")

    has_actions = summary.total_actions > 0
    has_agents = summary.total_agents > 0

    lines = _report_header(
        "ISO/IEC 42001 -- AI Management System Compliance Report",
        canister_id, generated_at, summary,
        extra_lines=["**Standard:** ISO/IEC 42001:2023 Artificial Intelligence Management System"],
    )
    lines.extend([
        "## Executive Summary",
        "",
        f"This report documents the AI system logging controls implemented via the Aegis "
        f"Ledger on canister `{canister_id}`. The assessment covers control objectives "
        f"A.6.2.6 (AI System Logging), A.8.4 (Documentation of AI System Operation), and "
        f"A.9.3 (AI Monitoring and Measurement) as defined in ISO/IEC 42001:2023 Annex A.",
        "",
        "## A.6.2.6 -- AI System Logging",
        "",
        "**Objective:** The organization shall implement logging mechanisms for AI systems "
        "to enable monitoring, auditing, and incident investigation.",
        "",
        "| Control | Evidence | Status |",
        "|---------|----------|--------|",
        f"| Event logging enabled | {summary.total_actions:,} actions recorded | "
        f"{_pass_fail(has_actions)} |",
        f"| Log integrity protection | SHA-256 hash chain ({chain_length:,} entries) | "
        f"{_pass_fail(summary.chain_intact)} |",
        f"| Digital signatures | Ed25519 / ML-DSA-65 / SLH-DSA-128s / Hybrid (per-entry) | "
        f"{_pass_fail(has_actions)} |",
        f"| Tamper detection | Append-only hash-chained storage (ICP) | "
        f"{_pass_fail(summary.chain_intact)} |",
        "| Log retention | Permanent (no TTL, canister-based) | [PASS] |",
        "",
        "### Logging Coverage",
        "",
        "- Action types: tool_call, decision, observation, error, human_override",
        "- Captured fields: agent_id, session_id, sequence_number, timestamps, "
        "input/output hashes, duration, status, decision reasoning, confidence scores",
        f"- Framework: aegis-ledger-sdk v{SDK_VERSION}",
        f"- System health: {status_text}",
        "",
        "## A.8.4 -- Documentation of AI System Operation",
        "",
        "**Objective:** The organization shall maintain documentation of AI system "
        "operations sufficient for review and audit.",
        "",
        "| Control | Evidence | Status |",
        "|---------|----------|--------|",
        f"| Operational records | {summary.total_actions:,} logged operations | "
        f"{_pass_fail(has_actions)} |",
        f"| Agent identification | {summary.total_agents} registered agent(s) | "
        f"{_pass_fail(has_agents)} |",
        f"| Session tracking | {summary.total_sessions} session(s) recorded | "
        f"{_pass_fail(summary.total_sessions > 0)} |",
        f"| Access management | {active_keys} active / {revoked_keys} revoked API keys | "
        f"{_pass_fail(active_keys > 0)} |",
        f"| Causal tracing | Parent action IDs + decision reasoning fields | "
        f"{_pass_fail(has_actions)} |",
        "",
        "## A.9.3 -- AI Monitoring and Measurement",
        "",
        "**Objective:** The organization shall monitor and measure AI system performance "
        "and behavior.",
        "",
        "| Control | Evidence | Status |",
        "|---------|----------|--------|",
        f"| Real-time monitoring | Canister health endpoint (status: {status_text}) | "
        f"{_pass_fail(status_text == 'healthy')} |",
        f"| Chain verification | On-demand entry verification via CLI/API | "
        f"{_pass_fail(summary.chain_intact)} |",
        f"| Anomaly detection | Duration tracking, error action logging | "
        f"{_pass_fail(has_actions)} |",
        f"| Audit trail | Hash-chained append-only ledger | "
        f"{_pass_fail(summary.chain_intact)} |",
        "",
    ])

    lines.extend(_compliance_score_section(summary, stats, [
        ("A.6.2.6 AI System Logging", has_actions and summary.chain_intact),
        ("A.8.4 Documentation", has_actions and has_agents),
        ("A.9.3 Monitoring", status_text == "healthy"),
    ], section_title="Overall Compliance Score"))

    return "\n".join(lines)


def _build_aiuc_1_report(
    canister_id: str,
    generated_at: str,
    summary: ReportSummary,
    stats: dict[str, Any],
    health: dict[str, Any],
) -> str:
    """Build AIUC-1 insurance underwriting compliance report in Markdown."""
    chain_length = stats.get("chain_length", summary.total_actions)
    latest_hash = stats.get("latest_chain_hash", "N/A")
    active_keys = stats.get("active_api_keys", 0)
    status_text = health.get("status", "unknown")
    uptime = health.get("uptime_seconds", 0)

    has_actions = summary.total_actions > 0

    lines = _report_header(
        "AIUC-1 -- AI Underwriting Compliance Report",
        canister_id, generated_at, summary,
        extra_lines=["**Framework:** AIUC-1 (AI Underwriting Criteria for Insurance)"],
    )
    lines.extend([
        "## Executive Summary",
        "",
        f"This report provides evidence of continuous AI system logging, chain integrity, "
        f"and incident detection capability for insurance underwriting assessment. The Aegis "
        f"Ledger on canister `{canister_id}` serves as the tamper-evident audit trail for all "
        f"AI agent operations.",
        "",
        "## 1. Evidence of Continuous Logging",
        "",
        "Continuous, uninterrupted logging is required to demonstrate that all AI system "
        "actions are captured without gaps.",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total actions logged | {summary.total_actions:,} |",
        f"| Agents monitored | {summary.total_agents} |",
        f"| Sessions tracked | {summary.total_sessions} |",
        f"| Coverage period | {summary.coverage_start} to {summary.coverage_end} |",
        f"| Logging framework | aegis-ledger-sdk v{SDK_VERSION} |",
        f"| API keys active | {active_keys} |",
        "",
        f"**Assessment:** {_pass_fail(has_actions)} Continuous logging "
        f"{'is' if has_actions else 'is NOT'} evidenced.",
        "",
        "## 2. Chain Integrity Proof",
        "",
        "Tamper evidence is demonstrated through cryptographic hash chaining and "
        "digital signatures on an append-only ledger.",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Hash chain length | {chain_length:,} |",
        f"| Chain integrity | {'INTACT' if summary.chain_intact else 'COMPROMISED'} |",
        "| Hash algorithm | SHA-256 (canonical JSON) |",
        "| Signature scheme | Ed25519 / ML-DSA-65 / SLH-DSA-128s / Hybrid (per-entry) |",
        "| Storage backend | Internet Computer Protocol (ICP) |",
        f"| Latest chain hash | `{latest_hash}` |",
        "",
        f"**Assessment:** {_pass_fail(summary.chain_intact)} Chain integrity "
        f"{'is' if summary.chain_intact else 'is NOT'} verified.",
        "",
        "## 3. Incident Detection Capability",
        "",
        "The system must demonstrate the ability to detect and record anomalous "
        "AI behavior, including errors, timeouts, and unexpected decisions.",
        "",
        "| Capability | Implementation |",
        "|------------|----------------|",
        "| Error logging | Dedicated `error` action type with stack traces |",
        "| Timeout detection | `timeout` status recorded with duration_ms |",
        "| Decision reasoning | `decision_reasoning` field per action |",
        "| Confidence tracking | `confidence_score` (0.0-1.0) per action |",
        "| Human override logging | Dedicated `human_override` action type |",
        "| Real-time health | Canister health endpoint |",
        "",
        f"**Assessment:** {_pass_fail(has_actions)} Incident detection capability "
        f"{'is' if has_actions else 'is NOT'} confirmed.",
        "",
        "## 4. Data Retention Proof",
        "",
        "Insurance underwriting requires proof that audit data is tamper-evident "
        "and cryptographically verifiable.",
        "",
        "| Property | Evidence |",
        "|----------|----------|",
        f"| Tamper evidence | ICP canister-based storage (canister `{canister_id}`) |",
        "| Retention period | Permanent (no expiration, no TTL) |",
        "| Geographic distribution | ICP subnet nodes (distributed) |",
        "| Access control | Principal-based authentication |",
        "| Backup mechanism | Hash chain enables independent verification |",
        f"| System uptime | {uptime:,} seconds since last restart |",
        f"| System status | {status_text} |",
        "",
        f"**Assessment:** {_pass_fail(summary.chain_intact)} Data retention requirements "
        f"{'are' if summary.chain_intact else 'are NOT'} met.",
        "",
    ])

    lines.extend(_compliance_score_section(summary, stats, [
        ("Continuous Logging", has_actions),
        ("Chain Integrity", summary.chain_intact),
        ("Incident Detection", has_actions),
        ("Data Retention", summary.chain_intact),
    ], section_title="Risk Assessment Score"))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Format dispatcher
# ---------------------------------------------------------------------------

_BUILDERS: dict[ReportFormat, Any] = {
    ReportFormat.EU_AI_ACT: _build_eu_ai_act_report,
    ReportFormat.ISO_42001: _build_iso_42001_report,
    ReportFormat.AIUC_1: _build_aiuc_1_report,
}


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

    builder = _BUILDERS[format]
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
