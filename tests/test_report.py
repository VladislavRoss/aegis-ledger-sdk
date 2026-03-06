"""Tests for aegis.report -- Compliance report generator."""

from __future__ import annotations

import subprocess
import sys
from typing import TYPE_CHECKING

import pytest
from aegis.report import (
    ComplianceReport,
    ReportFormat,
    ReportSummary,
    _build_summary,
    _compute_compliance_score,
    _pass_fail,
    generate_all_reports,
    generate_report,
)

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

MOCK_STATS: dict = {
    "total_actions": 1234,
    "total_agents": 5,
    "total_sessions": 89,
    "active_api_keys": 3,
    "revoked_api_keys": 1,
    "chain_length": 1234,
    "latest_chain_hash": "a7f3b2c19e4d8a6b0f2e7d9c1a3b5e8f4d6c2a0b9e7f1d3c5a8b0e2f4d6a8c",
    "coverage_start": "2026-01-01T00:00:00Z",
    "coverage_end": "2026-03-05T14:32:01Z",
}

MOCK_HEALTH: dict = {
    "status": "healthy",
    "chain_valid": True,
    "uptime_seconds": 86400,
}

CANISTER_ID = "toqqq-lqaaa-aaaae-afc2a-cai"

MOCK_EMPTY_STATS: dict = {
    "total_actions": 0,
    "total_agents": 0,
    "total_sessions": 0,
    "active_api_keys": 0,
    "revoked_api_keys": 0,
    "chain_length": 0,
    "latest_chain_hash": "",
    "coverage_start": "2026-03-05T00:00:00Z",
    "coverage_end": "2026-03-05T00:00:00Z",
}

MOCK_BROKEN_HEALTH: dict = {
    "status": "degraded",
    "chain_valid": False,
    "uptime_seconds": 3600,
}


# ---------------------------------------------------------------------------
# ReportSummary dataclass
# ---------------------------------------------------------------------------


class TestReportSummary:
    def test_frozen(self) -> None:
        summary = ReportSummary(
            total_actions=100,
            total_sessions=10,
            total_agents=2,
            chain_intact=True,
            coverage_start="2026-01-01T00:00:00Z",
            coverage_end="2026-03-05T00:00:00Z",
            compliance_score=1.0,
        )
        with pytest.raises(AttributeError):
            summary.total_actions = 999  # type: ignore[misc]

    def test_fields(self) -> None:
        summary = ReportSummary(
            total_actions=1234,
            total_sessions=89,
            total_agents=5,
            chain_intact=True,
            coverage_start="2026-01-01T00:00:00Z",
            coverage_end="2026-03-05T00:00:00Z",
            compliance_score=0.8,
        )
        assert summary.total_actions == 1234
        assert summary.total_sessions == 89
        assert summary.total_agents == 5
        assert summary.chain_intact is True
        assert summary.compliance_score == 0.8


# ---------------------------------------------------------------------------
# ComplianceReport dataclass
# ---------------------------------------------------------------------------


class TestComplianceReport:
    def test_report_fields(self) -> None:
        report = ComplianceReport(
            format=ReportFormat.EU_AI_ACT,
            canister_id=CANISTER_ID,
            generated_at="2026-03-05T14:32:01Z",
            markdown="# Test",
            summary=ReportSummary(
                total_actions=100,
                total_sessions=10,
                total_agents=2,
                chain_intact=True,
                coverage_start="2026-01-01T00:00:00Z",
                coverage_end="2026-03-05T00:00:00Z",
                compliance_score=1.0,
            ),
        )
        assert report.format == ReportFormat.EU_AI_ACT
        assert report.canister_id == CANISTER_ID
        assert report.markdown == "# Test"


# ---------------------------------------------------------------------------
# ReportFormat enum
# ---------------------------------------------------------------------------


class TestReportFormat:
    def test_values(self) -> None:
        assert ReportFormat.EU_AI_ACT.value == "eu-ai-act"
        assert ReportFormat.ISO_42001.value == "iso-42001"
        assert ReportFormat.AIUC_1.value == "aiuc-1"

    def test_all_formats(self) -> None:
        assert len(ReportFormat) == 3


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestPassFail:
    def test_pass(self) -> None:
        assert _pass_fail(True) == "[PASS]"

    def test_fail(self) -> None:
        assert _pass_fail(False) == "[FAIL]"


class TestComplianceScore:
    def test_full_score(self) -> None:
        score = _compute_compliance_score(MOCK_STATS, MOCK_HEALTH)
        assert score == 1.0

    def test_zero_score(self) -> None:
        score = _compute_compliance_score(MOCK_EMPTY_STATS, MOCK_BROKEN_HEALTH)
        assert score == 0.0

    def test_partial_score_no_chain(self) -> None:
        score = _compute_compliance_score(MOCK_STATS, MOCK_BROKEN_HEALTH)
        # Has actions, agents, sessions, api_keys but NOT chain_valid
        assert score == 0.8

    def test_partial_score_no_agents(self) -> None:
        stats = {**MOCK_STATS, "total_agents": 0}
        score = _compute_compliance_score(stats, MOCK_HEALTH)
        assert score == 0.8

    def test_only_chain_valid(self) -> None:
        score = _compute_compliance_score(MOCK_EMPTY_STATS, MOCK_HEALTH)
        assert score == 0.2


class TestBuildSummary:
    def test_summary_from_mock_data(self) -> None:
        summary = _build_summary(MOCK_STATS, MOCK_HEALTH, "2026-03-05T14:32:01Z")
        assert summary.total_actions == 1234
        assert summary.total_sessions == 89
        assert summary.total_agents == 5
        assert summary.chain_intact is True
        assert summary.compliance_score == 1.0
        assert summary.coverage_start == "2026-01-01T00:00:00Z"
        assert summary.coverage_end == "2026-03-05T14:32:01Z"

    def test_summary_defaults_coverage_to_generated_at(self) -> None:
        stats = {"total_actions": 10, "total_agents": 1, "total_sessions": 1}
        summary = _build_summary(stats, MOCK_HEALTH, "2026-03-05T12:00:00Z")
        # No coverage_start/end in stats -> defaults to generated_at
        assert summary.coverage_start == "2026-03-05T12:00:00Z"
        assert summary.coverage_end == "2026-03-05T12:00:00Z"


# ---------------------------------------------------------------------------
# EU AI Act report
# ---------------------------------------------------------------------------


class TestEuAiActReport:
    def test_generate_eu_ai_act(self) -> None:
        report = generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.EU_AI_ACT,
            stats=MOCK_STATS,
            health=MOCK_HEALTH,
        )
        assert report.format == ReportFormat.EU_AI_ACT
        assert report.canister_id == CANISTER_ID
        assert isinstance(report.markdown, str)
        assert len(report.markdown) > 200

    def test_contains_required_sections(self) -> None:
        report = generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.EU_AI_ACT,
            stats=MOCK_STATS,
            health=MOCK_HEALTH,
        )
        md = report.markdown
        assert "EU AI Act Article 12" in md
        assert "1. Automatic Logging (Art. 12.1)" in md
        assert "2. Traceability (Art. 12.2)" in md
        assert "3. Monitoring (Art. 12.3)" in md
        assert "4. Record Keeping (Art. 12.4)" in md
        assert "Compliance Score:" in md
        assert "Executive Summary" in md
        assert "Appendix A" in md

    def test_contains_canister_id(self) -> None:
        report = generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.EU_AI_ACT,
            stats=MOCK_STATS,
            health=MOCK_HEALTH,
        )
        assert CANISTER_ID in report.markdown

    def test_pass_indicators_for_healthy(self) -> None:
        report = generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.EU_AI_ACT,
            stats=MOCK_STATS,
            health=MOCK_HEALTH,
        )
        assert "[PASS]" in report.markdown
        assert "[FAIL]" not in report.markdown

    def test_strong_compliance_text(self) -> None:
        report = generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.EU_AI_ACT,
            stats=MOCK_STATS,
            health=MOCK_HEALTH,
        )
        assert "strong compliance" in report.markdown

    def test_chain_verified_text(self) -> None:
        report = generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.EU_AI_ACT,
            stats=MOCK_STATS,
            health=MOCK_HEALTH,
        )
        assert "VERIFIED" in report.markdown


# ---------------------------------------------------------------------------
# ISO 42001 report
# ---------------------------------------------------------------------------


class TestIso42001Report:
    def test_generate_iso_42001(self) -> None:
        report = generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.ISO_42001,
            stats=MOCK_STATS,
            health=MOCK_HEALTH,
        )
        assert report.format == ReportFormat.ISO_42001
        assert isinstance(report.markdown, str)

    def test_contains_iso_sections(self) -> None:
        report = generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.ISO_42001,
            stats=MOCK_STATS,
            health=MOCK_HEALTH,
        )
        md = report.markdown
        assert "ISO/IEC 42001" in md
        assert "A.6.2.6" in md
        assert "A.8.4" in md
        assert "A.9.3" in md
        assert "Executive Summary" in md
        assert "Overall Compliance Score:" in md


# ---------------------------------------------------------------------------
# AIUC-1 report
# ---------------------------------------------------------------------------


class TestAiuc1Report:
    def test_generate_aiuc_1(self) -> None:
        report = generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.AIUC_1,
            stats=MOCK_STATS,
            health=MOCK_HEALTH,
        )
        assert report.format == ReportFormat.AIUC_1
        assert isinstance(report.markdown, str)

    def test_contains_aiuc_sections(self) -> None:
        report = generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.AIUC_1,
            stats=MOCK_STATS,
            health=MOCK_HEALTH,
        )
        md = report.markdown
        assert "AIUC-1" in md
        assert "Evidence of Continuous Logging" in md
        assert "Chain Integrity Proof" in md
        assert "Incident Detection Capability" in md
        assert "Data Retention Proof" in md
        assert "Risk Assessment Score:" in md


# ---------------------------------------------------------------------------
# Chain broken scenarios
# ---------------------------------------------------------------------------


class TestChainBroken:
    def test_broken_chain_shows_fail(self) -> None:
        report = generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.EU_AI_ACT,
            stats=MOCK_STATS,
            health=MOCK_BROKEN_HEALTH,
        )
        assert "[FAIL]" in report.markdown
        assert report.summary.chain_intact is False

    def test_broken_chain_score_80(self) -> None:
        report = generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.EU_AI_ACT,
            stats=MOCK_STATS,
            health=MOCK_BROKEN_HEALTH,
        )
        assert report.summary.compliance_score == 0.8

    def test_broken_chain_partial_compliance_text(self) -> None:
        report = generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.EU_AI_ACT,
            stats=MOCK_STATS,
            health=MOCK_BROKEN_HEALTH,
        )
        assert "partial compliance" in report.markdown


# ---------------------------------------------------------------------------
# Empty canister (0 actions)
# ---------------------------------------------------------------------------


class TestEmptyCanister:
    def test_empty_canister_zero_score(self) -> None:
        report = generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.EU_AI_ACT,
            stats=MOCK_EMPTY_STATS,
            health=MOCK_BROKEN_HEALTH,
        )
        assert report.summary.compliance_score == 0.0
        assert report.summary.total_actions == 0

    def test_empty_canister_insufficient_text(self) -> None:
        report = generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.EU_AI_ACT,
            stats=MOCK_EMPTY_STATS,
            health=MOCK_BROKEN_HEALTH,
        )
        assert "insufficient compliance" in report.markdown

    def test_empty_canister_all_fail(self) -> None:
        report = generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.EU_AI_ACT,
            stats=MOCK_EMPTY_STATS,
            health=MOCK_BROKEN_HEALTH,
        )
        assert "[PASS]" not in report.markdown


# ---------------------------------------------------------------------------
# Output file writing
# ---------------------------------------------------------------------------


class TestOutputFile:
    def test_write_to_file(self, tmp_path: Path) -> None:
        out = tmp_path / "report.md"
        report = generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.EU_AI_ACT,
            output_path=str(out),
            stats=MOCK_STATS,
            health=MOCK_HEALTH,
        )
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert content == report.markdown

    def test_write_creates_parent_dirs(self, tmp_path: Path) -> None:
        out = tmp_path / "subdir" / "nested" / "report.md"
        generate_report(
            canister_id=CANISTER_ID,
            format=ReportFormat.EU_AI_ACT,
            output_path=str(out),
            stats=MOCK_STATS,
            health=MOCK_HEALTH,
        )
        assert out.exists()


# ---------------------------------------------------------------------------
# generate_all_reports (--format all)
# ---------------------------------------------------------------------------


class TestGenerateAllReports:
    def test_returns_three_reports(self) -> None:
        reports = generate_all_reports(
            canister_id=CANISTER_ID,
            stats=MOCK_STATS,
            health=MOCK_HEALTH,
        )
        assert len(reports) == 3
        formats = {r.format for r in reports}
        assert formats == {ReportFormat.EU_AI_ACT, ReportFormat.ISO_42001, ReportFormat.AIUC_1}

    def test_all_reports_write_to_dir(self, tmp_path: Path) -> None:
        reports = generate_all_reports(
            canister_id=CANISTER_ID,
            output_dir=str(tmp_path),
            stats=MOCK_STATS,
            health=MOCK_HEALTH,
        )
        for r in reports:
            expected = tmp_path / f"aegis-{r.format.value}-report.md"
            assert expected.exists()
            assert expected.read_text(encoding="utf-8") == r.markdown

    def test_all_reports_consistent_summary(self) -> None:
        reports = generate_all_reports(
            canister_id=CANISTER_ID,
            stats=MOCK_STATS,
            health=MOCK_HEALTH,
        )
        # All reports should use the same underlying data
        scores = {r.summary.compliance_score for r in reports}
        assert len(scores) == 1
        assert scores.pop() == 1.0


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


class TestCliReport:
    def test_report_missing_args_exits_1(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "AEGIS_LEDGER.cli", "report"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 1
        assert "Usage:" in result.stdout

    def test_report_unknown_format_exits_1(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "AEGIS_LEDGER.cli", "report", CANISTER_ID,
             "--format", "invalid-format"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 1
        assert "Unknown format" in result.stdout

    def test_help_includes_report(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "AEGIS_LEDGER.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "report" in result.stdout
        assert "compliance" in result.stdout.lower()
