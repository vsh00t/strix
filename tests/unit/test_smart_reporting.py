"""Unit tests for the Smart Reporting module."""

import json
import pytest

from strix.tools.correlation.correlation_engine import (
    Finding,
    Severity,
    get_correlation_engine,
)
from strix.tools.smart_reporting.report_generator import (
    REMEDIATION_DATABASE,
    ReportFormat,
    ReportGenerator,
    ReportSection,
    get_report_generator,
)


@pytest.fixture
def generator() -> ReportGenerator:
    """Get a fresh report generator instance."""
    gen = get_report_generator()
    gen.clear()
    gen.set_target("https://test-target.com")
    return gen


@pytest.fixture
def engine_with_findings():
    """Get correlation engine with sample findings."""
    engine = get_correlation_engine()
    engine.clear()

    findings = [
        Finding(
            id="sqli_001",
            title="SQL Injection in login",
            description="User input is concatenated into SQL query",
            severity=Severity.CRITICAL,
            category="sqli",
            url="https://test-target.com/api/login",
            parameter="username",
            evidence="Database error: syntax error near 'admin'--'",
            tool="browser",
            confidence=0.9,
        ),
        Finding(
            id="xss_001",
            title="Reflected XSS in search",
            description="User input reflected without encoding",
            severity=Severity.HIGH,
            category="xss",
            url="https://test-target.com/search",
            parameter="q",
            evidence="<script>alert(1)</script> reflected",
            tool="browser",
            confidence=0.85,
        ),
        Finding(
            id="idor_001",
            title="IDOR in user profile",
            description="Can access other users' profiles",
            severity=Severity.HIGH,
            category="idor",
            url="https://test-target.com/api/users/123",
            parameter="user_id",
            evidence="Accessed user 456 data with user 123 token",
            tool="browser",
            confidence=0.95,
        ),
        Finding(
            id="info_001",
            title="Server version disclosure",
            description="Server header reveals version",
            severity=Severity.LOW,
            category="information_disclosure",
            url="https://test-target.com",
            evidence="Server: nginx/1.18.0",
            tool="browser",
            confidence=0.99,
        ),
    ]

    for f in findings:
        engine.add_finding(f)

    yield engine
    engine.clear()


class TestReportFormat:
    """Tests for ReportFormat enum."""

    def test_format_values(self) -> None:
        """Test report format enum values."""
        assert ReportFormat.JSON.value == "json"
        assert ReportFormat.MARKDOWN.value == "markdown"
        assert ReportFormat.HTML.value == "html"
        assert ReportFormat.TEXT.value == "text"


class TestReportSection:
    """Tests for ReportSection dataclass."""

    def test_section_creation(self) -> None:
        """Test creating a report section."""
        section = ReportSection(
            title="Test Section",
            content="This is test content",
            priority=1,
        )
        assert section.title == "Test Section"
        assert section.priority == 1


class TestRemediationDatabase:
    """Tests for the remediation database."""

    def test_sqli_remediation_exists(self) -> None:
        """Test SQL injection remediation is available."""
        assert "sqli" in REMEDIATION_DATABASE
        guidance = REMEDIATION_DATABASE["sqli"]
        assert guidance.category == "sqli"
        assert len(guidance.steps) > 0
        assert len(guidance.references) > 0

    def test_xss_remediation_exists(self) -> None:
        """Test XSS remediation is available."""
        assert "xss" in REMEDIATION_DATABASE
        guidance = REMEDIATION_DATABASE["xss"]
        assert guidance.priority == "immediate"

    def test_all_common_categories_covered(self) -> None:
        """Test that common vulnerability categories have guidance."""
        expected_categories = [
            "sqli", "xss", "idor", "ssrf", "csrf", 
            "auth_bypass", "rce", "file_upload", "path_traversal"
        ]
        for cat in expected_categories:
            assert cat in REMEDIATION_DATABASE, f"Missing remediation for {cat}"


class TestReportGenerator:
    """Tests for the ReportGenerator class."""

    def test_singleton_pattern(self) -> None:
        """Test that report generator is a singleton."""
        gen1 = get_report_generator()
        gen2 = get_report_generator()
        assert gen1 is gen2

    def test_set_target(self, generator: ReportGenerator) -> None:
        """Test setting the target."""
        generator.set_target("https://new-target.com")
        summary = generator.generate_executive_summary()
        assert summary["target"] == "https://new-target.com"

    def test_add_section(self, generator: ReportGenerator) -> None:
        """Test adding custom sections."""
        section = ReportSection(
            title="Custom Section",
            content="Custom content",
        )
        generator.add_section(section)
        # Should not raise


class TestExecutiveSummary:
    """Tests for executive summary generation."""

    def test_generate_executive_summary(
        self, generator: ReportGenerator, engine_with_findings
    ) -> None:
        """Test generating executive summary."""
        summary = generator.generate_executive_summary()

        assert "target" in summary
        assert "overall_risk_score" in summary
        assert "overall_risk_level" in summary
        assert "total_findings" in summary
        assert "by_severity" in summary
        assert "top_priorities" in summary
        assert "recommendations" in summary

    def test_risk_score_calculation(
        self, generator: ReportGenerator, engine_with_findings
    ) -> None:
        """Test risk score is calculated correctly."""
        summary = generator.generate_executive_summary()
        
        # With critical and high findings, score should be significant
        assert summary["overall_risk_score"] > 5
        assert summary["overall_risk_level"] in ["High", "Critical"]

    def test_top_priorities_sorted(
        self, generator: ReportGenerator, engine_with_findings
    ) -> None:
        """Test that top priorities are sorted by severity."""
        summary = generator.generate_executive_summary()
        priorities = summary["top_priorities"]
        
        if len(priorities) >= 2:
            # First priority should be critical or high
            assert priorities[0]["severity"] in ["critical", "high"]


class TestReportGeneration:
    """Tests for full report generation."""

    def test_generate_json_report(
        self, generator: ReportGenerator, engine_with_findings
    ) -> None:
        """Test generating JSON format report."""
        report = generator.generate_report(format_type=ReportFormat.JSON)
        
        # Should be valid JSON
        parsed = json.loads(report)
        assert "metadata" in parsed
        assert "executive_summary" in parsed
        assert "findings" in parsed
        assert len(parsed["findings"]) == 4

    def test_generate_markdown_report(
        self, generator: ReportGenerator, engine_with_findings
    ) -> None:
        """Test generating Markdown format report."""
        report = generator.generate_report(format_type=ReportFormat.MARKDOWN)
        
        assert "# Security Assessment Report" in report
        assert "## Executive Summary" in report
        assert "## Detailed Findings" in report
        assert "SQL Injection" in report

    def test_generate_html_report(
        self, generator: ReportGenerator, engine_with_findings
    ) -> None:
        """Test generating HTML format report."""
        report = generator.generate_report(format_type=ReportFormat.HTML)
        
        assert "<!DOCTYPE html>" in report
        assert "<title>Security Assessment Report</title>" in report
        assert "SQL Injection" in report

    def test_generate_text_report(
        self, generator: ReportGenerator, engine_with_findings
    ) -> None:
        """Test generating plain text format report."""
        report = generator.generate_report(format_type=ReportFormat.TEXT)
        
        assert "SECURITY ASSESSMENT REPORT" in report
        assert "FINDINGS" in report

    def test_report_without_evidence(
        self, generator: ReportGenerator, engine_with_findings
    ) -> None:
        """Test generating report without evidence."""
        report = generator.generate_report(
            format_type=ReportFormat.JSON,
            include_evidence=False,
        )
        parsed = json.loads(report)
        
        for finding in parsed["findings"]:
            assert "evidence" not in finding

    def test_report_with_remediation(
        self, generator: ReportGenerator, engine_with_findings
    ) -> None:
        """Test that reports include remediation guidance."""
        report = generator.generate_report(
            format_type=ReportFormat.JSON,
            include_remediation=True,
        )
        parsed = json.loads(report)
        
        # At least SQL injection should have remediation
        sqli_findings = [f for f in parsed["findings"] if f["category"] == "sqli"]
        assert len(sqli_findings) > 0
        assert "remediation" in sqli_findings[0]


class TestExportFindings:
    """Tests for findings export functionality."""

    def test_export_json(
        self, generator: ReportGenerator, engine_with_findings
    ) -> None:
        """Test exporting findings as JSON."""
        result = generator.export_findings(format_type="json")
        
        assert result["success"] is True
        assert result["format"] == "json"
        assert result["count"] == 4
        assert "content" in result

    def test_export_csv(
        self, generator: ReportGenerator, engine_with_findings
    ) -> None:
        """Test exporting findings as CSV."""
        result = generator.export_findings(format_type="csv")
        
        assert result["success"] is True
        lines = result["content"].split("\n")
        assert "id,title,severity" in lines[0]  # Header
        assert len(lines) == 5  # Header + 4 findings


class TestRemediationGuidance:
    """Tests for remediation guidance retrieval."""

    def test_get_sqli_guidance(self, generator: ReportGenerator) -> None:
        """Test getting SQL injection guidance."""
        result = generator.get_remediation_guidance("sqli")
        
        assert result["success"] is True
        assert result["guidance"]["category"] == "sqli"
        assert "steps" in result["guidance"]
        assert "references" in result["guidance"]

    def test_get_unknown_category(self, generator: ReportGenerator) -> None:
        """Test getting guidance for unknown category."""
        result = generator.get_remediation_guidance("nonexistent")
        
        assert result["success"] is False
        assert "error" in result
        assert "available_categories" in result


class TestRiskScoreCalculation:
    """Tests for risk score calculation."""

    def test_calculate_risk_score_with_findings(
        self, generator: ReportGenerator, engine_with_findings
    ) -> None:
        """Test risk score calculation with findings."""
        engine = get_correlation_engine()
        findings = engine.get_all_findings()
        chains = engine.get_attack_chains()
        
        score = generator.calculate_risk_score(findings, chains)
        
        assert 0 <= score <= 10
        assert score > 5  # Critical and high findings should give high score

    def test_calculate_risk_score_empty(self, generator: ReportGenerator) -> None:
        """Test risk score with no findings."""
        score = generator.calculate_risk_score([], [])
        assert score == 0.0


class TestSmartReportingActions:
    """Tests for smart reporting action functions."""

    def test_generate_report_action(self, engine_with_findings) -> None:
        """Test generate_report action."""
        from strix.tools.smart_reporting.smart_reporting_actions import generate_report

        result = generate_report(
            format_type="markdown",
            target="https://test.com",
        )

        assert result["success"] is True
        assert result["format"] == "markdown"
        assert "# Security Assessment Report" in result["report"]

    def test_generate_executive_summary_action(self, engine_with_findings) -> None:
        """Test generate_executive_summary action."""
        from strix.tools.smart_reporting.smart_reporting_actions import (
            generate_executive_summary,
        )

        result = generate_executive_summary(target="https://test.com")

        assert result["success"] is True
        assert "summary" in result
        assert "overall_risk_score" in result["summary"]

    def test_export_findings_action(self, engine_with_findings) -> None:
        """Test export_findings action."""
        from strix.tools.smart_reporting.smart_reporting_actions import export_findings

        result = export_findings(format_type="json")

        assert result["success"] is True
        assert result["count"] == 4

    def test_get_remediation_guidance_action(self) -> None:
        """Test get_remediation_guidance action."""
        from strix.tools.smart_reporting.smart_reporting_actions import (
            get_remediation_guidance,
        )

        result = get_remediation_guidance(category="xss")

        assert result["success"] is True
        assert result["guidance"]["category"] == "xss"

    def test_calculate_risk_score_action(self, engine_with_findings) -> None:
        """Test calculate_risk_score action."""
        from strix.tools.smart_reporting.smart_reporting_actions import (
            calculate_risk_score,
        )

        result = calculate_risk_score()

        assert result["success"] is True
        assert "risk_score" in result
        assert "risk_level" in result
        assert result["total_findings"] == 4

    def test_set_report_target_action(self) -> None:
        """Test set_report_target action."""
        from strix.tools.smart_reporting.smart_reporting_actions import (
            set_report_target,
        )

        result = set_report_target(target="https://new-target.com")

        assert result["success"] is True
        assert "new-target.com" in result["target"]


class TestEmptyReports:
    """Tests for reports with no findings."""

    def test_empty_executive_summary(self, generator: ReportGenerator) -> None:
        """Test executive summary with no findings."""
        engine = get_correlation_engine()
        engine.clear()

        summary = generator.generate_executive_summary()
        
        assert summary["total_findings"] == 0
        assert summary["overall_risk_score"] == 0

    def test_empty_report(self, generator: ReportGenerator) -> None:
        """Test generating report with no findings."""
        engine = get_correlation_engine()
        engine.clear()

        report = generator.generate_report(format_type=ReportFormat.MARKDOWN)
        
        assert "# Security Assessment Report" in report
        # Should still generate structure even with no findings
