"""
Smart Reporting actions for the tool registry.
"""

from typing import Any

from strix.tools.registry import register_tool
from strix.tools.smart_reporting.report_generator import (
    ReportFormat,
    get_report_generator,
)
from strix.tools.correlation.correlation_engine import get_correlation_engine


@register_tool
def generate_report(
    format_type: str = "markdown",
    include_evidence: bool = True,
    include_remediation: bool = True,
    target: str = "",
) -> dict[str, Any]:
    """Generate a comprehensive security report."""
    try:
        format_map = {
            "json": ReportFormat.JSON,
            "markdown": ReportFormat.MARKDOWN,
            "html": ReportFormat.HTML,
            "text": ReportFormat.TEXT,
        }

        report_format = format_map.get(format_type.lower(), ReportFormat.MARKDOWN)

        generator = get_report_generator()
        if target:
            generator.set_target(target)

        report = generator.generate_report(
            format_type=report_format,
            include_evidence=include_evidence,
            include_remediation=include_remediation,
        )

        return {
            "success": True,
            "format": format_type,
            "report": report,
        }
    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to generate report: {e}"}


@register_tool
def generate_executive_summary(target: str = "") -> dict[str, Any]:
    """Generate an executive summary of findings."""
    try:
        generator = get_report_generator()
        if target:
            generator.set_target(target)

        summary = generator.generate_executive_summary()

        return {
            "success": True,
            "summary": summary,
        }
    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to generate executive summary: {e}"}


@register_tool
def export_findings(
    format_type: str = "json",
    file_path: str = "",
) -> dict[str, Any]:
    """Export findings to a file or return as content."""
    try:
        generator = get_report_generator()
        result = generator.export_findings(
            format_type=format_type,
            file_path=file_path if file_path else None,
        )

        return result
    except (ValueError, TypeError, OSError) as e:
        return {"success": False, "error": f"Failed to export findings: {e}"}


@register_tool
def get_remediation_guidance(category: str) -> dict[str, Any]:
    """Get remediation guidance for a vulnerability category."""
    try:
        if not category:
            return {"success": False, "error": "category is required"}

        generator = get_report_generator()
        result = generator.get_remediation_guidance(category)

        return result
    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to get remediation guidance: {e}"}


@register_tool
def calculate_risk_score() -> dict[str, Any]:
    """Calculate overall risk score for the assessment."""
    try:
        engine = get_correlation_engine()
        findings = engine.get_all_findings()
        chains = engine.get_attack_chains()

        if not findings:
            return {
                "success": True,
                "risk_score": 0.0,
                "risk_level": "None",
                "message": "No findings to calculate risk from",
            }

        generator = get_report_generator()
        risk_score = generator.calculate_risk_score(findings, chains)

        risk_level = "Low"
        if risk_score >= 8:
            risk_level = "Critical"
        elif risk_score >= 6:
            risk_level = "High"
        elif risk_score >= 4:
            risk_level = "Medium"

        return {
            "success": True,
            "risk_score": round(risk_score, 1),
            "risk_level": risk_level,
            "total_findings": len(findings),
            "attack_chains": len(chains),
        }
    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to calculate risk score: {e}"}


@register_tool
def set_report_target(target: str) -> dict[str, Any]:
    """Set the target URL for reports."""
    try:
        if not target:
            return {"success": False, "error": "target is required"}

        generator = get_report_generator()
        generator.set_target(target)

        return {
            "success": True,
            "target": target,
            "message": f"Report target set to: {target}",
        }
    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to set report target: {e}"}
