"""
Smart Reporting module for DAST.

Provides intelligent report generation with:
- Multiple output formats (JSON, Markdown, HTML)
- Executive summaries
- Technical details
- Remediation guidance
- Risk scoring and prioritization
"""

from strix.tools.smart_reporting.report_generator import (
    ReportFormat,
    ReportGenerator,
    ReportSection,
    get_report_generator,
)

from strix.tools.smart_reporting.smart_reporting_actions import (
    calculate_risk_score,
    export_findings,
    generate_executive_summary,
    generate_report,
    get_remediation_guidance,
    set_report_target,
)

__all__ = [
    # Generator classes
    "ReportFormat",
    "ReportGenerator",
    "ReportSection",
    "get_report_generator",
    # Actions
    "calculate_risk_score",
    "export_findings",
    "generate_executive_summary",
    "generate_report",
    "get_remediation_guidance",
    "set_report_target",
]
