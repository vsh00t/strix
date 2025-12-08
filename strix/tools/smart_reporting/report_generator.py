"""
Smart Report Generator.

Generates comprehensive security reports with:
- Multiple formats (JSON, Markdown, HTML)
- Executive summaries
- Technical details
- Remediation guidance
- Risk scoring
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from strix.tools.correlation.correlation_engine import (
    AttackChain,
    CorrelatedFinding,
    Finding,
    Severity,
    get_correlation_engine,
)


class ReportFormat(Enum):
    """Available report formats."""

    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    TEXT = "text"


@dataclass
class ReportSection:
    """A section in a report."""

    title: str
    content: str
    priority: int = 0  # Higher = more important
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RemediationGuidance:
    """Remediation guidance for a vulnerability type."""

    category: str
    title: str
    description: str
    steps: list[str]
    references: list[str]
    priority: str  # immediate, short_term, long_term
    estimated_effort: str  # low, medium, high


# Remediation database
REMEDIATION_DATABASE: dict[str, RemediationGuidance] = {
    "sqli": RemediationGuidance(
        category="sqli",
        title="SQL Injection Remediation",
        description="SQL injection allows attackers to manipulate database queries.",
        steps=[
            "Use parameterized queries or prepared statements",
            "Implement input validation and sanitization",
            "Apply the principle of least privilege to database accounts",
            "Use ORM frameworks that handle escaping automatically",
            "Implement WAF rules as additional protection layer",
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
        priority="immediate",
        estimated_effort="medium",
    ),
    "xss": RemediationGuidance(
        category="xss",
        title="Cross-Site Scripting (XSS) Remediation",
        description="XSS allows attackers to inject malicious scripts into web pages.",
        steps=[
            "Encode output based on context (HTML, JavaScript, URL, CSS)",
            "Use Content Security Policy (CSP) headers",
            "Implement input validation and sanitization",
            "Use modern frameworks with automatic escaping",
            "Set HttpOnly and Secure flags on cookies",
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
        priority="immediate",
        estimated_effort="medium",
    ),
    "idor": RemediationGuidance(
        category="idor",
        title="Insecure Direct Object Reference (IDOR) Remediation",
        description="IDOR allows unauthorized access to resources by manipulating references.",
        steps=[
            "Implement proper authorization checks for all resources",
            "Use indirect references (UUIDs, tokens) instead of sequential IDs",
            "Validate user permissions before resource access",
            "Log and monitor access patterns for anomalies",
            "Implement rate limiting on sensitive endpoints",
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/639.html",
        ],
        priority="immediate",
        estimated_effort="medium",
    ),
    "ssrf": RemediationGuidance(
        category="ssrf",
        title="Server-Side Request Forgery (SSRF) Remediation",
        description="SSRF allows attackers to make requests from the server to internal resources.",
        steps=[
            "Implement allowlist of permitted URLs/domains",
            "Disable unnecessary URL schemes (file://, gopher://, etc.)",
            "Use network segmentation to limit internal access",
            "Validate and sanitize all user-provided URLs",
            "Block requests to cloud metadata endpoints",
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/918.html",
        ],
        priority="immediate",
        estimated_effort="medium",
    ),
    "csrf": RemediationGuidance(
        category="csrf",
        title="Cross-Site Request Forgery (CSRF) Remediation",
        description="CSRF tricks authenticated users into performing unintended actions.",
        steps=[
            "Implement anti-CSRF tokens in all state-changing forms",
            "Use SameSite cookie attribute",
            "Verify Origin and Referer headers",
            "Require re-authentication for sensitive actions",
            "Use custom request headers for AJAX requests",
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/352.html",
        ],
        priority="short_term",
        estimated_effort="low",
    ),
    "auth_bypass": RemediationGuidance(
        category="auth_bypass",
        title="Authentication Bypass Remediation",
        description="Authentication bypass allows unauthorized access without proper credentials.",
        steps=[
            "Review and strengthen authentication logic",
            "Implement multi-factor authentication",
            "Use secure session management",
            "Rate limit authentication attempts",
            "Implement proper password policies",
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/287.html",
        ],
        priority="immediate",
        estimated_effort="high",
    ),
    "rce": RemediationGuidance(
        category="rce",
        title="Remote Code Execution (RCE) Remediation",
        description="RCE allows attackers to execute arbitrary code on the server.",
        steps=[
            "Never pass user input to system commands",
            "Use allowlist validation for any required command inputs",
            "Implement sandboxing for code execution",
            "Keep all dependencies and systems updated",
            "Use application-level firewalls",
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/94.html",
        ],
        priority="immediate",
        estimated_effort="high",
    ),
    "file_upload": RemediationGuidance(
        category="file_upload",
        title="Insecure File Upload Remediation",
        description="Insecure file uploads can lead to RCE or stored XSS.",
        steps=[
            "Validate file types using magic bytes, not just extensions",
            "Store uploaded files outside web root",
            "Use random filenames for stored files",
            "Scan uploaded files for malware",
            "Set proper Content-Type and Content-Disposition headers",
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/434.html",
        ],
        priority="immediate",
        estimated_effort="medium",
    ),
    "path_traversal": RemediationGuidance(
        category="path_traversal",
        title="Path Traversal Remediation",
        description="Path traversal allows access to files outside intended directories.",
        steps=[
            "Use canonical path resolution before file access",
            "Implement allowlist of permitted paths",
            "Chroot or jail file access operations",
            "Validate and sanitize all file path inputs",
            "Use indirect file references",
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
        priority="immediate",
        estimated_effort="low",
    ),
    "information_disclosure": RemediationGuidance(
        category="information_disclosure",
        title="Information Disclosure Remediation",
        description="Information disclosure exposes sensitive data to unauthorized parties.",
        steps=[
            "Remove verbose error messages in production",
            "Disable directory listing",
            "Remove sensitive comments from client-side code",
            "Implement proper access controls",
            "Use generic error pages",
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
        priority="short_term",
        estimated_effort="low",
    ),
}


class ReportGenerator:
    """
    Generates comprehensive security reports.

    Features:
    - Multiple output formats
    - Executive summaries
    - Technical details
    - Remediation guidance
    - Risk scoring
    """

    _instance: "ReportGenerator | None" = None

    def __new__(cls) -> "ReportGenerator":
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialize the report generator."""
        if self._initialized:
            return
        self._initialized = True
        self._target: str = ""
        self._scan_start: datetime | None = None
        self._scan_end: datetime | None = None
        self._custom_sections: list[ReportSection] = []

    def set_target(self, target: str) -> None:
        """Set the scan target."""
        self._target = target

    def set_scan_times(
        self, start: datetime | None = None, end: datetime | None = None
    ) -> None:
        """Set scan start and end times."""
        self._scan_start = start
        self._scan_end = end

    def add_section(self, section: ReportSection) -> None:
        """Add a custom section to the report."""
        self._custom_sections.append(section)

    def generate_executive_summary(self) -> dict[str, Any]:
        """Generate an executive summary of findings."""
        engine = get_correlation_engine()
        summary = engine.get_findings_summary()
        chains = engine.get_attack_chains()
        findings = engine.get_all_findings()

        # Calculate risk score
        risk_score = self.calculate_risk_score(findings, chains)

        # Determine overall risk level
        risk_level = "Low"
        if risk_score >= 8:
            risk_level = "Critical"
        elif risk_score >= 6:
            risk_level = "High"
        elif risk_score >= 4:
            risk_level = "Medium"

        # Get top priorities
        critical_high = [
            f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        critical_high.sort(key=lambda x: x.severity.score, reverse=True)

        return {
            "target": self._target,
            "scan_date": (
                self._scan_start.isoformat() if self._scan_start else datetime.now().isoformat()
            ),
            "overall_risk_score": round(risk_score, 1),
            "overall_risk_level": risk_level,
            "total_findings": summary["total_findings"],
            "unique_findings": summary["unique_findings"],
            "attack_chains_detected": len(chains),
            "by_severity": summary["by_severity"],
            "top_priorities": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "category": f.category,
                    "url": f.url,
                }
                for f in critical_high[:5]
            ],
            "recommendations": self._get_top_recommendations(findings),
        }

    def calculate_risk_score(
        self, findings: list[Finding], chains: list[AttackChain]
    ) -> float:
        """Calculate overall risk score (0-10)."""
        if not findings:
            return 0.0

        # Base score from severity distribution
        severity_weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 2,
            Severity.INFO: 0.5,
        }

        total_weight = sum(severity_weights[f.severity] for f in findings)
        avg_severity = total_weight / len(findings)

        # Bonus for attack chains (indicates systemic issues)
        chain_bonus = min(2.0, len(chains) * 0.5)

        # Confidence factor
        avg_confidence = sum(f.confidence for f in findings) / len(findings)
        confidence_factor = 0.5 + (avg_confidence * 0.5)

        # Calculate final score
        base_score = min(8.0, avg_severity)
        final_score = (base_score + chain_bonus) * confidence_factor

        return min(10.0, final_score)

    def _get_top_recommendations(self, findings: list[Finding]) -> list[str]:
        """Get top recommendations based on findings."""
        recommendations: list[str] = []
        categories_seen: set[str] = set()

        # Sort by severity
        sorted_findings = sorted(
            findings, key=lambda x: x.severity.score, reverse=True
        )

        for finding in sorted_findings:
            if finding.category not in categories_seen:
                guidance = REMEDIATION_DATABASE.get(finding.category)
                if guidance:
                    recommendations.append(
                        f"[{guidance.priority.upper()}] {guidance.title}: {guidance.steps[0]}"
                    )
                    categories_seen.add(finding.category)

            if len(recommendations) >= 5:
                break

        return recommendations

    def generate_report(
        self,
        format_type: ReportFormat = ReportFormat.MARKDOWN,
        include_evidence: bool = True,
        include_remediation: bool = True,
    ) -> str:
        """Generate a full report in the specified format."""
        engine = get_correlation_engine()
        findings = engine.get_all_findings()
        correlations = list(engine._correlations.values())
        chains = engine.get_attack_chains()

        if format_type == ReportFormat.JSON:
            return self._generate_json_report(
                findings, correlations, chains, include_evidence, include_remediation
            )
        elif format_type == ReportFormat.HTML:
            return self._generate_html_report(
                findings, correlations, chains, include_evidence, include_remediation
            )
        elif format_type == ReportFormat.TEXT:
            return self._generate_text_report(
                findings, correlations, chains, include_evidence
            )
        else:  # MARKDOWN is default
            return self._generate_markdown_report(
                findings, correlations, chains, include_evidence, include_remediation
            )

    def _generate_json_report(
        self,
        findings: list[Finding],
        correlations: list[CorrelatedFinding],
        chains: list[AttackChain],
        include_evidence: bool,
        include_remediation: bool,
    ) -> str:
        """Generate JSON format report."""
        report = {
            "metadata": {
                "target": self._target,
                "scan_start": (
                    self._scan_start.isoformat() if self._scan_start else None
                ),
                "scan_end": self._scan_end.isoformat() if self._scan_end else None,
                "generated_at": datetime.now().isoformat(),
            },
            "executive_summary": self.generate_executive_summary(),
            "findings": [],
            "attack_chains": [c.to_dict() for c in chains],
            "correlations_count": len(correlations),
        }

        for finding in sorted(
            findings, key=lambda x: x.severity.score, reverse=True
        ):
            finding_dict = finding.to_dict()
            if not include_evidence:
                finding_dict.pop("evidence", None)
            if include_remediation:
                guidance = REMEDIATION_DATABASE.get(finding.category)
                if guidance:
                    finding_dict["remediation"] = {
                        "title": guidance.title,
                        "steps": guidance.steps,
                        "priority": guidance.priority,
                        "references": guidance.references,
                    }
            report["findings"].append(finding_dict)

        return json.dumps(report, indent=2, default=str)

    def _generate_markdown_report(
        self,
        findings: list[Finding],
        correlations: list[CorrelatedFinding],
        chains: list[AttackChain],
        include_evidence: bool,
        include_remediation: bool,
    ) -> str:
        """Generate Markdown format report."""
        lines: list[str] = []
        exec_summary = self.generate_executive_summary()

        # Header
        lines.append(f"# Security Assessment Report")
        lines.append(f"\n**Target:** {self._target or 'Not specified'}")
        lines.append(f"\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append(f"\n**Risk Level:** {exec_summary['overall_risk_level']}")
        lines.append(f"\n**Risk Score:** {exec_summary['overall_risk_score']}/10")

        # Executive Summary
        lines.append("\n\n## Executive Summary\n")
        lines.append(f"- **Total Findings:** {exec_summary['total_findings']}")
        lines.append(f"- **Unique Findings:** {exec_summary['unique_findings']}")
        lines.append(f"- **Attack Chains:** {exec_summary['attack_chains_detected']}")

        lines.append("\n### Severity Breakdown\n")
        for severity, count in exec_summary["by_severity"].items():
            lines.append(f"- **{severity.capitalize()}:** {count}")

        # Top Priorities
        if exec_summary["top_priorities"]:
            lines.append("\n### Top Priorities\n")
            for i, priority in enumerate(exec_summary["top_priorities"], 1):
                lines.append(
                    f"{i}. [{priority['severity'].upper()}] {priority['title']} ({priority['url']})"
                )

        # Attack Chains
        if chains:
            lines.append("\n\n## Attack Chains\n")
            for chain in chains:
                lines.append(f"\n### {chain.name}\n")
                lines.append(f"**Severity:** {chain.severity.value.capitalize()}")
                lines.append(f"\n**Impact:** {chain.impact}")
                lines.append("\n**Exploitation Steps:**")
                for step in chain.exploitation_steps:
                    lines.append(f"1. {step}")

        # Findings
        lines.append("\n\n## Detailed Findings\n")
        sorted_findings = sorted(
            findings, key=lambda x: x.severity.score, reverse=True
        )

        for finding in sorted_findings:
            lines.append(f"\n### {finding.title}\n")
            lines.append(f"**ID:** {finding.id}")
            lines.append(f"\n**Severity:** {finding.severity.value.capitalize()}")
            lines.append(f"\n**Category:** {finding.category}")
            lines.append(f"\n**URL:** {finding.url}")
            if finding.parameter:
                lines.append(f"\n**Parameter:** {finding.parameter}")
            lines.append(f"\n**Confidence:** {finding.confidence:.0%}")

            if finding.description:
                lines.append(f"\n\n**Description:**\n{finding.description}")

            if include_evidence and finding.evidence:
                lines.append(f"\n\n**Evidence:**\n```\n{finding.evidence}\n```")

            if include_remediation:
                guidance = REMEDIATION_DATABASE.get(finding.category)
                if guidance:
                    lines.append(f"\n\n**Remediation:**\n")
                    for step in guidance.steps[:3]:
                        lines.append(f"- {step}")
                    if guidance.references:
                        lines.append(f"\n**References:**")
                        for ref in guidance.references[:2]:
                            lines.append(f"- {ref}")

            lines.append("\n---")

        # Custom sections
        for section in self._custom_sections:
            lines.append(f"\n\n## {section.title}\n")
            lines.append(section.content)

        return "\n".join(lines)

    def _generate_html_report(
        self,
        findings: list[Finding],
        correlations: list[CorrelatedFinding],
        chains: list[AttackChain],
        include_evidence: bool,
        include_remediation: bool,
    ) -> str:
        """Generate HTML format report."""
        exec_summary = self.generate_executive_summary()

        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
        }

        html_parts: list[str] = []

        # HTML header
        html_parts.append("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1, h2, h3 { color: #333; }
        .summary-box { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .severity { padding: 4px 8px; border-radius: 4px; color: white; font-weight: bold; }
        .finding { border: 1px solid #ddd; padding: 15px; margin: 15px 0; border-radius: 8px; }
        .finding h3 { margin-top: 0; }
        .evidence { background: #f1f1f1; padding: 10px; border-radius: 4px; font-family: monospace; overflow-x: auto; }
        .attack-chain { background: #fff3cd; padding: 15px; border-radius: 8px; margin: 15px 0; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
    </style>
</head>
<body>
""")

        # Title and metadata
        html_parts.append(f"""
<h1>Security Assessment Report</h1>
<div class="summary-box">
    <p><strong>Target:</strong> {self._target or 'Not specified'}</p>
    <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
    <p><strong>Risk Level:</strong> <span class="severity" style="background-color: {severity_colors.get(exec_summary['overall_risk_level'].lower(), '#6c757d')}">{exec_summary['overall_risk_level']}</span></p>
    <p><strong>Risk Score:</strong> {exec_summary['overall_risk_score']}/10</p>
</div>
""")

        # Executive Summary
        html_parts.append(f"""
<h2>Executive Summary</h2>
<table>
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Total Findings</td><td>{exec_summary['total_findings']}</td></tr>
    <tr><td>Unique Findings</td><td>{exec_summary['unique_findings']}</td></tr>
    <tr><td>Attack Chains</td><td>{exec_summary['attack_chains_detected']}</td></tr>
</table>
""")

        # Severity breakdown
        html_parts.append("<h3>Severity Breakdown</h3><ul>")
        for severity, count in exec_summary["by_severity"].items():
            color = severity_colors.get(severity, "#6c757d")
            html_parts.append(
                f'<li><span class="severity" style="background-color: {color}">{severity.capitalize()}</span>: {count}</li>'
            )
        html_parts.append("</ul>")

        # Attack Chains
        if chains:
            html_parts.append("<h2>Attack Chains</h2>")
            for chain in chains:
                html_parts.append(f"""
<div class="attack-chain">
    <h3>{chain.name}</h3>
    <p><strong>Severity:</strong> {chain.severity.value.capitalize()}</p>
    <p><strong>Impact:</strong> {chain.impact}</p>
    <p><strong>Steps:</strong></p>
    <ol>
""")
                for step in chain.exploitation_steps:
                    html_parts.append(f"<li>{step}</li>")
                html_parts.append("</ol></div>")

        # Findings
        html_parts.append("<h2>Detailed Findings</h2>")
        sorted_findings = sorted(
            findings, key=lambda x: x.severity.score, reverse=True
        )

        for finding in sorted_findings:
            color = severity_colors.get(finding.severity.value, "#6c757d")
            html_parts.append(f"""
<div class="finding">
    <h3>{finding.title}</h3>
    <p><span class="severity" style="background-color: {color}">{finding.severity.value.capitalize()}</span></p>
    <p><strong>ID:</strong> {finding.id}</p>
    <p><strong>Category:</strong> {finding.category}</p>
    <p><strong>URL:</strong> <code>{finding.url}</code></p>
""")
            if finding.parameter:
                html_parts.append(
                    f"<p><strong>Parameter:</strong> <code>{finding.parameter}</code></p>"
                )

            html_parts.append(
                f"<p><strong>Confidence:</strong> {finding.confidence:.0%}</p>"
            )

            if finding.description:
                html_parts.append(
                    f"<p><strong>Description:</strong> {finding.description}</p>"
                )

            if include_evidence and finding.evidence:
                html_parts.append(
                    f'<p><strong>Evidence:</strong></p><div class="evidence">{finding.evidence}</div>'
                )

            if include_remediation:
                guidance = REMEDIATION_DATABASE.get(finding.category)
                if guidance:
                    html_parts.append("<p><strong>Remediation:</strong></p><ul>")
                    for step in guidance.steps[:3]:
                        html_parts.append(f"<li>{step}</li>")
                    html_parts.append("</ul>")

            html_parts.append("</div>")

        # Close HTML
        html_parts.append("</body></html>")

        return "".join(html_parts)

    def _generate_text_report(
        self,
        findings: list[Finding],
        correlations: list[CorrelatedFinding],
        chains: list[AttackChain],
        include_evidence: bool,
    ) -> str:
        """Generate plain text format report."""
        lines: list[str] = []
        exec_summary = self.generate_executive_summary()

        lines.append("=" * 60)
        lines.append("SECURITY ASSESSMENT REPORT")
        lines.append("=" * 60)
        lines.append(f"Target: {self._target or 'Not specified'}")
        lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append(f"Risk Level: {exec_summary['overall_risk_level']}")
        lines.append(f"Risk Score: {exec_summary['overall_risk_score']}/10")
        lines.append("")

        lines.append("-" * 60)
        lines.append("SUMMARY")
        lines.append("-" * 60)
        lines.append(f"Total Findings: {exec_summary['total_findings']}")
        lines.append(f"Unique Findings: {exec_summary['unique_findings']}")
        lines.append(f"Attack Chains: {exec_summary['attack_chains_detected']}")
        lines.append("")

        # Findings
        lines.append("-" * 60)
        lines.append("FINDINGS")
        lines.append("-" * 60)

        sorted_findings = sorted(
            findings, key=lambda x: x.severity.score, reverse=True
        )

        for finding in sorted_findings:
            lines.append("")
            lines.append(f"[{finding.severity.value.upper()}] {finding.title}")
            lines.append(f"  ID: {finding.id}")
            lines.append(f"  Category: {finding.category}")
            lines.append(f"  URL: {finding.url}")
            if finding.parameter:
                lines.append(f"  Parameter: {finding.parameter}")
            if include_evidence and finding.evidence:
                lines.append(f"  Evidence: {finding.evidence[:100]}...")

        return "\n".join(lines)

    def export_findings(
        self, format_type: str = "json", file_path: str | None = None
    ) -> dict[str, Any]:
        """Export findings to a file or return as string."""
        engine = get_correlation_engine()
        findings = engine.get_all_findings()

        if format_type == "json":
            content = json.dumps(
                [f.to_dict() for f in findings], indent=2, default=str
            )
        elif format_type == "csv":
            lines = ["id,title,severity,category,url,parameter,confidence"]
            for f in findings:
                lines.append(
                    f'"{f.id}","{f.title}","{f.severity.value}","{f.category}","{f.url}","{f.parameter or ""}",{f.confidence}'
                )
            content = "\n".join(lines)
        else:
            content = "\n".join(f"{f.id}: {f.title}" for f in findings)

        result = {
            "success": True,
            "format": format_type,
            "count": len(findings),
        }

        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(content)
                result["file_path"] = file_path
            except OSError as e:
                result["success"] = False
                result["error"] = str(e)
        else:
            result["content"] = content

        return result

    def get_remediation_guidance(self, category: str) -> dict[str, Any]:
        """Get remediation guidance for a vulnerability category."""
        guidance = REMEDIATION_DATABASE.get(category)

        if not guidance:
            return {
                "success": False,
                "error": f"No remediation guidance found for category: {category}",
                "available_categories": list(REMEDIATION_DATABASE.keys()),
            }

        return {
            "success": True,
            "guidance": {
                "category": guidance.category,
                "title": guidance.title,
                "description": guidance.description,
                "steps": guidance.steps,
                "references": guidance.references,
                "priority": guidance.priority,
                "estimated_effort": guidance.estimated_effort,
            },
        }

    def clear(self) -> None:
        """Clear custom sections."""
        self._custom_sections.clear()


def get_report_generator() -> ReportGenerator:
    """Get the singleton report generator instance."""
    return ReportGenerator()
