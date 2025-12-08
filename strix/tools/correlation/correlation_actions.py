"""
Correlation Engine actions for the tool registry.
"""

from typing import Any

from strix.tools.correlation.correlation_engine import (
    Finding,
    Severity,
    get_correlation_engine,
)
from strix.tools.registry import register_tool


@register_tool
def add_finding(
    finding_id: str,
    title: str,
    category: str,
    url: str = "",
    severity: str = "medium",
    description: str = "",
    parameter: str | None = None,
    evidence: str = "",
    tool: str = "",
    confidence: float = 0.5,
) -> dict[str, Any]:
    """Add a security finding to the correlation engine for analysis."""
    try:
        if not finding_id or not title or not category:
            return {"success": False, "error": "finding_id, title, and category are required"}

        # Map severity string to enum
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        severity_enum = severity_map.get(severity.lower(), Severity.MEDIUM)

        finding = Finding(
            id=finding_id,
            title=title,
            description=description,
            severity=severity_enum,
            category=category,
            url=url,
            parameter=parameter,
            evidence=evidence,
            tool=tool,
            confidence=confidence,
        )

        engine = get_correlation_engine()
        is_new, result_id = engine.add_finding(finding)

        return {
            "success": True,
            "is_new": is_new,
            "finding_id": result_id,
            "message": "Finding added" if is_new else f"Duplicate of {result_id}",
        }
    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to add finding: {e}"}


@register_tool
def correlate_findings() -> dict[str, Any]:
    """Run correlation analysis on all collected findings."""
    try:
        engine = get_correlation_engine()
        correlations = engine.correlate_all()
        attack_chains = engine.get_attack_chains()

        return {
            "success": True,
            "correlations_found": len(correlations),
            "attack_chains_detected": len(attack_chains),
            "correlations": [c.to_dict() for c in correlations[:10]],
            "attack_chains": [a.to_dict() for a in attack_chains],
        }
    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to correlate findings: {e}"}


@register_tool
def get_attack_chains() -> dict[str, Any]:
    """Get all detected attack chains from correlated findings."""
    try:
        engine = get_correlation_engine()
        chains = engine.get_attack_chains()

        return {
            "success": True,
            "count": len(chains),
            "attack_chains": [c.to_dict() for c in chains],
        }
    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to get attack chains: {e}"}


@register_tool
def get_findings_summary() -> dict[str, Any]:
    """Get summary statistics of all findings in the correlation engine."""
    try:
        engine = get_correlation_engine()
        summary = engine.get_findings_summary()

        return {
            "success": True,
            "summary": summary,
        }
    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to get findings summary: {e}"}


@register_tool
def check_false_positive(finding_id: str) -> dict[str, Any]:
    """Check if a finding is likely a false positive."""
    try:
        if not finding_id:
            return {"success": False, "error": "finding_id is required"}

        engine = get_correlation_engine()
        finding = engine.get_finding(finding_id)

        if not finding:
            return {"success": False, "error": f"Finding '{finding_id}' not found"}

        fp_score = engine.calculate_false_positive_score(finding)

        assessment = "likely_real"
        if fp_score > 0.7:
            assessment = "likely_false_positive"
        elif fp_score > 0.4:
            assessment = "needs_verification"

        return {
            "success": True,
            "finding_id": finding_id,
            "false_positive_score": round(fp_score, 2),
            "assessment": assessment,
            "recommendation": (
                "Verify manually - high FP likelihood"
                if fp_score > 0.5
                else "Likely valid finding - proceed with reporting"
            ),
        }
    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to check false positive: {e}"}


@register_tool
def deduplicate_findings() -> dict[str, Any]:
    """Deduplicate findings based on fingerprints."""
    try:
        engine = get_correlation_engine()
        before, after = engine.deduplicate()

        return {
            "success": True,
            "total_before": before,
            "unique_findings": after,
            "duplicates_removed": before - after,
        }
    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to deduplicate findings: {e}"}


@register_tool
def clear_correlation_engine() -> dict[str, Any]:
    """Clear all findings and correlations from the engine."""
    try:
        engine = get_correlation_engine()
        count = engine.clear()

        return {
            "success": True,
            "findings_cleared": count,
        }
    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to clear correlation engine: {e}"}
