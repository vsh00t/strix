"""
Vulnerability Correlation Engine for DAST.

Provides intelligent correlation of findings across different tools
and attack vectors to identify attack chains and reduce false positives.
"""

from strix.tools.correlation.correlation_engine import (
    AttackChain,
    CorrelatedFinding,
    CorrelationEngine,
    CorrelationRule,
    CorrelationType,
    Finding,
    Severity,
    get_correlation_engine,
)

from strix.tools.correlation.correlation_actions import (
    add_finding,
    check_false_positive,
    clear_correlation_engine,
    correlate_findings,
    deduplicate_findings,
    get_attack_chains,
    get_findings_summary,
)

__all__ = [
    # Engine classes
    "AttackChain",
    "CorrelatedFinding",
    "CorrelationEngine",
    "CorrelationRule",
    "CorrelationType",
    "Finding",
    "Severity",
    "get_correlation_engine",
    # Actions
    "add_finding",
    "check_false_positive",
    "clear_correlation_engine",
    "correlate_findings",
    "deduplicate_findings",
    "get_attack_chains",
    "get_findings_summary",
]
