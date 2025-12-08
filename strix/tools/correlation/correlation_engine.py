"""
Vulnerability Correlation Engine.

Correlates findings from multiple sources to:
- Identify attack chains
- Reduce false positives through cross-validation
- Calculate combined severity scores
- Group related vulnerabilities
"""

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable


class CorrelationType(Enum):
    """Types of correlation relationships."""

    SAME_ENDPOINT = "same_endpoint"
    SAME_PARAMETER = "same_parameter"
    ATTACK_CHAIN = "attack_chain"
    AMPLIFICATION = "amplification"
    PREREQUISITE = "prerequisite"
    RELATED_VULN = "related_vulnerability"
    DUPLICATE = "duplicate"
    FALSE_POSITIVE = "false_positive"


class Severity(Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        """Numeric score for severity."""
        scores = {
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 3,
            "info": 1,
        }
        return scores.get(self.value, 0)


@dataclass
class Finding:
    """Represents a security finding from any tool."""

    id: str
    title: str
    description: str
    severity: Severity
    category: str  # e.g., "xss", "sqli", "idor"
    url: str
    parameter: str | None = None
    evidence: str = ""
    tool: str = ""  # Source tool
    timestamp: datetime = field(default_factory=datetime.now)
    confidence: float = 0.5  # 0.0 to 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category,
            "url": self.url,
            "parameter": self.parameter,
            "evidence": self.evidence[:200] if len(self.evidence) > 200 else self.evidence,
            "tool": self.tool,
            "timestamp": self.timestamp.isoformat(),
            "confidence": self.confidence,
        }

    def get_fingerprint(self) -> str:
        """Generate unique fingerprint for deduplication."""
        content = f"{self.category}:{self.url}:{self.parameter or ''}:{self.title}"
        return hashlib.md5(content.encode()).hexdigest()[:16]


@dataclass
class CorrelatedFinding:
    """A finding with correlation information."""

    primary_finding: Finding
    related_findings: list[Finding]
    correlation_type: CorrelationType
    combined_severity: Severity
    combined_confidence: float
    attack_chain_position: int | None = None
    correlation_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "primary": self.primary_finding.to_dict(),
            "related_count": len(self.related_findings),
            "related_ids": [f.id for f in self.related_findings],
            "correlation_type": self.correlation_type.value,
            "combined_severity": self.combined_severity.value,
            "combined_confidence": round(self.combined_confidence, 2),
            "attack_chain_position": self.attack_chain_position,
            "correlation_reasons": self.correlation_reasons,
        }


@dataclass
class AttackChain:
    """Represents a chain of vulnerabilities that can be exploited together."""

    id: str
    name: str
    description: str
    findings: list[Finding]
    severity: Severity
    impact: str
    exploitation_steps: list[str]
    prerequisites: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "finding_count": len(self.findings),
            "finding_ids": [f.id for f in self.findings],
            "severity": self.severity.value,
            "impact": self.impact,
            "exploitation_steps": self.exploitation_steps,
            "prerequisites": self.prerequisites,
        }


@dataclass
class CorrelationRule:
    """Rule for correlating findings."""

    name: str
    description: str
    match_function: Callable[[Finding, Finding], bool]
    correlation_type: CorrelationType
    confidence_boost: float = 0.1  # How much to increase confidence
    severity_impact: int = 0  # Positive increases, negative decreases


# Predefined correlation rules
def _same_endpoint_rule(f1: Finding, f2: Finding) -> bool:
    """Check if findings are on the same endpoint."""
    return f1.url == f2.url and f1.id != f2.id


def _same_parameter_rule(f1: Finding, f2: Finding) -> bool:
    """Check if findings affect the same parameter."""
    return (
        f1.parameter is not None
        and f1.parameter == f2.parameter
        and f1.url == f2.url
        and f1.id != f2.id
    )


def _sqli_to_data_exposure_rule(f1: Finding, f2: Finding) -> bool:
    """SQL injection can lead to data exposure."""
    return (
        f1.category == "sqli"
        and f2.category in ["data_exposure", "information_disclosure"]
        and _same_endpoint_rule(f1, f2)
    )


def _auth_bypass_to_idor_rule(f1: Finding, f2: Finding) -> bool:
    """Auth bypass can enable IDOR exploitation."""
    return (
        f1.category in ["auth_bypass", "broken_auth"]
        and f2.category == "idor"
    )


def _xss_to_csrf_rule(f1: Finding, f2: Finding) -> bool:
    """XSS can be used to bypass CSRF protections."""
    return f1.category == "xss" and f2.category == "csrf"


def _ssrf_to_internal_access_rule(f1: Finding, f2: Finding) -> bool:
    """SSRF can lead to internal service access."""
    return (
        f1.category == "ssrf"
        and f2.category in ["internal_access", "data_exposure", "rce"]
    )


DEFAULT_CORRELATION_RULES = [
    CorrelationRule(
        name="same_endpoint",
        description="Findings on the same endpoint are likely related",
        match_function=_same_endpoint_rule,
        correlation_type=CorrelationType.SAME_ENDPOINT,
        confidence_boost=0.05,
    ),
    CorrelationRule(
        name="same_parameter",
        description="Findings affecting the same parameter are likely related",
        match_function=_same_parameter_rule,
        correlation_type=CorrelationType.SAME_PARAMETER,
        confidence_boost=0.1,
    ),
    CorrelationRule(
        name="sqli_data_exposure_chain",
        description="SQL injection leading to data exposure",
        match_function=_sqli_to_data_exposure_rule,
        correlation_type=CorrelationType.ATTACK_CHAIN,
        confidence_boost=0.2,
        severity_impact=1,
    ),
    CorrelationRule(
        name="auth_bypass_idor_chain",
        description="Authentication bypass enabling IDOR",
        match_function=_auth_bypass_to_idor_rule,
        correlation_type=CorrelationType.ATTACK_CHAIN,
        confidence_boost=0.15,
        severity_impact=2,
    ),
    CorrelationRule(
        name="xss_csrf_chain",
        description="XSS can bypass CSRF protections",
        match_function=_xss_to_csrf_rule,
        correlation_type=CorrelationType.AMPLIFICATION,
        confidence_boost=0.1,
        severity_impact=1,
    ),
    CorrelationRule(
        name="ssrf_internal_chain",
        description="SSRF leading to internal service access",
        match_function=_ssrf_to_internal_access_rule,
        correlation_type=CorrelationType.ATTACK_CHAIN,
        confidence_boost=0.2,
        severity_impact=2,
    ),
]


class CorrelationEngine:
    """
    Engine for correlating security findings across tools and attack vectors.

    Features:
    - Deduplication based on fingerprints
    - Attack chain detection
    - Confidence score aggregation
    - False positive reduction
    """

    _instance: "CorrelationEngine | None" = None

    def __new__(cls) -> "CorrelationEngine":
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialize the correlation engine."""
        if self._initialized:
            return
        self._initialized = True
        self._findings: dict[str, Finding] = {}
        self._correlations: dict[str, CorrelatedFinding] = {}
        self._attack_chains: list[AttackChain] = []
        self._rules: list[CorrelationRule] = DEFAULT_CORRELATION_RULES.copy()
        self._fingerprints: dict[str, str] = {}  # fingerprint -> finding_id

    def add_finding(self, finding: Finding) -> tuple[bool, str]:
        """
        Add a finding to the engine.

        Returns:
            Tuple of (is_new, finding_id or duplicate_id)
        """
        fingerprint = finding.get_fingerprint()

        # Check for duplicates
        if fingerprint in self._fingerprints:
            existing_id = self._fingerprints[fingerprint]
            existing = self._findings.get(existing_id)
            if existing:
                # Update confidence if new finding has higher confidence
                if finding.confidence > existing.confidence:
                    existing.confidence = finding.confidence
                return False, existing_id

        self._findings[finding.id] = finding
        self._fingerprints[fingerprint] = finding.id
        return True, finding.id

    def add_rule(self, rule: CorrelationRule) -> None:
        """Add a custom correlation rule."""
        self._rules.append(rule)

    def correlate_all(self) -> list[CorrelatedFinding]:
        """
        Correlate all findings using defined rules.

        Returns:
            List of correlated findings
        """
        findings_list = list(self._findings.values())
        self._correlations.clear()

        for i, f1 in enumerate(findings_list):
            related: list[tuple[Finding, CorrelationRule]] = []

            for j, f2 in enumerate(findings_list):
                if i == j:
                    continue

                for rule in self._rules:
                    if rule.match_function(f1, f2):
                        related.append((f2, rule))
                        break

            if related:
                correlated = self._create_correlated_finding(f1, related)
                self._correlations[f1.id] = correlated

        # Detect attack chains
        self._detect_attack_chains()

        return list(self._correlations.values())

    def _create_correlated_finding(
        self,
        primary: Finding,
        related: list[tuple[Finding, CorrelationRule]],
    ) -> CorrelatedFinding:
        """Create a correlated finding from primary and related findings."""
        related_findings = [r[0] for r in related]
        rules_applied = [r[1] for r in related]

        # Calculate combined confidence
        confidence_boost = sum(r.confidence_boost for r in rules_applied)
        combined_confidence = min(1.0, primary.confidence + confidence_boost)

        # Calculate combined severity
        severity_impact = sum(r.severity_impact for r in rules_applied)
        new_severity_score = min(10, primary.severity.score + severity_impact)
        combined_severity = self._score_to_severity(new_severity_score)

        # Determine primary correlation type
        correlation_type = CorrelationType.RELATED_VULN
        for rule in rules_applied:
            if rule.correlation_type == CorrelationType.ATTACK_CHAIN:
                correlation_type = CorrelationType.ATTACK_CHAIN
                break
            if rule.correlation_type == CorrelationType.AMPLIFICATION:
                correlation_type = CorrelationType.AMPLIFICATION

        # Generate correlation reasons
        reasons = [f"Rule '{r.name}': {r.description}" for r in rules_applied]

        return CorrelatedFinding(
            primary_finding=primary,
            related_findings=related_findings,
            correlation_type=correlation_type,
            combined_severity=combined_severity,
            combined_confidence=combined_confidence,
            correlation_reasons=reasons,
        )

    def _score_to_severity(self, score: int) -> Severity:
        """Convert numeric score to severity enum."""
        if score >= 9:
            return Severity.CRITICAL
        if score >= 7:
            return Severity.HIGH
        if score >= 4:
            return Severity.MEDIUM
        if score >= 2:
            return Severity.LOW
        return Severity.INFO

    def _detect_attack_chains(self) -> None:
        """Detect attack chains from correlated findings."""
        self._attack_chains.clear()
        chain_id = 0

        # Look for chain patterns
        chain_patterns = [
            {
                "name": "Authentication Bypass to Data Theft",
                "categories": ["auth_bypass", "idor", "data_exposure"],
                "impact": "Complete unauthorized access to user data",
            },
            {
                "name": "SQL Injection to RCE",
                "categories": ["sqli", "file_upload", "rce"],
                "impact": "Remote code execution on database server",
            },
            {
                "name": "XSS to Account Takeover",
                "categories": ["xss", "session_hijacking", "csrf"],
                "impact": "Full account compromise",
            },
            {
                "name": "SSRF to Cloud Metadata",
                "categories": ["ssrf", "internal_access", "credential_exposure"],
                "impact": "Cloud infrastructure compromise",
            },
        ]

        for pattern in chain_patterns:
            chain_findings = []
            for category in pattern["categories"]:
                for finding in self._findings.values():
                    if finding.category == category:
                        chain_findings.append(finding)
                        break

            if len(chain_findings) >= 2:
                chain_id += 1
                max_severity = max(f.severity.score for f in chain_findings)

                chain = AttackChain(
                    id=f"chain_{chain_id}",
                    name=pattern["name"],
                    description=f"Attack chain involving {', '.join(pattern['categories'])}",
                    findings=chain_findings,
                    severity=self._score_to_severity(min(10, max_severity + 2)),
                    impact=pattern["impact"],
                    exploitation_steps=[
                        f"Step {i+1}: Exploit {f.category} at {f.url}"
                        for i, f in enumerate(chain_findings)
                    ],
                )
                self._attack_chains.append(chain)

    def get_attack_chains(self) -> list[AttackChain]:
        """Get detected attack chains."""
        return self._attack_chains

    def deduplicate(self) -> tuple[int, int]:
        """
        Deduplicate findings based on fingerprints.

        Returns:
            Tuple of (total_before, total_after)
        """
        before = len(self._findings)
        # Deduplication happens on add, so just return current stats
        return before, len(set(self._fingerprints.values()))

    def calculate_false_positive_score(self, finding: Finding) -> float:
        """
        Calculate false positive likelihood score.

        Returns:
            Score from 0.0 (likely real) to 1.0 (likely false positive)
        """
        fp_score = 0.0
        indicators = []

        # Low confidence is suspicious
        if finding.confidence < 0.3:
            fp_score += 0.3
            indicators.append("low_confidence")

        # No evidence is suspicious
        if not finding.evidence:
            fp_score += 0.2
            indicators.append("no_evidence")

        # Generic/common false positive patterns
        fp_patterns = [
            r"generic\s+error",
            r"connection\s+refused",
            r"timeout",
            r"waf\s+block",
            r"cloudflare",
            r"rate\s+limit",
        ]

        evidence_lower = finding.evidence.lower()
        for pattern in fp_patterns:
            if re.search(pattern, evidence_lower):
                fp_score += 0.15
                indicators.append(f"fp_pattern:{pattern}")

        # Check for correlation - findings with correlations are less likely FP
        if finding.id in self._correlations:
            corr = self._correlations[finding.id]
            if len(corr.related_findings) > 0:
                fp_score -= 0.2  # Correlated findings are more credible

        # Info severity with no correlation is suspicious
        if finding.severity == Severity.INFO and finding.id not in self._correlations:
            fp_score += 0.1

        return max(0.0, min(1.0, fp_score))

    def get_findings_summary(self) -> dict[str, Any]:
        """Get summary of all findings."""
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_tool: dict[str, int] = {}

        for finding in self._findings.values():
            sev = finding.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

            cat = finding.category
            by_category[cat] = by_category.get(cat, 0) + 1

            tool = finding.tool or "unknown"
            by_tool[tool] = by_tool.get(tool, 0) + 1

        return {
            "total_findings": len(self._findings),
            "unique_findings": len(set(self._fingerprints.values())),
            "correlated_findings": len(self._correlations),
            "attack_chains": len(self._attack_chains),
            "by_severity": by_severity,
            "by_category": by_category,
            "by_tool": by_tool,
        }

    def get_finding(self, finding_id: str) -> Finding | None:
        """Get a finding by ID."""
        return self._findings.get(finding_id)

    def get_all_findings(self) -> list[Finding]:
        """Get all findings."""
        return list(self._findings.values())

    def clear(self) -> int:
        """Clear all findings and correlations."""
        count = len(self._findings)
        self._findings.clear()
        self._correlations.clear()
        self._attack_chains.clear()
        self._fingerprints.clear()
        return count


def get_correlation_engine() -> CorrelationEngine:
    """Get the singleton correlation engine instance."""
    return CorrelationEngine()
