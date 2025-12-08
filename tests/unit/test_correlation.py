"""Unit tests for the Correlation Engine module."""

import pytest

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


@pytest.fixture
def engine() -> CorrelationEngine:
    """Get a fresh correlation engine instance."""
    engine = get_correlation_engine()
    engine.clear()
    return engine


@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample finding."""
    return Finding(
        id="test_001",
        title="SQL Injection in login",
        description="User input is concatenated into SQL query",
        severity=Severity.HIGH,
        category="sqli",
        url="https://example.com/api/login",
        parameter="username",
        evidence="Database error: syntax error",
        tool="browser",
        confidence=0.85,
    )


class TestSeverity:
    """Tests for the Severity enum."""

    def test_severity_values(self) -> None:
        """Test severity enum values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_scores(self) -> None:
        """Test severity scores."""
        assert Severity.CRITICAL.score == 10
        assert Severity.HIGH.score == 8
        assert Severity.MEDIUM.score == 5
        assert Severity.LOW.score == 3
        assert Severity.INFO.score == 1


class TestFinding:
    """Tests for the Finding dataclass."""

    def test_finding_creation(self, sample_finding: Finding) -> None:
        """Test creating a finding."""
        assert sample_finding.id == "test_001"
        assert sample_finding.title == "SQL Injection in login"
        assert sample_finding.severity == Severity.HIGH
        assert sample_finding.category == "sqli"
        assert sample_finding.confidence == 0.85

    def test_finding_to_dict(self, sample_finding: Finding) -> None:
        """Test converting finding to dictionary."""
        result = sample_finding.to_dict()
        assert result["id"] == "test_001"
        assert result["title"] == "SQL Injection in login"
        assert result["severity"] == "high"
        assert result["category"] == "sqli"

    def test_finding_fingerprint(self, sample_finding: Finding) -> None:
        """Test fingerprint generation."""
        fingerprint = sample_finding.get_fingerprint()
        assert len(fingerprint) == 16

        # Same content should produce same fingerprint
        duplicate = Finding(
            id="different_id",
            title=sample_finding.title,
            description="Different description",
            severity=Severity.MEDIUM,  # Different severity
            category=sample_finding.category,
            url=sample_finding.url,
            parameter=sample_finding.parameter,
            evidence="Different evidence",
            tool="different_tool",
            confidence=0.5,
        )
        assert duplicate.get_fingerprint() == fingerprint


class TestCorrelationEngine:
    """Tests for the CorrelationEngine class."""

    def test_singleton_pattern(self) -> None:
        """Test that correlation engine is a singleton."""
        engine1 = get_correlation_engine()
        engine2 = get_correlation_engine()
        assert engine1 is engine2

    def test_add_finding(self, engine: CorrelationEngine, sample_finding: Finding) -> None:
        """Test adding a finding."""
        is_new, finding_id = engine.add_finding(sample_finding)
        assert is_new is True
        assert finding_id == "test_001"

    def test_add_duplicate_finding(self, engine: CorrelationEngine) -> None:
        """Test adding duplicate findings."""
        finding1 = Finding(
            id="test_001",
            title="SQL Injection",
            description="Test",
            severity=Severity.HIGH,
            category="sqli",
            url="https://example.com/api",
            confidence=0.5,
        )
        finding2 = Finding(
            id="test_002",
            title="SQL Injection",  # Same title
            description="Different",
            severity=Severity.HIGH,
            category="sqli",  # Same category
            url="https://example.com/api",  # Same URL
            confidence=0.8,
        )

        is_new1, _ = engine.add_finding(finding1)
        is_new2, dup_id = engine.add_finding(finding2)

        assert is_new1 is True
        assert is_new2 is False
        assert dup_id == "test_001"

    def test_get_finding(self, engine: CorrelationEngine, sample_finding: Finding) -> None:
        """Test retrieving a finding by ID."""
        engine.add_finding(sample_finding)
        
        result = engine.get_finding("test_001")
        assert result is not None
        assert result.id == "test_001"

        assert engine.get_finding("nonexistent") is None

    def test_get_all_findings(self, engine: CorrelationEngine) -> None:
        """Test getting all findings."""
        for i in range(5):
            finding = Finding(
                id=f"test_{i}",
                title=f"Finding {i}",
                description="Test",
                severity=Severity.MEDIUM,
                category=f"category_{i}",
                url=f"https://example.com/endpoint_{i}",
            )
            engine.add_finding(finding)

        findings = engine.get_all_findings()
        assert len(findings) == 5

    def test_clear(self, engine: CorrelationEngine, sample_finding: Finding) -> None:
        """Test clearing all findings."""
        engine.add_finding(sample_finding)
        count = engine.clear()
        
        assert count == 1
        assert len(engine.get_all_findings()) == 0

    def test_deduplicate(self, engine: CorrelationEngine) -> None:
        """Test deduplication returns correct counts."""
        for i in range(3):
            finding = Finding(
                id=f"test_{i}",
                title=f"Finding {i}",
                description="Test",
                severity=Severity.MEDIUM,
                category=f"category_{i}",
                url=f"https://example.com/endpoint_{i}",
            )
            engine.add_finding(finding)

        before, after = engine.deduplicate()
        assert before == 3
        assert after == 3  # No duplicates added

    def test_get_findings_summary(self, engine: CorrelationEngine) -> None:
        """Test getting findings summary."""
        findings = [
            Finding(id="1", title="High1", description="", severity=Severity.HIGH, 
                    category="sqli", url="https://a.com", tool="browser"),
            Finding(id="2", title="High2", description="", severity=Severity.HIGH,
                    category="sqli", url="https://b.com", tool="fuzzer"),
            Finding(id="3", title="Med1", description="", severity=Severity.MEDIUM,
                    category="xss", url="https://c.com", tool="browser"),
        ]
        for f in findings:
            engine.add_finding(f)

        summary = engine.get_findings_summary()
        
        assert summary["total_findings"] == 3
        assert summary["by_severity"]["high"] == 2
        assert summary["by_severity"]["medium"] == 1
        assert summary["by_category"]["sqli"] == 2
        assert summary["by_category"]["xss"] == 1
        assert summary["by_tool"]["browser"] == 2


class TestCorrelation:
    """Tests for correlation functionality."""

    def test_correlate_same_endpoint(self, engine: CorrelationEngine) -> None:
        """Test correlating findings on same endpoint."""
        finding1 = Finding(
            id="sqli_1",
            title="SQL Injection",
            description="",
            severity=Severity.HIGH,
            category="sqli",
            url="https://example.com/api/users",
        )
        finding2 = Finding(
            id="xss_1",
            title="XSS",
            description="",
            severity=Severity.MEDIUM,
            category="xss",
            url="https://example.com/api/users",  # Same endpoint
        )

        engine.add_finding(finding1)
        engine.add_finding(finding2)
        correlations = engine.correlate_all()

        assert len(correlations) >= 1

    def test_correlate_same_parameter(self, engine: CorrelationEngine) -> None:
        """Test correlating findings on same parameter."""
        finding1 = Finding(
            id="sqli_1",
            title="SQL Injection",
            description="",
            severity=Severity.HIGH,
            category="sqli",
            url="https://example.com/api/users",
            parameter="id",
        )
        finding2 = Finding(
            id="idor_1",
            title="IDOR",
            description="",
            severity=Severity.HIGH,
            category="idor",
            url="https://example.com/api/users",
            parameter="id",  # Same parameter
        )

        engine.add_finding(finding1)
        engine.add_finding(finding2)
        correlations = engine.correlate_all()

        assert len(correlations) >= 1


class TestAttackChains:
    """Tests for attack chain detection."""

    def test_detect_attack_chain(self, engine: CorrelationEngine) -> None:
        """Test detecting an attack chain."""
        # Add findings that form a chain
        findings = [
            Finding(id="1", title="Auth Bypass", description="",
                    severity=Severity.HIGH, category="auth_bypass",
                    url="https://example.com/login"),
            Finding(id="2", title="IDOR", description="",
                    severity=Severity.HIGH, category="idor",
                    url="https://example.com/api/users"),
        ]
        for f in findings:
            engine.add_finding(f)

        engine.correlate_all()
        chains = engine.get_attack_chains()

        # Should detect auth_bypass -> idor chain
        assert len(chains) >= 1

    def test_attack_chain_to_dict(self) -> None:
        """Test converting attack chain to dictionary."""
        chain = AttackChain(
            id="chain_1",
            name="Test Chain",
            description="A test attack chain",
            findings=[],
            severity=Severity.HIGH,
            impact="High impact",
            exploitation_steps=["Step 1", "Step 2"],
        )
        
        result = chain.to_dict()
        assert result["id"] == "chain_1"
        assert result["name"] == "Test Chain"
        assert result["severity"] == "high"
        assert len(result["exploitation_steps"]) == 2


class TestFalsePositiveDetection:
    """Tests for false positive detection."""

    def test_low_confidence_fp_score(self, engine: CorrelationEngine) -> None:
        """Test that low confidence findings have higher FP scores."""
        finding = Finding(
            id="test_1",
            title="Maybe vuln",
            description="",
            severity=Severity.LOW,
            category="xss",
            url="https://example.com",
            confidence=0.2,
            evidence="",  # No evidence
        )
        engine.add_finding(finding)
        
        fp_score = engine.calculate_false_positive_score(finding)
        assert fp_score >= 0.4  # Low confidence + no evidence

    def test_high_confidence_fp_score(self, engine: CorrelationEngine) -> None:
        """Test that high confidence findings have lower FP scores."""
        finding = Finding(
            id="test_1",
            title="Definite vuln",
            description="",
            severity=Severity.HIGH,
            category="sqli",
            url="https://example.com",
            confidence=0.95,
            evidence="Error: SQL syntax error at line 1",
        )
        engine.add_finding(finding)
        
        fp_score = engine.calculate_false_positive_score(finding)
        assert fp_score < 0.3


class TestCorrelationActions:
    """Tests for correlation action functions."""

    @pytest.mark.asyncio
    async def test_add_finding_action(self, engine: CorrelationEngine) -> None:
        """Test add_finding action."""
        from strix.tools.correlation.correlation_actions import add_finding as action_add_finding

        result = action_add_finding(
            finding_id="action_test_1",
            title="Test Finding",
            category="xss",
            url="https://example.com/test",
            severity="high",
        )

        assert result["success"] is True
        assert result["is_new"] is True
        engine.clear()

    @pytest.mark.asyncio
    async def test_correlate_findings_action(self, engine: CorrelationEngine) -> None:
        """Test correlate_findings action."""
        from strix.tools.correlation.correlation_actions import (
            add_finding as action_add_finding,
            correlate_findings as action_correlate,
        )

        # Add some findings
        action_add_finding(
            finding_id="1", title="Finding 1", category="sqli",
            url="https://example.com/api", severity="high"
        )
        action_add_finding(
            finding_id="2", title="Finding 2", category="xss",
            url="https://example.com/api", severity="medium"
        )

        result = action_correlate()
        
        assert result["success"] is True
        assert "correlations_found" in result
        engine.clear()

    @pytest.mark.asyncio
    async def test_get_findings_summary_action(self, engine: CorrelationEngine) -> None:
        """Test get_findings_summary action."""
        from strix.tools.correlation.correlation_actions import (
            add_finding as action_add_finding,
            get_findings_summary as action_summary,
        )

        action_add_finding(
            finding_id="1", title="Test", category="sqli",
            url="https://example.com", severity="high"
        )

        result = action_summary()
        
        assert result["success"] is True
        assert result["summary"]["total_findings"] == 1
        engine.clear()

    @pytest.mark.asyncio
    async def test_check_false_positive_action(self, engine: CorrelationEngine) -> None:
        """Test check_false_positive action."""
        from strix.tools.correlation.correlation_actions import (
            add_finding as action_add_finding,
            check_false_positive as action_check_fp,
        )

        action_add_finding(
            finding_id="fp_test", title="Test", category="xss",
            url="https://example.com", severity="low", confidence=0.2
        )

        result = action_check_fp(finding_id="fp_test")
        
        assert result["success"] is True
        assert "false_positive_score" in result
        assert "assessment" in result
        engine.clear()

    @pytest.mark.asyncio
    async def test_clear_correlation_engine_action(self, engine: CorrelationEngine) -> None:
        """Test clear_correlation_engine action."""
        from strix.tools.correlation.correlation_actions import (
            add_finding as action_add_finding,
            clear_correlation_engine as action_clear,
        )

        action_add_finding(
            finding_id="1", title="Test", category="sqli",
            url="https://example.com", severity="high"
        )

        result = action_clear()
        
        assert result["success"] is True
        assert result["findings_cleared"] >= 1


class TestCorrelatedFinding:
    """Tests for CorrelatedFinding dataclass."""

    def test_correlated_finding_to_dict(self, sample_finding: Finding) -> None:
        """Test converting correlated finding to dictionary."""
        correlated = CorrelatedFinding(
            primary_finding=sample_finding,
            related_findings=[],
            correlation_type=CorrelationType.SAME_ENDPOINT,
            combined_severity=Severity.HIGH,
            combined_confidence=0.9,
            correlation_reasons=["Same endpoint detected"],
        )

        result = correlated.to_dict()
        assert result["primary"]["id"] == "test_001"
        assert result["correlation_type"] == "same_endpoint"
        assert result["combined_confidence"] == 0.9


class TestCorrelationRule:
    """Tests for CorrelationRule dataclass."""

    def test_correlation_rule_creation(self) -> None:
        """Test creating a correlation rule."""
        rule = CorrelationRule(
            name="test_rule",
            description="A test rule",
            match_function=lambda f1, f2: f1.url == f2.url,
            correlation_type=CorrelationType.SAME_ENDPOINT,
            confidence_boost=0.15,
        )

        assert rule.name == "test_rule"
        assert rule.confidence_boost == 0.15

    def test_custom_rule_matching(self, engine: CorrelationEngine) -> None:
        """Test adding and using a custom rule."""
        custom_rule = CorrelationRule(
            name="custom_test",
            description="Custom test rule",
            match_function=lambda f1, f2: f1.category == f2.category and f1.id != f2.id,
            correlation_type=CorrelationType.RELATED_VULN,
            confidence_boost=0.1,
        )
        engine.add_rule(custom_rule)

        finding1 = Finding(
            id="1", title="XSS 1", description="",
            severity=Severity.MEDIUM, category="xss",
            url="https://a.com"
        )
        finding2 = Finding(
            id="2", title="XSS 2", description="",
            severity=Severity.MEDIUM, category="xss",
            url="https://b.com"
        )

        engine.add_finding(finding1)
        engine.add_finding(finding2)
        correlations = engine.correlate_all()

        assert len(correlations) >= 1
