"""
Tests for Browser Security Testing module.
"""

import pytest

from strix.tools.browser_security.security_scanner import (
    BrowserSecurityScanner,
    SecurityFinding,
    Severity,
    VulnerabilityCategory,
    get_browser_security_scanner,
)


class TestSecurityFinding:
    """Tests for SecurityFinding dataclass."""

    def test_security_finding_creation(self) -> None:
        """Test creating a security finding."""
        finding = SecurityFinding(
            id="test_1",
            category=VulnerabilityCategory.XSS,
            severity=Severity.HIGH,
            title="Reflected XSS",
            description="Input is reflected in response",
            evidence="<script>alert(1)</script>",
            url="https://example.com/search",
            payload="<script>alert(1)</script>",
        )

        assert finding.category == VulnerabilityCategory.XSS
        assert finding.severity == Severity.HIGH
        assert finding.title == "Reflected XSS"
        assert finding.url == "https://example.com/search"

    def test_security_finding_to_dict(self) -> None:
        """Test converting finding to dictionary."""
        finding = SecurityFinding(
            id="test_2",
            category=VulnerabilityCategory.CORS,
            severity=Severity.MEDIUM,
            title="CORS Misconfiguration",
            description="Wildcard origin allowed",
            evidence="Access-Control-Allow-Origin: *",
        )

        result = finding.to_dict()

        assert result["category"] == "cors"
        assert result["severity"] == "medium"
        assert result["title"] == "CORS Misconfiguration"


class TestBrowserSecurityScanner:
    """Tests for BrowserSecurityScanner class."""

    def test_singleton_pattern(self) -> None:
        """Test that scanner follows singleton pattern."""
        scanner1 = get_browser_security_scanner()
        scanner2 = get_browser_security_scanner()
        assert scanner1 is scanner2

    def test_generate_xss_marker(self) -> None:
        """Test unique marker generation."""
        scanner = get_browser_security_scanner()
        marker1 = scanner._generate_xss_marker()
        marker2 = scanner._generate_xss_marker()

        assert marker1 != marker2
        assert "STRIX_XSS_" in marker1
        assert len(marker1) > 10

    def test_get_xss_payloads_html_context(self) -> None:
        """Test XSS payload generation for HTML context."""
        scanner = get_browser_security_scanner()
        payloads = scanner.get_xss_payloads("html", "TEST_MARKER")

        assert len(payloads) > 0
        assert all("TEST_MARKER" in p for p in payloads)
        assert any("<script>" in p for p in payloads)

    def test_get_xss_payloads_attribute_context(self) -> None:
        """Test XSS payload generation for attribute context."""
        scanner = get_browser_security_scanner()
        payloads = scanner.get_xss_payloads("attribute", "TEST_MARKER")

        assert len(payloads) > 0
        assert any("onmouseover" in p.lower() for p in payloads)

    def test_get_xss_payloads_javascript_context(self) -> None:
        """Test XSS payload generation for JavaScript context."""
        scanner = get_browser_security_scanner()
        payloads = scanner.get_xss_payloads("javascript", "TEST_MARKER")

        assert len(payloads) > 0
        assert any("</script>" in p for p in payloads)

    def test_detect_reflection_context_html(self) -> None:
        """Test detection of HTML reflection context."""
        scanner = get_browser_security_scanner()
        html_response = "<div>user_input_here</div>"
        context = scanner._detect_reflection_context("user_input_here", html_response)
        assert context == "html"

    def test_detect_reflection_context_attribute(self) -> None:
        """Test detection of attribute reflection context."""
        scanner = get_browser_security_scanner()
        attr_response = '<input value="user_input_here">'
        context = scanner._detect_reflection_context("user_input_here", attr_response)
        assert context == "attribute"

    def test_detect_reflection_context_javascript(self) -> None:
        """Test detection of script reflection context."""
        scanner = get_browser_security_scanner()
        script_response = '<script>var x = "user_input_here";</script>'
        context = scanner._detect_reflection_context("user_input_here", script_response)
        assert context == "javascript"

    def test_analyze_xss_reflection_found(self) -> None:
        """Test XSS reflection detection when input is reflected."""
        scanner = get_browser_security_scanner()
        response = '<div>Hello <script>alert(1)</script></div>'
        finding = scanner.analyze_xss_reflection(
            '<script>alert(1)</script>',
            response,
            'https://example.com/test'
        )

        assert finding is not None
        assert finding.category == VulnerabilityCategory.XSS
        assert finding.severity in [Severity.HIGH, Severity.MEDIUM]

    def test_analyze_xss_reflection_not_found(self) -> None:
        """Test XSS reflection when input is not reflected."""
        scanner = get_browser_security_scanner()
        response = '<div>Hello World</div>'
        finding = scanner.analyze_xss_reflection(
            '<script>alert(1)</script>',
            response,
            'https://example.com/test'
        )

        assert finding is None

    def test_analyze_clickjacking_no_protection(self) -> None:
        """Test clickjacking analysis with no protection."""
        scanner = get_browser_security_scanner()
        headers: dict[str, str] = {}
        findings = scanner.analyze_clickjacking(headers)

        assert len(findings) > 0
        assert any(f.category == VulnerabilityCategory.CLICKJACKING for f in findings)

    def test_analyze_clickjacking_with_xfo_deny(self) -> None:
        """Test clickjacking with X-Frame-Options: DENY."""
        scanner = get_browser_security_scanner()
        headers = {"X-Frame-Options": "DENY"}
        findings = scanner.analyze_clickjacking(headers)

        # Should have finding for missing frame-ancestors but not for XFO
        xfo_findings = [f for f in findings if "X-Frame-Options" in f.title]
        assert len(xfo_findings) == 0

    def test_analyze_clickjacking_with_csp_frame_ancestors(self) -> None:
        """Test clickjacking with CSP frame-ancestors."""
        scanner = get_browser_security_scanner()
        headers = {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "frame-ancestors 'none'"
        }
        findings = scanner.analyze_clickjacking(headers)

        # Should have no clickjacking findings
        assert len(findings) == 0

    def test_analyze_cors_wildcard(self) -> None:
        """Test CORS analysis with wildcard origin."""
        scanner = get_browser_security_scanner()
        headers = {"Access-Control-Allow-Origin": "*"}
        findings = scanner.analyze_cors(headers)

        assert len(findings) > 0
        assert any(f.category == VulnerabilityCategory.CORS for f in findings)

    def test_analyze_cors_with_credentials(self) -> None:
        """Test CORS analysis with credentials allowed."""
        scanner = get_browser_security_scanner()
        headers = {
            "Access-Control-Allow-Origin": "https://evil.com",
            "Access-Control-Allow-Credentials": "true",
        }
        findings = scanner.analyze_cors(headers, "https://evil.com", "https://example.com")

        assert len(findings) > 0

    def test_analyze_cors_no_headers(self) -> None:
        """Test CORS analysis with no CORS headers."""
        scanner = get_browser_security_scanner()
        headers: dict[str, str] = {}
        findings = scanner.analyze_cors(headers)

        # No CORS headers means no CORS findings
        assert len(findings) == 0


class TestVulnerabilityCategories:
    """Tests for vulnerability category enums."""

    def test_vulnerability_categories_exist(self) -> None:
        """Test that all expected vulnerability categories exist."""
        assert VulnerabilityCategory.XSS
        assert VulnerabilityCategory.CLICKJACKING
        assert VulnerabilityCategory.CORS
        assert VulnerabilityCategory.CSP
        assert VulnerabilityCategory.COOKIE
        assert VulnerabilityCategory.DOM

    def test_severity_levels_exist(self) -> None:
        """Test that all severity levels exist."""
        assert Severity.CRITICAL
        assert Severity.HIGH
        assert Severity.MEDIUM
        assert Severity.LOW
        assert Severity.INFO


class TestBrowserSecurityIntegration:
    """Integration tests for browser security scanner."""

    def test_full_security_analysis_flow(self) -> None:
        """Test complete security analysis workflow."""
        scanner = get_browser_security_scanner()

        # Test XSS reflection
        xss_response = '<div>test_payload</div>'
        xss_finding = scanner.analyze_xss_reflection('test_payload', xss_response)
        assert xss_finding is not None

        # Test clickjacking
        empty_headers: dict[str, str] = {}
        clickjack_findings = scanner.analyze_clickjacking(empty_headers)
        assert len(clickjack_findings) > 0

        # Test CORS
        cors_headers = {"Access-Control-Allow-Origin": "*"}
        cors_findings = scanner.analyze_cors(cors_headers)
        assert len(cors_findings) > 0

    def test_payload_generation_coverage(self) -> None:
        """Test that payload generation covers multiple attack vectors."""
        scanner = get_browser_security_scanner()
        payloads = scanner.get_xss_payloads("html", "MARKER")

        # Should have various payload types
        has_script_tag = any("<script" in p.lower() for p in payloads)
        has_event_handler = any("onerror" in p.lower() or "onload" in p.lower() for p in payloads)
        has_svg = any("<svg" in p.lower() for p in payloads)
        has_img = any("<img" in p.lower() for p in payloads)

        assert has_script_tag, "Should have script tag payloads"
        assert has_event_handler, "Should have event handler payloads"
        # SVG or IMG depends on implementation
        assert has_svg or has_img, "Should have SVG or IMG payloads"

    def test_finding_id_generation(self) -> None:
        """Test that finding IDs are unique."""
        scanner = get_browser_security_scanner()
        id1 = scanner._generate_finding_id()
        id2 = scanner._generate_finding_id()

        assert id1 != id2
        assert "finding_" in id1
