"""
Tests for Authentication Testing module.
"""

import base64
import json
import time

import pytest

from strix.tools.auth_testing.auth_tester import (
    AccessControlTest,
    AuthenticationTester,
    AuthTestResult,
    AuthTestType,
    AuthVulnerability,
    JWTAnalysis,
    SessionAnalysis,
    get_auth_tester,
)


class TestJWTAnalysis:
    """Tests for JWTAnalysis dataclass."""

    def test_jwt_analysis_creation(self) -> None:
        """Test creating a JWT analysis result."""
        analysis = JWTAnalysis(
            valid_structure=True,
            header={"alg": "HS256", "typ": "JWT"},
            payload={"sub": "123", "name": "Test"},
            signature="abc123",
            algorithm="HS256",
            issues=["No expiration claim"],
            expiration=None,
            is_expired=False,
            claims={"sub": "123", "name": "Test"},
        )

        assert analysis.valid_structure is True
        assert analysis.algorithm == "HS256"
        assert len(analysis.issues) == 1

    def test_jwt_analysis_to_dict(self) -> None:
        """Test converting JWT analysis to dictionary."""
        analysis = JWTAnalysis(
            valid_structure=True,
            header={"alg": "HS256"},
            payload={"sub": "123"},
            signature="sig",
            algorithm="HS256",
            issues=[],
            expiration=1234567890,
            is_expired=True,
            claims={"sub": "123"},
        )

        result = analysis.to_dict()

        assert result["valid_structure"] is True
        assert result["algorithm"] == "HS256"
        assert result["is_expired"] is True


class TestSessionAnalysis:
    """Tests for SessionAnalysis dataclass."""

    def test_session_analysis_creation(self) -> None:
        """Test creating a session analysis result."""
        analysis = SessionAnalysis(
            token_value="abc123def456",
            entropy_bits=64.5,
            length=12,
            character_set="lowercase+digits",
            predictable_patterns=[],
            issues=["Low entropy"],
            cookie_flags={"httponly": True, "secure": True, "samesite": True},
        )

        assert analysis.entropy_bits == 64.5
        assert analysis.length == 12
        assert analysis.cookie_flags["httponly"] is True

    def test_session_analysis_to_dict_long_token(self) -> None:
        """Test token preview truncation."""
        analysis = SessionAnalysis(
            token_value="a" * 100,
            entropy_bits=100.0,
            length=100,
            character_set="lowercase",
            predictable_patterns=[],
            issues=[],
            cookie_flags={},
        )

        result = analysis.to_dict()

        assert len(result["token_preview"]) == 23  # 20 + "..."


class TestAuthTestResult:
    """Tests for AuthTestResult dataclass."""

    def test_auth_test_result_creation(self) -> None:
        """Test creating an auth test result."""
        result = AuthTestResult(
            test_type=AuthTestType.TOKEN_MANIPULATION,
            vulnerable=True,
            severity="critical",
            vulnerability=AuthVulnerability.JWT_WEAK_SECRET,
            evidence={"secret": "password"},
            recommendations=["Use strong secret"],
            details="Weak secret found",
        )

        assert result.vulnerable is True
        assert result.severity == "critical"

    def test_auth_test_result_to_dict(self) -> None:
        """Test converting result to dictionary."""
        result = AuthTestResult(
            test_type=AuthTestType.SESSION_FIXATION,
            vulnerable=False,
            severity="info",
            vulnerability=None,
            evidence={},
            recommendations=[],
            details="No vulnerability found",
        )

        output = result.to_dict()

        assert output["test_type"] == "session_fixation"
        assert output["vulnerability"] is None


class TestAuthTestTypes:
    """Tests for authentication test type enums."""

    def test_all_auth_test_types_exist(self) -> None:
        """Test that all expected auth test types exist."""
        assert AuthTestType.SESSION_FIXATION
        assert AuthTestType.SESSION_HIJACKING
        assert AuthTestType.PRIVILEGE_ESCALATION
        assert AuthTestType.HORIZONTAL_PRIVILEGE
        assert AuthTestType.VERTICAL_PRIVILEGE
        assert AuthTestType.TOKEN_MANIPULATION
        assert AuthTestType.BRUTE_FORCE
        assert AuthTestType.CREDENTIAL_STUFFING
        assert AuthTestType.ACCOUNT_ENUMERATION
        assert AuthTestType.PASSWORD_POLICY
        assert AuthTestType.MFA_BYPASS
        assert AuthTestType.OAUTH_MISCONFIGURATION

    def test_all_vulnerability_types_exist(self) -> None:
        """Test that all expected vulnerability types exist."""
        assert AuthVulnerability.WEAK_SESSION_ID
        assert AuthVulnerability.PREDICTABLE_TOKEN
        assert AuthVulnerability.INSECURE_COOKIE
        assert AuthVulnerability.MISSING_CSRF
        assert AuthVulnerability.JWT_WEAK_SECRET
        assert AuthVulnerability.JWT_ALG_NONE
        assert AuthVulnerability.JWT_KEY_CONFUSION
        assert AuthVulnerability.SESSION_NO_EXPIRY
        assert AuthVulnerability.CONCURRENT_SESSIONS
        assert AuthVulnerability.CREDENTIAL_LEAK
        assert AuthVulnerability.IDOR
        assert AuthVulnerability.BROKEN_ACCESS_CONTROL


class TestAuthenticationTester:
    """Tests for AuthenticationTester class."""

    def test_singleton_pattern(self) -> None:
        """Test that tester follows singleton pattern."""
        tester1 = get_auth_tester()
        tester2 = get_auth_tester()
        assert tester1 is tester2

    def test_analyze_jwt_valid(self) -> None:
        """Test JWT analysis with valid token."""
        tester = get_auth_tester()

        # Create a valid JWT
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).decode().rstrip("=")
        
        payload_data = {"sub": "123", "name": "Test", "exp": int(time.time()) + 3600}
        payload = base64.urlsafe_b64encode(
            json.dumps(payload_data).encode()
        ).decode().rstrip("=")
        
        token = f"{header}.{payload}.signature123"

        analysis = tester.analyze_jwt(token)

        assert analysis.valid_structure is True
        assert analysis.algorithm == "HS256"
        assert analysis.is_expired is False

    def test_analyze_jwt_invalid_structure(self) -> None:
        """Test JWT analysis with invalid structure."""
        tester = get_auth_tester()

        analysis = tester.analyze_jwt("not.a.valid.jwt.token")

        assert analysis.valid_structure is False
        assert len(analysis.issues) > 0

    def test_analyze_jwt_none_algorithm(self) -> None:
        """Test JWT analysis with 'none' algorithm."""
        tester = get_auth_tester()

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).decode().rstrip("=")
        
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "123"}).encode()
        ).decode().rstrip("=")
        
        token = f"{header}.{payload}."

        analysis = tester.analyze_jwt(token)

        assert analysis.algorithm == "none"
        assert any("none" in issue.lower() for issue in analysis.issues)

    def test_analyze_jwt_expired(self) -> None:
        """Test JWT analysis with expired token."""
        tester = get_auth_tester()

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256"}).encode()
        ).decode().rstrip("=")
        
        # Expired 1 hour ago
        payload_data = {"sub": "123", "exp": int(time.time()) - 3600}
        payload = base64.urlsafe_b64encode(
            json.dumps(payload_data).encode()
        ).decode().rstrip("=")
        
        token = f"{header}.{payload}.sig"

        analysis = tester.analyze_jwt(token)

        assert analysis.is_expired is True
        assert any("expired" in issue.lower() for issue in analysis.issues)

    def test_analyze_jwt_no_expiration(self) -> None:
        """Test JWT analysis without expiration claim."""
        tester = get_auth_tester()

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256"}).encode()
        ).decode().rstrip("=")
        
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "123"}).encode()  # No exp claim
        ).decode().rstrip("=")
        
        token = f"{header}.{payload}.sig"

        analysis = tester.analyze_jwt(token)

        assert analysis.expiration is None
        assert any("expiration" in issue.lower() or "exp" in issue.lower() for issue in analysis.issues)

    def test_forge_jwt_none_alg(self) -> None:
        """Test JWT forging with none algorithm."""
        tester = get_auth_tester()

        # Create a valid JWT
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256"}).encode()
        ).decode().rstrip("=")
        
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "123", "role": "user"}).encode()
        ).decode().rstrip("=")
        
        token = f"{header}.{payload}.signature"

        result = tester.forge_jwt_none_alg(token)

        assert result["success"] is True
        assert len(result["forged_tokens"]) > 0
        assert all("." in ft for ft in result["forged_tokens"])

    def test_forge_jwt_modified_claims(self) -> None:
        """Test JWT claim modification."""
        tester = get_auth_tester()

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256"}).encode()
        ).decode().rstrip("=")
        
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "123", "role": "user"}).encode()
        ).decode().rstrip("=")
        
        token = f"{header}.{payload}.sig"

        result = tester.forge_jwt_modified_claims(token, {"role": "admin", "user_id": 1})

        assert result["success"] is True
        assert result["modified_claims"]["role"] == "admin"
        assert result["original_claims"]["role"] == "user"

    def test_analyze_session_token(self) -> None:
        """Test session token analysis."""
        tester = get_auth_tester()

        analysis = tester.analyze_session_token(
            "abc123def456ghi789jkl012mno345",
            "Set-Cookie: session=abc123; HttpOnly; Secure"
        )

        assert analysis.length == 30
        assert analysis.cookie_flags["httponly"] is True
        assert analysis.cookie_flags["secure"] is True

    def test_analyze_session_token_missing_flags(self) -> None:
        """Test session token analysis with missing security flags."""
        tester = get_auth_tester()

        analysis = tester.analyze_session_token(
            "session123",
            "Set-Cookie: session=session123"
        )

        assert analysis.cookie_flags["httponly"] is False
        assert analysis.cookie_flags["secure"] is False
        assert len(analysis.issues) > 0

    def test_analyze_session_token_low_entropy(self) -> None:
        """Test session token with low entropy."""
        tester = get_auth_tester()

        analysis = tester.analyze_session_token("12345678")

        assert analysis.entropy_bits < 64
        assert any("entropy" in issue.lower() for issue in analysis.issues)

    def test_generate_privilege_escalation_tests(self) -> None:
        """Test privilege escalation test generation."""
        tester = get_auth_tester()

        tests = tester.generate_privilege_escalation_tests(
            "https://api.example.com",
            ["admin", "user", "guest"]
        )

        assert len(tests) > 0
        assert all(isinstance(t, AccessControlTest) for t in tests)
        # Admin shouldn't have tests (they're the target)
        assert not any(t.user_role == "admin" for t in tests)

    def test_generate_idor_tests(self) -> None:
        """Test IDOR test generation."""
        tester = get_auth_tester()

        tests = tester.generate_idor_tests(
            "/api/users/{id}/profile",
            "123",
            ["124", "125", "1", "admin"]
        )

        assert len(tests) == 4
        assert all("/api/users/" in t.endpoint for t in tests)
        assert not any(t.endpoint.endswith("/123/profile") for t in tests)

    def test_generate_account_enumeration_payloads(self) -> None:
        """Test account enumeration payload generation."""
        tester = get_auth_tester()

        payloads = tester.generate_account_enumeration_payloads("company.com")

        assert "common_usernames" in payloads
        assert "common_emails" in payloads
        assert "format_variations" in payloads
        assert "special_cases" in payloads
        assert any("@company.com" in email for email in payloads["common_emails"])

    def test_analyze_password_policy(self) -> None:
        """Test password policy analysis."""
        tester = get_auth_tester()

        test_passwords = [
            ("abc", False),  # Too short
            ("password", True),  # Common, accepted
            ("Password123!", True),  # Complex, accepted
            ("12345678", True),  # Just numbers, accepted
        ]

        analysis = tester.analyze_password_policy(test_passwords)

        assert "min_length" in analysis
        assert "issues" in analysis
        assert "recommendations" in analysis
        # Should detect that common passwords are allowed
        assert analysis.get("allows_common_passwords") is True


class TestJWTWeakSecretTesting:
    """Tests for JWT weak secret detection."""

    def test_detect_weak_secret(self) -> None:
        """Test detection of weak JWT secret."""
        tester = get_auth_tester()

        # Create JWT with known weak secret "secret"
        import hmac
        import hashlib

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).decode().rstrip("=")
        
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "123"}).encode()
        ).decode().rstrip("=")
        
        # Sign with weak secret
        message = f"{header}.{payload}"
        signature = hmac.new(
            b"secret", message.encode(), hashlib.sha256
        ).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        
        token = f"{header}.{payload}.{signature_b64}"

        result = tester.test_jwt_weak_secret(token)

        assert result.vulnerable is True
        assert result.vulnerability == AuthVulnerability.JWT_WEAK_SECRET
        assert result.evidence.get("weak_secret") == "secret"

    def test_no_weak_secret_found(self) -> None:
        """Test when no weak secret is found."""
        tester = get_auth_tester()

        # Create JWT with strong secret
        import hmac
        import hashlib

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256"}).encode()
        ).decode().rstrip("=")
        
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "123"}).encode()
        ).decode().rstrip("=")
        
        # Sign with strong secret
        strong_secret = "this-is-a-very-strong-256-bit-secret-key-for-jwt!"
        message = f"{header}.{payload}"
        signature = hmac.new(
            strong_secret.encode(), message.encode(), hashlib.sha256
        ).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        
        token = f"{header}.{payload}.{signature_b64}"

        result = tester.test_jwt_weak_secret(token)

        assert result.vulnerable is False


class TestAccessControlTest:
    """Tests for AccessControlTest dataclass."""

    def test_access_control_test_creation(self) -> None:
        """Test creating an access control test."""
        test = AccessControlTest(
            endpoint="/api/admin/users",
            method="GET",
            authenticated_user_id="user123",
            target_resource_id="admin_panel",
            user_role="user",
            expected_access=False,
            headers={"Authorization": "Bearer token"},
        )

        assert test.endpoint == "/api/admin/users"
        assert test.method == "GET"
        assert test.expected_access is False
        assert test.headers["Authorization"] == "Bearer token"

    def test_access_control_test_defaults(self) -> None:
        """Test default values."""
        test = AccessControlTest(
            endpoint="/api/resource",
            method="POST",
            authenticated_user_id="user1",
            target_resource_id="resource1",
            user_role="user",
            expected_access=True,
        )

        assert test.headers == {}
        assert test.body is None
