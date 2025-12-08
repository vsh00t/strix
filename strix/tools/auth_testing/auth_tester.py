"""
Authentication Testing Framework for DAST.

Provides comprehensive authentication and authorization testing capabilities
including session management, token analysis, and access control testing.
"""

import base64
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AuthTestType(Enum):
    """Types of authentication tests."""

    SESSION_FIXATION = "session_fixation"
    SESSION_HIJACKING = "session_hijacking"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    HORIZONTAL_PRIVILEGE = "horizontal_privilege"
    VERTICAL_PRIVILEGE = "vertical_privilege"
    TOKEN_MANIPULATION = "token_manipulation"
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    ACCOUNT_ENUMERATION = "account_enumeration"
    PASSWORD_POLICY = "password_policy"
    MFA_BYPASS = "mfa_bypass"
    OAUTH_MISCONFIGURATION = "oauth_misconfiguration"


class AuthVulnerability(Enum):
    """Authentication vulnerability types."""

    WEAK_SESSION_ID = "weak_session_id"
    PREDICTABLE_TOKEN = "predictable_token"
    INSECURE_COOKIE = "insecure_cookie"
    MISSING_CSRF = "missing_csrf"
    JWT_WEAK_SECRET = "jwt_weak_secret"
    JWT_ALG_NONE = "jwt_alg_none"
    JWT_KEY_CONFUSION = "jwt_key_confusion"
    SESSION_NO_EXPIRY = "session_no_expiry"
    CONCURRENT_SESSIONS = "concurrent_sessions"
    CREDENTIAL_LEAK = "credential_leak"
    IDOR = "idor"
    BROKEN_ACCESS_CONTROL = "broken_access_control"


@dataclass
class AuthTestResult:
    """Result of an authentication test."""

    test_type: AuthTestType
    vulnerable: bool
    severity: str  # critical, high, medium, low, info
    vulnerability: AuthVulnerability | None
    evidence: dict[str, Any]
    recommendations: list[str]
    details: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "test_type": self.test_type.value,
            "vulnerable": self.vulnerable,
            "severity": self.severity,
            "vulnerability": self.vulnerability.value if self.vulnerability else None,
            "evidence": self.evidence,
            "recommendations": self.recommendations,
            "details": self.details,
        }


@dataclass
class JWTAnalysis:
    """Analysis results for a JWT token."""

    valid_structure: bool
    header: dict[str, Any]
    payload: dict[str, Any]
    signature: str
    algorithm: str
    issues: list[str]
    expiration: int | None
    is_expired: bool
    claims: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "valid_structure": self.valid_structure,
            "header": self.header,
            "payload": self.payload,
            "algorithm": self.algorithm,
            "issues": self.issues,
            "expiration": self.expiration,
            "is_expired": self.is_expired,
            "claims": self.claims,
        }


@dataclass
class SessionAnalysis:
    """Analysis results for a session token/cookie."""

    token_value: str
    entropy_bits: float
    length: int
    character_set: str
    predictable_patterns: list[str]
    issues: list[str]
    cookie_flags: dict[str, bool]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "token_preview": self.token_value[:20] + "..."
            if len(self.token_value) > 20
            else self.token_value,
            "entropy_bits": round(self.entropy_bits, 2),
            "length": self.length,
            "character_set": self.character_set,
            "predictable_patterns": self.predictable_patterns,
            "issues": self.issues,
            "cookie_flags": self.cookie_flags,
        }


@dataclass
class AccessControlTest:
    """Configuration for access control testing."""

    endpoint: str
    method: str
    authenticated_user_id: str
    target_resource_id: str
    user_role: str
    expected_access: bool  # Should this user have access?
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None


class AuthenticationTester:
    """
    Comprehensive authentication and authorization testing framework.

    Provides tools for testing:
    - JWT token security
    - Session management
    - Access control (horizontal/vertical)
    - OAuth flows
    - Credential security
    """

    _instance: "AuthenticationTester | None" = None

    # Common weak JWT secrets to test
    WEAK_JWT_SECRETS = [
        "secret",
        "password",
        "123456",
        "qwerty",
        "admin",
        "jwt_secret",
        "your-256-bit-secret",
        "your-512-bit-secret",
        "supersecret",
        "changeme",
        "mysecret",
        "jwt",
        "token",
        "key",
        "private",
        "secret123",
        "password123",
    ]

    def __new__(cls) -> "AuthenticationTester":
        """Singleton pattern for authentication tester."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialize the authentication tester."""
        if self._initialized:
            return
        self._initialized = True

    def analyze_jwt(self, token: str) -> JWTAnalysis:
        """
        Analyze a JWT token for security issues.

        Args:
            token: The JWT token to analyze

        Returns:
            JWTAnalysis with detailed findings
        """
        issues: list[str] = []
        header: dict[str, Any] = {}
        payload: dict[str, Any] = {}
        signature = ""
        algorithm = ""
        expiration: int | None = None
        is_expired = False
        valid_structure = True

        parts = token.split(".")
        if len(parts) != 3:
            valid_structure = False
            issues.append("Invalid JWT structure - expected 3 parts separated by dots")
            return JWTAnalysis(
                valid_structure=False,
                header={},
                payload={},
                signature="",
                algorithm="unknown",
                issues=issues,
                expiration=None,
                is_expired=False,
                claims={},
            )

        try:
            # Decode header
            header_b64 = parts[0] + "=" * (-len(parts[0]) % 4)  # Add padding
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            algorithm = header.get("alg", "unknown")

            # Check algorithm issues
            if algorithm.lower() == "none":
                issues.append(
                    "CRITICAL: Algorithm 'none' detected - signature not verified"
                )
            elif algorithm.upper().startswith("HS"):
                issues.append(
                    "HMAC algorithm used - vulnerable to brute force if weak secret"
                )
            elif algorithm.upper().startswith("RS"):
                issues.append(
                    "RSA algorithm used - check for algorithm confusion attacks"
                )

        except Exception as e:
            issues.append(f"Failed to decode header: {e!s}")
            valid_structure = False

        try:
            # Decode payload
            payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # Check expiration
            if "exp" in payload:
                expiration = payload["exp"]
                if expiration < time.time():
                    is_expired = True
                    issues.append("Token is expired")
            else:
                issues.append("No expiration claim (exp) - token never expires")

            # Check other security claims
            if "iat" not in payload:
                issues.append("No issued-at claim (iat)")

            if "nbf" in payload and payload["nbf"] > time.time():
                issues.append("Token not yet valid (nbf in future)")

            # Check for sensitive data
            sensitive_keys = ["password", "secret", "key", "token", "credential"]
            for key in payload:
                if any(s in key.lower() for s in sensitive_keys):
                    issues.append(
                        f"Potentially sensitive data in payload: '{key}'"
                    )

        except Exception as e:
            issues.append(f"Failed to decode payload: {e!s}")
            valid_structure = False

        signature = parts[2]

        return JWTAnalysis(
            valid_structure=valid_structure,
            header=header,
            payload=payload,
            signature=signature,
            algorithm=algorithm,
            issues=issues,
            expiration=expiration,
            is_expired=is_expired,
            claims=payload,
        )

    def test_jwt_weak_secret(
        self, token: str, custom_secrets: list[str] | None = None
    ) -> AuthTestResult:
        """
        Test if a JWT uses a weak/common secret.

        Args:
            token: The JWT token to test
            custom_secrets: Additional secrets to test

        Returns:
            AuthTestResult with findings
        """
        import hmac

        secrets_to_test = self.WEAK_JWT_SECRETS.copy()
        if custom_secrets:
            secrets_to_test.extend(custom_secrets)

        parts = token.split(".")
        if len(parts) != 3:
            return AuthTestResult(
                test_type=AuthTestType.TOKEN_MANIPULATION,
                vulnerable=False,
                severity="info",
                vulnerability=None,
                evidence={"error": "Invalid JWT structure"},
                recommendations=["Provide a valid JWT token"],
                details="Could not test - invalid JWT structure",
            )

        header_payload = f"{parts[0]}.{parts[1]}"
        original_signature = parts[2]

        # Add padding for base64 decoding
        sig_b64 = original_signature + "=" * (-len(original_signature) % 4)
        try:
            original_sig_bytes = base64.urlsafe_b64decode(sig_b64)
        except Exception:
            return AuthTestResult(
                test_type=AuthTestType.TOKEN_MANIPULATION,
                vulnerable=False,
                severity="info",
                vulnerability=None,
                evidence={"error": "Could not decode signature"},
                recommendations=["Verify JWT format"],
                details="Could not decode signature for comparison",
            )

        # Test each secret
        for secret in secrets_to_test:
            # Try HS256
            computed = hmac.new(
                secret.encode(), header_payload.encode(), hashlib.sha256
            ).digest()

            if computed == original_sig_bytes:
                return AuthTestResult(
                    test_type=AuthTestType.TOKEN_MANIPULATION,
                    vulnerable=True,
                    severity="critical",
                    vulnerability=AuthVulnerability.JWT_WEAK_SECRET,
                    evidence={
                        "weak_secret": secret,
                        "algorithm": "HS256",
                    },
                    recommendations=[
                        "Use a cryptographically secure random secret (minimum 256 bits)",
                        "Consider using asymmetric algorithms (RS256, ES256)",
                        "Rotate the secret immediately",
                        "Invalidate all existing tokens",
                    ],
                    details=f"JWT is signed with weak secret: '{secret}'",
                )

            # Try HS384
            computed384 = hmac.new(
                secret.encode(), header_payload.encode(), hashlib.sha384
            ).digest()

            if computed384 == original_sig_bytes:
                return AuthTestResult(
                    test_type=AuthTestType.TOKEN_MANIPULATION,
                    vulnerable=True,
                    severity="critical",
                    vulnerability=AuthVulnerability.JWT_WEAK_SECRET,
                    evidence={
                        "weak_secret": secret,
                        "algorithm": "HS384",
                    },
                    recommendations=[
                        "Use a cryptographically secure random secret",
                        "Consider using asymmetric algorithms",
                        "Rotate the secret immediately",
                    ],
                    details=f"JWT is signed with weak secret: '{secret}'",
                )

        return AuthTestResult(
            test_type=AuthTestType.TOKEN_MANIPULATION,
            vulnerable=False,
            severity="info",
            vulnerability=None,
            evidence={"secrets_tested": len(secrets_to_test)},
            recommendations=[
                "Secret not found in common wordlist - consider extended brute force",
                "Use hashcat or john for more comprehensive testing",
            ],
            details=f"Tested {len(secrets_to_test)} common secrets - none matched",
        )

    def forge_jwt_none_alg(self, token: str) -> dict[str, Any]:
        """
        Attempt to forge a JWT with 'none' algorithm.

        Args:
            token: Original JWT token

        Returns:
            Dictionary with forged token and test instructions
        """
        parts = token.split(".")
        if len(parts) != 3:
            return {"success": False, "error": "Invalid JWT structure"}

        try:
            # Decode original header and payload
            header_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # Create forged tokens with 'none' algorithm
            forged_headers = [
                {"alg": "none", "typ": "JWT"},
                {"alg": "None", "typ": "JWT"},
                {"alg": "NONE", "typ": "JWT"},
                {"alg": "nOnE", "typ": "JWT"},
            ]

            forged_tokens: list[str] = []
            for forged_header in forged_headers:
                new_header_b64 = (
                    base64.urlsafe_b64encode(json.dumps(forged_header).encode())
                    .decode()
                    .rstrip("=")
                )
                new_payload_b64 = (
                    base64.urlsafe_b64encode(json.dumps(payload).encode())
                    .decode()
                    .rstrip("=")
                )

                # Forged token with empty signature
                forged_tokens.append(f"{new_header_b64}.{new_payload_b64}.")
                # Forged token with no signature part
                forged_tokens.append(f"{new_header_b64}.{new_payload_b64}")

            return {
                "success": True,
                "original_header": header,
                "original_payload": payload,
                "forged_tokens": forged_tokens,
                "test_instructions": [
                    "Replace the original token with each forged token",
                    "If the application accepts any forged token, it's vulnerable",
                    "This vulnerability allows complete authentication bypass",
                ],
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def forge_jwt_modified_claims(
        self, token: str, claim_modifications: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Create JWT with modified claims for testing.

        Args:
            token: Original JWT token
            claim_modifications: Claims to modify/add

        Returns:
            Dictionary with modified token information
        """
        parts = token.split(".")
        if len(parts) != 3:
            return {"success": False, "error": "Invalid JWT structure"}

        try:
            header_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # Modify payload
            original_payload = payload.copy()
            payload.update(claim_modifications)

            # Create unsigned modified token
            new_header_b64 = (
                base64.urlsafe_b64encode(json.dumps(header).encode())
                .decode()
                .rstrip("=")
            )
            new_payload_b64 = (
                base64.urlsafe_b64encode(json.dumps(payload).encode())
                .decode()
                .rstrip("=")
            )

            return {
                "success": True,
                "original_claims": original_payload,
                "modified_claims": payload,
                "modifications_applied": claim_modifications,
                "unsigned_token": f"{new_header_b64}.{new_payload_b64}.",
                "note": "Token needs valid signature for most applications",
                "test_suggestions": [
                    "Try with 'none' algorithm attack",
                    "Try with weak secret if known",
                    "Test for algorithm confusion if RSA public key is available",
                ],
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def analyze_session_token(
        self, token: str, cookie_header: str | None = None
    ) -> SessionAnalysis:
        """
        Analyze a session token for security issues.

        Args:
            token: The session token/ID to analyze
            cookie_header: Optional Set-Cookie header for flag analysis

        Returns:
            SessionAnalysis with detailed findings
        """
        issues: list[str] = []

        # Calculate entropy
        entropy = self._calculate_entropy(token)

        # Determine character set
        char_set = self._determine_charset(token)

        # Check for predictable patterns
        patterns = self._detect_predictable_patterns(token)

        # Analyze cookie flags if header provided
        cookie_flags = {
            "httponly": False,
            "secure": False,
            "samesite": False,
            "path_restricted": False,
        }

        if cookie_header:
            cookie_lower = cookie_header.lower()
            cookie_flags["httponly"] = "httponly" in cookie_lower
            cookie_flags["secure"] = "secure" in cookie_lower
            cookie_flags["samesite"] = "samesite" in cookie_lower
            cookie_flags["path_restricted"] = "path=" in cookie_lower

            if not cookie_flags["httponly"]:
                issues.append("Missing HttpOnly flag - vulnerable to XSS token theft")
            if not cookie_flags["secure"]:
                issues.append(
                    "Missing Secure flag - token transmitted over unencrypted connections"
                )
            if not cookie_flags["samesite"]:
                issues.append("Missing SameSite flag - potential CSRF vulnerability")

        # Check entropy
        if entropy < 64:
            issues.append(
                f"Low entropy ({entropy:.1f} bits) - session ID may be predictable"
            )
        elif entropy < 128:
            issues.append(
                f"Moderate entropy ({entropy:.1f} bits) - consider using longer tokens"
            )

        # Check length
        if len(token) < 16:
            issues.append("Short token length - increases predictability")

        # Check patterns
        if patterns:
            issues.extend([f"Predictable pattern detected: {p}" for p in patterns])

        return SessionAnalysis(
            token_value=token,
            entropy_bits=entropy,
            length=len(token),
            character_set=char_set,
            predictable_patterns=patterns,
            issues=issues,
            cookie_flags=cookie_flags,
        )

    def _calculate_entropy(self, token: str) -> float:
        """Calculate Shannon entropy of a token in bits."""
        import math

        if not token:
            return 0.0

        # Count character frequencies
        freq: dict[str, int] = {}
        for char in token:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        for count in freq.values():
            prob = count / len(token)
            if prob > 0:
                entropy -= prob * math.log2(prob)

        # Return total entropy in bits
        return entropy * len(token)

    def _determine_charset(self, token: str) -> str:
        """Determine the character set used in a token."""
        has_lower = any(c.islower() for c in token)
        has_upper = any(c.isupper() for c in token)
        has_digit = any(c.isdigit() for c in token)
        has_special = any(not c.isalnum() for c in token)

        parts = []
        if has_lower:
            parts.append("lowercase")
        if has_upper:
            parts.append("uppercase")
        if has_digit:
            parts.append("digits")
        if has_special:
            parts.append("special")

        return "+".join(parts) if parts else "unknown"

    def _detect_predictable_patterns(self, token: str) -> list[str]:
        """Detect predictable patterns in a token."""
        patterns: list[str] = []

        # Check for sequential numbers
        if re.search(r"\d{4,}", token):
            nums = re.findall(r"\d{4,}", token)
            for num in nums:
                if self._is_sequential(num):
                    patterns.append(f"Sequential numbers: {num}")

        # Check for timestamps
        if re.search(r"1[67]\d{8,}", token):  # Unix timestamp pattern
            patterns.append("Possible Unix timestamp detected")

        # Check for base64 encoded predictable data
        try:
            decoded = base64.b64decode(token + "=" * (-len(token) % 4))
            if decoded.isascii():
                decoded_str = decoded.decode("ascii", errors="ignore")
                if re.search(r"\d{4}-\d{2}-\d{2}", decoded_str):
                    patterns.append("Base64-encoded date detected")
        except Exception:
            pass

        # Check for UUID format
        if re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            token.lower(),
        ):
            patterns.append("UUID format - check if sequential or predictable")

        # Check for hex encoding
        if re.match(r"^[0-9a-fA-F]+$", token) and len(token) % 2 == 0:
            patterns.append("Hex-encoded value - analyze decoded content")

        return patterns

    def _is_sequential(self, num_str: str) -> bool:
        """Check if a number string is sequential."""
        for i in range(len(num_str) - 1):
            if abs(int(num_str[i + 1]) - int(num_str[i])) > 1:
                return False
        return True

    def generate_privilege_escalation_tests(
        self, base_endpoint: str, user_roles: list[str]
    ) -> list[AccessControlTest]:
        """
        Generate test cases for privilege escalation testing.

        Args:
            base_endpoint: Base API endpoint
            user_roles: List of roles to test (e.g., ['admin', 'user', 'guest'])

        Returns:
            List of AccessControlTest configurations
        """
        tests: list[AccessControlTest] = []

        # Common admin endpoints to test
        admin_endpoints = [
            "/admin",
            "/admin/users",
            "/admin/settings",
            "/admin/logs",
            "/api/admin",
            "/api/v1/admin",
            "/management",
            "/dashboard/admin",
            "/system/config",
        ]

        for role in user_roles:
            if role.lower() != "admin":
                for endpoint in admin_endpoints:
                    tests.append(
                        AccessControlTest(
                            endpoint=f"{base_endpoint}{endpoint}",
                            method="GET",
                            authenticated_user_id=f"test_{role}",
                            target_resource_id="admin_resource",
                            user_role=role,
                            expected_access=False,
                        )
                    )

        return tests

    def generate_idor_tests(
        self,
        endpoint_template: str,
        current_user_id: str,
        test_ids: list[str],
    ) -> list[AccessControlTest]:
        """
        Generate IDOR (Insecure Direct Object Reference) test cases.

        Args:
            endpoint_template: Endpoint with {id} placeholder
            current_user_id: ID of the authenticated user
            test_ids: List of other user IDs to test access to

        Returns:
            List of AccessControlTest configurations
        """
        tests: list[AccessControlTest] = []

        for test_id in test_ids:
            if test_id != current_user_id:
                endpoint = endpoint_template.replace("{id}", test_id)
                tests.append(
                    AccessControlTest(
                        endpoint=endpoint,
                        method="GET",
                        authenticated_user_id=current_user_id,
                        target_resource_id=test_id,
                        user_role="user",
                        expected_access=False,
                    )
                )

        return tests

    def generate_account_enumeration_payloads(
        self, domain: str = "example.com"
    ) -> dict[str, list[str]]:
        """
        Generate payloads for account enumeration testing.

        Args:
            domain: Email domain to use for testing

        Returns:
            Dictionary of enumeration payloads by category
        """
        return {
            "common_usernames": [
                "admin",
                "administrator",
                "root",
                "test",
                "user",
                "guest",
                "demo",
                "support",
                "info",
                "sales",
                "contact",
            ],
            "common_emails": [
                f"admin@{domain}",
                f"test@{domain}",
                f"user@{domain}",
                f"info@{domain}",
                f"support@{domain}",
                f"contact@{domain}",
                f"sales@{domain}",
            ],
            "format_variations": [
                "user1",
                "user01",
                "user001",
                "user_1",
                "user-1",
                "test123",
                f"john.doe@{domain}",
                f"jane.doe@{domain}",
            ],
            "special_cases": [
                "",  # Empty
                " ",  # Space
                "a" * 100,  # Long input
                "user'--",  # SQL injection attempt
                "user<script>",  # XSS attempt
            ],
        }

    def analyze_password_policy(
        self,
        test_passwords: list[tuple[str, bool]],  # (password, accepted)
    ) -> dict[str, Any]:
        """
        Analyze password policy based on test results.

        Args:
            test_passwords: List of (password, was_accepted) tuples

        Returns:
            Analysis of the password policy
        """
        analysis: dict[str, Any] = {
            "min_length": None,
            "requires_uppercase": None,
            "requires_lowercase": None,
            "requires_digit": None,
            "requires_special": None,
            "allows_common_passwords": None,
            "issues": [],
            "recommendations": [],
        }

        # Analyze accepted passwords
        accepted = [p for p, a in test_passwords if a]
        rejected = [p for p, a in test_passwords if not a]

        if accepted:
            min_len = min(len(p) for p in accepted)
            analysis["min_length"] = min_len
            if min_len < 8:
                analysis["issues"].append(
                    f"Minimum password length is only {min_len} characters"
                )
                analysis["recommendations"].append(
                    "Enforce minimum 8 character passwords (12+ recommended)"
                )

        # Check character requirements
        if any(not any(c.isupper() for c in p) for p in accepted):
            analysis["requires_uppercase"] = False
        if any(not any(c.islower() for c in p) for p in accepted):
            analysis["requires_lowercase"] = False
        if any(not any(c.isdigit() for c in p) for p in accepted):
            analysis["requires_digit"] = False
        if any(not any(not c.isalnum() for c in p) for p in accepted):
            analysis["requires_special"] = False

        # Check for common passwords
        common_passwords = [
            "password",
            "123456",
            "password123",
            "qwerty",
            "admin123",
        ]
        common_accepted = [p for p in accepted if p.lower() in common_passwords]
        if common_accepted:
            analysis["allows_common_passwords"] = True
            analysis["issues"].append(
                f"Common passwords are accepted: {common_accepted}"
            )
            analysis["recommendations"].append(
                "Implement password blacklist for common passwords"
            )

        return analysis


def get_auth_tester() -> AuthenticationTester:
    """Get the singleton authentication tester instance."""
    return AuthenticationTester()
