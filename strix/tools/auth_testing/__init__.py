"""
Authentication Testing module for DAST.

Provides comprehensive authentication and authorization testing capabilities
including JWT analysis, session management, and access control testing.
"""

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

__all__ = [
    "AccessControlTest",
    "AuthenticationTester",
    "AuthTestResult",
    "AuthTestType",
    "AuthVulnerability",
    "JWTAnalysis",
    "SessionAnalysis",
    "get_auth_tester",
]
