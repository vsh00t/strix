"""
Authentication Testing actions for the tool registry.
"""

from typing import Any

from strix.tools.argument_parser import parse_tool_arguments
from strix.tools.auth_testing.auth_tester import (
    AuthenticationTester,
    AuthTestType,
    get_auth_tester,
)
from strix.tools.registry import register_tool


@register_tool(
    name="analyze_jwt",
    description="""Analyze a JWT token for security vulnerabilities.

Performs comprehensive analysis including:
- Structure validation
- Algorithm security (none, weak HMAC, etc.)
- Expiration and time-based claims
- Sensitive data exposure in payload
- Common misconfigurations

Example:
<analyze_jwt>
<token>eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c</token>
</analyze_jwt>

Returns detailed analysis with security issues and recommendations.""",
    schema="<analyze_jwt>\n<token>$JWT_TOKEN</token>\n</analyze_jwt>",
)
async def analyze_jwt(arguments: str) -> dict[str, Any]:
    """Analyze a JWT token for security issues."""
    args = parse_tool_arguments(arguments, {"token": str})
    token = args.get("token", "")

    if not token:
        return {"success": False, "error": "JWT token is required"}

    tester = get_auth_tester()
    analysis = tester.analyze_jwt(token)

    return {
        "success": True,
        "analysis": analysis.to_dict(),
    }


@register_tool(
    name="test_jwt_weak_secret",
    description="""Test if a JWT token uses a weak/common secret.

Tests the JWT against a list of common weak secrets to determine
if the signature can be forged. If a weak secret is found, the token
can be modified and re-signed.

Example:
<test_jwt_weak_secret>
<token>eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...</token>
<custom_secrets>["company123", "api_secret"]</custom_secrets>
</test_jwt_weak_secret>

Returns vulnerability status and discovered secret if found.""",
    schema="<test_jwt_weak_secret>\n<token>$JWT_TOKEN</token>\n<custom_secrets>$OPTIONAL_SECRETS_JSON</custom_secrets>\n</test_jwt_weak_secret>",
)
async def test_jwt_weak_secret(arguments: str) -> dict[str, Any]:
    """Test JWT for weak secret vulnerability."""
    args = parse_tool_arguments(
        arguments,
        {"token": str, "custom_secrets": str},
    )
    token = args.get("token", "")
    custom_secrets_str = args.get("custom_secrets", "[]")

    if not token:
        return {"success": False, "error": "JWT token is required"}

    custom_secrets: list[str] = []
    if custom_secrets_str:
        import json

        try:
            custom_secrets = json.loads(custom_secrets_str)
        except json.JSONDecodeError:
            pass  # Ignore invalid JSON, use default secrets only

    tester = get_auth_tester()
    result = tester.test_jwt_weak_secret(token, custom_secrets)

    return {
        "success": True,
        "result": result.to_dict(),
    }


@register_tool(
    name="forge_jwt_none_algorithm",
    description="""Attempt to create a JWT with 'none' algorithm for authentication bypass.

Creates multiple variations of the JWT with 'none' algorithm
(none, None, NONE, nOnE) which may bypass signature verification
in vulnerable implementations.

Example:
<forge_jwt_none_algorithm>
<token>eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...</token>
</forge_jwt_none_algorithm>

Returns forged tokens to test and exploitation instructions.""",
    schema="<forge_jwt_none_algorithm>\n<token>$JWT_TOKEN</token>\n</forge_jwt_none_algorithm>",
)
async def forge_jwt_none_algorithm(arguments: str) -> dict[str, Any]:
    """Forge JWT with none algorithm."""
    args = parse_tool_arguments(arguments, {"token": str})
    token = args.get("token", "")

    if not token:
        return {"success": False, "error": "JWT token is required"}

    tester = get_auth_tester()
    result = tester.forge_jwt_none_alg(token)

    return result


@register_tool(
    name="forge_jwt_modified_claims",
    description="""Create a JWT with modified claims for testing.

Modifies the JWT payload claims (e.g., changing user_id, role, permissions)
and creates an unsigned token. Useful for testing access control when
combined with none algorithm attack or if the secret is known.

Example:
<forge_jwt_modified_claims>
<token>eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...</token>
<modifications>{"role": "admin", "user_id": 1}</modifications>
</forge_jwt_modified_claims>

Returns modified token with instructions for exploitation.""",
    schema="<forge_jwt_modified_claims>\n<token>$JWT_TOKEN</token>\n<modifications>$CLAIMS_JSON</modifications>\n</forge_jwt_modified_claims>",
)
async def forge_jwt_modified_claims(arguments: str) -> dict[str, Any]:
    """Create JWT with modified claims."""
    args = parse_tool_arguments(
        arguments,
        {"token": str, "modifications": str},
    )
    token = args.get("token", "")
    modifications_str = args.get("modifications", "{}")

    if not token:
        return {"success": False, "error": "JWT token is required"}

    import json

    try:
        modifications = json.loads(modifications_str)
    except json.JSONDecodeError:
        return {"success": False, "error": "Invalid modifications JSON format"}

    tester = get_auth_tester()
    result = tester.forge_jwt_modified_claims(token, modifications)

    return result


@register_tool(
    name="analyze_session_token",
    description="""Analyze a session token for security weaknesses.

Performs analysis including:
- Entropy calculation (randomness)
- Character set analysis
- Predictable pattern detection (timestamps, sequential IDs, etc.)
- Cookie security flags (HttpOnly, Secure, SameSite)

Example:
<analyze_session_token>
<token>abc123def456ghi789</token>
<cookie_header>Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict</cookie_header>
</analyze_session_token>

Returns detailed analysis with security recommendations.""",
    schema="<analyze_session_token>\n<token>$SESSION_TOKEN</token>\n<cookie_header>$OPTIONAL_SET_COOKIE_HEADER</cookie_header>\n</analyze_session_token>",
)
async def analyze_session_token(arguments: str) -> dict[str, Any]:
    """Analyze session token for security issues."""
    args = parse_tool_arguments(
        arguments,
        {"token": str, "cookie_header": str},
    )
    token = args.get("token", "")
    cookie_header = args.get("cookie_header")

    if not token:
        return {"success": False, "error": "Session token is required"}

    tester = get_auth_tester()
    analysis = tester.analyze_session_token(token, cookie_header)

    return {
        "success": True,
        "analysis": analysis.to_dict(),
    }


@register_tool(
    name="generate_idor_tests",
    description="""Generate test cases for IDOR (Insecure Direct Object Reference) vulnerabilities.

Creates test configurations for checking if a user can access
resources belonging to other users by manipulating IDs in requests.

Example:
<generate_idor_tests>
<endpoint_template>/api/users/{id}/profile</endpoint_template>
<current_user_id>123</current_user_id>
<test_ids>["124", "125", "1", "admin"]</test_ids>
</generate_idor_tests>

Returns list of IDOR test configurations to execute.""",
    schema="<generate_idor_tests>\n<endpoint_template>$ENDPOINT_WITH_ID_PLACEHOLDER</endpoint_template>\n<current_user_id>$CURRENT_USER_ID</current_user_id>\n<test_ids>$IDS_TO_TEST_JSON</test_ids>\n</generate_idor_tests>",
)
async def generate_idor_tests(arguments: str) -> dict[str, Any]:
    """Generate IDOR test cases."""
    args = parse_tool_arguments(
        arguments,
        {"endpoint_template": str, "current_user_id": str, "test_ids": str},
    )
    endpoint_template = args.get("endpoint_template", "")
    current_user_id = args.get("current_user_id", "")
    test_ids_str = args.get("test_ids", "[]")

    if not endpoint_template or not current_user_id:
        return {
            "success": False,
            "error": "endpoint_template and current_user_id are required",
        }

    import json

    try:
        test_ids = json.loads(test_ids_str)
    except json.JSONDecodeError:
        return {"success": False, "error": "Invalid test_ids JSON format"}

    tester = get_auth_tester()
    tests = tester.generate_idor_tests(endpoint_template, current_user_id, test_ids)

    return {
        "success": True,
        "tests": [
            {
                "endpoint": t.endpoint,
                "method": t.method,
                "authenticated_user_id": t.authenticated_user_id,
                "target_resource_id": t.target_resource_id,
                "expected_access": t.expected_access,
            }
            for t in tests
        ],
        "count": len(tests),
    }


@register_tool(
    name="generate_privilege_escalation_tests",
    description="""Generate test cases for privilege escalation vulnerabilities.

Creates test configurations for checking vertical privilege escalation
by testing if lower-privileged users can access admin endpoints.

Example:
<generate_privilege_escalation_tests>
<base_endpoint>https://api.example.com</base_endpoint>
<user_roles>["admin", "user", "guest"]</user_roles>
</generate_privilege_escalation_tests>

Returns list of privilege escalation test configurations.""",
    schema="<generate_privilege_escalation_tests>\n<base_endpoint>$BASE_API_URL</base_endpoint>\n<user_roles>$ROLES_JSON</user_roles>\n</generate_privilege_escalation_tests>",
)
async def generate_privilege_escalation_tests(arguments: str) -> dict[str, Any]:
    """Generate privilege escalation test cases."""
    args = parse_tool_arguments(
        arguments,
        {"base_endpoint": str, "user_roles": str},
    )
    base_endpoint = args.get("base_endpoint", "")
    user_roles_str = args.get("user_roles", '["admin", "user"]')

    if not base_endpoint:
        return {"success": False, "error": "base_endpoint is required"}

    import json

    try:
        user_roles = json.loads(user_roles_str)
    except json.JSONDecodeError:
        user_roles = ["admin", "user"]

    tester = get_auth_tester()
    tests = tester.generate_privilege_escalation_tests(base_endpoint, user_roles)

    return {
        "success": True,
        "tests": [
            {
                "endpoint": t.endpoint,
                "method": t.method,
                "user_role": t.user_role,
                "target_resource": t.target_resource_id,
                "expected_access": t.expected_access,
            }
            for t in tests
        ],
        "count": len(tests),
    }


@register_tool(
    name="generate_account_enumeration_payloads",
    description="""Generate payloads for account enumeration testing.

Creates various payloads to test if the application reveals
information about valid/invalid accounts through different responses.

Example:
<generate_account_enumeration_payloads>
<domain>targetcompany.com</domain>
</generate_account_enumeration_payloads>

Returns categorized enumeration payloads.""",
    schema="<generate_account_enumeration_payloads>\n<domain>$EMAIL_DOMAIN</domain>\n</generate_account_enumeration_payloads>",
)
async def generate_account_enumeration_payloads(arguments: str) -> dict[str, Any]:
    """Generate account enumeration payloads."""
    args = parse_tool_arguments(arguments, {"domain": str})
    domain = args.get("domain", "example.com")

    tester = get_auth_tester()
    payloads = tester.generate_account_enumeration_payloads(domain)

    return {
        "success": True,
        "payloads": payloads,
    }


@register_tool(
    name="analyze_password_policy",
    description="""Analyze password policy based on test results.

Analyzes which passwords were accepted/rejected to determine
the password policy and identify weaknesses.

Example:
<analyze_password_policy>
<test_results>[["password123", true], ["abc", false], ["Password1!", true]]</test_results>
</analyze_password_policy>

Returns password policy analysis with recommendations.""",
    schema="<analyze_password_policy>\n<test_results>$PASSWORD_RESULTS_JSON</test_results>\n</analyze_password_policy>",
)
async def analyze_password_policy(arguments: str) -> dict[str, Any]:
    """Analyze password policy from test results."""
    args = parse_tool_arguments(arguments, {"test_results": str})
    test_results_str = args.get("test_results", "[]")

    import json

    try:
        test_results = json.loads(test_results_str)
        # Convert to list of tuples
        test_passwords = [(p, a) for p, a in test_results]
    except (json.JSONDecodeError, ValueError):
        return {"success": False, "error": "Invalid test_results JSON format"}

    tester = get_auth_tester()
    analysis = tester.analyze_password_policy(test_passwords)

    return {
        "success": True,
        "analysis": analysis,
    }
