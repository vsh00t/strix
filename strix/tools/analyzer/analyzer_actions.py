"""Analyzer tool actions for Strix agent.

Provides registered tools for intelligent response analysis and
vulnerability detection.
"""
from typing import Any

from strix.tools.registry import register_tool
from strix.tools.analyzer.response_analyzer import get_response_analyzer


@register_tool
def analyze_response(
    response_body: str,
    status_code: int = 200,
    response_headers: dict[str, str] | None = None,
    url: str = "",
    method: str = "GET",
    payload: str | None = None,
) -> dict[str, Any]:
    """Analyze an HTTP response for security vulnerabilities and information disclosure.
    
    This tool performs comprehensive analysis including:
    - Error message detection (SQL, PHP, Java, Python, etc.)
    - Stack trace identification
    - Sensitive data exposure (API keys, passwords, tokens)
    - Path disclosure
    - Version information leakage
    - Security header analysis
    - Payload reflection detection (XSS indicator)
    
    Args:
        response_body: The HTTP response body to analyze
        status_code: HTTP response status code
        response_headers: Response headers dictionary
        url: The request URL (for context)
        method: HTTP method used
        payload: If provided, checks for reflection in response
        
    Returns:
        Dictionary containing:
        - result_id: ID to retrieve detailed results
        - risk_score: Overall risk score (0.0-1.0)
        - highest_severity: Highest severity finding
        - findings_count: Number of findings
        - findings: List of detailed findings
        - summary: Human-readable summary
        
    Example:
        >>> result = analyze_response(
        ...     response_body="<html>Error: mysql_query() failed</html>",
        ...     status_code=500,
        ...     url="https://example.com/search"
        ... )
        >>> if result["risk_score"] > 0.5:
        ...     print("High risk findings detected!")
    """
    analyzer = get_response_analyzer()
    
    result = analyzer.analyze(
        response_body=response_body,
        response_headers=response_headers,
        status_code=status_code,
        url=url,
        method=method,
        payload=payload,
    )
    
    # Generate summary
    summary = _generate_analysis_summary(result)
    
    return {
        "result_id": result.id,
        "risk_score": round(result.risk_score, 2),
        "highest_severity": result._get_highest_severity(),
        "findings_count": len(result.findings),
        "findings": [f.to_dict() for f in result.findings],
        "summary": summary,
    }


def _generate_analysis_summary(result: Any) -> str:
    """Generate human-readable summary."""
    if not result.findings:
        return "No security issues detected in the response."
    
    severity_counts: dict[str, int] = {}
    for finding in result.findings:
        sev = finding.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    parts = [f"Found {len(result.findings)} security issues:"]
    
    for severity in ["critical", "high", "medium", "low", "info"]:
        if severity in severity_counts:
            parts.append(f"  - {severity_counts[severity]} {severity.upper()}")
    
    # Add top findings
    if result.findings:
        top_finding = max(result.findings, key=lambda f: ["info", "low", "medium", "high", "critical"].index(f.severity.value))
        parts.append(f"\nTop issue: {top_finding.title}")
    
    return "\n".join(parts)


@register_tool
def compare_responses(
    response1_body: str,
    response2_body: str,
    response1_status: int = 200,
    response2_status: int = 200,
    response1_headers: dict[str, str] | None = None,
    response2_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Compare two HTTP responses for differential analysis.
    
    Useful for detecting boolean-based SQL injection, blind XSS,
    and other vulnerabilities where responses differ based on conditions.
    
    Args:
        response1_body: First response body
        response2_body: Second response body
        response1_status: First response status code
        response2_status: Second response status code
        response1_headers: First response headers
        response2_headers: Second response headers
        
    Returns:
        Dictionary with comparison metrics:
        - identical: Whether responses are identical
        - status_different: Whether status codes differ
        - length_difference: Absolute length difference
        - length_ratio: Ratio of smaller to larger response
        - word_similarity: Jaccard similarity of word sets
        - analysis: Interpretation of the comparison
        
    Example:
        >>> # Test boolean SQL injection
        >>> resp1 = send_request(url + "?id=1' AND '1'='1")
        >>> resp2 = send_request(url + "?id=1' AND '1'='2")
        >>> result = compare_responses(resp1["body"], resp2["body"])
        >>> if not result["identical"] and result["status_different"]:
        ...     print("Boolean SQL injection likely!")
    """
    analyzer = get_response_analyzer()
    
    return analyzer.compare_responses(
        response1={
            "body": response1_body,
            "status_code": response1_status,
            "headers": response1_headers or {},
        },
        response2={
            "body": response2_body,
            "status_code": response2_status,
            "headers": response2_headers or {},
        },
    )


@register_tool
def detect_error_disclosure(
    response_body: str,
    technologies: list[str] | None = None,
) -> dict[str, Any]:
    """Detect error messages and stack traces in a response.
    
    Focused analysis for error disclosure that might reveal:
    - Database type and structure
    - File paths and directory structure
    - Technology stack information
    - Debug information
    
    Args:
        response_body: Response body to analyze
        technologies: Specific technologies to check (mysql, postgresql, php, etc.)
                     If None, checks all known patterns.
                     
    Returns:
        Dictionary with error disclosure findings
        
    Example:
        >>> result = detect_error_disclosure(
        ...     response_body=error_page,
        ...     technologies=["mysql", "php"]
        ... )
    """
    analyzer = get_response_analyzer()
    
    # Run full analysis
    result = analyzer.analyze(
        response_body=response_body,
        status_code=500,  # Assume error context
    )
    
    # Filter for error-related findings
    error_types = ["error_disclosure", "stack_trace", "sql_error", "debug_info", "path_disclosure"]
    error_findings = [
        f for f in result.findings 
        if f.type.value in error_types
    ]
    
    # Group by technology if we detected any
    tech_findings: dict[str, list[dict[str, Any]]] = {}
    for finding in error_findings:
        # Try to extract technology from description
        tech = "general"
        for t in ["mysql", "postgresql", "mssql", "oracle", "sqlite", "php", "python", "java", "dotnet", "node"]:
            if t in finding.description.lower():
                tech = t
                break
        
        if tech not in tech_findings:
            tech_findings[tech] = []
        tech_findings[tech].append(finding.to_dict())
    
    return {
        "errors_found": len(error_findings) > 0,
        "findings_count": len(error_findings),
        "findings_by_technology": tech_findings,
        "all_findings": [f.to_dict() for f in error_findings],
        "recommendation": (
            "Error disclosure detected. Implement custom error pages and disable debug mode in production."
            if error_findings else
            "No obvious error disclosure detected."
        ),
    }


@register_tool
def extract_sensitive_data(
    response_body: str,
    categories: list[str] | None = None,
) -> dict[str, Any]:
    """Extract and identify sensitive data patterns in a response.
    
    Scans for patterns that might indicate:
    - API keys (generic, OpenAI, Google, AWS)
    - Passwords and credentials
    - Access tokens and JWTs
    - Connection strings
    - Private keys
    - Email addresses
    - Internal IP addresses
    
    Note: Findings are masked to prevent accidental exposure.
    
    Args:
        response_body: Response body to scan
        categories: Specific categories to check. Options:
                   api_key, aws, password, token, connection_string,
                   private_key, email, ip_address
                   If None, checks all categories.
                   
    Returns:
        Dictionary with sensitive data findings (masked)
        
    Example:
        >>> result = extract_sensitive_data(config_response)
        >>> if result["sensitive_data_found"]:
        ...     print("WARNING: Sensitive data exposed!")
    """
    analyzer = get_response_analyzer()
    
    result = analyzer.analyze(response_body=response_body)
    
    # Filter for sensitive data findings
    sensitive_findings = [
        f for f in result.findings 
        if f.type.value == "sensitive_data"
    ]
    
    # Group by category
    categorized: dict[str, list[dict[str, Any]]] = {}
    for finding in sensitive_findings:
        # Extract category from title
        category = "other"
        for cat in ["api_key", "aws", "password", "token", "connection_string", "private_key", "email", "ip_address"]:
            if cat.replace("_", " ") in finding.title.lower() or cat in finding.description.lower():
                category = cat
                break
        
        if categories and category not in categories:
            continue
        
        if category not in categorized:
            categorized[category] = []
        categorized[category].append(finding.to_dict())
    
    total_findings = sum(len(findings) for findings in categorized.values())
    
    return {
        "sensitive_data_found": total_findings > 0,
        "findings_count": total_findings,
        "findings_by_category": categorized,
        "severity_assessment": _assess_severity(categorized),
        "recommendation": (
            "CRITICAL: Sensitive data exposed in response. "
            "Review and remove sensitive data immediately. "
            "Implement data masking and audit logging."
            if total_findings > 0 else
            "No sensitive data patterns detected."
        ),
    }


def _assess_severity(categorized: dict[str, list[dict[str, Any]]]) -> str:
    """Assess overall severity of sensitive data findings."""
    critical_categories = {"aws", "private_key", "connection_string"}
    high_categories = {"api_key", "password", "token"}
    
    if any(cat in categorized for cat in critical_categories):
        return "CRITICAL"
    if any(cat in categorized for cat in high_categories):
        return "HIGH"
    if categorized:
        return "MEDIUM"
    return "NONE"


@register_tool
def check_security_headers(
    response_headers: dict[str, str],
    check_all: bool = True,
) -> dict[str, Any]:
    """Analyze response headers for security configuration.
    
    Checks for presence and configuration of security headers:
    - Content-Security-Policy (CSP)
    - X-Content-Type-Options
    - X-Frame-Options
    - Strict-Transport-Security (HSTS)
    - X-XSS-Protection
    - Referrer-Policy
    - Permissions-Policy
    
    Args:
        response_headers: Response headers dictionary
        check_all: If True, checks all security headers. If False, only critical ones.
        
    Returns:
        Dictionary with header analysis results
        
    Example:
        >>> headers = {"Server": "nginx", "Content-Type": "text/html"}
        >>> result = check_security_headers(headers)
        >>> for missing in result["missing_headers"]:
        ...     print(f"Missing: {missing}")
    """
    security_headers = {
        "Content-Security-Policy": {
            "severity": "medium",
            "description": "Prevents XSS and injection attacks",
            "recommendation": "Add CSP header with strict policy",
        },
        "X-Content-Type-Options": {
            "severity": "low",
            "description": "Prevents MIME type sniffing",
            "recommendation": "Add 'nosniff' value",
        },
        "X-Frame-Options": {
            "severity": "medium",
            "description": "Prevents clickjacking",
            "recommendation": "Add 'DENY' or 'SAMEORIGIN' value",
        },
        "Strict-Transport-Security": {
            "severity": "medium",
            "description": "Enforces HTTPS connections",
            "recommendation": "Add with max-age and includeSubDomains",
        },
        "X-XSS-Protection": {
            "severity": "low",
            "description": "Legacy XSS protection (use CSP instead)",
            "recommendation": "Add '1; mode=block' or rely on CSP",
        },
        "Referrer-Policy": {
            "severity": "low",
            "description": "Controls referrer information",
            "recommendation": "Add 'strict-origin-when-cross-origin'",
        },
        "Permissions-Policy": {
            "severity": "low",
            "description": "Controls browser features",
            "recommendation": "Restrict unnecessary features",
        },
    }
    
    # Normalize header names
    normalized = {k.lower(): v for k, v in response_headers.items()}
    
    present = []
    missing = []
    
    for header, info in security_headers.items():
        if header.lower() in normalized:
            present.append({
                "header": header,
                "value": normalized[header.lower()],
                **info,
            })
        else:
            missing.append({
                "header": header,
                **info,
            })
    
    # Check for risky headers
    risky = []
    if "server" in normalized:
        risky.append({
            "header": "Server",
            "value": normalized["server"],
            "issue": "Server version disclosed",
        })
    if "x-powered-by" in normalized:
        risky.append({
            "header": "X-Powered-By",
            "value": normalized["x-powered-by"],
            "issue": "Technology stack disclosed",
        })
    
    score = len(present) / len(security_headers) * 100
    
    return {
        "score": round(score, 1),
        "grade": _calculate_grade(score, len(risky)),
        "present_headers": present,
        "missing_headers": missing,
        "risky_headers": risky,
        "summary": f"{len(present)}/{len(security_headers)} security headers present. "
                   f"{len(risky)} headers with version/tech disclosure.",
    }


def _calculate_grade(score: float, risky_count: int) -> str:
    """Calculate security header grade."""
    adjusted_score = score - (risky_count * 5)
    
    if adjusted_score >= 90:
        return "A"
    elif adjusted_score >= 80:
        return "B"
    elif adjusted_score >= 60:
        return "C"
    elif adjusted_score >= 40:
        return "D"
    else:
        return "F"
