"""Browser Security tool actions for Strix agent.

Provides registered tools for browser-based security testing.
"""
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.browser_security.security_scanner import (
    get_browser_security_scanner,
    VulnerabilityCategory,
    Severity,
)


@register_tool
def scan_for_xss(
    html_content: str,
    input_value: str,
    url: str = "",
    context: Literal["html", "attribute", "javascript", "url"] = "html",
) -> dict[str, Any]:
    """Scan HTML response for XSS vulnerabilities.
    
    Analyzes if user input is reflected in the HTML response and
    determines the injection context for exploitation.
    
    Args:
        html_content: The HTML response to analyze
        input_value: The value that was injected (to check for reflection)
        url: Target URL for context
        context: Expected injection context (html, attribute, javascript, url)
        
    Returns:
        Dictionary containing:
        - reflected: Whether input was reflected
        - xss_payloads: Context-aware payloads to test
        - finding: Security finding if reflection detected
        - context_detected: Detected injection context
        
    Example:
        >>> # After injecting "testXSS123" in a search parameter
        >>> result = scan_for_xss(
        ...     html_content=response.text,
        ...     input_value="testXSS123",
        ...     url="https://example.com/search?q=testXSS123"
        ... )
        >>> if result["reflected"]:
        ...     print(f"XSS potential! Context: {result['context_detected']}")
        ...     for payload in result["xss_payloads"]:
        ...         # Test each payload
    """
    scanner = get_browser_security_scanner()
    
    # Check for reflection
    finding = scanner.analyze_xss_reflection(input_value, html_content, url)
    
    # Get context-aware payloads
    marker = scanner._generate_xss_marker()
    payloads = scanner.get_xss_payloads(context, marker)
    
    return {
        "reflected": finding is not None,
        "context_detected": scanner._detect_reflection_context(input_value, html_content) if finding else None,
        "xss_payloads": payloads,
        "marker": marker,
        "finding": finding.to_dict() if finding else None,
        "recommendation": (
            "Input is reflected in the response. Test with the provided payloads to confirm XSS. "
            "Look for the marker in browser console or DOM to confirm execution."
        ) if finding else "No direct reflection detected. Try encoded payloads or DOM-based XSS testing.",
    }


@register_tool
def test_clickjacking(
    response_headers: dict[str, str],
    url: str = "",
) -> dict[str, Any]:
    """Test for clickjacking vulnerability by analyzing security headers.
    
    Checks X-Frame-Options and CSP frame-ancestors directives.
    
    Args:
        response_headers: HTTP response headers
        url: Target URL
        
    Returns:
        Dictionary with clickjacking analysis results
        
    Example:
        >>> result = test_clickjacking(
        ...     response_headers={"Content-Type": "text/html"},
        ...     url="https://example.com/admin"
        ... )
        >>> if result["vulnerable"]:
        ...     print("Clickjacking possible!")
    """
    scanner = get_browser_security_scanner()
    
    findings = scanner.analyze_clickjacking(response_headers, url)
    
    # Generate PoC iframe
    poc_html = f'''<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC</title></head>
<body>
<h1>Clickjacking Test</h1>
<iframe src="{url}" width="800" height="600" style="opacity:0.5;position:absolute;top:100px;left:100px;"></iframe>
<button style="position:absolute;top:200px;left:200px;">Click me!</button>
</body>
</html>'''
    
    return {
        "vulnerable": len(findings) > 0,
        "findings_count": len(findings),
        "findings": [f.to_dict() for f in findings],
        "headers_present": {
            "x_frame_options": "x-frame-options" in {k.lower() for k in response_headers},
            "csp_frame_ancestors": "frame-ancestors" in response_headers.get("content-security-policy", "").lower(),
        },
        "poc_html": poc_html if findings else None,
        "recommendation": (
            "Page is vulnerable to clickjacking. Add X-Frame-Options: DENY and/or "
            "Content-Security-Policy: frame-ancestors 'none'"
        ) if findings else "Clickjacking protections appear to be in place.",
    }


@register_tool
def extract_forms(
    html_content: str,
    base_url: str = "",
    check_csrf: bool = True,
) -> dict[str, Any]:
    """Extract and analyze HTML forms for security testing.
    
    Identifies forms, inputs, and checks for CSRF protection.
    
    Args:
        html_content: HTML content to analyze
        base_url: Base URL for resolving form actions
        check_csrf: Whether to check for CSRF tokens
        
    Returns:
        Dictionary with form analysis including CSRF status
        
    Example:
        >>> forms = extract_forms(page_html, base_url="https://example.com")
        >>> for form in forms["forms"]:
        ...     if not form["has_csrf_token"] and form["method"] == "POST":
        ...         print(f"Potential CSRF in {form['action']}")
    """
    scanner = get_browser_security_scanner()
    
    forms = scanner.extract_forms(html_content, base_url)
    
    # Analyze CSRF vulnerabilities
    csrf_issues = []
    for form in forms:
        if form.method == "POST" and not form.has_csrf_token:
            csrf_issues.append({
                "action": form.action,
                "method": form.method,
                "issue": "POST form without CSRF token",
            })
    
    return {
        "forms_found": len(forms),
        "forms": [f.to_dict() for f in forms],
        "csrf_issues": csrf_issues,
        "has_csrf_vulnerabilities": len(csrf_issues) > 0,
        "summary": f"Found {len(forms)} forms, {len(csrf_issues)} potential CSRF issues",
    }


@register_tool
def test_cors(
    response_headers: dict[str, str],
    origin_tested: str = "https://evil.com",
    url: str = "",
) -> dict[str, Any]:
    """Test CORS configuration for security issues.
    
    Analyzes Access-Control-Allow-Origin and related headers.
    
    Args:
        response_headers: HTTP response headers
        origin_tested: The Origin header that was sent in the request
        url: Target URL
        
    Returns:
        Dictionary with CORS analysis results
        
    Example:
        >>> # Test with a malicious origin
        >>> result = test_cors(
        ...     response_headers=resp.headers,
        ...     origin_tested="https://attacker.com"
        ... )
        >>> if result["misconfigured"]:
        ...     print("CORS misconfiguration detected!")
    """
    scanner = get_browser_security_scanner()
    
    findings = scanner.analyze_cors(response_headers, origin_tested, url)
    
    acao = response_headers.get("Access-Control-Allow-Origin", "")
    acac = response_headers.get("Access-Control-Allow-Credentials", "")
    
    return {
        "misconfigured": len(findings) > 0,
        "findings_count": len(findings),
        "findings": [f.to_dict() for f in findings],
        "cors_headers": {
            "access_control_allow_origin": acao,
            "access_control_allow_credentials": acac,
            "access_control_allow_methods": response_headers.get("Access-Control-Allow-Methods", ""),
            "access_control_allow_headers": response_headers.get("Access-Control-Allow-Headers", ""),
        },
        "origin_reflected": acao == origin_tested,
        "allows_credentials": acac.lower() == "true",
        "recommendation": (
            "CORS misconfiguration detected. Review and restrict allowed origins. "
            "Never reflect Origin header without validation."
        ) if findings else "CORS configuration appears secure.",
    }


@register_tool
def test_csp_bypass(
    csp_header: str,
    url: str = "",
) -> dict[str, Any]:
    """Analyze Content Security Policy for bypasses and weaknesses.
    
    Identifies unsafe directives, missing protections, and potential bypasses.
    
    Args:
        csp_header: The Content-Security-Policy header value
        url: Target URL
        
    Returns:
        Dictionary with CSP analysis and bypass possibilities
        
    Example:
        >>> result = test_csp_bypass(
        ...     csp_header="default-src 'self' 'unsafe-inline'",
        ...     url="https://example.com"
        ... )
        >>> for bypass in result["bypass_possibilities"]:
        ...     print(f"Bypass: {bypass}")
    """
    scanner = get_browser_security_scanner()
    
    findings = scanner.analyze_csp(csp_header, url)
    
    # Identify bypass possibilities
    bypasses = []
    csp_lower = csp_header.lower() if csp_header else ""
    
    if "'unsafe-inline'" in csp_lower:
        bypasses.append("Inline scripts allowed - standard XSS works")
    
    if "'unsafe-eval'" in csp_lower:
        bypasses.append("eval() allowed - can execute dynamic code")
    
    if "data:" in csp_lower:
        bypasses.append("data: URIs allowed - can use data:text/html payload")
    
    if "*.google.com" in csp_lower or "*.googleapis.com" in csp_lower:
        bypasses.append("Google domains allowed - JSONP endpoints may bypass CSP")
    
    if "*.cloudflare.com" in csp_lower:
        bypasses.append("Cloudflare allowed - cdnjs.cloudflare.com has bypassable scripts")
    
    if "script-src" not in csp_lower and "default-src 'none'" not in csp_lower:
        bypasses.append("No script-src directive - may inherit permissive default-src")
    
    return {
        "has_csp": bool(csp_header),
        "bypasses_found": len(bypasses) > 0,
        "bypass_possibilities": bypasses,
        "findings_count": len(findings),
        "findings": [f.to_dict() for f in findings],
        "csp_header": csp_header,
        "parsed_directives": _parse_csp(csp_header) if csp_header else {},
        "recommendation": (
            f"CSP has {len(bypasses)} potential bypasses. Review and strengthen the policy."
        ) if bypasses else "CSP appears reasonably strict.",
    }


def _parse_csp(csp: str) -> dict[str, list[str]]:
    """Parse CSP header into directives."""
    directives = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directive = tokens[0].lower()
            values = tokens[1:] if len(tokens) > 1 else []
            directives[directive] = values
    return directives


@register_tool
def analyze_cookies(
    cookies: list[dict[str, Any]],
    url: str = "",
    is_https: bool = True,
) -> dict[str, Any]:
    """Analyze browser cookies for security issues.
    
    Checks for missing Secure, HttpOnly, SameSite flags on sensitive cookies.
    
    Args:
        cookies: List of cookie dictionaries from browser
        url: Target URL
        is_https: Whether the site uses HTTPS
        
    Returns:
        Dictionary with cookie analysis and security findings
        
    Example:
        >>> # Get cookies from browser and analyze
        >>> result = analyze_cookies(
        ...     cookies=browser_cookies,
        ...     url="https://example.com",
        ...     is_https=True
        ... )
        >>> for cookie in result["insecure_cookies"]:
        ...     print(f"Insecure: {cookie['name']} - {cookie['issues']}")
    """
    scanner = get_browser_security_scanner()
    
    analyzed, findings = scanner.analyze_cookies(cookies, url, is_https)
    
    insecure_cookies = [c for c in analyzed if c.issues]
    
    return {
        "total_cookies": len(analyzed),
        "insecure_cookies_count": len(insecure_cookies),
        "cookies": [c.to_dict() for c in analyzed],
        "insecure_cookies": [c.to_dict() for c in insecure_cookies],
        "findings": [f.to_dict() for f in findings],
        "summary": f"Analyzed {len(analyzed)} cookies, {len(insecure_cookies)} have security issues",
    }


@register_tool
def capture_dom_state(
    html_content: str,
    url: str = "",
) -> dict[str, Any]:
    """Capture and analyze DOM state for security review.
    
    Identifies potentially dangerous DOM patterns like innerHTML usage,
    eval calls, javascript: links, and more.
    
    Args:
        html_content: HTML content to analyze
        url: Target URL
        
    Returns:
        Dictionary with DOM security analysis
        
    Example:
        >>> result = capture_dom_state(page_html)
        >>> if result["dangerous_sinks"]:
        ...     print("Found dangerous DOM sinks!")
        ...     for sink in result["dangerous_sinks"]:
        ...         print(f"  - {sink['pattern']}")
    """
    scanner = get_browser_security_scanner()
    
    dom_state = scanner.capture_dom_state(html_content, url)
    
    # Assess risk
    risk_factors = []
    if dom_state["dangerous_sinks"]:
        risk_factors.append(f"{len(dom_state['dangerous_sinks'])} dangerous DOM sinks")
    if dom_state["javascript_links"]:
        risk_factors.append(f"{len(dom_state['javascript_links'])} javascript: links")
    if dom_state["inline_scripts_count"] > 5:
        risk_factors.append(f"{dom_state['inline_scripts_count']} inline scripts")
    
    risk_level = "high" if len(risk_factors) >= 2 else "medium" if risk_factors else "low"
    
    return {
        **dom_state,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "recommendation": (
            f"DOM has {len(risk_factors)} risk factors. Review dangerous sinks for DOM-XSS. "
            "Test with DOM-based XSS payloads."
        ) if risk_factors else "No obvious DOM security issues detected.",
    }


@register_tool
def get_security_findings(
    category: str | None = None,
    severity: str | None = None,
) -> dict[str, Any]:
    """Get all security findings from browser security testing.
    
    Args:
        category: Filter by category (xss, clickjacking, cors, csp, cookie, dom)
        severity: Filter by severity (info, low, medium, high, critical)
        
    Returns:
        Dictionary with filtered findings
    """
    scanner = get_browser_security_scanner()
    
    all_findings = scanner.get_all_findings()
    
    # Apply filters
    filtered = all_findings
    
    if category:
        try:
            cat = VulnerabilityCategory(category)
            filtered = [f for f in filtered if f.category == cat]
        except ValueError:
            pass
    
    if severity:
        try:
            sev = Severity(severity)
            filtered = [f for f in filtered if f.severity == sev]
        except ValueError:
            pass
    
    # Group by severity
    by_severity = {}
    for f in filtered:
        sev = f.severity.value
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(f.to_dict())
    
    return {
        "total_findings": len(filtered),
        "findings": [f.to_dict() for f in filtered],
        "by_severity": by_severity,
        "summary": {
            "critical": len([f for f in filtered if f.severity == Severity.CRITICAL]),
            "high": len([f for f in filtered if f.severity == Severity.HIGH]),
            "medium": len([f for f in filtered if f.severity == Severity.MEDIUM]),
            "low": len([f for f in filtered if f.severity == Severity.LOW]),
            "info": len([f for f in filtered if f.severity == Severity.INFO]),
        },
    }
