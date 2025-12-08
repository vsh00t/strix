"""Browser Security Testing module.

Provides automated security testing capabilities using Playwright browser.
"""
from strix.tools.browser_security.security_scanner import (
    BrowserSecurityScanner,
    SecurityFinding,
    get_browser_security_scanner,
)
from strix.tools.browser_security.security_actions import (
    scan_for_xss,
    test_clickjacking,
    extract_forms,
    test_cors,
    test_csp_bypass,
    analyze_cookies,
    capture_dom_state,
)

__all__ = [
    "BrowserSecurityScanner",
    "SecurityFinding",
    "get_browser_security_scanner",
    "scan_for_xss",
    "test_clickjacking",
    "extract_forms",
    "test_cors",
    "test_csp_bypass",
    "analyze_cookies",
    "capture_dom_state",
]
