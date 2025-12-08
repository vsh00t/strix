"""Browser Security Scanner for automated DOM and client-side testing.

Provides comprehensive browser-based security testing including XSS detection,
clickjacking analysis, CORS testing, and DOM manipulation security.
"""
import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Literal

logger = logging.getLogger(__name__)


class VulnerabilityCategory(Enum):
    """Categories of browser security vulnerabilities."""
    XSS = "xss"
    CLICKJACKING = "clickjacking"
    CORS = "cors"
    CSP = "csp"
    COOKIE = "cookie"
    DOM = "dom"
    INFORMATION_DISCLOSURE = "information_disclosure"
    OPEN_REDIRECT = "open_redirect"


class Severity(Enum):
    """Severity levels for findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityFinding:
    """Represents a security finding from browser testing."""
    
    id: str
    category: VulnerabilityCategory
    severity: Severity
    title: str
    description: str
    evidence: str
    url: str = ""
    element: str = ""
    payload: str = ""
    recommendation: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence[:500] if len(self.evidence) > 500 else self.evidence,
            "url": self.url,
            "element": self.element,
            "payload": self.payload,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class FormInfo:
    """Information about an HTML form."""
    
    action: str
    method: str
    id: str | None
    name: str | None
    inputs: list[dict[str, Any]]
    has_csrf_token: bool
    enctype: str | None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "action": self.action,
            "method": self.method,
            "id": self.id,
            "name": self.name,
            "inputs": self.inputs,
            "has_csrf_token": self.has_csrf_token,
            "enctype": self.enctype,
        }


@dataclass
class CookieInfo:
    """Information about a browser cookie."""
    
    name: str
    value: str
    domain: str
    path: str
    secure: bool
    http_only: bool
    same_site: str | None
    expires: str | None
    issues: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "value": f"{self.value[:10]}..." if len(self.value) > 10 else self.value,
            "domain": self.domain,
            "path": self.path,
            "secure": self.secure,
            "http_only": self.http_only,
            "same_site": self.same_site,
            "expires": self.expires,
            "issues": self.issues,
        }


# XSS detection payloads
XSS_PAYLOADS = [
    # Basic script tags
    '<script>alert(1)</script>',
    '<script>alert("XSS")</script>',
    '<script>confirm(1)</script>',
    
    # Event handlers
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    
    # JavaScript URLs
    '<a href="javascript:alert(1)">click</a>',
    '<iframe src="javascript:alert(1)">',
    
    # DOM-based
    '<div id=x tabindex=1 onfocus=alert(1)></div>',
    
    # Encoded payloads
    '<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>',
    '<script>eval(atob("YWxlcnQoMSk="))</script>',
    
    # Filter bypass
    '<ScRiPt>alert(1)</ScRiPt>',
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '</title><script>alert(1)</script>',
    '</textarea><script>alert(1)</script>',
]

# Unique markers for XSS detection
XSS_MARKERS = [
    "STRIX_XSS_MARKER_",
    "CANARY_XSS_",
    "PROBE_XSS_",
]


class BrowserSecurityScanner:
    """Browser-based security scanner for client-side vulnerabilities."""
    
    _instance = None
    
    def __new__(cls) -> "BrowserSecurityScanner":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True
        self._finding_count = 0
        self._findings: dict[str, SecurityFinding] = {}
        self._scanned_urls: set[str] = set()
    
    def _generate_finding_id(self) -> str:
        """Generate unique finding ID."""
        self._finding_count += 1
        return f"finding_{self._finding_count}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    def _generate_xss_marker(self) -> str:
        """Generate unique XSS marker for detection."""
        import secrets
        return f"STRIX_XSS_{secrets.token_hex(8)}"
    
    def get_xss_payloads(
        self,
        context: Literal["html", "attribute", "javascript", "url"] = "html",
        marker: str | None = None,
    ) -> list[str]:
        """Get context-aware XSS payloads.
        
        Args:
            context: The injection context
            marker: Unique marker for tracking payload execution
            
        Returns:
            List of XSS payloads for the specified context
        """
        marker = marker or self._generate_xss_marker()
        
        if context == "html":
            return [
                f'<script>window.{marker}=1</script>',
                f'<img src=x onerror="window.{marker}=1">',
                f'<svg onload="window.{marker}=1">',
                f'<body onload="window.{marker}=1">',
                f'<input onfocus="window.{marker}=1" autofocus>',
            ]
        
        if context == "attribute":
            return [
                f'" onmouseover="window.{marker}=1',
                f"' onmouseover='window.{marker}=1",
                f'" onfocus="window.{marker}=1" autofocus="',
                f'"><script>window.{marker}=1</script><"',
            ]
        
        if context == "javascript":
            return [
                f"';window.{marker}=1;//",
                f'";window.{marker}=1;//',
                f"</script><script>window.{marker}=1</script>",
                f"\\';window.{marker}=1;//",
            ]
        
        if context == "url":
            return [
                f"javascript:window.{marker}=1",
                f"data:text/html,<script>window.{marker}=1</script>",
            ]
        
        return XSS_PAYLOADS
    
    def analyze_xss_reflection(
        self,
        input_value: str,
        response_html: str,
        url: str = "",
    ) -> SecurityFinding | None:
        """Analyze if input is reflected in response (potential XSS).
        
        Args:
            input_value: The injected value
            response_html: The HTML response
            url: The target URL
            
        Returns:
            SecurityFinding if XSS indicator detected
        """
        # Check for exact reflection
        if input_value in response_html:
            # Determine context
            context = self._detect_reflection_context(input_value, response_html)
            
            finding = SecurityFinding(
                id=self._generate_finding_id(),
                category=VulnerabilityCategory.XSS,
                severity=Severity.HIGH if context in ["html", "javascript"] else Severity.MEDIUM,
                title=f"XSS Reflection Detected ({context} context)",
                description=f"User input is reflected in the response without proper encoding in {context} context",
                evidence=self._extract_evidence(input_value, response_html),
                url=url,
                payload=input_value,
                recommendation="Implement context-aware output encoding. Use CSP headers.",
            )
            
            self._findings[finding.id] = finding
            return finding
        
        return None
    
    def _detect_reflection_context(self, payload: str, html: str) -> str:
        """Detect the context where reflection occurs."""
        # Find payload position
        pos = html.find(payload)
        if pos == -1:
            return "unknown"
        
        # Get surrounding context
        before = html[max(0, pos-100):pos]
        
        # Check if inside script tag
        if "<script" in before.lower() and "</script>" not in before.lower():
            return "javascript"
        
        # Check if inside attribute
        if re.search(r'[\w-]+=["\']\s*$', before):
            return "attribute"
        
        # Check if inside HTML comment
        if "<!--" in before and "-->" not in before:
            return "comment"
        
        return "html"
    
    def _extract_evidence(self, payload: str, html: str, context_size: int = 100) -> str:
        """Extract evidence with context around the payload."""
        pos = html.find(payload)
        if pos == -1:
            return ""
        
        start = max(0, pos - context_size)
        end = min(len(html), pos + len(payload) + context_size)
        
        return html[start:end]
    
    def analyze_clickjacking(
        self,
        response_headers: dict[str, str],
        url: str = "",
    ) -> list[SecurityFinding]:
        """Analyze response headers for clickjacking protection.
        
        Args:
            response_headers: HTTP response headers
            url: Target URL
            
        Returns:
            List of findings related to clickjacking
        """
        findings = []
        
        # Normalize header names
        headers = {k.lower(): v for k, v in response_headers.items()}
        
        # Check X-Frame-Options
        xfo = headers.get("x-frame-options", "").lower()
        if not xfo:
            finding = SecurityFinding(
                id=self._generate_finding_id(),
                category=VulnerabilityCategory.CLICKJACKING,
                severity=Severity.MEDIUM,
                title="Missing X-Frame-Options Header",
                description="The response does not include X-Frame-Options header, allowing the page to be framed",
                evidence="X-Frame-Options header not present",
                url=url,
                recommendation="Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header",
            )
            findings.append(finding)
            self._findings[finding.id] = finding
        elif xfo not in ["deny", "sameorigin"]:
            finding = SecurityFinding(
                id=self._generate_finding_id(),
                category=VulnerabilityCategory.CLICKJACKING,
                severity=Severity.LOW,
                title="Weak X-Frame-Options Configuration",
                description=f"X-Frame-Options is set to '{xfo}' which may allow framing",
                evidence=f"X-Frame-Options: {xfo}",
                url=url,
                recommendation="Use 'DENY' or 'SAMEORIGIN' for X-Frame-Options",
            )
            findings.append(finding)
            self._findings[finding.id] = finding
        
        # Check CSP frame-ancestors
        csp = headers.get("content-security-policy", "")
        if "frame-ancestors" not in csp.lower():
            finding = SecurityFinding(
                id=self._generate_finding_id(),
                category=VulnerabilityCategory.CLICKJACKING,
                severity=Severity.LOW,
                title="Missing CSP frame-ancestors Directive",
                description="CSP does not include frame-ancestors directive for clickjacking protection",
                evidence="frame-ancestors not in CSP",
                url=url,
                recommendation="Add 'frame-ancestors self' or 'frame-ancestors none' to CSP",
            )
            findings.append(finding)
            self._findings[finding.id] = finding
        
        return findings
    
    def analyze_cors(
        self,
        response_headers: dict[str, str],
        origin: str = "",
        url: str = "",
    ) -> list[SecurityFinding]:
        """Analyze CORS configuration for security issues.
        
        Args:
            response_headers: HTTP response headers
            origin: The Origin header sent in request
            url: Target URL
            
        Returns:
            List of CORS-related findings
        """
        findings = []
        headers = {k.lower(): v for k, v in response_headers.items()}
        
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()
        
        if acao == "*":
            severity = Severity.HIGH if acac == "true" else Severity.MEDIUM
            finding = SecurityFinding(
                id=self._generate_finding_id(),
                category=VulnerabilityCategory.CORS,
                severity=severity,
                title="Wildcard CORS Policy",
                description="CORS allows any origin (*) which may expose sensitive data",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                url=url,
                recommendation="Restrict CORS to specific trusted origins",
            )
            findings.append(finding)
            self._findings[finding.id] = finding
        
        # Check if origin is reflected (vulnerable pattern)
        if origin and acao == origin:
            finding = SecurityFinding(
                id=self._generate_finding_id(),
                category=VulnerabilityCategory.CORS,
                severity=Severity.HIGH,
                title="CORS Origin Reflection",
                description="Server reflects the Origin header, potentially allowing any origin",
                evidence=f"Sent Origin: {origin}, Received ACAO: {acao}",
                url=url,
                recommendation="Validate Origin against whitelist of allowed origins",
            )
            findings.append(finding)
            self._findings[finding.id] = finding
        
        # Credentials with permissive CORS
        if acac == "true" and acao and acao != "null":
            finding = SecurityFinding(
                id=self._generate_finding_id(),
                category=VulnerabilityCategory.CORS,
                severity=Severity.MEDIUM,
                title="CORS Allows Credentials",
                description="CORS configuration allows credentials which increases attack surface",
                evidence=f"Access-Control-Allow-Credentials: {acac}",
                url=url,
                recommendation="Review if credentials are necessary for cross-origin requests",
            )
            findings.append(finding)
            self._findings[finding.id] = finding
        
        return findings
    
    def analyze_csp(
        self,
        csp_header: str,
        url: str = "",
    ) -> list[SecurityFinding]:
        """Analyze Content Security Policy for weaknesses.
        
        Args:
            csp_header: The Content-Security-Policy header value
            url: Target URL
            
        Returns:
            List of CSP-related findings
        """
        findings = []
        
        if not csp_header:
            finding = SecurityFinding(
                id=self._generate_finding_id(),
                category=VulnerabilityCategory.CSP,
                severity=Severity.MEDIUM,
                title="Missing Content Security Policy",
                description="No Content-Security-Policy header present",
                evidence="CSP header not found",
                url=url,
                recommendation="Implement a strict CSP to prevent XSS and data injection",
            )
            findings.append(finding)
            self._findings[finding.id] = finding
            return findings
        
        csp_lower = csp_header.lower()
        
        # Check for unsafe directives
        unsafe_patterns = [
            ("'unsafe-inline'", "Allows inline scripts/styles", Severity.HIGH),
            ("'unsafe-eval'", "Allows eval() and similar functions", Severity.HIGH),
            ("data:", "Allows data: URIs which can execute scripts", Severity.MEDIUM),
            ("*", "Wildcard source allows any host", Severity.MEDIUM),
        ]
        
        for pattern, desc, severity in unsafe_patterns:
            if pattern in csp_lower:
                finding = SecurityFinding(
                    id=self._generate_finding_id(),
                    category=VulnerabilityCategory.CSP,
                    severity=severity,
                    title=f"Weak CSP: {pattern}",
                    description=desc,
                    evidence=f"Found in CSP: {pattern}",
                    url=url,
                    recommendation=f"Remove {pattern} from CSP if possible",
                )
                findings.append(finding)
                self._findings[finding.id] = finding
        
        # Check for missing important directives
        important_directives = [
            ("default-src", "No default-src directive"),
            ("script-src", "No script-src directive"),
            ("object-src", "No object-src directive (allows Flash/plugins)"),
        ]
        
        for directive, desc in important_directives:
            if directive not in csp_lower:
                finding = SecurityFinding(
                    id=self._generate_finding_id(),
                    category=VulnerabilityCategory.CSP,
                    severity=Severity.LOW,
                    title=f"Missing CSP Directive: {directive}",
                    description=desc,
                    evidence=f"{directive} not in CSP",
                    url=url,
                    recommendation=f"Add {directive} directive to CSP",
                )
                findings.append(finding)
                self._findings[finding.id] = finding
        
        return findings
    
    def analyze_cookies(
        self,
        cookies: list[dict[str, Any]],
        url: str = "",
        is_https: bool = True,
    ) -> tuple[list[CookieInfo], list[SecurityFinding]]:
        """Analyze browser cookies for security issues.
        
        Args:
            cookies: List of cookie dictionaries from browser
            url: Target URL
            is_https: Whether the site uses HTTPS
            
        Returns:
            Tuple of (analyzed cookies, security findings)
        """
        analyzed_cookies = []
        findings = []
        
        sensitive_patterns = ["session", "token", "auth", "jwt", "csrf", "user", "login"]
        
        for cookie in cookies:
            issues = []
            name = cookie.get("name", "")
            value = cookie.get("value", "")
            secure = cookie.get("secure", False)
            http_only = cookie.get("httpOnly", False)
            same_site = cookie.get("sameSite", None)
            
            # Check for sensitive cookies
            is_sensitive = any(p in name.lower() for p in sensitive_patterns)
            
            # Security checks
            if is_https and not secure and is_sensitive:
                issues.append("Sensitive cookie missing Secure flag")
            
            if not http_only and is_sensitive:
                issues.append("Sensitive cookie missing HttpOnly flag")
            
            if same_site not in ["Strict", "Lax"] and is_sensitive:
                issues.append(f"Sensitive cookie has weak SameSite: {same_site}")
            
            cookie_info = CookieInfo(
                name=name,
                value=value,
                domain=cookie.get("domain", ""),
                path=cookie.get("path", "/"),
                secure=secure,
                http_only=http_only,
                same_site=same_site,
                expires=cookie.get("expires"),
                issues=issues,
            )
            analyzed_cookies.append(cookie_info)
            
            # Create findings for issues
            if issues:
                finding = SecurityFinding(
                    id=self._generate_finding_id(),
                    category=VulnerabilityCategory.COOKIE,
                    severity=Severity.MEDIUM if is_sensitive else Severity.LOW,
                    title=f"Cookie Security Issue: {name}",
                    description="; ".join(issues),
                    evidence=f"Cookie: {name}, Issues: {', '.join(issues)}",
                    url=url,
                    recommendation="Set Secure, HttpOnly, and SameSite=Strict for sensitive cookies",
                )
                findings.append(finding)
                self._findings[finding.id] = finding
        
        return analyzed_cookies, findings
    
    def extract_forms(
        self,
        html: str,
        base_url: str = "",
    ) -> list[FormInfo]:
        """Extract form information from HTML for security analysis.
        
        Args:
            html: HTML content
            base_url: Base URL for resolving relative form actions
            
        Returns:
            List of FormInfo objects
        """
        forms = []
        
        # Simple regex-based form extraction
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, html, re.DOTALL | re.IGNORECASE)
        
        for i, form_html in enumerate(form_matches):
            # Extract form attributes
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            id_match = re.search(r'id=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            name_match = re.search(r'name=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            enctype_match = re.search(r'enctype=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            
            action = action_match.group(1) if action_match else ""
            method = method_match.group(1).upper() if method_match else "GET"
            
            # Extract inputs
            inputs = []
            input_pattern = r'<input[^>]*>'
            for input_tag in re.findall(input_pattern, form_html, re.IGNORECASE):
                input_type = re.search(r'type=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                input_name = re.search(r'name=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                input_value = re.search(r'value=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                
                inputs.append({
                    "type": input_type.group(1) if input_type else "text",
                    "name": input_name.group(1) if input_name else None,
                    "value": input_value.group(1) if input_value else None,
                })
            
            # Check for CSRF token
            csrf_patterns = ["csrf", "_token", "authenticity_token", "csrfmiddlewaretoken"]
            has_csrf = any(
                inp.get("name") and any(p in inp["name"].lower() for p in csrf_patterns)
                for inp in inputs
            )
            
            form_info = FormInfo(
                action=action,
                method=method,
                id=id_match.group(1) if id_match else None,
                name=name_match.group(1) if name_match else None,
                inputs=inputs,
                has_csrf_token=has_csrf,
                enctype=enctype_match.group(1) if enctype_match else None,
            )
            forms.append(form_info)
        
        return forms
    
    def capture_dom_state(
        self,
        html: str,
        url: str = "",
    ) -> dict[str, Any]:
        """Capture and analyze DOM state for security review.
        
        Args:
            html: HTML content
            url: Target URL
            
        Returns:
            Dictionary with DOM analysis
        """
        # Extract scripts
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
        inline_scripts = [s for s in scripts if s.strip()]
        
        # Extract external scripts
        external_scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE)
        
        # Find potential DOM sinks
        dangerous_sinks = []
        sink_patterns = [
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',
            r'eval\s*\(',
            r'setTimeout\s*\([^,]*["\']',
            r'setInterval\s*\([^,]*["\']',
            r'\.insertAdjacentHTML\s*\(',
            r'location\.href\s*=',
            r'location\.replace\s*\(',
        ]
        
        for script in inline_scripts:
            for pattern in sink_patterns:
                if re.search(pattern, script, re.IGNORECASE):
                    match = re.search(pattern, script, re.IGNORECASE)
                    if match:
                        dangerous_sinks.append({
                            "pattern": pattern,
                            "context": script[max(0, match.start()-30):match.end()+30],
                        })
        
        # Extract links
        links = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
        javascript_links = [l for l in links if l.lower().startswith("javascript:")]
        
        # Find iframes
        iframes = re.findall(r'<iframe[^>]*src=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE)
        
        return {
            "url": url,
            "inline_scripts_count": len(inline_scripts),
            "external_scripts": external_scripts,
            "dangerous_sinks": dangerous_sinks,
            "javascript_links": javascript_links,
            "iframes": iframes,
            "forms_count": len(re.findall(r'<form', html, re.IGNORECASE)),
            "inputs_count": len(re.findall(r'<input', html, re.IGNORECASE)),
        }
    
    def get_finding(self, finding_id: str) -> SecurityFinding | None:
        """Get a finding by ID."""
        return self._findings.get(finding_id)
    
    def get_all_findings(self) -> list[SecurityFinding]:
        """Get all findings."""
        return list(self._findings.values())
    
    def clear_findings(self) -> int:
        """Clear all findings."""
        count = len(self._findings)
        self._findings.clear()
        return count


# Singleton accessor
_scanner_instance: BrowserSecurityScanner | None = None


def get_browser_security_scanner() -> BrowserSecurityScanner:
    """Get the singleton BrowserSecurityScanner instance."""
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = BrowserSecurityScanner()
    return _scanner_instance
