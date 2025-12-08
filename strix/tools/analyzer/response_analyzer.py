"""Response Analyzer for intelligent security analysis.

Provides pattern-based and heuristic analysis of HTTP responses
to detect potential vulnerabilities and information disclosure.
"""
import re
import hashlib
from dataclasses import dataclass, field
from typing import Any, Literal
from datetime import datetime
from enum import Enum


class Severity(Enum):
    """Severity levels for findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingType(Enum):
    """Types of security findings."""
    ERROR_DISCLOSURE = "error_disclosure"
    STACK_TRACE = "stack_trace"
    SQL_ERROR = "sql_error"
    DEBUG_INFO = "debug_info"
    SENSITIVE_DATA = "sensitive_data"
    PATH_DISCLOSURE = "path_disclosure"
    VERSION_DISCLOSURE = "version_disclosure"
    REFLECTION = "reflection"
    HEADER_ANOMALY = "header_anomaly"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"


@dataclass
class Finding:
    """Individual security finding."""
    type: FindingType
    severity: Severity
    title: str
    description: str
    evidence: str
    location: str = ""
    recommendation: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence[:500] if len(self.evidence) > 500 else self.evidence,
            "location": self.location,
            "recommendation": self.recommendation,
        }


@dataclass
class AnalysisResult:
    """Result of response analysis."""
    id: str
    timestamp: datetime
    findings: list[Finding] = field(default_factory=list)
    request_info: dict[str, Any] = field(default_factory=dict)
    response_info: dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "request_info": self.request_info,
            "response_info": self.response_info,
            "risk_score": self.risk_score,
            "highest_severity": self._get_highest_severity(),
        }
    
    def _get_highest_severity(self) -> str:
        """Get the highest severity among findings."""
        severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        if not self.findings:
            return "none"
        max_severity = max(self.findings, key=lambda f: severity_order.index(f.severity))
        return max_severity.severity.value


# Error patterns for different technologies
ERROR_PATTERNS = {
    # SQL Errors
    "mysql": [
        (r"SQL syntax.*MySQL", Severity.HIGH, "MySQL SQL Syntax Error"),
        (r"mysql_fetch_array\(\)", Severity.HIGH, "MySQL Function Error"),
        (r"MySQL Query fail", Severity.HIGH, "MySQL Query Failure"),
        (r"MySqlException", Severity.HIGH, "MySQL Exception"),
        (r"Warning.*mysql_", Severity.MEDIUM, "MySQL Warning"),
        (r"valid MySQL result", Severity.MEDIUM, "MySQL Result Error"),
        (r"SQLSTATE\[\d+\]", Severity.HIGH, "SQL State Error"),
    ],
    "postgresql": [
        (r"PostgreSQL.*ERROR", Severity.HIGH, "PostgreSQL Error"),
        (r"pg_query\(\)", Severity.HIGH, "PostgreSQL Query Error"),
        (r"pg_exec\(\)", Severity.HIGH, "PostgreSQL Exec Error"),
        (r"PG::Error", Severity.HIGH, "PostgreSQL PG Error"),
        (r"Npgsql\.", Severity.HIGH, "Npgsql Error"),
    ],
    "mssql": [
        (r"Microsoft SQL Server", Severity.HIGH, "MSSQL Server Error"),
        (r"Unclosed quotation mark", Severity.HIGH, "MSSQL Syntax Error"),
        (r"ODBC SQL Server Driver", Severity.HIGH, "MSSQL ODBC Error"),
        (r"\bOLE DB\b.*\bSQL Server\b", Severity.HIGH, "MSSQL OLE DB Error"),
        (r"SqlException", Severity.HIGH, "SQL Exception"),
    ],
    "oracle": [
        (r"ORA-\d{5}", Severity.HIGH, "Oracle Error Code"),
        (r"Oracle error", Severity.HIGH, "Oracle Error"),
        (r"quoted string not properly terminated", Severity.HIGH, "Oracle Syntax Error"),
    ],
    "sqlite": [
        (r"SQLite/JDBCDriver", Severity.HIGH, "SQLite JDBC Error"),
        (r"SQLite\.Exception", Severity.HIGH, "SQLite Exception"),
        (r"SQLITE_ERROR", Severity.HIGH, "SQLite Error"),
        (r"System\.Data\.SQLite", Severity.HIGH, "SQLite System Error"),
    ],
    # Web Framework Errors
    "php": [
        (r"Fatal error:.*on line \d+", Severity.MEDIUM, "PHP Fatal Error"),
        (r"Warning:.*on line \d+", Severity.LOW, "PHP Warning"),
        (r"Parse error:.*on line \d+", Severity.MEDIUM, "PHP Parse Error"),
        (r"Notice:.*on line \d+", Severity.LOW, "PHP Notice"),
        (r"<b>(?:Fatal error|Warning|Notice)</b>:.*in <b>.*</b> on line", Severity.MEDIUM, "PHP Error with Path"),
    ],
    "python": [
        (r"Traceback \(most recent call last\)", Severity.MEDIUM, "Python Stack Trace"),
        (r"File \".*\", line \d+", Severity.MEDIUM, "Python Error Location"),
        (r"^\s+raise \w+Error", Severity.MEDIUM, "Python Raised Error"),
        (r"django\..*Exception", Severity.MEDIUM, "Django Exception"),
        (r"flask\..*error", Severity.MEDIUM, "Flask Error"),
    ],
    "java": [
        (r"java\.lang\.\w+Exception", Severity.MEDIUM, "Java Exception"),
        (r"at [\w\.$]+\([\w.]+:\d+\)", Severity.MEDIUM, "Java Stack Trace"),
        (r"org\.springframework\..*Exception", Severity.MEDIUM, "Spring Exception"),
        (r"javax\.servlet\.ServletException", Severity.MEDIUM, "Servlet Exception"),
    ],
    "dotnet": [
        (r"System\.\w+Exception", Severity.MEDIUM, ".NET Exception"),
        (r"at [\w.]+\.[\w.]+\(.*\) in .*:\d+", Severity.MEDIUM, ".NET Stack Trace"),
        (r"Server Error in '/' Application", Severity.HIGH, "ASP.NET Server Error"),
        (r"<title>.*Error.*</title>", Severity.LOW, "Error Page Title"),
    ],
    "node": [
        (r"at \w+ \(.*:\d+:\d+\)", Severity.MEDIUM, "Node.js Stack Trace"),
        (r"ReferenceError:", Severity.MEDIUM, "JavaScript Reference Error"),
        (r"TypeError:", Severity.MEDIUM, "JavaScript Type Error"),
        (r"SyntaxError:", Severity.MEDIUM, "JavaScript Syntax Error"),
    ],
}

# Sensitive data patterns
SENSITIVE_PATTERNS = {
    "api_key": [
        (r"['\"]?(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9]{20,})['\"]", Severity.HIGH, "API Key Exposure"),
        (r"sk-[a-zA-Z0-9]{48}", Severity.CRITICAL, "OpenAI API Key"),
        (r"AIza[0-9A-Za-z\-_]{35}", Severity.HIGH, "Google API Key"),
    ],
    "aws": [
        (r"AKIA[0-9A-Z]{16}", Severity.CRITICAL, "AWS Access Key ID"),
        (r"['\"]?aws[_-]?secret['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9/+=]{40})['\"]", Severity.CRITICAL, "AWS Secret Key"),
    ],
    "password": [
        (r"['\"]?(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{3,})['\"]", Severity.HIGH, "Password Exposure"),
        (r"['\"]?(?:db_pass|database_password)['\"]?\s*[:=]\s*['\"]([^'\"]{3,})['\"]", Severity.CRITICAL, "Database Password"),
    ],
    "token": [
        (r"['\"]?(?:access_token|auth_token|bearer)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9._-]{20,})['\"]", Severity.HIGH, "Access Token"),
        (r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", Severity.MEDIUM, "JWT Token"),
    ],
    "connection_string": [
        (r"(?:mongodb|postgres|mysql|redis)://[^\s<>\"']+", Severity.CRITICAL, "Database Connection String"),
        (r"Data Source=.*?;", Severity.HIGH, "SQL Connection String"),
    ],
    "private_key": [
        (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", Severity.CRITICAL, "Private Key Exposure"),
        (r"-----BEGIN OPENSSH PRIVATE KEY-----", Severity.CRITICAL, "SSH Private Key"),
    ],
    "email": [
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", Severity.LOW, "Email Address"),
    ],
    "ip_address": [
        (r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", Severity.LOW, "Internal IP Address"),
    ],
}

# Path disclosure patterns
PATH_PATTERNS = [
    (r"/(?:var|usr|etc|opt|home|root)/[\w/.-]+", Severity.LOW, "Unix Path Disclosure"),
    (r"[A-Za-z]:\\(?:[\w\\.-]+)+", Severity.LOW, "Windows Path Disclosure"),
    (r"/(?:www|htdocs|public_html|webapp)/[\w/.-]+", Severity.MEDIUM, "Web Root Path"),
]

# Version disclosure patterns
VERSION_PATTERNS = [
    (r"Apache/[\d.]+", Severity.LOW, "Apache Version"),
    (r"nginx/[\d.]+", Severity.LOW, "Nginx Version"),
    (r"PHP/[\d.]+", Severity.LOW, "PHP Version"),
    (r"Python/[\d.]+", Severity.LOW, "Python Version"),
    (r"Node\.js v[\d.]+", Severity.LOW, "Node.js Version"),
    (r"Microsoft-IIS/[\d.]+", Severity.LOW, "IIS Version"),
    (r"X-Powered-By:\s*[\w\s/.-]+", Severity.LOW, "X-Powered-By Header"),
]

# Security header checks
SECURITY_HEADERS = {
    "Content-Security-Policy": (Severity.MEDIUM, "Missing Content Security Policy"),
    "X-Content-Type-Options": (Severity.LOW, "Missing X-Content-Type-Options"),
    "X-Frame-Options": (Severity.LOW, "Missing X-Frame-Options"),
    "Strict-Transport-Security": (Severity.MEDIUM, "Missing HSTS Header"),
    "X-XSS-Protection": (Severity.LOW, "Missing X-XSS-Protection"),
}


class ResponseAnalyzer:
    """Intelligent response analyzer for security testing."""
    
    _instance = None
    
    def __new__(cls) -> "ResponseAnalyzer":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True
        self._analysis_count = 0
        self._results: dict[str, AnalysisResult] = {}
    
    def analyze(
        self,
        response_body: str,
        response_headers: dict[str, str] | None = None,
        status_code: int = 200,
        url: str = "",
        method: str = "GET",
        payload: str | None = None,
    ) -> AnalysisResult:
        """Analyze an HTTP response for security issues.
        
        Args:
            response_body: Response body content
            response_headers: Response headers
            status_code: HTTP status code
            url: Request URL
            method: HTTP method
            payload: Payload used (for reflection detection)
            
        Returns:
            AnalysisResult with findings
        """
        self._analysis_count += 1
        result_id = f"analysis_{self._analysis_count}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        result = AnalysisResult(
            id=result_id,
            timestamp=datetime.now(),
            request_info={
                "url": url,
                "method": method,
                "payload": payload,
            },
            response_info={
                "status_code": status_code,
                "body_length": len(response_body),
                "body_hash": hashlib.md5(response_body.encode()).hexdigest()[:16],
            },
        )
        
        # Run all analyzers
        self._analyze_errors(result, response_body)
        self._analyze_sensitive_data(result, response_body)
        self._analyze_path_disclosure(result, response_body)
        self._analyze_version_disclosure(result, response_body, response_headers)
        self._analyze_headers(result, response_headers)
        
        if payload:
            self._analyze_reflection(result, response_body, payload)
        
        # Calculate risk score
        result.risk_score = self._calculate_risk_score(result.findings)
        
        self._results[result_id] = result
        return result
    
    def _analyze_errors(self, result: AnalysisResult, body: str) -> None:
        """Analyze for error disclosure."""
        for tech, patterns in ERROR_PATTERNS.items():
            for pattern, severity, title in patterns:
                matches = re.findall(pattern, body, re.IGNORECASE | re.MULTILINE)
                if matches:
                    # Get context around the match
                    match = re.search(pattern, body, re.IGNORECASE | re.MULTILINE)
                    if match:
                        start = max(0, match.start() - 50)
                        end = min(len(body), match.end() + 50)
                        evidence = body[start:end]
                        
                        result.findings.append(Finding(
                            type=FindingType.ERROR_DISCLOSURE if "error" in title.lower() else FindingType.STACK_TRACE,
                            severity=severity,
                            title=title,
                            description=f"Detected {tech} error/stack trace disclosure",
                            evidence=evidence,
                            location="response_body",
                            recommendation=f"Disable debug mode and implement proper error handling for {tech}",
                        ))
                    break  # One finding per tech category
    
    def _analyze_sensitive_data(self, result: AnalysisResult, body: str) -> None:
        """Analyze for sensitive data exposure."""
        for category, patterns in SENSITIVE_PATTERNS.items():
            for pattern, severity, title in patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                if matches:
                    # Mask sensitive values
                    masked_evidence = matches[0] if isinstance(matches[0], str) else str(matches[0])
                    if len(masked_evidence) > 8:
                        masked_evidence = masked_evidence[:4] + "..." + masked_evidence[-4:]
                    
                    result.findings.append(Finding(
                        type=FindingType.SENSITIVE_DATA,
                        severity=severity,
                        title=title,
                        description=f"Detected potential {category} exposure in response",
                        evidence=f"Found pattern: {masked_evidence}",
                        location="response_body",
                        recommendation=f"Remove or mask {category} from response. Review data handling.",
                    ))
    
    def _analyze_path_disclosure(self, result: AnalysisResult, body: str) -> None:
        """Analyze for path disclosure."""
        for pattern, severity, title in PATH_PATTERNS:
            matches = re.findall(pattern, body)
            if matches:
                result.findings.append(Finding(
                    type=FindingType.PATH_DISCLOSURE,
                    severity=severity,
                    title=title,
                    description="Server file paths exposed in response",
                    evidence=matches[0][:100],
                    location="response_body",
                    recommendation="Remove internal paths from responses. Use generic error messages.",
                ))
    
    def _analyze_version_disclosure(
        self,
        result: AnalysisResult,
        body: str,
        headers: dict[str, str] | None,
    ) -> None:
        """Analyze for version disclosure."""
        # Check body
        for pattern, severity, title in VERSION_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                result.findings.append(Finding(
                    type=FindingType.VERSION_DISCLOSURE,
                    severity=severity,
                    title=title,
                    description="Software version information disclosed",
                    evidence=match.group(0),
                    location="response_body",
                    recommendation="Hide version information to reduce attack surface.",
                ))
        
        # Check headers
        if headers:
            for header in ["Server", "X-Powered-By", "X-AspNet-Version"]:
                if header in headers:
                    result.findings.append(Finding(
                        type=FindingType.VERSION_DISCLOSURE,
                        severity=Severity.LOW,
                        title=f"{header} Header Disclosure",
                        description=f"Server version exposed via {header} header",
                        evidence=f"{header}: {headers[header]}",
                        location="response_headers",
                        recommendation=f"Remove or obfuscate the {header} header.",
                    ))
    
    def _analyze_headers(self, result: AnalysisResult, headers: dict[str, str] | None) -> None:
        """Analyze response headers for security issues."""
        if not headers:
            return
        
        # Normalize header names
        normalized = {k.lower(): k for k in headers}
        
        for header, (severity, title) in SECURITY_HEADERS.items():
            if header.lower() not in normalized:
                result.findings.append(Finding(
                    type=FindingType.SECURITY_MISCONFIGURATION,
                    severity=severity,
                    title=title,
                    description=f"Security header {header} is not set",
                    evidence=f"Missing: {header}",
                    location="response_headers",
                    recommendation=f"Add {header} header with appropriate value.",
                ))
    
    def _analyze_reflection(self, result: AnalysisResult, body: str, payload: str) -> None:
        """Analyze for payload reflection (XSS indicator)."""
        if not payload:
            return
        
        # Check for exact reflection
        if payload in body:
            result.findings.append(Finding(
                type=FindingType.REFLECTION,
                severity=Severity.MEDIUM,
                title="Payload Reflection Detected",
                description="The injected payload was reflected in the response without encoding",
                evidence=f"Reflected payload: {payload[:100]}",
                location="response_body",
                recommendation="Implement proper output encoding for reflected content.",
            ))
        
        # Check for partial reflection (URL decoded, etc.)
        import urllib.parse
        decoded = urllib.parse.unquote(payload)
        if decoded != payload and decoded in body:
            result.findings.append(Finding(
                type=FindingType.REFLECTION,
                severity=Severity.MEDIUM,
                title="Decoded Payload Reflection",
                description="URL-decoded payload reflected in response",
                evidence=f"Reflected: {decoded[:100]}",
                location="response_body",
                recommendation="Implement proper output encoding.",
            ))
    
    def _calculate_risk_score(self, findings: list[Finding]) -> float:
        """Calculate overall risk score from findings."""
        if not findings:
            return 0.0
        
        severity_weights = {
            Severity.INFO: 0.1,
            Severity.LOW: 0.25,
            Severity.MEDIUM: 0.5,
            Severity.HIGH: 0.75,
            Severity.CRITICAL: 1.0,
        }
        
        total_weight = sum(severity_weights[f.severity] for f in findings)
        max_weight = len(findings) * 1.0  # If all were critical
        
        return min(1.0, total_weight / max_weight) if max_weight > 0 else 0.0
    
    def compare_responses(
        self,
        response1: dict[str, Any],
        response2: dict[str, Any],
    ) -> dict[str, Any]:
        """Compare two responses for differential analysis.
        
        Args:
            response1: First response dict with keys: body, headers, status_code
            response2: Second response dict
            
        Returns:
            Comparison results
        """
        body1 = response1.get("body", "")
        body2 = response2.get("body", "")
        
        # Length comparison
        len1 = len(body1)
        len2 = len(body2)
        length_diff = abs(len1 - len2)
        length_ratio = min(len1, len2) / max(len1, len2, 1)
        
        # Hash comparison
        hash1 = hashlib.md5(body1.encode()).hexdigest()
        hash2 = hashlib.md5(body2.encode()).hexdigest()
        
        # Status comparison
        status1 = response1.get("status_code", 0)
        status2 = response2.get("status_code", 0)
        
        # Word count comparison
        words1 = set(body1.lower().split())
        words2 = set(body2.lower().split())
        common_words = words1 & words2
        word_similarity = len(common_words) / max(len(words1 | words2), 1)
        
        return {
            "identical": hash1 == hash2,
            "status_different": status1 != status2,
            "status_codes": {"response1": status1, "response2": status2},
            "length_difference": length_diff,
            "length_ratio": round(length_ratio, 3),
            "word_similarity": round(word_similarity, 3),
            "analysis": self._interpret_comparison(
                hash1 == hash2,
                status1 != status2,
                length_ratio,
                word_similarity,
            ),
        }
    
    def _interpret_comparison(
        self,
        identical: bool,
        status_diff: bool,
        length_ratio: float,
        word_sim: float,
    ) -> str:
        """Interpret comparison results."""
        if identical:
            return "Responses are identical - no differential detected"
        
        if status_diff:
            return "Status codes differ - potential boolean-based condition detected"
        
        if length_ratio < 0.8:
            return "Significant length difference - potential content-based differential"
        
        if word_sim < 0.7:
            return "Low word similarity - responses have different content structure"
        
        return "Minor differences detected - may indicate subtle condition change"
    
    def get_result(self, result_id: str) -> AnalysisResult | None:
        """Get analysis result by ID."""
        return self._results.get(result_id)
    
    def get_all_results(self) -> list[AnalysisResult]:
        """Get all analysis results."""
        return list(self._results.values())
    
    def clear_results(self) -> None:
        """Clear all stored results."""
        self._results.clear()


# Singleton accessor
_analyzer_instance: ResponseAnalyzer | None = None


def get_response_analyzer() -> ResponseAnalyzer:
    """Get the singleton ResponseAnalyzer instance."""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = ResponseAnalyzer()
    return _analyzer_instance
