"""Tests for the Response Analyzer module."""
import pytest

from strix.tools.analyzer.response_analyzer import (
    ResponseAnalyzer,
    AnalysisResult,
    Finding,
    FindingType,
    Severity,
    get_response_analyzer,
)
from strix.tools.analyzer.analyzer_actions import (
    analyze_response,
    compare_responses,
    detect_error_disclosure,
    extract_sensitive_data,
    check_security_headers,
)


class TestFinding:
    """Tests for Finding dataclass."""
    
    def test_finding_creation(self):
        """Test creating a finding."""
        finding = Finding(
            type=FindingType.SQL_ERROR,
            severity=Severity.HIGH,
            title="SQL Error Detected",
            description="MySQL syntax error in response",
            evidence="Error: mysql_query() failed",
        )
        
        assert finding.type == FindingType.SQL_ERROR
        assert finding.severity == Severity.HIGH
        assert finding.title == "SQL Error Detected"
    
    def test_finding_to_dict(self):
        """Test finding serialization."""
        finding = Finding(
            type=FindingType.SENSITIVE_DATA,
            severity=Severity.CRITICAL,
            title="API Key Exposed",
            description="Found API key in response",
            evidence="sk-1234...5678",
        )
        
        d = finding.to_dict()
        
        assert d["type"] == "sensitive_data"
        assert d["severity"] == "critical"


class TestAnalysisResult:
    """Tests for AnalysisResult dataclass."""
    
    def test_result_creation(self):
        """Test creating an analysis result."""
        from datetime import datetime
        result = AnalysisResult(
            id="test_1",
            timestamp=datetime.now(),
        )
        
        assert result.id == "test_1"
        assert result.findings == []
        assert result.risk_score == 0.0
    
    def test_result_to_dict(self):
        """Test result serialization."""
        from datetime import datetime
        result = AnalysisResult(
            id="test_3",
            timestamp=datetime.now(),
            risk_score=0.5,
        )
        
        d = result.to_dict()
        
        assert d["id"] == "test_3"
        assert d["risk_score"] == 0.5


class TestResponseAnalyzer:
    """Tests for ResponseAnalyzer class."""
    
    def test_singleton_pattern(self):
        """Test that ResponseAnalyzer is a singleton."""
        analyzer1 = get_response_analyzer()
        analyzer2 = get_response_analyzer()
        
        assert analyzer1 is analyzer2
    
    def test_analyze_empty_response(self):
        """Test analyzing an empty response."""
        analyzer = get_response_analyzer()
        
        result = analyzer.analyze("")
        
        assert result.id is not None
    
    def test_detect_python_traceback(self):
        """Test detection of Python stack traces."""
        analyzer = get_response_analyzer()
        
        body = """
        Traceback (most recent call last):
          File "/app/views.py", line 42, in get_user
            user = User.objects.get(id=user_id)
        DoesNotExist: User matching query does not exist.
        """
        
        result = analyzer.analyze(body)
        
        assert len(result.findings) > 0
    
    def test_detect_api_key(self):
        """Test detection of API key exposure."""
        analyzer = get_response_analyzer()
        
        body = """
        {
            "config": {
                "api_key": "sk-1234567890abcdefghijklmnopqrstuvwxyz1234567890abc"
            }
        }
        """
        
        result = analyzer.analyze(body)
        
        assert len(result.findings) > 0
    
    def test_detect_aws_key(self):
        """Test detection of AWS access key."""
        analyzer = get_response_analyzer()
        
        body = """
        aws_access_key_id = AKIAIOSFODNN7EXAMPLE
        """
        
        result = analyzer.analyze(body)
        
        assert len(result.findings) > 0
    
    def test_detect_jwt_token(self):
        """Test detection of JWT tokens."""
        analyzer = get_response_analyzer()
        
        body = """
        {
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        }
        """
        
        result = analyzer.analyze(body)
        
        assert len(result.findings) > 0
    
    def test_detect_path_disclosure(self):
        """Test detection of file path disclosure."""
        analyzer = get_response_analyzer()
        
        body = """
        Error loading file from /var/www/html/uploads/config.php
        """
        
        result = analyzer.analyze(body)
        
        assert len(result.findings) > 0
    
    def test_compare_identical_responses(self):
        """Test comparing identical responses."""
        analyzer = get_response_analyzer()
        
        result = analyzer.compare_responses(
            {"body": "Hello World", "status_code": 200},
            {"body": "Hello World", "status_code": 200},
        )
        
        assert result["identical"] is True
        assert result["status_different"] is False
    
    def test_compare_different_responses(self):
        """Test comparing different responses."""
        analyzer = get_response_analyzer()
        
        result = analyzer.compare_responses(
            {"body": "User found: admin", "status_code": 200},
            {"body": "No user found", "status_code": 200},
        )
        
        assert result["identical"] is False
    
    def test_compare_status_difference(self):
        """Test detecting status code difference."""
        analyzer = get_response_analyzer()
        
        result = analyzer.compare_responses(
            {"body": "OK", "status_code": 200},
            {"body": "Error", "status_code": 500},
        )
        
        assert result["status_different"] is True


class TestAnalyzerActions:
    """Tests for analyzer tool actions."""
    
    def test_analyze_response_basic(self):
        """Test analyze_response action."""
        result = analyze_response(
            response_body="<html>Normal page</html>",
            status_code=200,
        )
        
        assert "result_id" in result
        assert "risk_score" in result
        assert "findings_count" in result
    
    def test_compare_responses_action(self):
        """Test compare_responses action."""
        result = compare_responses(
            response1_body="User: admin",
            response2_body="User not found",
            response1_status=200,
            response2_status=200,
        )
        
        assert "identical" in result
        assert "length_difference" in result
    
    def test_detect_error_disclosure_action(self):
        """Test detect_error_disclosure action."""
        result = detect_error_disclosure(
            response_body="""
            Traceback (most recent call last):
              File "/app/api/users.py", line 42
            """,
        )
        
        assert "errors_found" in result
    
    def test_detect_error_disclosure_none(self):
        """Test detect_error_disclosure with no errors."""
        result = detect_error_disclosure(
            response_body="<html>Welcome to our site!</html>",
        )
        
        assert result["errors_found"] is False
    
    def test_extract_sensitive_data_none(self):
        """Test extract_sensitive_data with no sensitive data."""
        result = extract_sensitive_data(
            response_body='{"message": "Hello World"}'
        )
        
        assert "sensitive_data_found" in result
    
    def test_check_security_headers_all_present(self):
        """Test check_security_headers with good headers."""
        result = check_security_headers({
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        })
        
        assert result["score"] == 100.0
        assert result["grade"] == "A"
    
    def test_check_security_headers_missing(self):
        """Test check_security_headers with missing headers."""
        result = check_security_headers({
            "Content-Type": "text/html",
        })
        
        assert len(result["missing_headers"]) > 0
