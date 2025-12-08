"""Tests for the Fuzzer module."""
import pytest
from unittest.mock import patch, MagicMock

from strix.tools.fuzzer.wordlists import (
    WORDLISTS,
    get_payloads,
    list_available_wordlists,
)
from strix.tools.fuzzer.fuzzer_manager import (
    FuzzerManager,
    FuzzResult,
    get_fuzzer_manager,
)
from strix.tools.fuzzer.fuzzer_actions import (
    get_wordlist,
    list_wordlists,
)


class TestWordlists:
    """Tests for wordlist functionality."""
    
    def test_wordlists_exist(self):
        """Test wordlists are loaded."""
        assert len(WORDLISTS) > 0
    
    def test_get_payloads_sql_injection(self):
        """Test getting SQL injection payloads."""
        payloads = get_payloads("sql_injection")
        
        assert len(payloads) > 0
        # Check common SQL injection patterns
        assert any("'" in p for p in payloads)
    
    def test_get_payloads_xss(self):
        """Test getting XSS payloads."""
        payloads = get_payloads("cross_site_scripting")
        
        assert len(payloads) > 0
        assert any("<script" in p.lower() for p in payloads)
    
    def test_get_payloads_with_max(self):
        """Test getting limited payloads."""
        payloads = get_payloads("sql_injection", max_payloads=5)
        
        assert len(payloads) == 5
    
    def test_get_payloads_url_encoded(self):
        """Test URL encoding payloads."""
        payloads = get_payloads("sql_injection", encoding="url", max_payloads=1)
        
        # Should contain URL encoded characters
        assert len(payloads) == 1
    
    def test_get_payloads_invalid_wordlist(self):
        """Test error on invalid wordlist."""
        with pytest.raises(ValueError) as exc_info:
            get_payloads("nonexistent_wordlist")
        
        assert "Unknown wordlist" in str(exc_info.value)
    
    def test_list_available_wordlists(self):
        """Test listing available wordlists."""
        wordlists = list_available_wordlists()
        
        assert len(wordlists) > 0
        # Check that some common wordlists exist
        assert any("sql" in name for name in wordlists.keys())


class TestFuzzResult:
    """Tests for FuzzResult dataclass."""
    
    def test_result_creation(self):
        """Test creating a fuzz result."""
        result = FuzzResult(
            payload="' OR '1'='1",
            status_code=200,
            response_length=1000,
            response_time_ms=50.5,
            response_hash="abc123",
        )
        
        assert result.payload == "' OR '1'='1"
        assert result.status_code == 200
        assert result.response_length == 1000
    
    def test_result_to_dict(self):
        """Test result serialization."""
        result = FuzzResult(
            payload="<script>",
            status_code=500,
            response_length=500,
            response_time_ms=100.0,
            response_hash="xyz789",
        )
        
        d = result.to_dict()
        
        assert d["payload"] == "<script>"
        assert d["status_code"] == 500


class TestFuzzerManager:
    """Tests for FuzzerManager class."""
    
    def test_singleton_pattern(self):
        """Test that FuzzerManager is a singleton."""
        manager1 = get_fuzzer_manager()
        manager2 = get_fuzzer_manager()
        
        assert manager1 is manager2


class TestFuzzerActions:
    """Tests for fuzzer tool actions."""
    
    def test_list_wordlists(self):
        """Test listing wordlists action."""
        result = list_wordlists()
        
        assert "wordlists" in result
        assert "total_wordlists" in result
        assert result["total_wordlists"] > 0
    
    def test_get_wordlist(self):
        """Test getting a specific wordlist."""
        result = get_wordlist("sql_injection", max_payloads=10)
        
        assert "wordlist" in result
        assert "payloads" in result
        assert len(result["payloads"]) <= 10
    
    def test_get_wordlist_with_encoding(self):
        """Test getting encoded wordlist."""
        result = get_wordlist("sql_injection", encoding="url", max_payloads=5)
        
        assert result["encoding"] == "url"
        assert len(result["payloads"]) <= 5
    
    def test_get_wordlist_invalid(self):
        """Test error handling for invalid wordlist."""
        result = get_wordlist("nonexistent")
        
        assert "error" in result
        assert "available_wordlists" in result
