"""Tests for the OAST (Out-of-Band Application Security Testing) module."""
import pytest
from datetime import datetime

from strix.tools.oast.oast_manager import (
    OASTManager,
    OASTPayload,
    OASTCallback,
    get_oast_manager,
)
from strix.tools.oast.oast_actions import (
    generate_oast_payload,
    check_oast_interactions,
    list_oast_payloads,
    clear_oast_payloads,
)


class TestOASTCallback:
    """Tests for OASTCallback dataclass."""
    
    def test_callback_creation(self):
        """Test creating an OAST callback."""
        callback = OASTCallback(
            id="cb_test123",
            payload_id="payload_123",
            callback_type="dns",
            timestamp=datetime.now(),
            source_ip="192.168.1.1",
        )
        
        assert callback.id == "cb_test123"
        assert callback.callback_type == "dns"
        assert callback.source_ip == "192.168.1.1"
    
    def test_callback_to_dict(self):
        """Test callback serialization."""
        callback = OASTCallback(
            id="cb_test456",
            payload_id="payload_456",
            callback_type="http",
            timestamp=datetime.now(),
            source_ip="10.0.0.1",
        )
        
        result = callback.to_dict()
        
        assert result["id"] == "cb_test456"
        assert result["type"] == "http"
        assert "timestamp" in result


class TestOASTPayload:
    """Tests for OASTPayload dataclass."""
    
    def test_payload_creation(self):
        """Test creating an OAST payload."""
        payload = OASTPayload(
            id="oast_1",
            marker="abc123",
            payload_type="both",
            vuln_type="ssrf",
            created_at=datetime.now(),
            dns_payload="abc123.oast.test.com",
            http_payload="http://callback.test.com/abc123",
        )
        
        assert payload.id == "oast_1"
        assert payload.vuln_type == "ssrf"
        assert payload.dns_payload is not None
        assert payload.http_payload is not None


class TestOASTManager:
    """Tests for OASTManager class."""
    
    def test_singleton_pattern(self):
        """Test that OASTManager is a singleton."""
        manager1 = get_oast_manager()
        manager2 = get_oast_manager()
        
        assert manager1 is manager2
    
    def test_generate_marker(self):
        """Test marker generation."""
        manager = get_oast_manager()
        
        marker1 = manager._generate_marker()
        marker2 = manager._generate_marker()
        
        assert marker1 != marker2
        assert len(marker1) > 8
    
    def test_generate_payload_dns(self):
        """Test DNS payload generation."""
        manager = get_oast_manager()
        
        payload = manager.generate_payload(
            vuln_type="ssrf",
            payload_type="dns",
        )
        
        assert payload.dns_payload is not None
        assert payload.marker in payload.dns_payload
    
    def test_generate_payload_http(self):
        """Test HTTP payload generation."""
        manager = get_oast_manager()
        
        payload = manager.generate_payload(
            vuln_type="xxe",
            payload_type="http",
        )
        
        assert payload.http_payload is not None
        assert "http" in payload.http_payload.lower()
    
    def test_get_payload(self):
        """Test retrieving a payload by ID."""
        manager = get_oast_manager()
        
        created = manager.generate_payload(
            vuln_type="sqli_blind",
            payload_type="dns",
        )
        
        retrieved = manager.get_payload(created.id)
        
        assert retrieved is not None
        assert retrieved.id == created.id
    
    def test_get_nonexistent_payload(self):
        """Test retrieving a non-existent payload."""
        manager = get_oast_manager()
        
        result = manager.get_payload("nonexistent_id")
        
        assert result is None


class TestOASTActions:
    """Tests for OAST tool actions."""
    
    def test_generate_oast_payload(self):
        """Test generate_oast_payload action."""
        result = generate_oast_payload(
            vuln_type="ssrf",
            payload_type="both",
            description="Testing SSRF in image URL",
        )
        
        assert "payload_id" in result
        assert "marker" in result
        assert "dns_payload" in result or "http_payload" in result
    
    def test_list_oast_payloads(self):
        """Test listing OAST payloads."""
        generate_oast_payload(vuln_type="ssrf", description="Test 1")
        
        result = list_oast_payloads()
        
        assert "total_count" in result
        assert "payloads" in result
        assert result["total_count"] >= 1
    
    def test_check_oast_interactions_no_callbacks(self):
        """Test checking interactions when none received."""
        create_result = generate_oast_payload(
            vuln_type="sqli_blind",
            description="Testing blind SQLi",
        )
        
        payload_id = create_result["payload_id"]
        check_result = check_oast_interactions(payload_id, wait=False)
        
        assert check_result["payload_id"] == payload_id
        assert check_result["has_callbacks"] is False
    
    def test_check_oast_interactions_nonexistent(self):
        """Test checking non-existent payload."""
        result = check_oast_interactions("nonexistent_payload_id")
        
        assert "error" in result


class TestOASTIntegration:
    """Integration tests for OAST workflow."""
    
    def test_full_workflow(self):
        """Test complete OAST workflow."""
        # Generate payload
        create_result = generate_oast_payload(
            vuln_type="ssrf",
            payload_type="both",
            description="Integration test payload",
        )
        
        assert "payload_id" in create_result
        payload_id = create_result["payload_id"]
        
        # Check for interactions
        check_result = check_oast_interactions(payload_id, wait=False)
        assert "has_callbacks" in check_result
        
        # List payloads
        list_result = list_oast_payloads()
        assert list_result["total_count"] >= 1
