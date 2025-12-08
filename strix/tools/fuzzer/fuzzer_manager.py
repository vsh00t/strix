"""Fuzzer Manager for intelligent payload injection.

Handles fuzzing sessions, differential analysis, and result aggregation.
"""
import asyncio
import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
from requests.exceptions import RequestException, Timeout

logger = logging.getLogger(__name__)


@dataclass
class FuzzResult:
    """Result of a single fuzz attempt."""
    
    payload: str
    status_code: int
    response_length: int
    response_time_ms: float
    response_hash: str
    error: str | None = None
    reflection_found: bool = False
    reflection_context: str | None = None
    anomaly_score: float = 0.0
    anomaly_reasons: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "payload": self.payload,
            "status_code": self.status_code,
            "response_length": self.response_length,
            "response_time_ms": self.response_time_ms,
            "response_hash": self.response_hash[:16],
            "error": self.error,
            "reflection_found": self.reflection_found,
            "reflection_context": self.reflection_context,
            "anomaly_score": round(self.anomaly_score, 2),
            "anomaly_reasons": self.anomaly_reasons,
            "is_anomaly": self.anomaly_score >= 0.5,
        }


@dataclass
class FuzzSession:
    """A fuzzing session with its configuration and results."""
    
    id: str
    target_url: str
    parameter: str
    wordlist: str
    created_at: datetime
    results: list[FuzzResult] = field(default_factory=list)
    baseline_status: int | None = None
    baseline_length: int | None = None
    baseline_hash: str | None = None
    baseline_time_ms: float | None = None
    total_requests: int = 0
    anomalies_found: int = 0
    status: Literal["pending", "running", "completed", "error"] = "pending"
    error_message: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert session to dictionary."""
        return {
            "id": self.id,
            "target_url": self.target_url,
            "parameter": self.parameter,
            "wordlist": self.wordlist,
            "created_at": self.created_at.isoformat(),
            "status": self.status,
            "total_requests": self.total_requests,
            "anomalies_found": self.anomalies_found,
            "baseline": {
                "status": self.baseline_status,
                "length": self.baseline_length,
                "time_ms": self.baseline_time_ms,
            },
            "error": self.error_message,
        }


class FuzzerManager:
    """Manager for fuzzing operations.
    
    Provides intelligent fuzzing with:
    - Baseline establishment
    - Differential analysis
    - Anomaly detection
    - Rate limiting
    """
    
    def __init__(
        self,
        proxy_url: str | None = None,
        rate_limit: float = 0.1,
        timeout: int = 30,
    ):
        """Initialize Fuzzer Manager.
        
        Args:
            proxy_url: Proxy to route requests through
            rate_limit: Minimum seconds between requests
            timeout: Request timeout in seconds
        """
        self.proxy_url = proxy_url
        self.rate_limit = rate_limit
        self.timeout = timeout
        
        self._sessions: dict[str, FuzzSession] = {}
        self._last_request_time = 0.0
        
        self.proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    
    def _wait_for_rate_limit(self) -> None:
        """Wait to respect rate limiting."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request_time = time.time()
    
    def _make_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> tuple[requests.Response | None, float, str | None]:
        """Make an HTTP request with timing.
        
        Returns:
            Tuple of (response, time_ms, error_message)
        """
        self._wait_for_rate_limit()
        
        try:
            start_time = time.time()
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=body,
                proxies=self.proxies,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            time_ms = (time.time() - start_time) * 1000
            return response, time_ms, None
            
        except Timeout:
            return None, 0, "Request timeout"
        except RequestException as e:
            return None, 0, str(e)
    
    def _compute_hash(self, content: str) -> str:
        """Compute hash of response content."""
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _check_reflection(self, payload: str, response_text: str) -> tuple[bool, str | None]:
        """Check if payload is reflected in response.
        
        Returns:
            Tuple of (found, context)
        """
        if payload in response_text:
            # Find context around reflection
            idx = response_text.find(payload)
            start = max(0, idx - 50)
            end = min(len(response_text), idx + len(payload) + 50)
            context = response_text[start:end]
            return True, context
        
        return False, None
    
    def _calculate_anomaly_score(
        self,
        result: FuzzResult,
        baseline_status: int,
        baseline_length: int,
        baseline_time_ms: float,
    ) -> tuple[float, list[str]]:
        """Calculate anomaly score based on deviation from baseline.
        
        Returns:
            Tuple of (score, reasons)
        """
        score = 0.0
        reasons = []
        
        # Status code difference
        if result.status_code != baseline_status:
            if result.status_code == 500:
                score += 0.4
                reasons.append(f"Status 500 (baseline: {baseline_status})")
            elif result.status_code in (400, 403):
                score += 0.2
                reasons.append(f"Status {result.status_code} (baseline: {baseline_status})")
            else:
                score += 0.3
                reasons.append(f"Status changed: {baseline_status} -> {result.status_code}")
        
        # Response length difference
        if baseline_length > 0:
            length_diff = abs(result.response_length - baseline_length) / baseline_length
            if length_diff > 0.5:  # >50% difference
                score += 0.3
                reasons.append(f"Length diff: {length_diff:.0%}")
            elif length_diff > 0.2:  # >20% difference
                score += 0.15
                reasons.append(f"Length diff: {length_diff:.0%}")
        
        # Response time difference (potential time-based injection)
        if baseline_time_ms > 0:
            time_diff = result.response_time_ms - baseline_time_ms
            if time_diff > 5000:  # >5 seconds slower
                score += 0.5
                reasons.append(f"Time delay: +{time_diff:.0f}ms")
            elif time_diff > 2000:  # >2 seconds slower
                score += 0.3
                reasons.append(f"Time delay: +{time_diff:.0f}ms")
        
        # Reflection detection
        if result.reflection_found:
            score += 0.2
            reasons.append("Payload reflected in response")
        
        return min(score, 1.0), reasons
    
    def establish_baseline(
        self,
        method: str,
        url: str,
        parameter: str,
        original_value: str,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Establish baseline response for comparison.
        
        Args:
            method: HTTP method
            url: Target URL
            parameter: Parameter being fuzzed
            original_value: Original parameter value
            headers: Additional headers
            
        Returns:
            Baseline metrics
        """
        # Make baseline request with original value
        response, time_ms, error = self._make_request(method, url, headers)
        
        if error or response is None:
            return {"error": error, "success": False}
        
        return {
            "success": True,
            "status_code": response.status_code,
            "response_length": len(response.text),
            "response_time_ms": time_ms,
            "response_hash": self._compute_hash(response.text),
        }
    
    def fuzz_parameter(
        self,
        method: str,
        url: str,
        parameter: str,
        payloads: list[str],
        param_location: Literal["query", "body", "path", "header"] = "query",
        headers: dict[str, str] | None = None,
        body_template: str | None = None,
        establish_baseline: bool = True,
    ) -> FuzzSession:
        """Fuzz a parameter with given payloads.
        
        Args:
            method: HTTP method
            url: Target URL
            parameter: Parameter to fuzz
            payloads: List of payloads to inject
            param_location: Where the parameter is located
            headers: Additional headers
            body_template: Body template with {FUZZ} placeholder
            establish_baseline: Whether to establish baseline first
            
        Returns:
            FuzzSession with results
        """
        session_id = f"fuzz_{secrets.token_hex(8)}"
        session = FuzzSession(
            id=session_id,
            target_url=url,
            parameter=parameter,
            wordlist="custom",
            created_at=datetime.now(UTC),
            status="running",
        )
        self._sessions[session_id] = session
        
        # Establish baseline if requested
        if establish_baseline:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            original_value = query_params.get(parameter, [""])[0] if param_location == "query" else ""
            
            baseline = self.establish_baseline(method, url, parameter, original_value, headers)
            if baseline.get("success"):
                session.baseline_status = baseline["status_code"]
                session.baseline_length = baseline["response_length"]
                session.baseline_time_ms = baseline["response_time_ms"]
                session.baseline_hash = baseline["response_hash"]
        
        # Fuzz with each payload
        for payload in payloads:
            try:
                result = self._fuzz_single(
                    method=method,
                    url=url,
                    parameter=parameter,
                    payload=payload,
                    param_location=param_location,
                    headers=headers,
                    body_template=body_template,
                    session=session,
                )
                session.results.append(result)
                session.total_requests += 1
                
                if result.anomaly_score >= 0.5:
                    session.anomalies_found += 1
                    
            except Exception as e:
                logger.error(f"Error fuzzing with payload {payload[:50]}: {e}")
        
        session.status = "completed"
        return session
    
    def _fuzz_single(
        self,
        method: str,
        url: str,
        parameter: str,
        payload: str,
        param_location: str,
        headers: dict[str, str] | None,
        body_template: str | None,
        session: FuzzSession,
    ) -> FuzzResult:
        """Execute a single fuzz attempt."""
        # Build the fuzzed request
        fuzzed_url = url
        fuzzed_body = None
        fuzzed_headers = headers.copy() if headers else {}
        
        if param_location == "query":
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            query_params[parameter] = [payload]
            new_query = urlencode(query_params, doseq=True)
            fuzzed_url = urlunparse(parsed._replace(query=new_query))
            
        elif param_location == "body":
            if body_template:
                fuzzed_body = body_template.replace("{FUZZ}", payload)
            else:
                fuzzed_body = f"{parameter}={payload}"
                
        elif param_location == "header":
            fuzzed_headers[parameter] = payload
            
        elif param_location == "path":
            fuzzed_url = url.replace("{FUZZ}", payload)
        
        # Make request
        response, time_ms, error = self._make_request(
            method, fuzzed_url, fuzzed_headers, fuzzed_body
        )
        
        if error or response is None:
            return FuzzResult(
                payload=payload,
                status_code=0,
                response_length=0,
                response_time_ms=time_ms,
                response_hash="",
                error=error,
            )
        
        # Analyze response
        response_text = response.text
        response_hash = self._compute_hash(response_text)
        reflection_found, reflection_context = self._check_reflection(payload, response_text)
        
        result = FuzzResult(
            payload=payload,
            status_code=response.status_code,
            response_length=len(response_text),
            response_time_ms=time_ms,
            response_hash=response_hash,
            reflection_found=reflection_found,
            reflection_context=reflection_context,
        )
        
        # Calculate anomaly score if baseline exists
        if session.baseline_status is not None:
            score, reasons = self._calculate_anomaly_score(
                result,
                session.baseline_status,
                session.baseline_length or 0,
                session.baseline_time_ms or 0,
            )
            result.anomaly_score = score
            result.anomaly_reasons = reasons
        
        return result
    
    def get_session(self, session_id: str) -> FuzzSession | None:
        """Get a fuzzing session by ID."""
        return self._sessions.get(session_id)
    
    def list_sessions(self) -> list[FuzzSession]:
        """List all fuzzing sessions."""
        return list(self._sessions.values())
    
    def get_anomalies(self, session_id: str, min_score: float = 0.5) -> list[FuzzResult]:
        """Get anomalous results from a session."""
        session = self._sessions.get(session_id)
        if not session:
            return []
        
        return [r for r in session.results if r.anomaly_score >= min_score]


# Global manager instance
_global_fuzzer_manager: FuzzerManager | None = None


def get_fuzzer_manager() -> FuzzerManager:
    """Get or create the global fuzzer manager.
    
    The fuzzer will route traffic through Caido proxy by default,
    which may have an upstream proxy configured (e.g., Burp Suite).
    """
    global _global_fuzzer_manager
    if _global_fuzzer_manager is None:
        # Use Caido as proxy so traffic is captured and can be forwarded to upstream proxy
        caido_port = os.getenv("CAIDO_PORT", "56789")
        proxy_url = f"http://127.0.0.1:{caido_port}"
        _global_fuzzer_manager = FuzzerManager(proxy_url=proxy_url)
    return _global_fuzzer_manager


def reset_fuzzer_manager() -> None:
    """Reset the global fuzzer manager (for testing)."""
    global _global_fuzzer_manager
    _global_fuzzer_manager = None
