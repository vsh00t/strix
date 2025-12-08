"""
Race Conditions Detector for DAST testing.

Provides mechanisms to detect and exploit race conditions in web applications
through parallel request execution and timing analysis.
"""

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RaceConditionType(Enum):
    """Types of race conditions to test."""

    TIME_OF_CHECK_TIME_OF_USE = "toctou"
    DOUBLE_SPENDING = "double_spending"
    LIMIT_OVERRUN = "limit_overrun"
    AUTHENTICATION_BYPASS = "auth_bypass"
    DUPLICATE_CREATION = "duplicate_creation"
    COUNTER_MANIPULATION = "counter_manipulation"


@dataclass
class RaceRequest:
    """Configuration for a race condition request."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    identifier: str = ""  # To track which request is which

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "identifier": self.identifier,
        }


@dataclass
class RaceResponse:
    """Response from a race condition request."""

    identifier: str
    status_code: int
    body: str
    headers: dict[str, str]
    timing_ms: float
    request_sent_at: float
    response_received_at: float

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "identifier": self.identifier,
            "status_code": self.status_code,
            "body_preview": self.body[:500] if len(self.body) > 500 else self.body,
            "headers": self.headers,
            "timing_ms": self.timing_ms,
            "request_sent_at": self.request_sent_at,
            "response_received_at": self.response_received_at,
        }


@dataclass
class RaceResult:
    """Result of a race condition test."""

    test_type: RaceConditionType
    vulnerable: bool
    confidence: str  # high, medium, low
    responses: list[RaceResponse]
    analysis: dict[str, Any]
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "test_type": self.test_type.value,
            "vulnerable": self.vulnerable,
            "confidence": self.confidence,
            "response_count": len(self.responses),
            "responses": [r.to_dict() for r in self.responses],
            "analysis": self.analysis,
            "recommendations": self.recommendations,
        }


class RaceConditionDetector:
    """
    Detector for race condition vulnerabilities.

    Uses parallel request execution with precise timing to identify
    race conditions in web applications.
    """

    _instance: "RaceConditionDetector | None" = None

    def __new__(cls) -> "RaceConditionDetector":
        """Singleton pattern for race condition detector."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialize the race condition detector."""
        if self._initialized:
            return
        self._initialized = True
        self._http_client: Any = None

    def set_http_client(self, client: Any) -> None:
        """Set the HTTP client for making requests."""
        self._http_client = client

    async def _send_request(self, request: RaceRequest) -> RaceResponse:
        """
        Send a single HTTP request and measure timing.

        This is a placeholder - actual implementation will use Burp's HTTP client.
        """
        start_time = time.time()
        request_sent_at = start_time

        # Placeholder response - actual implementation will use HTTP client
        await asyncio.sleep(0.01)  # Simulate network delay

        end_time = time.time()
        timing_ms = (end_time - start_time) * 1000

        return RaceResponse(
            identifier=request.identifier,
            status_code=200,
            body="",
            headers={},
            timing_ms=timing_ms,
            request_sent_at=request_sent_at,
            response_received_at=end_time,
        )

    async def send_parallel_requests(
        self,
        requests: list[RaceRequest],
        sync_barrier: bool = True,
    ) -> list[RaceResponse]:
        """
        Send multiple requests in parallel with optional synchronization.

        Args:
            requests: List of requests to send
            sync_barrier: If True, use a barrier to synchronize request start times

        Returns:
            List of responses with timing information
        """
        if sync_barrier:
            # Use asyncio barrier to synchronize all requests
            barrier = asyncio.Barrier(len(requests))

            async def synchronized_request(request: RaceRequest) -> RaceResponse:
                await barrier.wait()  # All tasks wait here until everyone is ready
                return await self._send_request(request)

            tasks = [synchronized_request(req) for req in requests]
        else:
            tasks = [self._send_request(req) for req in requests]

        responses = await asyncio.gather(*tasks)
        return list(responses)

    def analyze_responses(
        self,
        responses: list[RaceResponse],
        test_type: RaceConditionType,
    ) -> RaceResult:
        """
        Analyze responses to detect race condition indicators.

        Args:
            responses: List of responses from parallel requests
            test_type: Type of race condition being tested

        Returns:
            RaceResult with analysis
        """
        analysis: dict[str, Any] = {
            "total_requests": len(responses),
            "timing_spread_ms": 0,
            "unique_status_codes": [],
            "success_count": 0,
            "error_count": 0,
        }

        if responses:
            timings = [r.timing_ms for r in responses]
            analysis["timing_spread_ms"] = max(timings) - min(timings)
            analysis["avg_timing_ms"] = sum(timings) / len(timings)

            status_codes = [r.status_code for r in responses]
            analysis["unique_status_codes"] = list(set(status_codes))
            analysis["success_count"] = sum(1 for s in status_codes if 200 <= s < 300)
            analysis["error_count"] = sum(1 for s in status_codes if s >= 400)

        # Determine vulnerability based on test type
        vulnerable = False
        confidence = "low"
        recommendations: list[str] = []

        if test_type == RaceConditionType.DOUBLE_SPENDING:
            # If multiple successful transactions, likely vulnerable
            if analysis["success_count"] > 1:
                vulnerable = True
                confidence = "high" if analysis["success_count"] > 2 else "medium"
                recommendations = [
                    "Implement database-level locks for balance/transaction operations",
                    "Use SELECT FOR UPDATE to prevent concurrent modifications",
                    "Implement idempotency keys for transaction requests",
                    "Add distributed locking for multi-instance deployments",
                ]

        elif test_type == RaceConditionType.LIMIT_OVERRUN:
            # If we exceeded limits (multiple successes when only one should work)
            if analysis["success_count"] > 1:
                vulnerable = True
                confidence = "high"
                recommendations = [
                    "Implement atomic counter operations",
                    "Use database constraints for limit enforcement",
                    "Add rate limiting at infrastructure level",
                    "Consider using Redis INCR for atomic counters",
                ]

        elif test_type == RaceConditionType.DUPLICATE_CREATION:
            # Check for duplicate resource creation
            success_responses = [r for r in responses if 200 <= r.status_code < 300]
            if len(success_responses) > 1:
                vulnerable = True
                confidence = "medium"
                recommendations = [
                    "Implement unique constraints at database level",
                    "Use INSERT ... ON CONFLICT for upsert operations",
                    "Add distributed locks for resource creation",
                    "Implement optimistic locking with version checks",
                ]

        elif test_type == RaceConditionType.TIME_OF_CHECK_TIME_OF_USE:
            # TOCTOU is harder to detect automatically
            # Look for inconsistent responses
            unique_statuses = len(analysis["unique_status_codes"])
            if unique_statuses > 1 and analysis["success_count"] > 0:
                vulnerable = True
                confidence = "low"  # Need manual verification
                recommendations = [
                    "Combine check and use operations atomically",
                    "Use database transactions with appropriate isolation",
                    "Implement file locking for file system operations",
                    "Review all check-then-act patterns in code",
                ]

        elif test_type == RaceConditionType.AUTHENTICATION_BYPASS:
            # Check for inconsistent auth responses
            if analysis["success_count"] > 0 and analysis["error_count"] > 0:
                vulnerable = True
                confidence = "medium"
                recommendations = [
                    "Implement atomic session/token operations",
                    "Use database-backed session storage with locks",
                    "Review authentication middleware for race conditions",
                    "Ensure token generation is thread-safe",
                ]

        elif test_type == RaceConditionType.COUNTER_MANIPULATION:
            if analysis["success_count"] > 1:
                vulnerable = True
                confidence = "high"
                recommendations = [
                    "Use atomic increment operations (e.g., SQL UPDATE counter = counter + 1)",
                    "Implement optimistic locking with version checks",
                    "Use Redis or similar for atomic counter operations",
                    "Avoid read-modify-write patterns",
                ]

        return RaceResult(
            test_type=test_type,
            vulnerable=vulnerable,
            confidence=confidence,
            responses=responses,
            analysis=analysis,
            recommendations=recommendations,
        )

    async def test_double_spending(
        self,
        request: RaceRequest,
        parallel_count: int = 10,
    ) -> RaceResult:
        """
        Test for double-spending race conditions.

        Sends multiple identical requests in parallel to test if a resource
        can be consumed multiple times (e.g., using a discount code twice).

        Args:
            request: The request to duplicate
            parallel_count: Number of parallel requests to send

        Returns:
            RaceResult with analysis
        """
        requests = []
        for i in range(parallel_count):
            req = RaceRequest(
                method=request.method,
                url=request.url,
                headers=request.headers.copy(),
                body=request.body,
                identifier=f"double_spend_{i}",
            )
            requests.append(req)

        responses = await self.send_parallel_requests(requests, sync_barrier=True)
        return self.analyze_responses(responses, RaceConditionType.DOUBLE_SPENDING)

    async def test_limit_overrun(
        self,
        request: RaceRequest,
        parallel_count: int = 20,
    ) -> RaceResult:
        """
        Test for limit overrun race conditions.

        Useful for testing rate limits, usage quotas, or inventory checks.

        Args:
            request: The request to test
            parallel_count: Number of parallel requests

        Returns:
            RaceResult with analysis
        """
        requests = []
        for i in range(parallel_count):
            req = RaceRequest(
                method=request.method,
                url=request.url,
                headers=request.headers.copy(),
                body=request.body,
                identifier=f"limit_overrun_{i}",
            )
            requests.append(req)

        responses = await self.send_parallel_requests(requests, sync_barrier=True)
        return self.analyze_responses(responses, RaceConditionType.LIMIT_OVERRUN)

    async def test_duplicate_creation(
        self,
        request: RaceRequest,
        parallel_count: int = 5,
    ) -> RaceResult:
        """
        Test for duplicate resource creation.

        Tests if the same resource can be created multiple times
        due to race conditions.

        Args:
            request: The creation request to test
            parallel_count: Number of parallel requests

        Returns:
            RaceResult with analysis
        """
        requests = []
        for i in range(parallel_count):
            req = RaceRequest(
                method=request.method,
                url=request.url,
                headers=request.headers.copy(),
                body=request.body,
                identifier=f"duplicate_create_{i}",
            )
            requests.append(req)

        responses = await self.send_parallel_requests(requests, sync_barrier=True)
        return self.analyze_responses(responses, RaceConditionType.DUPLICATE_CREATION)

    async def test_toctou(
        self,
        check_request: RaceRequest,
        use_request: RaceRequest,
        parallel_count: int = 5,
    ) -> RaceResult:
        """
        Test for Time-of-Check to Time-of-Use (TOCTOU) race conditions.

        Sends interleaved check and use requests to detect TOCTOU vulnerabilities.

        Args:
            check_request: The "check" request (e.g., validate permissions)
            use_request: The "use" request (e.g., perform action)
            parallel_count: Number of request pairs

        Returns:
            RaceResult with analysis
        """
        requests = []
        for i in range(parallel_count):
            check_req = RaceRequest(
                method=check_request.method,
                url=check_request.url,
                headers=check_request.headers.copy(),
                body=check_request.body,
                identifier=f"check_{i}",
            )
            use_req = RaceRequest(
                method=use_request.method,
                url=use_request.url,
                headers=use_request.headers.copy(),
                body=use_request.body,
                identifier=f"use_{i}",
            )
            requests.extend([check_req, use_req])

        responses = await self.send_parallel_requests(requests, sync_barrier=True)
        return self.analyze_responses(
            responses, RaceConditionType.TIME_OF_CHECK_TIME_OF_USE
        )

    def generate_race_payloads(
        self,
        base_request: RaceRequest,
        test_type: RaceConditionType,
        count: int = 10,
    ) -> list[RaceRequest]:
        """
        Generate payloads for race condition testing.

        Args:
            base_request: Base request to modify
            test_type: Type of race condition to test
            count: Number of payloads to generate

        Returns:
            List of race condition test requests
        """
        requests: list[RaceRequest] = []

        for i in range(count):
            req = RaceRequest(
                method=base_request.method,
                url=base_request.url,
                headers=base_request.headers.copy(),
                body=base_request.body,
                identifier=f"{test_type.value}_{i}",
            )
            requests.append(req)

        return requests


def get_race_detector() -> RaceConditionDetector:
    """Get the singleton race condition detector instance."""
    return RaceConditionDetector()
