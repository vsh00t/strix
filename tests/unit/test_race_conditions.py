"""
Tests for Race Conditions Detector module.
"""

import pytest

from strix.tools.race_conditions.race_detector import (
    RaceConditionDetector,
    RaceConditionType,
    RaceRequest,
    RaceResponse,
    RaceResult,
    get_race_detector,
)


class TestRaceRequest:
    """Tests for RaceRequest dataclass."""

    def test_race_request_creation(self) -> None:
        """Test creating a race request."""
        request = RaceRequest(
            method="POST",
            url="https://example.com/api/transfer",
            headers={"Authorization": "Bearer token"},
            body='{"amount": 100}',
            identifier="test_1",
        )

        assert request.method == "POST"
        assert request.url == "https://example.com/api/transfer"
        assert request.headers["Authorization"] == "Bearer token"
        assert request.body == '{"amount": 100}'
        assert request.identifier == "test_1"

    def test_race_request_to_dict(self) -> None:
        """Test converting request to dictionary."""
        request = RaceRequest(
            method="GET",
            url="https://example.com/balance",
            identifier="balance_check",
        )

        result = request.to_dict()

        assert result["method"] == "GET"
        assert result["url"] == "https://example.com/balance"
        assert result["identifier"] == "balance_check"

    def test_race_request_defaults(self) -> None:
        """Test default values for RaceRequest."""
        request = RaceRequest(method="POST", url="https://example.com")

        assert request.headers == {}
        assert request.body is None
        assert request.identifier == ""


class TestRaceResponse:
    """Tests for RaceResponse dataclass."""

    def test_race_response_creation(self) -> None:
        """Test creating a race response."""
        response = RaceResponse(
            identifier="test_1",
            status_code=200,
            body='{"success": true}',
            headers={"Content-Type": "application/json"},
            timing_ms=45.5,
            request_sent_at=1000.0,
            response_received_at=1000.0455,
        )

        assert response.identifier == "test_1"
        assert response.status_code == 200
        assert response.timing_ms == 45.5

    def test_race_response_to_dict(self) -> None:
        """Test converting response to dictionary."""
        response = RaceResponse(
            identifier="test_1",
            status_code=200,
            body="x" * 1000,  # Long body
            headers={},
            timing_ms=50.0,
            request_sent_at=1000.0,
            response_received_at=1000.05,
        )

        result = response.to_dict()

        assert result["status_code"] == 200
        assert len(result["body_preview"]) <= 503  # 500 + "..."


class TestRaceResult:
    """Tests for RaceResult dataclass."""

    def test_race_result_creation(self) -> None:
        """Test creating a race result."""
        result = RaceResult(
            test_type=RaceConditionType.DOUBLE_SPENDING,
            vulnerable=True,
            confidence="high",
            responses=[],
            analysis={"success_count": 5},
            recommendations=["Add locking"],
        )

        assert result.test_type == RaceConditionType.DOUBLE_SPENDING
        assert result.vulnerable is True
        assert result.confidence == "high"

    def test_race_result_to_dict(self) -> None:
        """Test converting result to dictionary."""
        result = RaceResult(
            test_type=RaceConditionType.LIMIT_OVERRUN,
            vulnerable=False,
            confidence="low",
            responses=[],
            analysis={},
            recommendations=[],
        )

        output = result.to_dict()

        assert output["test_type"] == "limit_overrun"
        assert output["vulnerable"] is False


class TestRaceConditionTypes:
    """Tests for RaceConditionType enum."""

    def test_all_types_exist(self) -> None:
        """Test that all expected race condition types exist."""
        assert RaceConditionType.TIME_OF_CHECK_TIME_OF_USE
        assert RaceConditionType.DOUBLE_SPENDING
        assert RaceConditionType.LIMIT_OVERRUN
        assert RaceConditionType.AUTHENTICATION_BYPASS
        assert RaceConditionType.DUPLICATE_CREATION
        assert RaceConditionType.COUNTER_MANIPULATION

    def test_type_values(self) -> None:
        """Test enum values."""
        assert RaceConditionType.DOUBLE_SPENDING.value == "double_spending"
        assert RaceConditionType.LIMIT_OVERRUN.value == "limit_overrun"
        assert RaceConditionType.TIME_OF_CHECK_TIME_OF_USE.value == "toctou"


class TestRaceConditionDetector:
    """Tests for RaceConditionDetector class."""

    def test_singleton_pattern(self) -> None:
        """Test that detector follows singleton pattern."""
        detector1 = get_race_detector()
        detector2 = get_race_detector()
        assert detector1 is detector2

    def test_analyze_responses_double_spending(self) -> None:
        """Test response analysis for double spending."""
        detector = get_race_detector()

        # Simulate multiple successful responses (vulnerable)
        responses = [
            RaceResponse(
                identifier=f"test_{i}",
                status_code=200,
                body='{"success": true}',
                headers={},
                timing_ms=50.0,
                request_sent_at=1000.0,
                response_received_at=1000.05,
            )
            for i in range(5)
        ]

        result = detector.analyze_responses(responses, RaceConditionType.DOUBLE_SPENDING)

        assert result.vulnerable is True
        assert result.confidence in ["high", "medium"]
        assert len(result.recommendations) > 0

    def test_analyze_responses_limit_overrun(self) -> None:
        """Test response analysis for limit overrun."""
        detector = get_race_detector()

        responses = [
            RaceResponse(
                identifier=f"test_{i}",
                status_code=200,
                body="",
                headers={},
                timing_ms=30.0,
                request_sent_at=1000.0,
                response_received_at=1000.03,
            )
            for i in range(10)
        ]

        result = detector.analyze_responses(responses, RaceConditionType.LIMIT_OVERRUN)

        assert result.vulnerable is True
        assert result.analysis["success_count"] == 10

    def test_analyze_responses_no_vulnerability(self) -> None:
        """Test response analysis when not vulnerable."""
        detector = get_race_detector()

        # Only one success, rest are errors
        responses = [
            RaceResponse(
                identifier="test_0",
                status_code=200,
                body='{"success": true}',
                headers={},
                timing_ms=50.0,
                request_sent_at=1000.0,
                response_received_at=1000.05,
            )
        ] + [
            RaceResponse(
                identifier=f"test_{i}",
                status_code=409,
                body='{"error": "conflict"}',
                headers={},
                timing_ms=50.0,
                request_sent_at=1000.0,
                response_received_at=1000.05,
            )
            for i in range(1, 5)
        ]

        result = detector.analyze_responses(responses, RaceConditionType.DOUBLE_SPENDING)

        assert result.vulnerable is False

    def test_analyze_responses_timing_analysis(self) -> None:
        """Test timing analysis in results."""
        detector = get_race_detector()

        responses = [
            RaceResponse(
                identifier=f"test_{i}",
                status_code=200,
                body="",
                headers={},
                timing_ms=float(50 + i * 10),  # 50, 60, 70, 80, 90
                request_sent_at=1000.0,
                response_received_at=1000.0 + (50 + i * 10) / 1000,
            )
            for i in range(5)
        ]

        result = detector.analyze_responses(responses, RaceConditionType.DOUBLE_SPENDING)

        assert result.analysis["timing_spread_ms"] == 40.0  # 90 - 50
        assert result.analysis["avg_timing_ms"] == 70.0

    def test_generate_race_payloads(self) -> None:
        """Test payload generation."""
        detector = get_race_detector()

        base_request = RaceRequest(
            method="POST",
            url="https://example.com/api",
            headers={"Authorization": "Bearer token"},
            body='{"data": "test"}',
        )

        payloads = detector.generate_race_payloads(
            base_request, RaceConditionType.DOUBLE_SPENDING, count=15
        )

        assert len(payloads) == 15
        assert all(p.method == "POST" for p in payloads)
        assert all(p.url == "https://example.com/api" for p in payloads)
        assert all("double_spending" in p.identifier for p in payloads)


class TestRaceConditionDetectorAsync:
    """Async tests for RaceConditionDetector."""

    @pytest.mark.asyncio
    async def test_send_parallel_requests(self) -> None:
        """Test parallel request sending."""
        detector = get_race_detector()

        requests = [
            RaceRequest(
                method="GET",
                url="https://example.com",
                identifier=f"test_{i}",
            )
            for i in range(5)
        ]

        responses = await detector.send_parallel_requests(requests, sync_barrier=True)

        assert len(responses) == 5
        assert all(isinstance(r, RaceResponse) for r in responses)

    @pytest.mark.asyncio
    async def test_test_double_spending(self) -> None:
        """Test double spending test execution."""
        detector = get_race_detector()

        request = RaceRequest(
            method="POST",
            url="https://example.com/redeem",
            body='{"code": "DISCOUNT"}',
        )

        result = await detector.test_double_spending(request, parallel_count=5)

        assert isinstance(result, RaceResult)
        assert result.test_type == RaceConditionType.DOUBLE_SPENDING
        assert len(result.responses) == 5

    @pytest.mark.asyncio
    async def test_test_limit_overrun(self) -> None:
        """Test limit overrun test execution."""
        detector = get_race_detector()

        request = RaceRequest(
            method="POST",
            url="https://example.com/api/action",
        )

        result = await detector.test_limit_overrun(request, parallel_count=10)

        assert isinstance(result, RaceResult)
        assert result.test_type == RaceConditionType.LIMIT_OVERRUN
        assert len(result.responses) == 10

    @pytest.mark.asyncio
    async def test_test_duplicate_creation(self) -> None:
        """Test duplicate creation test execution."""
        detector = get_race_detector()

        request = RaceRequest(
            method="POST",
            url="https://example.com/api/create",
            body='{"name": "resource"}',
        )

        result = await detector.test_duplicate_creation(request, parallel_count=3)

        assert isinstance(result, RaceResult)
        assert result.test_type == RaceConditionType.DUPLICATE_CREATION

    @pytest.mark.asyncio
    async def test_test_toctou(self) -> None:
        """Test TOCTOU test execution."""
        detector = get_race_detector()

        check_request = RaceRequest(
            method="GET",
            url="https://example.com/api/check",
        )

        use_request = RaceRequest(
            method="POST",
            url="https://example.com/api/action",
        )

        result = await detector.test_toctou(check_request, use_request, parallel_count=3)

        assert isinstance(result, RaceResult)
        assert result.test_type == RaceConditionType.TIME_OF_CHECK_TIME_OF_USE
        # 3 check + 3 use = 6 total requests
        assert len(result.responses) == 6
