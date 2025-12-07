"""
Unit tests for strix/llm/request_queue.py

Tests cover:
- Request queue initialization
- Rate limiting
- Retry logic
- Concurrent request handling
"""

import os
import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from typing import Any

from litellm import ModelResponse

# Set environment before importing
os.environ.setdefault("STRIX_LLM", "openai/gpt-4")

from strix.llm.request_queue import (
    LLMRequestQueue,
    get_global_queue,
    should_retry_exception,
)


class TestShouldRetryException:
    """Tests for should_retry_exception function."""

    def test_retry_on_rate_limit(self) -> None:
        """Test that rate limit errors trigger retry."""
        exception = MagicMock()
        exception.status_code = 429
        
        with patch("strix.llm.request_queue.litellm._should_retry", return_value=True):
            assert should_retry_exception(exception) is True

    def test_retry_on_server_error(self) -> None:
        """Test that server errors trigger retry."""
        exception = MagicMock()
        exception.status_code = 500
        
        with patch("strix.llm.request_queue.litellm._should_retry", return_value=True):
            assert should_retry_exception(exception) is True

    def test_no_retry_on_auth_error(self) -> None:
        """Test that auth errors don't trigger retry."""
        exception = MagicMock()
        exception.status_code = 401
        
        with patch("strix.llm.request_queue.litellm._should_retry", return_value=False):
            assert should_retry_exception(exception) is False

    def test_retry_without_status_code(self) -> None:
        """Test retry behavior when no status code is present."""
        exception = Exception("Generic error")
        # Should default to True when no status code
        assert should_retry_exception(exception) is True

    def test_retry_with_response_status_code(self) -> None:
        """Test retry with status code in response object."""
        exception = MagicMock(spec=[])
        exception.response = MagicMock()
        exception.response.status_code = 503
        
        with patch("strix.llm.request_queue.litellm._should_retry", return_value=True):
            assert should_retry_exception(exception) is True


class TestLLMRequestQueueInit:
    """Tests for LLMRequestQueue initialization."""

    def test_default_initialization(self) -> None:
        """Test default initialization values."""
        queue = LLMRequestQueue()
        
        assert queue.max_concurrent == 6
        assert queue.delay_between_requests == 5.0

    def test_custom_initialization(self) -> None:
        """Test custom initialization values."""
        queue = LLMRequestQueue(max_concurrent=10, delay_between_requests=2.0)
        
        assert queue.max_concurrent == 10
        assert queue.delay_between_requests == 2.0

    def test_init_from_env_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test initialization from environment variables."""
        monkeypatch.setenv("LLM_RATE_LIMIT_DELAY", "3.0")
        monkeypatch.setenv("LLM_RATE_LIMIT_CONCURRENT", "4")
        
        queue = LLMRequestQueue()
        
        assert queue.delay_between_requests == 3.0
        assert queue.max_concurrent == 4

    def test_env_vars_override_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that env vars override constructor defaults."""
        monkeypatch.setenv("LLM_RATE_LIMIT_DELAY", "1.0")
        
        # Even with explicit args, env var takes precedence
        queue = LLMRequestQueue(delay_between_requests=10.0)
        
        assert queue.delay_between_requests == 1.0


class TestLLMRequestQueueMakeRequest:
    """Tests for LLMRequestQueue.make_request method."""

    @pytest.fixture
    def queue(self) -> LLMRequestQueue:
        """Create a test queue with minimal delays."""
        return LLMRequestQueue(max_concurrent=2, delay_between_requests=0.01)

    @pytest.fixture
    def mock_model_response(self) -> ModelResponse:
        """Create a proper ModelResponse for testing."""
        return ModelResponse(
            id="test-id",
            choices=[{"index": 0, "message": {"role": "assistant", "content": "Test response"}, "finish_reason": "stop"}],
            created=1234567890,
            model="gpt-4",
            usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        )

    @pytest.mark.asyncio
    async def test_successful_request(self, queue: LLMRequestQueue, mock_model_response: ModelResponse) -> None:
        """Test successful request execution."""
        with patch("strix.llm.request_queue.completion", return_value=mock_model_response):
            result = await queue.make_request({
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "Hello"}],
            })
        
        assert isinstance(result, ModelResponse)
        assert result.id == "test-id"

    @pytest.mark.asyncio
    async def test_request_includes_stream_false(self, queue: LLMRequestQueue, mock_model_response: ModelResponse) -> None:
        """Test that requests include stream=False."""
        with patch("strix.llm.request_queue.completion", return_value=mock_model_response) as mock_completion:
            await queue.make_request({
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "Test"}],
            })
            
            # Verify stream=False was passed
            call_kwargs = mock_completion.call_args
            assert call_kwargs.kwargs.get("stream") is False

    @pytest.mark.skip(reason="Conflicts with Strix terminal signal handler - tested manually")
    @pytest.mark.asyncio
    async def test_rate_limiting_delay(self, queue: LLMRequestQueue, mock_model_response: ModelResponse) -> None:
        """Test that rate limiting delays are applied."""
        with patch("strix.llm.request_queue.completion", return_value=mock_model_response):
            import time
            
            start = time.time()
            await queue.make_request({"model": "gpt-4", "messages": []})
            await queue.make_request({"model": "gpt-4", "messages": []})
            elapsed = time.time() - start
            
            # Should have delay between requests (0.01s in this test)
            assert elapsed >= queue.delay_between_requests * 0.5  # Allow tolerance

    @pytest.mark.skip(reason="Conflicts with Strix terminal signal handler - tested manually")
    @pytest.mark.asyncio
    async def test_retry_on_transient_error(self, queue: LLMRequestQueue, mock_model_response: ModelResponse) -> None:
        """Test that transient errors trigger retry."""
        # First call fails, second succeeds
        call_count = 0
        def mock_completion_fn(*args: Any, **kwargs: Any) -> ModelResponse:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                error = Exception("Temporary error")
                error.status_code = 503  # type: ignore
                raise error
            return mock_model_response
        
        with patch("strix.llm.request_queue.completion", side_effect=mock_completion_fn):
            # This should succeed after retry
            result = await queue.make_request({"model": "gpt-4", "messages": []})
            assert isinstance(result, ModelResponse)
            assert call_count == 2  # One failure, one success


class TestGetGlobalQueue:
    """Tests for get_global_queue function."""

    def test_returns_singleton(self) -> None:
        """Test that get_global_queue returns the same instance."""
        # Reset global queue for test
        import strix.llm.request_queue as rq
        rq._global_queue = None
        
        queue1 = get_global_queue()
        queue2 = get_global_queue()
        
        assert queue1 is queue2

    def test_creates_queue_on_first_call(self) -> None:
        """Test that queue is created on first call."""
        import strix.llm.request_queue as rq
        rq._global_queue = None
        
        queue = get_global_queue()
        
        assert queue is not None
        assert isinstance(queue, LLMRequestQueue)


class TestConcurrentRequests:
    """Tests for concurrent request handling."""

    @pytest.mark.asyncio
    async def test_concurrent_limit_enforced(self) -> None:
        """Test that concurrent request limit is enforced."""
        queue = LLMRequestQueue(max_concurrent=2, delay_between_requests=0.01)
        
        active_requests = 0
        max_active = 0
        
        async def mock_request(args: dict[str, Any]) -> MagicMock:
            nonlocal active_requests, max_active
            active_requests += 1
            max_active = max(max_active, active_requests)
            await asyncio.sleep(0.1)
            active_requests -= 1
            return MagicMock()
        
        with patch.object(queue, "_reliable_request", side_effect=mock_request):
            # Start 4 concurrent requests
            tasks = [
                asyncio.create_task(queue.make_request({"model": "gpt-4", "messages": []}))
                for _ in range(4)
            ]
            
            await asyncio.gather(*tasks)
        
        # Should never exceed max_concurrent
        assert max_active <= queue.max_concurrent


class TestRequestQueueEdgeCases:
    """Edge case tests for request queue."""

    @pytest.fixture
    def mock_model_response(self) -> ModelResponse:
        """Create a proper ModelResponse for testing."""
        return ModelResponse(
            id="test-id",
            choices=[{"index": 0, "message": {"role": "assistant", "content": "Test"}, "finish_reason": "stop"}],
            created=1234567890,
            model="gpt-4",
            usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        )

    @pytest.mark.asyncio
    async def test_empty_completion_args(self, mock_model_response: ModelResponse) -> None:
        """Test handling of empty completion args."""
        queue = LLMRequestQueue(max_concurrent=1, delay_between_requests=0.01)
        
        with patch("strix.llm.request_queue.completion", return_value=mock_model_response):
            result = await queue.make_request({})
            assert isinstance(result, ModelResponse)

    @pytest.mark.asyncio
    async def test_non_model_response_raises(self) -> None:
        """Test that non-ModelResponse raises error."""
        queue = LLMRequestQueue(max_concurrent=1, delay_between_requests=0.01)
        
        # Return something that's not a ModelResponse
        with patch("strix.llm.request_queue.completion", return_value="not a response"):
            with pytest.raises(RuntimeError, match="Unexpected response type"):
                await queue.make_request({"model": "gpt-4", "messages": []})

    def test_semaphore_initialization(self) -> None:
        """Test that semaphore is properly initialized."""
        queue = LLMRequestQueue(max_concurrent=5, delay_between_requests=1.0)
        
        # Semaphore should allow up to max_concurrent acquisitions
        for _ in range(5):
            assert queue._semaphore.acquire(timeout=0)
        
        # Next acquisition should fail immediately
        assert not queue._semaphore.acquire(timeout=0)
        
        # Release all
        for _ in range(5):
            queue._semaphore.release()
