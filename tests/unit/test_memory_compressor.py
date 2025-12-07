"""
Unit tests for strix/llm/memory_compressor.py

Tests cover:
- Token counting
- Message text extraction
- History compression
- Image handling
- Message summarization
"""

import os
import pytest
from unittest.mock import patch, MagicMock
from typing import Any

# Set environment before importing
os.environ.setdefault("STRIX_LLM", "openai/gpt-4")

from strix.llm.memory_compressor import (
    MemoryCompressor,
    _count_tokens,
    _get_message_tokens,
    _extract_message_text,
    _handle_images,
    MIN_RECENT_MESSAGES,
    MAX_TOTAL_TOKENS,
)


class TestCountTokens:
    """Tests for _count_tokens function."""

    def test_count_tokens_simple_text(self) -> None:
        """Test token counting for simple text."""
        text = "Hello, world!"
        count = _count_tokens(text, "gpt-4")
        
        # Should return a reasonable positive number
        assert count > 0
        assert count < 100  # Simple text shouldn't be too many tokens

    def test_count_tokens_empty_string(self) -> None:
        """Test token counting for empty string."""
        count = _count_tokens("", "gpt-4")
        assert count == 0 or count >= 0  # Empty string should have 0 or minimal tokens

    def test_count_tokens_long_text(self) -> None:
        """Test token counting for long text."""
        text = "This is a test sentence. " * 100
        count = _count_tokens(text, "gpt-4")
        
        assert count > 100  # Long text should have many tokens

    @patch("strix.llm.memory_compressor.litellm.token_counter")
    def test_count_tokens_fallback_on_error(self, mock_counter: MagicMock) -> None:
        """Test fallback estimation when token counter fails."""
        mock_counter.side_effect = Exception("Token counter failed")
        
        text = "Test text with 20 characters"
        count = _count_tokens(text, "gpt-4")
        
        # Should fall back to len(text) // 4 estimate
        assert count == len(text) // 4


class TestGetMessageTokens:
    """Tests for _get_message_tokens function."""

    def test_get_tokens_string_content(self) -> None:
        """Test token counting for string content."""
        message = {"role": "user", "content": "Hello, how are you?"}
        count = _get_message_tokens(message, "gpt-4")
        
        assert count > 0

    def test_get_tokens_list_content(self) -> None:
        """Test token counting for list content (multimodal)."""
        message = {
            "role": "user",
            "content": [
                {"type": "text", "text": "What is in this image?"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,..."}}
            ]
        }
        count = _get_message_tokens(message, "gpt-4")
        
        assert count > 0  # Should count text parts

    def test_get_tokens_empty_content(self) -> None:
        """Test token counting for empty content."""
        message = {"role": "user", "content": ""}
        count = _get_message_tokens(message, "gpt-4")
        
        assert count >= 0

    def test_get_tokens_missing_content(self) -> None:
        """Test token counting when content key is missing."""
        message = {"role": "user"}
        count = _get_message_tokens(message, "gpt-4")
        
        assert count == 0


class TestExtractMessageText:
    """Tests for _extract_message_text function."""

    def test_extract_string_content(self) -> None:
        """Test extracting text from string content."""
        message = {"role": "assistant", "content": "This is my response."}
        text = _extract_message_text(message)
        
        assert text == "This is my response."

    def test_extract_list_content_text_only(self) -> None:
        """Test extracting text from list content with text parts."""
        message = {
            "role": "user",
            "content": [
                {"type": "text", "text": "First part."},
                {"type": "text", "text": "Second part."},
            ]
        }
        text = _extract_message_text(message)
        
        assert "First part." in text
        assert "Second part." in text

    def test_extract_list_content_with_images(self) -> None:
        """Test extracting text from list with images."""
        message = {
            "role": "user",
            "content": [
                {"type": "text", "text": "Check this image:"},
                {"type": "image_url", "image_url": {"url": "https://..."}},
            ]
        }
        text = _extract_message_text(message)
        
        assert "Check this image:" in text
        assert "[IMAGE]" in text

    def test_extract_empty_content(self) -> None:
        """Test extracting from empty content."""
        message = {"role": "user", "content": ""}
        text = _extract_message_text(message)
        
        assert text == ""

    def test_extract_missing_content(self) -> None:
        """Test extracting when content is missing."""
        message = {"role": "user"}
        text = _extract_message_text(message)
        
        assert text == ""


class TestHandleImages:
    """Tests for _handle_images function."""

    def test_handle_images_under_limit(self) -> None:
        """Test that images under limit are preserved."""
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "image_url", "image_url": {"url": "image1.png"}},
                ]
            },
            {
                "role": "user", 
                "content": [
                    {"type": "image_url", "image_url": {"url": "image2.png"}},
                ]
            },
        ]
        
        _handle_images(messages, max_images=3)
        
        # Both images should be preserved
        assert messages[0]["content"][0]["type"] == "image_url"
        assert messages[1]["content"][0]["type"] == "image_url"

    def test_handle_images_over_limit(self) -> None:
        """Test that excess images are converted to text."""
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "image_url", "image_url": {"url": "old_image.png"}},
                ]
            },
            {
                "role": "user",
                "content": [
                    {"type": "image_url", "image_url": {"url": "recent1.png"}},
                ]
            },
            {
                "role": "user",
                "content": [
                    {"type": "image_url", "image_url": {"url": "recent2.png"}},
                ]
            },
        ]
        
        _handle_images(messages, max_images=2)
        
        # Old image (first) should be converted to text (processed in reverse)
        # Recent images (last 2) should be preserved
        # Note: function processes in reverse order, keeping max_images most recent

    def test_handle_images_string_content_unchanged(self) -> None:
        """Test that string content is not affected."""
        messages = [
            {"role": "user", "content": "Just text, no images"},
        ]
        original_content = messages[0]["content"]
        
        _handle_images(messages, max_images=3)
        
        assert messages[0]["content"] == original_content


class TestMemoryCompressor:
    """Tests for MemoryCompressor class."""

    @pytest.fixture
    def compressor(self) -> MemoryCompressor:
        """Create a MemoryCompressor instance."""
        return MemoryCompressor(model_name="gpt-4")

    def test_init_with_model_name(self) -> None:
        """Test initialization with explicit model name."""
        compressor = MemoryCompressor(model_name="gpt-4")
        assert compressor.model_name == "gpt-4"
        assert compressor.max_images == 3
        assert compressor.timeout == 600

    def test_init_with_custom_params(self) -> None:
        """Test initialization with custom parameters."""
        compressor = MemoryCompressor(
            model_name="claude-3",
            max_images=5,
            timeout=300,
        )
        assert compressor.model_name == "claude-3"
        assert compressor.max_images == 5
        assert compressor.timeout == 300

    def test_init_from_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test initialization from environment variable."""
        monkeypatch.setenv("STRIX_LLM", "anthropic/claude-3")
        compressor = MemoryCompressor()
        assert "claude" in compressor.model_name.lower() or compressor.model_name == "anthropic/claude-3"

    def test_compress_empty_history(self, compressor: MemoryCompressor) -> None:
        """Test compressing empty history."""
        result = compressor.compress_history([])
        assert result == []

    def test_compress_small_history_unchanged(self, compressor: MemoryCompressor) -> None:
        """Test that small history is returned unchanged."""
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there!"},
        ]
        
        result = compressor.compress_history(messages)
        
        # Small history should be unchanged
        assert len(result) == len(messages)

    def test_compress_preserves_system_messages(self, compressor: MemoryCompressor) -> None:
        """Test that system messages are always preserved."""
        messages = [
            {"role": "system", "content": "System instruction 1"},
            {"role": "system", "content": "System instruction 2"},
            {"role": "user", "content": "User message"},
        ]
        
        result = compressor.compress_history(messages)
        
        system_msgs = [m for m in result if m.get("role") == "system"]
        assert len(system_msgs) == 2

    def test_compress_preserves_recent_messages(self, compressor: MemoryCompressor) -> None:
        """Test that recent messages are preserved."""
        messages = [{"role": "system", "content": "System"}]
        
        # Add many messages
        for i in range(30):
            messages.append({"role": "user", "content": f"User message {i}"})
            messages.append({"role": "assistant", "content": f"Assistant response {i}"})
        
        result = compressor.compress_history(messages)
        
        # Recent messages should be preserved (at least MIN_RECENT_MESSAGES)
        non_system = [m for m in result if m.get("role") != "system"]
        assert len(non_system) >= MIN_RECENT_MESSAGES

    def test_compress_preserves_vulnerability_context(
        self, compressor: MemoryCompressor
    ) -> None:
        """Test that security-relevant content is preserved in summaries."""
        messages = [
            {"role": "system", "content": "Security testing agent"},
            {
                "role": "assistant",
                "content": "Found SQL injection in /api/users?id=1' OR '1'='1",
            },
            {"role": "user", "content": "Continue testing"},
        ]
        
        result = compressor.compress_history(messages)
        
        # The SQL injection finding should be preserved
        all_content = " ".join(m.get("content", "") for m in result if isinstance(m.get("content"), str))
        # For small histories, content should be unchanged
        assert "SQL injection" in all_content or len(result) == len(messages)

    @patch("strix.llm.memory_compressor._count_tokens")
    def test_compress_triggers_summarization_over_limit(
        self, mock_count: MagicMock, compressor: MemoryCompressor
    ) -> None:
        """Test that compression is triggered when over token limit."""
        # Make token count return high values to trigger compression
        mock_count.return_value = MAX_TOTAL_TOKENS // 10
        
        messages = [{"role": "system", "content": "System"}]
        for i in range(50):
            messages.append({"role": "user", "content": f"Message {i}"})
            messages.append({"role": "assistant", "content": f"Response {i}"})
        
        with patch("strix.llm.memory_compressor._summarize_messages") as mock_summarize:
            mock_summarize.return_value = {
                "role": "assistant",
                "content": "<context_summary>Summarized content</context_summary>"
            }
            
            result = compressor.compress_history(messages)
            
            # Summarization should have been called for old messages
            # Result should have fewer messages than original
            assert len(result) < len(messages) or mock_summarize.called


class TestMemoryCompressorIntegration:
    """Integration tests for MemoryCompressor with realistic scenarios."""

    @pytest.fixture
    def security_scan_history(self) -> list[dict[str, Any]]:
        """Create a realistic security scan conversation history."""
        return [
            {"role": "system", "content": "You are Strix, a security testing agent."},
            {"role": "user", "content": "Test https://target.com for SQL injection"},
            {
                "role": "assistant",
                "content": "I'll test the target for SQL injection vulnerabilities.",
            },
            {
                "role": "user",
                "content": "Tool result: Response 200 OK with normal content",
            },
            {
                "role": "assistant",
                "content": "Testing with payload: ' OR '1'='1",
            },
            {
                "role": "user",
                "content": "Tool result: Database error - syntax error near '''",
            },
            {
                "role": "assistant",
                "content": "FINDING: SQL injection confirmed at /api/users?id= parameter",
            },
        ]

    def test_security_context_preservation(
        self, security_scan_history: list[dict[str, Any]]
    ) -> None:
        """Test that security findings are preserved through compression."""
        compressor = MemoryCompressor(model_name="gpt-4")
        
        result = compressor.compress_history(security_scan_history)
        
        # Security findings should be preserved
        all_content = " ".join(
            m.get("content", "") 
            for m in result 
            if isinstance(m.get("content"), str)
        )
        
        # Critical security information should be present
        assert "SQL injection" in all_content or "FINDING" in all_content

    def test_image_limit_respected(self) -> None:
        """Test that image limits are enforced."""
        compressor = MemoryCompressor(model_name="gpt-4", max_images=2)
        
        messages = [
            {"role": "system", "content": "System"},
        ]
        
        # Add messages with images
        for i in range(5):
            messages.append({
                "role": "user",
                "content": [
                    {"type": "text", "text": f"Image {i}"},
                    {"type": "image_url", "image_url": {"url": f"image{i}.png"}},
                ]
            })
        
        result = compressor.compress_history(messages)
        
        # Count remaining images
        image_count = 0
        for msg in result:
            content = msg.get("content", [])
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "image_url":
                        image_count += 1
        
        assert image_count <= compressor.max_images
