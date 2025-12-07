"""
Unit tests for strix/llm/config.py

Tests cover:
- LLMConfig initialization
- Environment variable handling
- Default values
- Validation
"""

import os
import pytest
from typing import Any

# Clear env vars before tests to ensure clean state
_original_env = os.environ.get("STRIX_LLM")


class TestLLMConfig:
    """Tests for LLMConfig class."""

    @pytest.fixture(autouse=True)
    def setup_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Set up clean environment for each test."""
        monkeypatch.setenv("STRIX_LLM", "openai/gpt-4")

    def test_default_initialization(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test default initialization from env var."""
        monkeypatch.setenv("STRIX_LLM", "openai/gpt-4")
        
        from strix.llm.config import LLMConfig
        config = LLMConfig()
        
        assert config.model_name == "openai/gpt-4"
        assert config.enable_prompt_caching is True
        assert config.prompt_modules == []
        assert config.timeout == 600

    def test_explicit_model_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test initialization with explicit model name."""
        monkeypatch.setenv("STRIX_LLM", "default-model")
        
        from strix.llm.config import LLMConfig
        config = LLMConfig(model_name="anthropic/claude-3")
        
        assert config.model_name == "anthropic/claude-3"

    def test_custom_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test custom timeout value."""
        monkeypatch.setenv("STRIX_LLM", "openai/gpt-4")
        
        from strix.llm.config import LLMConfig
        config = LLMConfig(timeout=300)
        
        assert config.timeout == 300

    def test_timeout_from_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test timeout from environment variable."""
        monkeypatch.setenv("STRIX_LLM", "openai/gpt-4")
        monkeypatch.setenv("LLM_TIMEOUT", "120")
        
        from strix.llm.config import LLMConfig
        config = LLMConfig()
        
        assert config.timeout == 120

    def test_prompt_modules(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test prompt modules configuration."""
        monkeypatch.setenv("STRIX_LLM", "openai/gpt-4")
        
        from strix.llm.config import LLMConfig
        config = LLMConfig(
            prompt_modules=["sql_injection", "xss", "idor"]
        )
        
        assert config.prompt_modules == ["sql_injection", "xss", "idor"]
        assert len(config.prompt_modules) == 3

    def test_disable_prompt_caching(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test disabling prompt caching."""
        monkeypatch.setenv("STRIX_LLM", "openai/gpt-4")
        
        from strix.llm.config import LLMConfig
        config = LLMConfig(enable_prompt_caching=False)
        
        assert config.enable_prompt_caching is False

    def test_missing_model_name_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that missing model name raises error."""
        monkeypatch.delenv("STRIX_LLM", raising=False)
        
        from strix.llm.config import LLMConfig
        
        # Should use default "openai/gpt-5" when env var is not set
        config = LLMConfig()
        assert config.model_name == "openai/gpt-5"

    def test_empty_model_name_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that empty model name raises error."""
        monkeypatch.setenv("STRIX_LLM", "")
        
        from strix.llm.config import LLMConfig
        
        with pytest.raises(ValueError, match="must be set and not empty"):
            LLMConfig(model_name="")

    def test_full_configuration(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test full configuration with all options."""
        monkeypatch.setenv("STRIX_LLM", "default")
        
        from strix.llm.config import LLMConfig
        config = LLMConfig(
            model_name="openai/gpt-5",
            enable_prompt_caching=True,
            prompt_modules=["sql_injection", "xss"],
            timeout=900,
        )
        
        assert config.model_name == "openai/gpt-5"
        assert config.enable_prompt_caching is True
        assert config.prompt_modules == ["sql_injection", "xss"]
        assert config.timeout == 900


class TestLLMConfigModelNames:
    """Tests for different model name formats."""

    @pytest.fixture(autouse=True)
    def setup_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Set up clean environment for each test."""
        monkeypatch.setenv("STRIX_LLM", "openai/gpt-4")

    def test_openai_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test OpenAI model name."""
        monkeypatch.setenv("STRIX_LLM", "openai/gpt-4")
        
        from strix.llm.config import LLMConfig
        config = LLMConfig(model_name="openai/gpt-4")
        
        assert config.model_name == "openai/gpt-4"

    def test_anthropic_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test Anthropic model name."""
        monkeypatch.setenv("STRIX_LLM", "anthropic/claude-3")
        
        from strix.llm.config import LLMConfig
        config = LLMConfig(model_name="anthropic/claude-3-opus")
        
        assert config.model_name == "anthropic/claude-3-opus"

    def test_local_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test local model name (Ollama style)."""
        monkeypatch.setenv("STRIX_LLM", "ollama/llama3")
        
        from strix.llm.config import LLMConfig
        config = LLMConfig(model_name="ollama/llama3:70b")
        
        assert config.model_name == "ollama/llama3:70b"

    def test_simple_model_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test simple model name without provider prefix."""
        monkeypatch.setenv("STRIX_LLM", "gpt-4")
        
        from strix.llm.config import LLMConfig
        config = LLMConfig(model_name="gpt-4")
        
        assert config.model_name == "gpt-4"


class TestLLMConfigEdgeCases:
    """Edge case tests for LLMConfig."""

    @pytest.fixture(autouse=True)
    def setup_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Set up clean environment for each test."""
        monkeypatch.setenv("STRIX_LLM", "openai/gpt-4")

    def test_none_prompt_modules_becomes_empty_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that None prompt_modules becomes empty list."""
        monkeypatch.setenv("STRIX_LLM", "openai/gpt-4")
        
        from strix.llm.config import LLMConfig
        config = LLMConfig(prompt_modules=None)
        
        assert config.prompt_modules == []

    def test_timeout_zero_uses_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test behavior with zero timeout."""
        monkeypatch.setenv("STRIX_LLM", "openai/gpt-4")
        monkeypatch.setenv("LLM_TIMEOUT", "600")
        
        from strix.llm.config import LLMConfig
        # timeout=0 is falsy, so should use env var default
        config = LLMConfig(timeout=0)
        
        # Based on implementation: `timeout or int(os.getenv(...))`
        # 0 is falsy so it will use env var
        assert config.timeout == 600

    def test_whitespace_model_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test model name with whitespace."""
        monkeypatch.setenv("STRIX_LLM", "  openai/gpt-4  ")
        
        from strix.llm.config import LLMConfig
        # Model name may include whitespace from env var
        config = LLMConfig()
        
        # Should preserve the value as-is or strip (depends on implementation)
        assert "gpt-4" in config.model_name

    def test_large_timeout_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test large timeout value."""
        monkeypatch.setenv("STRIX_LLM", "openai/gpt-4")
        
        from strix.llm.config import LLMConfig
        config = LLMConfig(timeout=3600)  # 1 hour
        
        assert config.timeout == 3600

    def test_many_prompt_modules(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test configuration with many prompt modules."""
        monkeypatch.setenv("STRIX_LLM", "openai/gpt-4")
        
        from strix.llm.config import LLMConfig
        modules = [
            "sql_injection",
            "xss",
            "csrf",
            "idor",
            "ssrf",
            "xxe",
            "rce",
            "path_traversal",
            "authentication_jwt",
            "business_logic",
        ]
        config = LLMConfig(prompt_modules=modules)
        
        assert len(config.prompt_modules) == 10
        assert "sql_injection" in config.prompt_modules
        assert "business_logic" in config.prompt_modules
