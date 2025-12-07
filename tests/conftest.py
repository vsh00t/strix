"""
Pytest configuration and shared fixtures for Strix tests.
"""

import os
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from typing import Any, Generator


# Set test environment variables before importing strix modules
os.environ.setdefault("STRIX_LLM", "openai/gpt-4")
os.environ.setdefault("LLM_API_KEY", "test-api-key")


@pytest.fixture
def mock_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set up mock environment variables for testing."""
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-4")
    monkeypatch.setenv("LLM_API_KEY", "test-api-key")
    monkeypatch.setenv("LLM_TIMEOUT", "60")


@pytest.fixture
def sample_conversation_history() -> list[dict[str, Any]]:
    """Sample conversation history for testing."""
    return [
        {"role": "system", "content": "You are a security testing agent."},
        {"role": "user", "content": "Test the login endpoint for SQL injection."},
        {
            "role": "assistant",
            "content": "I'll test the endpoint with various SQL injection payloads.",
        },
        {"role": "user", "content": "The response showed a database error."},
        {
            "role": "assistant",
            "content": "<function=browser_actions.navigate>\n"
            "<parameter=url>https://target.com/login?user=admin'--</parameter>\n"
            "</function>",
        },
    ]


@pytest.fixture
def sample_tool_response_valid() -> str:
    """Valid tool invocation response from LLM."""
    return """I'll analyze the endpoint for vulnerabilities.

<function=browser_actions.navigate>
<parameter=url>https://target.com/api/users?id=1</parameter>
</function>"""


@pytest.fixture
def sample_tool_response_truncated() -> str:
    """Truncated tool invocation response (missing closing tag)."""
    return """Testing the endpoint now.

<function=browser_actions.navigate>
<parameter=url>https://target.com/api/users</parameter>
</"""


@pytest.fixture
def sample_tool_response_multiple() -> str:
    """Response with multiple tool invocations (only first should be used)."""
    return """<function=tool1>
<parameter=arg1>value1</parameter>
</function>
<function=tool2>
<parameter=arg2>value2</parameter>
</function>"""


@pytest.fixture
def sample_tool_response_html_entities() -> str:
    """Tool response with HTML entities that need decoding."""
    return """<function=python_actions.execute>
<parameter=code>if x &lt; 10 and y &gt; 5:
    print(&quot;valid&quot;)</parameter>
</function>"""


@pytest.fixture
def sample_tool_response_empty() -> str:
    """Empty response from LLM."""
    return ""


@pytest.fixture
def sample_tool_response_no_function() -> str:
    """Response without any function calls."""
    return "I've analyzed the target and found no vulnerabilities."


@pytest.fixture
def mock_litellm_response() -> MagicMock:
    """Mock LiteLLM response object."""
    response = MagicMock()
    response.choices = [MagicMock()]
    response.choices[0].message = MagicMock()
    response.choices[0].message.content = "Test response content"
    response.usage = MagicMock()
    response.usage.prompt_tokens = 100
    response.usage.completion_tokens = 50
    response.usage.prompt_tokens_details = MagicMock()
    response.usage.prompt_tokens_details.cached_tokens = 20
    response.usage.cache_creation_input_tokens = 0
    return response


@pytest.fixture
def mock_litellm_completion() -> Generator[MagicMock, None, None]:
    """Mock litellm.completion function."""
    with patch("litellm.completion") as mock_completion:
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Mocked response"
        mock_response.usage = MagicMock()
        mock_response.usage.prompt_tokens = 100
        mock_response.usage.completion_tokens = 50
        mock_completion.return_value = mock_response
        yield mock_completion


@pytest.fixture
def large_conversation_history() -> list[dict[str, Any]]:
    """Large conversation history for memory compression testing."""
    messages = [{"role": "system", "content": "You are a security testing agent."}]
    
    for i in range(50):
        messages.append({"role": "user", "content": f"User message {i}: Testing endpoint {i}"})
        messages.append(
            {
                "role": "assistant",
                "content": f"Assistant response {i}: Analyzing endpoint {i} for vulnerabilities. "
                f"Found potential SQL injection vector in parameter 'id'.",
            }
        )
    
    return messages


@pytest.fixture
def vulnerability_finding_high_confidence() -> dict[str, Any]:
    """Sample high confidence vulnerability finding."""
    return {
        "type": "sql_injection",
        "confidence": "high",
        "evidence": [
            "Database error in response: 'You have an error in your SQL syntax'",
            "Different response length with payload vs normal request",
            "Successfully extracted data using UNION SELECT",
        ],
        "reproduction_steps": [
            "Navigate to https://target.com/users?id=1",
            "Modify id parameter to: 1' UNION SELECT username,password FROM users--",
            "Observe extracted credentials in response",
        ],
        "false_positive_indicators": [],
    }


@pytest.fixture
def vulnerability_finding_false_positive() -> dict[str, Any]:
    """Sample false positive vulnerability finding."""
    return {
        "type": "sql_injection",
        "confidence": "low",
        "evidence": ["Generic 500 error returned"],
        "reproduction_steps": ["Send payload to endpoint"],
        "false_positive_indicators": [
            "WAF block signature detected (Cloudflare)",
            "Same error returned for all payloads",
            "No database-specific error messages",
        ],
    }
