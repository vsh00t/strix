"""
Unit tests for strix/llm/utils.py

Tests cover:
- Tool invocation parsing
- Stopword fixing
- Function truncation
- HTML entity decoding
- Content cleaning
"""

import pytest
from strix.llm.utils import (
    parse_tool_invocations,
    _fix_stopword,
    _truncate_to_first_function,
    format_tool_call,
    clean_content,
)


class TestParseToolInvocations:
    """Tests for parse_tool_invocations function."""

    def test_parse_valid_single_function(self) -> None:
        """Test parsing a valid single function call."""
        content = """<function=test_tool>
<parameter=arg1>value1</parameter>
</function>"""
        result = parse_tool_invocations(content)
        
        assert result is not None
        assert len(result) == 1
        assert result[0]["toolName"] == "test_tool"
        assert result[0]["args"]["arg1"] == "value1"

    def test_parse_function_with_multiple_parameters(self) -> None:
        """Test parsing function with multiple parameters."""
        content = """<function=browser_actions.navigate>
<parameter=url>https://example.com</parameter>
<parameter=method>GET</parameter>
<parameter=headers>{"Authorization": "Bearer token"}</parameter>
</function>"""
        result = parse_tool_invocations(content)
        
        assert result is not None
        assert len(result) == 1
        assert result[0]["toolName"] == "browser_actions.navigate"
        assert result[0]["args"]["url"] == "https://example.com"
        assert result[0]["args"]["method"] == "GET"
        assert "Authorization" in result[0]["args"]["headers"]

    def test_parse_function_with_multiline_parameter(self) -> None:
        """Test parsing function with multiline parameter value."""
        content = """<function=python_actions.execute>
<parameter=code>def test():
    print("hello")
    return True</parameter>
</function>"""
        result = parse_tool_invocations(content)
        
        assert result is not None
        assert len(result) == 1
        assert "def test():" in result[0]["args"]["code"]
        assert 'print("hello")' in result[0]["args"]["code"]

    def test_parse_html_entities_decoded(self) -> None:
        """Test that HTML entities are properly decoded."""
        content = """<function=python_actions.execute>
<parameter=code>if x &lt; 10 and y &gt; 5:
    print(&quot;valid&quot;)
    data = {&apos;key&apos;: &amp;value}</parameter>
</function>"""
        result = parse_tool_invocations(content)
        
        assert result is not None
        code = result[0]["args"]["code"]
        assert "x < 10" in code
        assert "y > 5" in code
        assert '"valid"' in code
        assert "{'key':" in code
        assert "&value" in code

    def test_parse_empty_content_returns_none(self) -> None:
        """Test that empty content returns None."""
        assert parse_tool_invocations("") is None
        assert parse_tool_invocations("   ") is None

    def test_parse_no_function_returns_none(self) -> None:
        """Test that content without function returns None."""
        content = "I analyzed the target and found no vulnerabilities."
        assert parse_tool_invocations(content) is None

    def test_parse_truncated_function_with_autofix(self) -> None:
        """Test that truncated function tags are auto-fixed."""
        content = """<function=test_tool>
<parameter=arg1>value1</parameter>
</"""
        result = parse_tool_invocations(content)
        
        assert result is not None
        assert len(result) == 1
        assert result[0]["toolName"] == "test_tool"

    def test_parse_function_without_closing_tag(self) -> None:
        """Test handling of function without any closing tag."""
        content = """<function=test_tool>
<parameter=arg1>value1</parameter>"""
        result = parse_tool_invocations(content)
        
        # Should auto-fix and parse
        assert result is not None
        assert len(result) == 1

    def test_parse_multiple_functions(self) -> None:
        """Test parsing multiple functions (all should be captured)."""
        content = """<function=tool1>
<parameter=a>1</parameter>
</function>
<function=tool2>
<parameter=b>2</parameter>
</function>"""
        result = parse_tool_invocations(content)
        
        assert result is not None
        assert len(result) == 2
        assert result[0]["toolName"] == "tool1"
        assert result[1]["toolName"] == "tool2"

    def test_parse_function_with_special_characters_in_value(self) -> None:
        """Test parsing function with special characters in parameter values."""
        content = """<function=browser_actions.navigate>
<parameter=url>https://target.com/search?q=test&page=1&sort=desc</parameter>
</function>"""
        result = parse_tool_invocations(content)
        
        assert result is not None
        url = result[0]["args"]["url"]
        assert "q=test" in url
        assert "page=1" in url

    def test_parse_function_with_empty_parameter(self) -> None:
        """Test parsing function with empty parameter value."""
        content = """<function=test_tool>
<parameter=empty></parameter>
<parameter=filled>value</parameter>
</function>"""
        result = parse_tool_invocations(content)
        
        assert result is not None
        assert result[0]["args"]["empty"] == ""
        assert result[0]["args"]["filled"] == "value"


class TestFixStopword:
    """Tests for _fix_stopword function."""

    def test_fix_truncated_closing_tag(self) -> None:
        """Test fixing truncated </function> tag."""
        content = "<function=test>\n<parameter=x>y</parameter>\n</"
        result = _fix_stopword(content)
        assert result.endswith("</function>")

    def test_fix_missing_closing_tag(self) -> None:
        """Test adding missing </function> tag."""
        content = "<function=test>\n<parameter=x>y</parameter>"
        result = _fix_stopword(content)
        assert "</function>" in result

    def test_no_fix_needed_complete_tag(self) -> None:
        """Test that complete tags are not modified."""
        content = "<function=test>\n<parameter=x>y</parameter>\n</function>"
        result = _fix_stopword(content)
        assert result == content

    def test_no_fix_for_multiple_functions(self) -> None:
        """Test that multiple functions are not auto-fixed."""
        content = "<function=a></function><function=b>"
        result = _fix_stopword(content)
        # Should not add closing tag when multiple functions exist
        assert result == content

    def test_no_fix_for_no_function(self) -> None:
        """Test that content without function is not modified."""
        content = "Just some text without any function"
        result = _fix_stopword(content)
        assert result == content


class TestTruncateToFirstFunction:
    """Tests for _truncate_to_first_function function."""

    def test_truncate_removes_second_function(self) -> None:
        """Test that second function is removed."""
        content = """<function=first>
<parameter=a>1</parameter>
</function>
<function=second>
<parameter=b>2</parameter>
</function>"""
        result = _truncate_to_first_function(content)
        
        assert "<function=first>" in result
        assert "<function=second>" not in result

    def test_truncate_preserves_single_function(self) -> None:
        """Test that single function is preserved."""
        content = """Some text
<function=only_one>
<parameter=x>value</parameter>
</function>"""
        result = _truncate_to_first_function(content)
        assert result == content

    def test_truncate_empty_content(self) -> None:
        """Test handling of empty content."""
        assert _truncate_to_first_function("") == ""
        assert _truncate_to_first_function(None) is None  # type: ignore

    def test_truncate_preserves_text_before_function(self) -> None:
        """Test that text before first function is preserved."""
        content = """I'll analyze the endpoint.

<function=test>
<parameter=a>1</parameter>
</function>
<function=second>
<parameter=b>2</parameter>
</function>"""
        result = _truncate_to_first_function(content)
        
        assert "I'll analyze the endpoint" in result
        assert "<function=test>" in result
        assert "<function=second>" not in result


class TestFormatToolCall:
    """Tests for format_tool_call function."""

    def test_format_simple_tool_call(self) -> None:
        """Test formatting a simple tool call."""
        result = format_tool_call("test_tool", {"arg1": "value1"})
        
        assert "<function=test_tool>" in result
        assert "<parameter=arg1>value1</parameter>" in result
        assert "</function>" in result

    def test_format_tool_call_multiple_args(self) -> None:
        """Test formatting tool call with multiple arguments."""
        result = format_tool_call(
            "browser_actions.navigate",
            {"url": "https://example.com", "method": "POST"},
        )
        
        assert "<function=browser_actions.navigate>" in result
        assert "<parameter=url>https://example.com</parameter>" in result
        assert "<parameter=method>POST</parameter>" in result

    def test_format_tool_call_empty_args(self) -> None:
        """Test formatting tool call with no arguments."""
        result = format_tool_call("simple_tool", {})
        
        assert "<function=simple_tool>" in result
        assert "</function>" in result
        assert "<parameter=" not in result


class TestCleanContent:
    """Tests for clean_content function."""

    def test_clean_removes_function_tags(self) -> None:
        """Test that complete function blocks are removed from content."""
        content = """Here is my analysis.

<function=test>
<parameter=x>y</parameter>
</function>

More text here."""
        result = clean_content(content)
        
        # The function block itself should be removed
        assert "<function=test>" not in result
        assert "<parameter=x>" not in result
        assert "Here is my analysis" in result
        assert "More text here" in result

    def test_clean_removes_complete_function_block(self) -> None:
        """Test that a standalone function block is fully removed."""
        content = "<function=tool><parameter=x>y</parameter></function>"
        result = clean_content(content)
        assert result == ""

    def test_clean_removes_inter_agent_messages(self) -> None:
        """Test that inter_agent_message XML is removed."""
        content = """Response text.

<inter_agent_message>
<sender>agent1</sender>
<content>Internal message</content>
</inter_agent_message>

More response."""
        result = clean_content(content)
        
        assert "<inter_agent_message>" not in result
        assert "Internal message" not in result
        assert "Response text" in result

    def test_clean_removes_agent_completion_report(self) -> None:
        """Test that agent_completion_report XML is removed."""
        content = """<agent_completion_report>
<status>completed</status>
</agent_completion_report>
Visible content."""
        result = clean_content(content)
        
        assert "<agent_completion_report>" not in result
        assert "Visible content" in result

    def test_clean_empty_content(self) -> None:
        """Test handling of empty content."""
        assert clean_content("") == ""
        assert clean_content("   ") == ""

    def test_clean_normalizes_whitespace(self) -> None:
        """Test that excessive whitespace is normalized."""
        content = "Line 1\n\n\n\n\nLine 2"
        result = clean_content(content)
        
        # Should have at most double newlines
        assert "\n\n\n" not in result
        assert "Line 1" in result
        assert "Line 2" in result

    def test_clean_fixes_truncated_function(self) -> None:
        """Test that truncated functions are fixed before cleaning."""
        content = """Text before
<function=test>
<parameter=a>b</parameter>
</
Text after"""
        result = clean_content(content)
        
        # Should fix the truncated tag and then remove the function
        assert "<function=" not in result
        assert "Text before" in result


class TestParseToolInvocationsEdgeCases:
    """Edge case tests for tool invocation parsing."""

    def test_parse_nested_angle_brackets(self) -> None:
        """Test parsing with nested angle brackets in values."""
        content = """<function=test>
<parameter=html><div><span>test</span></div></parameter>
</function>"""
        result = parse_tool_invocations(content)
        
        assert result is not None
        # This is a known limitation - nested tags may cause issues
        # The test documents current behavior

    def test_parse_sql_injection_payload(self) -> None:
        """Test parsing SQL injection payloads."""
        content = """<function=browser_actions.navigate>
<parameter=url>https://target.com/users?id=1' OR '1'='1</parameter>
</function>"""
        result = parse_tool_invocations(content)
        
        assert result is not None
        assert "1' OR '1'='1" in result[0]["args"]["url"]

    def test_parse_xss_payload(self) -> None:
        """Test parsing XSS payloads (HTML entities)."""
        content = """<function=browser_actions.navigate>
<parameter=url>https://target.com/search?q=&lt;script&gt;alert(1)&lt;/script&gt;</parameter>
</function>"""
        result = parse_tool_invocations(content)
        
        assert result is not None
        url = result[0]["args"]["url"]
        # HTML entities should be decoded
        assert "<script>" in url
        assert "</script>" in url

    def test_parse_unicode_content(self) -> None:
        """Test parsing Unicode content."""
        content = """<function=test>
<parameter=text>こんにちは世界 🎉 émojis</parameter>
</function>"""
        result = parse_tool_invocations(content)
        
        assert result is not None
        assert "こんにちは世界" in result[0]["args"]["text"]
        assert "🎉" in result[0]["args"]["text"]

    def test_parse_very_long_parameter(self) -> None:
        """Test parsing very long parameter values."""
        long_value = "A" * 10000
        content = f"""<function=test>
<parameter=data>{long_value}</parameter>
</function>"""
        result = parse_tool_invocations(content)
        
        assert result is not None
        assert result[0]["args"]["data"] == long_value


# ============================================================================
# Tests for Tool Validation (Phase 2)
# ============================================================================

from strix.llm.utils import (
    validate_tool_invocation,
    validate_all_invocations,
    _validate_url,
    _validate_file_path,
    _validate_command,
    KNOWN_TOOLS,
)


class TestValidateToolInvocation:
    """Tests for validate_tool_invocation function."""

    def test_valid_browser_navigate(self) -> None:
        """Test validating a valid browser navigation."""
        invocation = {
            "toolName": "browser_actions.navigate",
            "args": {"url": "https://example.com"}
        }
        is_valid, errors = validate_tool_invocation(invocation)
        
        assert is_valid is True
        assert len(errors) == 0

    def test_valid_terminal_execute(self) -> None:
        """Test validating a valid terminal command."""
        invocation = {
            "toolName": "terminal.execute",
            "args": {"command": "ls -la"}
        }
        is_valid, errors = validate_tool_invocation(invocation)
        
        assert is_valid is True
        assert len(errors) == 0

    def test_missing_toolname(self) -> None:
        """Test that missing toolName is detected."""
        invocation = {"args": {"url": "https://example.com"}}
        is_valid, errors = validate_tool_invocation(invocation)
        
        assert is_valid is False
        assert "Missing toolName" in errors

    def test_invalid_toolname_type(self) -> None:
        """Test that non-string toolName is detected."""
        invocation = {"toolName": 123, "args": {}}
        is_valid, errors = validate_tool_invocation(invocation)
        
        assert is_valid is False
        assert any("must be a string" in e for e in errors)

    def test_invalid_args_type(self) -> None:
        """Test that non-dict args is detected."""
        invocation = {"toolName": "test", "args": "not a dict"}
        is_valid, errors = validate_tool_invocation(invocation)
        
        assert is_valid is False
        assert any("must be a dictionary" in e for e in errors)

    def test_missing_required_parameter(self) -> None:
        """Test that missing required parameters are detected."""
        invocation = {
            "toolName": "browser_actions.navigate",
            "args": {}  # Missing 'url' parameter
        }
        is_valid, errors = validate_tool_invocation(invocation)
        
        assert is_valid is False
        assert any("Missing required parameter 'url'" in e for e in errors)

    def test_missing_command_parameter(self) -> None:
        """Test that missing command parameter is detected."""
        invocation = {
            "toolName": "terminal.execute",
            "args": {}  # Missing 'command' parameter
        }
        is_valid, errors = validate_tool_invocation(invocation)
        
        assert is_valid is False
        assert any("Missing required parameter 'command'" in e for e in errors)

    def test_invalid_url_scheme(self) -> None:
        """Test that invalid URL scheme is detected."""
        invocation = {
            "toolName": "browser_actions.navigate",
            "args": {"url": "ftp://example.com"}
        }
        is_valid, errors = validate_tool_invocation(invocation)
        
        assert is_valid is False
        assert any("Invalid URL scheme" in e for e in errors)

    def test_valid_http_url(self) -> None:
        """Test that http:// URLs are valid."""
        invocation = {
            "toolName": "browser_actions.navigate",
            "args": {"url": "http://localhost:8080/api"}
        }
        is_valid, errors = validate_tool_invocation(invocation)
        
        assert is_valid is True

    def test_valid_https_url(self) -> None:
        """Test that https:// URLs are valid."""
        invocation = {
            "toolName": "browser_actions.navigate",
            "args": {"url": "https://secure.example.com/path?query=value"}
        }
        is_valid, errors = validate_tool_invocation(invocation)
        
        assert is_valid is True

    def test_unknown_tool_passes(self) -> None:
        """Test that unknown tools pass validation (no required params check)."""
        invocation = {
            "toolName": "custom_tool.action",
            "args": {"custom_arg": "value"}
        }
        is_valid, errors = validate_tool_invocation(invocation)
        
        assert is_valid is True

    def test_empty_args_for_tool_without_required_params(self) -> None:
        """Test that empty args is valid for tools without required params."""
        invocation = {
            "toolName": "browser_actions.screenshot",
            "args": {}
        }
        is_valid, errors = validate_tool_invocation(invocation)
        
        assert is_valid is True


class TestValidateUrl:
    """Tests for _validate_url function."""

    def test_valid_http_url(self) -> None:
        """Test valid http URL."""
        errors = _validate_url("http://example.com")
        assert len(errors) == 0

    def test_valid_https_url(self) -> None:
        """Test valid https URL."""
        errors = _validate_url("https://example.com/path?query=value")
        assert len(errors) == 0

    def test_empty_url(self) -> None:
        """Test empty URL returns error."""
        errors = _validate_url("")
        assert "URL is empty" in errors

    def test_invalid_scheme(self) -> None:
        """Test invalid URL scheme."""
        errors = _validate_url("ftp://example.com")
        assert any("Invalid URL scheme" in e for e in errors)

    def test_javascript_scheme_rejected(self) -> None:
        """Test that javascript: scheme is rejected."""
        errors = _validate_url("javascript:alert(1)")
        assert any("Invalid URL scheme" in e for e in errors)

    def test_missing_hostname(self) -> None:
        """Test URL without hostname."""
        errors = _validate_url("http:///path")
        assert any("missing hostname" in e for e in errors)

    def test_complex_url_with_query_and_fragment(self) -> None:
        """Test complex URL with query and fragment."""
        errors = _validate_url("https://example.com/path?a=1&b=2#section")
        assert len(errors) == 0


class TestValidateFilePath:
    """Tests for _validate_file_path function."""

    def test_valid_path(self) -> None:
        """Test valid file path."""
        errors = _validate_file_path("/home/user/file.txt")
        assert len(errors) == 0

    def test_empty_path(self) -> None:
        """Test empty file path."""
        errors = _validate_file_path("")
        assert "file_path is empty" in errors

    def test_relative_path(self) -> None:
        """Test relative path (should be valid in pentesting context)."""
        errors = _validate_file_path("../config/secrets.json")
        # Path traversal is allowed in pentesting context
        assert len(errors) == 0


class TestValidateCommand:
    """Tests for _validate_command function."""

    def test_valid_command(self) -> None:
        """Test valid command."""
        errors = _validate_command("ls -la /home")
        assert len(errors) == 0

    def test_empty_command(self) -> None:
        """Test empty command."""
        errors = _validate_command("")
        assert "command is empty" in errors

    def test_complex_command(self) -> None:
        """Test complex piped command."""
        errors = _validate_command("cat file.txt | grep pattern | sort")
        assert len(errors) == 0


class TestValidateAllInvocations:
    """Tests for validate_all_invocations function."""

    def test_all_valid_invocations(self) -> None:
        """Test validating multiple valid invocations."""
        invocations = [
            {"toolName": "browser_actions.navigate", "args": {"url": "https://a.com"}},
            {"toolName": "terminal.execute", "args": {"command": "ls"}},
        ]
        all_valid, errors = validate_all_invocations(invocations)
        
        assert all_valid is True
        assert len(errors) == 0

    def test_one_invalid_invocation(self) -> None:
        """Test with one invalid invocation."""
        invocations = [
            {"toolName": "browser_actions.navigate", "args": {"url": "https://a.com"}},
            {"toolName": "terminal.execute", "args": {}},  # Missing command
        ]
        all_valid, errors = validate_all_invocations(invocations)
        
        assert all_valid is False
        assert "1" in errors  # Index 1 has errors

    def test_multiple_invalid_invocations(self) -> None:
        """Test with multiple invalid invocations."""
        invocations = [
            {"args": {}},  # Missing toolName
            {"toolName": "terminal.execute", "args": {}},  # Missing command
        ]
        all_valid, errors = validate_all_invocations(invocations)
        
        assert all_valid is False
        assert "0" in errors
        assert "1" in errors

    def test_empty_invocations(self) -> None:
        """Test with empty invocations list."""
        all_valid, errors = validate_all_invocations([])
        
        assert all_valid is True
        assert len(errors) == 0

    def test_none_invocations(self) -> None:
        """Test with None invocations."""
        all_valid, errors = validate_all_invocations(None)
        
        assert all_valid is True
        assert len(errors) == 0


class TestKnownTools:
    """Tests for KNOWN_TOOLS dictionary."""

    def test_known_tools_not_empty(self) -> None:
        """Test that KNOWN_TOOLS is not empty."""
        assert len(KNOWN_TOOLS) > 0

    def test_browser_tools_present(self) -> None:
        """Test that browser tools are present."""
        assert "browser_actions.navigate" in KNOWN_TOOLS
        assert "browser_actions.click" in KNOWN_TOOLS

    def test_terminal_tool_present(self) -> None:
        """Test that terminal tool is present."""
        assert "terminal.execute" in KNOWN_TOOLS

    def test_required_params_are_lists(self) -> None:
        """Test that required params are lists."""
        for tool_name, params in KNOWN_TOOLS.items():
            assert isinstance(params, list), f"{tool_name} params should be a list"
