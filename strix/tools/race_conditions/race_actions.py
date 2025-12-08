"""
Race Conditions Detector actions for the tool registry.
"""

from typing import Any

from strix.tools.argument_parser import parse_tool_arguments
from strix.tools.race_conditions.race_detector import (
    RaceConditionDetector,
    RaceConditionType,
    RaceRequest,
    get_race_detector,
)
from strix.tools.registry import register_tool


@register_tool(
    name="test_race_condition",
    description="""Test for race condition vulnerabilities by sending parallel requests.

Use this tool to detect race conditions in critical operations like:
- Payment processing (double spending)
- Coupon/discount code redemption
- Inventory management
- Rate limit enforcement
- Resource creation

Supported test types:
- double_spending: Test if a resource can be consumed multiple times
- limit_overrun: Test if limits can be exceeded through parallel requests
- duplicate_creation: Test if resources can be created multiple times
- toctou: Time-of-check to time-of-use vulnerabilities
- auth_bypass: Authentication race conditions
- counter_manipulation: Counter increment/decrement races

Example usage:
<test_race_condition>
<test_type>double_spending</test_type>
<method>POST</method>
<url>https://api.example.com/redeem-coupon</url>
<headers>{"Authorization": "Bearer token123", "Content-Type": "application/json"}</headers>
<body>{"coupon_code": "DISCOUNT50"}</body>
<parallel_count>10</parallel_count>
</test_race_condition>

Returns analysis of responses to determine if race condition exists.""",
    schema="<test_race_condition>\n<test_type>$TEST_TYPE</test_type>\n<method>$HTTP_METHOD</method>\n<url>$TARGET_URL</url>\n<headers>$HEADERS_JSON</headers>\n<body>$REQUEST_BODY</body>\n<parallel_count>$COUNT</parallel_count>\n</test_race_condition>",
)
async def test_race_condition(arguments: str) -> dict[str, Any]:
    """Execute a race condition test."""
    args = parse_tool_arguments(
        arguments,
        {
            "test_type": str,
            "method": str,
            "url": str,
            "headers": str,
            "body": str,
            "parallel_count": int,
        },
    )

    test_type_str = args.get("test_type", "double_spending")
    method = args.get("method", "POST")
    url = args.get("url", "")
    headers_str = args.get("headers", "{}")
    body = args.get("body")
    parallel_count = args.get("parallel_count", 10)

    if not url:
        return {"success": False, "error": "URL is required"}

    # Parse headers
    headers: dict[str, str] = {}
    if headers_str:
        import json

        try:
            headers = json.loads(headers_str)
        except json.JSONDecodeError:
            return {"success": False, "error": "Invalid headers JSON format"}

    # Map test type string to enum
    type_mapping = {
        "double_spending": RaceConditionType.DOUBLE_SPENDING,
        "limit_overrun": RaceConditionType.LIMIT_OVERRUN,
        "duplicate_creation": RaceConditionType.DUPLICATE_CREATION,
        "toctou": RaceConditionType.TIME_OF_CHECK_TIME_OF_USE,
        "auth_bypass": RaceConditionType.AUTHENTICATION_BYPASS,
        "counter_manipulation": RaceConditionType.COUNTER_MANIPULATION,
    }

    test_type = type_mapping.get(test_type_str.lower())
    if not test_type:
        return {
            "success": False,
            "error": f"Invalid test type. Valid types: {', '.join(type_mapping.keys())}",
        }

    request = RaceRequest(
        method=method,
        url=url,
        headers=headers,
        body=body,
    )

    detector = get_race_detector()

    # Execute appropriate test based on type
    if test_type == RaceConditionType.DOUBLE_SPENDING:
        result = await detector.test_double_spending(request, parallel_count)
    elif test_type == RaceConditionType.LIMIT_OVERRUN:
        result = await detector.test_limit_overrun(request, parallel_count)
    elif test_type == RaceConditionType.DUPLICATE_CREATION:
        result = await detector.test_duplicate_creation(request, parallel_count)
    else:
        # For other types, use generic parallel request approach
        requests = detector.generate_race_payloads(request, test_type, parallel_count)
        responses = await detector.send_parallel_requests(requests, sync_barrier=True)
        result = detector.analyze_responses(responses, test_type)

    return {
        "success": True,
        "result": result.to_dict(),
    }


@register_tool(
    name="test_toctou",
    description="""Test for Time-of-Check to Time-of-Use (TOCTOU) race conditions.

This test sends interleaved "check" and "use" requests to detect TOCTOU vulnerabilities
where there's a gap between permission verification and action execution.

Common TOCTOU scenarios:
- Check balance -> Transfer funds
- Verify file exists -> Read file
- Check permission -> Perform action
- Validate input -> Process request

Example usage:
<test_toctou>
<check_method>GET</check_method>
<check_url>https://api.example.com/balance</check_url>
<use_method>POST</use_method>
<use_url>https://api.example.com/transfer</use_url>
<headers>{"Authorization": "Bearer token123"}</headers>
<use_body>{"amount": 1000, "to": "attacker"}</use_body>
<parallel_count>5</parallel_count>
</test_toctou>""",
    schema="<test_toctou>\n<check_method>$CHECK_METHOD</check_method>\n<check_url>$CHECK_URL</check_url>\n<use_method>$USE_METHOD</use_method>\n<use_url>$USE_URL</use_url>\n<headers>$HEADERS_JSON</headers>\n<use_body>$USE_BODY</use_body>\n<parallel_count>$COUNT</parallel_count>\n</test_toctou>",
)
async def test_toctou(arguments: str) -> dict[str, Any]:
    """Execute a TOCTOU race condition test."""
    args = parse_tool_arguments(
        arguments,
        {
            "check_method": str,
            "check_url": str,
            "use_method": str,
            "use_url": str,
            "headers": str,
            "check_body": str,
            "use_body": str,
            "parallel_count": int,
        },
    )

    check_method = args.get("check_method", "GET")
    check_url = args.get("check_url", "")
    use_method = args.get("use_method", "POST")
    use_url = args.get("use_url", "")
    headers_str = args.get("headers", "{}")
    check_body = args.get("check_body")
    use_body = args.get("use_body")
    parallel_count = args.get("parallel_count", 5)

    if not check_url or not use_url:
        return {"success": False, "error": "Both check_url and use_url are required"}

    # Parse headers
    headers: dict[str, str] = {}
    if headers_str:
        import json

        try:
            headers = json.loads(headers_str)
        except json.JSONDecodeError:
            return {"success": False, "error": "Invalid headers JSON format"}

    check_request = RaceRequest(
        method=check_method,
        url=check_url,
        headers=headers,
        body=check_body,
    )

    use_request = RaceRequest(
        method=use_method,
        url=use_url,
        headers=headers,
        body=use_body,
    )

    detector = get_race_detector()
    result = await detector.test_toctou(check_request, use_request, parallel_count)

    return {
        "success": True,
        "result": result.to_dict(),
    }


@register_tool(
    name="analyze_race_timing",
    description="""Analyze timing patterns from race condition test results.

Use this to get detailed timing analysis from race condition responses
to understand the window of vulnerability and optimize attack timing.

Provides:
- Response time distribution
- Request synchronization quality
- Timing window analysis
- Recommendations for exploitation

Example:
<analyze_race_timing>
<responses>$RACE_RESPONSES_JSON</responses>
</analyze_race_timing>""",
    schema="<analyze_race_timing>\n<responses>$RESPONSES_JSON</responses>\n</analyze_race_timing>",
)
async def analyze_race_timing(arguments: str) -> dict[str, Any]:
    """Analyze timing patterns from race responses."""
    args = parse_tool_arguments(
        arguments,
        {
            "responses": str,
        },
    )

    responses_str = args.get("responses", "[]")

    import json

    try:
        responses_data = json.loads(responses_str)
    except json.JSONDecodeError:
        return {"success": False, "error": "Invalid responses JSON format"}

    if not responses_data:
        return {"success": False, "error": "No responses to analyze"}

    # Extract timing information
    timings = []
    sent_times = []
    received_times = []

    for resp in responses_data:
        if "timing_ms" in resp:
            timings.append(resp["timing_ms"])
        if "request_sent_at" in resp:
            sent_times.append(resp["request_sent_at"])
        if "response_received_at" in resp:
            received_times.append(resp["response_received_at"])

    analysis: dict[str, Any] = {
        "total_responses": len(responses_data),
        "timing_analysis": {},
        "synchronization_quality": "unknown",
        "recommendations": [],
    }

    if timings:
        analysis["timing_analysis"] = {
            "min_ms": min(timings),
            "max_ms": max(timings),
            "avg_ms": sum(timings) / len(timings),
            "spread_ms": max(timings) - min(timings),
        }

    if sent_times:
        sent_spread = max(sent_times) - min(sent_times)
        sent_spread_ms = sent_spread * 1000

        if sent_spread_ms < 1:
            analysis["synchronization_quality"] = "excellent"
            analysis["recommendations"].append(
                "Excellent synchronization achieved - requests arrived within 1ms"
            )
        elif sent_spread_ms < 5:
            analysis["synchronization_quality"] = "good"
            analysis["recommendations"].append(
                "Good synchronization - consider testing with more parallel requests"
            )
        elif sent_spread_ms < 20:
            analysis["synchronization_quality"] = "moderate"
            analysis["recommendations"].append(
                "Moderate synchronization - try reducing network latency or using local testing"
            )
        else:
            analysis["synchronization_quality"] = "poor"
            analysis["recommendations"].append(
                "Poor synchronization - requests are too spread out for effective race testing"
            )

        analysis["timing_analysis"]["request_spread_ms"] = sent_spread_ms

    return {
        "success": True,
        "analysis": analysis,
    }


@register_tool(
    name="generate_race_payloads",
    description="""Generate multiple payloads for race condition testing.

Creates variations of a base request for parallel execution testing.
Useful for preparing custom race condition tests.

Example:
<generate_race_payloads>
<method>POST</method>
<url>https://api.example.com/vote</url>
<headers>{"Authorization": "Bearer token"}</headers>
<body>{"candidate_id": 1}</body>
<test_type>counter_manipulation</test_type>
<count>15</count>
</generate_race_payloads>""",
    schema="<generate_race_payloads>\n<method>$METHOD</method>\n<url>$URL</url>\n<headers>$HEADERS_JSON</headers>\n<body>$BODY</body>\n<test_type>$TEST_TYPE</test_type>\n<count>$COUNT</count>\n</generate_race_payloads>",
)
async def generate_race_payloads(arguments: str) -> dict[str, Any]:
    """Generate payloads for race condition testing."""
    args = parse_tool_arguments(
        arguments,
        {
            "method": str,
            "url": str,
            "headers": str,
            "body": str,
            "test_type": str,
            "count": int,
        },
    )

    method = args.get("method", "POST")
    url = args.get("url", "")
    headers_str = args.get("headers", "{}")
    body = args.get("body")
    test_type_str = args.get("test_type", "double_spending")
    count = args.get("count", 10)

    if not url:
        return {"success": False, "error": "URL is required"}

    # Parse headers
    headers: dict[str, str] = {}
    if headers_str:
        import json

        try:
            headers = json.loads(headers_str)
        except json.JSONDecodeError:
            return {"success": False, "error": "Invalid headers JSON format"}

    type_mapping = {
        "double_spending": RaceConditionType.DOUBLE_SPENDING,
        "limit_overrun": RaceConditionType.LIMIT_OVERRUN,
        "duplicate_creation": RaceConditionType.DUPLICATE_CREATION,
        "toctou": RaceConditionType.TIME_OF_CHECK_TIME_OF_USE,
        "auth_bypass": RaceConditionType.AUTHENTICATION_BYPASS,
        "counter_manipulation": RaceConditionType.COUNTER_MANIPULATION,
    }

    test_type = type_mapping.get(test_type_str.lower(), RaceConditionType.DOUBLE_SPENDING)

    base_request = RaceRequest(
        method=method,
        url=url,
        headers=headers,
        body=body,
    )

    detector = get_race_detector()
    payloads = detector.generate_race_payloads(base_request, test_type, count)

    return {
        "success": True,
        "payloads": [p.to_dict() for p in payloads],
        "count": len(payloads),
    }
