"""Fuzzer tool actions for Strix agent.

Provides registered tools for intelligent fuzzing and payload injection.
"""
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.fuzzer.fuzzer_manager import get_fuzzer_manager
from strix.tools.fuzzer.wordlists import get_payloads, list_available_wordlists, WORDLISTS


@register_tool
def fuzz_parameter(
    url: str,
    parameter: str,
    wordlist: str = "sqli",
    method: str = "GET",
    param_location: Literal["query", "body", "path", "header"] = "query",
    encoding: Literal["none", "url", "double_url", "base64", "unicode"] = "none",
    custom_payloads: list[str] | None = None,
    headers: dict[str, str] | None = None,
    body_template: str | None = None,
    max_payloads: int = 50,
    rate_limit: float = 0.1,
) -> dict[str, Any]:
    """Fuzz a parameter with payloads from a wordlist.
    
    Automatically establishes a baseline and detects anomalies based on:
    - Status code changes
    - Response length differences
    - Response time delays (for time-based injection)
    - Payload reflection
    
    Args:
        url: Target URL to fuzz
        parameter: Parameter name to inject payloads into
        wordlist: Wordlist to use (sqli, xss, ssti, ssrf, xxe, path_traversal, cmd_injection, etc.)
        method: HTTP method (GET, POST, etc.)
        param_location: Where the parameter is located (query, body, path, header)
        encoding: Encoding to apply to payloads
        custom_payloads: Additional custom payloads to include
        headers: Additional HTTP headers
        body_template: Body template with {FUZZ} placeholder for body injection
        max_payloads: Maximum number of payloads to test
        rate_limit: Minimum seconds between requests
        
    Returns:
        Dictionary containing:
        - session_id: ID to retrieve detailed results
        - total_requests: Number of requests made
        - anomalies_found: Number of anomalous responses
        - top_anomalies: Top 10 most anomalous results
        - baseline: Baseline response metrics
        
    Example:
        >>> result = fuzz_parameter(
        ...     url="https://example.com/search?q=test",
        ...     parameter="q",
        ...     wordlist="sqli",
        ...     max_payloads=30
        ... )
        >>> if result["anomalies_found"] > 0:
        ...     print("Potential vulnerabilities detected!")
    """
    manager = get_fuzzer_manager()
    manager.rate_limit = rate_limit
    
    # Get payloads
    try:
        payloads = get_payloads(wordlist, encoding=encoding, max_payloads=max_payloads)
    except ValueError as e:
        return {"error": str(e)}
    
    # Add custom payloads if provided
    if custom_payloads:
        payloads.extend(custom_payloads)
    
    # Run fuzzing session
    session = manager.fuzz_parameter(
        method=method,
        url=url,
        parameter=parameter,
        payloads=payloads,
        param_location=param_location,
        headers=headers,
        body_template=body_template,
    )
    
    # Get top anomalies
    anomalies = manager.get_anomalies(session.id, min_score=0.3)
    top_anomalies = sorted(anomalies, key=lambda r: r.anomaly_score, reverse=True)[:10]
    
    return {
        "session_id": session.id,
        "status": session.status,
        "total_requests": session.total_requests,
        "anomalies_found": session.anomalies_found,
        "baseline": {
            "status_code": session.baseline_status,
            "response_length": session.baseline_length,
            "response_time_ms": session.baseline_time_ms,
        },
        "top_anomalies": [a.to_dict() for a in top_anomalies],
        "summary": _generate_summary(session, top_anomalies),
    }


def _generate_summary(session: Any, top_anomalies: list[Any]) -> str:
    """Generate human-readable summary of fuzzing results."""
    if not top_anomalies:
        return f"Fuzzing completed. {session.total_requests} requests, no significant anomalies detected."
    
    summary_parts = [
        f"Fuzzing completed. {session.total_requests} requests, {session.anomalies_found} anomalies detected.",
    ]
    
    # Categorize findings
    status_changes = [a for a in top_anomalies if any("Status" in r for r in a.anomaly_reasons)]
    time_delays = [a for a in top_anomalies if any("Time" in r for r in a.anomaly_reasons)]
    reflections = [a for a in top_anomalies if a.reflection_found]
    
    if status_changes:
        summary_parts.append(f"- {len(status_changes)} status code changes (potential errors)")
    if time_delays:
        summary_parts.append(f"- {len(time_delays)} time-based anomalies (potential injection)")
    if reflections:
        summary_parts.append(f"- {len(reflections)} payload reflections (potential XSS/injection)")
    
    return "\n".join(summary_parts)


@register_tool
def spray_payloads(
    url: str,
    injection_points: list[dict[str, str]],
    wordlist: str = "sqli",
    method: str = "GET",
    encoding: Literal["none", "url", "double_url"] = "none",
    headers: dict[str, str] | None = None,
    max_payloads: int = 20,
    stop_on_anomaly: bool = False,
) -> dict[str, Any]:
    """Spray payloads across multiple injection points simultaneously.
    
    More efficient than fuzzing parameters one by one. Tests all injection
    points with the same payload before moving to the next payload.
    
    Args:
        url: Target URL
        injection_points: List of injection points, e.g.:
            [{"type": "query", "name": "id"}, {"type": "header", "name": "X-Custom"}]
        wordlist: Wordlist to use
        method: HTTP method
        encoding: Encoding to apply
        headers: Base headers
        max_payloads: Maximum payloads per injection point
        stop_on_anomaly: Stop spraying when anomaly is found
        
    Returns:
        Dictionary with results per injection point
    """
    manager = get_fuzzer_manager()
    
    try:
        payloads = get_payloads(wordlist, encoding=encoding, max_payloads=max_payloads)
    except ValueError as e:
        return {"error": str(e)}
    
    results = {}
    
    for point in injection_points:
        param_type = point.get("type", "query")
        param_name = point.get("name", "")
        
        if not param_name:
            continue
        
        session = manager.fuzz_parameter(
            method=method,
            url=url,
            parameter=param_name,
            payloads=payloads,
            param_location=param_type,  # type: ignore
            headers=headers,
        )
        
        anomalies = manager.get_anomalies(session.id, min_score=0.5)
        
        results[f"{param_type}:{param_name}"] = {
            "session_id": session.id,
            "total_requests": session.total_requests,
            "anomalies_found": len(anomalies),
            "top_anomaly": anomalies[0].to_dict() if anomalies else None,
        }
        
        if stop_on_anomaly and anomalies:
            results["stopped_early"] = True
            break
    
    total_anomalies = sum(r.get("anomalies_found", 0) for r in results.values() if isinstance(r, dict))
    
    return {
        "injection_points_tested": len(results),
        "total_anomalies": total_anomalies,
        "results": results,
        "verdict": "POTENTIAL_VULNERABILITIES" if total_anomalies > 0 else "NO_ANOMALIES",
    }


@register_tool
def differential_analysis(
    url: str,
    parameter: str,
    true_payload: str,
    false_payload: str,
    method: str = "GET",
    param_location: Literal["query", "body"] = "query",
    headers: dict[str, str] | None = None,
    iterations: int = 3,
) -> dict[str, Any]:
    """Perform differential analysis for boolean-based injection detection.
    
    Compares responses between "true" and "false" conditions to detect
    boolean-based SQL injection, blind XSS, etc.
    
    Args:
        url: Target URL
        parameter: Parameter to test
        true_payload: Payload expected to produce "true" response (e.g., "' OR '1'='1")
        false_payload: Payload expected to produce "false" response (e.g., "' OR '1'='2")
        method: HTTP method
        param_location: Parameter location
        headers: Additional headers
        iterations: Number of iterations for consistency check
        
    Returns:
        Dictionary with differential analysis results
    """
    manager = get_fuzzer_manager()
    
    true_results = []
    false_results = []
    
    for _ in range(iterations):
        # Test true payload
        session_true = manager.fuzz_parameter(
            method=method,
            url=url,
            parameter=parameter,
            payloads=[true_payload],
            param_location=param_location,
            headers=headers,
            establish_baseline=False,
        )
        if session_true.results:
            true_results.append(session_true.results[0])
        
        # Test false payload
        session_false = manager.fuzz_parameter(
            method=method,
            url=url,
            parameter=parameter,
            payloads=[false_payload],
            param_location=param_location,
            headers=headers,
            establish_baseline=False,
        )
        if session_false.results:
            false_results.append(session_false.results[0])
    
    if not true_results or not false_results:
        return {"error": "Failed to get responses for analysis"}
    
    # Analyze differences
    true_lengths = [r.response_length for r in true_results]
    false_lengths = [r.response_length for r in false_results]
    true_statuses = [r.status_code for r in true_results]
    false_statuses = [r.status_code for r in false_results]
    true_hashes = [r.response_hash for r in true_results]
    false_hashes = [r.response_hash for r in false_results]
    
    # Check consistency
    true_consistent = len(set(true_hashes)) == 1
    false_consistent = len(set(false_hashes)) == 1
    
    # Check for differences
    avg_true_length = sum(true_lengths) / len(true_lengths)
    avg_false_length = sum(false_lengths) / len(false_lengths)
    length_diff = abs(avg_true_length - avg_false_length)
    length_diff_pct = length_diff / max(avg_true_length, avg_false_length, 1) * 100
    
    status_diff = set(true_statuses) != set(false_statuses)
    content_diff = set(true_hashes) != set(false_hashes)
    
    # Determine verdict
    is_differential = (
        content_diff and 
        true_consistent and 
        false_consistent and
        (length_diff_pct > 5 or status_diff)
    )
    
    return {
        "is_differential": is_differential,
        "verdict": "BOOLEAN_INJECTION_LIKELY" if is_differential else "NO_DIFFERENTIAL_DETECTED",
        "analysis": {
            "true_payload": true_payload,
            "false_payload": false_payload,
            "true_avg_length": avg_true_length,
            "false_avg_length": avg_false_length,
            "length_difference": length_diff,
            "length_diff_percent": round(length_diff_pct, 2),
            "status_difference": status_diff,
            "content_difference": content_diff,
            "true_consistent": true_consistent,
            "false_consistent": false_consistent,
        },
        "recommendation": (
            "Responses differ consistently between true/false conditions. "
            "This indicates potential boolean-based injection. "
            "Try extracting data character by character."
        ) if is_differential else (
            "No consistent differential detected. "
            "Try different payloads or check for time-based injection."
        ),
    }


@register_tool
def get_wordlist(
    wordlist_name: str,
    encoding: Literal["none", "url", "double_url", "base64", "unicode"] = "none",
    max_payloads: int | None = None,
) -> dict[str, Any]:
    """Get payloads from a built-in wordlist.
    
    Useful for reviewing available payloads or getting them for manual testing.
    
    Args:
        wordlist_name: Name of wordlist (sqli, xss, ssti, ssrf, xxe, etc.)
        encoding: Encoding to apply
        max_payloads: Maximum number of payloads to return
        
    Returns:
        Dictionary with payloads and metadata
    """
    try:
        payloads = get_payloads(wordlist_name, encoding=encoding, max_payloads=max_payloads)
        
        return {
            "wordlist": wordlist_name,
            "encoding": encoding,
            "count": len(payloads),
            "payloads": payloads,
        }
    except ValueError as e:
        available = list_available_wordlists()
        return {
            "error": str(e),
            "available_wordlists": available,
        }


@register_tool
def list_wordlists() -> dict[str, Any]:
    """List all available fuzzing wordlists.
    
    Returns:
        Dictionary with wordlist names and payload counts
    """
    wordlists = list_available_wordlists()
    
    return {
        "wordlists": wordlists,
        "total_wordlists": len(wordlists),
        "categories": {
            "injection": ["sqli", "xss", "ssti", "cmd_injection", "xxe"],
            "traversal": ["path_traversal", "ssrf", "open_redirect"],
            "headers": ["header_injection"],
        },
    }
