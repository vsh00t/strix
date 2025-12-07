import html
import re
from typing import Any
from urllib.parse import urlparse


# Herramientas conocidas y sus parámetros requeridos
KNOWN_TOOLS: dict[str, list[str]] = {
    "browser_actions.navigate": ["url"],
    "browser_actions.click": ["selector"],
    "browser_actions.fill": ["selector", "value"],
    "browser_actions.screenshot": [],
    "browser_actions.get_page_content": [],
    "terminal.execute": ["command"],
    "file_edit.read_file": ["file_path"],
    "file_edit.write_file": ["file_path", "content"],
    "notes.add_note": ["content"],
    "proxy.get_history": [],
    "python.execute": ["code"],
    "reporting.create_report": ["title"],
    "thinking.think": ["thought"],
    "web_search.search": ["query"],
    "finish.finish": ["summary"],
}


def _truncate_to_first_function(content: str) -> str:
    if not content:
        return content

    function_starts = [match.start() for match in re.finditer(r"<function=", content)]

    if len(function_starts) >= 2:
        second_function_start = function_starts[1]

        return content[:second_function_start].rstrip()

    return content


def parse_tool_invocations(content: str) -> list[dict[str, Any]] | None:
    content = _fix_stopword(content)

    tool_invocations: list[dict[str, Any]] = []

    fn_regex_pattern = r"<function=([^>]+)>\n?(.*?)</function>"
    fn_param_regex_pattern = r"<parameter=([^>]+)>(.*?)</parameter>"

    fn_matches = re.finditer(fn_regex_pattern, content, re.DOTALL)

    for fn_match in fn_matches:
        fn_name = fn_match.group(1)
        fn_body = fn_match.group(2)

        param_matches = re.finditer(fn_param_regex_pattern, fn_body, re.DOTALL)

        args = {}
        for param_match in param_matches:
            param_name = param_match.group(1)
            param_value = param_match.group(2).strip()

            param_value = html.unescape(param_value)
            args[param_name] = param_value

        tool_invocations.append({"toolName": fn_name, "args": args})

    return tool_invocations if tool_invocations else None


def _fix_stopword(content: str) -> str:
    if "<function=" in content and content.count("<function=") == 1:
        if content.endswith("</"):
            content = content.rstrip() + "function>"
        elif not content.rstrip().endswith("</function>"):
            content = content + "\n</function>"
    return content


def format_tool_call(tool_name: str, args: dict[str, Any]) -> str:
    xml_parts = [f"<function={tool_name}>"]

    for key, value in args.items():
        xml_parts.append(f"<parameter={key}>{value}</parameter>")

    xml_parts.append("</function>")

    return "\n".join(xml_parts)


def clean_content(content: str) -> str:
    if not content:
        return ""

    content = _fix_stopword(content)

    tool_pattern = r"<function=[^>]+>.*?</function>"
    cleaned = re.sub(tool_pattern, "", content, flags=re.DOTALL)

    hidden_xml_patterns = [
        r"<inter_agent_message>.*?</inter_agent_message>",
        r"<agent_completion_report>.*?</agent_completion_report>",
    ]
    for pattern in hidden_xml_patterns:
        cleaned = re.sub(pattern, "", cleaned, flags=re.DOTALL | re.IGNORECASE)

    cleaned = re.sub(r"\n\s*\n", "\n\n", cleaned)

    return cleaned.strip()


def validate_tool_invocation(invocation: dict[str, Any]) -> tuple[bool, list[str]]:
    """Valida que una invocación de herramienta sea correcta.
    
    Realiza validaciones de:
    - Presencia de toolName
    - Formato correcto de args
    - Parámetros requeridos según la herramienta
    - Validación de URLs para herramientas de browser
    
    Args:
        invocation: Diccionario con la invocación de herramienta
        
    Returns:
        Tuple de (es_válido, lista_de_errores)
        
    Example:
        >>> invocation = {"toolName": "browser_actions.navigate", "args": {"url": "https://example.com"}}
        >>> is_valid, errors = validate_tool_invocation(invocation)
        >>> is_valid
        True
    """
    errors: list[str] = []
    
    # Validar presencia de toolName
    tool_name = invocation.get("toolName", "")
    if not tool_name:
        errors.append("Missing toolName")
        return False, errors
    
    if not isinstance(tool_name, str):
        errors.append(f"toolName must be a string, got {type(tool_name).__name__}")
        return False, errors
    
    # Validar args
    args = invocation.get("args", {})
    if not isinstance(args, dict):
        errors.append(f"args must be a dictionary, got {type(args).__name__}")
        return False, errors
    
    # Validar parámetros requeridos si la herramienta es conocida
    if tool_name in KNOWN_TOOLS:
        required_params = KNOWN_TOOLS[tool_name]
        for param in required_params:
            if param not in args:
                errors.append(f"Missing required parameter '{param}' for {tool_name}")
    
    # Validaciones específicas por herramienta
    if "browser" in tool_name.lower() and "url" in args:
        url = args["url"]
        if isinstance(url, str):
            url_validation_errors = _validate_url(url)
            errors.extend(url_validation_errors)
    
    if "file" in tool_name.lower() and "file_path" in args:
        file_path = args["file_path"]
        if isinstance(file_path, str):
            path_validation_errors = _validate_file_path(file_path)
            errors.extend(path_validation_errors)
    
    if "terminal" in tool_name.lower() and "command" in args:
        command = args["command"]
        if isinstance(command, str):
            cmd_validation_errors = _validate_command(command)
            errors.extend(cmd_validation_errors)
    
    return len(errors) == 0, errors


def _validate_url(url: str) -> list[str]:
    """Valida que una URL sea correcta y segura.
    
    Args:
        url: URL a validar
        
    Returns:
        Lista de errores encontrados
    """
    errors: list[str] = []
    
    if not url:
        errors.append("URL is empty")
        return errors
    
    # Validar esquema
    if not url.startswith(("http://", "https://")):
        errors.append(f"Invalid URL scheme. URL must start with http:// or https://. Got: {url[:50]}")
        return errors
    
    # Intentar parsear la URL
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            errors.append(f"Invalid URL: missing hostname in {url[:50]}")
    except Exception as e:
        errors.append(f"Failed to parse URL: {str(e)[:100]}")
    
    return errors


def _validate_file_path(file_path: str) -> list[str]:
    """Valida que una ruta de archivo sea razonable.
    
    Args:
        file_path: Ruta de archivo a validar
        
    Returns:
        Lista de errores encontrados
    """
    errors: list[str] = []
    
    if not file_path:
        errors.append("file_path is empty")
        return errors
    
    # Detectar posibles path traversal maliciosos
    dangerous_patterns = ["../", "..\\", "%2e%2e", "%252e"]
    for pattern in dangerous_patterns:
        if pattern.lower() in file_path.lower():
            # Esto es una advertencia, no un error, porque podría ser intencional en pentesting
            pass  # No bloqueamos, pero podríamos loggear
    
    return errors


def _validate_command(command: str) -> list[str]:
    """Valida que un comando de terminal sea razonable.
    
    Args:
        command: Comando a validar
        
    Returns:
        Lista de errores encontrados
    """
    errors: list[str] = []
    
    if not command:
        errors.append("command is empty")
        return errors
    
    # Comandos que podrían ser peligrosos (solo advertencias en contexto de pentesting)
    # No bloqueamos pero podríamos querer loggear
    
    return errors


def validate_all_invocations(
    invocations: list[dict[str, Any]] | None,
) -> tuple[bool, dict[str, list[str]]]:
    """Valida todas las invocaciones de herramientas.
    
    Args:
        invocations: Lista de invocaciones a validar
        
    Returns:
        Tuple de (todas_válidas, diccionario_de_errores_por_índice)
        
    Example:
        >>> invocations = [
        ...     {"toolName": "browser_actions.navigate", "args": {"url": "https://example.com"}},
        ...     {"toolName": "terminal.execute", "args": {}},  # Missing command
        ... ]
        >>> all_valid, errors = validate_all_invocations(invocations)
        >>> all_valid
        False
        >>> errors
        {1: ["Missing required parameter 'command' for terminal.execute"]}
    """
    if not invocations:
        return True, {}
    
    all_errors: dict[str, list[str]] = {}
    all_valid = True
    
    for idx, invocation in enumerate(invocations):
        is_valid, errors = validate_tool_invocation(invocation)
        if not is_valid:
            all_valid = False
            all_errors[str(idx)] = errors
    
    return all_valid, all_errors
