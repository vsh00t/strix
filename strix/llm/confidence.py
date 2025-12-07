"""Sistema de puntuación de confianza para hallazgos de seguridad.

Este módulo implementa un sistema de clasificación de confianza para
vulnerabilidades detectadas, ayudando a reducir falsos positivos mediante
la evaluación de múltiples indicadores de evidencia.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ConfidenceLevel(Enum):
    """Niveles de confianza para hallazgos de vulnerabilidades."""
    
    HIGH = "high"      # Explotación confirmada con PoC
    MEDIUM = "medium"  # Indicadores fuertes sin explotación completa
    LOW = "low"        # Potencial vulnerabilidad, requiere verificación manual
    FALSE_POSITIVE = "false_positive"  # Descartado como falso positivo


# Indicadores comunes de falsos positivos por tipo de vulnerabilidad
FALSE_POSITIVE_PATTERNS: dict[str, list[str]] = {
    "sql_injection": [
        "invalid parameter",
        "bad request",
        "waf block",
        "rate limit",
        "cloudflare",
        "access denied",
        "too many requests",
        "invalid characters",
        "input validation",
    ],
    "xss": [
        "content-security-policy",
        "csp violation",
        "sanitized",
        "encoded output",
        "escaped",
        "htmlspecialchars",
    ],
    "ssrf": [
        "invalid url",
        "url not allowed",
        "blocked domain",
        "internal network",
        "firewall",
    ],
    "idor": [
        "not found",
        "does not exist",
        "invalid id",
        "unauthorized",  # Could be valid authz, not necessarily IDOR
    ],
    "path_traversal": [
        "invalid path",
        "path not allowed",
        "file not found",
        "access denied",
    ],
    "generic": [
        "waf",
        "firewall",
        "rate limit",
        "too many requests",
        "blocked",
        "forbidden",
        "static error page",
    ],
}


# Indicadores de explotación exitosa por tipo de vulnerabilidad
EXPLOITATION_INDICATORS: dict[str, list[str]] = {
    "sql_injection": [
        "sql syntax",
        "mysql_fetch",
        "pg_query",
        "sqlite3",
        "ora-",
        "sqlserver",
        "data extracted",
        "union select",
        "column count",
        "table_name",
        "information_schema",
    ],
    "xss": [
        "script executed",
        "alert triggered",
        "dom manipulation",
        "reflected payload",
        "stored payload",
        "cookie accessed",
    ],
    "ssrf": [
        "internal response",
        "metadata",
        "169.254.169.254",
        "localhost response",
        "internal service",
        "cloud metadata",
    ],
    "idor": [
        "different user data",
        "unauthorized access",
        "data from other user",
        "resource belonging to",
    ],
    "path_traversal": [
        "file contents",
        "/etc/passwd",
        "root:x:",
        "windows\\system32",
        "file read successful",
    ],
    "rce": [
        "command output",
        "shell response",
        "system information",
        "uid=",
        "whoami",
        "reverse shell",
    ],
}


@dataclass
class VulnerabilityFinding:
    """Representa un hallazgo de vulnerabilidad con metadatos de confianza."""
    
    vuln_type: str
    confidence: ConfidenceLevel
    evidence: list[str] = field(default_factory=list)
    reproduction_steps: list[str] = field(default_factory=list)
    false_positive_indicators: list[str] = field(default_factory=list)
    payload_used: str = ""
    response_analysis: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        """Convierte el hallazgo a diccionario para serialización."""
        return {
            "type": self.vuln_type,
            "confidence": self.confidence.value,
            "evidence": self.evidence,
            "reproduction_steps": self.reproduction_steps,
            "fp_indicators": self.false_positive_indicators,
            "payload": self.payload_used,
            "analysis": self.response_analysis,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VulnerabilityFinding":
        """Crea un VulnerabilityFinding desde un diccionario."""
        return cls(
            vuln_type=data.get("type", "unknown"),
            confidence=ConfidenceLevel(data.get("confidence", "low")),
            evidence=data.get("evidence", []),
            reproduction_steps=data.get("reproduction_steps", []),
            false_positive_indicators=data.get("fp_indicators", []),
            payload_used=data.get("payload", ""),
            response_analysis=data.get("analysis", ""),
        )
    
    def is_actionable(self) -> bool:
        """Determina si el hallazgo es accionable (HIGH o MEDIUM confidence)."""
        return self.confidence in (ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM)


def calculate_confidence(
    indicators: list[str],
    fp_indicators: list[str],
    exploitation_confirmed: bool = False,
    vuln_type: str = "generic",
) -> ConfidenceLevel:
    """Calcula el nivel de confianza basado en evidencia.
    
    Args:
        indicators: Lista de indicadores positivos de vulnerabilidad
        fp_indicators: Lista de indicadores de falso positivo encontrados
        exploitation_confirmed: Si la explotación fue confirmada
        vuln_type: Tipo de vulnerabilidad para aplicar reglas específicas
    
    Returns:
        ConfidenceLevel apropiado basado en la evidencia
    
    Example:
        >>> calculate_confidence(
        ...     indicators=["sql_error", "data_leak", "timing_diff"],
        ...     fp_indicators=[],
        ...     exploitation_confirmed=True
        ... )
        ConfidenceLevel.HIGH
    """
    # Si hay explotación confirmada con suficiente evidencia, es HIGH
    if exploitation_confirmed and len(indicators) >= 2:
        return ConfidenceLevel.HIGH
    
    # Si los indicadores de FP superan a los positivos, es FALSE_POSITIVE
    if len(fp_indicators) > len(indicators) and not exploitation_confirmed:
        return ConfidenceLevel.FALSE_POSITIVE
    
    # Si hay múltiples indicadores sin FP significativos
    if len(indicators) >= 3 and len(fp_indicators) <= 1:
        return ConfidenceLevel.HIGH if exploitation_confirmed else ConfidenceLevel.MEDIUM
    
    # Si hay algunos indicadores
    if len(indicators) >= 2:
        return ConfidenceLevel.MEDIUM
    
    # Pocos indicadores = baja confianza
    return ConfidenceLevel.LOW


def analyze_response_for_fp_indicators(
    response_text: str,
    vuln_type: str = "generic",
) -> list[str]:
    """Analiza una respuesta HTTP buscando indicadores de falso positivo.
    
    Args:
        response_text: Texto de la respuesta a analizar
        vuln_type: Tipo de vulnerabilidad para usar patrones específicos
    
    Returns:
        Lista de indicadores de falso positivo encontrados
    """
    found_indicators: list[str] = []
    response_lower = response_text.lower()
    
    # Obtener patrones específicos del tipo de vulnerabilidad
    patterns = FALSE_POSITIVE_PATTERNS.get(vuln_type, [])
    patterns.extend(FALSE_POSITIVE_PATTERNS.get("generic", []))
    
    for pattern in patterns:
        if pattern.lower() in response_lower:
            found_indicators.append(pattern)
    
    return list(set(found_indicators))  # Eliminar duplicados


def analyze_response_for_exploitation(
    response_text: str,
    vuln_type: str = "generic",
) -> list[str]:
    """Analiza una respuesta buscando indicadores de explotación exitosa.
    
    Args:
        response_text: Texto de la respuesta a analizar
        vuln_type: Tipo de vulnerabilidad para usar patrones específicos
    
    Returns:
        Lista de indicadores de explotación encontrados
    """
    found_indicators: list[str] = []
    response_lower = response_text.lower()
    
    # Obtener patrones específicos del tipo de vulnerabilidad
    patterns = EXPLOITATION_INDICATORS.get(vuln_type, [])
    
    for pattern in patterns:
        if pattern.lower() in response_lower:
            found_indicators.append(pattern)
    
    return list(set(found_indicators))


def create_finding(
    vuln_type: str,
    response_text: str,
    payload: str = "",
    reproduction_steps: list[str] | None = None,
    exploitation_confirmed: bool = False,
) -> VulnerabilityFinding:
    """Crea un VulnerabilityFinding con análisis automático de confianza.
    
    Esta función analiza automáticamente la respuesta para detectar
    indicadores de falso positivo y explotación exitosa.
    
    Args:
        vuln_type: Tipo de vulnerabilidad (sql_injection, xss, etc.)
        response_text: Texto de la respuesta HTTP
        payload: Payload utilizado
        reproduction_steps: Pasos de reproducción
        exploitation_confirmed: Si el usuario confirmó la explotación
    
    Returns:
        VulnerabilityFinding con confidence level calculado
    
    Example:
        >>> finding = create_finding(
        ...     vuln_type="sql_injection",
        ...     response_text="Error: mysql_fetch_array() expects parameter",
        ...     payload="1' OR '1'='1",
        ... )
        >>> finding.confidence
        ConfidenceLevel.MEDIUM
    """
    # Analizar la respuesta
    fp_indicators = analyze_response_for_fp_indicators(response_text, vuln_type)
    exploitation_indicators = analyze_response_for_exploitation(response_text, vuln_type)
    
    # Calcular confianza
    confidence = calculate_confidence(
        indicators=exploitation_indicators,
        fp_indicators=fp_indicators,
        exploitation_confirmed=exploitation_confirmed,
        vuln_type=vuln_type,
    )
    
    return VulnerabilityFinding(
        vuln_type=vuln_type,
        confidence=confidence,
        evidence=exploitation_indicators,
        reproduction_steps=reproduction_steps or [],
        false_positive_indicators=fp_indicators,
        payload_used=payload,
        response_analysis=response_text[:500] if len(response_text) > 500 else response_text,
    )
