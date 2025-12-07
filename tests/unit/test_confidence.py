"""Tests para el módulo de confidence scoring (Fase 2).

Este módulo contiene tests para validar el sistema de puntuación de
confianza de vulnerabilidades, incluyendo:
- Cálculo de niveles de confianza
- Detección de indicadores de falsos positivos
- Detección de indicadores de explotación
- Creación de VulnerabilityFinding
"""
import pytest
from strix.llm.confidence import (
    ConfidenceLevel,
    VulnerabilityFinding,
    calculate_confidence,
    analyze_response_for_fp_indicators,
    analyze_response_for_exploitation,
    create_finding,
    FALSE_POSITIVE_PATTERNS,
    EXPLOITATION_INDICATORS,
)


class TestConfidenceLevel:
    """Tests para el enum ConfidenceLevel."""
    
    def test_confidence_level_values(self):
        """Verifica que los valores del enum son correctos."""
        assert ConfidenceLevel.HIGH.value == "high"
        assert ConfidenceLevel.MEDIUM.value == "medium"
        assert ConfidenceLevel.LOW.value == "low"
        assert ConfidenceLevel.FALSE_POSITIVE.value == "false_positive"
    
    def test_confidence_level_from_string(self):
        """Verifica que se puede crear ConfidenceLevel desde string."""
        assert ConfidenceLevel("high") == ConfidenceLevel.HIGH
        assert ConfidenceLevel("medium") == ConfidenceLevel.MEDIUM
        assert ConfidenceLevel("low") == ConfidenceLevel.LOW
        assert ConfidenceLevel("false_positive") == ConfidenceLevel.FALSE_POSITIVE


class TestCalculateConfidence:
    """Tests para la función calculate_confidence."""
    
    def test_high_confidence_with_exploitation(self):
        """Confianza HIGH cuando hay explotación confirmada."""
        result = calculate_confidence(
            indicators=["sql_error", "data_leak"],
            fp_indicators=[],
            exploitation_confirmed=True,
        )
        assert result == ConfidenceLevel.HIGH
    
    def test_high_confidence_many_indicators(self):
        """Confianza HIGH con muchos indicadores y explotación."""
        result = calculate_confidence(
            indicators=["sql_error", "data_leak", "timing_diff"],
            fp_indicators=[],
            exploitation_confirmed=True,
        )
        assert result == ConfidenceLevel.HIGH
    
    def test_false_positive_detection(self):
        """Detecta FALSE_POSITIVE cuando hay más indicadores FP."""
        result = calculate_confidence(
            indicators=["generic_error"],
            fp_indicators=["waf_block", "rate_limit", "static_page"],
            exploitation_confirmed=False,
        )
        assert result == ConfidenceLevel.FALSE_POSITIVE
    
    def test_false_positive_even_with_indicators(self):
        """FALSE_POSITIVE cuando FP supera indicadores positivos."""
        result = calculate_confidence(
            indicators=["error_msg"],
            fp_indicators=["waf_block", "rate_limit"],
            exploitation_confirmed=False,
        )
        assert result == ConfidenceLevel.FALSE_POSITIVE
    
    def test_medium_confidence_multiple_indicators(self):
        """Confianza MEDIUM con múltiples indicadores sin explotación."""
        result = calculate_confidence(
            indicators=["sql_syntax", "database_error"],
            fp_indicators=[],
            exploitation_confirmed=False,
        )
        assert result == ConfidenceLevel.MEDIUM
    
    def test_medium_confidence_three_indicators_one_fp(self):
        """Confianza MEDIUM con 3 indicadores y 1 FP."""
        result = calculate_confidence(
            indicators=["sql_syntax", "database_error", "timing"],
            fp_indicators=["generic_error"],
            exploitation_confirmed=False,
        )
        assert result == ConfidenceLevel.MEDIUM
    
    def test_low_confidence_single_indicator(self):
        """Confianza LOW con un solo indicador."""
        result = calculate_confidence(
            indicators=["maybe_error"],
            fp_indicators=[],
            exploitation_confirmed=False,
        )
        assert result == ConfidenceLevel.LOW
    
    def test_low_confidence_no_indicators(self):
        """Confianza LOW sin indicadores."""
        result = calculate_confidence(
            indicators=[],
            fp_indicators=[],
            exploitation_confirmed=False,
        )
        assert result == ConfidenceLevel.LOW
    
    def test_exploitation_overrides_fp_indicators(self):
        """Explotación confirmada supera indicadores de FP."""
        result = calculate_confidence(
            indicators=["sql_error", "data_leak"],
            fp_indicators=["waf_block"],
            exploitation_confirmed=True,
        )
        assert result == ConfidenceLevel.HIGH


class TestAnalyzeResponseForFPIndicators:
    """Tests para analyze_response_for_fp_indicators."""
    
    def test_detects_waf_block(self):
        """Detecta bloqueo de WAF."""
        response = "Access denied by Cloudflare security rules"
        indicators = analyze_response_for_fp_indicators(response, "sql_injection")
        assert "cloudflare" in indicators
    
    def test_detects_rate_limit(self):
        """Detecta rate limiting."""
        response = "Too many requests. Please try again later."
        indicators = analyze_response_for_fp_indicators(response, "generic")
        assert "too many requests" in indicators
    
    def test_detects_input_validation(self):
        """Detecta validación de input."""
        response = "Invalid parameter: ID must be numeric"
        indicators = analyze_response_for_fp_indicators(response, "sql_injection")
        assert "invalid parameter" in indicators
    
    def test_detects_multiple_indicators(self):
        """Detecta múltiples indicadores en una respuesta."""
        response = "Bad Request: Invalid characters detected. Access denied by WAF."
        indicators = analyze_response_for_fp_indicators(response, "sql_injection")
        assert len(indicators) >= 2
    
    def test_empty_response(self):
        """Maneja respuestas vacías."""
        indicators = analyze_response_for_fp_indicators("", "sql_injection")
        assert indicators == []
    
    def test_no_fp_indicators_in_clean_response(self):
        """No encuentra indicadores en respuesta limpia."""
        response = "User profile loaded successfully"
        indicators = analyze_response_for_fp_indicators(response, "sql_injection")
        assert len(indicators) == 0
    
    def test_case_insensitive_detection(self):
        """Detecta indicadores sin importar mayúsculas/minúsculas."""
        response = "CLOUDFLARE blocked this request"
        indicators = analyze_response_for_fp_indicators(response, "sql_injection")
        assert "cloudflare" in indicators
    
    def test_xss_specific_indicators(self):
        """Detecta indicadores específicos de XSS."""
        response = "Content blocked due to Content-Security-Policy violation"
        indicators = analyze_response_for_fp_indicators(response, "xss")
        assert "content-security-policy" in indicators


class TestAnalyzeResponseForExploitation:
    """Tests para analyze_response_for_exploitation."""
    
    def test_detects_sql_error(self):
        """Detecta errores de SQL."""
        response = "Error: You have an error in your SQL syntax near..."
        indicators = analyze_response_for_exploitation(response, "sql_injection")
        assert "sql syntax" in indicators
    
    def test_detects_mysql_function(self):
        """Detecta funciones de MySQL."""
        response = "Warning: mysql_fetch_array() expects parameter 1"
        indicators = analyze_response_for_exploitation(response, "sql_injection")
        assert "mysql_fetch" in indicators
    
    def test_detects_information_schema(self):
        """Detecta acceso a information_schema."""
        response = "Results from information_schema.tables"
        indicators = analyze_response_for_exploitation(response, "sql_injection")
        assert "information_schema" in indicators
    
    def test_detects_xss_execution(self):
        """Detecta indicadores de XSS ejecutado."""
        response = "Script executed in DOM, cookie accessed"
        indicators = analyze_response_for_exploitation(response, "xss")
        assert "cookie accessed" in indicators or "script executed" in indicators
    
    def test_detects_ssrf_metadata(self):
        """Detecta acceso a metadata de cloud."""
        response = "Retrieved cloud metadata from 169.254.169.254"
        indicators = analyze_response_for_exploitation(response, "ssrf")
        assert "169.254.169.254" in indicators or "cloud metadata" in indicators
    
    def test_detects_path_traversal(self):
        """Detecta path traversal exitoso."""
        response = "root:x:0:0:root:/root:/bin/bash"
        indicators = analyze_response_for_exploitation(response, "path_traversal")
        assert "root:x:" in indicators
    
    def test_detects_rce(self):
        """Detecta ejecución de comandos."""
        response = "uid=1000(user) gid=1000(user) groups=1000(user)"
        indicators = analyze_response_for_exploitation(response, "rce")
        assert "uid=" in indicators
    
    def test_empty_response_returns_empty(self):
        """Maneja respuestas vacías."""
        indicators = analyze_response_for_exploitation("", "sql_injection")
        assert indicators == []
    
    def test_no_indicators_in_normal_response(self):
        """No encuentra indicadores en respuesta normal."""
        response = "Welcome to the application dashboard"
        indicators = analyze_response_for_exploitation(response, "sql_injection")
        assert len(indicators) == 0


class TestVulnerabilityFinding:
    """Tests para la clase VulnerabilityFinding."""
    
    def test_create_finding_basic(self):
        """Crea un finding básico."""
        finding = VulnerabilityFinding(
            vuln_type="sql_injection",
            confidence=ConfidenceLevel.HIGH,
        )
        assert finding.vuln_type == "sql_injection"
        assert finding.confidence == ConfidenceLevel.HIGH
        assert finding.evidence == []
        assert finding.reproduction_steps == []
    
    def test_create_finding_with_all_fields(self):
        """Crea un finding con todos los campos."""
        finding = VulnerabilityFinding(
            vuln_type="xss",
            confidence=ConfidenceLevel.MEDIUM,
            evidence=["reflected payload", "alert triggered"],
            reproduction_steps=["Send payload", "Observe alert"],
            false_positive_indicators=["rate limit warning"],
            payload_used="<script>alert(1)</script>",
            response_analysis="Script executed in browser",
        )
        assert finding.vuln_type == "xss"
        assert len(finding.evidence) == 2
        assert len(finding.reproduction_steps) == 2
        assert finding.payload_used == "<script>alert(1)</script>"
    
    def test_to_dict(self):
        """Convierte finding a diccionario."""
        finding = VulnerabilityFinding(
            vuln_type="sql_injection",
            confidence=ConfidenceLevel.HIGH,
            evidence=["sql_error"],
        )
        data = finding.to_dict()
        assert data["type"] == "sql_injection"
        assert data["confidence"] == "high"
        assert data["evidence"] == ["sql_error"]
    
    def test_from_dict(self):
        """Crea finding desde diccionario."""
        data = {
            "type": "idor",
            "confidence": "medium",
            "evidence": ["different user data"],
            "reproduction_steps": ["Change ID in URL"],
        }
        finding = VulnerabilityFinding.from_dict(data)
        assert finding.vuln_type == "idor"
        assert finding.confidence == ConfidenceLevel.MEDIUM
        assert "different user data" in finding.evidence
    
    def test_from_dict_defaults(self):
        """from_dict maneja valores por defecto."""
        data = {}
        finding = VulnerabilityFinding.from_dict(data)
        assert finding.vuln_type == "unknown"
        assert finding.confidence == ConfidenceLevel.LOW
    
    def test_is_actionable_high(self):
        """HIGH confidence es accionable."""
        finding = VulnerabilityFinding(
            vuln_type="sql_injection",
            confidence=ConfidenceLevel.HIGH,
        )
        assert finding.is_actionable() is True
    
    def test_is_actionable_medium(self):
        """MEDIUM confidence es accionable."""
        finding = VulnerabilityFinding(
            vuln_type="sql_injection",
            confidence=ConfidenceLevel.MEDIUM,
        )
        assert finding.is_actionable() is True
    
    def test_is_actionable_low(self):
        """LOW confidence no es accionable."""
        finding = VulnerabilityFinding(
            vuln_type="sql_injection",
            confidence=ConfidenceLevel.LOW,
        )
        assert finding.is_actionable() is False
    
    def test_is_actionable_false_positive(self):
        """FALSE_POSITIVE no es accionable."""
        finding = VulnerabilityFinding(
            vuln_type="sql_injection",
            confidence=ConfidenceLevel.FALSE_POSITIVE,
        )
        assert finding.is_actionable() is False


class TestCreateFinding:
    """Tests para la función create_finding."""
    
    def test_create_finding_with_sql_error(self):
        """Crea finding con error SQL detectado."""
        response = "Error: You have an error in your SQL syntax near 'OR'"
        finding = create_finding(
            vuln_type="sql_injection",
            response_text=response,
            payload="' OR '1'='1",
        )
        assert finding.vuln_type == "sql_injection"
        assert finding.confidence in (ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW)
        assert len(finding.evidence) > 0
        assert finding.payload_used == "' OR '1'='1"
    
    def test_create_finding_false_positive(self):
        """Crea finding que es falso positivo."""
        response = "Access denied by Cloudflare. Rate limit exceeded. Invalid parameter."
        finding = create_finding(
            vuln_type="sql_injection",
            response_text=response,
            payload="' OR '1'='1",
        )
        assert finding.confidence == ConfidenceLevel.FALSE_POSITIVE
        assert len(finding.false_positive_indicators) >= 2
    
    def test_create_finding_high_confidence(self):
        """Crea finding con alta confianza."""
        response = "Data extracted from information_schema.tables using UNION SELECT"
        finding = create_finding(
            vuln_type="sql_injection",
            response_text=response,
            payload="' UNION SELECT table_name FROM information_schema.tables--",
            exploitation_confirmed=True,
        )
        assert finding.confidence == ConfidenceLevel.HIGH
    
    def test_create_finding_truncates_long_response(self):
        """Trunca respuestas largas."""
        response = "x" * 1000
        finding = create_finding(
            vuln_type="sql_injection",
            response_text=response,
        )
        assert len(finding.response_analysis) <= 500
    
    def test_create_finding_with_reproduction_steps(self):
        """Incluye pasos de reproducción."""
        finding = create_finding(
            vuln_type="xss",
            response_text="Alert triggered",
            reproduction_steps=["Navigate to page", "Enter payload", "Submit form"],
        )
        assert len(finding.reproduction_steps) == 3


class TestPatternDictionaries:
    """Tests para verificar que los diccionarios de patrones están completos."""
    
    def test_false_positive_patterns_has_required_keys(self):
        """Verifica que FALSE_POSITIVE_PATTERNS tiene las claves requeridas."""
        required_keys = ["sql_injection", "xss", "ssrf", "idor", "generic"]
        for key in required_keys:
            assert key in FALSE_POSITIVE_PATTERNS
    
    def test_exploitation_indicators_has_required_keys(self):
        """Verifica que EXPLOITATION_INDICATORS tiene las claves requeridas."""
        required_keys = ["sql_injection", "xss", "ssrf", "idor", "rce"]
        for key in required_keys:
            assert key in EXPLOITATION_INDICATORS
    
    def test_patterns_are_not_empty(self):
        """Verifica que los patrones no están vacíos."""
        for key, patterns in FALSE_POSITIVE_PATTERNS.items():
            assert len(patterns) > 0, f"FALSE_POSITIVE_PATTERNS[{key}] is empty"
        
        for key, patterns in EXPLOITATION_INDICATORS.items():
            assert len(patterns) > 0, f"EXPLOITATION_INDICATORS[{key}] is empty"
