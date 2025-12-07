"""Métricas de rendimiento y calidad del LLM.

Este módulo proporciona un sistema completo de observabilidad para el LLM,
incluyendo:
- Tracking de requests exitosas/fallidas
- Métricas de uso de tokens (input, output, cached)
- Métricas de calidad (parsing de tools, confidence levels)
- Métricas de rendimiento (latencia, throughput)
- Exportación a JSON para análisis posterior
"""
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Control de habilitación via env var
METRICS_ENABLED = os.getenv("STRIX_METRICS_ENABLED", "true").lower() in ("true", "1", "yes")


@dataclass
class RequestMetrics:
    """Métricas de una request individual."""
    
    timestamp: str
    success: bool
    input_tokens: int
    output_tokens: int
    cached_tokens: int
    latency_ms: float
    tool_parsed: bool
    confidence_level: str | None = None
    error_type: str | None = None
    model_name: str | None = None


@dataclass
class LLMMetrics:
    """Recolector de métricas del LLM.
    
    Esta clase actúa como un agregador de métricas que puede ser
    consultado en cualquier momento para obtener un resumen del
    rendimiento del sistema LLM.
    
    Uso:
        metrics = get_global_metrics()
        metrics.record_request(success=True, input_tokens=100, ...)
        summary = metrics.get_summary()
    """
    
    # Contadores de requests
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    empty_responses: int = 0
    
    # Métricas de tokens
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cached_tokens: int = 0
    
    # Métricas de calidad
    tool_parse_successes: int = 0
    tool_parse_failures: int = 0
    confidence_high: int = 0
    confidence_medium: int = 0
    confidence_low: int = 0
    false_positives_detected: int = 0
    
    # Timing
    total_latency_ms: float = 0.0
    min_latency_ms: float = float('inf')
    max_latency_ms: float = 0.0
    
    # Historial de requests (últimas N)
    request_history: list[RequestMetrics] = field(default_factory=list)
    max_history_size: int = 1000
    
    # Errores por tipo
    errors_by_type: dict[str, int] = field(default_factory=dict)
    
    # Timestamps
    first_request_time: str | None = None
    last_request_time: str | None = None
    
    def record_request(
        self,
        success: bool,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cached_tokens: int = 0,
        latency_ms: float = 0.0,
        tool_parsed: bool = True,
        confidence_level: str | None = None,
        error_type: str | None = None,
        model_name: str | None = None,
    ) -> None:
        """Registra métricas de una request.
        
        Args:
            success: Si la request fue exitosa
            input_tokens: Tokens de entrada usados
            output_tokens: Tokens de salida generados
            cached_tokens: Tokens servidos desde cache
            latency_ms: Latencia en milisegundos
            tool_parsed: Si el parsing de tools fue exitoso
            confidence_level: Nivel de confianza del resultado (high/medium/low/false_positive)
            error_type: Tipo de error si la request falló
            model_name: Nombre del modelo utilizado
        """
        if not METRICS_ENABLED:
            return
        
        timestamp = datetime.now(UTC).isoformat()
        
        # Primera request
        if self.first_request_time is None:
            self.first_request_time = timestamp
        self.last_request_time = timestamp
        
        # Contadores básicos
        self.total_requests += 1
        
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
            if error_type:
                self.errors_by_type[error_type] = self.errors_by_type.get(error_type, 0) + 1
        
        # Tokens
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_cached_tokens += cached_tokens
        
        # Latencia
        self.total_latency_ms += latency_ms
        if latency_ms > 0:
            self.min_latency_ms = min(self.min_latency_ms, latency_ms)
            self.max_latency_ms = max(self.max_latency_ms, latency_ms)
        
        # Tool parsing
        if tool_parsed:
            self.tool_parse_successes += 1
        else:
            self.tool_parse_failures += 1
        
        # Confidence levels
        if confidence_level:
            level = confidence_level.lower()
            if level == "high":
                self.confidence_high += 1
            elif level == "medium":
                self.confidence_medium += 1
            elif level == "low":
                self.confidence_low += 1
            elif level == "false_positive":
                self.false_positives_detected += 1
        
        # Historial
        request_metric = RequestMetrics(
            timestamp=timestamp,
            success=success,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_tokens=cached_tokens,
            latency_ms=latency_ms,
            tool_parsed=tool_parsed,
            confidence_level=confidence_level,
            error_type=error_type,
            model_name=model_name,
        )
        self.request_history.append(request_metric)
        
        # Limitar tamaño del historial
        if len(self.request_history) > self.max_history_size:
            self.request_history = self.request_history[-self.max_history_size:]
    
    def record_empty_response(self) -> None:
        """Registra una respuesta vacía del LLM."""
        if METRICS_ENABLED:
            self.empty_responses += 1
    
    def get_summary(self) -> dict[str, Any]:
        """Retorna resumen de métricas.
        
        Returns:
            Diccionario con todas las métricas agregadas
        """
        # Cálculos de tasas
        success_rate = (
            self.successful_requests / self.total_requests * 100
            if self.total_requests > 0 else 0
        )
        
        avg_latency = (
            self.total_latency_ms / self.total_requests
            if self.total_requests > 0 else 0
        )
        
        cache_hit_rate = (
            self.total_cached_tokens / self.total_input_tokens * 100
            if self.total_input_tokens > 0 else 0
        )
        
        tool_parse_total = self.tool_parse_successes + self.tool_parse_failures
        tool_parse_rate = (
            self.tool_parse_successes / tool_parse_total * 100
            if tool_parse_total > 0 else 0
        )
        
        # Tokens promedio por request
        avg_input_tokens = (
            self.total_input_tokens / self.total_requests
            if self.total_requests > 0 else 0
        )
        avg_output_tokens = (
            self.total_output_tokens / self.total_requests
            if self.total_requests > 0 else 0
        )
        
        # Costo estimado (aproximado para GPT-4)
        # Input: $0.03/1K tokens, Output: $0.06/1K tokens
        estimated_cost_usd = (
            (self.total_input_tokens - self.total_cached_tokens) * 0.00003 +
            self.total_output_tokens * 0.00006
        )
        
        return {
            "meta": {
                "first_request": self.first_request_time,
                "last_request": self.last_request_time,
                "metrics_enabled": METRICS_ENABLED,
            },
            "requests": {
                "total": self.total_requests,
                "successful": self.successful_requests,
                "failed": self.failed_requests,
                "empty_responses": self.empty_responses,
                "success_rate_pct": round(success_rate, 2),
            },
            "tokens": {
                "total_input": self.total_input_tokens,
                "total_output": self.total_output_tokens,
                "total_cached": self.total_cached_tokens,
                "avg_input_per_request": round(avg_input_tokens, 1),
                "avg_output_per_request": round(avg_output_tokens, 1),
                "cache_hit_rate_pct": round(cache_hit_rate, 2),
                "estimated_cost_usd": round(estimated_cost_usd, 4),
            },
            "quality": {
                "tool_parse_successes": self.tool_parse_successes,
                "tool_parse_failures": self.tool_parse_failures,
                "tool_parse_rate_pct": round(tool_parse_rate, 2),
                "false_positives_detected": self.false_positives_detected,
            },
            "confidence_distribution": {
                "high": self.confidence_high,
                "medium": self.confidence_medium,
                "low": self.confidence_low,
                "false_positive": self.false_positives_detected,
            },
            "performance": {
                "avg_latency_ms": round(avg_latency, 2),
                "min_latency_ms": round(self.min_latency_ms, 2) if self.min_latency_ms != float('inf') else 0,
                "max_latency_ms": round(self.max_latency_ms, 2),
                "total_latency_ms": round(self.total_latency_ms, 2),
            },
            "errors": {
                "by_type": dict(self.errors_by_type),
                "total": self.failed_requests,
            },
        }
    
    def get_recent_requests(self, count: int = 10) -> list[dict[str, Any]]:
        """Obtiene las últimas N requests.
        
        Args:
            count: Número de requests a retornar
            
        Returns:
            Lista de métricas de requests recientes
        """
        recent = self.request_history[-count:]
        return [
            {
                "timestamp": r.timestamp,
                "success": r.success,
                "input_tokens": r.input_tokens,
                "output_tokens": r.output_tokens,
                "latency_ms": round(r.latency_ms, 2),
                "tool_parsed": r.tool_parsed,
                "confidence": r.confidence_level,
                "error": r.error_type,
            }
            for r in recent
        ]
    
    def export_json(self, filepath: str | Path) -> None:
        """Exporta métricas a archivo JSON.
        
        Args:
            filepath: Ruta del archivo de salida
        """
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            "summary": self.get_summary(),
            "recent_requests": self.get_recent_requests(50),
        }
        
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Metrics exported to {filepath}")
    
    def reset(self) -> None:
        """Resetea todas las métricas a cero."""
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.empty_responses = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cached_tokens = 0
        self.tool_parse_successes = 0
        self.tool_parse_failures = 0
        self.confidence_high = 0
        self.confidence_medium = 0
        self.confidence_low = 0
        self.false_positives_detected = 0
        self.total_latency_ms = 0.0
        self.min_latency_ms = float('inf')
        self.max_latency_ms = 0.0
        self.request_history = []
        self.errors_by_type = {}
        self.first_request_time = None
        self.last_request_time = None


# Singleton global
_global_metrics: LLMMetrics | None = None


def get_global_metrics() -> LLMMetrics:
    """Obtiene la instancia global de métricas.
    
    Returns:
        Instancia singleton de LLMMetrics
    """
    global _global_metrics
    if _global_metrics is None:
        _global_metrics = LLMMetrics()
    return _global_metrics


def reset_global_metrics() -> None:
    """Resetea las métricas globales."""
    global _global_metrics
    if _global_metrics is not None:
        _global_metrics.reset()


def export_metrics_on_exit(filepath: str | Path = "strix_metrics.json") -> None:
    """Exporta métricas al finalizar (para usar con atexit).
    
    Args:
        filepath: Ruta del archivo de salida
    """
    metrics = get_global_metrics()
    if metrics.total_requests > 0:
        metrics.export_json(filepath)
