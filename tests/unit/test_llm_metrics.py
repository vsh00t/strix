"""Tests para el módulo de métricas LLM (Fase 3).

Este módulo contiene tests para:
- LLMMetrics dataclass
- Recording de requests
- Cálculo de resúmenes
- Exportación JSON
- Singleton global
"""
import json
import tempfile
from pathlib import Path

import pytest

from strix.telemetry.llm_metrics import (
    LLMMetrics,
    RequestMetrics,
    get_global_metrics,
    reset_global_metrics,
    METRICS_ENABLED,
)


class TestRequestMetrics:
    """Tests para RequestMetrics dataclass."""
    
    def test_create_request_metrics(self):
        """Crea RequestMetrics con todos los campos."""
        metrics = RequestMetrics(
            timestamp="2025-01-01T00:00:00Z",
            success=True,
            input_tokens=100,
            output_tokens=50,
            cached_tokens=20,
            latency_ms=500.0,
            tool_parsed=True,
            confidence_level="high",
            error_type=None,
            model_name="gpt-4",
        )
        
        assert metrics.timestamp == "2025-01-01T00:00:00Z"
        assert metrics.success is True
        assert metrics.input_tokens == 100
        assert metrics.output_tokens == 50
        assert metrics.cached_tokens == 20
        assert metrics.latency_ms == 500.0
        assert metrics.tool_parsed is True
        assert metrics.confidence_level == "high"
        assert metrics.error_type is None
        assert metrics.model_name == "gpt-4"


class TestLLMMetrics:
    """Tests para LLMMetrics class."""
    
    @pytest.fixture
    def metrics(self):
        """Crea una instancia limpia de LLMMetrics."""
        return LLMMetrics()
    
    def test_initial_state(self, metrics):
        """Verifica estado inicial de métricas."""
        assert metrics.total_requests == 0
        assert metrics.successful_requests == 0
        assert metrics.failed_requests == 0
        assert metrics.total_input_tokens == 0
        assert metrics.total_output_tokens == 0
        assert metrics.total_cached_tokens == 0
        assert metrics.first_request_time is None
        assert metrics.last_request_time is None
    
    def test_record_successful_request(self, metrics):
        """Registra una request exitosa."""
        metrics.record_request(
            success=True,
            input_tokens=100,
            output_tokens=50,
            cached_tokens=20,
            latency_ms=500.0,
            tool_parsed=True,
        )
        
        assert metrics.total_requests == 1
        assert metrics.successful_requests == 1
        assert metrics.failed_requests == 0
        assert metrics.total_input_tokens == 100
        assert metrics.total_output_tokens == 50
        assert metrics.total_cached_tokens == 20
        assert metrics.total_latency_ms == 500.0
        assert metrics.tool_parse_successes == 1
        assert metrics.tool_parse_failures == 0
    
    def test_record_failed_request(self, metrics):
        """Registra una request fallida."""
        metrics.record_request(
            success=False,
            input_tokens=0,
            output_tokens=0,
            cached_tokens=0,
            latency_ms=100.0,
            tool_parsed=False,
            error_type="RateLimitError",
        )
        
        assert metrics.total_requests == 1
        assert metrics.successful_requests == 0
        assert metrics.failed_requests == 1
        assert metrics.tool_parse_failures == 1
        assert metrics.errors_by_type["RateLimitError"] == 1
    
    def test_record_multiple_requests(self, metrics):
        """Registra múltiples requests."""
        for i in range(5):
            metrics.record_request(
                success=True,
                input_tokens=100,
                output_tokens=50,
                cached_tokens=10,
                latency_ms=500.0,
            )
        
        assert metrics.total_requests == 5
        assert metrics.successful_requests == 5
        assert metrics.total_input_tokens == 500
        assert metrics.total_output_tokens == 250
        assert metrics.total_latency_ms == 2500.0
    
    def test_record_confidence_levels(self, metrics):
        """Registra diferentes niveles de confianza."""
        metrics.record_request(success=True, confidence_level="high")
        metrics.record_request(success=True, confidence_level="medium")
        metrics.record_request(success=True, confidence_level="low")
        metrics.record_request(success=True, confidence_level="false_positive")
        
        assert metrics.confidence_high == 1
        assert metrics.confidence_medium == 1
        assert metrics.confidence_low == 1
        assert metrics.false_positives_detected == 1
    
    def test_latency_tracking(self, metrics):
        """Verifica tracking de latencia min/max."""
        metrics.record_request(success=True, latency_ms=100.0)
        metrics.record_request(success=True, latency_ms=500.0)
        metrics.record_request(success=True, latency_ms=300.0)
        
        assert metrics.min_latency_ms == 100.0
        assert metrics.max_latency_ms == 500.0
        assert metrics.total_latency_ms == 900.0
    
    def test_record_empty_response(self, metrics):
        """Registra respuestas vacías."""
        metrics.record_empty_response()
        metrics.record_empty_response()
        
        assert metrics.empty_responses == 2
    
    def test_timestamps_recorded(self, metrics):
        """Verifica que se registran timestamps."""
        assert metrics.first_request_time is None
        
        metrics.record_request(success=True)
        
        assert metrics.first_request_time is not None
        assert metrics.last_request_time is not None
    
    def test_history_limited(self, metrics):
        """Verifica que el historial se limita correctamente."""
        metrics.max_history_size = 10
        
        for i in range(20):
            metrics.record_request(success=True, input_tokens=i)
        
        assert len(metrics.request_history) == 10
        # Debe tener los más recientes
        assert metrics.request_history[-1].input_tokens == 19


class TestLLMMetricsGetSummary:
    """Tests para get_summary()."""
    
    @pytest.fixture
    def populated_metrics(self):
        """Crea métricas con datos de ejemplo."""
        metrics = LLMMetrics()
        
        # 8 exitosas
        for _ in range(8):
            metrics.record_request(
                success=True,
                input_tokens=1000,
                output_tokens=500,
                cached_tokens=200,
                latency_ms=1000.0,
                tool_parsed=True,
            )
        
        # 2 fallidas
        for _ in range(2):
            metrics.record_request(
                success=False,
                input_tokens=500,
                output_tokens=0,
                cached_tokens=0,
                latency_ms=500.0,
                tool_parsed=False,
                error_type="TimeoutError",
            )
        
        return metrics
    
    def test_summary_requests(self, populated_metrics):
        """Verifica resumen de requests."""
        summary = populated_metrics.get_summary()
        
        assert summary["requests"]["total"] == 10
        assert summary["requests"]["successful"] == 8
        assert summary["requests"]["failed"] == 2
        assert summary["requests"]["success_rate_pct"] == 80.0
    
    def test_summary_tokens(self, populated_metrics):
        """Verifica resumen de tokens."""
        summary = populated_metrics.get_summary()
        
        # 8 * 1000 + 2 * 500 = 9000 input tokens
        assert summary["tokens"]["total_input"] == 9000
        # 8 * 500 = 4000 output tokens
        assert summary["tokens"]["total_output"] == 4000
        # 8 * 200 = 1600 cached tokens
        assert summary["tokens"]["total_cached"] == 1600
        
        # Promedio: 9000 / 10 = 900
        assert summary["tokens"]["avg_input_per_request"] == 900.0
    
    def test_summary_cache_hit_rate(self, populated_metrics):
        """Verifica cálculo de cache hit rate."""
        summary = populated_metrics.get_summary()
        
        # Cache hit rate: 1600 / 9000 * 100 ≈ 17.78%
        assert summary["tokens"]["cache_hit_rate_pct"] > 0
    
    def test_summary_performance(self, populated_metrics):
        """Verifica métricas de rendimiento."""
        summary = populated_metrics.get_summary()
        
        # Total latency: 8*1000 + 2*500 = 9000ms
        # Avg: 9000 / 10 = 900ms
        assert summary["performance"]["avg_latency_ms"] == 900.0
        assert summary["performance"]["min_latency_ms"] == 500.0
        assert summary["performance"]["max_latency_ms"] == 1000.0
    
    def test_summary_quality(self, populated_metrics):
        """Verifica métricas de calidad."""
        summary = populated_metrics.get_summary()
        
        # 8 parse successes, 2 failures
        assert summary["quality"]["tool_parse_successes"] == 8
        assert summary["quality"]["tool_parse_failures"] == 2
        assert summary["quality"]["tool_parse_rate_pct"] == 80.0
    
    def test_summary_errors(self, populated_metrics):
        """Verifica resumen de errores."""
        summary = populated_metrics.get_summary()
        
        assert summary["errors"]["total"] == 2
        assert summary["errors"]["by_type"]["TimeoutError"] == 2
    
    def test_summary_empty_metrics(self):
        """Verifica resumen con métricas vacías."""
        metrics = LLMMetrics()
        summary = metrics.get_summary()
        
        assert summary["requests"]["total"] == 0
        assert summary["requests"]["success_rate_pct"] == 0
        assert summary["tokens"]["cache_hit_rate_pct"] == 0
        assert summary["performance"]["avg_latency_ms"] == 0


class TestLLMMetricsGetRecentRequests:
    """Tests para get_recent_requests()."""
    
    def test_get_recent_requests(self):
        """Obtiene requests recientes."""
        metrics = LLMMetrics()
        
        for i in range(5):
            metrics.record_request(
                success=True,
                input_tokens=i * 100,
                output_tokens=i * 50,
                latency_ms=i * 100.0,
            )
        
        recent = metrics.get_recent_requests(3)
        
        assert len(recent) == 3
        assert recent[0]["input_tokens"] == 200  # El 3er request
        assert recent[2]["input_tokens"] == 400  # El 5to request
    
    def test_get_recent_requests_empty(self):
        """Maneja historial vacío."""
        metrics = LLMMetrics()
        recent = metrics.get_recent_requests(10)
        
        assert len(recent) == 0
    
    def test_get_recent_requests_less_than_count(self):
        """Maneja cuando hay menos requests que el count solicitado."""
        metrics = LLMMetrics()
        metrics.record_request(success=True)
        metrics.record_request(success=True)
        
        recent = metrics.get_recent_requests(10)
        
        assert len(recent) == 2


class TestLLMMetricsExport:
    """Tests para exportación de métricas."""
    
    def test_export_json(self):
        """Exporta métricas a JSON."""
        metrics = LLMMetrics()
        metrics.record_request(
            success=True,
            input_tokens=100,
            output_tokens=50,
            latency_ms=500.0,
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "metrics.json"
            metrics.export_json(filepath)
            
            assert filepath.exists()
            
            with open(filepath) as f:
                data = json.load(f)
            
            assert "summary" in data
            assert "recent_requests" in data
            assert data["summary"]["requests"]["total"] == 1
    
    def test_export_creates_directory(self):
        """Export crea directorio si no existe."""
        metrics = LLMMetrics()
        metrics.record_request(success=True)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "subdir" / "metrics.json"
            metrics.export_json(filepath)
            
            assert filepath.exists()


class TestLLMMetricsReset:
    """Tests para reset de métricas."""
    
    def test_reset(self):
        """Resetea todas las métricas."""
        metrics = LLMMetrics()
        
        # Agregar datos
        metrics.record_request(success=True, input_tokens=100)
        metrics.record_request(success=False, error_type="Error")
        metrics.record_empty_response()
        
        # Verificar que hay datos
        assert metrics.total_requests == 2
        assert metrics.empty_responses == 1
        
        # Reset
        metrics.reset()
        
        # Verificar reset
        assert metrics.total_requests == 0
        assert metrics.successful_requests == 0
        assert metrics.failed_requests == 0
        assert metrics.total_input_tokens == 0
        assert metrics.empty_responses == 0
        assert len(metrics.request_history) == 0
        assert len(metrics.errors_by_type) == 0
        assert metrics.first_request_time is None


class TestGlobalMetrics:
    """Tests para funciones globales de métricas."""
    
    def test_get_global_metrics_singleton(self):
        """Verifica que get_global_metrics retorna singleton."""
        metrics1 = get_global_metrics()
        metrics2 = get_global_metrics()
        
        assert metrics1 is metrics2
    
    def test_reset_global_metrics(self):
        """Resetea métricas globales."""
        metrics = get_global_metrics()
        metrics.record_request(success=True, input_tokens=100)
        
        assert metrics.total_requests >= 1
        
        reset_global_metrics()
        
        assert metrics.total_requests == 0


class TestMetricsEnabled:
    """Tests para control de habilitación de métricas."""
    
    def test_metrics_enabled_default(self):
        """Verifica que métricas están habilitadas por defecto."""
        # METRICS_ENABLED viene del env var, por defecto es True
        assert METRICS_ENABLED is True
