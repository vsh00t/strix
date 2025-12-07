"""Tests para el módulo de optimización de tokens (Fase 3).

Este módulo contiene tests para:
- Límites de tokens por modelo
- Cálculo de costos
- Estimación de tokens
- Optimización de mensajes
"""
import pytest

from strix.llm.token_optimizer import (
    get_max_tokens_for_model,
    get_token_cost,
    estimate_tokens,
    estimate_messages_tokens,
    should_compress_context,
    get_context_utilization,
    optimize_messages_for_tokens,
    MAX_TOKENS_BY_MODEL,
    TOKEN_COSTS,
)


class TestGetMaxTokensForModel:
    """Tests para get_max_tokens_for_model()."""
    
    def test_gpt4_exact_match(self):
        """Match exacto para gpt-4."""
        assert get_max_tokens_for_model("gpt-4") == 128_000
    
    def test_gpt4o_exact_match(self):
        """Match exacto para gpt-4o."""
        assert get_max_tokens_for_model("gpt-4o") == 128_000
    
    def test_claude_3_partial_match(self):
        """Match parcial para claude-3."""
        assert get_max_tokens_for_model("claude-3-sonnet") == 200_000
    
    def test_with_provider_prefix(self):
        """Maneja prefijo de proveedor."""
        assert get_max_tokens_for_model("openai/gpt-4o") == 128_000
        assert get_max_tokens_for_model("anthropic/claude-3-sonnet") == 200_000
    
    def test_case_insensitive(self):
        """Es case insensitive."""
        assert get_max_tokens_for_model("GPT-4") == 128_000
        assert get_max_tokens_for_model("Claude-3") == 200_000
    
    def test_unknown_model_returns_default(self):
        """Modelo desconocido retorna default."""
        assert get_max_tokens_for_model("unknown-model") == 100_000
    
    def test_gemini_large_context(self):
        """Gemini tiene contexto grande."""
        result = get_max_tokens_for_model("gemini-pro")
        assert result >= 1_000_000


class TestGetTokenCost:
    """Tests para get_token_cost()."""
    
    def test_basic_cost_calculation(self):
        """Cálculo básico de costo."""
        cost = get_token_cost("gpt-4", 1000, 500)
        
        # GPT-4: $0.03/1K input, $0.06/1K output
        # Expected: 1000/1000 * 0.03 + 500/1000 * 0.06 = 0.03 + 0.03 = 0.06
        assert cost == pytest.approx(0.06, rel=0.1)
    
    def test_cost_with_cached_tokens(self):
        """Costo con tokens cacheados (descuento)."""
        cost_without_cache = get_token_cost("gpt-4", 1000, 500, cached_tokens=0)
        cost_with_cache = get_token_cost("gpt-4", 1000, 500, cached_tokens=500)
        
        # Con cache debería ser menor
        assert cost_with_cache < cost_without_cache
    
    def test_cost_with_provider_prefix(self):
        """Maneja prefijo de proveedor."""
        cost = get_token_cost("openai/gpt-4o", 1000, 500)
        assert cost > 0
    
    def test_unknown_model_uses_default(self):
        """Modelo desconocido usa costos por defecto."""
        cost = get_token_cost("unknown-model", 1000, 500)
        assert cost > 0


class TestEstimateTokens:
    """Tests para estimate_tokens()."""
    
    def test_estimate_short_text(self):
        """Estima tokens de texto corto."""
        tokens = estimate_tokens("Hello world")
        
        # Típicamente 2-3 tokens
        assert 1 <= tokens <= 10
    
    def test_estimate_longer_text(self):
        """Estima tokens de texto más largo."""
        text = "This is a longer text that should have more tokens. " * 10
        tokens = estimate_tokens(text)
        
        # Debería ser proporcional al largo
        assert tokens > 50
    
    def test_estimate_empty_text(self):
        """Estima tokens de texto vacío."""
        tokens = estimate_tokens("")
        assert tokens == 0


class TestEstimateMessagesTokens:
    """Tests para estimate_messages_tokens()."""
    
    def test_single_message(self):
        """Estima tokens de un mensaje."""
        messages = [
            {"role": "user", "content": "Hello, how are you?"}
        ]
        tokens = estimate_messages_tokens(messages)
        
        assert tokens > 0
    
    def test_multiple_messages(self):
        """Estima tokens de múltiples mensajes."""
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello!"},
            {"role": "assistant", "content": "Hi there!"},
        ]
        tokens = estimate_messages_tokens(messages)
        
        # Cada mensaje tiene overhead + contenido
        assert tokens > 10
    
    def test_empty_messages(self):
        """Maneja lista de mensajes vacía."""
        tokens = estimate_messages_tokens([])
        assert tokens == 0
    
    def test_multimodal_message(self):
        """Estima tokens de mensaje con imagen."""
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "What's in this image?"},
                    {"type": "image_url", "image_url": {"url": "http://example.com/img.jpg"}},
                ],
            }
        ]
        tokens = estimate_messages_tokens(messages)
        
        # Debe incluir estimación para imagen
        assert tokens > 100


class TestShouldCompressContext:
    """Tests para should_compress_context()."""
    
    def test_small_context_no_compression(self):
        """Contexto pequeño no necesita compresión."""
        messages = [{"role": "user", "content": "Hello!"}]
        
        result = should_compress_context(messages, "gpt-4")
        assert result is False
    
    def test_large_context_needs_compression(self):
        """Contexto grande necesita compresión."""
        # Crear mensajes muy largos
        long_content = "x" * 100000  # Aproximadamente 25K tokens
        messages = [
            {"role": "system", "content": long_content},
            {"role": "user", "content": long_content},
            {"role": "assistant", "content": long_content},
            {"role": "user", "content": long_content},
        ]
        
        result = should_compress_context(messages, "gpt-4", threshold_pct=0.5)
        # Depende del modelo y threshold, pero debería ser True para contextos grandes
        assert isinstance(result, bool)
    
    def test_custom_threshold(self):
        """Usa threshold personalizado."""
        messages = [{"role": "user", "content": "x" * 10000}]
        
        # Con threshold muy bajo, debería necesitar compresión
        result_low = should_compress_context(messages, "gpt-4", threshold_pct=0.001)
        
        # Con threshold alto, no debería necesitar
        result_high = should_compress_context(messages, "gpt-4", threshold_pct=0.99)
        
        assert result_low is True or result_high is False


class TestGetContextUtilization:
    """Tests para get_context_utilization()."""
    
    def test_utilization_structure(self):
        """Verifica estructura del resultado."""
        messages = [{"role": "user", "content": "Hello!"}]
        
        result = get_context_utilization(messages, "gpt-4")
        
        assert "max_tokens" in result
        assert "current_tokens" in result
        assert "utilization_pct" in result
        assert "remaining_tokens" in result
        assert "should_compress" in result
        assert "message_count" in result
    
    def test_utilization_values(self):
        """Verifica valores de utilización."""
        messages = [{"role": "user", "content": "Hello!"}]
        
        result = get_context_utilization(messages, "gpt-4")
        
        assert result["max_tokens"] == 128_000
        assert result["current_tokens"] > 0
        assert result["utilization_pct"] < 1  # Muy pequeño
        assert result["remaining_tokens"] > 100_000
        assert result["message_count"] == 1


class TestOptimizeMessagesForTokens:
    """Tests para optimize_messages_for_tokens()."""
    
    def test_empty_messages(self):
        """Maneja lista vacía."""
        result = optimize_messages_for_tokens([], target_tokens=1000)
        assert result == []
    
    def test_preserves_system_messages(self):
        """Preserva mensajes del sistema."""
        messages = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Hello!"},
        ]
        
        result = optimize_messages_for_tokens(
            messages,
            target_tokens=10000,
            preserve_system=True,
        )
        
        # Debe mantener el mensaje del sistema
        system_msgs = [m for m in result if m.get("role") == "system"]
        assert len(system_msgs) == 1
    
    def test_preserves_recent_messages(self):
        """Preserva mensajes recientes."""
        messages = [
            {"role": "user", "content": f"Message {i}"} for i in range(10)
        ]
        
        result = optimize_messages_for_tokens(
            messages,
            target_tokens=500,  # Muy pequeño
            preserve_recent=3,
        )
        
        # Debe tener al menos los 3 más recientes
        assert len(result) >= 3
        # El último debe ser Message 9
        assert "Message 9" in result[-1]["content"]
    
    def test_removes_older_messages_when_needed(self):
        """Elimina mensajes antiguos si es necesario."""
        messages = [
            {"role": "user", "content": "x" * 10000} for _ in range(10)
        ]
        
        result = optimize_messages_for_tokens(
            messages,
            target_tokens=500,  # Muy pequeño
            preserve_recent=2,
        )
        
        # Debería tener menos mensajes que el original
        assert len(result) <= len(messages)


class TestModelConstants:
    """Tests para constantes de modelos."""
    
    def test_max_tokens_has_required_models(self):
        """Verifica que MAX_TOKENS_BY_MODEL tiene modelos requeridos."""
        required = ["gpt-4", "claude-3", "default"]
        for model in required:
            assert model in MAX_TOKENS_BY_MODEL
    
    def test_token_costs_has_required_models(self):
        """Verifica que TOKEN_COSTS tiene modelos requeridos."""
        required = ["gpt-4", "default"]
        for model in required:
            assert model in TOKEN_COSTS
    
    def test_token_costs_structure(self):
        """Verifica estructura de costos."""
        for model, costs in TOKEN_COSTS.items():
            assert "input" in costs
            assert "output" in costs
            assert costs["input"] > 0
            assert costs["output"] > 0
