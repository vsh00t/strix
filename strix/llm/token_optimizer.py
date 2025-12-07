"""Helpers de optimización de tokens para el LLM.

Este módulo proporciona utilidades para optimizar el uso de tokens,
incluyendo:
- Límites de tokens por modelo
- Estimación de costos
- Estrategias de compresión
"""
import os
from typing import Any

import litellm


# Límites de contexto por modelo (tokens máximos)
MAX_TOKENS_BY_MODEL: dict[str, int] = {
    # OpenAI
    "gpt-4": 128_000,
    "gpt-4-turbo": 128_000,
    "gpt-4o": 128_000,
    "gpt-4o-mini": 128_000,
    "gpt-5": 200_000,
    "o1": 200_000,
    "o1-mini": 128_000,
    "o1-preview": 128_000,
    "o3": 200_000,
    "o3-mini": 128_000,
    # Anthropic
    "claude-3": 200_000,
    "claude-3-opus": 200_000,
    "claude-3-sonnet": 200_000,
    "claude-3-haiku": 200_000,
    "claude-sonnet": 200_000,
    "claude-opus": 200_000,
    "claude-4": 200_000,
    # Google
    "gemini": 1_000_000,
    "gemini-pro": 1_000_000,
    "gemini-1.5": 2_000_000,
    # Local/Open source
    "llama": 8_000,
    "llama-3": 128_000,
    "mistral": 32_000,
    "mixtral": 32_000,
    "codellama": 16_000,
    "deepseek": 64_000,
    # Default
    "default": 100_000,
}


# Costos por 1K tokens (USD) - Aproximados
TOKEN_COSTS: dict[str, dict[str, float]] = {
    "gpt-4": {"input": 0.03, "output": 0.06},
    "gpt-4-turbo": {"input": 0.01, "output": 0.03},
    "gpt-4o": {"input": 0.005, "output": 0.015},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "o1": {"input": 0.015, "output": 0.06},
    "o1-mini": {"input": 0.003, "output": 0.012},
    "claude-3-opus": {"input": 0.015, "output": 0.075},
    "claude-3-sonnet": {"input": 0.003, "output": 0.015},
    "claude-3-haiku": {"input": 0.00025, "output": 0.00125},
    "claude-sonnet": {"input": 0.003, "output": 0.015},
    "gemini-pro": {"input": 0.00025, "output": 0.0005},
    "default": {"input": 0.01, "output": 0.03},
}


def get_max_tokens_for_model(model_name: str) -> int:
    """Obtiene el límite de tokens para un modelo.
    
    Args:
        model_name: Nombre del modelo (puede incluir prefijo de proveedor)
        
    Returns:
        Número máximo de tokens que el modelo soporta
        
    Example:
        >>> get_max_tokens_for_model("openai/gpt-4o")
        128000
        >>> get_max_tokens_for_model("anthropic/claude-3-sonnet")
        200000
    """
    # Remover prefijo de proveedor si existe
    if "/" in model_name:
        model_name = model_name.split("/")[-1]
    
    model_lower = model_name.lower()
    
    # Buscar coincidencia exacta primero
    if model_lower in MAX_TOKENS_BY_MODEL:
        return MAX_TOKENS_BY_MODEL[model_lower]
    
    # Buscar coincidencia parcial
    for key, value in MAX_TOKENS_BY_MODEL.items():
        if key in model_lower:
            return value
    
    return MAX_TOKENS_BY_MODEL["default"]


def get_token_cost(
    model_name: str,
    input_tokens: int,
    output_tokens: int,
    cached_tokens: int = 0,
) -> float:
    """Calcula el costo estimado de tokens.
    
    Args:
        model_name: Nombre del modelo
        input_tokens: Tokens de entrada
        output_tokens: Tokens de salida
        cached_tokens: Tokens servidos desde cache (costo reducido)
        
    Returns:
        Costo estimado en USD
        
    Example:
        >>> get_token_cost("gpt-4o", 1000, 500, 200)
        0.0115
    """
    # Remover prefijo de proveedor
    if "/" in model_name:
        model_name = model_name.split("/")[-1]
    
    model_lower = model_name.lower()
    
    # Buscar costos del modelo
    costs = TOKEN_COSTS.get("default")
    for key, value in TOKEN_COSTS.items():
        if key in model_lower:
            costs = value
            break
    
    if costs is None:
        costs = TOKEN_COSTS["default"]
    
    # Calcular costo
    # Tokens cacheados típicamente tienen 50% de descuento
    effective_input = input_tokens - cached_tokens + (cached_tokens * 0.5)
    input_cost = (effective_input / 1000) * costs["input"]
    output_cost = (output_tokens / 1000) * costs["output"]
    
    return round(input_cost + output_cost, 6)


def estimate_tokens(text: str, model_name: str = "gpt-4") -> int:
    """Estima el número de tokens en un texto.
    
    Args:
        text: Texto a analizar
        model_name: Modelo para usar el tokenizer correcto
        
    Returns:
        Número estimado de tokens
    """
    try:
        count = litellm.token_counter(model=model_name, text=text)
        return int(count)
    except Exception:
        # Fallback: aproximadamente 4 caracteres por token
        return len(text) // 4


def estimate_messages_tokens(
    messages: list[dict[str, Any]],
    model_name: str = "gpt-4",
) -> int:
    """Estima el número de tokens en una lista de mensajes.
    
    Args:
        messages: Lista de mensajes en formato OpenAI
        model_name: Modelo para usar el tokenizer correcto
        
    Returns:
        Número estimado de tokens totales
    """
    total = 0
    
    for msg in messages:
        # Overhead por mensaje (role, structure)
        total += 4
        
        content = msg.get("content", "")
        if isinstance(content, str):
            total += estimate_tokens(content, model_name)
        elif isinstance(content, list):
            # Contenido multimodal
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    total += estimate_tokens(item.get("text", ""), model_name)
                elif isinstance(item, dict) and item.get("type") == "image_url":
                    # Imágenes típicamente cuestan ~85-1000 tokens
                    total += 500  # Estimación conservadora
        
        # Role
        role = msg.get("role", "")
        total += estimate_tokens(role, model_name)
    
    return total


def should_compress_context(
    messages: list[dict[str, Any]],
    model_name: str,
    threshold_pct: float = 0.75,
) -> bool:
    """Determina si el contexto debería comprimirse.
    
    Args:
        messages: Lista de mensajes
        model_name: Nombre del modelo
        threshold_pct: Porcentaje del límite para activar compresión
        
    Returns:
        True si el contexto excede el umbral
    """
    max_tokens = get_max_tokens_for_model(model_name)
    current_tokens = estimate_messages_tokens(messages, model_name)
    threshold = int(max_tokens * threshold_pct)
    
    return current_tokens >= threshold


def get_context_utilization(
    messages: list[dict[str, Any]],
    model_name: str,
) -> dict[str, Any]:
    """Obtiene estadísticas de utilización del contexto.
    
    Args:
        messages: Lista de mensajes
        model_name: Nombre del modelo
        
    Returns:
        Diccionario con estadísticas de utilización
    """
    max_tokens = get_max_tokens_for_model(model_name)
    current_tokens = estimate_messages_tokens(messages, model_name)
    
    return {
        "max_tokens": max_tokens,
        "current_tokens": current_tokens,
        "utilization_pct": round(current_tokens / max_tokens * 100, 2),
        "remaining_tokens": max_tokens - current_tokens,
        "should_compress": current_tokens >= (max_tokens * 0.75),
        "message_count": len(messages),
    }


def optimize_messages_for_tokens(
    messages: list[dict[str, Any]],
    target_tokens: int,
    preserve_system: bool = True,
    preserve_recent: int = 5,
) -> list[dict[str, Any]]:
    """Optimiza mensajes para alcanzar un número objetivo de tokens.
    
    Estrategia:
    1. Preservar mensajes del sistema
    2. Preservar los N mensajes más recientes
    3. Truncar o eliminar mensajes intermedios
    
    Args:
        messages: Lista de mensajes
        target_tokens: Número objetivo de tokens
        preserve_system: Si preservar mensajes del sistema
        preserve_recent: Número de mensajes recientes a preservar
        
    Returns:
        Lista de mensajes optimizada
    """
    if not messages:
        return messages
    
    # Separar mensajes por tipo
    system_messages = []
    other_messages = []
    
    for msg in messages:
        if msg.get("role") == "system" and preserve_system:
            system_messages.append(msg)
        else:
            other_messages.append(msg)
    
    # Preservar los más recientes
    if len(other_messages) <= preserve_recent:
        return system_messages + other_messages
    
    recent = other_messages[-preserve_recent:]
    older = other_messages[:-preserve_recent]
    
    # Calcular tokens de partes fijas
    fixed_tokens = estimate_messages_tokens(system_messages + recent)
    available_for_older = target_tokens - fixed_tokens
    
    if available_for_older <= 0:
        return system_messages + recent
    
    # Incluir mensajes antiguos hasta llenar el espacio disponible
    optimized_older = []
    current_older_tokens = 0
    
    for msg in reversed(older):
        msg_tokens = estimate_messages_tokens([msg])
        if current_older_tokens + msg_tokens <= available_for_older:
            optimized_older.insert(0, msg)
            current_older_tokens += msg_tokens
        else:
            break
    
    return system_messages + optimized_older + recent


# Constantes exportadas
DEFAULT_CONTEXT_THRESHOLD = float(os.getenv("STRIX_CONTEXT_THRESHOLD", "0.75"))
DEFAULT_PRESERVE_RECENT = int(os.getenv("STRIX_PRESERVE_RECENT", "15"))
