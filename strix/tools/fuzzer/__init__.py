"""Fuzzer module for automated payload injection and differential analysis.

Provides intelligent fuzzing capabilities with built-in wordlists
and anomaly detection.
"""
from strix.tools.fuzzer.fuzzer_manager import (
    FuzzerManager,
    FuzzResult,
    FuzzSession,
    get_fuzzer_manager,
)
from strix.tools.fuzzer.fuzzer_actions import (
    fuzz_parameter,
    spray_payloads,
    differential_analysis,
    get_wordlist,
    list_wordlists,
)
from strix.tools.fuzzer.wordlists import (
    WORDLISTS,
    get_payloads,
    list_available_wordlists,
)

__all__ = [
    "FuzzerManager",
    "FuzzResult",
    "FuzzSession",
    "get_fuzzer_manager",
    "fuzz_parameter",
    "spray_payloads",
    "differential_analysis",
    "get_wordlist",
    "list_wordlists",
    "WORDLISTS",
    "get_payloads",
    "list_available_wordlists",
]
