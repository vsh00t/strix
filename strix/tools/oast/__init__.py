"""OAST (Out-of-Band Application Security Testing) module.

Provides infrastructure for detecting blind vulnerabilities through
DNS and HTTP callbacks.
"""
from strix.tools.oast.oast_manager import (
    OASTCallback,
    OASTManager,
    OASTPayload,
    get_oast_manager,
)
from strix.tools.oast.oast_actions import (
    generate_oast_payload,
    check_oast_interactions,
    list_oast_payloads,
    clear_oast_payloads,
)

__all__ = [
    "OASTCallback",
    "OASTManager",
    "OASTPayload",
    "get_oast_manager",
    "generate_oast_payload",
    "check_oast_interactions",
    "list_oast_payloads",
    "clear_oast_payloads",
]
