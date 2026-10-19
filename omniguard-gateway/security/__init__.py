"""
OmniGuard Security Package
Modular security components ported from Odysseus and enhanced for enterprise gateway.
"""

from security.trust_boundary import (
    TrustBoundary,
    TrustSegment, 
    TrustLevel,
    untrusted_context_message,
    UNTRUSTED_CONTEXT_POLICY,
    UNTRUSTED_CONTEXT_HEADER,
    GUARD_OPEN,
    GUARD_CLOSE,
)

from security.agent_vault import (
    AgentVault,
    ToolCategory,
    ToolPolicyDecision,
    NON_ADMIN_BLOCKED_TOOLS,
    PLAN_MODE_READONLY_TOOLS,
    PLAN_MODE_KNOWN_MUTATORS,
    is_public_blocked_tool,
    is_allowed_in_plan_mode,
    check_tool,
)

from security.governance import (
    GovernanceSigner,
    GovernanceSignature,
    InternalToolAuth,
    INTERNAL_TOOL_TOKEN,
    INTERNAL_TOOL_HEADER,
    INTERNAL_TOOL_USER,
    generate_governance_signature,
    verify_governance_signature,
    create_request_signature,
    create_response_signature,
    SecurityHeaders,
    DEFAULT_SIGNER,
    DEFAULT_INTERNAL_AUTH,
)

from security.waf import (
    WAFScanner,
    WAFResult,
    WAFMatch,
    WAFRuleCategory,
    waf_scan,
    waf_scan_segments,
    is_blocked,
    get_matches,
    tier0_fast_path,
    normalize_compact,
    normalize_unicode,
    decode_base64_safe,
    extract_base64_candidates,
)

__all__ = [
    # trust_boundary
    "TrustBoundary",
    "TrustSegment", 
    "TrustLevel",
    "untrusted_context_message",
    "UNTRUSTED_CONTEXT_POLICY",
    "UNTRUSTED_CONTEXT_HEADER",
    "GUARD_OPEN",
    "GUARD_CLOSE",
    # agent_vault
    "AgentVault",
    "ToolCategory",
    "ToolPolicyDecision",
    "NON_ADMIN_BLOCKED_TOOLS",
    "PLAN_MODE_READONLY_TOOLS",
    "PLAN_MODE_KNOWN_MUTATORS",
    "is_public_blocked_tool",
    "is_allowed_in_plan_mode",
    "check_tool",
    # governance
    "GovernanceSigner",
    "GovernanceSignature",
    "InternalToolAuth",
    "INTERNAL_TOOL_TOKEN",
    "INTERNAL_TOOL_HEADER",
    "INTERNAL_TOOL_USER",
    "generate_governance_signature",
    "verify_governance_signature",
    "create_request_signature",
    "create_response_signature",
    "SecurityHeaders",
    "DEFAULT_SIGNER",
    "DEFAULT_INTERNAL_AUTH",
    # waf
    "WAFScanner",
    "WAFResult",
    "WAFMatch",
    "WAFRuleCategory",
    "waf_scan",
    "waf_scan_segments",
    "is_blocked",
    "get_matches",
    "tier0_fast_path",
    "normalize_compact",
    "normalize_unicode",
    "decode_base64_safe",
    "extract_base64_candidates",
]

__version__ = "2.0.0"