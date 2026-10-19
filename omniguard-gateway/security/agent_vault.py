"""
OmniGuard Agent Vault Module
Ported from Odysseus src/tool_security.py
Tool filtering logic to prevent unauthorized tool execution.
"""

from __future__ import annotations
import logging
from typing import Optional, Set, FrozenSet
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class ToolCategory(Enum):
    """Categories of tools for policy enforcement."""
    SYSTEM = "system"           # bash, python, shell access
    FILE = "file"               # read_file, write_file, edit_file
    NETWORK = "network"         # api_call, web_fetch, curl
    DATABASE = "database"       # query_database, SQL tools
    EMAIL = "email"             # send_email, list_emails, etc.
    MANAGEMENT = "management"   # manage_*, admin tools
    MODEL = "model"             # serve_model, download_model
    MCP = "mcp"                 # MCP server tools


# Odysseus NON_ADMIN_BLOCKED_TOOLS - exact port
NON_ADMIN_BLOCKED_TOOLS: FrozenSet[str] = frozenset({
    # Built-in email tools (Odysseus BUILTIN_EMAIL_TOOLS)
    "list_email_accounts",
    "list_emails",
    "read_email",
    "search_emails",
    "scan_email_unsubscribes",
    "unsubscribe_email",
    "send_email",
    "reply_to_email",
    "draft_email",
    "draft_email_reply",
    "ai_draft_email_reply",
    "archive_email",
    "delete_email",
    "mark_email_read",
    "bulk_email",
    "download_attachment",
    # System/execution tools
    "bash",
    "python",
    "manage_bg_jobs",
    # File operations
    "read_file",
    "write_file",
    "edit_file",
    "apply_patch",
    "grep",
    "glob",
    "ls",
    "get_workspace",
    # Chat/history
    "search_chats",
    # Management tools
    "manage_memory",
    "manage_skills",
    "manage_tasks",
    "manage_endpoints",
    "manage_mcp",
    "manage_webhooks",
    "manage_tokens",
    "manage_documents",
    "manage_settings",
    # API/integration
    "api_call",
    "app_api",
    # Contacts/calendar
    "resolve_contact",
    "manage_contact",
    "manage_calendar",
    # Vault
    "vault_search",
    "vault_get",
    "vault_unlock",
    # Model serving
    "download_model",
    "serve_model",
    "serve_preset",
    "stop_served_model",
    "cancel_download",
    "adopt_served_model",
})


# Odysseus PLAN_MODE_READONLY_TOOLS - exact port
PLAN_MODE_READONLY_TOOLS: FrozenSet[str] = frozenset({
    "read_file",
    "grep",
    "glob",
    "ls",
    "get_workspace",
    "web_search",
    "web_fetch",
    "search_chats",
    "list_models",
    "list_sessions",
    "list_email_accounts",
    "list_emails",
    "read_email",
    "search_emails",
    "scan_email_unsubscribes",
    "list_served_models",
    "list_downloads",
    "list_cached_models",
    "search_hf_models",
    "list_serve_presets",
    "list_cookbook_servers",
    "resolve_contact",
    "chat_with_model",
    "ask_teacher",
})


# Odysseus _PLAN_MODE_KNOWN_MUTATORS - exact port
PLAN_MODE_KNOWN_MUTATORS: FrozenSet[str] = frozenset({
    "write_file", "edit_file", "apply_patch", "todowrite",
    "create_document", "edit_document", "update_document",
    "suggest_document", "manage_documents", "create_session", "manage_session",
    "send_to_session", "pipeline", "manage_memory", "manage_skills",
    "manage_tasks", "manage_notes", "manage_endpoints", "manage_mcp",
    "manage_webhooks", "manage_tokens", "manage_settings", "manage_contact",
    "manage_calendar", "api_call", "app_api", "ui_control",
    "send_email", "reply_to_email", "bulk_email", "delete_email",
    "archive_email", "mark_email_read", "unsubscribe_email",
    "draft_email", "draft_email_reply", "ai_draft_email_reply",
    "download_attachment",
    "download_model", "serve_model",
    "stop_served_model", "cancel_download", "adopt_served_model", "serve_preset",
    "generate_image", "edit_image", "trigger_research", "manage_research",
    "bash", "python",
    "manage_bg_jobs",
})


# Tool category mapping for policy decisions
TOOL_CATEGORIES = {
    # System
    "bash": ToolCategory.SYSTEM,
    "python": ToolCategory.SYSTEM,
    "manage_bg_jobs": ToolCategory.SYSTEM,
    # File
    "read_file": ToolCategory.FILE,
    "write_file": ToolCategory.FILE,
    "edit_file": ToolCategory.FILE,
    "apply_patch": ToolCategory.FILE,
    "grep": ToolCategory.FILE,
    "glob": ToolCategory.FILE,
    "ls": ToolCategory.FILE,
    "get_workspace": ToolCategory.FILE,
    # Network
    "api_call": ToolCategory.NETWORK,
    "app_api": ToolCategory.NETWORK,
    "web_search": ToolCategory.NETWORK,
    "web_fetch": ToolCategory.NETWORK,
    # Email
    "list_email_accounts": ToolCategory.EMAIL,
    "list_emails": ToolCategory.EMAIL,
    "read_email": ToolCategory.EMAIL,
    "search_emails": ToolCategory.EMAIL,
    "scan_email_unsubscribes": ToolCategory.EMAIL,
    "unsubscribe_email": ToolCategory.EMAIL,
    "send_email": ToolCategory.EMAIL,
    "reply_to_email": ToolCategory.EMAIL,
    "draft_email": ToolCategory.EMAIL,
    "draft_email_reply": ToolCategory.EMAIL,
    "ai_draft_email_reply": ToolCategory.EMAIL,
    "archive_email": ToolCategory.EMAIL,
    "delete_email": ToolCategory.EMAIL,
    "mark_email_read": ToolCategory.EMAIL,
    "bulk_email": ToolCategory.EMAIL,
    "download_attachment": ToolCategory.EMAIL,
    # Database
    "query_database": ToolCategory.DATABASE,
    # Management
    "manage_memory": ToolCategory.MANAGEMENT,
    "manage_skills": ToolCategory.MANAGEMENT,
    "manage_tasks": ToolCategory.MANAGEMENT,
    "manage_endpoints": ToolCategory.MANAGEMENT,
    "manage_mcp": ToolCategory.MANAGEMENT,
    "manage_webhooks": ToolCategory.MANAGEMENT,
    "manage_tokens": ToolCategory.MANAGEMENT,
    "manage_documents": ToolCategory.MANAGEMENT,
    "manage_settings": ToolCategory.MANAGEMENT,
    "manage_contact": ToolCategory.MANAGEMENT,
    "manage_calendar": ToolCategory.MANAGEMENT,
    # Model
    "download_model": ToolCategory.MODEL,
    "serve_model": ToolCategory.MODEL,
    "serve_preset": ToolCategory.MODEL,
    "stop_served_model": ToolCategory.MODEL,
    "cancel_download": ToolCategory.MODEL,
    "adopt_served_model": ToolCategory.MODEL,
    "list_models": ToolCategory.MODEL,
    "list_served_models": ToolCategory.MODEL,
    "list_downloads": ToolCategory.MODEL,
    "list_cached_models": ToolCategory.MODEL,
    "search_hf_models": ToolCategory.MODEL,
    "list_serve_presets": ToolCategory.MODEL,
    "list_cookbook_servers": ToolCategory.MODEL,
    # MCP
    "manage_mcp": ToolCategory.MCP,
    "vault_search": ToolCategory.MCP,
    "vault_get": ToolCategory.MCP,
    "vault_unlock": ToolCategory.MCP,
}


@dataclass
class ToolPolicyDecision:
    """Result of a tool policy check."""
    allowed: bool
    tool_name: str
    category: Optional[ToolCategory]
    reason: str
    required_role: str  # "admin", "user", "plan_mode"
    matched_aliases: FrozenSet[str]


class AgentVault:
    """Tool execution firewall ported from Odysseus tool_security.py.
    
    Enforces:
    - Non-admin users blocked from NON_ADMIN_BLOCKED_TOOLS
    - Plan mode only allows PLAN_MODE_READONLY_TOOLS
    - MCP tool alias matching (bare vs mcp__ qualified names)
    - Fail-closed: unknown/malformed tool names are blocked
    """
    
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        # Allow custom blocked tools
        if "additional_blocked_tools" in self.config:
            extra = frozenset(self.config["additional_blocked_tools"])
            self._blocked_tools = NON_ADMIN_BLOCKED_TOOLS | extra
        else:
            self._blocked_tools = NON_ADMIN_BLOCKED_TOOLS
        
        if "plan_mode_allowlist" in self.config:
            self._plan_mode_allowlist = frozenset(self.config["plan_mode_allowlist"])
        else:
            self._plan_mode_allowlist = PLAN_MODE_READONLY_TOOLS
        
        # Read-only tools a non-admin caller MAY invoke. Everything outside this
        # set is denied (see is_public_blocked_tool) so a new or renamed tool
        # fails closed instead of defaulting to allowed.
        self._public_safe_tools = frozenset({
            "web_search", "web_fetch", "list_models", "list_sessions",
            "search_hf_models", "chat_with_model", "ask_teacher",
        })
    
    @staticmethod
    def email_tool_policy_names(tool_name: str) -> FrozenSet[str]:
        """All policy-equivalent spellings of a tool name.
        
        Ported from Odysseus email_tool_policy_names().
        A bare built-in email tool name and its MCP-qualified
        mcp__email__<name> form dispatch to the same tool.
        """
        if not isinstance(tool_name, str):
            return frozenset((tool_name,))
        if tool_name in NON_ADMIN_BLOCKED_TOOLS:
            # Check if it's an email tool
            email_tools = {
                "list_email_accounts", "list_emails", "read_email", "search_emails",
                "scan_email_unsubscribes", "unsubscribe_email", "send_email",
                "reply_to_email", "draft_email", "draft_email_reply",
                "ai_draft_email_reply", "archive_email", "delete_email",
                "mark_email_read", "bulk_email", "download_attachment"
            }
            if tool_name in email_tools:
                return frozenset((tool_name, f"mcp__email__{tool_name}"))
        if tool_name.startswith("mcp__email__"):
            bare = tool_name[len("mcp__email__"):]
            email_tools = {
                "list_email_accounts", "list_emails", "read_email", "search_emails",
                "scan_email_unsubscribes", "unsubscribe_email", "send_email",
                "reply_to_email", "draft_email", "draft_email_reply",
                "ai_draft_email_reply", "archive_email", "delete_email",
                "mark_email_read", "bulk_email", "download_attachment"
            }
            if bare in email_tools:
                return frozenset((tool_name, bare))
        return frozenset((tool_name,))
    
    def is_public_blocked_tool(self, tool_name: Optional[str]) -> bool:
        """Return True when a non-admin/public user must not execute this tool.
        
        Ported from Odysseus is_public_blocked_tool().
        Fails CLOSED: malformed/non-string tool names are treated as blocked.
        """
        if tool_name is None or tool_name == "":
            return False
        if not isinstance(tool_name, str):
            return True
        
        # Check direct match
        if tool_name in self._blocked_tools:
            return True
        
        # Check MCP namespace (all mcp__ tools blocked for non-admin)
        if tool_name.startswith("mcp__"):
            return True
        
        # Check email tool aliases
        aliases = self.email_tool_policy_names(tool_name)
        for alias in aliases:
            if alias in self._blocked_tools:
                return True
        
        # Deny-by-default: any tool name that isn't explicitly recognised as a
        # safe, read-only public tool is treated as blocked. Odysseus's version
        # returned False here, which let a novel or renamed tool slip past the
        # blocklist -- the exact bypass an attacker would reach for.
        if tool_name in self._public_safe_tools:
            return False
        return True
    
    def is_allowed_in_plan_mode(self, tool_name: Optional[str]) -> bool:
        """Check if tool is allowed in plan (read-only) mode.
        
        Plan mode uses an ALLOWLIST (PLAN_MODE_READONLY_TOOLS).
        """
        if tool_name is None or tool_name == "":
            return True  # No tool = no restriction
        if not isinstance(tool_name, str):
            return False  # Malformed = blocked
        
        # Direct allowlist check
        if tool_name in self._plan_mode_allowlist:
            return True
        
        # Check email tool aliases against allowlist
        aliases = self.email_tool_policy_names(tool_name)
        for alias in aliases:
            if alias in self._plan_mode_allowlist:
                return True
        
        return False
    
    def get_plan_mode_disabled_tools(self, known_tools: Optional[Set[str]] = None) -> Set[str]:
        """Get all tools to disable in plan mode.
        
        Ported from Odysseus plan_mode_disabled_tools().
        Returns the inverse of the allowlist (denylist format).
        """
        if known_tools is None:
            known_tools = set()
        
        # Add known mutators as backstop
        all_known = known_tools | PLAN_MODE_KNOWN_MUTATORS
        
        # Return everything NOT in allowlist
        return all_known - self._plan_mode_allowlist
    
    def check_tool(
        self,
        tool_name: Optional[str],
        is_admin: bool = False,
        is_plan_mode: bool = False,
        is_single_user_mode: bool = False,
    ) -> ToolPolicyDecision:
        """Comprehensive tool policy check.
        
        Args:
            tool_name: Name of tool to check
            is_admin: Whether caller is admin
            is_plan_mode: Whether in plan/read-only mode
            is_single_user_mode: Auth disabled (local single-user)
            
        Returns:
            ToolPolicyDecision with allowed/blocked and reason
        """
        if tool_name is None or tool_name == "":
            return ToolPolicyDecision(
                allowed=True,
                tool_name=tool_name or "",
                category=None,
                reason="no_tool_specified",
                required_role="none",
                matched_aliases=frozenset(),
            )
        
        if not isinstance(tool_name, str):
            return ToolPolicyDecision(
                allowed=False,
                tool_name=str(tool_name),
                category=None,
                reason="malformed_tool_name",
                required_role="admin",
                matched_aliases=frozenset(),
            )
        
        category = TOOL_CATEGORIES.get(tool_name)
        aliases = self.email_tool_policy_names(tool_name)
        
        # Single user mode = full access (Odysseus behavior)
        if is_single_user_mode:
            return ToolPolicyDecision(
                allowed=True,
                tool_name=tool_name,
                category=category,
                reason="single_user_mode",
                required_role="user",
                matched_aliases=aliases,
            )
        
        # Admin = full access
        if is_admin:
            return ToolPolicyDecision(
                allowed=True,
                tool_name=tool_name,
                category=category,
                reason="admin_access",
                required_role="admin",
                matched_aliases=aliases,
            )
        
        # Plan mode check
        if is_plan_mode:
            allowed = self.is_allowed_in_plan_mode(tool_name)
            return ToolPolicyDecision(
                allowed=allowed,
                tool_name=tool_name,
                category=category,
                reason="plan_mode_allowlist" if allowed else "plan_mode_denied",
                required_role="admin",
                matched_aliases=aliases,
            )
        
        # Public user check
        blocked = self.is_public_blocked_tool(tool_name)
        return ToolPolicyDecision(
            allowed=not blocked,
            tool_name=tool_name,
            category=category,
            reason="public_allowed" if not blocked else "public_blocked",
            required_role="admin" if blocked else "user",
            matched_aliases=aliases,
        )
    
    def filter_tools(
        self,
        tool_names: list[str],
        is_admin: bool = False,
        is_plan_mode: bool = False,
        is_single_user_mode: bool = False,
    ) -> tuple[list[str], list[str]]:
        """Filter a list of tool names, returning (allowed, blocked)."""
        allowed = []
        blocked = []
        for tool in tool_names:
            decision = self.check_tool(
                tool, is_admin, is_plan_mode, is_single_user_mode
            )
            if decision.allowed:
                allowed.append(tool)
            else:
                blocked.append(tool)
        return allowed, blocked


# Convenience functions for direct use
def is_public_blocked_tool(tool_name: Optional[str]) -> bool:
    """Quick check if tool is blocked for non-admin users."""
    return AgentVault().is_public_blocked_tool(tool_name)


def is_allowed_in_plan_mode(tool_name: Optional[str]) -> bool:
    """Quick check if tool is allowed in plan mode."""
    return AgentVault().is_allowed_in_plan_mode(tool_name)


def check_tool(
    tool_name: Optional[str],
    is_admin: bool = False,
    is_plan_mode: bool = False,
    is_single_user_mode: bool = False,
) -> ToolPolicyDecision:
    """Quick tool policy check."""
    return AgentVault().check_tool(tool_name, is_admin, is_plan_mode, is_single_user_mode)