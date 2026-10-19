"""
OmniGuard Authorization Framework
Enforces authorization outside the model for agent, tool, and MCP calls.
"""

import time
import hashlib
import hmac
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Any
from abc import ABC, abstractmethod


class AuthDecision(Enum):
    """Authorization decision outcomes."""
    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"  # Requires human approval
    ERROR = "error"


class PrincipalType(Enum):
    """Types of principals that can be authorized."""
    USER = "user"
    SERVICE = "service"
    AGENT = "agent"
    MCP_CLIENT = "mcp_client"


@dataclass
class Principal:
    """Represents an authenticated principal."""
    id: str
    type: PrincipalType
    tenant_id: str
    scopes: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def has_scope(self, scope: str) -> bool:
        """Check if principal has a specific scope."""
        return scope in self.scopes or "*" in self.scopes


@dataclass
class ToolOperation:
    """Represents a tool operation that requires authorization."""
    tool_name: str
    operation: str
    params: Dict[str, Any]
    required_scopes: Set[str]
    risk_level: str = "medium"  # low, medium, high, critical
    requires_human_approval: bool = False


@dataclass
class AuthContext:
    """Context for authorization decisions."""
    principal: Optional[Principal] = None
    tool_operation: Optional[ToolOperation] = None
    request_id: str = ""
    timestamp: int = field(default_factory=lambda: int(time.time()))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthResult:
    """Result of an authorization check."""
    decision: AuthDecision
    principal_id: str
    tool_name: str
    operation: str
    reason: str
    required_scopes: Set[str]
    principal_scopes: Set[str]
    missing_scopes: Set[str]
    risk_level: str
    requires_human_approval: bool
    latency_ms: float


class TokenValidator(ABC):
    """Abstract base for token validation."""
    
    @abstractmethod
    def validate(self, token: str, expected_audience: str, expected_issuer: str) -> Optional[Principal]:
        """Validate token and return principal if valid."""
        pass


class JWTTokenValidator(TokenValidator):
    """JWT token validator with audience and issuer verification."""
    
    def __init__(self, secret: str, algorithms: List[str] = None):
        self.secret = secret
        self.algorithms = algorithms or ["HS256"]
    
    def validate(self, token: str, expected_audience: str, expected_issuer: str) -> Optional[Principal]:
        """Validate JWT token - simplified implementation."""
        try:
            import jwt
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=self.algorithms,
                audience=expected_audience,
                issuer=expected_issuer
            )
            
            return Principal(
                id=payload.get("sub", "unknown"),
                type=PrincipalType(payload.get("type", "user")),
                tenant_id=payload.get("tenant_id", "default"),
                scopes=set(payload.get("scopes", [])),
                metadata=payload
            )
        except Exception as e:
            return None


class APIKeyValidator(TokenValidator):
    """API key validator with scope mapping."""
    
    def __init__(self, key_store: Dict[str, Dict]):
        """key_store maps API keys to principal info."""
        self.key_store = key_store
    
    def validate(self, token: str, expected_audience: str, expected_issuer: str) -> Optional[Principal]:
        """Validate API key."""
        if token not in self.key_store:
            return None
        
        info = self.key_store[token]
        return Principal(
            id=info.get("id", "unknown"),
            type=PrincipalType(info.get("type", "service")),
            tenant_id=info.get("tenant_id", "default"),
            scopes=set(info.get("scopes", [])),
            metadata=info
        )


class AuthorizationPolicy(ABC):
    """Abstract base for authorization policies."""
    
    @abstractmethod
    def evaluate(self, context: AuthContext) -> AuthResult:
        pass


class DenyByDefaultPolicy(AuthorizationPolicy):
    """Deny-by-default policy with explicit allow rules."""
    
    def __init__(self, allow_rules: List[Dict] = None):
        self.allow_rules = allow_rules or []
    
    def evaluate(self, context: AuthContext) -> AuthResult:
        start = time.perf_counter()
        
        if not context.principal:
            return AuthResult(
                decision=AuthDecision.DENY,
                principal_id="anonymous",
                tool_name=context.tool_operation.tool_name if context.tool_operation else "unknown",
                operation=context.tool_operation.operation if context.tool_operation else "unknown",
                reason="No authenticated principal",
                required_scopes=set(),
                principal_scopes=set(),
                missing_scopes=set(),
                risk_level="critical",
                requires_human_approval=False,
                latency_ms=(time.perf_counter() - start) * 1000
            )
        
        if not context.tool_operation:
            return AuthResult(
                decision=AuthDecision.ALLOW,
                principal_id=context.principal.id,
                tool_name="none",
                operation="none",
                reason="No tool operation to authorize",
                required_scopes=set(),
                principal_scopes=context.principal.scopes,
                missing_scopes=set(),
                risk_level="low",
                requires_human_approval=False,
                latency_ms=(time.perf_counter() - start) * 1000
            )
        
        # Check required scopes
        required = context.tool_operation.required_scopes
        principal_scopes = context.principal.scopes
        missing = required - principal_scopes
        
        # Check allow rules
        for rule in self.allow_rules:
            if self._matches_rule(context, rule):
                missing = set()
                break
        
        # Check tenant isolation
        if context.tool_operation and hasattr(context.tool_operation, 'tenant_id'):
            if context.tool_operation.tenant_id != context.principal.tenant_id:
                return AuthResult(
                    decision=AuthDecision.DENY,
                    principal_id=context.principal.id,
                    tool_name=context.tool_operation.tool_name,
                    operation=context.tool_operation.operation,
                    reason="Tenant isolation violation",
                    required_scopes=required,
                    principal_scopes=principal_scopes,
                    missing_scopes=required,
                    risk_level="critical",
                    requires_human_approval=False,
                    latency_ms=(time.perf_counter() - start) * 1000
                )
        
        # High-risk operations require human approval
        requires_approval = context.tool_operation.requires_human_approval or context.tool_operation.risk_level == "critical"
        
        if missing:
            return AuthResult(
                decision=AuthDecision.DENY,
                principal_id=context.principal.id,
                tool_name=context.tool_operation.tool_name,
                operation=context.tool_operation.operation,
                reason=f"Missing required scopes: {', '.join(missing)}",
                required_scopes=required,
                principal_scopes=principal_scopes,
                missing_scopes=missing,
                risk_level=context.tool_operation.risk_level,
                requires_human_approval=requires_approval,
                latency_ms=(time.perf_counter() - start) * 1000
            )
        
        decision = AuthDecision.CHALLENGE if requires_approval else AuthDecision.ALLOW
        
        return AuthResult(
            decision=decision,
            principal_id=context.principal.id,
            tool_name=context.tool_operation.tool_name,
            operation=context.tool_operation.operation,
            reason="Authorization successful" if decision == AuthDecision.ALLOW else "Requires human approval",
            required_scopes=required,
            principal_scopes=principal_scopes,
            missing_scopes=set(),
            risk_level=context.tool_operation.risk_level,
            requires_human_approval=requires_approval,
            latency_ms=(time.perf_counter() - start) * 1000
        )
    
    def _matches_rule(self, context: AuthContext, rule: Dict) -> bool:
        """Check if context matches an allow rule."""
        if "principal_id" in rule and context.principal.id != rule["principal_id"]:
            return False
        if "tool_name" in rule and context.tool_operation.tool_name != rule["tool_name"]:
            return False
        if "operation" in rule and context.tool_operation.operation != rule["operation"]:
            return False
        if "tenant_id" in rule and context.principal.tenant_id != rule["tenant_id"]:
            return False
        return True


class LeastPrivilegePolicy(AuthorizationPolicy):
    """Least-privilege policy - only grant minimum required access."""
    
    def __init__(self, max_scopes_per_operation: int = 3):
        self.max_scopes_per_operation = max_scopes_per_operation
    
    def evaluate(self, context: AuthContext) -> AuthResult:
        start = time.perf_counter()
        
        if not context.principal or not context.tool_operation:
            return AuthResult(
                decision=AuthDecision.DENY,
                principal_id=context.principal.id if context.principal else "anonymous",
                tool_name=context.tool_operation.tool_name if context.tool_operation else "unknown",
                operation=context.tool_operation.operation if context.tool_operation else "unknown",
                reason="Missing principal or tool operation",
                required_scopes=set(),
                principal_scopes=set(),
                missing_scopes=set(),
                risk_level="critical",
                requires_human_approval=False,
                latency_ms=(time.perf_counter() - start) * 1000
            )
        
        # Enforce least privilege - operation should not require more than max scopes
        required = context.tool_operation.required_scopes
        if len(required) > self.max_scopes_per_operation:
            return AuthResult(
                decision=AuthDecision.DENY,
                principal_id=context.principal.id,
                tool_name=context.tool_operation.tool_name,
                operation=context.tool_operation.operation,
                reason=f"Operation requires too many scopes ({len(required)} > {self.max_scopes_per_operation})",
                required_scopes=required,
                principal_scopes=context.principal.scopes,
                missing_scopes=required,
                risk_level="high",
                requires_human_approval=True,
                latency_ms=(time.perf_counter() - start) * 1000
            )
        
        # Check scopes
        missing = required - context.principal.scopes
        if missing:
            return AuthResult(
                decision=AuthDecision.DENY,
                principal_id=context.principal.id,
                tool_name=context.tool_operation.tool_name,
                operation=context.tool_operation.operation,
                reason=f"Missing scopes: {', '.join(missing)}",
                required_scopes=required,
                principal_scopes=context.principal.scopes,
                missing_scopes=missing,
                risk_level=context.tool_operation.risk_level,
                requires_human_approval=False,
                latency_ms=(time.perf_counter() - start) * 1000
            )
        
        return AuthResult(
            decision=AuthDecision.ALLOW,
            principal_id=context.principal.id,
            tool_name=context.tool_operation.tool_name,
            operation=context.tool_operation.operation,
            reason="Least-privilege check passed",
            required_scopes=required,
            principal_scopes=context.principal.scopes,
            missing_scopes=set(),
            risk_level=context.tool_operation.risk_level,
            requires_human_approval=False,
            latency_ms=(time.perf_counter() - start) * 1000
        )


class MCPAuthorizationPolicy(AuthorizationPolicy):
    """MCP-specific authorization following MCP specification."""
    
    def __init__(self, allowed_origins: List[str] = None):
        self.allowed_origins = allowed_origins or ["localhost"]
    
    def evaluate(self, context: AuthContext) -> AuthResult:
        start = time.perf_counter()
        
        # Check for MCP-specific context
        mcp_context = context.metadata.get("mcp", {})
        
        if not mcp_context:
            # Not an MCP request, pass through
            return AuthResult(
                decision=AuthDecision.ALLOW,
                principal_id=context.principal.id if context.principal else "anonymous",
                tool_name="mcp_passthrough",
                operation="passthrough",
                reason="Non-MCP request",
                required_scopes=set(),
                principal_scopes=context.principal.scopes if context.principal else set(),
                missing_scopes=set(),
                risk_level="low",
                requires_human_approval=False,
                latency_ms=(time.perf_counter() - start) * 1000
            )
        
        # Validate origin
        origin = mcp_context.get("origin", "")
        if origin and origin not in self.allowed_origins:
            return AuthResult(
                decision=AuthDecision.DENY,
                principal_id=context.principal.id if context.principal else "anonymous",
                tool_name="mcp",
                operation=mcp_context.get("method", "unknown"),
                reason=f"Origin not allowed: {origin}",
                required_scopes={"mcp:access"},
                principal_scopes=context.principal.scopes if context.principal else set(),
                missing_scopes={"mcp:access"},
                risk_level="high",
                requires_human_approval=False,
                latency_ms=(time.perf_counter() - start) * 1000
            )
        
        # Validate token audience for MCP
        token_audience = mcp_context.get("token_audience")
        expected_audience = "omniguard-mcp"
        if token_audience and token_audience != expected_audience:
            return AuthResult(
                decision=AuthDecision.DENY,
                principal_id=context.principal.id if context.principal else "anonymous",
                tool_name="mcp",
                operation=mcp_context.get("method", "unknown"),
                reason=f"Invalid token audience: {token_audience}",
                required_scopes={"mcp:access"},
                principal_scopes=context.principal.scopes if context.principal else set(),
                missing_scopes={"mcp:access"},
                risk_level="high",
                requires_human_approval=False,
                latency_ms=(time.perf_counter() - start) * 1000
            )
        
        # Check scopes for MCP method
        method = mcp_context.get("method", "")
        required_scopes = self._get_required_scopes_for_method(method)
        principal_scopes = context.principal.scopes if context.principal else set()
        missing = required_scopes - principal_scopes
        
        if missing:
            return AuthResult(
                decision=AuthDecision.DENY,
                principal_id=context.principal.id if context.principal else "anonymous",
                tool_name="mcp",
                operation=method,
                reason=f"MCP method requires scopes: {', '.join(missing)}",
                required_scopes=required_scopes,
                principal_scopes=principal_scopes,
                missing_scopes=missing,
                risk_level="medium",
                requires_human_approval=False,
                latency_ms=(time.perf_counter() - start) * 1000
            )
        
        return AuthResult(
            decision=AuthDecision.ALLOW,
            principal_id=context.principal.id,
            tool_name="mcp",
            operation=method,
            reason="MCP authorization successful",
            required_scopes=required_scopes,
            principal_scopes=principal_scopes,
            missing_scopes=set(),
            risk_level="low",
            requires_human_approval=False,
            latency_ms=(time.perf_counter() - start) * 1000
        )
    
    def _get_required_scopes_for_method(self, method: str) -> Set[str]:
        """Map MCP methods to required scopes."""
        scope_map = {
            "tools/list": {"mcp:tools:read"},
            "tools/call": {"mcp:tools:execute"},
            "resources/list": {"mcp:resources:read"},
            "resources/read": {"mcp:resources:read"},
            "prompts/list": {"mcp:prompts:read"},
            "prompts/get": {"mcp:prompts:read"},
        }
        return scope_map.get(method, {"mcp:access"})


class AuthorizationEngine:
    """Main authorization engine coordinating policies."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.token_validators: List[TokenValidator] = []
        self.policies: List[AuthorizationPolicy] = []
        
        # Initialize default policies
        self._init_default_policies()
    
    def _init_default_policies(self):
        """Initialize default authorization policies."""
        # Deny-by-default with some allow rules
        self.policies.append(DenyByDefaultPolicy(
            allow_rules=self.config.get("allow_rules", [])
        ))
        
        # Least privilege
        self.policies.append(LeastPrivilegePolicy(
            max_scopes_per_operation=self.config.get("max_scopes_per_operation", 3)
        ))
        
        # MCP authorization
        self.policies.append(MCPAuthorizationPolicy(
            allowed_origins=self.config.get("mcp_allowed_origins", ["localhost"])
        ))
    
    def add_token_validator(self, validator: TokenValidator):
        """Add a token validator."""
        self.token_validators.append(validator)
    
    def add_policy(self, policy: AuthorizationPolicy):
        """Add an authorization policy."""
        self.policies.append(policy)
    
    def authenticate(self, token: str, audience: str = "omniguard", issuer: str = "omniguard") -> Optional[Principal]:
        """Authenticate a token using registered validators."""
        for validator in self.token_validators:
            principal = validator.validate(token, audience, issuer)
            if principal:
                return principal
        return None
    
    def authorize(self, context: AuthContext) -> AuthResult:
        """Run authorization through all policies."""
        # All policies must allow (deny-by-default)
        for policy in self.policies:
            result = policy.evaluate(context)
            if result.decision != AuthDecision.ALLOW:
                return result
        
        # All policies passed
        return AuthResult(
            decision=AuthDecision.ALLOW,
            principal_id=context.principal.id if context.principal else "anonymous",
            tool_name=context.tool_operation.tool_name if context.tool_operation else "none",
            operation=context.tool_operation.operation if context.tool_operation else "none",
            reason="All authorization policies passed",
            required_scopes=context.tool_operation.required_scopes if context.tool_operation else set(),
            principal_scopes=context.principal.scopes if context.principal else set(),
            missing_scopes=set(),
            risk_level=context.tool_operation.risk_level if context.tool_operation else "low",
            requires_human_approval=False,
            latency_ms=0  # Will be set by caller
        )
    
    def authorize_tool_call(self, principal: Principal, tool_name: str, operation: str, 
                           params: Dict[str, Any], required_scopes: Set[str],
                           risk_level: str = "medium", requires_human_approval: bool = False) -> AuthResult:
        """Convenience method to authorize a tool call."""
        tool_op = ToolOperation(
            tool_name=tool_name,
            operation=operation,
            params=params,
            required_scopes=required_scopes,
            risk_level=risk_level,
            requires_human_approval=requires_human_approval
        )
        
        context = AuthContext(
            principal=principal,
            tool_operation=tool_op,
            request_id=hashlib.sha256(f"{principal.id}{tool_name}{operation}{time.time()}".encode()).hexdigest()[:16]
        )
        
        start = time.perf_counter()
        result = self.authorize(context)
        result.latency_ms = (time.perf_counter() - start) * 1000
        return result


# Tool registry with built-in authorization
class ToolRegistry:
    """Registry of available tools with authorization metadata."""
    
    def __init__(self):
        self.tools: Dict[str, Dict[str, Any]] = {}
    
    def register_tool(self, name: str, operations: Dict[str, Dict[str, Any]]):
        """Register a tool with its operations and required scopes."""
        self.tools[name] = {
            "operations": operations,
            "registered_at": time.time()
        }
    
    def get_operation(self, tool_name: str, operation: str) -> Optional[Dict[str, Any]]:
        """Get operation metadata including required scopes."""
        if tool_name not in self.tools:
            return None
        return self.tools[tool_name]["operations"].get(operation)
    
    def list_tools(self) -> Dict[str, List[str]]:
        """List all tools and their operations."""
        return {name: list(info["operations"].keys()) for name, info in self.tools.items()}


# Default tool registry with common tools
DEFAULT_TOOL_REGISTRY = ToolRegistry()
DEFAULT_TOOL_REGISTRY.register_tool("email", {
    "send": {
        "required_scopes": {"email:send"},
        "risk_level": "medium",
        "description": "Send email"
    },
    "read": {
        "required_scopes": {"email:read"},
        "risk_level": "low",
        "description": "Read emails"
    }
})
DEFAULT_TOOL_REGISTRY.register_tool("database", {
    "query": {
        "required_scopes": {"db:query"},
        "risk_level": "high",
        "description": "Execute read query"
    },
    "execute": {
        "required_scopes": {"db:execute"},
        "risk_level": "critical",
        "requires_human_approval": True,
        "description": "Execute write/mutation"
    },
    "admin": {
        "required_scopes": {"db:admin"},
        "risk_level": "critical",
        "requires_human_approval": True,
        "description": "Administrative operations"
    }
})
DEFAULT_TOOL_REGISTRY.register_tool("payment", {
    "transfer": {
        "required_scopes": {"payment:transfer"},
        "risk_level": "critical",
        "requires_human_approval": True,
        "description": "Transfer funds"
    },
    "refund": {
        "required_scopes": {"payment:refund"},
        "risk_level": "critical",
        "requires_human_approval": True,
        "description": "Process refund"
    }
})
DEFAULT_TOOL_REGISTRY.register_tool("shell", {
    "execute": {
        "required_scopes": {"shell:execute"},
        "risk_level": "critical",
        "requires_human_approval": True,
        "description": "Execute shell command"
    }
})
DEFAULT_TOOL_REGISTRY.register_tool("api", {
    "invoke": {
        "required_scopes": {"api:invoke"},
        "risk_level": "high",
        "description": "Invoke external API"
    }
})


# Example usage
if __name__ == "__main__":
    # Setup authorization engine
    engine = AuthorizationEngine({
        "allow_rules": [
            {"principal_id": "admin", "tool_name": "*", "operation": "*"},
        ],
        "max_scopes_per_operation": 3,
        "mcp_allowed_origins": ["localhost", "https://trusted.example.com"]
    })
    
    # Add API key validator
    engine.add_token_validator(APIKeyValidator({
        "sk-admin-123": {"id": "admin", "type": "user", "tenant_id": "acme", "scopes": ["*"]},
        "sk-agent-456": {"id": "agent-1", "type": "agent", "tenant_id": "acme", "scopes": ["email:send", "db:query"]},
        "sk-service-789": {"id": "service-1", "type": "service", "tenant_id": "acme", "scopes": ["payment:transfer", "api:invoke"]},
    }))
    
    # Test authentication
    print("=== Authentication Tests ===")
    for key in ["sk-admin-123", "sk-agent-456", "sk-invalid"]:
        principal = engine.authenticate(key)
        print(f"  {key}: {'OK' if principal else 'FAILED'} - {principal.id if principal else 'None'}")
    
    # Test tool authorization
    print("\n=== Tool Authorization Tests ===")
    admin = engine.authenticate("sk-admin-123")
    agent = engine.authenticate("sk-agent-456")
    
    test_cases = [
        (admin, "email", "send", {}, {"email:send"}, "medium"),
        (agent, "email", "send", {}, {"email:send"}, "medium"),
        (agent, "database", "execute", {}, {"db:execute"}, "critical"),
        (agent, "payment", "transfer", {"amount": 1000}, {"payment:transfer"}, "critical"),
        (agent, "shell", "execute", {"cmd": "ls"}, {"shell:execute"}, "critical"),
    ]
    
    for principal, tool, op, params, scopes, risk in test_cases:
        result = engine.authorize_tool_call(principal, tool, op, params, scopes, risk)
        status = "✅" if result.decision == AuthDecision.ALLOW else "🔴" if result.decision == AuthDecision.DENY else "⚠️"
        print(f"  {status} {principal.id} -> {tool}.{op}: {result.decision.value} ({result.reason}) [{result.latency_ms:.2f}ms]")
    
    # Test MCP authorization
    print("\n=== MCP Authorization Tests ===")
    mcp_context = AuthContext(
        principal=agent,
        tool_operation=None,
        metadata={
            "mcp": {
                "origin": "localhost",
                "method": "tools/call",
                "token_audience": "omniguard-mcp"
            }
        }
    )
    
    # This would need MCP policy to be evaluated
    mcp_policy = MCPAuthorizationPolicy(["localhost"])
    mcp_result = mcp_policy.evaluate(mcp_context)
    print(f"  MCP tools/call from localhost: {mcp_result.decision.value} ({mcp_result.reason})")
    
    # Test with invalid origin
    mcp_context2 = AuthContext(
        principal=agent,
        tool_operation=None,
        metadata={
            "mcp": {
                "origin": "evil.com",
                "method": "tools/call",
                "token_audience": "omniguard-mcp"
            }
        }
    )
    mcp_result2 = mcp_policy.evaluate(mcp_context2)
    print(f"  MCP tools/call from evil.com: {mcp_result2.decision.value} ({mcp_result2.reason})")