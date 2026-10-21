"""Tenant isolation regression tests."""
from authorization import (
    AuthContext, AuthDecision, DenyByDefaultPolicy,
    Principal, PrincipalType, ToolOperation,
)


def _evaluate(principal_tenant, operation_tenant):
    principal = Principal(
        id="agent", type=PrincipalType.AGENT,
        tenant_id=principal_tenant, scopes={"tool:execute"},
    )
    operation = ToolOperation(
        tool_name="tool", operation="execute", params={},
        required_scopes={"tool:execute"}, tenant_id=operation_tenant,
    )
    return DenyByDefaultPolicy().evaluate(
        AuthContext(principal=principal, tool_operation=operation)
    ).decision


def test_matching_tenant_allowed():
    assert _evaluate("tenant-a", "tenant-a") == AuthDecision.ALLOW


def test_cross_tenant_denied():
    assert _evaluate("tenant-a", "tenant-b") == AuthDecision.DENY


def test_missing_tenant_denied():
    assert _evaluate("tenant-a", None) == AuthDecision.DENY
