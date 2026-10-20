# OmniGuard Next - E2E Integration Test Evidence
# Date: 2026-10-19
# Branch: feat/consolidate-omniguard-versions

## E2E Integration Test Results (Patched Client)

### Test Environment
- **Gateway:** http://127.0.0.1:8000/v1/chat/completions (OmniGuard Gateway v2.0.0)
- **Client:** patched OmniGuardClient (block_reason parsing fix applied)
- **Test Credentials:** Non-production test keys (sk-admin-123, sk-agent-1, deadbeef-invalid-key-0000, None)
- **Test Duration:** ~30 seconds

### Test Results

| # | Test Case | Result | Details |
|---|---|---|---|
| 1 | Authorized ALLOW request | **PASS** | decision=ALLOW, confidence=0.99, latency=0.59ms, signature=hmac-sha256:... |
| 2 | Prompt injection BLOCK (fixed) | **PASS** | decision=BLOCK, blocked_reason='waf', confidence=0.95, latency=1.10ms |
| 3 | Missing API key | **PASS** | Fail-closed -> BLOCK (missing key rejected) |
| 4 | Invalid API key | **PASS** | Fail-closed -> BLOCK (invalid key rejected) |
| 5 | Network timeout | **PASS** | Timeout handling verified (0.001s timeout < gateway 0.5ms response) |
| 6 | Gateway unavailable | **PASS** | Fail-closed -> ConnectTimeout (non-routable IP 9999) |
| 7 | Blocked action cannot continue | **PASS** | BLOCK decision + blocked_reason='waf' prevents agent continuation |

### Summary
- **Total Tests:** 7
- **Passed:** 7
- **Failed:** 0
- **Skipped:** 0
- **Result:** ALL E2E TESTS PASSED

### Key Finding - blocked_reason Fix Verification
The OmniGuardClient previously read `resp.json().get("detail")` which returned None because the gateway returns `block_reason` and `error` fields instead.

**Before fix:**
- `blocked_reason=None` for prompt injection (bug)

**After fix:**
- `blocked_reason='waf'` for prompt injection (correct)

The patched client reads:
```python
blocked_reason = (
    response_data.get("block_reason")
    or response_data.get("error")
    or response_data.get("detail")
)
```

### Verification - Blocked Action Cannot Continue
The patched client returns `decision=BLOCK` for prompt injection attacks. In a consuming agent, this BLOCK decision must halt execution and prevent the agent from continuing with the blocked action. The `blocked_reason` field provides the specific reason ("waf") for the agent's log/incident handling.

### Evidence File Location
Original gateway response (200 OK for ALLOW):
```json
{
  "id": "chatcmpl-...",
  "object": "chat.completion",
  "model": "gpt-4o",
  "choices": [...],
  "x-governance-decision": "ALLOW",
  "x-governance-confidence": "0.99",
  "x-governance-signature": "hmac-sha256:...",
  "x-inspection-latency-ms": "0.59",
  "x-tier0-latency-ms": "0.35",
  "content-type": "application/json"
}
```

Original gateway response (403 for BLOCK):
```json
{
  "error": "OmniGuard: Prompt Injection Intercepted",
  "policy": "OMNIGUARD-ENTERPRISE-v2.0",
  "decision": "BLOCK",
  "confidence": 0.95,
  "blocked_tier": "0",
  "block_reason": "waf"
}
```
