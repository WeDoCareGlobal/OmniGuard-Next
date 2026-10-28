# OmniGuard Integration Guide

## Overview

OmniGuard v2.0.0-RC2 integrates as a security middleware layer in front of all WDCG systems:

```
Client → OmniGuard (port 8000) → FoundationCentar / AgentGuard / Hybrid-RAG / Pharma / AgentVault / AgentEval
```

## Integration Points

### 1. FoundationCentar-Next (MCP Gateway)

**File:** `foundation_next/mcp_gateway.py`

```python
from foundation_next.omniguard_client import get_omniguard_client

gateway = MCPGateway(enable_omniguard=True)
result = await gateway.execute(
    tool="search",
    capability="web",
    arguments={"query": "AI safety"},
    authorization="valid-token"
)
# OmniGuard inspects before local authorization
```

### 2. AgentGuard-Next (API Layer)

**File:** `agentguard/api.py`

```python
from agentguard.api import create_app

app = create_app(
    guard=guard,
    api_key="...",
    admin_key="...",
    enable_omniguard=True
)
# OmniGuard inspects every /v1/execute call
```

### 3. Other Systems (Hybrid-RAG, Pharma, AgentVault, AgentEval)

Add OmniGuard client to any service that makes tool calls or processes user prompts:

```python
from omniguard_client import get_omniguard_client

omniguard = get_omniguard_client()
result = await omniguard.inspect([
    {"role": "user", "content": user_prompt}
])
if result.decision == OmniGuardDecision.BLOCK:
    raise HTTPException(403, f"Blocked: {result.blocked_reason}")
```

## Deployment

### Docker Compose (Recommended)

```yaml
services:
  omniguard:
    build: ./omniguard/omniguard-gateway
    ports:
      - "8000:8000"
    environment:
      - REDIS_HOST=redis
      - REDIS_PORT=6379
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')"]
      interval: 30s
      timeout: 10s
      retries: 3

  foundation-centar:
    build: ./FoundationCentar-Next
    ports:
      - "8001:8000"
    environment:
      - OMNIGUARD_URL=http://omniguard:8000/v1
      - OMNIGUARD_API_KEY=sk-service-1
    depends_on:
      omniguard:
        condition: service_healthy

  agentguard:
    build: ./agentguard-next
    ports:
      - "8002:8000"
    environment:
      - OMNIGUARD_URL=http://omniguard:8000/v1
      - OMNIGUARD_API_KEY=sk-service-1
    depends_on:
      omniguard:
        condition: service_healthy
```

### Local Development

```bash
# Terminal 1: Start OmniGuard
cd omniguard/omniguard-gateway
python -m uvicorn main:app --host 0.0.0.0 --port 8000

# Terminal 2: Start FoundationCentar
cd FoundationCentar-Next
export OMNIGUARD_API_KEY=sk-service-1
python -m foundation_next.main

# Terminal 3: Start AgentGuard
cd agentguard-next
export OMNIGUARD_API_KEY=sk-service-1
uvicorn agentguard.api:create_app --factory --host 0.0.0.0 --port 8002
```

## Verified Benchmarks

- **Detection Rate**: 100% (25/25 adversarial vectors blocked)
- **False Positive Rate**: 0% (0/25 benign blocked)
- **P95 Latency**: 18.18ms (gateway inspection only, excludes LLM call)
- **P99 Latency**: 22.23ms

## Response Headers

Every OmniGuard response includes:

| Header | Description |
|--------|-------------|
| `X-Governance-Decision` | `ALLOW` or `BLOCK` |
| `X-Governance-Signature` | HMAC-SHA256 of decision |
| `X-Governance-Confidence` | Decision confidence (0-1) |
| `X-Inspection-Latency-Ms` | Total inspection time |
| `X-Tier0-Latency-Ms` ... `X-Tier3-Latency-Ms` | Per-tier latency |

## Fail-Open Design

If OmniGuard is unavailable:
- FoundationCentar: Proceeds with local authorization only
- AgentGuard: Proceeds with local Guard execution only
- Other systems: Should implement fail-open based on risk profile

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OMNIGUARD_API_KEY` | `sk-admin-123` | API key for OmniGuard gateway |
| `OMNIGUARD_URL` | `http://localhost:8000/v1` | OmniGuard gateway URL |

## Regulatory Compliance

OmniGuard provides technical controls for:
- **EU AI Act Article 50** — Transparency & governance signatures
- **EU AI Act Articles 26/27** — High-risk deployer logging & oversight
- **NIST AI RMF** — GOVERN, MAP, MEASURE, MANAGE functions
