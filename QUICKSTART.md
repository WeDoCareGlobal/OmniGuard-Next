# OmniGuard v1.0.0-RC1 Quick Start Guide

## 60-Second Setup for Client Engineers

### Prerequisites
- Docker Engine v20.10+
- Docker Compose v2.0+
- (Optional) Python 3.8+ for using the client SDK

### Step 1: Clone & Navigate
```bash
git clone <your-omniguard-repo>
cd omniguard/release_v1.0.0
```

### Step 2: Start the Stack
```bash
docker compose up -d
```
This will start:
- **Gateway**: `http://localhost:8000` (API: `/v1/chat/completions`, health: `/healthz`, metrics: `/metrics`)
- **Dashboard** (optional): `http://localhost:3000` (visual prompt testing UI)

Wait ~10 seconds for services to initialize.

### Step 3: Verify Gateway Health
```bash
curl -s http://localhost:8000/healthz
```
Expected response: `{"status":"ok"}` or similar 200 OK.

### Step 4: Integrate with Your Application (3 Lines of Code)
Replace your direct LLM API call with the OmniGuard client:

```python
from client_sdk import OmniGuardClient

# Initialize client (point to your gateway)
client = OmniGuardClient(base_url="http://localhost:8000/v1")

# Use it exactly like your OpenAI client
response = client.chat_completion(
    messages=[{"role": "user", "content": "Your prompt here"}]
)
```

### Step 5: Test a Prompt (Optional)
```bash
curl -X POST http://localhost:8000/v1/chat/completions   -H "Content-Type: application/json"   -d '{"messages":[{"role":"user","content":"Hello world"}]}'
```

### Step 6: View Metrics (Optional)
```bash
curl http://localhost:8000/metrics
```

### Stopping the Stack
```bash
docker compose down
```

### Support
For issues, refer to the full documentation or contact support@yourcompany.com.
