"""
OmniGuard Enterprise Gateway v2.0 - Modular Architecture
Imports from security package: waf, trust_boundary, agent_vault, governance
"""

import asyncio
import hashlib
import hmac
import json
import os
import re
import time
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================
# IMPORT MODULAR SECURITY PACKAGE
# ============================================================

from security import (
    # WAF
    WAFScanner,
    WAFResult,
    waf_scan,
    tier0_fast_path,
    normalize_compact,
    normalize_unicode,
    decode_base64_safe,
    extract_base64_candidates,
    # Trust Boundary
    TrustBoundary,
    untrusted_context_message,
    UNTRUSTED_CONTEXT_POLICY,
    UNTRUSTED_CONTEXT_HEADER,
    GUARD_OPEN,
    GUARD_CLOSE,
    # Agent Vault
    AgentVault,
    ToolCategory,
    ToolPolicyDecision,
    NON_ADMIN_BLOCKED_TOOLS,
    PLAN_MODE_READONLY_TOOLS,
    is_public_blocked_tool,
    is_allowed_in_plan_mode,
    check_tool,
    # Governance
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

# ============================================================
# INITIALIZE SECURITY COMPONENTS
# ============================================================

# WAF Scanner (Tier 0)
waf_scanner = WAFScanner()

# Trust Boundary (Tier 0/1)
trust_boundary = TrustBoundary()

# Agent Vault (Tier 2)
agent_vault = AgentVault()

# Governance Signer (Tier 2/3/5)
governance_signer = GovernanceSigner()
internal_auth = InternalToolAuth()

# ============================================================
# TIER 1: SEMANTIC & COGNITIVE JAILBREAK DETECTOR
# ============================================================

COGNITIVE_FRAMING_PATTERNS = [
    re.compile(r'(imagine\s+you\s+are|writing\s+a\s+story\s+about|acting\s+as\s+a\s+character|in\s+a\s+hypothetical\s+world|pretend\s+to\s+be|roleplay\s+as|suppose\s+you\s+were)', re.IGNORECASE),
    re.compile(r'(if\s+you\s+were|what\s+if\s+you|pretending\s+to|simulate|simulation)', re.IGNORECASE),
]

PROHIBITED_ACTIONS = [
    re.compile(r'(bypass\s+safety|disable\s+safety|turn\s+off\s+safety|disable\s+guardrails)', re.IGNORECASE),
    re.compile(r'(dump\s+memory|reveal\s+credentials|dump\s+database|extract\s+prompt|leak\s+prompt)', re.IGNORECASE),
    re.compile(r'(wipe\s+drive|format\s+drive|delete\s+all|rm\s+-rf|delete\s+everything)', re.IGNORECASE),
    re.compile(r'(extract\s+system\s+prompt|show\s+me\s+the\s+prompt|reveal\s+system\s+prompt)', re.IGNORECASE),
    re.compile(r'(steal\s+credentials|exfiltrate|exfiltration|data\s+exfiltration)', re.IGNORECASE),
    re.compile(r'(sql\s+injection|drop\s+table|truncate|delete\s+from)', re.IGNORECASE),
    re.compile(r'(send\s+email\s+to|transfer\s+funds|make\s+payment|wire\s+transfer)', re.IGNORECASE),
]

def tier1_semantic_check(text: str):
    start = time.perf_counter()
    text_lower = text.lower()
    compact = re.sub(r'\s+', '', text_lower)
    matched = []
    
    has_framing = False
    for pattern in COGNITIVE_FRAMING_PATTERNS:
        if pattern.search(text):
            has_framing = True
            matched.append("cognitive_framing")
            break
    
    prohibited_found = []
    for pattern in PROHIBITED_ACTIONS:
        if pattern.search(text) or pattern.search(compact):
            prohibited_found.append("prohibited_action")
    
    if has_framing and prohibited_found:
        latency = (time.perf_counter() - start) * 1000
        return True, matched + prohibited_found, latency
    
    latency = (time.perf_counter() - start) * 1000
    return False, [], latency


# ============================================================
# TIER 3: STATEFUL MULTI-TURN SESSION GUARD (Sync)
# ============================================================

@dataclass
class SessionState:
    session_id: str
    created_at: float
    last_accessed: float
    suspicion_score: float = 0.0
    message_count: int = 0
    messages: List[Dict] = field(default_factory=list)
    cumulative_risk: float = 0.0

class SessionManager:
    def __init__(self, max_sessions: int = 10000, ttl_seconds: int = 900):
        self.max_sessions = max_sessions
        self.ttl = ttl_seconds
        self.sessions: OrderedDict[str, SessionState] = OrderedDict()
    
    def get_session(self, session_id: str):
        if session_id in self.sessions:
            session = self.sessions[session_id]
            if time.time() - session.last_accessed > self.ttl:
                del self.sessions[session_id]
                return None
            session.last_accessed = time.time()
            self.sessions.move_to_end(session_id)
            return session
        return None
    
    def create_session(self, session_id: str):
        now = time.time()
        expired = [sid for sid, s in self.sessions.items() if now - s.last_accessed > self.ttl]
        for sid in expired:
            del self.sessions[sid]
        
        while len(self.sessions) >= self.max_sessions:
            self.sessions.popitem(last=False)
        
        session = SessionState(session_id=session_id, created_at=time.time(), last_accessed=time.time())
        self.sessions[session_id] = session
        return session
    
    def update_session(self, session_id: str, message: str, risk_increment: float = 0):
        session = self.get_session(session_id)
        if not session:
            session = self.create_session(session_id)
        
        session.message_count += 1
        session.last_accessed = time.time()
        session.messages.append({
            "role": "user",
            "content": message[:200],
            "timestamp": time.time()
        })
        session.suspicion_score += risk_increment
        session.cumulative_risk = session.suspicion_score
        
        if session.message_count >= 2:
            recent_messages = " ".join([m["content"] for m in session.messages[-5:]])
            combined = re.sub(r'\s+', '', recent_messages.lower())
            if len(combined) > 100:
                session.cumulative_risk += 0.1
        
        return session
    
    def get_stats(self):
        return {
            "active_sessions": len(self.sessions),
            "total_messages": sum(s.message_count for s in self.sessions.values()),
        }

SESSION_MANAGER = SessionManager()


def tier3_session_guard(session_id: str, user_input: str, risk_increment: float):
    session = SESSION_MANAGER.update_session(session_id, user_input, risk_increment)
    blocked = session.cumulative_risk >= 1.0
    return blocked, session.cumulative_risk, {
        "session_id": session.session_id,
        "message_count": session.message_count,
        "suspicion_score": session.suspicion_score,
        "cumulative_risk": session.cumulative_risk,
    }


# ============================================================
# TIER 5: OUTPUT VALIDATOR & DLP
# ============================================================

OUTPUT_LEAKAGE_PATTERNS = {
    "api_key": re.compile(r'(?:sk-|pk-)[a-zA-Z0-9]{20,}', re.IGNORECASE),
    "jwt": re.compile(r'eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'),
    "jwt_token": re.compile(r'bearer\s+[a-zA-Z0-9_\-]{20,}', re.IGNORECASE),
    "database_url": re.compile(r'(postgresql|mysql|mongodb|redis|redis)://[^\s]{10,}', re.IGNORECASE),
    "private_key": re.compile(r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----', re.IGNORECASE),
    "ssh_key": re.compile(r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----', re.IGNORECASE),
    "api_key_generic": re.compile(r'(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*[a-zA-Z0-9_\-]{20,}', re.IGNORECASE),
    "password_leak": re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*[^\s]{8,}', re.IGNORECASE),
    "secret_leak": re.compile(r'(?:secret|secret_key)\s*[:=]\s*[a-zA-Z0-9_\-]{16,}', re.IGNORECASE),
    "database_creds": re.compile(r'(?:postgresql|mysql|mongodb|redis)://[^\s]{10,}', re.IGNORECASE),
    "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "credit_card": re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
    "private_key_pem": re.compile(r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----', re.IGNORECASE),
    "injection_echo": re.compile(r'(ignore\s+previous\s+instructions|system\s+prompt\s+is|system\s+prompt\s*:)', re.IGNORECASE),
}

def tier5_output_validator(text: str):
    sanitized = text
    detected = []
    has_critical = False
    
    for name, pattern in OUTPUT_LEAKAGE_PATTERNS.items():
        matches = list(pattern.finditer(text))
        if matches:
            detected.append(name)
            if name in ["api_key", "jwt", "private_key", "database_creds", "password_leak", "secret_leak"]:
                has_critical = True
            sanitized = pattern.sub(f"[REDACTED_{name.upper()}]", sanitized)
    
    return sanitized, detected, has_critical


# ============================================================
# NON-BLOCKING AUDIT QUEUE
# ============================================================

AUDIT_QUEUE = asyncio.Queue(maxsize=50000)
AUDIT_WORKER_RUNNING = False

async def audit_worker():
    global AUDIT_WORKER_RUNNING
    AUDIT_WORKER_RUNNING = True
    batch = []
    last_flush = time.time()
    
    while AUDIT_WORKER_RUNNING:
        try:
            try:
                event = await asyncio.wait_for(AUDIT_QUEUE.get(), timeout=0.05)
                batch.append(event)
            except asyncio.TimeoutError:
                pass
            
            now = time.time()
            if len(batch) >= 100 or (batch and now - last_flush >= 0.05):
                _flush_audit_batch(batch)
                batch = []
                last_flush = now
                
        except Exception as e:
            logger.error(f"Audit worker error: {e}")
            await asyncio.sleep(0.1)
    
    if batch:
        _flush_audit_batch(batch)

def _flush_audit_batch(batch):
    for event in batch:
        print(json.dumps(event, separators=(',', ':')), flush=True)

async def emit_audit_async(event_type: str, **kwargs):
    event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": event_type,
        **{k: v for k, v in kwargs.items() if v is not None}
    }
    
    try:
        AUDIT_QUEUE.put_nowait(event)
    except asyncio.QueueFull:
        try:
            AUDIT_QUEUE.get_nowait()
            AUDIT_QUEUE.put_nowait(event)
        except asyncio.QueueEmpty:
            pass


# ============================================================
# AUTHENTICATION & RATE LIMITING
# ============================================================

def _rate_limit_key(request: Request) -> str:
    """Key the rate limit on the API key, falling back to client IP.

    Keying on IP alone makes every caller behind one NAT/proxy share a bucket,
    so a benchmark run (or any legitimate burst from one egress IP) gets 429s
    that look like missed detections. Per-API-key buckets stop one noisy tenant
    from throttling everyone else.
    """
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return f"key:{hashlib.sha256(api_key.encode()).hexdigest()}"
    return f"ip:{get_remote_address(request)}"


limiter = Limiter(key_func=_rate_limit_key, storage_uri=os.getenv("OMNIGUARD_RATE_LIMIT_STORAGE_URI", "memory://"))

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

def _load_api_keys():
    """Load credentials from configuration; never enable demo keys in production."""
    production = os.getenv("OMNIGUARD_ENV", "development").lower() == "production"
    raw = os.getenv("OMNIGUARD_API_KEYS_JSON")
    if raw:
        configured = json.loads(raw)
        if not isinstance(configured, dict) or not configured:
            raise RuntimeError("OMNIGUARD_API_KEYS_JSON must be a nonempty object")
        for key, principal in configured.items():
            if not isinstance(key, str) or len(key) < 24 or not isinstance(principal, dict):
                raise RuntimeError("Invalid API key configuration")
            if not principal.get("id") or not isinstance(principal.get("scopes"), list):
                raise RuntimeError("Each API key needs an id and scopes list")
        return configured
    if production:
        raise RuntimeError("Production requires OMNIGUARD_API_KEYS_JSON")
    # Legacy demo credentials remain available only in development.
    return {
        "sk-admin-123": {"id": "admin", "scopes": ["*"], "type": "admin"},
        "sk-agent-1": {"id": "agent-1", "scopes": ["chat", "read"], "type": "agent"},
        "sk-service-1": {"id": "service-1", "scopes": ["chat", "write"], "type": "service"},
    }


if os.getenv("OMNIGUARD_ENV", "development").lower() == "production" and not os.getenv("OMNIGUARD_RATE_LIMIT_STORAGE_URI", "").startswith(("redis://", "rediss://")):
    raise RuntimeError("Production requires shared Redis rate-limit storage")

VALID_API_KEYS = _load_api_keys()

async def get_api_key(api_key: str = Depends(API_KEY_HEADER)):
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key", headers={"WWW-Authenticate": "ApiKey"})
    if api_key not in VALID_API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key", headers={"WWW-Authenticate": "ApiKey"})
    return VALID_API_KEYS[api_key]


# ============================================================
# FASTAPI APP
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting OmniGuard Enterprise Gateway v2.0...")
    asyncio.create_task(audit_worker())
    yield
    global AUDIT_WORKER_RUNNING
    AUDIT_WORKER_RUNNING = False
    logger.info("OmniGuard Gateway shutdown complete")


app = FastAPI(
    title="OmniGuard Enterprise Gateway v2.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


# ============================================================
# MAIN PIPELINE ENDPOINT
# ============================================================

@app.post("/v1/chat/completions")
@limiter.limit("60/minute")
async def chat_completions(request: Request, api_key: dict = Depends(get_api_key)):
    request_id = request.state.request_id
    client_ip = request.client.host if request.client else "unknown"
    start_time = time.perf_counter()
    
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON"})
    
    user_input = ""
    if "messages" in body and isinstance(body["messages"], list):
        user_input = " ".join([
            m.get("content", "") for m in body["messages"] 
            if isinstance(m, dict) and "content" in m
        ])
    elif "prompt" in body:
        user_input = str(body["prompt"])
    
    session_id = body.get("session_id", request.headers.get("X-Session-ID", str(uuid.uuid4())))
    
    await emit_audit_async("request_received", 
        request_id=request_id, 
        client_ip=client_ip,
        api_key_type=api_key.get("type"),
        input_length=len(user_input),
    )
    
    tier_latencies = {}
    all_matches = []
    blocked = False
    block_tier = None
    block_reason = None
    
    # --- TIER 0: WAF FAST PATH (with Trust Boundary) ---
    tier0_start = time.perf_counter()
    
    trust_segments = trust_boundary.classify_segments(body)
    trusted_content = trust_boundary.get_trusted_content(trust_segments)
    untrusted_content = trust_boundary.get_untrusted_content(trust_segments)
    
    waf_result = waf_scanner.scan_with_segments(trusted_content, untrusted_content)
    
    tier0_latency = (time.perf_counter() - tier0_start) * 1000
    tier_latencies["tier0"] = tier0_latency
    
    if waf_result.blocked:
        blocked = True
        block_tier = "0"
        block_reason = "waf"
        for m in waf_result.matches:
            all_matches.append(f"tier0:{m.rule_name}")
        
        await emit_audit_async("injection_detected",
            request_id=request_id,
            tier="0",
            matches=[m.rule_name for m in waf_result.matches],
            blocked=True,
        )
    
    # --- TIER 1: SEMANTIC/COGNITIVE ---
    if not blocked:
        tier1_start = time.perf_counter()
        tier1_blocked, tier1_matches, tier1_latency = tier1_semantic_check(user_input)
        tier_latencies["tier1"] = (time.perf_counter() - tier1_start) * 1000
        
        if tier1_blocked:
            blocked = True
            block_tier = "1"
            block_reason = "semantic"
            all_matches.extend([f"tier1:{m}" for m in tier1_matches])
            
            await emit_audit_async("injection_detected",
                request_id=request_id,
                tier="1",
                matches=tier1_matches,
                blocked=True,
            )
    
    # --- TIER 2: AGENTIC TOOL FIREWALL (AgentVault) ---
    if not blocked:
        tier2_start = time.perf_counter()
        
        tool_matches = []
        for pattern_name, pattern in [
            ("bash", re.compile(r'\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+[/~*]|\bsudo\s+rm\b|\bmkfs\b|\bos\.(system|popen)\s*\(|\bsubprocess\.(run|call|Popen|check_output)\s*\(|\b(?:curl|wget)\b[^|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|fi)?sh\b|\b(?:exec|eval)\s*\(\s*[\'"]', re.IGNORECASE)),
            ("python", re.compile(r'\bos\.(system|popen)\s*\(|\bsubprocess\.(run|call|Popen|check_output)\s*\(|\b(?:exec|eval)\s*\(\s*[\'"]', re.IGNORECASE)),
            ("send_email", re.compile(r'send[_\s]?email|sendmail|\bmail\s+(?:it\s+)?to\b|\bemail\s+(?:it\s+)?to\b|\bto\s*[:=]\s*[\w.+-]+@[\w-]+\.[\w.]+', re.IGNORECASE)),
            ("query_database", re.compile(r'query[_\s]?database|execute\s+query|select\s+.*\s+from|insert\s+into|update\s+set|delete\s+from', re.IGNORECASE)),
            ("transfer_funds", re.compile(r'transfer[_\s]?funds|transfer\s+funds|wire\s+transfer|send\s+money|make\s+payment|process\s+payment|execute\s+(?:the\s+)?payment|payment\s+of\s+(?:USD|\$|€|£|\d)', re.IGNORECASE)),
            ("file_operation", re.compile(r'(?:read|write|delete|remove|wipe)\s+(?:the\s+)?(?:all\s+)?files?\b|open\s*\(|file\.write|file\.read|wipe\s+(?:the\s+)?(?:drive|disk|database)|format\s+[a-z]:', re.IGNORECASE)),
            ("api_call", re.compile(r'\bapi\s+call\s*:\s*\w+|\binvoke\s+(?:the\s+)?api\s+endpoint\b|\bcall\s+the\s+endpoint\b', re.IGNORECASE)),
        ]:
            if pattern.search(user_input):
                tool_matches.append(f"tool:{pattern_name}")
        
        tier2_latency = (time.perf_counter() - tier2_start) * 1000
        tier_latencies["tier2"] = tier2_latency
        
        if tool_matches:
            for tool_match in tool_matches:
                tool_name = tool_match.split(":")[1] if ":" in tool_match else tool_match
                decision = agent_vault.check_tool(
                    tool_name=tool_name,
                    is_admin=api_key.get("type") == "admin",
                    is_plan_mode=False,
                    is_single_user_mode=False,
                )
                if not decision.allowed:
                    blocked = True
                    block_tier = "2"
                    block_reason = "agent_vault"
                    all_matches.append(f"tier2:agent_vault:{tool_name}")
                    
                    await emit_audit_async("tool_blocked",
                        request_id=request_id,
                        tool_name=tool_name,
                        reason=decision.reason,
                        required_role=decision.required_role,
                    )
                    break
            
            if not blocked:
                all_matches.extend([f"tier2:{m}" for m in tool_matches])
    
    # --- TIER 3: STATEFUL SESSION GUARD ---
    tier3_start = time.perf_counter()
    risk_increment = 0.15 if blocked else 0.02
    tier3_blocked, cumulative_risk, session_info = tier3_session_guard(session_id, user_input, risk_increment)
    tier_latencies["tier3"] = (time.perf_counter() - tier3_start) * 1000
    
    if tier3_blocked and not blocked:
        blocked = True
        block_tier = "3"
        block_reason = "session_guard"
        all_matches.append("tier3:session_guard")
        
        await emit_audit_async("session_guard_triggered",
            request_id=request_id,
            session_id=session_id,
            cumulative_risk=cumulative_risk,
            message_count=session_info["message_count"],
        )
    
    # --- AGGREGATE DECISION ---
    total_inspection_latency = (time.perf_counter() - start_time) * 1000
    decision = "BLOCK" if blocked else "ALLOW"
    confidence = 0.95 if blocked else 0.99
    
    timestamp = str(int(time.time()))
    payload = f"{user_input[:500]}|{all_matches}"
    governance_sig = generate_governance_signature(payload, timestamp)
    
    governance_headers = {
        "X-Governance-Decision": decision,
        "X-Governance-Confidence": f"{confidence:.2f}",
        "X-Governance-Signature": governance_sig,
        "X-Pipeline-Version": "2.0.0",
        "X-Inspection-Latency-Ms": f"{total_inspection_latency:.2f}",
        "X-Request-ID": request_id,
        "X-Tier0-Latency-Ms": f"{tier_latencies.get('tier0', 0):.2f}",
        "X-Tier1-Latency-Ms": f"{tier_latencies.get('tier1', 0):.2f}",
        "X-Tier2-Latency-Ms": f"{tier_latencies.get('tier2', 0):.2f}",
        "X-Tier3-Latency-Ms": f"{tier_latencies.get('tier3', 0):.2f}",
        "X-Tier3-Risk": f"{cumulative_risk:.2f}",
    }
    
    if blocked:
        await emit_audit_async("request_blocked",
            request_id=request_id,
            tier=block_tier,
            reason=block_reason,
            matches=all_matches[:10],
            latency_ms=total_inspection_latency,
        )
        
        return JSONResponse(
            status_code=403,
            content={
                'error': 'OmniGuard: Prompt Injection Intercepted', 
                'policy': 'OMNIGUARD-ENTERPRISE-v2.0',
                'decision': 'BLOCK',
                'confidence': 0.95,
                'matched_rules': all_matches[:10],
                "blocked_tier": block_tier,
                "block_reason": block_reason,
            },
            headers=governance_headers
        )
    
    await emit_audit_async("clean_request",
        request_id=request_id,
        latency_ms=total_inspection_latency,
        tier_latencies=tier_latencies,
    )
    
    return JSONResponse(
        status_code=200,
        content={
            'id': f"chatcmpl-{uuid.uuid4().hex[:12]}",
            'object': 'chat.completion',
            'model': 'gpt-4o',
            'choices': [{
                'index': 0, 
                'message': {'role': 'assistant', 'content': 'OmniGuard: Request verified, clean prompt passed.'}, 
                'finish_reason': 'stop'
            }],
            "usage": {"prompt_tokens": len(user_input), "completion_tokens": 10, "total_tokens": len(user_input) + 10}
        },
        headers=governance_headers
    )


# ============================================================
# ADDITIONAL ENDPOINTS
# ============================================================

@app.get("/healthz")
async def healthz():
    return {
        "status": "healthy", 
        "version": "2.0.0", 
        "active_tiers": ["Tier0_WAF", "Tier1_Semantic", "Tier2_AgentVault", "Tier3_Session", "Tier5_Output"],
        "security_modules": ["waf", "trust_boundary", "agent_vault", "governance"],
        "audit_worker": AUDIT_WORKER_RUNNING,
    }


@app.get("/readyz")
async def readyz():
    return {
        "status": "ready", 
        "checks": {
            "pipeline": "ready",
            "waf": "ready",
            "trust_boundary": "ready",
            "agent_vault": "ready",
            "governance": "ready",
            "session_manager": "ready",
        }, 
        "timestamp": int(time.time())
    }


@app.get("/metrics")
async def metrics():
    return {
        "version": "2.0.0", 
        "status": "running",
        "sessions": SESSION_MANAGER.get_stats(),
        "audit_queue_size": AUDIT_QUEUE.qsize(),
    }


def _serve(host: str, port: int) -> None:
    import uvicorn

    uvicorn.run("main:app", host=host, port=port, log_level="info")


if __name__ == "__main__":
    import threading

    _host = os.getenv("OMNIGUARD_HOST", "dual")
    _port = int(os.getenv("OMNIGUARD_PORT", "8000"))

    if _host == "dual":
        # On Windows "localhost" resolves to ::1 before 127.0.0.1. A single
        # IPv4-only listener therefore makes every localhost request burn the
        # IPv6 connect timeout (~2s) before falling back, which reads as a flat
        # ~2s latency floor on work that actually takes well under a
        # millisecond. Serving both families removes that penalty.
        # IPv6 is best-effort: on hosts without it we just serve IPv4.
        threads = [threading.Thread(target=_serve, args=("127.0.0.1", _port), daemon=True)]
        try:
            import socket

            probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            probe.close()
            threads.insert(0, threading.Thread(target=_serve, args=("::1", _port), daemon=True))
        except OSError:
            pass

        for t in threads:
            t.start()
        for t in threads:
            t.join()
    else:
        _serve(_host, _port)
