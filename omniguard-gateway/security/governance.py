"""
OmniGuard Governance Module
Ported from Odysseus core/middleware.py
HMAC token generation for tamper-evident governance signatures.
"""

from __future__ import annotations
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any

# Odysseus INTERNAL_TOOL_TOKEN pattern - exact port
# Per-process token for in-app tool layer loopback calls
INTERNAL_TOOL_TOKEN = os.environ.get("ODYSSEUS_INTERNAL_TOKEN") or secrets.token_hex(32)
INTERNAL_TOOL_HEADER = "X-Odysseus-Internal-Token"
INTERNAL_TOOL_USER = "internal-tool"

# OmniGuard governance signature configuration
def _load_hmac_key() -> str:
    key = os.environ.get("OMNIGUARD_HMAC_KEY", "")
    if os.environ.get("OMNIGUARD_ENV", "development").lower() == "production":
        if len(key.encode()) < 32:
            raise RuntimeError("Production requires OMNIGUARD_HMAC_KEY of at least 32 bytes")
        if not os.environ.get("ODYSSEUS_INTERNAL_TOKEN"):
            raise RuntimeError("Production requires ODYSSEUS_INTERNAL_TOKEN")
    return key or "omniguard-development-only-signing-key"


OMNIGUARD_HMAC_KEY = _load_hmac_key()
OMNIGUARD_HMAC_KEY_BYTES = OMNIGUARD_HMAC_KEY.encode()


@dataclass
class GovernanceSignature:
    """Tamper-evident governance signature for request/response."""
    algorithm: str  # "hmac-sha256"
    signature: str
    timestamp: str
    payload_hash: str
    version: str = "2.0.0"


class GovernanceSigner:
    """Generates and verifies HMAC-SHA256 governance signatures.
    
    Ported from Odysseus middleware INTERNAL_TOOL_TOKEN pattern.
    Used for X-Governance-Signature headers to prove inspection integrity.
    """
    
    def __init__(self, hmac_key: Optional[bytes] = None):
        self.hmac_key = hmac_key if hmac_key is not None else OMNIGUARD_HMAC_KEY_BYTES
        previous = os.environ.get("OMNIGUARD_HMAC_PREVIOUS_KEYS", "")
        self.previous_keys = [key.encode() for key in previous.split(",") if key] if hmac_key is None else []
    
    def sign(self, payload: str, timestamp: Optional[str] = None) -> GovernanceSignature:
        """Generate a governance signature for payload."""
        if timestamp is None:
            timestamp = str(int(time.time()))
        
        # Create message: payload|timestamp
        message = f"{payload}|{timestamp}".encode()
        
        # HMAC-SHA256
        signature = hmac.new(
            self.hmac_key,
            message,
            hashlib.sha256
        ).hexdigest()
        
        # Also compute payload hash for integrity
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]
        
        return GovernanceSignature(
            algorithm="hmac-sha256",
            signature=signature,
            timestamp=timestamp,
            payload_hash=payload_hash,
        )
    
    def sign_bytes(self, payload: bytes, timestamp: Optional[str] = None) -> GovernanceSignature:
        """Generate signature for bytes payload."""
        if timestamp is None:
            timestamp = str(int(time.time()))
        
        message = payload + b"|" + timestamp.encode()
        signature = hmac.new(
            self.hmac_key,
            message,
            hashlib.sha256
        ).hexdigest()
        
        payload_hash = hashlib.sha256(payload).hexdigest()[:16]
        
        return GovernanceSignature(
            algorithm="hmac-sha256",
            signature=signature,
            timestamp=timestamp,
            payload_hash=payload_hash,
        )
    
    def verify(self, payload: str, signature: GovernanceSignature) -> bool:
        """Verify a governance signature."""
        if signature.algorithm != "hmac-sha256" or not signature.timestamp:
            return False
        message = f"{payload}|{signature.timestamp}".encode()
        for key in [self.hmac_key, *self.previous_keys]:
            expected = hmac.new(key, message, hashlib.sha256).hexdigest()
            if secrets.compare_digest(expected, signature.signature):
                return True
        return False
    
    def to_header(self, sig: GovernanceSignature) -> str:
        """Format signature for HTTP header."""
        return f"{sig.algorithm}:{sig.signature}"
    
    def parse_header(self, header: str) -> Optional[GovernanceSignature]:
        """Parse signature from HTTP header."""
        try:
            if ":" not in header:
                return None
            algo, sig = header.split(":", 1)
            return GovernanceSignature(
                algorithm=algo,
                signature=sig,
                timestamp="",  # Would need to be passed separately
                payload_hash="",
            )
        except Exception:
            return None


class InternalToolAuth:
    """Internal tool authentication for loopback calls.
    
    Ported from Odysseus middleware INTERNAL_TOOL_TOKEN.
    Allows in-process tool calls to bypass admin checks.
    """
    
    def __init__(self, token: Optional[str] = None):
        self.token = token or INTERNAL_TOOL_TOKEN
        self.header_name = INTERNAL_TOOL_HEADER
        self.internal_user = INTERNAL_TOOL_USER
    
    def verify_header(self, header_value: Optional[str]) -> bool:
        """Verify internal tool token from header."""
        if not header_value:
            return False
        return secrets.compare_digest(header_value, self.token)
    
    def get_token(self) -> str:
        """Get the current internal token (for tool layer to use)."""
        return self.token
    
    def get_header_name(self) -> str:
        return self.header_name
    
    def get_internal_user(self) -> str:
        return self.internal_user
    
    def create_internal_headers(self) -> Dict[str, str]:
        """Create headers for internal tool loopback calls."""
        return {
            self.header_name: self.token,
            "X-Internal-User": self.internal_user,
        }


# Default signer instance
DEFAULT_SIGNER = GovernanceSigner()
DEFAULT_INTERNAL_AUTH = InternalToolAuth()


def generate_governance_signature(payload: str, timestamp: Optional[str] = None) -> str:
    """Generate governance signature header value.
    
    Convenience function matching the main.py pattern.
    Returns: "hmac-sha256:<signature>"
    """
    sig = DEFAULT_SIGNER.sign(payload, timestamp)
    return DEFAULT_SIGNER.to_header(sig)


def verify_governance_signature(payload: str, header: str, timestamp: str) -> bool:
    """Verify a governance signature from header."""
    sig_obj = DEFAULT_SIGNER.parse_header(header)
    if not sig_obj:
        return False
    sig_obj.timestamp = timestamp
    return DEFAULT_SIGNER.verify(payload, sig_obj)


def generate_internal_tool_token() -> str:
    """Generate a new internal tool token."""
    return secrets.token_hex(32)


# Integration with request/response flow
def create_request_signature(
    request_id: str,
    user_input: str,
    matched_rules: list,
    decision: str,
    tier_latencies: Dict[str, float],
) -> tuple[str, GovernanceSignature]:
    """Create governance signature for a request decision.
    
    Returns (header_value, GovernanceSignature object)
    """
    timestamp = str(int(time.time()))
    payload = (
        f"{request_id}|"
        f"{user_input[:500]}|"
        f"{','.join(matched_rules)}|"
        f"{decision}|"
        f"{tier_latencies.get('tier0', 0):.2f},"
        f"{tier_latencies.get('tier1', 0):.2f},"
        f"{tier_latencies.get('tier2', 0):.2f},"
        f"{tier_latencies.get('tier3', 0):.2f}"
    )
    sig = DEFAULT_SIGNER.sign(payload, timestamp)
    header = DEFAULT_SIGNER.to_header(sig)
    return header, sig


def create_response_signature(
    request_id: str,
    response_content: str,
    inspection_latency_ms: float,
) -> tuple[str, GovernanceSignature]:
    """Create governance signature for response.
    
    Returns (header_value, GovernanceSignature object)
    """
    timestamp = str(int(time.time()))
    payload = (
        f"{request_id}|"
        f"{response_content[:500]}|"
        f"{inspection_latency_ms:.2f}"
    )
    sig = DEFAULT_SIGNER.sign(payload, timestamp)
    header = DEFAULT_SIGNER.to_header(sig)
    return header, sig


# Security headers middleware (Odysseus pattern)
class SecurityHeaders:
    """Security headers based on Odysseus middleware."""
    
    @staticmethod
    def apply_headers(response, request, is_https: bool = False):
        """Apply standard security headers."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(self), geolocation=()"
        
        if is_https:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "font-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        
        return response