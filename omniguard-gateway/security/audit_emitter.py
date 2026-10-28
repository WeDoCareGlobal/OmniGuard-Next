"""
Audit Emitter
Structured logging for security events and governance audit trail.
"""

import json
import time
import uuid
import os
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime
from contextvars import ContextVar
import threading


class AuditEventType(Enum):
    """Types of audit events."""
    REQUEST_RECEIVED = "request_received"
    INJECTION_DETECTED = "injection_detected"
    INJECTION_BLOCKED = "injection_blocked"
    CLEAN_REQUEST_PASSED = "clean_request_passed"
    OUTPUT_LEAKAGE_DETECTED = "output_leakage_detected"
    OUTPUT_LEAKAGE_BLOCKED = "output_leakage_blocked"
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHORIZATION_GRANTED = "authorization_granted"
    AUTHORIZATION_DENIED = "authorization_denied"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    POLICY_DECISION = "policy_decision"
    HEALTH_CHECK = "health_check"
    STARTUP = "startup"
    SHUTDOWN = "shutdown"
    CONFIG_CHANGE = "config_change"
    ERROR = "error"


class Severity(Enum):
    """Event severity levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Structured audit event."""
    event_id: str
    timestamp: str
    event_type: str
    severity: str
    request_id: Optional[str] = None
    client_ip: Optional[str] = None
    user_id: Optional[str] = None
    api_key_id: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    decision: Optional[str] = None
    confidence: Optional[float] = None
    matched_patterns: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    latency_ms: Optional[float] = None
    input_length: Optional[int] = None
    output_length: Optional[int] = None
    error: Optional[str] = None
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(',', ':'))
    
    def to_cef(self) -> str:
        """Convert to Common Event Format for SIEM integration."""
        cef_parts = [
            "CEF:0",
            "OmniGuard",
            "AI-Security-Gateway",
            "1.0.0",
            self.event_type,
            self.event_type.replace("_", " "),
            self.severity.upper(),
        ]
        # Add extensions
        extensions = []
        if self.request_id:
            extensions.append(f"requestId={self.request_id}")
        if self.client_ip:
            extensions.append(f"src={self.client_ip}")
        if self.user_id:
            extensions.append(f"suser={self.user_id}")
        if self.decision:
            extensions.append(f"outcome={self.decision}")
        if self.confidence is not None:
            extensions.append(f"confidence={self.confidence}")
        if self.matched_patterns:
            extensions.append(f"patterns={','.join(self.matched_patterns)}")
        if self.categories:
            extensions.append(f"cats={','.join(self.categories)}")
        if self.latency_ms is not None:
            extensions.append(f"latency={self.latency_ms}")
        
        return "|".join(cef_parts + ["|".join(extensions)])


# Context variable for request tracking
request_context: ContextVar[Optional[Dict]] = ContextVar('request_context', default=None)


class AuditEmitter:
    """
    Thread-safe audit event emitter with multiple output sinks.
    
    Supports:
    - JSON Lines to stdout/file
    - CEF format for SIEM
    - Structured logging
    - Async buffering for performance
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.output_file = self.config.get("output_file")
        self.siem_endpoint = self.config.get("siem_endpoint")
        self.min_severity = self.config.get("min_severity", "info")
        self.buffer_size = self.config.get("buffer_size", 100)
        self.flush_interval = self.config.get("flush_interval", 5.0)
        
        self._buffer: List[AuditEvent] = []
        self._lock = threading.Lock()
        self._running = False
        self._flush_thread: Optional[threading.Thread] = None
        
        # Severity ordering
        self.severity_order = {
            "debug": 0, "info": 1, "warning": 2, "high": 3, "critical": 4
        }
        self.min_severity_level = self.severity_order.get(self.min_severity, 1)
        
        # Start background flusher
        self.start()
    
    def _should_emit(self, severity: str) -> bool:
        return self.severity_order.get(severity, 0) >= self.min_severity_level
    
    def emit(self, event: AuditEvent) -> None:
        """Emit an audit event."""
        if not self.enabled or not self._should_emit(event.severity):
            return
        
        with self._lock:
            self._buffer.append(event)
            if len(self._buffer) >= self.buffer_size:
                self._flush_locked()
    
    def emit_event(self, 
                   event_type: AuditEventType,
                   severity: Severity = Severity.INFO,
                   **kwargs) -> AuditEvent:
        """Create and emit an audit event."""
        # Get request context if available
        ctx = request_context.get() or {}
        
        event = AuditEvent(
            event_id=str(uuid.uuid4())[:8],
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=event_type.value,
            severity=severity.value,
            request_id=ctx.get("request_id"),
            client_ip=ctx.get("client_ip"),
            user_id=ctx.get("user_id"),
            api_key_id=ctx.get("api_key_id"),
            endpoint=ctx.get("endpoint"),
            method=ctx.get("method"),
            **kwargs
        )
        
        self.emit(event)
        return event
    
    def _flush_locked(self) -> None:
        """Flush buffer (must hold lock)."""
        if not self._buffer:
            return
        
        events = self._buffer[:]
        self._buffer.clear()
        
        # Write to file
        if self.output_file:
            try:
                with open(self.output_file, "a", encoding="utf-8") as f:
                    for event in events:
                        f.write(event.to_json() + "\n")
            except Exception as e:
                print(f"AuditEmitter: Failed to write to file: {e}")
        
        # Write to stdout (JSON Lines)
        try:
            for event in events:
                print(event.to_json(), flush=True)
        except Exception:
            pass
        
        # Send to SIEM if configured
        if self.siem_endpoint:
            self._send_to_siem(events)
    
    def _send_to_siem(self, events: List[AuditEvent]) -> None:
        """Send events to SIEM endpoint."""
        try:
            import urllib.request
            import urllib.error
            
            payload = json.dumps([e.to_dict() for e in events]).encode()
            req = urllib.request.Request(
                self.siem_endpoint,
                data=payload,
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=5) if self.siem_endpoint else None
        except Exception:
            pass  # Silently fail SIEM delivery
    
    def start(self) -> None:
        """Start background flusher."""
        if self._running:
            return
        self._running = True
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()
    
    def stop(self) -> None:
        """Stop background flusher and flush remaining."""
        self._running = False
        if self._flush_thread:
            self._flush_thread.join(timeout=10)
        self.flush()
    
    def flush(self) -> None:
        """Flush remaining events."""
        with self._lock:
            self._flush_locked()
    
    def _flush_loop(self) -> None:
        """Background flush loop."""
        while self._running:
            time.sleep(self.flush_interval)
            if self._running:
                with self._lock:
                    self._flush_locked()


# Global audit emitter
AUDIT_EMITTER = AuditEmitter({
    "enabled": True,
    "output_file": os.getenv("OMNIGUARD_AUDIT_LOG"),
    "min_severity": "info",
    "buffer_size": 100,
    "flush_interval": 5.0
})


def set_request_context(context: Dict) -> None:
    """Set request context for current thread."""
    request_context.set(context)


def clear_request_context() -> None:
    """Clear request context."""
    request_context.set(None)


def emit_audit(event_type: AuditEventType, 
               severity: Severity = Severity.INFO, 
               **kwargs) -> AuditEvent:
    """Convenience function to emit audit event."""
    return AUDIT_EMITTER.emit_event(event_type, severity, **kwargs)


# Convenience functions for common events
def audit_request_received(request_id: str, client_ip: str, endpoint: str, 
                          method: str, api_key_id: str = None) -> None:
    emit_audit(
        AuditEventType.REQUEST_RECEIVED,
        Severity.INFO,
        request_id=request_id,
        client_ip=client_ip,
        endpoint=endpoint,
        method=method,
        api_key_id=api_key_id
    )


def audit_injection_detected(request_id: str, decision: str, confidence: float,
                           matched_patterns: List[str], categories: List[str],
                           latency_ms: float, input_length: int) -> None:
    emit_audit(
        AuditEventType.INJECTION_DETECTED if decision == "BLOCK" else AuditEventType.INJECTION_BLOCKED,
        Severity.HIGH if decision == "BLOCK" else Severity.WARNING,
        request_id=request_id,
        decision=decision,
        confidence=confidence,
        matched_patterns=matched_patterns,
        categories=categories,
        latency_ms=latency_ms,
        input_length=input_length
    )


def audit_clean_request(request_id: str, latency_ms: float, input_length: int) -> None:
    emit_audit(
        AuditEventType.CLEAN_REQUEST_PASSED,
        Severity.INFO,
        request_id=request_id,
        latency_ms=latency_ms,
        input_length=input_length
    )


def audit_output_leakage(request_id: str, categories: List[str], 
                        severity: str, blocked: bool) -> None:
    emit_audit(
        AuditEventType.OUTPUT_LEAKAGE_BLOCKED if blocked else AuditEventType.OUTPUT_LEAKAGE_DETECTED,
        Severity.CRITICAL if severity == "critical" else Severity.HIGH,
        request_id=request_id,
        categories=categories,
        decision="BLOCKED" if blocked else "DETECTED",
        metadata={"leakage_severity": severity}
    )


def audit_authentication(request_id: str, success: bool, api_key_id: Optional[str] = None,
                        client_ip: str = None, error: str = None) -> None:
    emit_audit(
        AuditEventType.AUTHENTICATION_SUCCESS if success else AuditEventType.AUTHENTICATION_FAILURE,
        Severity.INFO if success else Severity.WARNING,
        request_id=request_id,
        api_key_id=api_key_id,
        client_ip=client_ip,
        error=error
    )


def audit_authorization(request_id: str, granted: bool, tool: Optional[str] = None,
                       operation: str = None, principal: str = None,
                       missing_scopes: List[str] = None) -> None:
    emit_audit(
        AuditEventType.AUTHORIZATION_GRANTED if granted else AuditEventType.AUTHORIZATION_DENIED,
        Severity.INFO if granted else Severity.WARNING,
        request_id=request_id,
        decision="GRANTED" if granted else "DENIED",
        metadata={
            "tool": tool,
            "operation": operation,
            "principal": principal,
            "missing_scopes": missing_scopes or []
        }
    )


def audit_rate_limit(request_id: str, client_ip: str, limit: int, window: str) -> None:
    emit_audit(
        AuditEventType.RATE_LIMIT_EXCEEDED,
        Severity.WARNING,
        request_id=request_id,
        client_ip=client_ip,
        metadata={"limit": limit, "window": window}
    )


def audit_policy_decision(request_id: str, decision: str, confidence: float,
                         triggered_rule: str, latency_ms: float) -> None:
    emit_audit(
        AuditEventType.POLICY_DECISION,
        Severity.INFO,
        request_id=request_id,
        decision=decision,
        confidence=confidence,
        latency_ms=latency_ms,
        metadata={"triggered_rule": triggered_rule}
    )


def audit_startup(config_summary: Dict) -> None:
    emit_audit(AuditEventType.STARTUP, Severity.INFO, metadata=config_summary)


def audit_shutdown() -> None:
    emit_audit(AuditEventType.SHUTDOWN, Severity.INFO)


def audit_error(request_id: Optional[str] = None, error: Optional[str] = None, 
                endpoint: str = None, method: str = None) -> None:
    emit_audit(
        AuditEventType.ERROR,
        Severity.CRITICAL,
        request_id=request_id,
        error=error,
        endpoint=endpoint,
        method=method
    )