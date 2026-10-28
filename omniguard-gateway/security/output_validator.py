"""
Output Validator
Inspects model responses for sensitive data leakage.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Pattern
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .injection_detector import DetectionResult, DetectionCategory


class LeakageCategory(Enum):
    """Categories of sensitive data leakage."""
    SYSTEM_PROMPT = "system_prompt"
    INTERNAL_INSTRUCTIONS = "internal_instructions"
    API_KEY = "api_key"
    PASSWORD = "password"
    SECRET = "secret"
    TOKEN = "token"
    DATABASE_CREDENTIAL = "database_credential"
    PRIVATE_KEY = "private_key"
    PII = "pii"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    IP_ADDRESS = "ip_address"
    INJECTION_ECHO = "injection_echo"  # Model echoes back the injection attempt


@dataclass
class LeakagePattern:
    """A compiled pattern for detecting sensitive data leakage."""
    name: str
    pattern: Pattern
    category: str
    severity: str = "high"
    description: str = ""
    redact: bool = True  # Whether to redact in logs


@dataclass
class LeakageResult:
    """Result of a leakage detection."""
    pattern_name: str
    category: str
    matched_text: str
    severity: str
    confidence: float
    position: int  # Position in text


class OutputValidator:
    """
    Validates model outputs for sensitive data leakage.
    
    Checks for:
    - System prompt leakage
    - API keys, passwords, tokens
    - Database credentials
    - Private keys
    - PII (SSN, credit card, etc.)
    - Injection echo (model repeating the attack)
    """
    
    DEFAULT_PATTERNS = [
        # System prompt leakage
        {
            "name": "system_prompt_leak",
            "pattern": r"(?:system\s+prompt|system\s+message|system\s+instruction)\s*(?:is|:)\s*.{10,}",
            "category": "system_prompt",
            "severity": "critical",
            "description": "System prompt leaked in response"
        },
        {
            "name": "internal_instructions_leak",
            "pattern": r"(?:internal\s+instructions?|hidden\s+instructions?|meta\s+prompt)\s*(?:is|:)\s*.{10,}",
            "category": "internal_instructions",
            "severity": "critical",
            "description": "Internal instructions leaked"
        },
        
        # API Keys and tokens
        {
            "name": "api_key_leak",
            "pattern": r"(?:api[_-]?key|apikey)\s*[:=]\s*[a-zA-Z0-9_\-]{20,}",
            "category": "api_key",
            "severity": "critical",
            "description": "API key exposed in response"
        },
        {
            "name": "bearer_token_leak",
            "pattern": r"bearer\s+[a-zA-Z0-9_\-]{20,}",
            "category": "token",
            "severity": "critical",
            "description": "Bearer token exposed"
        },
        {
            "name": "jwt_leak",
            "pattern": r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
            "category": "token",
            "severity": "critical",
            "description": "JWT token exposed"
        },
        
        # Passwords and secrets
        {
            "name": "password_leak",
            "pattern": r"(?:password|passwd|pwd)\s*[:=]\s*[^\s]{8,}",
            "category": "password",
            "severity": "critical",
            "description": "Password exposed in response"
        },
        {
            "name": "secret_leak",
            "pattern": r"(?:secret|secret_key)\s*[:=]\s*[a-zA-Z0-9_\-]{16,}",
            "category": "secret",
            "severity": "critical",
            "description": "Secret key exposed"
        },
        
        # Database credentials
        {
            "name": "db_connection_string",
            "pattern": r"(?:postgresql|mysql|mongodb|redis)://[^\s]{20,}",
            "category": "database_credential",
            "severity": "critical",
            "description": "Database connection string exposed"
        },
        {
            "name": "db_credentials",
            "pattern": r"(?:username|user|password|pwd)\s*[:=]\s*[^\s]{8,}.*(?:host|database|db)\s*[:=]",
            "category": "database_credential",
            "severity": "critical",
            "description": "Database credentials exposed"
        },
        
        # Private keys
        {
            "name": "private_key_pem",
            "pattern": r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----",
            "category": "private_key",
            "severity": "critical",
            "description": "Private key in PEM format exposed"
        },
        {
            "name": "ssh_private_key",
            "pattern": r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
            "category": "private_key",
            "severity": "critical",
            "description": "SSH private key exposed"
        },
        
        # PII
        {
            "name": "ssn",
            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
            "category": "ssn",
            "severity": "high",
            "description": "US Social Security Number"
        },
        {
            "name": "credit_card",
            "pattern": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            "category": "credit_card",
            "severity": "high",
            "description": "Credit card number"
        },
        {
            "name": "email",
            "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "category": "pii",
            "severity": "medium",
            "description": "Email address"
        },
        {
            "name": "phone_us",
            "pattern": r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
            "category": "pii",
            "severity": "medium",
            "description": "US phone number"
        },
        
        # IP addresses
        {
            "name": "ipv4_address",
            "pattern": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            "category": "ip_address",
            "severity": "medium",
            "description": "IPv4 address"
        },
        {
            "name": "ipv6_address",
            "pattern": r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
            "category": "ip_address",
            "severity": "medium",
            "description": "IPv6 address"
        },
        
        # Injection echo (model repeating the attack)
        {
            "name": "injection_echo_ignore",
            "pattern": r"(?:ignore|disregard|forget|override|bypass)\s+(?:previous|prior|all|earlier)\s*(?:instructions?|commands?)",
            "category": "injection_echo",
            "severity": "high",
            "description": "Model echoing injection attempt"
        },
        {
            "name": "injection_echo_system",
            "pattern": r"(?:system\s+prompt|internal\s+instructions?)\s*(?:is|:)\s*.{20,}",
            "category": "injection_echo",
            "severity": "critical",
            "description": "Model echoing system prompt request"
        },
    ]

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.patterns = self._compile_patterns()

    def _compile_patterns(self) -> List[Dict]:
        patterns = []
        for p in self.DEFAULT_PATTERNS:
            try:
                compiled = re.compile(p["pattern"], re.IGNORECASE | re.MULTILINE)
                patterns.append({
                    "name": p["name"],
                    "pattern": re.compile(p["pattern"], re.IGNORECASE | re.MULTILINE),
                    "category": p["category"],
                    "severity": p["severity"],
                    "description": p.get("description", "")
                })
            except re.error as e:
                print(f"Warning: Failed to compile output pattern {p['name']}: {e}")
        return patterns

    def validate(self, text: str) -> List[Dict]:
        """
        Check output text for leakage.
        
        Returns list of detected leakage findings.
        """
        results = []
        
        for pattern_info in self.patterns:
            try:
                matches = pattern_info["pattern"].finditer(text)
                for match in matches:
                    results.append({
                        "pattern_name": pattern_info["name"],
                        "category": pattern_info["category"],
                        "severity": pattern_info["severity"],
                        "matched_text": match.group()[:200],
                        "position": match.start(),
                        "confidence": 0.95 if pattern_info["severity"] == "critical" else 0.9
                    })
            except Exception:
                continue
        
        return results

    def has_critical_leakage(self, text: str) -> bool:
        """Quick check for critical leakage."""
        results = self.validate(text)
        return any(r["severity"] == "critical" for r in results)

    def redact(self, text: str) -> str:
        """Redact sensitive information from text."""
        redacted = text
        for pattern_info in self.patterns:
            try:
                redacted = pattern_info["pattern"].sub("[REDACTED]", redacted)
            except Exception:
                continue
        return redacted


# Global instance
OUTPUT_VALIDATOR = OutputValidator()


def validate_output(text: str) -> List[Dict]:
    """Convenience function for output validation."""
    return OUTPUT_VALIDATOR.validate(text)


def has_critical_leakage(text: str) -> bool:
    """Quick check for critical leakage."""
    return OUTPUT_VALIDATOR.has_critical_leakage(text)


def redact_output(text: str) -> str:
    """Redact sensitive data from output."""
    return OUTPUT_VALIDATOR.redact(text)