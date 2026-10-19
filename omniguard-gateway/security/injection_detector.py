"""
Injection Detector
Core deterministic pattern matching for prompt injection detection.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Callable
from abc import ABC, abstractmethod


class DetectionCategory(Enum):
    """Categories of injection attacks."""
    DIRECTIVE_OVERRIDE = "directive_override"
    CREDENTIAL_LEAK = "credential_leak"
    TOOL_HIJACKING = "tool_hijacking"
    BASE64_SMUGGLING = "base64_smuggling"
    AUTHORITY_SPOOFING = "authority_spoofing"
    MULTILINGUAL_INJECTION = "multilingual_injection"
    INDIRECT_RAG_INJECTION = "indirect_rag_injection"
    STRUCTURAL_MANY_SHOT = "structural_many_shot"
    ENCODING_OBFUSCATION = "encoding_obfuscation"
    CONTEXT_OVERFLOW = "context_overflow"


@dataclass
class DetectionPattern:
    """A compiled detection pattern with metadata."""
    name: str
    pattern: re.Pattern
    category: DetectionCategory
    severity: str = "high"  # high, medium, low
    description: str = ""
    requires_untrusted_context: bool = False  # Only match in untrusted content


@dataclass
class DetectionResult:
    """Result of a pattern match."""
    pattern_name: str
    category: DetectionCategory
    matched_text: str
    form_matched: str  # Which canonical form matched
    severity: str
    confidence: float


class PatternRegistry:
    """Registry of all detection patterns with compilation management."""
    
    DEFAULT_PATTERNS = [
        # Directive Override - Core patterns
        DetectionPattern(
            name="directive_override_1",
            pattern=re.compile(
                r"(ignore|disregard|forget|override|bypass|do\s*not\s*follow)"
                r"\b[\s\S]{0,60}\b"
                r"(everything|previous|prior|all|earlier|instructions?|commands?|rules?|settings?|guidelines?|directives?|system)",
                re.IGNORECASE
            ),
            category=DetectionCategory.DIRECTIVE_OVERRIDE,
            severity="high",
            description="Classic instruction override with flexible spacing"
        ),
        DetectionPattern(
            name="directive_override_2",
            pattern=re.compile(
                r"(ignore|disregard|forget|override|bypass|donotfollow)"
                r".{0,50}"
                r"(everything|previous|prior|all|earlier|instruction|command|rule|setting|directive|hack|broken|smug)",
                re.IGNORECASE
            ),
            category=DetectionCategory.DIRECTIVE_OVERRIDE,
            severity="high",
            description="Compact instruction override variant"
        ),
        DetectionPattern(
            name="directive_override_3",
            pattern=re.compile(
                r"(you\s+are\s+now|from\s+now\s+on|act\s+as\s+if|pretend\s+you\s+are|roleplay\s+as)"
                r".{0,30}"
                r"(unrestricted|developer\s*mode|dan\s*mode|admin\s*mode|free|no\s*rules?|unlimited)",
                re.IGNORECASE
            ),
            category=DetectionCategory.DIRECTIVE_OVERRIDE,
            severity="high",
            description="Roleplay/persona adoption attempts"
        ),
        
        # Credential Leak / System Prompt Extraction
        DetectionPattern(
            name="system_credential_leak",
            pattern=re.compile(
                r"(system\s*prompt|hidden\s*instructions?|dump\s*context|secret\s*internal|"
                r"admin\s*username|password\s*is|api\s*key\s*is|server\s*ip\s*is|"
                r"root\s*supervisor|admin_override|developer\s*mode|dan\s*mode|unrestricted\s*ai)",
                re.IGNORECASE
            ),
            category=DetectionCategory.CREDENTIAL_LEAK,
            severity="critical",
            description="Attempts to extract system prompts or credentials"
        ),
        DetectionPattern(
            name="credential_extraction",
            pattern=re.compile(
                r"(what\s+is\s+(?:the\s+)?(?:password|api\s*key|secret|token)|"
                r"(?:show|give|tell|reveal)\s+(?:me\s+)?(?:the\s+)?(?:password|api\s*key|secret|token))",
                re.IGNORECASE
            ),
            category=DetectionCategory.CREDENTIAL_LEAK,
            severity="critical",
            description="Direct credential extraction requests"
        ),
        
        # Tool Hijacking
        DetectionPattern(
            name="tool_hijacking",
            pattern=re.compile(
                r"(call\s*the\s*function|query_database|run\s*the\s*shell|rm\s*-rf|"
                r"transfer_funds|execute\s*the\s*payment|invoke\s*the\s*api|"
                r"exploit\s*script|send_email|delete_user|drop_table|exec\s*\()",
                re.IGNORECASE
            ),
            category=DetectionCategory.TOOL_HIJACKING,
            severity="critical",
            description="Tool/function invocation hijacking attempts"
        ),
        DetectionPattern(
            name="shell_command_injection",
            pattern=re.compile(
                r"(rm\s+-rf|sudo\s+|exec\s*\(|subprocess|os\.system|shell_exec|"
                r"bash\s+-c|powershell\s+-c|cmd\s+/c)",
                re.IGNORECASE
            ),
            category=DetectionCategory.TOOL_HIJACKING,
            severity="critical",
            description="Shell command execution attempts"
        ),
        
        # Base64 / Encoding Smuggling
        DetectionPattern(
            name="base64_decode_request",
            pattern=re.compile(
                r"(decode\s*(this)?\s*base64|base64-encoded|base64\s*input|"
                r"decode:\s*[A-Za-z0-9+/]|base64\s*:)",
                re.IGNORECASE
            ),
            category=DetectionCategory.BASE64_SMUGGLING,
            severity="high",
            description="Explicit Base64 decode requests"
        ),
        DetectionPattern(
            name="encoding_obfuscation",
            pattern=re.compile(
                r"(rot13|caesar\s*cipher|base32|base58|hex\s*encoded|"
                r"url\s*encoded|unicode\s*escape|zero.width|zwsp)",
                re.IGNORECASE
            ),
            category=DetectionCategory.ENCODING_OBFUSCATION,
            severity="medium",
            description="Encoding obfuscation indicators"
        ),
        
        # Authority Spoofing / Context Manipulation
        DetectionPattern(
            name="authority_spoofing",
            pattern=re.compile(
                r"(trusted\s*source|internal\s*memo|attached\s*document|"
                r"provided\s*information|guidelines\s*state|per\s+the|as\s+per\s+the|"
                r"the\s+following\s+(?:text|document|content)\s+(?:is|states?|says?)|"
                r"retrieved\s+(?:from|context)|knowledge\s+base\s+(?:states?|says?))",
                re.IGNORECASE
            ),
            category=DetectionCategory.AUTHORITY_SPOOFING,
            severity="high",
            description="Authority spoofing via trusted source framing"
        ),
        DetectionPattern(
            name="context_manipulation",
            pattern=re.compile(
                r"(forget\s+(?:everything|all|previous)|reset\s+(?:your\s+)?(?:instructions?|context|memory)|"
                r"new\s+instructions?\s*:|override\s+(?:all|previous)\s+(?:instructions?|rules?|commands?))",
                re.IGNORECASE
            ),
            category=DetectionCategory.AUTHORITY_SPOOFING,
            severity="high",
            description="Context reset/manipulation attempts"
        ),
        
        # Multilingual Injection
        DetectionPattern(
            name="multilingual_injection",
            pattern=re.compile(
                r"(ignore|disregard|forget|override)\s*(?:previous|prior|all|earlier)\s*(?:instructions?|commands?|rules?|directives?)",
                re.IGNORECASE
            ),
            category=DetectionCategory.MULTILINGUAL_INJECTION,
            severity="high",
            description="Multilingual directive override (pattern covers English variants)"
        ),
        DetectionPattern(
            name="multilingual_spanish",
            pattern=re.compile(
                r"(ignora|olvida|desprecia|anula)\s+(?:instrucciones?|ordenes?|reglas?|directivas?)",
                re.IGNORECASE
            ),
            category=DetectionCategory.MULTILINGUAL_INJECTION,
            severity="high",
            description="Spanish directive override"
        ),
        DetectionPattern(
            name="multilingual_french",
            pattern=re.compile(
                r"(ignore|oublie|disregarde|annule)\s+(?:les\s+)?(?:instructions?|ordres?|regles?)",
                re.IGNORECASE
            ),
            category=DetectionCategory.MULTILINGUAL_INJECTION,
            severity="high",
            description="French directive override"
        ),
        DetectionPattern(
            name="multilingual_german",
            pattern=re.compile(
                r"(ignoriere|vergiss|missachte|ueberschreibe)\s+(?:die\s+)?(?:anweisungen?|befehle?|regeln?)",
                re.IGNORECASE
            ),
            category=DetectionCategory.MULTILINGUAL_INJECTION,
            severity="high",
            description="German directive override"
        ),
        
        # Indirect RAG Injection
        DetectionPattern(
            name="indirect_rag_injection",
            pattern=re.compile(
                r"(according\s+to|based\s+on|as\s+per|per\s+the|the\s+(?:attached|retrieved|provided|document)\s+(?:states?|says?|indicates?))"
                r".{0,100}"
                r"(ignore|disregard|forget|override|bypass|reveal|dump|execute|send|transfer|delete)",
                re.IGNORECASE
            ),
            category=DetectionCategory.INDIRECT_RAG_INJECTION,
            severity="high",
            description="Injection hidden in retrieved/RAG content"
        ),
        DetectionPattern(
            name="rag_credential_leak",
            pattern=re.compile(
                r"(the\s+(?:password|key|token|secret)\s+is|access\s+code\s+is|"
                r"api\s*key\s*[:=]\s*[\w-]+|server\s+ip\s+is\s+\d+\.\d+\.\d+\.\d+)",
                re.IGNORECASE
            ),
            category=DetectionCategory.INDIRECT_RAG_INJECTION,
            severity="critical",
            description="Credentials embedded in retrieved content"
        ),
        
        # Structural Many-Shot / Context Overflow
        DetectionPattern(
            name="many_shot_structural",
            pattern=re.compile(
                r"(?:^|\n)(?:user|assistant|human|ai):\s*.{10,200}\n(?:user|assistant|human|ai):\s*.{10,200}\n"
                r"(?:user|assistant|human|ai):\s*.{10,200}\n(?:user|assistant|human|ai):\s*.{10,200}\n"
                r"(?:user|assistant|human|ai):\s*.{10,200}",
                re.IGNORECASE
            ),
            category=DetectionCategory.STRUCTURAL_MANY_SHOT,
            severity="medium",
            description="Many-shot structural pattern (5+ alternating messages)"
        ),
        DetectionPattern(
            name="context_overflow_repetition",
            pattern=re.compile(
                r"(.{50,200})\1{10,}",  # Same text repeated 10+ times
                re.IGNORECASE
            ),
            category=DetectionCategory.CONTEXT_OVERFLOW,
            severity="medium",
            description="Excessive repetition for context overflow"
        ),
        
        # Encoding Obfuscation
        DetectionPattern(
            name="zero_width_chars",
            pattern=re.compile(r'[\u200B\u200C\u200D\uFEFF\u2060\u200E\u200F]'),
            category=DetectionCategory.ENCODING_OBFUSCATION,
            severity="medium",
            description="Zero-width / invisible Unicode characters"
        ),
        DetectionPattern(
            name="homoglyph_substitution",
            pattern=re.compile(
                r"[аеорсух]|[аеорсух]|[𝐚𝐛𝐜𝐝𝐞𝐟𝐠𝐡𝐢𝐣𝐤𝐥𝐦𝐧𝐨𝐩𝐪𝐫𝐬𝐭𝐮𝐯𝐰𝐱𝐲𝐳]",
                re.IGNORECASE
            ),
            category=DetectionCategory.ENCODING_OBFUSCATION,
            severity="medium",
            description="Cyrillic/homoglyph character substitution"
        ),
        
        # Smith-Waterman style structural alignment detection
        DetectionPattern(
            name="structural_alignment",
            pattern=re.compile(
                r"(?:ignore|disregard|forget|override|bypass).{0,5}"
                r"(?:previous|prior|all|earlier|instructions?|commands?|rules?)"
                r".{0,5}"
                r"(?:and|then|so)\s*"
                r"(?:output|print|return|show|reveal|dump|execute|send|transfer|delete)",
                re.IGNORECASE
            ),
            category=DetectionCategory.STRUCTURAL_MANY_SHOT,
            severity="high",
            description="Smith-Waterman style structural alignment pattern"
        ),
    ]

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> List[DetectionPattern]:
        patterns = self.DEFAULT_PATTERNS.copy()
        
        # Add custom patterns from config
        if self.config and "custom_patterns" in self.config:
            for pc in self.config["custom_patterns"]:
                try:
                    patterns.append(DetectionPattern(
                        name=pc["name"],
                        pattern=re.compile(pc["pattern"], re.IGNORECASE),
                        category=DetectionCategory(pc["category"]),
                        severity=pc.get("severity", "medium"),
                        description=pc.get("description", ""),
                        requires_untrusted_context=pc.get("requires_untrusted_context", False)
                    ))
                except Exception as e:
                    print(f"Warning: Failed to compile custom pattern {pc.get('name', 'unknown')}: {e}")
        
        return patterns
    
    def get_patterns_by_category(self, category: DetectionCategory) -> List[DetectionPattern]:
        return [p for p in self.patterns if p.category == category]
    
    def get_patterns_for_trusted(self) -> List[DetectionPattern]:
        """Patterns that can match in trusted (user) content."""
        return [p for p in self.patterns if not p.requires_untrusted_context]
    
    def get_patterns_for_untrusted(self) -> List[DetectionPattern]:
        """Patterns that specifically target untrusted content."""
        return [p for p in self.patterns if p.requires_untrusted_context]


class InjectionDetector:
    """
    Deterministic injection detector using compiled pattern registry.
    
    Matches patterns against multiple canonical forms of input text.
    Supports context-aware detection (trusted vs untrusted content).
    """
    
    def __init__(self, pattern_registry: Optional[PatternRegistry] = None, config: Optional[Dict] = None):
        self.registry = pattern_registry or PatternRegistry(config)
        self.config = config or {}
        self.threshold = self.config.get("threshold", 1)  # Min patterns to trigger BLOCK
        
        # Minimum confidence per category to trigger
        self.category_thresholds = {
            DetectionCategory.CREDENTIAL_LEAK: 1,
            DetectionCategory.TOOL_HIJACKING: 1,
            DetectionCategory.DIRECTIVE_OVERRIDE: 1,
            DetectionCategory.BASE64_SMUGGLING: 1,
            DetectionCategory.AUTHORITY_SPOOFING: 1,
            DetectionCategory.INDIRECT_RAG_INJECTION: 1,
            DetectionCategory.MULTILINGUAL_INJECTION: 1,
            DetectionCategory.ENCODING_OBFUSCATION: 2,
            DetectionCategory.STRUCTURAL_MANY_SHOT: 3,
            DetectionCategory.CONTEXT_OVERFLOW: 2,
        }

    def detect(self, 
               forms: Dict[str, str], 
               trust_context: Optional[Dict] = None) -> List[DetectionResult]:
        """
        Detect injection patterns across all canonical forms.
        
        Args:
            forms: Dict of canonical forms from InputNormalizer
            trust_context: Optional trust boundary info (trusted/untrusted segments)
            
        Returns:
            List of DetectionResult for each match
        """
        results = []
        
        for form_name, form_text in forms.items():
            if not form_text:
                continue
            
            # Determine if this form is from untrusted content
            is_untrusted_form = any(
                keyword in form_name 
                for keyword in ["base64", "caesar", "rot13", "compact", "unicode"]
            )
            
            for pattern in self.registry.patterns:
                # Skip patterns that require untrusted context if this is trusted
                if pattern.requires_untrusted_context and not is_untrusted_form:
                    continue
                
                try:
                    matches = pattern.pattern.finditer(form_text)
                    for match in matches:
                        severity = pattern.severity
                        cat_threshold = self.category_thresholds.get(pattern.category, 1)
                        
                        # Base confidence on severity and category
                        confidence_map = {
                            "critical": 0.99,
                            "high": 0.95,
                            "medium": 0.85,
                            "low": 0.70
                        }
                        confidence = confidence_map.get(pattern.severity, 0.9)
                        
                        # Boost confidence for critical categories
                        if pattern.category in [DetectionCategory.CREDENTIAL_LEAK, DetectionCategory.TOOL_HIJACKING]:
                            confidence = max(confidence, 0.99)
                        
                        results.append(DetectionResult(
                            pattern_name=pattern.name,
                            category=pattern.category,
                            matched_text=match.group()[:100],
                            form_matched=form_name,
                            severity=pattern.severity,
                            confidence=confidence
                        ))
                except Exception:
                    continue
        
        return results
    
    def evaluate_detections(self, detections: List[DetectionResult]) -> Dict:
        """
        Evaluate detections and return decision.
        
        Returns: dict with decision, confidence, categories, details
        """
        if not detections:
            return {
                "decision": "ALLOW",
                "confidence": 1.0,
                "categories": [],
                "detections": [],
                "details": "No patterns matched"
            }
        
        # Count by category
        category_counts = {}
        max_confidence = 0
        critical_found = False
        
        for det in detections:
            cat = det.category
            category_counts[cat] = category_counts.get(cat, 0) + 1
            max_confidence = max(max_confidence, det.confidence)
            if det.severity == "critical":
                critical_found = True
        
        # Determine decision
        total_matches = len(detections)
        
        # Critical severity always blocks
        if critical_found:
            decision = "BLOCK"
            confidence = max_confidence
        # Check category-specific thresholds
        elif any(category_counts.get(cat, 0) >= self.category_thresholds.get(cat, 1) 
                for cat in category_counts):
            decision = "BLOCK"
            confidence = max_confidence
        # General threshold
        elif total_matches >= self.threshold:
            decision = "BLOCK"
            confidence = max_confidence
        else:
            decision = "ALLOW"
            confidence = 1.0 - (total_matches * 0.1)
        
        return {
            "decision": decision,
            "confidence": round(confidence, 2),
            "categories": list(category_counts.keys()),
            "category_counts": category_counts,
            "total_matches": total_matches,
            "detections": [
                {
                    "pattern": d.pattern_name,
                    "category": d.category.value,
                    "form": d.form_matched,
                    "severity": d.severity,
                    "confidence": d.confidence,
                    "matched_text": d.matched_text
                }
                for d in detections
            ]
        }


def create_detector(config: Optional[Dict] = None) -> InjectionDetector:
    """Factory function to create configured detector."""
    registry = PatternRegistry(config)
    return InjectionDetector(registry, config)