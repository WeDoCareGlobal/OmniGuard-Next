"""
Policy Engine
Central policy decision point combining all layer results.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set
from abc import ABC, abstractmethod
import hashlib
import json


class Decision(Enum):
    """Policy decision outcomes."""
    ALLOW = "allow"
    BLOCK = "block"
    REVIEW = "review"
    ERROR = "error"


class LayerName(Enum):
    """Inspection layer identifiers."""
    INPUT_VALIDATION = "input_validation"
    CANONICALIZATION = "canonicalization"
    DETERMINISTIC_RULES = "deterministic_rules"
    CONTEXT_CLASSIFICATION = "context_classification"
    POLICY_DECISION = "policy_decision"
    OUTPUT_VALIDATION = "output_validation"


@dataclass
class LayerResult:
    """Result from a single inspection layer."""
    layer: str
    decision: str
    confidence: float
    matched_patterns: List[str] = field(default_factory=list)
    details: Dict = field(default_factory=dict)
    latency_ms: float = 0.0


@dataclass
class PolicyResult:
    """Final policy decision result."""
    decision: str
    confidence: float
    layer_results: List[Dict] = field(default_factory=list)
    total_latency_ms: float = 0.0
    policy_version: str = "1.0.0"
    rule_set_hash: str = ""
    governance_headers: Dict[str, str] = field(default_factory=dict)


class PolicyRule(ABC):
    """Abstract base for policy rules."""
    
    @abstractmethod
    def evaluate(self, layer_results: List[Dict], context: Dict) -> tuple:
        """
        Evaluate rule against layer results.
        
        Returns: (decision, confidence, details)
        """
        pass


class BlockOnAnyBlock(PolicyRule):
    """Block if any layer returns BLOCK or ERROR."""
    
    def evaluate(self, layer_results: List[Dict], context: Dict) -> tuple:
        for lr in layer_results:
            if lr.get("decision") in ("BLOCK", "ERROR"):
                return ("BLOCK", lr.get("confidence", 0.95), {
                    "triggered_by": lr.get("layer"),
                    "triggered_decision": lr.get("decision"),
                    "policy": "block_on_any_block"
                })
        return ("ALLOW", 1.0, {"policy": "block_on_any_block", "reason": "no_blocks_found"})


class BlockOnCriticalSeverity(PolicyRule):
    """Block if any detection has critical severity."""
    
    def evaluate(self, layer_results: List[Dict], context: Dict) -> tuple:
        for lr in layer_results:
            detections = lr.get("details", {}).get("detections", [])
            for det in detections:
                if det.get("severity") == "critical":
                    return ("BLOCK", 0.99, {
                        "triggered_by": det.get("pattern"),
                        "category": det.get("category"),
                        "policy": "block_on_critical"
                    })
        return ("ALLOW", 1.0, {"policy": "block_on_critical", "reason": "no_critical_found"})


class BlockOnThreshold(PolicyRule):
    """Block if detection count exceeds threshold per category."""
    
    def __init__(self, thresholds: Dict = None):
        self.thresholds = thresholds or {
            "credential_leak": 1,
            "tool_hijacking": 1,
            "directive_override": 1,
            "base64_smuggling": 1,
            "authority_spoofing": 1,
            "indirect_rag_injection": 1,
            "encoding_obfuscation": 2,
            "structural_many_shot": 3,
            "context_overflow": 2,
        }
    
    def evaluate(self, layer_results: List[Dict], context: Dict) -> tuple:
        category_counts = {}
        
        for lr in layer_results:
            detections = lr.get("details", {}).get("detections", [])
            for det in detections:
                cat = det.get("category")
                if cat:
                    category_counts[cat] = category_counts.get(cat, 0) + 1
        
        for cat, count in category_counts.items():
            threshold = self.thresholds.get(cat, 1)
            if count >= threshold:
                return ("BLOCK", 0.95, {
                    "triggered_category": cat,
                    "count": count,
                    "threshold": threshold,
                    "policy": "block_on_threshold"
                })
        
        return ("ALLOW", 1.0, {"policy": "block_on_threshold", "counts": category_counts})


class RequireReviewOnSuspicion(PolicyRule):
    """Require REVIEW decision for suspicious but not definitively malicious content."""
    
    def __init__(self, suspicion_categories: List[str] = None):
        self.suspicion_categories = suspicion_categories or [
            "authority_spoofing",
            "indirect_rag_injection",
            "encoding_obfuscation",
            "multilingual_injection"
        ]
    
    def evaluate(self, layer_results: List[Dict], context: Dict) -> tuple:
        # Check if any layer has REVIEW decision
        for lr in layer_results:
            if lr.get("decision") == "REVIEW":
                return ("REVIEW", lr.get("confidence", 0.8), {
                    "triggered_by": lr.get("layer"),
                    "policy": "require_review_on_suspicion"
                })
        
        # Check for suspicious categories in detections
        for lr in layer_results:
            detections = lr.get("details", {}).get("detections", [])
            for det in detections:
                if det.get("category") in self.suspicion_categories:
                    return ("REVIEW", 0.7, {
                        "triggered_category": det.get("category"),
                        "pattern": det.get("pattern"),
                        "policy": "require_review_on_suspicion"
                    })
        
        return ("ALLOW", 1.0, {"policy": "require_review_on_suspicion", "reason": "no_suspicion"})


class CompositePolicy:
    """Combines multiple policy rules with defined precedence."""
    
    RULE_PRECEDENCE: List[tuple] = [
        ("block_critical", BlockOnCriticalSeverity()),
        ("block_any_block", BlockOnAnyBlock()),
        ("block_threshold", BlockOnThreshold()),
        ("review_suspicion", RequireReviewOnSuspicion()),
    ]
    
    def __init__(self, custom_rules: Optional[List[tuple]] = None):
        self.rules = list(self.RULE_PRECEDENCE)
        if custom_rules is not None:
            for name, rule in custom_rules:
                self.rules.append((name, rule))
    
    def evaluate(self, layer_results: List[Dict], context: Dict) -> tuple:
        """Evaluate all rules in precedence order."""
        for name, rule in self.rules:
            decision, confidence, details = rule.evaluate(layer_results, context)
            if decision != "ALLOW":
                details["triggered_rule"] = name
                return (decision, confidence, details)
        
        # All rules passed
        min_confidence = min((lr.get("confidence", 1.0) for lr in layer_results), default=1.0)
        return ("ALLOW", min_confidence, {"policy": "composite_allow", "rules_passed": len(self.rules)})


class PolicyEngine:
    """
    Central policy decision point.
    
    Combines results from all inspection layers into a final policy decision.
    Supports configurable rule composition and governance metadata.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config if config is not None else {}
        self.policy_version = "1.0.0"
        self.policy = CompositePolicy(self.config.get("custom_rules"))
        self.rule_set_hash = self._compute_rule_hash()
    
    def _compute_rule_hash(self) -> str:
        """Compute hash of rule configuration for governance."""
        rule_config = {
            "thresholds": self.config.get("thresholds", {}),
            "suspicion_categories": self.config.get("suspicion_categories", []),
        }
        rule_str = json.dumps(rule_config, sort_keys=True)
        return hashlib.sha256(rule_str.encode()).hexdigest()[:16]
    
    def evaluate(self, layer_results: List[Dict], context: Optional[Dict] = None) -> Dict:
        """
        Evaluate all layer results and produce final policy decision.
        
        Returns:
            Dict with decision, confidence, governance headers, etc.
        """
        context = context if context is not None else {}
        layer_results = layer_results if layer_results is not None else []
        
        # Evaluate composite policy
        decision, confidence, details = self.policy.evaluate(layer_results, context or {})
        
        # Build governance headers
        governance_headers = {
            "X-Governance-Decision": decision,
            "X-Governance-Confidence": f"{confidence:.2f}",
            "X-Policy-Version": "1.0.0",
            "X-Rule-Set-Hash": self.rule_set_hash,
        }
        
        # Add layer details to headers
        layer_decisions = {lr.get("layer", f"layer_{i}"): lr.get("decision") 
                          for i, lr in enumerate(layer_results)}
        governance_headers["X-Layer-Decisions"] = json.dumps(layer_decisions)
        
        if "triggered_rule" in details:
            governance_headers["X-Governance-Trigger"] = details["triggered_rule"]
        
        return {
            "decision": decision,
            "confidence": round(confidence, 2),
            "details": details,
            "governance_headers": governance_headers,
            "layer_results": layer_results,
            "policy_version": "1.0.0",
            "rule_set_hash": self.rule_set_hash
        }
    
    def get_governance_headers(self, evaluation: Dict) -> Dict[str, str]:
        """Extract governance headers from evaluation result."""
        return evaluation.get("governance_headers", {})


# Global policy engine instance
POLICY_ENGINE = PolicyEngine()


def evaluate_policy(layer_results: List[Dict], context: Dict = None) -> Dict:
    """Convenience function for policy evaluation."""
    return POLICY_ENGINE.evaluate(layer_results, context)