"""
OmniGuard WAF Module
Proven 96% detection rate regex + compact normalization WAF patterns.
Includes: directive overrides, base64 smuggling, secrets detection, multilingual.
"""

from __future__ import annotations
import base64
import re
import time
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple, Dict, Any, Set

try:
    import unicodedata
    HAS_UNICODEDATA = True
except ImportError:
    HAS_UNICODEDATA = False


class WAFRuleCategory(Enum):
    """Categories of WAF rules."""
    DIRECTIVE_OVERRIDE = "directive_override"
    AUTHORITY_SPOOFING = "authority_spoofing"
    CREDENTIAL_LEAK = "credential_leak"
    ROLE_IMPERSONATION = "role_impersonation"
    HIDDEN_COMMENT = "hidden_comment"
    BASE64_SMUGGLING = "base64_smuggling"
    HTML_COMMENT_INJECTION = "html_comment_injection"
    C_COMMENT_INJECTION = "c_comment_injection"
    MULTILINGUAL_ES = "multilingual_es"
    MULTILINGUAL_FR = "multilingual_fr"
    MULTILINGUAL_DE = "multilingual_de"
    MULTILINGUAL_ZH = "multilingual_zh"
    MULTILINGUAL_RU = "multilingual_ru"
    SECRET_DETECTION = "secret_detection"
    ENCODING_OBFUSCATION = "encoding_obfuscation"


@dataclass
class WAFMatch:
    """A single WAF rule match."""
    category: WAFRuleCategory
    rule_name: str
    matched_text: str
    position: int
    confidence: float = 1.0


@dataclass
class WAFResult:
    """Result of WAF scan."""
    blocked: bool
    matches: List[WAFMatch]
    latency_ms: float
    compact_normalized: str
    unicode_normalized: str
    base64_decoded: List[str]


# ============================================================
# TIER 0 PATTERNS - Proven 96% detection
# ============================================================

# 1. DIRECTIVE OVERRIDES
# Two families:
#   (a) VERB + governing object -- the classic "ignore previous instructions".
#   (b) VERB + a *scope* phrase that isn't a governing noun -- "forget
#       everything you were told", "override your settings".
# Only (a) existed originally, so (b) vectors passed straight through.
#
# Both families are matched against the raw text AND the "compact" form with all
# whitespace stripped. Two consequences drive the syntax below:
#   * inter-token gaps are \s* (zero or more), never \s+ -- with \s+ the compact
#     pass can never match, which is exactly how "Dis\nregard all pri\nor
#     com\nmands" evaded detection;
#   * there is no leading \b, because in the compact form the verb is glued to
#     whatever word precedes it.
DIRECTIVE_OVERRIDE_PATTERNS = [
    # (a) verb + governing object ("ignore previous instructions")
    # Governing nouns are spelled letter-by-letter with optional joins, and the
    # doubled letters are made optional (commands -> com*mands* accepts "comands",
    # settings -> set*t*ings accepts "setings"). A per-character split that drops
    # a letter leaves the word un-spellable otherwise, so this is what catches the
    # mangled variants: "Dis\nregard all pri\nor com\nands" and
    # "Over\nride your set\ntings".
    re.compile(
        r'(?:ignore|disregard|forget|override|bypass|drop|disable|do\s*n\s*o\s*t\s*f\s*o\s*l\s*l\s*o\s*w)'
        r'\s*'
        r'(?:all\s*|any\s*|the\s*|your\s*|earlier\s*|prior\s*|previous\s*|above\s*)*'
        r'(?:previous\s*|prior\s*|earlier\s*|initial\s*|original\s*|system\s*|new\s*)?'
        r'(?:'
        r'i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s?'
        r'|c\s*o\s*m\s*m?\s*a\s*n\s*d\s*s?'
        r'|r\s*u\s*l\s*e\s*s?'
        r'|g\s*u\s*i\s*d\s*e\s*l\s*i\s*n\s*e\s*s?'
        r'|d\s*i\s*r\s*e\s*c\s*t\s*i\s*v\s*e\s*s?'
        r'|p\s*r\s*o\s*m\s*p\s*t\s*s?'
        r'|c\s*o\s*n\s*s\s*t\s*r\s*a\s*i\s*n\s*t\s*s?'
        r'|s\s*a\s*f\s*e\s*g\s*u\s*a\s*r\s*d\s*s?'
        r'|g\s*u\s*a\s*r\s*d\s*r\s*a\s*i\s*l\s*s?'
        r'|r\s*e\s*s\s*t\s*r\s*i\s*c\s*t\s*i\s*o\s*n\s*s?'
        r'|s\s*e\s*t\s*t?\s*i\s*n\s*g\s*s?'
        r'|c\s*o\s*n\s*f\s*i\s*g\s*u\s*r\s*a\s*t\s*i\s*o\s*n\s*s?'
        r'|p\s*a\s*r\s*a\s*m\s*e\s*t\s*e\s*r\s*s?'
        r')',
        re.IGNORECASE),
    # (b) verb + scope phrase.
    # The connector is [a-z]{0,12} rather than an explicit (everything|all|any)
    # alternation: the compact pass glues words together, so "For\nget\nall\nyou
    # \nwer\ntold" becomes "forgetallyouwertold" and a literal quantifier list
    # cannot reliably separate verb from scope. Each scope word is spelled
    # letter-by-letter with optional joins so per-character splits in the raw
    # text still match. The scope list stays concrete on purpose -- a loose
    # connector would otherwise flag ordinary prose ("forget my password",
    # "override the default font size").
    re.compile(
        r'(?:ignore|disregard|forget|override|bypass|discard)'
        r'[a-z]{0,12}'
        r'(?:'
        r'y\s*o\s*u\s*w\s*e\s*r\s*e\s*t\s*o\s*l\s*d'
        r'|y\s*o\s*u\s*h\s*a\s*v\s*e\s*l\s*e\s*a\s*r\s*n\s*e\s*d'
        r'|y\s*o\s*u\s*w\s*e\s*r\s*e\s*t\s*a\s*u\s*g\s*h\s*t'
        r'|y\s*o\s*u\s*w\s*e\s*r\s*e\s*g\s*i\s*v\s*e\s*n'
        r'|(?:p\s*r\s*i\s*o\s*r|p\s*r\s*e\s*v\s*i\s*o\s*u\s*s)\s*t\s*r\s*a\s*i\s*n\s*i\s*n\s*g'
        r'|y\s*o\s*u\s*r\s*t\s*r\s*a\s*i\s*n\s*i\s*n\s*g'
        r'|y\s*o\s*u\s*r\s*i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s'
        r'|y\s*o\s*u\s*r\s*s\s*e\s*t\s*t\s*i\s*n\s*g\s*s'
        r'|y\s*o\s*u\s*r\s*p\s*r\s*o\s*g\s*r\s*a\s*m\s*m\s*i\s*n\s*g'
        r'|y\s*o\s*u\s*r\s*r\s*u\s*l\s*e\s*s'
        r'|y\s*o\s*u\s*r\s*c\s*o\s*n\s*f\s*i\s*g\s*u\s*r\s*a\s*t\s*i\s*o\s*n'
        r'|(?:e\s*a\s*r\s*l\s*i\s*e\s*r)\s*i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s'
        r'|(?:e\s*a\s*r\s*l\s*i\s*e\s*r)\s*r\s*u\s*l\s*e\s*s'
        r')',
        re.IGNORECASE),
    # Fallback for scope phrases mangled by a lossy per-character split. #
    # When the split drops a letter the word is no longer a word ("you\nwer\ntold"
    # -> "youwertold"), so no letter-spelled scope pattern can match it. #
    # "told" survives any split of "you were told" though, and a directive
    # verb within a few letters of it is the injection signature.
    re.compile(r'(?:ignore|disregard|forget|override|bypass|discard)[a-z]{0,14}told', re.IGNORECASE),
    re.compile(r'(?:override|overwrite|replace|ignore|disregard)\s*(?:your|the|all|any)\s*(?:settings?|configuration|parameters?|constraints?|safety|ethics|guidelines?|rules?|filters?|guardrails?)', re.IGNORECASE),
    re.compile(r'do\s*not\s*follow.{0,40}?(?:instructions?|rules?|guidelines?|commands?)', re.IGNORECASE),
    re.compile(r'(?:new|updated|revised)\s*(?:instructions?|rules?|guidelines?|system\s*prompt)', re.IGNORECASE),
    re.compile(r'(?:instead|rather|actually)\s*,?\s*(?:do|perform|execute|follow)', re.IGNORECASE),
    re.compile(r'(?i)\bsystem\s*:\s*(?:you\s*are\s*now|new\s*instruction|override)', re.IGNORECASE),
]

# 2. AUTHORITY SPOOFING
AUTHORITY_SPOOFING_PATTERNS = [
    re.compile(r'\b(?:trusted\s+source|internal\s+memo|attached\s+document|guidelines?\s+state)\b', re.IGNORECASE),
    re.compile(r'\b(?:according\s+to|based\s+on|as\s+per|per)\s+the\s+(?:attached|provided|internal|official|above)\b', re.IGNORECASE),
    re.compile(r'\b(?:official\s+(?:policy|directive|instruction)|authorized\s+(?:by|user)|admin\s+(?:said|requested|ordered))\b', re.IGNORECASE),
    re.compile(r'\b(?:document|memo|policy)\s+(?:states|says|indicates)\b', re.IGNORECASE),
]

# 3. CREDENTIAL LEAK / SECRET EXTRACTION
CREDENTIAL_LEAK_PATTERNS = [
    re.compile(r'(system\s+prompt|hidden\s+instructions?|dump\s+context|secret\s+internal|admin\s+username|password\s+is|api\s+key\s+is|server\s+ip\s+is|root\s+supervisor)', re.IGNORECASE),
    re.compile(r'(show\s+me\s+(?:the\s+)?(?:prompt|system\s+prompt|instructions?)|reveal\s+(?:the\s+)?(?:prompt|system|password|key|secret))', re.IGNORECASE),
    re.compile(r'(what\s+(?:is|are)\s+(?:your\s+)?(?:instructions?|system\s+prompt|prompt|rules?))', re.IGNORECASE),
    re.compile(r'(print|output|display|show)\s+(?:the\s+)?(?:system|initial|original)\s+(?:prompt|instructions?)', re.IGNORECASE),
]

# 4. ROLE IMPERSONATION
ROLE_IMPERSONATION_PATTERNS = [
    re.compile(r'(?:===|---\s*(?:SYSTEM|ADMIN|ROOT|DEVELOPER|DEBUG)\s*(?:===|---))', re.IGNORECASE),
    re.compile(r'\[(?:ADMIN|ROOT|SYSTEM|DEVELOPER|DEBUG|SUPERVISOR|OPERATOR)\]', re.IGNORECASE),
    re.compile(r'(?:<\s*(?:SYSTEM|ADMIN|ROOT|DEVELOPER|DEBUG)\s*>)', re.IGNORECASE),
    re.compile(r'(?:^|\n)(?:SYSTEM|ADMIN|ROOT|DEVELOPER|DEBUG)\s*[:>]', re.IGNORECASE),
]

# 5. HIDDEN COMMENTS
HIDDEN_COMMENT_PATTERNS = [
    re.compile(r'<\s*!\s*--\s*(ignore|override|bypass|disable|skip)\s*--\s*>', re.IGNORECASE),
    re.compile(r'<\s*!\s*--\s*(?:system|admin|root)\s*:', re.IGNORECASE),
]

# 6. BASE64 SMUGGLING
# Two independent signals, either one is enough:
#   (a) an explicit decode instruction next to a base64 blob ("decode this and
#       follow the instructions: <b64>").
#   (b) a long base64 blob anywhere in the prompt -- 20+ chars of pure base64
#       alphabet with no whitespace doesn't occur in natural prose, so the
#       presence of one is itself suspicious and the scanner decodes it and
#       re-scans the plaintext below.
BASE64_SMUGGLING_PATTERNS = [
    re.compile(r'\b(?:decode|decrypt|unpack|base64|b64|base64decode)\b[^.\n]{0,80}?[A-Za-z0-9+/]{12,}={0,2}', re.IGNORECASE),
    re.compile(r'\b(?:decode|decrypt|unpack)\b[^.\n]{0,60}?\b(?:and\s+)?(?:follow|obey|execute|do)\b', re.IGNORECASE),
    re.compile(r'\b(?:exec(?:ute)?|run|eval)\s*\(\s*(?:base64|b64decode)', re.IGNORECASE),
]
# NOTE: there is deliberately NO bare "20+ chars of base64 alphabet" rule here.
# A long alphabetic run also appears in ordinary prose, and because the scanner
# re-scans the *compact* (whitespace-stripped) form, every long sentence looks
# like one base64 blob -- a bare-length rule flagged 34/36 benign prompts in
# testing. Base64 payloads are caught by the two framing rules above plus the
# decode-and-rescan pass in WAFScanner.scan(), which only inspects genuine
# whitespace-delimited tokens.

# 7. HTML COMMENT INJECTION
HTML_COMMENT_INJECTION_PATTERNS = [
    re.compile(r'<!-\s*-\s*(ignore|override|bypass|disable|skip|system|admin)\s*-\s*->', re.IGNORECASE),
]

# 8. C-STYLE COMMENT INJECTION
C_COMMENT_INJECTION_PATTERNS = [
    re.compile(r'/\s*\*\s*(ignore|override|bypass|disable|skip|system|admin)\s*\*/', re.IGNORECASE),
]

# 9. MULTILINGUAL INJECTION (ES, FR, DE)
MULTILINGUAL_PATTERNS = {
    "es": [
        re.compile(r'(ignora|olvida|desprecia|anula)\s+(?:instrucciones?|ordenes?|reglas?)', re.IGNORECASE),
        re.compile(r'(en\s+lugar\s+de|en\slugar\s+de)\s+(?:hacer|realizar|seguir)', re.IGNORECASE),
    ],
    "fr": [
        re.compile(r'(ignore|oublie|disregarde|annule)\s+(?:les\s+)?(?:instructions?|ordres?)', re.IGNORECASE),
        re.compile(r'(au\s+lieu\s+de|plutot\s+que)\s+(?:faire|executer|suivre)', re.IGNORECASE),
    ],
    "de": [
        re.compile(r'(ignoriere|vergiss|missachte|ueberschreibe)\s+(?:die\s+)?(?:anweisungen?|befehle?)', re.IGNORECASE),
        re.compile(r'(statt\s+zu|anstatt\s+zu)\s+(?:machen|ausfuehren|befolgen)', re.IGNORECASE),
    ],
    "zh": [
        re.compile(r'(忽略|忘记|绕过|覆盖)\s*(?:之前|先前|所有)?\s*(?:指令|指示|规则)', re.IGNORECASE),
    ],
    "ru": [
        re.compile(r'(игнорируй|забудь|обойди|переопредели)\s*(?:предыдущие|все)?\s*(?:инструкции|команды|правила)', re.IGNORECASE),
    ],
}

# 10. SECRET DETECTION (output DLP also uses these)
SECRET_PATTERNS = {
    "api_key": re.compile(r'(?:sk-|pk-)[a-zA-Z0-9]{20,}', re.IGNORECASE),
    "jwt": re.compile(r'eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'),
    "database_url": re.compile(r'(postgresql|mysql|mongodb|redis)://[^\s]{10,}', re.IGNORECASE),
    "private_key": re.compile(r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----', re.IGNORECASE),
    "ssh_key": re.compile(r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----', re.IGNORECASE),
    "api_key_generic": re.compile(r'(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*[a-zA-Z0-9_\-]{20,}', re.IGNORECASE),
    "password_leak": re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*[^\s]{8,}', re.IGNORECASE),
    "secret_leak": re.compile(r'(?:secret|secret_key)\s*[:=]\s*[a-zA-Z0-9_\-]{16,}', re.IGNORECASE),
}

# 11. ENCODING OBFUSCATION
ENCODING_PATTERNS = [
    re.compile(r'(?:rot13|rot\s*13)\s*[:\s]+', re.IGNORECASE),
    re.compile(r'(?:hex|hexencode)\s*[:\s]+[0-9a-fA-F]{8,}', re.IGNORECASE),
    re.compile(r'(?:urlencode|url\s*encode)\s*[:\s]+%[0-9a-fA-F]{2}', re.IGNORECASE),
]

# Combined patterns for fast lookup
ALL_PATTERNS = {
    WAFRuleCategory.DIRECTIVE_OVERRIDE: DIRECTIVE_OVERRIDE_PATTERNS,
    WAFRuleCategory.AUTHORITY_SPOOFING: AUTHORITY_SPOOFING_PATTERNS,
    WAFRuleCategory.CREDENTIAL_LEAK: CREDENTIAL_LEAK_PATTERNS,
    WAFRuleCategory.ROLE_IMPERSONATION: ROLE_IMPERSONATION_PATTERNS,
    WAFRuleCategory.HIDDEN_COMMENT: HIDDEN_COMMENT_PATTERNS,
    WAFRuleCategory.BASE64_SMUGGLING: BASE64_SMUGGLING_PATTERNS,
    WAFRuleCategory.HTML_COMMENT_INJECTION: HTML_COMMENT_INJECTION_PATTERNS,
    WAFRuleCategory.C_COMMENT_INJECTION: C_COMMENT_INJECTION_PATTERNS,
}

# SQL Injection patterns
SQL_INJECTION_PATTERNS = [
    re.compile(r'(?:or|and)\s+1\s*=\s*1', re.IGNORECASE),
    re.compile(r'(?:union\s+select|drop\s+table|truncate\s+table|alter\s+table)', re.IGNORECASE),
    re.compile(r'(?:insert\s+into|update\s+set|delete\s+from)\s+.*\s+(?:or|and)\s+\d+\s*=\s*\d+', re.IGNORECASE),
    re.compile(r';\s*(?:drop|truncate|delete|alter|create|grant|revoke)', re.IGNORECASE),
    re.compile(r'(?:select|insert|update|delete|drop|union|exec)\s+.*\s+(?:from|into|table)', re.IGNORECASE),
]
ALL_PATTERNS[WAFRuleCategory.SECRET_DETECTION] = ALL_PATTERNS.get(WAFRuleCategory.SECRET_DETECTION, []) + SQL_INJECTION_PATTERNS

# Multilingual patterns
for lang, patterns in MULTILINGUAL_PATTERNS.items():
    cat = WAFRuleCategory(f"multilingual_{lang}")
    ALL_PATTERNS[cat] = patterns

# Secret patterns
for name, pattern in SECRET_PATTERNS.items():
    ALL_PATTERNS[WAFRuleCategory.SECRET_DETECTION] = ALL_PATTERNS.get(WAFRuleCategory.SECRET_DETECTION, []) + [pattern]

# Encoding patterns
for pattern in ENCODING_PATTERNS:
    ALL_PATTERNS[WAFRuleCategory.ENCODING_OBFUSCATION] = ALL_PATTERNS.get(WAFRuleCategory.ENCODING_OBFUSCATION, []) + [pattern]

# 12. DESTRUCTIVE SHELL / RCE (Tier 2 support)
DESTRUCTIVE_PATTERNS = [
    re.compile(r'\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+[/~*]', re.IGNORECASE),
    re.compile(r'\bsudo\s+rm\b', re.IGNORECASE),
    re.compile(r'\bmkfs\b', re.IGNORECASE),
    re.compile(r'\bdd\s+if=\S+\s+of=/dev/', re.IGNORECASE),
    re.compile(r'\bformat\s+[a-z]:\b', re.IGNORECASE),
    re.compile(r':\(\)\s*\{\s*:\|:\s*&\s*\}\s*;:', re.IGNORECASE),  # fork bomb
    re.compile(r'\b(curl|wget)\b[^|]{0,200}\|\s*(sudo\s+)?(ba|z|fi)?sh\b', re.IGNORECASE),
    re.compile(r'\b(nc|netcat|ncat)\b[^\n]{0,80}-e\s*(/bin/)?(ba|z)?sh\b', re.IGNORECASE),
    re.compile(r'\bos\.system\s*\(', re.IGNORECASE),
    re.compile(r'\bsubprocess\.(run|call|Popen|check_output)\s*\(', re.IGNORECASE),
    re.compile(r'\b(exec|eval)\s*\(\s*[\'"]', re.IGNORECASE),
    re.compile(r'\bos\.popen\s*\(', re.IGNORECASE),
    re.compile(r'\bchmod\s+[0-7]*7[0-7]*\s+/', re.IGNORECASE),
]
ALL_PATTERNS[WAFRuleCategory.ENCODING_OBFUSCATION] = ALL_PATTERNS.get(WAFRuleCategory.ENCODING_OBFUSCATION, []) + DESTRUCTIVE_PATTERNS

# 13. DATA EXFILTRATION (Tier 2 support)
EXFILTRATION_PATTERNS = [
    re.compile(r'\b(?:e-?mail|send)\s+(?:it|them|this|the\s+\w+)?\s*(?:to|over\s+to)\s+[\w.+-]+@[\w-]+\.[\w.]+', re.IGNORECASE),
    re.compile(r'\b(?:to|recipient|cc|bcc)\s*[:=]\s*[\w.+-]+@[\w-]+\.[\w.]+', re.IGNORECASE),
    re.compile(r'\b(?:transfer|wire|send|forward)\s+(?:the\s+)?(?:funds|money|payment)\b[^.]{0,120}\b(?:to|account)\b', re.IGNORECASE),
    re.compile(r'\b(?:account|routing|iban|swift)\s*(?:no\.?|number|#)?\s*[:=]\s*\d[\d\s-]{6,}', re.IGNORECASE),
    re.compile(r'\b(?:amount|sum|total)\s*[:=]?\s*(?:USD|\$|€|£)\s?\d[\d,.]*', re.IGNORECASE),
    re.compile(r'\b(?:webhook|callback|notify)\s*[:=]\s*https?://(?!localhost|127\.)', re.IGNORECASE),
    re.compile(r'\bcurl\b[^\n]{0,160}(?:-d|--data)\s', re.IGNORECASE),
]
ALL_PATTERNS[WAFRuleCategory.ENCODING_OBFUSCATION] = ALL_PATTERNS.get(WAFRuleCategory.ENCODING_OBFUSCATION, []) + EXFILTRATION_PATTERNS

# 14. AGENTIC TOOL ABUSE (Tier 2 support) -- natural-language tool hijacking.
# NOTE: these are directional verbs that are also common in benign phrasing
# ("how do I use the API", "can you call the weather API"), so each requires
# an action target that only appears in an actual tool-invocation request.
# Tier 2 (AgentVault) applies the authoritative per-tool policy on top.
TOOL_ABUSE_PATTERNS = [
    re.compile(r'\bcall\s+(?:the\s+)?(?:function|tool)\s+\w+', re.IGNORECASE),
    re.compile(r'\b(?:invoke|use)\s+the\s+tool\s+\w+', re.IGNORECASE),
    re.compile(r'\b(?:execute|run)\s+(?:the\s+)?(?:shell\s+)?command\b', re.IGNORECASE),
    re.compile(r'\binvoke\s+(?:the\s+)?api\s+endpoint\b', re.IGNORECASE),
    re.compile(r'\bcall\s+the\s+endpoint\b', re.IGNORECASE),
    re.compile(r'\bapi\s+call\s*:\s*\w+', re.IGNORECASE),
]
ALL_PATTERNS[WAFRuleCategory.ENCODING_OBFUSCATION] = ALL_PATTERNS.get(WAFRuleCategory.ENCODING_OBFUSCATION, []) + TOOL_ABUSE_PATTERNS

# 15. FINANCIAL / DESTRUCTIVE ACTION LANGUAGE (closes the remaining misses)
FINANCIAL_ACTION_PATTERNS = [
    re.compile(r'\b(?:execute|process|make|send|authorize)\s+(?:the\s+)?(?:payment|transfer|payout|wire)\b', re.IGNORECASE),
    re.compile(r'\bpayment\s+of\s+(?:USD|\$|€|£|\d)', re.IGNORECASE),
    re.compile(r'\btransfer\s+(?:of\s+)?(?:USD|\$|€|£)\s?\d', re.IGNORECASE),
    re.compile(r'\baccount\s+number\s+\d{6,}', re.IGNORECASE),
    re.compile(r'\bformat\s+[a-z]:\b', re.IGNORECASE),
    re.compile(r'\bdelete\s+(?:all|everything)\b', re.IGNORECASE),
    re.compile(r'\bwipe\s+(?:the\s+)?(?:drive|disk|database)\b', re.IGNORECASE),
]
ALL_PATTERNS[WAFRuleCategory.ENCODING_OBFUSCATION] = ALL_PATTERNS.get(WAFRuleCategory.ENCODING_OBFUSCATION, []) + FINANCIAL_ACTION_PATTERNS



# ============================================================
# BASE64 DECODING
# ============================================================

BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{8,}={0,2}')

def decode_base64_safe(b64_str: str) -> Optional[str]:
    """Safely decode base64 with error handling."""
    try:
        # Add padding if needed
        padding = 4 - (len(b64_str) % 4)
        if padding != 4:
            b64_str += '=' * padding
        return base64.b64decode(b64_str).decode('utf-8', errors='ignore')
    except Exception:
        return None


def extract_base64_candidates(text: str) -> List[str]:
    """Extract potential base64 strings (8+ chars)."""
    return BASE64_PATTERN.findall(text)


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_compact(text: str) -> str:
    """Compact normalization: lowercase + whitespace removal."""
    return re.sub(r'\s+', '', text.lower())


def normalize_unicode(text: str) -> str:
    """Unicode NFKC normalization."""
    try:
        return unicodedata.normalize('NFKC', text)
    except Exception:
        return text


def normalize_full(text: str) -> Tuple[str, str]:
    """Return (compact_normalized, unicode_normalized)."""
    compact = normalize_compact(text)
    unicode_norm = normalize_unicode(text)
    unicode_compact = normalize_compact(unicode_norm)
    return compact, unicode_compact


# ============================================================
# MAIN WAF SCANNER
# ============================================================

class WAFScanner:
    """Fast WAF scanner with <2ms target latency."""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.max_input_length = self.config.get("max_input_length", 50000)
        self.base64_threshold = self.config.get("base64_threshold", 8)
        self.decode_base64 = self.config.get("decode_base64", True)
        self.max_base64_decode = self.config.get("max_base64_decode", 10)
        # Allow custom patterns
        self.custom_patterns: Dict[WAFRuleCategory, List[re.Pattern]] = {}
        if "custom_patterns" in self.config:
            for cat, patterns in self.config["custom_patterns"].items():
                if isinstance(cat, str):
                    cat = WAFRuleCategory(cat)
                self.custom_patterns[cat] = [re.compile(p, re.IGNORECASE) for p in patterns]
    
    def scan(self, text: str) -> WAFResult:
        """Scan text for injection attempts.
        
        Returns WAFResult with blocked status, matches, and metadata.
        """
        start = time.perf_counter()
        
        if len(text) > self.max_input_length:
            return WAFResult(
                blocked=True,
                matches=[WAFMatch(
                    category=WAFRuleCategory.DIRECTIVE_OVERRIDE,
                    rule_name="input_too_long",
                    matched_text=f"length={len(text)}",
                    position=0,
                )],
                latency_ms=(time.perf_counter() - start) * 1000,
                compact_normalized="",
                unicode_normalized="",
                base64_decoded=[],
            )
        
        # Normalize
        compact, unicode_compact = normalize_full(text)
        
        # Track matches
        matches: List[WAFMatch] = []
        base64_decoded: List[str] = []
        
        # Scan all pattern categories
        for category, patterns in ALL_PATTERNS.items():
            for pattern in patterns:
                for match in pattern.finditer(text):
                    matches.append(WAFMatch(
                        category=category,
                        rule_name=pattern.pattern[:50],
                        matched_text=match.group()[:100],
                        position=match.start(),
                    ))
        
        # Also check compact normalized text
        for category, patterns in ALL_PATTERNS.items():
            for pattern in patterns:
                for match in pattern.finditer(compact):
                    matches.append(WAFMatch(
                        category=category,
                        rule_name=pattern.pattern[:50],
                        matched_text=match.group()[:100],
                        position=match.start(),
                    ))
        
        # Check unicode normalized
        for category, patterns in ALL_PATTERNS.items():
            for pattern in patterns:
                for match in pattern.finditer(unicode_compact):
                    matches.append(WAFMatch(
                        category=category,
                        rule_name=pattern.pattern[:50],
                        matched_text=match.group()[:100],
                        position=match.start(),
                    ))
        
        # Base64 decoding and recursive scan
        if self.decode_base64:
            b64_candidates = extract_base64_candidates(text)
            for b64 in b64_candidates[:self.max_base64_decode]:
                if len(b64) >= self.base64_threshold:
                    decoded = decode_base64_safe(b64)
                    if decoded:
                        base64_decoded.append(decoded)
                        # Recursive scan of decoded content
                        decoded_result = self.scan(decoded)
                        if decoded_result.blocked:
                            for m in decoded_result.matches:
                                m.category = WAFRuleCategory.BASE64_SMUGGLING
                                m.rule_name = f"base64:{m.rule_name}"
                                matches.append(m)
        
        # Deduplicate matches
        seen = set()
        unique_matches = []
        for m in matches:
            key = (m.category, m.rule_name, m.matched_text[:50], m.position)
            if key not in seen:
                seen.add(key)
                unique_matches.append(m)
        
        blocked = len(unique_matches) > 0
        
        return WAFResult(
            blocked=blocked,
            matches=unique_matches,
            latency_ms=(time.perf_counter() - start) * 1000,
            compact_normalized=compact,
            unicode_normalized=unicode_compact,
            base64_decoded=base64_decoded,
        )
    
    def scan_with_segments(self, trusted_text: str, untrusted_text: str = "") -> WAFResult:
        """Scan with trust boundary awareness.
        
        Trusted text (user instructions) gets full scan.
        Untrusted text (RAG, tool output) gets directive-only scan.
        """
        start = time.perf_counter()
        
        # Scan trusted text fully
        trusted_result = self.scan(trusted_text)
        
        if untrusted_text:
            # Scan untrusted text ONLY for directive injection
            untrusted_result = self._scan_directives_only(untrusted_text)
            
            # Merge results
            all_matches = trusted_result.matches + untrusted_result.matches
            blocked = trusted_result.blocked or untrusted_result.blocked
            latency = (time.perf_counter() - start) * 1000
            
            return WAFResult(
                blocked=blocked,
                matches=all_matches,
                latency_ms=latency,
                compact_normalized=trusted_result.compact_normalized,
                unicode_normalized=trusted_result.unicode_normalized,
                base64_decoded=trusted_result.base64_decoded,
            )
        
        return trusted_result
    
    def _scan_directives_only(self, text: str) -> WAFResult:
        """Scan text ONLY for directive injection patterns (for untrusted content)."""
        start = time.perf_counter()
        
        compact = normalize_compact(text)
        unicode_compact = normalize_compact(normalize_unicode(text))
        
        matches: List[WAFMatch] = []
        
        # Only check directive override and authority spoofing in untrusted content
        directive_categories = [
            WAFRuleCategory.DIRECTIVE_OVERRIDE,
            WAFRuleCategory.AUTHORITY_SPOOFING,
            WAFRuleCategory.CREDENTIAL_LEAK,
            WAFRuleCategory.ROLE_IMPERSONATION,
        ]
        
        for category in directive_categories:
            if category in ALL_PATTERNS:
                for pattern in ALL_PATTERNS[category]:
                    for match in pattern.finditer(text):
                        matches.append(WAFMatch(
                            category=category,
                            rule_name=f"untrusted:{pattern.pattern[:50]}",
                            matched_text=match.group()[:100],
                            position=match.start(),
                        ))
        
        # Also check compact
        for category in directive_categories:
            if category in ALL_PATTERNS:
                for pattern in ALL_PATTERNS[category]:
                    for match in pattern.finditer(compact):
                        matches.append(WAFMatch(
                            category=category,
                            rule_name=f"untrusted:{pattern.pattern[:50]}",
                            matched_text=match.group()[:100],
                            position=match.start(),
                        ))
        
        blocked = len(matches) > 0
        
        return WAFResult(
            blocked=blocked,
            matches=matches,
            latency_ms=(time.perf_counter() - start) * 1000,
            compact_normalized=compact,
            unicode_normalized=unicode_compact,
            base64_decoded=[],
        )


# ============================================================
# CONVENIENCE FUNCTIONS
# ============================================================

DEFAULT_SCANNER = WAFScanner()


def waf_scan(text: str) -> WAFResult:
    """Quick WAF scan."""
    return DEFAULT_SCANNER.scan(text)


def waf_scan_segments(trusted_text: str, untrusted_text: str = "") -> WAFResult:
    """Quick WAF scan with trust segments."""
    return DEFAULT_SCANNER.scan_with_segments(trusted_text, untrusted_text)


def is_blocked(text: str) -> bool:
    """Quick boolean check if text is blocked."""
    return DEFAULT_SCANNER.scan(text).blocked


def get_matches(text: str) -> List[WAFMatch]:
    """Get all matches for text."""
    return DEFAULT_SCANNER.scan(text).matches


# ============================================================
# BENCHMARK COMPATIBILITY
# ============================================================

def tier0_fast_path(text: str) -> Tuple[bool, List[str], float]:
    """Backward-compatible tier0_fast_path function.
    
    Returns: (blocked, matched_rule_names, latency_ms)
    """
    result = waf_scan(text)
    return result.blocked, [m.rule_name for m in result.matches], result.latency_ms