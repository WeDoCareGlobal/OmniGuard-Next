"""
Input Normalizer
Handles bounded canonicalization, Unicode normalization, and encoding detection.
"""

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class NormalizedForms:
    """Container for all canonical forms of input text."""
    original: str = ""
    compact: str = ""                      # Whitespace-normalized, lowercased
    unicode_normalized: str = ""           # NFKC normalized
    unicode_compact: str = ""              # NFKC + compact
    base64_decoded: Optional[str] = None
    base64_compact: Optional[str] = None
    caesar_shifted: Dict[int, str] = field(default_factory=dict)
    rot13: Optional[str] = None
    decode_depth: int = 0
    encoding_attempts: List[str] = field(default_factory=list)


class InputNormalizer:
    """
    Bounded canonicalization and encoding detection.
    
    Produces multiple canonical forms of input for consistent pattern matching.
    All decoding is bounded to prevent resource exhaustion.
    """
    
    # Default configuration
    DEFAULT_CONFIG = {
        "max_decode_depth": 2,
        "max_base64_length": 5000,
        "enable_caesar": True,
        "caesar_shifts": [3, 13, 47],  # Common shifts
        "enable_rot13": True,
        "enable_unicode_norm": True,
        "unicode_form": "NFKC",
        "min_base64_length": 20,
        "max_total_decoded_length": 50000,
    }
    
    # Common encoding patterns
    BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
    HEX_PATTERN = re.compile(r'(?:0x)?[0-9a-fA-F]{40,}')
    URL_ENCODED_PATTERN = re.compile(r'%[0-9a-fA-F]{2}')
    UNICODE_ESCAPE_PATTERN = re.compile(r'\\u[0-9a-fA-F]{4}')

    def __init__(self, config: Optional[Dict] = None):
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}

    def normalize(self, text: str) -> NormalizedForms:
        """
        Produce all canonical forms of the input text.
        
        This is the main entry point - call once per request input.
        """
        forms = NormalizedForms(original=text)
        
        # 1. Compact form (whitespace normalized, lowercased)
        forms.compact = self._compact(text)
        
        # 2. Unicode normalization
        if self.config.get("enable_unicode_norm", True):
            forms.unicode_normalized = self._unicode_normalize(text)
            forms.unicode_compact = self._compact(forms.unicode_normalized)
        
        # 3. Base64 decoding (bounded)
        forms.base64_decoded, forms.base64_compact, forms.decode_depth = self._decode_base64_bounded(text)
        
        # 4. Caesar cipher variants
        if self.config.get("enable_caesar", True):
            for shift in self.config.get("caesar_shifts", [3, 13, 47]):
                forms.caesar_shifted[shift] = self._caesar_decode(text, shift) or ""
        
        # 5. ROT13
        if self.config.get("enable_rot13", True):
            forms.rot13 = self._rot13(text) or ""
        
        # Track encoding attempts for audit
        forms.encoding_attempts = self._detect_encodings(text)
        
        return forms

    def _compact(self, text: str) -> str:
        """Remove all whitespace and lowercase."""
        return re.sub(r'\s+', '', text.lower())

    def _unicode_normalize(self, text: str) -> str:
        """Apply Unicode NFKC normalization."""
        return unicodedata.normalize(self.config.get("unicode_form", "NFKC"), text)

    def _decode_base64_bounded(self, text: str) -> tuple:
        """
        Decode Base64 strings with strict bounds.
        
        Returns: (decoded_text, compact_decoded, decode_depth)
        """
        max_depth = self.config.get("max_decode_depth", 2)
        max_len = self.config.get("max_base64_length", 5000)
        max_total = self.config.get("max_total_decoded_length", 50000)
        min_len = self.config.get("min_base64_length", 20)
        
        decoded_texts = []
        decode_depth = 0
        current_text = text
        total_decoded = 0
        
        while decode_depth < max_depth:
            # Find potential Base64 strings
            b64_matches = self.BASE64_PATTERN.findall(current_text)
            
            if not b64_matches:
                break
            
            any_decoded = False
            for b64 in b64_matches:
                if len(b64) < min_len or len(b64) > max_len:
                    continue
                
                try:
                    decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                    if decoded and decoded != current_text:
                        if total_decoded + len(decoded) > max_total:
                            break
                        decoded_texts.append(decoded)
                        total_decoded += len(decoded)
                        any_decoded = True
                except Exception:
                    continue
            
            if not any_decoded:
                break
            
            current_text = " ".join(decoded_texts)
            decode_depth += 1
        
        if decoded_texts:
            combined = " ".join(decoded_texts)
            compact = re.sub(r'\s+', '', " ".join(decoded_texts).lower())
            return combined, compact, decode_depth
        
        return None, None, 0

    def _caesar_decode(self, text: str, shift: int) -> str:
        """Decode Caesar cipher with given shift."""
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)

    def _rot13(self, text: str) -> str:
        """Apply ROT13 transformation."""
        return self._caesar_decode(text, 13)

    def _detect_encodings(self, text: str) -> List[str]:
        """Detect what encodings are present in the text."""
        detected = []
        
        if self.BASE64_PATTERN.search(text):
            detected.append("base64")
        if self.HEX_PATTERN.search(text):
            detected.append("hex")
        if self.URL_ENCODED_PATTERN.search(text):
            detected.append("url_encoded")
        if self.UNICODE_ESCAPE_PATTERN.search(text):
            detected.append("unicode_escape")
        
        # Check for homoglyphs / zero-width chars
        if any(ord(c) in [0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060] for c in text):
            detected.append("zero_width_chars")
        
        # Check for excessive Unicode categories
        categories = set(unicodedata.category(c) for c in text)
        if len(categories) > 10:
            detected.append("mixed_scripts")
        
        return detected

    def get_all_forms_for_matching(self, forms: NormalizedForms) -> Dict[str, str]:
        """Get all forms as a flat dict for pattern matching."""
        result = {
            "original": forms.original,
            "compact": forms.compact,
            "unicode_normalized": forms.unicode_normalized,
            "unicode_compact": forms.unicode_compact,
        }
        
        if forms.base64_decoded:
            result["base64_decoded"] = forms.base64_decoded
            result["base64_compact"] = forms.base64_compact
        
        for shift, decoded in forms.caesar_shifted.items():
            result[f"caesar_{shift}"] = decoded
            result[f"caesar_{shift}_compact"] = re.sub(r'\s+', '', decoded.lower())
        
        if forms.rot13:
            result["rot13"] = forms.rot13
            result["rot13_compact"] = re.sub(r'\s+', '', forms.rot13.lower())
        
        return result