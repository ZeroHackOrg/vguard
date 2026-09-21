# src/vguard/governance.py
import math
import re
from dataclasses import dataclass
from typing import List


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\b(\+?\d{1,3}[-.\s]?)?(\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
AWS_ACCESS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
GENERIC_SECRET_RE = re.compile(r"\b(?:api[_-]?key|secret|token|password)[=:\s]+['\"]?([A-Za-z0-9_\-./+]{12,})", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    category: str
    value: str
    offset: int

    def to_dict(self) -> dict:
        return {"category": self.category, "value": self.value, "offset": self.offset}


class PIIPolicy:
    PATTERNS = {
        "email": EMAIL_RE,
        "phone": PHONE_RE,
        "ssn": SSN_RE,
        "ip_address": IP_RE,
        "aws_access_key": AWS_ACCESS_KEY_RE,
        "generic_secret": GENERIC_SECRET_RE,
    }

    def scan_text(self, text: str) -> List[Finding]:
        findings = []
        for category, pattern in self.PATTERNS.items():
            for match in pattern.finditer(text):
                findings.append(Finding(category=category, value=match.group(0), offset=match.start()))
        return findings

    def has_match(self, text: str) -> bool:
        return bool(self.scan_text(text))

    def redact(self, text: str, replacement: str = "[REDACTED]") -> str:
        redacted = text
        for pattern in self.PATTERNS.values():
            redacted = pattern.sub(replacement, redacted)
        return redacted


class SecretScanPolicy:
    def __init__(self, min_entropy: float = 3.0, min_length: int = 12):
        self.min_entropy = float(min_entropy)
        self.min_length = int(min_length)

    def is_high_entropy(self, token: str) -> bool:
        if len(token) < self.min_length:
            return False
        counts = {}
        for char in token:
            counts[char] = counts.get(char, 0) + 1
        length = len(token)
        entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
        return entropy >= self.min_entropy

    def scan_payload(self, details: dict) -> List[Finding]:
        findings = []
        for key, value in details.items():
            if isinstance(value, str) and self.is_high_entropy(value):
                findings.append(Finding(category="high_entropy_secret", value=key, offset=0))
        return findings