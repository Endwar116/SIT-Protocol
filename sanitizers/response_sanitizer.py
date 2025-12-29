#!/usr/bin/env python3
"""SIT Protocol - Response Sanitizer (L4)"""

import json, re, uuid
from datetime import datetime
from typing import Any

SENSITIVE_PATTERNS = {
    "api_key": r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?[\w\-]{16,}",
    "password": r"(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?[^\s'\"]{6,}",
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "jwt": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
}

FORBIDDEN_FIELDS = {"password","secret","api_key","token","private_key","credentials","ssn","credit_card","raw_sql","system_prompt"}

class SITResponseSanitizer:
    def __init__(self):
        self.redactions = 0
        self.types = set()
    
    def sanitize(self, raw: Any, sit_state: dict) -> dict:
        self.redactions = 0
        self.types = set()
        data = self._clean(raw)
        return {
            "sit_version": "1.0",
            "data": data,
            "sanitization": {"redactions": self.redactions, "types": list(self.types)},
            "metadata": {"response_id": str(uuid.uuid4()), "timestamp": datetime.utcnow().isoformat()+"Z"}
        }
    
    def _clean(self, obj: Any) -> Any:
        if isinstance(obj, str):
            for name, pat in SENSITIVE_PATTERNS.items():
                if re.search(pat, obj):
                    obj = re.sub(pat, "[REDACTED]", obj)
                    self.redactions += 1
                    self.types.add(name)
            return obj
        elif isinstance(obj, dict):
            return {k: self._clean(v) for k, v in obj.items() if k.lower() not in FORBIDDEN_FIELDS}
        elif isinstance(obj, list):
            return [self._clean(i) for i in obj]
        return obj

if __name__ == "__main__":
    raw = {"user": {"name": "John", "email": "john@test.com", "password": "secret123"}, "msg": "key=sk-abc123def456"}
    print(json.dumps(SITResponseSanitizer().sanitize(raw, {}), indent=2))
