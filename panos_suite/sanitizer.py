import re
from typing import Dict, List, Tuple

class TextSanitizer:
    IPV4_PATTERN = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:3[0-2]|[12]?[0-9]))?\b"

    def __init__(self, custom_redactions: List[str] = None):
        self.custom_terms = custom_redactions or []

    def sanitize(self, text: str) -> Tuple[str, Dict[str, str]]:
        redaction_map = {}
        sanitized_text = text

        ips = set(re.findall(self.IPV4_PATTERN, sanitized_text))
        for idx, ip in enumerate(sorted(ips, key=len, reverse=True), start=1):
            placeholder = f"[REDACTED_IP_{idx}]"
            redaction_map[placeholder] = ip
            sanitized_text = re.sub(re.escape(ip), placeholder, sanitized_text)

        for idx, term in enumerate(self.custom_terms, start=1):
            if term and term in sanitized_text:
                placeholder = f"[REDACTED_ENTITY_{idx}]"
                redaction_map[placeholder] = term
                sanitized_text = re.sub(re.escape(term), placeholder, sanitized_text)

        return sanitized_text, redaction_map
