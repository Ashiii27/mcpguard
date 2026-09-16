# mcpguard/detectors/secrets.py
import re
import math
from typing import Any

PATTERNS = [
    ("aws_access_key",     re.compile(r'AKIA[0-9A-Z]{16}')),
    ("aws_secret_key",     re.compile(r'(?i)aws.{0,20}secret.{0,20}[\'"]([A-Za-z0-9/+=]{40})[\'"]')),
    ("github_token",       re.compile(r'gh[pousr]_[A-Za-z0-9]{36,}')),
    ("openai_key",         re.compile(r'sk-[A-Za-z0-9]{32,}')),
    ("anthropic_key",      re.compile(r'sk-ant-[A-Za-z0-9\-]{32,}')),
    ("generic_bearer",     re.compile(r'(?i)bearer\s+[A-Za-z0-9\-_.]{20,}')),
    ("generic_api_key",    re.compile(r'(?i)(api_key|apikey|api-key)\s*[=:]\s*[\'"]?([A-Za-z0-9\-_.]{20,})[\'"]?')),
    ("private_key_block",  re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----')),
]

ENTROPY_THRESHOLD = 4.5
MIN_LENGTH = 20


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def _extract_strings(obj: Any) -> list[str]:
    results = []
    if isinstance(obj, str):
        results.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            results.extend(_extract_strings(v))
    elif isinstance(obj, list):
        for item in obj:
            results.extend(_extract_strings(item))
    return results


def detect(arguments: dict) -> dict | None:
    strings = _extract_strings(arguments)

    for s in strings:
        for name, pattern in PATTERNS:
            if pattern.search(s):
                return {
                    "rule": "secret_leak",
                    "detail": f"pattern matched: {name}",
                }

    for s in strings:
        tokens = re.findall(r'[A-Za-z0-9+/=_\-]{%d,}' % MIN_LENGTH, s)
        for token in tokens:
            if _shannon_entropy(token) >= ENTROPY_THRESHOLD:
                return {
                    "rule": "secret_leak",
                    "detail": f"high-entropy string detected (entropy={_shannon_entropy(token):.2f})",
                }

    return None