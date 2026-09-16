# mcpguard/detectors/injection.py
import re
from typing import Any

PATTERNS = [
    re.compile(r'(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions?'),
    re.compile(r'(?i)disregard\s+(your|all|the)\s+(previous|prior|above|system)'),
    re.compile(r'(?i)you\s+are\s+now\s+(a|an|the)\s+\w+'),
    re.compile(r'(?i)act\s+as\s+(if\s+you\s+are|a|an)\s+\w+'),
    re.compile(r'(?i)new\s+(instruction|directive|prompt|system\s+prompt)'),
    re.compile(r'(?i)forget\s+(everything|all|your\s+instructions?)'),
    re.compile(r'(?i)jailbreak'),
    re.compile(r'(?i)do\s+anything\s+now'),
    re.compile(r'(?i)prompt\s+injection'),
    re.compile(r'(?i)<\s*system\s*>'),
    re.compile(r'(?i)\[system\]'),
    re.compile(r'(?i)###\s*(instruction|system|prompt)'),
]

LONG_STRING_THRESHOLD = 2000


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
        for pattern in PATTERNS:
            if pattern.search(s):
                return {
                    "rule": "prompt_injection",
                    "detail": f"matched pattern: {pattern.pattern}",
                }

    for s in strings:
        if len(s) >= LONG_STRING_THRESHOLD:
            return {
                "rule": "prompt_injection",
                "detail": f"suspiciously long string argument ({len(s)} chars), possible context stuffing",
            }

    return None