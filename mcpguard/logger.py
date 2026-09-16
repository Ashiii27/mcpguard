# mcpguard/logger.py
import json
import sys
import hashlib
import time
from typing import Any


_log_file = None


def init(path: str | None):
    global _log_file
    if path:
        _log_file = open(path, "a", buffering=1)


def _hash_args(arguments: dict) -> str:
    raw = json.dumps(arguments, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def log(event: str, tool_name: str, arguments: dict, verdict: dict | None, latency_ms: float):
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event,
        "tool": tool_name,
        "args_hash": _hash_args(arguments),
        "verdict": verdict,
        "latency_ms": round(latency_ms, 2),
    }
    line = json.dumps(entry)
    if _log_file:
        _log_file.write(line + "\n")
    else:
        print(line, file=sys.stderr)