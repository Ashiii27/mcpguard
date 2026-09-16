# tests/echo_server.py
import sys
import json

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    resp = {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"ok": True}}
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()