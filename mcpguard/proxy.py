# mcpguard/proxy.py
import json
import subprocess
import sys
import threading
import time
from mcpguard import pipeline, logger


def _read_message(stream) -> dict | None:
    try:
        line = stream.readline()
        if not line:
            return None
        return json.loads(line.decode())
    except (json.JSONDecodeError, OSError):
        return None


def _write_message(stream, message: dict):
    line = json.dumps(message).encode() + b"\n"
    stream.write(line)
    stream.flush()


def _error_response(req_id, code: int, message: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": code, "message": message},
    }


def _forward_responses(server_proc, dry_run: bool):
    while True:
        msg = _read_message(server_proc.stdout)
        if msg is None:
            break
        _write_message(sys.stdout.buffer, msg)


def run(server_cmd: str, dry_run: bool = False, allow_list: list[str] = None):
    allow_list = allow_list or []

    server_proc = subprocess.Popen(
        server_cmd,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )

    t = threading.Thread(target=_forward_responses, args=(server_proc, dry_run), daemon=True)
    t.start()

    while True:
        msg = _read_message(sys.stdin.buffer)
        if msg is None:
            break

        method = msg.get("method", "")
        req_id = msg.get("id")

        if method == "tools/call":
            params = msg.get("params", {})
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})

            if tool_name not in allow_list:
                t0 = time.monotonic()
                verdict = pipeline.inspect(tool_name, arguments)
                latency_ms = (time.monotonic() - t0) * 1000

                event = "blocked" if (verdict and not dry_run) else ("flagged" if verdict else "allowed")
                logger.log(event, tool_name, arguments, verdict, latency_ms)

                if verdict and not dry_run:
                    resp = _error_response(
                        req_id,
                        -32600,
                        f"mcpguard blocked: [{verdict['rule']}] {verdict['detail']}",
                    )
                    _write_message(sys.stdout.buffer, resp)
                    continue

        _write_message(server_proc.stdin, msg)

    server_proc.terminate()