# tests/test_proxy.py
import json
import subprocess
import sys
import os
import time

PAYLOAD_DIR = os.path.join(os.path.dirname(__file__), "payloads")
MAIN = os.path.join(os.path.dirname(__file__), "..", "main.py")

ECHO_SERVER = f'"{sys.executable}" "{os.path.join(os.path.dirname(__file__), "echo_server.py")}"'


def _send_payload(payload_file: str) -> dict:
    with open(os.path.join(PAYLOAD_DIR, payload_file)) as f:
        payload = json.dumps(json.load(f))

    proc = subprocess.Popen(
        [sys.executable, MAIN, "--server", ECHO_SERVER],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    proc.stdin.write((payload + "\n").encode())
    proc.stdin.flush()
    proc.stdin.close()

    raw_line = proc.stdout.readline()
    proc.wait(timeout=5)
    raw = raw_line.decode().strip()
    if not raw:
        stderr = proc.stderr.read().decode()
        raise AssertionError(f"empty stdout from proxy. stderr: {stderr}")
    return json.loads(raw)


def test_secret_leak_blocked():
    resp = _send_payload("secret_leak.json")
    assert "error" in resp, f"expected block, got: {resp}"
    assert "secret_leak" in resp["error"]["message"]
    print("  PASS  test_secret_leak_blocked")


def test_prompt_injection_blocked():
    resp = _send_payload("prompt_injection.json")
    assert "error" in resp, f"expected block, got: {resp}"
    assert "prompt_injection" in resp["error"]["message"]
    print("  PASS  test_prompt_injection_blocked")


def test_unsafe_write_blocked():
    resp = _send_payload("unsafe_write.json")
    assert "error" in resp, f"expected block, got: {resp}"
    assert "unsafe_file_write" in resp["error"]["message"]
    print("  PASS  test_unsafe_write_blocked")


if __name__ == "__main__":
    passed = 0
    failed = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            try:
                fn()
                passed += 1
            except Exception as e:
                print(f"  FAIL  {name}: {e}")
                failed += 1
    print(f"\n{passed} passed, {failed} failed")