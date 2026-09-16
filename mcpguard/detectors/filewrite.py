# mcpguard/detectors/filewrite.py
import re
import base64
from typing import Any

WRITE_TOOLS = {
    "write_file", "create_file", "overwrite_file",
    "fs.write", "fs.create", "file_write",
    "write", "save_file", "put_file",
}

DANGEROUS_PATHS = [
    re.compile(r'\.\.[\\/]'),
    re.compile(r'^/etc/'),
    re.compile(r'^/root/'),
    re.compile(r'[/\\]\.ssh[/\\]'),
    re.compile(r'^/proc/'),
    re.compile(r'^/sys/'),
    re.compile(r'%SYSTEMROOT%', re.IGNORECASE),
    re.compile(r'C:\\Windows', re.IGNORECASE),
    re.compile(r'C:\\Users\\[^\\]+\\AppData', re.IGNORECASE),
]

SHEBANG = re.compile(r'^#!')
BASE64_BLOB = re.compile(r'^[A-Za-z0-9+/\n]{200,}={0,2}$')


def _is_dangerous_path(path: str) -> bool:
    return any(p.search(path) for p in DANGEROUS_PATHS)


def _is_unsafe_content(content: str) -> bool:
    if SHEBANG.match(content.strip()):
        return True
    stripped = content.replace('\n', '').replace('\r', '')
    if BASE64_BLOB.match(stripped):
        try:
            base64.b64decode(stripped)
            return True
        except Exception:
            pass
    return False


def detect_with_name(tool_name: str, arguments: dict) -> dict | None:
    if tool_name.lower() not in WRITE_TOOLS:
        return None

    path = arguments.get("path") or arguments.get("file_path") or arguments.get("filename") or ""
    content = arguments.get("content") or arguments.get("data") or arguments.get("text") or ""

    if isinstance(path, str) and _is_dangerous_path(path):
        return {
            "rule": "unsafe_file_write",
            "detail": f"dangerous path detected: {path}",
        }

    if isinstance(content, str) and _is_unsafe_content(content):
        return {
            "rule": "unsafe_file_write",
            "detail": "suspicious content: shebang or base64 blob detected",
        }

    return None