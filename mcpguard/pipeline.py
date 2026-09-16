# mcpguard/pipeline.py
from mcpguard.detectors import secrets, injection, filewrite


def inspect(tool_name: str, arguments: dict) -> dict | None:
    verdict = secrets.detect(arguments)
    if verdict:
        return verdict

    verdict = injection.detect(arguments)
    if verdict:
        return verdict

    verdict = filewrite.detect_with_name(tool_name, arguments)
    if verdict:
        return verdict

    return None