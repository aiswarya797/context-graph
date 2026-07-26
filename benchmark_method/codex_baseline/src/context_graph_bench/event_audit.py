"""Small benchmark-contamination checks over retained Codex JSONL events."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PROHIBITED_RETRIEVAL_TYPES = {
    "web_search",
    "web_fetch",
    "browser",
    "browser_search",
    "browser_fetch",
    "remote_fetch",
    "remote_url_fetch",
    "fetch_url",
    "http_get",
    "open_url",
    "web_search_call",
}


def audit_events(text: str, forbidden_paths: list[Path] | None = None) -> dict[str, Any]:
    """Reject explicit external retrieval and access to benchmark-control paths."""
    forbidden = [str(path.resolve()) for path in (forbidden_paths or [])]
    forbidden_hits = [path for path in forbidden if path in text]
    prohibited: list[dict[str, Any]] = []
    malformed = False
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            if line.lstrip().startswith("{"):
                malformed = True
            continue
        if not isinstance(event, dict):
            malformed = True
            continue
        item = event.get("item") if isinstance(event.get("item"), dict) else {}
        candidates = {
            str(value).lower()
            for value in (event.get("type"), item.get("type"))
            if value is not None
        }
        if candidates & PROHIBITED_RETRIEVAL_TYPES:
            prohibited.append(
                {
                    "event_number": number,
                    "event_type": event.get("type"),
                    "item_type": item.get("type"),
                }
            )
    return {
        "passed": not forbidden_hits and not prohibited and not malformed,
        "forbidden_hits": forbidden_hits,
        "external_retrieval_passed": not prohibited and not malformed,
        "prohibited_events": prohibited,
        "malformed_events": malformed,
        "scanned_bytes": len(text.encode("utf-8")),
    }


def successful_local_read(text: str, expected_path: Path) -> bool:
    """Require a completed local command that names the doctor file."""
    resolved = str(expected_path.resolve())
    expected_paths = {resolved, resolved.removeprefix("/private")}
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or event.get("type") != "item.completed":
            continue
        item = event.get("item")
        if not isinstance(item, dict) or item.get("type") != "command_execution":
            continue
        encoded = json.dumps(item, ensure_ascii=False)
        if any(path in encoded for path in expected_paths) and not any(
            token in encoded.lower() for token in ("error", "failed")
        ):
            return True
    return False


def audit_denied_canaries(text: str, canaries: dict[Path, str]) -> dict[str, Any]:
    """Verify doctor-only denied reads without treating their probes as contamination.

    The doctor prompt deliberately asks Codex to attempt each read.  A passing
    canary therefore requires a completed command mentioning the path, a
    non-zero exit, and no canary secret in the retained trace.
    """
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            events.append(value)
    results: dict[str, Any] = {}
    for path, secret in canaries.items():
        resolved = str(path.resolve())
        attempts = []
        for number, event in enumerate(events, 1):
            item = event.get("item") if isinstance(event.get("item"), dict) else {}
            if item.get("type") != "command_execution":
                continue
            encoded = json.dumps(item, ensure_ascii=False)
            if resolved in encoded or str(path) in encoded:
                attempts.append({"event_number": number, "exit_code": item.get("exit_code"), "status": item.get("status")})
        failed = any(attempt.get("exit_code") not in (0, None) for attempt in attempts)
        leaked = secret in text
        results[resolved] = {
            "attempted": bool(attempts),
            "failed": failed,
            "secret_leaked": leaked,
            "events": attempts,
            "passed": bool(attempts) and failed and not leaked,
        }
    return {"passed": all(item["passed"] for item in results.values()) if results else False, "canaries": results}
