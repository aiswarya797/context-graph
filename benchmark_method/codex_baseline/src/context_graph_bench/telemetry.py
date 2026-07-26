"""Fail-closed Codex JSONL usage parsing and timing helpers."""

from __future__ import annotations

import json
from typing import Any


USAGE_FIELDS = (
    "input_tokens",
    "cached_input_tokens",
    "cache_write_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
)
REQUIRED_USAGE_FIELDS = ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_output_tokens")
KNOWN_EVENT_TYPES = {
    "thread.started",
    "thread.completed",
    "turn.started",
    "turn.completed",
    "turn.failed",
    "item.started",
    "item.updated",
    "item.completed",
    "error",
}


class TelemetryError(ValueError):
    """Raised when authoritative provider usage is unavailable."""


def _valid_counter(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def parse_events(text: str) -> dict[str, Any]:
    """Parse raw JSONL without estimating or reconstructing token counts."""
    events: list[dict[str, Any]] = []
    try:
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict) or not isinstance(value.get("type"), str):
                raise TelemetryError(f"unknown event envelope at line {line_number}")
            if value["type"] not in KNOWN_EVENT_TYPES:
                raise TelemetryError(f"unknown event type: {value['type']}")
            events.append(value)
    except (json.JSONDecodeError, TelemetryError) as exc:
        return {"valid": False, "failure_class": "malformed_jsonl", "error": str(exc), "event_count": len(events)}
    if not events:
        return {"valid": False, "failure_class": "malformed_jsonl", "error": "empty JSONL", "event_count": 0}
    last_timestamp = None
    for event in events:
        timestamp = event.get("timestamp")
        if isinstance(timestamp, (str, int, float)):
            last_timestamp = timestamp
    event_context = {"event_count": len(events), "last_event_number": len(events), "last_event_timestamp": last_timestamp}
    if any(event["type"] == "turn.failed" or event["type"] == "error" for event in events):
        return {"valid": False, "failure_class": "provider_turn_failure", "error": "provider turn failed", **event_context}
    completions = [event for event in events if event["type"] == "turn.completed"]
    if not completions:
        return {"valid": False, "failure_class": "missing_turn_completed", "error": "terminal turn.completed missing", **event_context}
    terminal = completions[-1]
    usage = terminal.get("usage")
    if not isinstance(usage, dict):
        return {"valid": False, "failure_class": "telemetry_unavailable", "error": "terminal usage missing", **event_context}
    for field in REQUIRED_USAGE_FIELDS:
        if not _valid_counter(usage.get(field)):
            return {"valid": False, "failure_class": "telemetry_unavailable", "error": f"usage field missing or invalid: {field}", **event_context}
    if "cache_write_input_tokens" in usage and not _valid_counter(usage["cache_write_input_tokens"]):
        return {"valid": False, "failure_class": "telemetry_unavailable", "error": "cache-write usage field invalid", **event_context}
    if usage["input_tokens"] < usage["cached_input_tokens"]:
        return {"valid": False, "failure_class": "telemetry_unavailable", "error": "cached input exceeds input", **event_context}

    usage_history = [event["usage"] for event in events if isinstance(event.get("usage"), dict)]
    for previous, current in zip(usage_history, usage_history[1:]):
        for field in USAGE_FIELDS:
            if field in previous and field in current and _valid_counter(previous[field]) and current[field] < previous[field]:
                return {"valid": False, "failure_class": "telemetry_unavailable", "error": f"usage counter decreased: {field}", **event_context}
    normalized = {field: usage[field] for field in USAGE_FIELDS if field in usage}
    normalized["uncached_input_tokens"] = usage["input_tokens"] - usage["cached_input_tokens"]
    for key, value in usage.items():
        if key not in normalized:
            normalized[f"provider_{key}"] = value
    return {
        "valid": True,
        "failure_class": None,
        **event_context,
        "terminal_event": "turn.completed",
        "usage": normalized,
        "provider_turn_valid": True,
    }


def duration_seconds(start: float, end: float) -> float:
    if end < start:
        raise TelemetryError("monotonic duration decreased")
    return end - start


def price_usage(usage: dict[str, Any], profile: dict[str, Any], requested_model: str) -> dict[str, Any]:
    """Calculate only from an explicit matching profile; otherwise unavailable."""
    if profile.get("model") != requested_model or profile.get("currency") != "USD":
        return {"cost_status": "unavailable", "reason": "pricing profile model or currency mismatch"}
    rates = profile.get("rates")
    accounting = profile.get("accounting")
    if not isinstance(rates, dict) or not isinstance(accounting, dict):
        return {"cost_status": "unavailable", "reason": "pricing profile incomplete"}
    try:
        cost = usage["input_tokens"] * rates["input_per_million"] / 1_000_000
        cost += usage["cached_input_tokens"] * rates["cached_input_per_million"] / 1_000_000
        cost += usage.get("cache_write_input_tokens", 0) * rates["cache_write_input_per_million"] / 1_000_000
        cost += usage["output_tokens"] * rates["output_per_million"] / 1_000_000
        if not accounting["reasoning_in_output"]:
            cost += usage["reasoning_output_tokens"] * rates["reasoning_per_million"] / 1_000_000
    except (KeyError, TypeError, ValueError):
        return {"cost_status": "unavailable", "reason": "pricing profile rates incomplete"}
    return {"cost_status": "estimated", "currency": "USD", "amount": cost, "profile_id": profile.get("profile_id")}
