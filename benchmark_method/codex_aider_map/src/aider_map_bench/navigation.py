"""Versioned, fail-closed replay of ordinary Codex repository navigation."""

from __future__ import annotations

import json
import re
from typing import Any


SCHEMA_VERSION = "codex-navigation-replay-v1"
KNOWN_EVENT_TYPES = {"thread.started", "thread.completed", "turn.started", "turn.completed", "turn.failed", "item.started", "item.updated", "item.completed", "error"}
KNOWN_ITEM_TYPES = {"agent_message", "reasoning", "command_execution"}
SEARCH = re.compile(r"(?:^|[\s;&|])(?:rg|grep|git\s+grep|find)(?:\s|$)", re.I)
READ = re.compile(r"(?:^|[\s;&|])(?:cat|sed|head|tail|nl|less|more)(?:\s|$)", re.I)


class NavigationReplayError(ValueError):
    pass


def _command_item(item: dict[str, Any]) -> str:
    required = {"id", "type", "command", "aggregated_output", "exit_code", "status"}
    if set(item) != required or not isinstance(item.get("id"), str) or not isinstance(item.get("command"), str):
        raise NavigationReplayError("unsupported command_execution item shape")
    if not isinstance(item.get("aggregated_output"), str) or not isinstance(item.get("exit_code"), int) or item.get("status") not in {"in_progress", "completed", "failed"}:
        raise NavigationReplayError("invalid command_execution fields")
    return item["command"]


def replay_navigation(text: str) -> dict[str, Any]:
    """Count only recognised command events; unknown evidence invalidates replay."""
    counters = {"total_tool_calls": 0, "repository_navigation_calls": 0, "search_calls": 0, "source_read_calls": 0, "other_inspection_calls": 0}
    commands: list[dict[str, Any]] = []
    final_position: int | None = None
    try:
        for position, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            event = json.loads(line)
            if not isinstance(event, dict) or set(event) - {"type", "timestamp", "usage", "item", "thread_id", "turn_id"} or event.get("type") not in KNOWN_EVENT_TYPES:
                raise NavigationReplayError("unknown event envelope")
            item = event.get("item")
            if item is None:
                continue
            if not isinstance(item, dict) or item.get("type") not in KNOWN_ITEM_TYPES:
                raise NavigationReplayError("unknown item form")
            if item["type"] == "command_execution":
                if event["type"] != "item.completed":
                    continue
                command = _command_item(item)
                kind = "search" if SEARCH.search(command) else "read" if READ.search(command) else "other"
                counters["total_tool_calls"] += 1
                counters["repository_navigation_calls"] += 1
                counter = {"search": "search_calls", "read": "source_read_calls", "other": "other_inspection_calls"}[kind]
                counters[counter] += 1
                commands.append({"position": position, "command": command, "classification": kind})
            elif item["type"] == "agent_message" and event["type"] == "item.completed":
                final_position = position
    except (json.JSONDecodeError, NavigationReplayError) as exc:
        return {"valid": False, "schema_version": SCHEMA_VERSION, "failure_class": "unknown_event_shape", "error": str(exc)}
    if final_position is None:
        # Codex's minimal fixture has only turn.completed; a future real fixture
        # establishes the richer final-message envelope in Task 5.
        final_position = sum(1 for line in text.splitlines() if line.strip())
    counters["calls_before_final_response"] = sum(1 for item in commands if item["position"] <= final_position)
    return {"valid": True, "schema_version": SCHEMA_VERSION, **counters, "final_response_event_position": final_position, "commands": commands}
