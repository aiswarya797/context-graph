"""Fail-closed CodeGraph MCP navigation parsing over retained Codex JSONL."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Any


REQUIRED_TOOL = "codegraph_explore"
SUPPORTED_FIXTURE_ENVELOPE = "codex-0.145.0-observed-partial-mcp-v1"
LIVE_CODEGRAPH_ENVELOPE = "codex-0.145.0-live-codegraph-mcp-v1"
REAL_ENVELOPE_INTEGRATION = LIVE_CODEGRAPH_ENVELOPE
NAVIGATION_WORDS = ("rg ", "grep ", "find ", "sed ", "cat ", "head ", "tail ", "nl ", "git show", "git log", "git diff")
KNOWN_ITEM_TYPES = {
    "agent_message",
    "reasoning",
    "command_execution",
    "mcp_server_status",
    "mcp_tool_call",
}
PROHIBITED_OUTPUT_NAMES = (
    "response.json",
    "score.json",
    "aggregate.json",
    "comparison.json",
    "report.json",
    "report.md",
    "attempts.jsonl",
    "valid-samples.jsonl",
    "prepared.json",
    "corpus.jsonl",
)
SYSTEM_EXECUTABLE_ROOTS = (Path("/bin"), Path("/usr/bin"), Path("/usr/sbin"), Path("/sbin"))
CODEX_DISCOVERY_TOOLS = {"list_mcp_resource_templates", "list_mcp_resources"}
CODEGRAPH_PATH_HEADER = re.compile(r"\*\*`([^`\r\n]+)`\*\*\s+—[^\r\n]*")
REDIRECTION_TOKEN = re.compile(
    r"^(?P<descriptor>\d+|&)?"
    r"(?P<operator><>|>>|>\||<<|>|<)"
    r"(?P<target>.*)$"
)
OUTPUT_REDIRECTION_OPERATORS = {">", ">>", ">|"}


class EventEnvelopeError(ValueError):
    """Raised internally for unsupported MCP evidence."""


def _base(event_count: int) -> dict[str, Any]:
    return {
        "schema_version": "codegraph-navigation-v1",
        "parser_envelope": SUPPORTED_FIXTURE_ENVELOPE,
        "real_envelope_integration": None,
        "event_count": event_count,
        "mcp_server_connected": False,
        "required_tool_name": REQUIRED_TOOL,
        "tool_available": False,
        "tool_call_count": 0,
        "successful_tool_call_count": 0,
        "failed_tool_call_count": 0,
        "first_codegraph_event_position": None,
        "last_codegraph_event_position": None,
        "final_response_event_position": None,
        "queries": [],
        "responses": [],
        "returned_paths": [],
        "built_in_navigation_before_graph": 0,
        "fallback_navigation_after_graph": 0,
        "outside_repository_accesses": [],
        "prohibited_benchmark_accesses": [],
        "unknown_mcp_events": [],
        "graph_use_valid": False,
        "failure_class": None,
    }


def _failure(summary: dict[str, Any], failure_class: str, error: str | None = None) -> dict[str, Any]:
    summary["graph_use_valid"] = False
    summary["failure_class"] = failure_class
    if error:
        summary["error"] = error
    return summary


def _event_lines(text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EventEnvelopeError(f"malformed JSONL at line {number}") from exc
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise EventEnvelopeError(f"unknown event envelope at line {number}")
        events.append(event)
    return events


def _navigation_command(item: dict[str, Any]) -> bool:
    if item.get("type") != "command_execution":
        return False
    command = item.get("command")
    return isinstance(command, str) and any(word in f" {command.lower()} " for word in NAVIGATION_WORDS)


def _observed_tool_discovery_command(item: dict[str, Any]) -> bool:
    """Recognize the exact read-only fallback probe emitted by the live doctor."""
    return (
        set(item) == {
            "id",
            "type",
            "command",
            "aggregated_output",
            "exit_code",
            "status",
        }
        and item.get("type") == "command_execution"
        and isinstance(item.get("id"), str)
        and item.get("command") == "/bin/zsh -lc 'command -v codegraph_explore || true'"
        and item.get("aggregated_output") == ""
        and item.get("exit_code") == 0
        and item.get("status") == "completed"
    )


def _canonical_returned_path(value: str, repository: Path) -> str:
    if (
        not value
        or "\\" in value
        or "%" in value
        or value.endswith("/")
        or value.startswith("/")
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise EventEnvelopeError("returned path is empty or not POSIX repository-relative")
    relative = PurePosixPath(value)
    if relative.is_absolute() or relative.as_posix() != value:
        raise EventEnvelopeError("returned path is absolute or traversal-bearing")
    canonical = relative.as_posix()
    candidate = repository / canonical
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise EventEnvelopeError(f"returned path does not exist: {canonical}") from exc
    root = repository.resolve()
    if not resolved.is_file() or not (resolved == root or root in resolved.parents):
        raise EventEnvelopeError(f"returned path is outside the project or not a file: {canonical}")
    if candidate.relative_to(repository).as_posix() != canonical:
        raise EventEnvelopeError(f"returned path is not canonical: {canonical}")
    return canonical


def _codegraph_path_headers(content: str) -> list[str]:
    """Extract canonical result headers while ignoring verbatim fenced source."""
    paths: list[str] = []
    fence: str | None = None
    for line in content.splitlines():
        stripped = line.lstrip()
        marker = next(
            (
                candidate
                for candidate in ("```", "~~~")
                if stripped.startswith(candidate)
            ),
            None,
        )
        if marker is not None:
            if fence is None:
                fence = marker
            elif marker == fence:
                fence = None
            continue
        if fence is not None:
            continue
        match = CODEGRAPH_PATH_HEADER.fullmatch(line)
        if match is not None:
            paths.append(match.group(1))
    return paths


def _inspect_paths(
    item: dict[str, Any],
    repository: Path,
    allowed_runtime_roots: list[Path],
) -> tuple[list[str], list[str]]:
    """Inspect only an event surface that represents an actual filesystem access."""
    command = item.get("command")
    if not isinstance(command, str):
        return [], []
    prohibited = [hit for hit in (".benchmark-runs", ".benchmark-work") if hit in command]
    allowed = [
        repository.resolve(),
        *(path.resolve() for path in allowed_runtime_roots),
        *SYSTEM_EXECUTABLE_ROOTS,
    ]
    try:
        tokens = shlex.split(command)
        if (
            len(tokens) >= 3
            and Path(tokens[0]).name in {"bash", "sh", "zsh"}
            and tokens[1] in {"-c", "-lc"}
        ):
            tokens.extend(shlex.split(tokens[2]))
    except ValueError:
        return ["<unparseable-command>"], sorted(set(prohibited))
    outside: list[str] = []
    candidates: list[tuple[str, bool]] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        redirection = REDIRECTION_TOKEN.match(token)
        if redirection is None:
            value = token
        else:
            operator = redirection.group("operator")
            value = redirection.group("target")
            if not value and index + 1 < len(tokens):
                index += 1
                value = tokens[index]
            if (
                operator in OUTPUT_REDIRECTION_OPERATORS
                and value == "/dev/null"
            ):
                index += 1
                continue
        value = value.rstrip(",:)]}")
        if "=" in value:
            _name, assigned = value.split("=", 1)
            if assigned.startswith(("/", "../")):
                value = assigned
        if value.startswith("/"):
            candidates.append((value, True))
        elif value.startswith("../") or ".." in PurePosixPath(value).parts:
            candidates.append((value, False))
        index += 1
    for value, absolute in candidates:
        candidate = (
            Path(value).resolve()
            if absolute
            else (repository / value).resolve()
        )
        if not any(candidate == root or root in candidate.parents for root in allowed):
            outside.append(str(candidate))
            lowered = candidate.as_posix().lower()
            if candidate.name.lower() in PROHIBITED_OUTPUT_NAMES or "ground_truth" in lowered:
                prohibited.append(str(candidate))
    return sorted(set(outside)), sorted(set(prohibited))


def _inspect_forbidden_paths(
    item: dict[str, Any],
    forbidden_paths: list[Path],
) -> list[str]:
    """Retain exact forbidden-path detection across commands and tool responses."""
    serialized = json.dumps(item, ensure_ascii=False, sort_keys=True)
    return sorted(
        {
            resolved
            for path in forbidden_paths
            if (resolved := str(path.resolve())) in serialized
        }
    )


def _observed_codex_discovery_call(event: dict[str, Any], item: dict[str, Any]) -> bool:
    """Accept only the unrelated MCP discovery shape observed in Codex 0.145.0."""
    if set(item) != {
        "id",
        "type",
        "server",
        "tool",
        "arguments",
        "result",
        "error",
        "status",
    }:
        return False
    if (
        item.get("server") != "codex"
        or item.get("tool") not in CODEX_DISCOVERY_TOOLS
        or not isinstance(item.get("id"), str)
        or not isinstance(item.get("arguments"), dict)
        or item.get("error") is not None
    ):
        return False
    if event.get("type") == "item.started":
        return item.get("status") == "in_progress" and item.get("result") is None
    if event.get("type") != "item.completed" or item.get("status") != "completed":
        return False
    result = item.get("result")
    if not isinstance(result, dict) or set(result) != {"content", "structured_content"}:
        return False
    content = result.get("content")
    if not isinstance(content, list) or not all(
        isinstance(block, dict)
        and set(block) == {"type", "text"}
        and block.get("type") == "text"
        and isinstance(block.get("text"), str)
        for block in content
    ):
        return False
    return result.get("structured_content") is None


def _observed_codegraph_call(
    event: dict[str, Any],
    item: dict[str, Any],
) -> tuple[str, str | None] | None:
    """Parse the exact Codex 0.145.0 MCP item envelope."""
    if set(item) != {
        "id",
        "type",
        "server",
        "tool",
        "arguments",
        "result",
        "error",
        "status",
    }:
        return None
    if (
        item.get("server") != "codegraph"
        or item.get("tool") != REQUIRED_TOOL
        or not isinstance(item.get("id"), str)
        or not isinstance(item.get("arguments"), dict)
    ):
        return None
    arguments = item["arguments"]
    if (
        not {"query"} <= set(arguments) <= {"projectPath", "query", "maxFiles"}
        or not isinstance(arguments.get("query"), str)
        or (
            "projectPath" in arguments
            and not isinstance(arguments["projectPath"], str)
        )
        or (
            "maxFiles" in arguments
            and (
                not isinstance(arguments["maxFiles"], int)
                or isinstance(arguments["maxFiles"], bool)
                or not 1 <= arguments["maxFiles"] <= 100
            )
        )
    ):
        return None
    if event.get("type") == "item.started":
        if (
            item.get("status") == "in_progress"
            and item.get("result") is None
            and item.get("error") is None
        ):
            return ("started", None)
        return None
    if event.get("type") != "item.completed":
        return None
    if item.get("status") != "completed" or item.get("error") is not None:
        return ("failed", None)
    result = item.get("result")
    if not isinstance(result, dict) or set(result) != {
        "content",
        "structured_content",
    }:
        return None
    content = result.get("content")
    if not isinstance(content, list) or not content:
        return None
    texts: list[str] = []
    for block in content:
        if (
            not isinstance(block, dict)
            or set(block) != {"type", "text"}
            or block.get("type") != "text"
            or not isinstance(block.get("text"), str)
        ):
            return None
        texts.append(block["text"])
    if result.get("structured_content") is not None:
        return None
    return ("completed", "\n".join(texts))


def parse_navigation_events(
    text: str,
    repository: Path,
    *,
    expected_project: Path | None = None,
    allowed_runtime_roots: list[Path] | None = None,
    forbidden_paths: list[Path] | None = None,
) -> dict[str, Any]:
    """Parse only explicitly supported MCP shapes; all other MCP shapes fail."""
    try:
        events = _event_lines(text)
    except EventEnvelopeError as exc:
        return _failure(_base(0), "unknown_event_shape", str(exc))
    summary = _base(len(events))
    expected = (expected_project or repository).resolve()
    first_success: int | None = None
    final_response: int | None = None
    startup_failed = False
    wrong_project = False
    live_started: dict[str, tuple[dict[str, Any], int]] = {}
    for position, event in enumerate(events, 1):
        item = event.get("item")
        if not isinstance(item, dict):
            continue
        item_type = item.get("type")
        outside, prohibited = _inspect_paths(
            item if item_type == "command_execution" else {},
            repository.resolve(),
            [*(allowed_runtime_roots or []), expected],
        )
        prohibited.extend(
            _inspect_forbidden_paths(item, list(forbidden_paths or []))
        )
        summary["outside_repository_accesses"].extend(outside)
        summary["prohibited_benchmark_accesses"].extend(prohibited)
        if not isinstance(item_type, str) or item_type not in KNOWN_ITEM_TYPES:
            if event.get("type", "").startswith("item."):
                summary["unknown_mcp_events"].append(position)
            continue
        if isinstance(item_type, str) and item_type.startswith("mcp_"):
            if item_type == "mcp_tool_call" and _observed_codex_discovery_call(event, item):
                continue
            live_call = (
                _observed_codegraph_call(event, item)
                if item_type == "mcp_tool_call"
                else None
            )
            if live_call is not None:
                state, content = live_call
                call_id = item["id"]
                if state == "started":
                    if call_id in live_started:
                        summary["unknown_mcp_events"].append(position)
                    else:
                        live_started[call_id] = (
                            dict(item["arguments"]),
                            position,
                        )
                    continue
                started_call = live_started.pop(call_id, None)
                if (
                    started_call is None
                    or started_call[0] != item["arguments"]
                ):
                    summary["unknown_mcp_events"].append(position)
                    if started_call is not None:
                        summary["unknown_mcp_events"].append(started_call[1])
                    continue
                summary["mcp_server_connected"] = True
                summary["tool_available"] = True
                summary["tool_call_count"] += 1
                summary["first_codegraph_event_position"] = (
                    summary["first_codegraph_event_position"] or position
                )
                summary["last_codegraph_event_position"] = position
                query = item["arguments"].get("query")
                if not isinstance(query, str) or not query.strip():
                    summary["unknown_mcp_events"].append(position)
                    continue
                summary["queries"].append(query)
                project_argument = item["arguments"].get("projectPath")
                if (
                    project_argument is not None
                    and Path(project_argument).resolve() != expected
                ):
                    wrong_project = True
                if state == "failed" or content is None:
                    summary["failed_tool_call_count"] += 1
                    continue
                returned = _codegraph_path_headers(content)
                try:
                    canonical_paths = [
                        _canonical_returned_path(path, repository)
                        for path in returned
                    ]
                except EventEnvelopeError:
                    summary["unknown_mcp_events"].append(position)
                    continue
                if not canonical_paths:
                    summary["unknown_mcp_events"].append(position)
                    continue
                response_bytes = content.encode()
                summary["responses"].append(
                    {
                        "event_position": position,
                        "bytes": len(response_bytes),
                        "sha256": hashlib.sha256(response_bytes).hexdigest(),
                        "project_root": project_argument or str(expected),
                        "project_binding": (
                            "event-argument-and-validated-mcp-launch-contract"
                            if project_argument is not None
                            else "validated-mcp-launch-contract"
                        ),
                    }
                )
                summary["returned_paths"].extend(canonical_paths)
                summary["successful_tool_call_count"] += 1
                summary["real_envelope_integration"] = LIVE_CODEGRAPH_ENVELOPE
                if first_success is None:
                    first_success = position
                continue
            if event.get("type") != "item.completed":
                summary["unknown_mcp_events"].append(position)
                continue
            if item_type == "mcp_server_status":
                required = {"type", "server", "status", "tools"}
                if set(item) != required or item.get("server") != "codegraph" or not isinstance(item.get("tools"), list):
                    summary["unknown_mcp_events"].append(position)
                    continue
                if item["status"] == "connected":
                    summary["mcp_server_connected"] = True
                    summary["tool_available"] = REQUIRED_TOOL in item["tools"]
                elif item["status"] == "failed":
                    startup_failed = True
                else:
                    summary["unknown_mcp_events"].append(position)
            elif item_type == "mcp_tool_call":
                required = {"type", "server", "tool", "arguments", "result", "status"}
                if set(item) != required or item.get("server") != "codegraph" or item.get("tool") != REQUIRED_TOOL:
                    summary["unknown_mcp_events"].append(position)
                    continue
                if not isinstance(item.get("arguments"), dict) or not isinstance(item.get("result"), dict):
                    summary["unknown_mcp_events"].append(position)
                    continue
                result = item["result"]
                if set(result) != {"content", "is_error", "project_root", "paths"}:
                    summary["unknown_mcp_events"].append(position)
                    continue
                if not isinstance(result["content"], str) or not isinstance(result["paths"], list) or not all(isinstance(path, str) for path in result["paths"]):
                    summary["unknown_mcp_events"].append(position)
                    continue
                summary["tool_call_count"] += 1
                summary["first_codegraph_event_position"] = summary["first_codegraph_event_position"] or position
                summary["last_codegraph_event_position"] = position
                query = item["arguments"].get("query")
                if not isinstance(query, str) or not query.strip():
                    summary["unknown_mcp_events"].append(position)
                    continue
                summary["queries"].append(query)
                response_bytes = result["content"].encode()
                summary["responses"].append(
                    {
                        "event_position": position,
                        "bytes": len(response_bytes),
                        "sha256": hashlib.sha256(response_bytes).hexdigest(),
                        "project_root": result["project_root"],
                    }
                )
                success = item["status"] == "completed" and result["is_error"] is False
                project_matches = isinstance(result["project_root"], str) and Path(result["project_root"]).resolve() == expected
                if success and project_matches:
                    try:
                        canonical_paths = [
                            _canonical_returned_path(path, repository)
                            for path in result["paths"]
                        ]
                    except EventEnvelopeError:
                        summary["unknown_mcp_events"].append(position)
                        continue
                    if not canonical_paths:
                        summary["unknown_mcp_events"].append(position)
                        continue
                    summary["returned_paths"].extend(canonical_paths)
                if success:
                    summary["successful_tool_call_count"] += 1
                    if first_success is None:
                        first_success = position
                    if not project_matches:
                        wrong_project = True
                else:
                    summary["failed_tool_call_count"] += 1
            else:
                summary["unknown_mcp_events"].append(position)
        elif event.get("type") == "item.completed" and item_type == "command_execution":
            if _observed_tool_discovery_command(item):
                continue
            if not _navigation_command(item):
                summary["unknown_mcp_events"].append(position)
            elif first_success is None:
                summary["built_in_navigation_before_graph"] += 1
            else:
                summary["fallback_navigation_after_graph"] += 1
        elif event.get("type") == "item.completed" and item_type == "agent_message":
            if not isinstance(item.get("text"), str) or not item["text"].strip():
                summary["unknown_mcp_events"].append(position)
            else:
                final_response = position
                summary["final_response_event_position"] = final_response
        elif event.get("type") == "item.completed" and item_type == "reasoning":
            if not isinstance(item.get("text", ""), str):
                summary["unknown_mcp_events"].append(position)

    summary["unknown_mcp_events"].extend(
        position for _arguments, position in live_started.values()
    )
    for key in ("outside_repository_accesses", "prohibited_benchmark_accesses", "returned_paths", "unknown_mcp_events"):
        summary[key] = sorted(set(summary[key]))
    if summary["unknown_mcp_events"]:
        return _failure(summary, "unknown_event_shape", "unsupported MCP event shape")
    if summary["prohibited_benchmark_accesses"]:
        if any("ground_truth" in value.lower() or "prepared.json" in value.lower() or "corpus.jsonl" in value.lower() for value in summary["prohibited_benchmark_accesses"]):
            return _failure(summary, "ground_truth_access")
        return _failure(summary, "benchmark_output_access")
    if wrong_project:
        return _failure(summary, "codegraph_wrong_project")
    if summary["outside_repository_accesses"]:
        return _failure(summary, "outside_repo_access")
    if startup_failed or not summary["mcp_server_connected"]:
        return _failure(summary, "mcp_startup_failure")
    if not summary["tool_available"]:
        return _failure(summary, "mcp_tool_unavailable")
    if summary["tool_call_count"] == 0:
        return _failure(summary, "codegraph_not_used")
    if summary["successful_tool_call_count"] == 0:
        return _failure(summary, "codegraph_tool_failure")
    if final_response is None:
        return _failure(summary, "missing_final_response_event")
    if first_success is None or first_success >= final_response:
        return _failure(summary, "codegraph_call_after_final_response")
    summary["graph_use_valid"] = True
    return summary
