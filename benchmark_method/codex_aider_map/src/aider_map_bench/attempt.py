"""Pre-child treatment attempt planning and retained input identities.

The execution function is intentionally dependency-injected.  That lets Task 4
prove every refusal and parity rule locally while Task 5 supplies the observed
provider envelope before a paid child is ever started.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from context_graph_bench.codex_runner import RunnerError, child_environment as baseline_child_environment

from .binding import BoundMap, bind_map
from .navigation import replay_navigation
from .prompt import build_treatment_prompt
from .runner import assert_command_parity


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class AttemptPlan:
    task: dict[str, Any]
    bound_map: BoundMap
    prompt: str
    prompt_metadata: dict[str, Any]
    command: list[str]
    metadata: dict[str, Any]


def plan_attempt(
    task: dict[str, Any],
    config: dict[str, Any],
    *,
    executable: Path,
    state_dir: Path,
    schema_path: Path,
    repository: Path,
    baseline_template: str,
    run_id: str,
    sample_id: int,
    attempt_number: int,
) -> AttemptPlan:
    """Validate all treatment inputs before constructing a Codex child command."""
    if not isinstance(run_id, str) or not run_id or not isinstance(sample_id, int) or sample_id < 1 or not isinstance(attempt_number, int) or attempt_number < 1:
        raise RunnerError("configuration_error: invalid immutable attempt identity")
    bound = bind_map(task)
    prompt, prompt_metadata = build_treatment_prompt(baseline_template, task["issue_text"], bound)
    command = assert_command_parity(executable, config, state_dir, schema_path, repository)
    environment = baseline_child_environment(executable)
    forbidden_values = (bound.map_text, str(Path(".benchmark-work/aider-map/maps-v3")), "AIDER", "MCP", "CODEGRAPH")
    if any(value and value in "\n".join(f"{key}={value}" for key, value in environment.items()) for value in forbidden_values):
        raise RunnerError("configuration_error: map or forbidden runtime leaked into child environment")
    if any("mcp_servers" in argument or argument.lower() in {"aider", "codegraph"} for argument in command):
        raise RunnerError("configuration_error: map generator or MCP leaked into child command")
    metadata = {
        "run_id": run_id,
        "arm": "codex-aider-map",
        "task_id": bound.task_id,
        "sample_id": sample_id,
        "attempt_number": attempt_number,
        "prompt": prompt_metadata,
        "map": bound.provenance(),
        "child_environment_keys": sorted(environment),
        "child_receives_map_path": False,
        "child_receives_map_text_only_in_prompt": True,
        "map_generation_in_child": False,
        "aider_agent_in_child": False,
        "mcp_in_child": False,
        "codegraph_in_child": False,
        "exact_argument_vector": command,
        "output_schema_sha256": _sha(schema_path.read_bytes()) if schema_path.is_file() else None,
        "repository_revision": bound.base_commit,
    }
    return AttemptPlan(task, bound, prompt, prompt_metadata, command, metadata)


def persist_attempt_inputs(plan: AttemptPlan, attempt_root: Path) -> dict[str, Any]:
    """Persist exact delivered inputs before the child can start.

    The map itself is not copied: the immutable map digest plus final prompt
    bytes prove delivery while avoiding a second mutable map authority.
    """
    attempt_root.mkdir(parents=True, exist_ok=False)
    prompt_path = attempt_root / "prompt.md"
    identity_path = attempt_root / "map-prompt-identity.json"
    prompt_path.write_bytes(plan.prompt.encode("utf-8"))
    os.chmod(prompt_path, 0o600)
    identity = {"metadata": plan.metadata, "final_prompt_sha256": _sha(prompt_path.read_bytes())}
    identity_path.write_text(json.dumps(identity, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.chmod(identity_path, 0o600)
    return {"prompt_path": str(prompt_path), "prompt_sha256": identity["final_prompt_sha256"], "identity_path": str(identity_path), "identity_sha256": _sha(identity_path.read_bytes())}


def finalize_attempt_telemetry(raw_events: str, raw_stderr: str) -> dict[str, Any]:
    """Replay retained events rather than trusting a running counter."""
    replay = replay_navigation(raw_events)
    if not replay.get("valid"):
        raise RunnerError("navigation_replay_refused: " + str(replay.get("error")))
    return {"navigation_replay": replay, "raw_events_sha256": _sha(raw_events.encode("utf-8")), "raw_stderr_sha256": _sha(raw_stderr.encode("utf-8")), "raw_events_retained": True, "raw_stderr_retained": True}
