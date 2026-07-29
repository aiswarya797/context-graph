"""Consume the frozen baseline corpus/preparation records without mutating them."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class TaskMetadataError(RuntimeError):
    """Raised when baseline-owned task preparation cannot be trusted."""


def load_prepared_tasks(common_manifest: Path, baseline_prepared: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not common_manifest.is_file() or not baseline_prepared.is_file():
        raise TaskMetadataError("configuration_error: run the frozen baseline prepare command first")
    manifest = json.loads(common_manifest.read_text(encoding="utf-8"))
    prepared = json.loads(baseline_prepared.read_text(encoding="utf-8"))
    tasks = manifest.get("tasks")
    prepared_rows = prepared.get("tasks")
    if not isinstance(tasks, list) or not isinstance(prepared_rows, list):
        raise TaskMetadataError("configuration_error: malformed baseline preparation records")
    by_id = {row.get("task_id"): row for row in prepared_rows if isinstance(row, dict)}
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for source_task in tasks:
        task = dict(source_task)
        task_id = task.get("instance_id")
        if not isinstance(task_id, str) or not task_id or task_id in seen:
            raise TaskMetadataError("configuration_error: task IDs must be unique non-empty strings")
        seen.add(task_id)
        task["prepared"] = by_id.get(task_id)
        if not isinstance(task["prepared"], dict):
            raise TaskMetadataError(f"repository_revision_mismatch: missing prepared task {task_id}")
        if task["prepared"].get("verified_head") != task.get("base_commit"):
            raise TaskMetadataError(f"repository_revision_mismatch: prepared revision differs for {task_id}")
        result.append(task)
    if manifest.get("source_row_count") != 25 or manifest.get("unique_task_count") != 24 or len(result) != 24:
        raise TaskMetadataError("configuration_error: expected frozen 25-row/24-task corpus identity")
    return result, manifest


def portable_task(task: dict[str, Any]) -> dict[str, Any]:
    """Exclude ground truth and machine-local preparation paths from run corpus."""
    allowed = (
        "instance_id",
        "repository_url",
        "base_commit",
        "language",
        "issue_text",
        "source_memberships",
        "weight",
    )
    return {key: task.get(key) for key in allowed}
