"""Independent fail-closed validation for a completed baseline run."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

from .artifacts import load_jsonl, raw_artifacts_match
from .codex_runner import validate_regions
from .corpus import verify_repository_head, verify_official_evaluator
from .event_audit import audit_events
from .report import METRICS, _line_counts
from .telemetry import parse_events


def _canonical_line_count_input(line_counts: dict[str, dict[str, int]]) -> bytes:
    return (json.dumps(line_counts, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _load_evaluator(path: Path):
    spec = importlib.util.spec_from_file_location("independent_pinned_swe_explore_eval", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_final_run(
    repo_root: Path,
    run_id: str,
    tasks: list[dict[str, Any]],
    evaluator_path: Path,
    provenance_path: Path,
    forbidden_paths: list[Path],
    required_samples: int = 3,
) -> dict[str, Any]:
    root = repo_root / ".benchmark-runs" / run_id
    records = load_jsonl(root / "attempts.jsonl")
    expected = {task["instance_id"]: task for task in tasks}
    evaluator_identity = verify_official_evaluator(evaluator_path, provenance_path)
    module = _load_evaluator(evaluator_path)
    errors: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    per_task: dict[str, int] = {task_id: 0 for task_id in expected}
    source_revision_cache: dict[str, bool] = {}
    counters = {
        "records": len(records),
        "unique_pairs": 0,
        "repository_revision_verified": 0,
        "clean_repository_verified": 0,
        "contamination_free": 0,
        "response_valid": 0,
        "official_score_valid": 0,
        "provider_telemetry_valid": 0,
        "authoritative_usage_present": 0,
        "failed_invalid_timed_out_or_contaminated": 0,
    }
    for record in records:
        task_id = record.get("task_id")
        sample_id = record.get("sample_id")
        label = f"{task_id}/sample-{sample_id}"
        local_errors: list[str] = []
        if task_id not in expected:
            local_errors.append("unknown_task")
        if not isinstance(sample_id, int) or isinstance(sample_id, bool) or not 1 <= sample_id <= required_samples:
            local_errors.append("invalid_sample_id")
        key = (str(task_id), int(sample_id) if isinstance(sample_id, int) and not isinstance(sample_id, bool) else -1)
        if key in seen:
            local_errors.append("duplicate_task_sample")
        else:
            seen.add(key)
            counters["unique_pairs"] += 1
        if record.get("attempt_number") != 1:
            local_errors.append("retry_present")
        task = expected.get(task_id)
        if task:
            per_task[task_id] += 1
            if record.get("requested_base_commit") != task["base_commit"]:
                local_errors.append("declared_base_commit_mismatch")
            if record.get("verified_head") != task["base_commit"]:
                local_errors.append("recorded_head_mismatch")
        repo = Path(record.get("repository_path", ""))
        if task and task_id not in source_revision_cache:
            try:
                revision = verify_repository_head(repo, task["base_commit"])
                source_revision_cache[task_id] = bool(revision["clean"] and revision["verified_head"] == task["base_commit"])
            except Exception as exc:
                source_revision_cache[task_id] = False
                local_errors.append(f"repository_revision:{exc}")
        if task and source_revision_cache.get(task_id):
            counters["repository_revision_verified"] += 1
            counters["clean_repository_verified"] += 1
        child_snapshot = record.get("child_snapshot") or {}
        if child_snapshot.get("head") != (task or {}).get("base_commit") or child_snapshot.get("clean") is not True:
            local_errors.append("child_snapshot_revision_or_cleanliness")
        raw_events = ""
        raw_stderr = ""
        if record.get("artifact_paths"):
            attempt_dir = root / record["artifact_paths"]["attempt"]
            events_path = root / record["artifact_paths"]["events"]
            stderr_path = root / record["artifact_paths"]["stderr"]
            raw_events = events_path.read_text(encoding="utf-8", errors="replace") if events_path.exists() else ""
            raw_stderr = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
            if not raw_artifacts_match(root, record):
                local_errors.append("raw_artifact_hash_mismatch")
            score_path = root / record.get("score_artifact", attempt_dir.relative_to(root).as_posix() + "/score.json")
            if not score_path.is_file():
                local_errors.append("missing_score_artifact")
            elif record.get("score_sha256") != hashlib.sha256(score_path.read_bytes()).hexdigest():
                local_errors.append("score_artifact_hash_mismatch")
        contamination = audit_events(raw_events + raw_stderr, forbidden_paths)
        if contamination.get("passed"):
            counters["contamination_free"] += 1
        else:
            local_errors.append("contamination_or_malformed_events")
        telemetry = parse_events(raw_events)
        if telemetry.get("valid") and record.get("provider_turn_valid") is True:
            counters["provider_telemetry_valid"] += 1
        else:
            local_errors.append("invalid_provider_telemetry")
        usage = telemetry.get("usage") if isinstance(telemetry, dict) else None
        required_usage = ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_output_tokens")
        if isinstance(usage, dict) and all(isinstance(usage.get(key), int) and not isinstance(usage.get(key), bool) and usage.get(key) >= 0 for key in required_usage):
            counters["authoritative_usage_present"] += 1
        else:
            local_errors.append("authoritative_usage_missing")
        if record.get("return_code") != 0 or record.get("timeout") is True or record.get("terminated") is True or record.get("failure_class") is not None:
            counters["failed_invalid_timed_out_or_contaminated"] += 1
            local_errors.append("failed_or_invalid_execution")
        response_path = root / record.get("artifact_paths", {}).get("response", "")
        if task and response_path.is_file():
            try:
                response = json.loads(response_path.read_text(encoding="utf-8"))
                regions = validate_regions(response, repo)
                if record.get("response_valid") is not True:
                    local_errors.append("recorded_response_validity_mismatch")
                else:
                    counters["response_valid"] += 1
                line_counts = {task_id: _line_counts(repo)}
                score = module.ExploreEvaluator(root / "corpus.jsonl", file_line_counts=line_counts).evaluate(
                    lambda _issue, _instance_id: [(region["path"], region["start"], region["end"]) for region in regions],
                    task_id,
                    METRICS,
                )[task_id]
                saved_score = record.get("score")
                saved_file = json.loads((root / record["score_artifact"]).read_text(encoding="utf-8")) if record.get("score_artifact") else {}
                if saved_score != score or saved_file.get("metrics") != score:
                    local_errors.append("official_score_mismatch")
                else:
                    counters["official_score_valid"] += 1
                expected_line_hash = hashlib.sha256(_canonical_line_count_input(line_counts)).hexdigest()
                if saved_file.get("line_count_sha256") != expected_line_hash:
                    local_errors.append("line_count_sha256_mismatch")
            except Exception as exc:
                local_errors.append(f"response_or_evaluator:{exc}")
        else:
            local_errors.append("missing_response")
        if local_errors:
            errors.append({"sample": label, "errors": sorted(set(local_errors))})
    for task_id, count in per_task.items():
        if count != required_samples:
            errors.append({"sample": task_id, "errors": [f"expected_{required_samples}_samples_got_{count}"]})
    expected_total = len(expected) * required_samples
    passed = len(records) == expected_total and len(seen) == expected_total and not errors
    return {
        "passed": passed,
        "run_id": run_id,
        "expected_unique_tasks": len(expected),
        "expected_samples": expected_total,
        "per_task_sample_counts": per_task,
        "counters": counters,
        "telemetry_coverage": counters["provider_telemetry_valid"] == expected_total and counters["authoritative_usage_present"] == expected_total,
        "contamination_count": expected_total - counters["contamination_free"],
        "failure_count": counters["failed_invalid_timed_out_or_contaminated"],
        "evaluator": evaluator_identity,
        "errors": errors,
    }
