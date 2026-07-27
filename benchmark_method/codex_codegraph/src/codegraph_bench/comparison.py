"""Fail-closed matched comparison between frozen baseline and CodeGraph arm."""

from __future__ import annotations

import hashlib
import json
import statistics
from pathlib import Path
from typing import Any

from .artifacts import claimable_sample, load_jsonl, scored_artifacts_match
from .codegraph import directory_manifest, write_json
from .integrity import (
    IntegrityError,
    load_treatment_manifest,
    reconcile_sample_slots,
    validate_attempt_records,
    verify_bound_run_artifacts,
    verify_corpus_contract,
)


class ComparisonRefused(RuntimeError):
    """Raised when a delta would not have two matched, claimable operands."""


def _json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ComparisonRefused(f"comparison_refused: required artifact missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _task_map(corpus_path: Path) -> dict[str, str]:
    result = {}
    for row in load_jsonl(corpus_path):
        task_id = row.get("instance_id")
        commit = row.get("base_commit")
        if not isinstance(task_id, str) or not isinstance(commit, str) or task_id in result:
            raise ComparisonRefused("comparison_refused: malformed or duplicate corpus task")
        result[task_id] = commit
    return result


def _median_tokens(records: list[dict[str, Any]], task_id: str, baseline: bool) -> float:
    selected = []
    for record in records:
        valid = record.get("quality_valid") and record.get("score_valid") if baseline else claimable_sample(record)
        if valid and record.get("task_id") == task_id:
            usage = record.get("telemetry", {}).get("usage", {})
            if not isinstance(usage.get("input_tokens"), int) or not isinstance(usage.get("output_tokens"), int):
                raise ComparisonRefused("comparison_refused: authoritative token telemetry missing")
            selected.append(usage["input_tokens"] + usage["output_tokens"])
    if len(selected) != 3:
        raise ComparisonRefused(f"comparison_refused: {task_id} lacks three token-valid samples")
    return float(statistics.median(selected))


def _median_duration(records: list[dict[str, Any]], task_id: str, baseline: bool) -> float:
    selected = []
    for record in records:
        valid = record.get("quality_valid") and record.get("score_valid") if baseline else claimable_sample(record)
        duration = record.get("elapsed_seconds")
        if valid and record.get("task_id") == task_id:
            if not isinstance(duration, (int, float)) or isinstance(duration, bool) or duration < 0:
                raise ComparisonRefused("comparison_refused: agent duration telemetry missing")
            selected.append(float(duration))
    if len(selected) != 3:
        raise ComparisonRefused(f"comparison_refused: {task_id} lacks three duration-valid samples")
    return float(statistics.median(selected))


def compare_runs(
    baseline_root: Path,
    codegraph_root: Path,
    *,
    expected_baseline_configuration_sha256: str,
    expected_timeout_seconds: int,
    output_path: Path | None = None,
) -> dict[str, Any]:
    baseline_manifest = _json(baseline_root / "run-manifest.json")
    try:
        treatment_manifest = load_treatment_manifest(codegraph_root, expected_run_id=codegraph_root.name)
        verify_corpus_contract(codegraph_root, treatment_manifest)
        verify_bound_run_artifacts(codegraph_root, treatment_manifest)
    except IntegrityError as exc:
        raise ComparisonRefused(f"comparison_refused: {exc}") from exc
    baseline_report = _json(baseline_root / "aggregate.json")
    treatment_report = _json(codegraph_root / "aggregate.json")
    baseline_freeze = _json(baseline_root / "freeze-report.json")
    baseline_validation = _json(baseline_root / "validation.json")
    if baseline_manifest.get("arm") != "codex-baseline" or treatment_manifest.get("arm") != "codex-codegraph":
        raise ComparisonRefused("comparison_refused: arm identities differ")
    if baseline_manifest.get("configuration", {}).get("configuration_sha256") != expected_baseline_configuration_sha256:
        raise ComparisonRefused("comparison_refused: baseline config digest cannot prove timeout identity")
    if treatment_manifest.get("configuration", {}).get("timeout_seconds") != expected_timeout_seconds:
        raise ComparisonRefused("comparison_refused: timeout differs")
    baseline_tasks = _task_map(baseline_root / "corpus.jsonl")
    treatment_tasks = _task_map(codegraph_root / "corpus.jsonl")
    if baseline_tasks != treatment_tasks or len(baseline_tasks) != 24:
        raise ComparisonRefused("comparison_refused: task IDs or base commits differ")
    baseline_attempts = load_jsonl(baseline_root / "attempts.jsonl")
    treatment_attempts = load_jsonl(codegraph_root / "attempts.jsonl")
    try:
        validate_attempt_records(
            treatment_attempts,
            run_id=treatment_manifest["run_id"],
            task_ids=set(treatment_tasks),
            required_samples=int(treatment_manifest["configuration"]["sample_count"]),
            run_root=codegraph_root,
            manifest=treatment_manifest,
        )
        reconciliation = reconcile_sample_slots(treatment_attempts, sorted(treatment_tasks), 3)
    except IntegrityError as exc:
        raise ComparisonRefused(f"comparison_refused: {exc}") from exc
    if not reconciliation["complete"]:
        raise ComparisonRefused("comparison_refused: CodeGraph sample slots are incomplete")
    if any(not scored_artifacts_match(codegraph_root, record) for record in treatment_attempts):
        raise ComparisonRefused("comparison_refused: CodeGraph attempt or score artifact bytes differ")
    baseline_slots = {
        (record.get("task_id"), record.get("sample_id"))
        for record in baseline_attempts
        if record.get("quality_valid") is True and record.get("score_valid") is True
    }
    expected_slots = {(task_id, sample_id) for task_id in baseline_tasks for sample_id in range(1, 4)}
    if baseline_slots != expected_slots:
        raise ComparisonRefused("comparison_refused: baseline sample slots are not exactly 1..3")
    index_references = treatment_manifest.get("indexes", {}).get("records", [])
    if not isinstance(index_references, list) or len(index_references) != 24:
        raise ComparisonRefused("comparison_refused: CodeGraph index record set is incomplete")
    index_task_ids: set[str] = set()
    for reference in index_references:
        record = _json(codegraph_root / reference["path"])
        if record.get("task_id") in index_task_ids:
            raise ComparisonRefused("comparison_refused: duplicate CodeGraph index task")
        index_task_ids.add(record.get("task_id"))
        index_path = Path(record.get("index_path", ""))
        if not index_path.is_dir() or directory_manifest(index_path) != record.get("index_artifact_manifest"):
            raise ComparisonRefused("comparison_refused: CodeGraph index artifacts mutated")
    if index_task_ids != set(treatment_tasks):
        raise ComparisonRefused("comparison_refused: CodeGraph index task set differs")
    baseline_config = baseline_manifest["configuration"]
    treatment_config = treatment_manifest["configuration"]
    match_values = {
        "requested_model": (baseline_config.get("requested_model"), treatment_config.get("requested_model")),
        "requested_reasoning_effort": (
            baseline_config.get("requested_reasoning_effort"),
            treatment_config.get("requested_reasoning_effort"),
        ),
        "codex_version": (baseline_config.get("codex_version"), treatment_config.get("codex_version")),
        "sample_count": (baseline_config.get("sample_count"), treatment_config.get("sample_count")),
        "output_schema_sha256": (
            baseline_config.get("output_schema_sha256"),
            treatment_config.get("output_schema_sha256"),
        ),
        "evaluator_sha256": (
            baseline_manifest.get("evaluator", {}).get("sha256"),
            treatment_manifest.get("evaluator", {}).get("sha256"),
        ),
    }
    for field, operands in match_values.items():
        if operands[0] is None or operands[0] != operands[1]:
            raise ComparisonRefused(f"comparison_refused: {field} differs")
    baseline_max = {record.get("max_regions") for record in baseline_attempts}
    treatment_max = {record.get("max_regions") for record in treatment_attempts}
    if baseline_max != treatment_max or baseline_max != {5}:
        raise ComparisonRefused("comparison_refused: maximum regions differ")
    if set(baseline_report.get("official_metrics", {})) != set(treatment_report.get("official_metrics", {})):
        raise ComparisonRefused("comparison_refused: official metric names differ")
    if baseline_freeze.get("claimable") is not True or baseline_validation.get("passed") is not True:
        raise ComparisonRefused("comparison_refused: baseline is not independently claimable")
    if baseline_report.get("claimable") is not True or treatment_report.get("claimable") is not True:
        raise ComparisonRefused("comparison_refused: an arm is not independently claimable")
    if baseline_report.get("telemetry", {}).get("coverage_complete") is not True:
        raise ComparisonRefused("comparison_refused: baseline telemetry coverage is incomplete")
    if treatment_report.get("telemetry", {}).get("coverage_complete") is not True:
        raise ComparisonRefused("comparison_refused: CodeGraph telemetry coverage is incomplete")
    metric_deltas = {
        metric: {
            "baseline": baseline_report["official_metrics"][metric],
            "codegraph": treatment_report["official_metrics"][metric],
            "delta": treatment_report["official_metrics"][metric] - baseline_report["official_metrics"][metric],
        }
        for metric in baseline_report["official_metrics"]
    }
    task_metric_deltas = {
        task_id: {
            metric: treatment_report["task_means"][task_id][metric] - baseline_report["task_means"][task_id][metric]
            for metric in baseline_report["official_metrics"]
        }
        for task_id in sorted(baseline_tasks)
    }
    token_reductions = {}
    duration_reductions = {}
    for task_id in sorted(baseline_tasks):
        baseline_median = _median_tokens(baseline_attempts, task_id, True)
        treatment_median = _median_tokens(treatment_attempts, task_id, False)
        if baseline_median <= 0:
            raise ComparisonRefused("comparison_refused: baseline token median is not positive")
        token_reductions[task_id] = {
            "baseline_median_total_tokens": baseline_median,
            "codegraph_median_total_tokens": treatment_median,
            "reduction_pct": 100 * (baseline_median - treatment_median) / baseline_median,
        }
        baseline_duration = _median_duration(baseline_attempts, task_id, True)
        treatment_duration = _median_duration(treatment_attempts, task_id, False)
        if baseline_duration <= 0:
            raise ComparisonRefused("comparison_refused: baseline duration median is not positive")
        duration_reductions[task_id] = {
            "baseline_median_agent_seconds": baseline_duration,
            "codegraph_median_agent_seconds": treatment_duration,
            "reduction_pct": 100 * (baseline_duration - treatment_duration) / baseline_duration,
        }
    result = {
        "schema_version": "codex-codegraph-comparison-v1",
        "matched": True,
        "baseline_run_id": baseline_manifest["run_id"],
        "codegraph_run_id": treatment_manifest["run_id"],
        "artifact_sha256": {
            "baseline_manifest": _sha(baseline_root / "run-manifest.json"),
            "baseline_aggregate": _sha(baseline_root / "aggregate.json"),
            "codegraph_manifest": _sha(codegraph_root / "run-manifest.json"),
            "codegraph_aggregate": _sha(codegraph_root / "aggregate.json"),
        },
        "matched_inputs": {
            **{field: operands[0] for field, operands in match_values.items()},
            "timeout_seconds": expected_timeout_seconds,
            "max_regions": 5,
            "task_ids_and_commits": baseline_tasks,
        },
        "official_quality": {"macro_deltas": metric_deltas, "per_task_deltas": task_metric_deltas},
        "tokens": {
            "definition": "input_tokens + output_tokens",
            "per_task_median_reductions": token_reductions,
            "equal_weighted_mean_reduction_pct": statistics.fmean(
                value["reduction_pct"] for value in token_reductions.values()
            ),
            "baseline_totals": baseline_report["telemetry"]["usage_totals"],
            "codegraph_totals": treatment_report["telemetry"]["totals"],
        },
        "timing": {
            "definition": "agent execution includes MCP startup and agent activity; index overhead is separate",
            "per_task_median_reductions": duration_reductions,
            "equal_weighted_mean_reduction_pct": statistics.fmean(
                value["reduction_pct"] for value in duration_reductions.values()
            ),
            "codegraph": treatment_report["timing"],
        },
        "indexes": treatment_report["indexes"],
        "adoption": treatment_report["adoption"],
        "fallback": treatment_report["fallback"],
        "intent_to_treat": treatment_report["intent_to_treat"],
        "cost": treatment_report["cost"],
        "treatment_differences": treatment_report["treatment_differences"],
    }
    if output_path is not None:
        resolved_output = output_path.resolve()
        resolved_root = codegraph_root.resolve()
        if resolved_output.parent != resolved_root or output_path.is_symlink():
            raise ComparisonRefused("comparison_refused: output must be a direct CodeGraph run artifact")
        write_json(output_path, result)
    return result
