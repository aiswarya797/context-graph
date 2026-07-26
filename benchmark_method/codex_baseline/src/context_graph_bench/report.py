"""Pinned official scoring and deterministic quality/telemetry reporting."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import math
import statistics
from pathlib import Path
from typing import Any

from .artifacts import load_jsonl, raw_artifacts_match, write_json, append_jsonl, sha256_file, attempt_quality_gate, validate_attempt_record
from .codex_runner import validate_regions
from .corpus import verify_official_evaluator


METRICS = [
    "precision",
    "recall",
    "f1_score",
    "hit_file_rate",
    "noise_file_rate",
    "hit_region_rate",
    "noise_region_rate",
    "weighted_core_coverage",
    "context_efficiency",
    "optional_coverage",
    "ndcg_at_100",
    "ndcg_at_300",
    "ndcg_at_500",
    "recall_at_100",
    "recall_at_300",
    "recall_at_500",
    "first_useful_hit",
]
DISPLAY_NAMES = {
    "precision": "line precision",
    "recall": "line recall",
    "f1_score": "line F1",
    "hit_region_rate": "hit region rate",
    "hit_file_rate": "hit file rate",
    "ndcg_at_500": "nDCG@500",
    "recall_at_500": "Recall@500",
    "first_useful_hit": "first useful hit",
    "context_efficiency": "context efficiency",
    "noise_region_rate": "noise region rate",
}


class ReportError(RuntimeError):
    """Raised when scoring/report reconciliation cannot be trusted."""


def _load_official(path: Path):
    spec = importlib.util.spec_from_file_location("pinned_swe_explore_eval", path)
    if spec is None or spec.loader is None:
        raise ReportError("evaluator_failure: cannot load pinned evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _line_counts(repo: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in repo.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        try:
            relative = path.relative_to(repo).as_posix()
            counts[relative] = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            continue
    return counts


def _canonical_line_count_input(line_counts: dict[str, dict[str, int]]) -> bytes:
    """Canonical evaluator side input for end-of-file/negative ranges."""
    return (json.dumps(line_counts, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def score_record(run_root: Path, record: dict[str, Any], corpus_path: Path, evaluator_path: Path, provenance_path: Path) -> dict[str, Any]:
    gate_valid, gate_failure = attempt_quality_gate(record)
    if not validate_attempt_record(record) or not gate_valid:
        rejected = dict(record)
        rejected["quality_valid"] = False
        rejected["score_valid"] = False
        rejected["failure_class"] = gate_failure or "invalid_attempt_record"
        return rejected
    if not record.get("quality_valid"):
        return {"score_valid": False, "failure_class": "not_quality_valid"}
    if not raw_artifacts_match(run_root, record):
        raise ReportError(f"artifact hash mismatch for {record['attempt_id']}")
    provenance = verify_official_evaluator(evaluator_path, provenance_path)
    module = _load_official(evaluator_path)
    repo = Path(record["repository_path"])
    response_path = run_root / record["artifact_paths"]["response"]
    try:
        response = json.loads(response_path.read_text(encoding="utf-8"))
        regions = validate_regions(response, repo)
    except Exception as exc:
        raise ReportError(f"invalid_response_schema: saved response failed validation: {exc}") from exc
    predictions = [(region["path"], region["start"], region["end"]) for region in regions]
    line_counts = {record["task_id"]: _line_counts(repo)}
    evaluator = module.ExploreEvaluator(corpus_path, file_line_counts=line_counts)
    try:
        result = evaluator.evaluate(lambda _issue, _instance_id: predictions, record["task_id"], METRICS)
    except Exception as exc:
        raise ReportError(f"evaluator_failure: {exc}") from exc
    metrics = result[record["task_id"]]
    score = {
        "score_valid": True,
        "evaluator_commit": provenance["commit"],
        "evaluator_sha256": provenance["sha256"],
        "task_id": record["task_id"],
        "attempt_id": record["attempt_id"],
        "regions": regions,
        "metrics": metrics,
        "line_count_sha256": hashlib.sha256(_canonical_line_count_input(line_counts)).hexdigest(),
    }
    score_path = run_root / record["artifact_paths"]["attempt"] / "score.json"
    write_json(score_path, score)
    record = dict(record)
    record["score_valid"] = True
    record["score"] = metrics
    record["evaluator_commit"] = provenance["commit"]
    record["evaluator_sha256"] = provenance["sha256"]
    record["score_artifact"] = str(score_path.relative_to(run_root))
    record["score_sha256"] = sha256_file(score_path)
    return record


def score_run(repo_root: Path, run_id: str, evaluator_path: Path, provenance_path: Path) -> list[dict[str, Any]]:
    root = repo_root / ".benchmark-runs" / run_id
    corpus_path = root / "corpus.jsonl"
    records = load_jsonl(root / "attempts.jsonl")
    scored: list[dict[str, Any]] = []
    for record in records:
        updated = score_record(root, record, corpus_path, evaluator_path, provenance_path)
        scored.append(updated)
    (root / "attempts.jsonl").write_text("".join(json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for item in scored), encoding="utf-8")
    (root / "attempts.jsonl").chmod(0o600)
    valid = [item for item in scored if item.get("quality_valid") and item.get("score_valid")]
    (root / "valid-samples.jsonl").write_text("".join(json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for item in valid), encoding="utf-8")
    (root / "valid-samples.jsonl").chmod(0o600)
    return scored


def _mean(values: list[float]) -> float | None:
    return statistics.fmean(values) if values else None


def _std(values: list[float]) -> float | None:
    return statistics.pstdev(values) if values else None


def build_aggregate(records: list[dict[str, Any]], task_count: int, required_samples: int, evaluator: dict[str, str], task_ids: list[str] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    scored = [record for record in records if attempt_quality_gate(record)[0] and record.get("quality_valid") and record.get("score_valid")]
    by_task: dict[str, list[dict[str, Any]]] = {}
    for record in scored:
        by_task.setdefault(record["task_id"], []).append(record)
    gaps = []
    task_means: dict[str, dict[str, float | None]] = {}
    for task_id in sorted(by_task):
        samples = by_task[task_id]
        if len(samples) != required_samples:
            gaps.append({"task_id": task_id, "valid_samples": len(samples), "required": required_samples})
        task_means[task_id] = {metric: _mean([float(s["score"][metric]) for s in samples]) for metric in METRICS}
    expected_task_ids = set(task_ids or {r["task_id"] for r in records})
    for task_id in expected_task_ids - set(task_means):
        gaps.append({"task_id": task_id, "valid_samples": 0, "required": required_samples})
    aggregates = {}
    distributions = {}
    for metric in METRICS:
        per_task = [value[metric] for value in task_means.values() if value[metric] is not None]
        samples = [float(record["score"][metric]) for record in scored]
        aggregates[metric] = _mean(per_task) if len(per_task) == task_count and not gaps else None
        distributions[metric] = {"sample_mean": _mean(samples), "sample_stddev": _std(samples), "task_mean_stddev": _std(per_task)}

    valid_telemetry = [r for r in scored if r.get("telemetry", {}).get("valid")]
    usage_totals = {key: sum(int(r["telemetry"]["usage"].get(key, 0)) for r in valid_telemetry) for key in ("input_tokens", "cached_input_tokens", "cache_write_input_tokens", "output_tokens", "reasoning_output_tokens", "uncached_input_tokens")}
    durations = [float(r["elapsed_seconds"]) for r in scored if isinstance(r.get("elapsed_seconds"), (int, float))]
    failures = [r for r in records if not r.get("quality_valid")]
    report = {
        "claimable": not gaps and len(scored) == task_count * required_samples,
        "claimability_gaps": sorted(gaps, key=lambda item: item["task_id"]),
        "task_count": task_count,
        "required_quality_valid_samples_per_task": required_samples,
        "quality_valid_sample_count": len(scored),
        "task_means": task_means,
        "official_metrics": aggregates,
        "metric_distributions": distributions,
        "evaluator": evaluator,
        "paper_to_code_conformance_note": "Metrics use pinned official eval.py semantics. The known paper-versus-code nDCG discrepancy is intentionally preserved.",
        "published_gpt54_reference": {"status": "non_comparable_external_context", "task_count": 848, "model": "GPT-5.4"},
        "attempts": {
            "total": len(records),
            "quality_valid": len(scored),
            "failed_or_invalid": len(failures),
            "retries": sum(1 for r in records if int(r.get("attempt_number", 1)) > 1),
            "failure_classes": {key: sum(1 for r in failures if r.get("failure_class") == key) for key in sorted({r.get("failure_class") for r in failures})},
        },
        "telemetry": {
            "valid_quality_samples": len(valid_telemetry),
            "coverage_complete": len(valid_telemetry) == len(scored),
            "usage_totals": usage_totals,
            "duration_seconds": {"count": len(durations), "total": sum(durations), "mean": _mean(durations), "median": statistics.median(durations) if durations else None, "stddev": _std(durations)},
        },
        "cost": {"status": "unavailable", "reason": "No defensible versioned GPT-5.6 Luna pricing profile is configured."},
    }
    task_summary = {"tasks": {task_id: {"valid_samples": len(by_task.get(task_id, [])), "claimable": len(by_task.get(task_id, [])) == required_samples} for task_id in sorted(expected_task_ids)}, "task_count": task_count, "claimable": report["claimable"]}
    return report, task_summary


def write_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Plain Codex SWE-Explore baseline report",
        "",
        f"Quality claimable: **{report['claimable']}** ({report['quality_valid_sample_count']} quality-valid samples across {report['task_count']} unique tasks).",
        "",
        f"Evaluator: commit `{report['evaluator'].get('commit')}`, SHA-256 `{report['evaluator'].get('sha256')}`.",
        f"Model/configuration: `{report.get('requested_model')}` with reasoning effort `{report.get('requested_reasoning_effort')}`, Codex `{report.get('codex_version')}`.",
        f"Harness SHA-256: `{report.get('harness_sha256')}`; configuration SHA-256: `{report.get('configuration_sha256')}`.",
        f"Filesystem isolation: `{report.get('filesystem_isolation')}`; repository revision verification: `{report.get('repository_revision_verification')}`.",
        "",
    ]
    if report.get("validation_scope") == "structural_path_validation_only":
        lines += [
            "**Non-baseline smoke:** structural path validation only; this report must not be used as a published baseline.",
            "",
        ]
    lines += [
        "Scores use pinned `official/eval.py` semantics. The known paper-to-code nDCG discrepancy is preserved and disclosed; the published GPT-5.4 row is non-comparable external context only.",
        "",
        "## Official metrics",
        "",
        "| Metric | Macro task mean | Sample stddev |",
        "|---|---:|---:|",
    ]
    for metric in METRICS:
        lines.append(f"| {DISPLAY_NAMES.get(metric, metric)} | {report['official_metrics'].get(metric)} | {report['metric_distributions'][metric]['sample_stddev']} |")
    lines += [
        "",
        "## Measurement coverage",
        "",
        f"Attempts: {report['attempts']['total']} total, {report['attempts']['failed_or_invalid']} failed/invalid, {report['attempts']['retries']} retries.",
        f"Telemetry: {report['telemetry']['valid_quality_samples']}/{report['quality_valid_sample_count']} quality-valid samples with authoritative usage.",
        f"Contamination: {report.get('contamination_count', 'not independently validated')}.",
        f"Cost: {report['cost']['status']} — {report['cost']['reason']}",
        "",
        "## Rebuild",
        "",
        "```bash",
        "python3 benchmark_method/codex_baseline/benchmark.py score --run-id <run-id>",
        "python3 benchmark_method/codex_baseline/benchmark.py report --run-id <run-id>",
        "```",
    ]
    return "\n".join(lines) + "\n"


def rebuild_report(repo_root: Path, run_id: str, task_count: int, required_samples: int, evaluator: dict[str, str]) -> dict[str, Any]:
    root = repo_root / ".benchmark-runs" / run_id
    records = load_jsonl(root / "attempts.jsonl")
    task_ids = [json.loads(line)["instance_id"] for line in (root / "corpus.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    report, task_summary = build_aggregate(records, task_count, required_samples, evaluator, task_ids)
    manifest_path = root / "run-manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        configuration = manifest.get("configuration", {})
        report.update({
            "requested_model": configuration.get("requested_model"),
            "requested_reasoning_effort": configuration.get("requested_reasoning_effort"),
            "codex_version": configuration.get("codex_version"),
            "harness_sha256": configuration.get("harness_sha256"),
            "configuration_sha256": configuration.get("configuration_sha256"),
            "filesystem_isolation": configuration.get("filesystem_isolation"),
            "repository_revision_verification": "independent validation required",
        })
    validation_path = root / "validation.json"
    if validation_path.is_file():
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        report["validation"] = validation
        report["contamination_count"] = validation.get("contamination_count")
        report["repository_revision_verification"] = validation.get("counters", {}).get("repository_revision_verified")
    if run_id.startswith("codex-baseline-path-smoke-") or run_id.startswith("codex-baseline-smoke-"):
        report["validation_scope"] = "structural_path_validation_only"
    write_json(root / "aggregate.json", report)
    write_json(root / "task-summary.json", task_summary)
    (root / "report.md").write_text(write_markdown(report), encoding="utf-8")
    return report
