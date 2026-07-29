"""Official scoring plus CodeGraph adoption, fallback, index, token, and timing reports."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import statistics
import sys
from pathlib import Path
from typing import Any

from .artifacts import (
    artifacts_match,
    claimable_sample,
    diagnostic_scoreable,
    load_jsonl,
    rewrite_jsonl,
    scored_artifacts_match,
    sha256_file,
    treatment_valid,
)
from .codegraph import write_json
from .codegraph import directory_manifest
from .integrity import (
    load_treatment_manifest,
    reconcile_sample_slots,
    validate_attempt_records,
    verify_bound_run_artifacts,
    verify_corpus_contract,
)


CODEGRAPH_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = CODEGRAPH_ROOT.parents[1]
BASELINE_SRC = REPOSITORY_ROOT / "benchmark_method" / "codex_baseline" / "src"
if str(BASELINE_SRC) not in sys.path:
    sys.path.insert(0, str(BASELINE_SRC))

from context_graph_bench.corpus import verify_official_evaluator  # noqa: E402
from context_graph_bench.report import DISPLAY_NAMES, METRICS  # noqa: E402


class ReportError(RuntimeError):
    """Raised when saved artifacts cannot support scoring or a report."""


def _load_evaluator(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("pinned_codegraph_swe_explore_eval", path)
    if spec is None or spec.loader is None:
        raise ReportError("evaluator_failure: cannot load pinned evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _scoring_source(run_root: Path, record: dict[str, Any]) -> tuple[dict[str, int], dict[str, dict[str, Any]]]:
    artifact = run_root / record["artifacts"]["scoring_source"]
    try:
        source = json.loads(artifact.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportError(f"scoring_provenance_refused: scoring source is unreadable: {exc}") from exc
    rows = source.get("files")
    if source.get("schema_version") != "codegraph-scoring-source-v1" or not isinstance(rows, list):
        raise ReportError("scoring_provenance_refused: scoring source schema differs")
    source_map = {row.get("path"): row for row in rows if isinstance(row, dict)}
    if len(source_map) != len(rows):
        raise ReportError("scoring_provenance_refused: scoring source paths are duplicate or malformed")
    canonical = json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if hashlib.sha256(canonical).hexdigest() != source.get("manifest_sha256"):
        raise ReportError("scoring_provenance_refused: scoring source manifest digest differs")
    repository = Path(record["repository_path"])
    current: list[dict[str, Any]] = []
    for path in sorted(repository.rglob("*")):
        relative = path.relative_to(repository)
        if not path.is_file() or ".git" in relative.parts:
            continue
        contents = path.read_bytes()
        current.append(
            {
                "path": relative.as_posix(),
                "bytes": len(contents),
                "sha256": hashlib.sha256(contents).hexdigest(),
                "line_count": len(contents.decode("utf-8", errors="replace").splitlines()),
            }
        )
    if current != rows:
        raise ReportError("scoring_provenance_refused: repository bytes drifted from the immutable scoring source")
    return {path: int(row["line_count"]) for path, row in source_map.items()}, source_map


def _validate_regions_from_source(response: Any, source_map: dict[str, dict[str, Any]], max_regions: int) -> list[dict[str, Any]]:
    if not isinstance(response, dict) or set(response) != {"regions"} or not isinstance(response["regions"], list):
        raise ReportError("scoring_provenance_refused: response schema differs")
    if not 1 <= len(response["regions"]) <= max_regions:
        raise ReportError("scoring_provenance_refused: response region count differs")
    regions: list[dict[str, Any]] = []
    for region in response["regions"]:
        if not isinstance(region, dict) or set(region) != {"path", "start", "end", "reason"}:
            raise ReportError("scoring_provenance_refused: response region fields differ")
        path = region["path"]
        if path not in source_map:
            raise ReportError("scoring_provenance_refused: response path is absent from scoring source")
        start, end = region["start"], region["end"]
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or start < 1
            or end < start
            or end > source_map[path]["line_count"]
        ):
            raise ReportError("scoring_provenance_refused: response range is outside scoring source")
        regions.append(dict(region))
    return regions


def score_run(run_root: Path, evaluator_path: Path, provenance_path: Path) -> list[dict[str, Any]]:
    manifest = load_treatment_manifest(run_root, expected_run_id=run_root.name)
    verify_corpus_contract(run_root, manifest)
    verify_bound_run_artifacts(run_root, manifest)
    provenance = verify_official_evaluator(evaluator_path, provenance_path)
    if manifest.get("evaluator") != provenance:
        raise ReportError("scoring_provenance_refused: evaluator identity differs from run manifest")
    evaluator_module = _load_evaluator(evaluator_path)
    corpus_path = run_root / "corpus.jsonl"
    records = load_jsonl(run_root / "attempts.jsonl")
    task_ids = {task["instance_id"] for task in manifest["corpus"]["tasks"]}
    validate_attempt_records(
        records,
        run_id=manifest["run_id"],
        task_ids=task_ids,
        required_samples=int(manifest["configuration"]["sample_count"]),
        run_root=run_root,
        manifest=manifest,
    )
    if any(not scored_artifacts_match(run_root, record) for record in records):
        raise ReportError("scoring_provenance_refused: scoring input artifact bytes differ")
    scored: list[dict[str, Any]] = []
    for original in records:
        record = dict(original)
        if not diagnostic_scoreable(record):
            record["score_valid"] = False
            record["validity"] = dict(record["validity"]) | {"scoring": False}
            record["quality_valid"] = False
            record["claimable_sample"] = False
            scored.append(record)
            continue
        if not artifacts_match(run_root, record):
            raise ReportError(f"artifact hash mismatch for {record['task_id']} {record['attempt_id']}")
        response_path = run_root / record["artifacts"]["response"]
        response = json.loads(response_path.read_text(encoding="utf-8"))
        line_count_map, source_map = _scoring_source(run_root, record)
        regions = _validate_regions_from_source(response, source_map, int(record["max_regions"]))
        predictions = [(region["path"], region["start"], region["end"]) for region in regions]
        line_counts = {record["task_id"]: line_count_map}
        evaluator = evaluator_module.ExploreEvaluator(corpus_path, file_line_counts=line_counts)
        result = evaluator.evaluate(lambda _issue, _instance_id: predictions, record["task_id"], METRICS)
        metrics = result[record["task_id"]]
        line_input = (json.dumps(line_counts, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
        score = {
            "score_valid": True,
            "diagnostic": not treatment_valid(record),
            "evaluator_commit": provenance["commit"],
            "evaluator_sha256": provenance["sha256"],
            "task_id": record["task_id"],
            "attempt_id": record["attempt_id"],
            "regions": regions,
            "metrics": metrics,
            "line_count_sha256": hashlib.sha256(line_input).hexdigest(),
        }
        score_path = run_root / record["artifacts"]["attempt"] / "score.json"
        if score_path.exists():
            try:
                existing_score = json.loads(score_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ReportError(
                    f"scoring_provenance_refused: existing score artifact is unreadable for {record['task_id']}"
                ) from exc
            if existing_score != score:
                raise ReportError(
                    f"scoring_provenance_refused: existing score artifact drifted for {record['task_id']}"
                )
            if record.get("score_valid") is True and record.get("score_sha256") != sha256_file(score_path):
                raise ReportError(
                    f"scoring_provenance_refused: recorded score digest drifted for {record['task_id']}"
                )
        else:
            write_json(score_path, score)
        record["score_valid"] = True
        record["score"] = metrics
        record["score_artifact"] = str(score_path.relative_to(run_root))
        record["score_sha256"] = sha256_file(score_path)
        record["evaluator_commit"] = provenance["commit"]
        record["evaluator_sha256"] = provenance["sha256"]
        record["validity"] = dict(record["validity"]) | {"scoring": True}
        record["quality_valid"] = treatment_valid(record)
        record["claimable_sample"] = claimable_sample(record)
        scored.append(record)
    validate_attempt_records(
        scored,
        run_id=manifest["run_id"],
        task_ids=task_ids,
        required_samples=int(manifest["configuration"]["sample_count"]),
        run_root=run_root,
        manifest=manifest,
    )
    rewrite_jsonl(run_root / "attempts.jsonl", scored)
    rewrite_jsonl(run_root / "valid-samples.jsonl", [record for record in scored if claimable_sample(record)])
    rewrite_jsonl(run_root / "diagnostic-scores.jsonl", [record for record in scored if record.get("score_valid")])
    return scored


def _mean(values: list[float]) -> float | None:
    return statistics.fmean(values) if values else None


def _distribution(values: list[float]) -> dict[str, Any]:
    return {
        "count": len(values),
        "total": sum(values),
        "mean": _mean(values),
        "median": statistics.median(values) if values else None,
        "min": min(values) if values else None,
        "max": max(values) if values else None,
    }


def _usage(records: list[dict[str, Any]]) -> dict[str, Any]:
    fields = (
        "input_tokens",
        "cached_input_tokens",
        "cache_write_input_tokens",
        "uncached_input_tokens",
        "output_tokens",
        "reasoning_output_tokens",
    )
    totals = {field: sum(int(record["telemetry"]["usage"].get(field, 0)) for record in records) for field in fields}
    totals["claim_aligned_total_tokens"] = totals["input_tokens"] + totals["output_tokens"]
    cache_free = totals["cached_input_tokens"] == 0 and totals["cache_write_input_tokens"] == 0
    return {
        "coverage_complete": len(records) > 0 and all(record.get("validity", {}).get("telemetry") is True for record in records),
        "totals": totals,
        "cache_free": cache_free,
        "performance_label": "cold-cache" if cache_free else "observed ephemeral-session performance",
    }


def _attempt_artifact_identities(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    identities: list[dict[str, Any]] = []
    for record in sorted(
        records,
        key=lambda value: (
            value["task_id"],
            int(value["sample_id"]),
            int(value["attempt_number"]),
        ),
    ):
        artifacts = {
            key: {
                "path": path,
                "sha256": record["artifact_sha256"][key],
            }
            for key, path in sorted(record.get("artifacts", {}).items())
            if key != "attempt"
        }
        score_path = record.get("score_artifact")
        score_sha256 = record.get("score_sha256")
        identities.append(
            {
                "task_id": record["task_id"],
                "sample_id": record["sample_id"],
                "attempt_id": record["attempt_id"],
                "artifacts": artifacts,
                "score": (
                    {"path": score_path, "sha256": score_sha256}
                    if isinstance(score_path, str)
                    and isinstance(score_sha256, str)
                    else None
                ),
            }
        )
    return identities


def build_report(
    records: list[dict[str, Any]],
    task_ids: list[str],
    index_records: list[dict[str, Any]],
    required_samples: int,
    evaluator: dict[str, str],
) -> dict[str, Any]:
    reconciliation = reconcile_sample_slots(records, task_ids, required_samples)
    included = list(reconciliation["adopted"].values())
    scored_diagnostics = [record for record in records if record.get("score_valid") is True]
    by_task: dict[str, list[dict[str, Any]]] = {task_id: [] for task_id in task_ids}
    for record in included:
        by_task.setdefault(record["task_id"], []).append(record)
    gaps = [
        {
            "task_id": task_id,
            "valid_samples": len(by_task[task_id]),
            "required": required_samples,
            "missing_sample_ids": [
                row["sample_id"] for row in reconciliation["missing"] if row["task_id"] == task_id
            ],
        }
        for task_id in task_ids
        if len(by_task[task_id]) != required_samples
    ]
    task_means = {
        task_id: {
            metric: _mean([float(record["score"][metric]) for record in by_task[task_id]])
            for metric in METRICS
        }
        for task_id in task_ids
        if by_task[task_id]
    }
    official_metrics = {
        metric: _mean([float(task_means[task_id][metric]) for task_id in task_ids])
        if not gaps and len(task_means) == len(task_ids)
        else None
        for metric in METRICS
    }
    failures = [record for record in records if not treatment_valid(record)]
    all_failure_classes = sorted(
        {
            failure
            for record in failures
            for failure in record.get("failure_classes", [record.get("failure_class")])
            if isinstance(failure, str) and failure
        }
    )
    failure_classes = {
        failure: sum(1 for record in failures if failure in record.get("failure_classes", [record.get("failure_class")]))
        for failure in all_failure_classes
    }
    graph_used = [record for record in records if record.get("validity", {}).get("graph_use") is True]
    fallback_counts = [int(record.get("navigation", {}).get("fallback_navigation_after_graph", 0)) for record in graph_used]
    pregraph_counts = [int(record.get("navigation", {}).get("built_in_navigation_before_graph", 0)) for record in records]
    index_ready = len(index_records) == len(task_ids) and all(record.get("ready") is True and record.get("frozen") is True for record in index_records)
    index_durations = [float(record["duration_seconds"]) for record in index_records if isinstance(record.get("duration_seconds"), (int, float))]
    index_bytes = [int(record["index_bytes"]) for record in index_records if isinstance(record.get("index_bytes"), int)]
    agent_durations = [float(record["elapsed_seconds"]) for record in included if isinstance(record.get("elapsed_seconds"), (int, float))]
    amortized_by_task = {}
    index_by_task = {record["task_id"]: record for record in index_records}
    for task_id in task_ids:
        attempt_seconds = sum(float(record.get("elapsed_seconds", 0)) for record in records if record.get("task_id") == task_id)
        amortized_by_task[task_id] = attempt_seconds + float(index_by_task.get(task_id, {}).get("duration_seconds", 0))
    report = {
        "arm": "codex-codegraph-enriched",
        "claimable": not gaps and len(included) == len(task_ids) * required_samples and index_ready,
        "claimability_gaps": gaps,
        "task_count": len(task_ids),
        "required_graph_and_quality_valid_samples_per_task": required_samples,
        "claimable_sample_count": len(included),
        "task_means": task_means,
        "official_metrics": official_metrics,
        "evaluator": evaluator,
        "attempts": {
            "total": len(records),
            "claimable": len(included),
            "diagnostically_scored": len(scored_diagnostics),
            "failed_or_invalid": len(failures),
            "retries": sum(1 for record in records if int(record.get("attempt_number", 1)) > 1),
            "failure_classes": failure_classes,
        },
        "adoption": {
            "successful_graph_use_attempts": len(graph_used),
            "successful_use_rate": len(graph_used) / len(records) if records else None,
            "no_use_attempts": sum(1 for record in records if record.get("failure_class") == "codegraph_not_used"),
            "tool_failure_attempts": sum(1 for record in records if record.get("failure_class") == "codegraph_tool_failure"),
        },
        "fallback": {
            "attempts_with_fallback_after_graph": sum(1 for count in fallback_counts if count > 0),
            "fallback_navigation_calls": sum(fallback_counts),
            "built_in_navigation_before_graph_calls": sum(pregraph_counts),
        },
        "intent_to_treat": {
            "response_valid_scored_attempts": len(scored_diagnostics),
            "official_metric_means": {
                metric: _mean([float(record["score"][metric]) for record in scored_diagnostics])
                for metric in METRICS
            },
        },
        "artifact_identities": _attempt_artifact_identities(records),
        "telemetry": _usage(included),
        "timing": {
            "agent_execution_seconds": _distribution(agent_durations),
            "index_preparation_seconds": _distribution(index_durations),
            "amortized_task_seconds": amortized_by_task,
        },
        "indexes": {
            "ready": index_ready,
            "record_count": len(index_records),
            "disk_bytes": _distribution([float(value) for value in index_bytes]),
        },
        "cost": {
            "status": "unavailable",
            "reason": "No versioned pricing profile proves per-request cache and long-context billing semantics.",
        },
        "treatment_differences": [
            "CodeGraph-use prompt addition",
            "pinned immutable CodeGraph index",
            "per-attempt CodeGraph MCP server",
        ],
    }
    return report


def write_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Codex + CodeGraph SWE-Explore report",
        "",
        f"Claimable: **{report['claimable']}** ({report['claimable_sample_count']} graph-use-valid, quality-valid samples).",
        "",
        "## Official metrics",
        "",
        "| Metric | Equal-task mean |",
        "|---|---:|",
    ]
    for metric in METRICS:
        lines.append(f"| {DISPLAY_NAMES.get(metric, metric)} | {report['official_metrics'].get(metric)} |")
    lines += [
        "",
        "## Adoption and fallback",
        "",
        f"Successful graph use: {report['adoption']['successful_graph_use_attempts']}/{report['attempts']['total']} attempts.",
        f"No-use attempts: {report['adoption']['no_use_attempts']}; tool failures: {report['adoption']['tool_failure_attempts']}.",
        f"Fallback navigation calls after graph use: {report['fallback']['fallback_navigation_calls']}.",
        "",
        "## Timing and index overhead",
        "",
        f"Agent execution seconds: {report['timing']['agent_execution_seconds']}.",
        f"Index preparation seconds: {report['timing']['index_preparation_seconds']}.",
        f"Index disk bytes: {report['indexes']['disk_bytes']}.",
        "",
        f"Token performance label: {report['telemetry']['performance_label']}.",
        f"Cost: {report['cost']['status']} — {report['cost']['reason']}",
    ]
    return "\n".join(lines) + "\n"


def rebuild_report(run_root: Path, evaluator_path: Path, provenance_path: Path) -> dict[str, Any]:
    manifest = load_treatment_manifest(run_root, expected_run_id=run_root.name)
    verify_corpus_contract(run_root, manifest)
    verify_bound_run_artifacts(run_root, manifest)
    evaluator = verify_official_evaluator(evaluator_path, provenance_path)
    records = load_jsonl(run_root / "attempts.jsonl")
    task_ids = [task["instance_id"] for task in manifest["corpus"]["tasks"]]
    validate_attempt_records(
        records,
        run_id=manifest["run_id"],
        task_ids=set(task_ids),
        required_samples=int(manifest["configuration"]["sample_count"]),
        run_root=run_root,
        manifest=manifest,
    )
    if any(not scored_artifacts_match(run_root, record) for record in records):
        raise ReportError("scoring_provenance_refused: report input artifact bytes differ")
    index_records = [
        json.loads((run_root / reference["path"]).read_text(encoding="utf-8"))
        for reference in manifest["indexes"]["records"]
    ]
    for record in index_records:
        index_path = Path(record.get("index_path", ""))
        if not index_path.is_dir() or directory_manifest(index_path) != record.get("index_artifact_manifest"):
            raise ReportError("codegraph_index_stale: report refuses mutated index artifacts")
    report = build_report(records, task_ids, index_records, int(manifest["configuration"]["sample_count"]), evaluator)
    report.update(
        {
            "run_id": manifest["run_id"],
            "requested_model": manifest["configuration"]["requested_model"],
            "requested_reasoning_effort": manifest["configuration"]["requested_reasoning_effort"],
            "codex_version": manifest["configuration"]["codex_version"],
            "configuration_sha256": manifest["configuration"]["configuration_sha256"],
            "harness_sha256": manifest["configuration"]["harness_sha256"],
        }
    )
    write_json(run_root / "aggregate.json", report)
    report_markdown = run_root / "report.md"
    report_markdown.write_text(write_markdown(report), encoding="utf-8")
    report_markdown.chmod(0o600)
    return report
