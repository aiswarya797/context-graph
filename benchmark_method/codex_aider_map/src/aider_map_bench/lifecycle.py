"""Concrete treatment lifecycle built on the frozen baseline child seam."""

from __future__ import annotations

import json
import shutil
import hashlib
import os
import tempfile
from pathlib import Path
from typing import Any, Callable

from context_graph_bench.codex_runner import (
    child_environment,
    run_child,
    validate_regions,
)
from context_graph_bench.event_audit import audit_events
from context_graph_bench.telemetry import parse_events
from context_graph_bench.artifacts import load_jsonl, persist_attempt, run_root, write_json
from context_graph_bench.codex_runner import create_runtime_dirs, prepare_isolated_repository, remove_isolated_repository, resolve_executable, validate_auth_source, verify_pinned_version
from context_graph_bench.corpus import verify_repository_head
from context_graph_bench.codex_runner import file_sha256
from context_graph_bench.corpus import verify_official_evaluator
from context_graph_bench.report import rebuild_report, score_run

from .attempt import AttemptPlan, finalize_attempt_telemetry, persist_attempt_inputs, plan_attempt
from .prompt import build_treatment_prompt
from .runner import baseline_equivalent_config, frozen_baseline_config

ROOT = Path(__file__).resolve().parents[4]
FROZEN_RESPONSE_SCHEMA_SHA256 = "59865ed199e17c7c27fc7a38ebdebf93170f48e6c593273bd28403c54a07f3bb"


class LifecycleError(RuntimeError):
    pass


def next_attempt_number(existing: list[dict[str, Any]], task_id: str, sample_id: int, retry_cap: int) -> int:
    """Match the baseline's immutable sample-slot and retry admission rule."""
    prior = [item for item in existing if item.get("task_id", item.get("metadata", {}).get("task_id")) == task_id and item.get("sample_id", item.get("metadata", {}).get("sample_id")) == sample_id]
    if any(item.get("quality_valid") is True for item in prior):
        raise LifecycleError("sample_admission_refused: quality-valid sample slot already exists")
    if len(prior) > retry_cap:
        raise LifecycleError("retry_cap: immutable sample slot exhausted")
    return len(prior) + 1


def execute_attempt(
    task: dict[str, Any], config: dict[str, Any], *, executable: Path, state_dir: Path,
    schema_path: Path, repository: Path, private_home: Path, baseline_template: str,
    attempt_root: Path, run_id: str, sample_id: int, attempt_number: int,
    child: Callable[..., dict[str, Any]] = run_child,
) -> dict[str, Any]:
    """Run exactly one already-bound attempt and retain all replay inputs.

    Every binding and prompt check in ``plan_attempt`` occurs before this calls
    the injected baseline runner.  This is the sole provider-launch seam.
    """
    plan = plan_attempt(task, config, executable=executable, state_dir=state_dir, schema_path=schema_path, repository=repository, baseline_template=baseline_template, run_id=run_id, sample_id=sample_id, attempt_number=attempt_number)
    persisted = persist_attempt_inputs(plan, attempt_root)
    events = state_dir / "events.jsonl"
    stderr = state_dir / "stderr.log"
    result = child(plan.command, plan.prompt, state_dir, events, stderr, config["treatment"]["timeout_seconds"], environment=child_environment(executable), working_directory=repository, codex_home=private_home)
    raw_events = events.read_text(encoding="utf-8", errors="replace") if events.exists() else ""
    raw_stderr = stderr.read_text(encoding="utf-8", errors="replace") if stderr.exists() else ""
    try:
        telemetry = finalize_attempt_telemetry(raw_events, raw_stderr)
    except Exception as exc:
        telemetry = {"valid": False, "failure_class": "navigation_replay_refused", "error": str(exc)}
    response_path = state_dir / "response.json"
    response_bytes = response_path.read_bytes() if response_path.is_file() else b""
    response_valid = False
    response_error = None
    try:
        response = json.loads(response_bytes)
        validate_regions(response, repository, config["treatment"]["max_regions"])
        response_valid = True
    except Exception as exc:
        response_error = str(exc)
    for source, name in ((events, "events.jsonl"), (stderr, "stderr.log"), (response_path, "response.json")):
        target = attempt_root / name
        if source.is_file():
            shutil.copyfile(source, target)
    contamination = audit_events(raw_events + "\n" + raw_stderr)
    admitted = bool(result.get("returncode") == 0 and not result.get("timed_out") and result.get("telemetry", {}).get("valid") and telemetry.get("navigation_replay", {}).get("valid") and response_valid and contamination.get("passed"))
    record = {"metadata": plan.metadata | {"repository_path": str(repository)}, "inputs": persisted, "result": result, "telemetry": telemetry, "response_sha256": hashlib.sha256(response_bytes).hexdigest() if response_bytes else None, "response_valid": response_valid, "response_validation_error": response_error, "contamination_audit": contamination, "quality_valid": admitted, "admission": {"baseline_response_rules": response_valid, "baseline_telemetry_rules": result.get("telemetry", {}).get("valid") is True, "baseline_contamination_rules": contamination.get("passed") is True, "navigation_replay_valid": telemetry.get("navigation_replay", {}).get("valid") is True}}
    record_path = attempt_root / "attempt-record.json"
    record_path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return record


def score(root: Path, run_id: str, evaluator: Path, provenance: Path) -> list[dict[str, Any]]:
    """Use the untouched official evaluator through the baseline scorer."""
    return score_run(root, run_id, evaluator, provenance)


def report(root: Path, run_id: str, task_count: int, samples: int, evaluator: dict[str, Any]) -> dict[str, Any]:
    return rebuild_report(root, run_id, task_count, samples, evaluator)


def audit_attempt(record_path: Path) -> dict[str, Any]:
    """Recompute every local claim from retained bytes; never trust flags."""
    record = json.loads(record_path.read_text(encoding="utf-8"))
    root = record_path.parent
    required = ("prompt.md", "map-prompt-identity.json", "events.jsonl", "stderr.log", "response.json")
    missing = [name for name in required if not (root / name).is_file()]
    if missing:
        return {"passed": False, "missing": missing}
    prompt = (root / "prompt.md").read_bytes()
    try:
        identity = json.loads((root / "map-prompt-identity.json").read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return {"passed": False, "missing": [], "audit_error": f"malformed_map_prompt_identity:{exc}"}
    events = (root / "events.jsonl").read_text(encoding="utf-8", errors="replace")
    stderr = (root / "stderr.log").read_text(encoding="utf-8", errors="replace")
    response = (root / "response.json").read_bytes()
    telemetry = parse_events(events)
    try:
        replay = finalize_attempt_telemetry(events, stderr).get("navigation_replay", {})
    except Exception as exc:
        replay = {"valid": False, "failure_class": "navigation_replay_refused", "error": str(exc)}
    contamination = audit_events(events + "\n" + stderr)
    expected_prompt = identity.get("final_prompt_sha256")
    map_info = identity.get("metadata", {}).get("map", {})
    response_digest = hashlib.sha256(response).hexdigest()
    expected_response = record.get("response_sha256", record.get("artifact_sha256", {}).get("response"))
    response_valid = False
    try:
        response_valid = bool(validate_regions(json.loads(response), Path(record.get("repository_path", record.get("metadata", {}).get("repository_path", "")))))
    except Exception:
        response_valid = False
    current_map = None
    prompt_reconstructed = False
    corpus_valid = False
    audit_error = None
    try:
        run_root = next(parent for parent in record_path.parents if (parent / "corpus.jsonl").is_file())
        corpus = (run_root / "corpus.jsonl").read_bytes()
        manifest = json.loads((run_root / "run-manifest.json").read_text(encoding="utf-8"))
        tasks = [json.loads(line) for line in corpus.decode("utf-8").splitlines() if line.strip()]
        corpus_valid = (
            manifest.get("corpus_sha256") == hashlib.sha256(corpus).hexdigest()
            and manifest.get("corpus_task_count") == len(tasks)
            and manifest.get("task_ids") == [item.get("instance_id") for item in tasks]
        )
        task = next(item for item in tasks if item.get("instance_id") == record.get("task_id"))
        from .binding import bind_map
        bound = bind_map(task)
        baseline_template = ROOT / "benchmark_method" / "codex_baseline" / "config" / "region-selection-prompt.md"
        rebuilt, rebuilt_metadata = build_treatment_prompt(baseline_template.read_text(encoding="utf-8"), task["issue_text"], bound)
        prompt_reconstructed = rebuilt.encode("utf-8") == prompt and rebuilt_metadata["final_prompt_sha256"] == hashlib.sha256(prompt).hexdigest()
        current_map = bound.map_sha256
    except Exception as exc:
        audit_error = f"authority_or_prompt_reconstruction:{exc}"
    hashes = record.get("artifact_sha256", {})
    raw_hashes_valid = all(not hashes.get(key) or hashes.get(key) == hashlib.sha256((root / name).read_bytes()).hexdigest() for key, name in (("events", "events.jsonl"), ("stderr", "stderr.log"), ("response", "response.json"), ("prompt", "prompt.md"), ("map_prompt_identity", "map-prompt-identity.json")))
    return {"passed": bool(expected_prompt == hashlib.sha256(prompt).hexdigest() and current_map == map_info.get("map_sha256") and prompt_reconstructed and corpus_valid and telemetry.get("valid") is True and replay.get("valid") is True and contamination.get("passed") is True and expected_response == response_digest and response_valid and raw_hashes_valid), "missing": [], "audit_error": audit_error, "prompt_sha256": hashlib.sha256(prompt).hexdigest(), "map_sha256": current_map, "prompt_reconstructed": prompt_reconstructed, "corpus_valid": corpus_valid, "raw_hashes_valid": raw_hashes_valid, "response_sha256": response_digest, "response_valid": response_valid, "provider_telemetry": telemetry, "navigation_replay": replay, "contamination": contamination}


def inspect_smoke(record_path: Path) -> dict[str, Any]:
    audit = audit_attempt(record_path)
    record = json.loads(record_path.read_text())
    return {"status": "passed" if audit["passed"] and record.get("quality_valid") is True else "failed", "audit": audit, "quality_valid": record.get("quality_valid") is True, "map_identity": record.get("metadata", {}).get("map", {})}


def smoke_gate(record_path: Path) -> dict[str, Any]:
    inspection = inspect_smoke(record_path)
    if inspection["status"] != "passed":
        raise LifecycleError("smoke_gate_failed: smoke inspection is not reproducibly valid")
    return {"status": "passed", "attempt_record": str(record_path), "map_sha256": inspection["map_identity"].get("map_sha256"), "prompt_sha256": inspection["audit"].get("prompt_sha256")}


def compare(baseline_records: list[dict[str, Any]], treatment_records: list[dict[str, Any]]) -> dict[str, Any]:
    """Fail closed unless admitted sample slots are exactly matched."""
    def slots(items: list[dict[str, Any]]) -> set[tuple[str, int]]:
        return {(str(item.get("task_id", item.get("metadata", {}).get("task_id"))), int(item.get("sample_id", item.get("metadata", {}).get("sample_id", 0)))) for item in items if item.get("quality_valid") is True}
    control, treatment = slots(baseline_records), slots(treatment_records)
    if not control or control != treatment:
        raise LifecycleError("comparison_refused: quality-valid baseline and treatment slots are not matched")
    return {"matched": True, "matched_sample_count": len(control), "baseline_slots": sorted(control), "treatment_slots": sorted(treatment)}


def _rewrite_record_line(path: Path, replacement: dict[str, Any]) -> None:
    records = load_jsonl(path)
    records[-1] = replacement
    path.write_text("".join(json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for item in records), encoding="utf-8")
    os.chmod(path, 0o600)


def run_treatment(
    repo_root: Path, tasks: list[dict[str, Any]], config: dict[str, Any], *, run_id: str,
    schema_path: Path, baseline_template: str, auth_source: Path, limit: int | None = None,
    samples: int | None = None, child: Callable[..., dict[str, Any]] = run_child,
) -> dict[str, Any]:
    """Full multi-task/sample production loop using baseline snapshots and persistence."""
    # Validate all mutable command/preparation inputs before any run directory,
    # snapshot, or child seam is touched.
    baseline_equivalent_config(config)
    if hashlib.sha256(schema_path.read_bytes()).hexdigest() != FROZEN_RESPONSE_SCHEMA_SHA256:
        raise LifecycleError("configuration_error: frozen response schema digest differs")
    expected_auth_source = Path(frozen_baseline_config()["paths"]["codex_auth_source"])
    if auth_source.expanduser().resolve(strict=False) != expected_auth_source.expanduser().resolve(strict=False):
        raise LifecycleError("configuration_error: auth source differs from frozen baseline")
    executable = resolve_executable(config)
    version = verify_pinned_version(executable, config["treatment"]["codex_version"])
    if file_sha256(executable) != "1da3f4e0e96028b8a771814293c3033dafd1971f943f6c7e79b0897fe705f590":
        raise LifecycleError("configuration_error: frozen Codex executable digest differs")
    validate_auth_source(auth_source)
    from .binding import EXPECTED_MANIFEST_SHA256, EXPECTED_PHASE_FREEZE_SHA256, EXPECTED_TASK3_SEAL_SHA256
    target = samples or config["treatment"]["sample_count"]
    selected = tasks[:limit] if limit else tasks
    corpus_bytes = b"".join((json.dumps(task, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8") for task in selected)
    corpus_sha = hashlib.sha256(corpus_bytes).hexdigest()
    task_ids = [task["instance_id"] for task in selected]
    root = run_root(repo_root, run_id)
    existing_manifest = root / "run-manifest.json"
    if not existing_manifest.exists() and any(root.iterdir()):
        raise LifecycleError("configuration_error: nonempty run root lacks run manifest")
    prompt_sha = hashlib.sha256(baseline_template.encode()).hexdigest()
    schema_sha = hashlib.sha256(schema_path.read_bytes()).hexdigest()
    evaluator = verify_official_evaluator(repo_root / "benchmark_method" / "common" / "official" / "eval.py", repo_root / "benchmark_method" / "common" / "official" / "provenance.json")
    if prompt_sha != "5acc7b53c178a4c67f382ac73252a4a3f524385d5f73c66e98bc8300865dc365" or evaluator["sha256"] != "feea0a7fe67b08e68c940e10887d5b4feaae0b8c58e256eb09f253e65492d745":
        raise LifecycleError("configuration_error: frozen baseline prompt or evaluator differs")
    if existing_manifest.exists():
        prior = json.loads(existing_manifest.read_text(encoding="utf-8"))
        required_resume = {"arm": "codex-aider-map", "run_id": run_id, "requested_model": config["treatment"]["model"], "requested_reasoning_effort": config["treatment"]["reasoning_effort"], "timeout_seconds": config["treatment"]["timeout_seconds"], "sample_count": target, "retry_cap": config["treatment"]["retry_cap"], "max_regions": config["treatment"]["max_regions"], "codex_executable_sha256": file_sha256(executable), "codex_version": version, "maps_manifest_sha256": EXPECTED_MANIFEST_SHA256, "phase_freeze_sha256": EXPECTED_PHASE_FREEZE_SHA256, "task3_seal_sha256": EXPECTED_TASK3_SEAL_SHA256, "prompt_template_sha256": prompt_sha, "schema_sha256": schema_sha, "evaluator_sha256": evaluator["sha256"], "corpus_task_count": len(selected), "corpus_sha256": corpus_sha, "task_ids": task_ids}
        if any(prior.get(key) != value for key, value in required_resume.items()):
            raise LifecycleError("configuration_error: refusing stale or foreign run resume")
        if not (root / "corpus.jsonl").is_file() or (root / "corpus.jsonl").read_bytes() != corpus_bytes:
            raise LifecycleError("configuration_error: refusing mismatched corpus resume")
    if not existing_manifest.exists():
        write_json(root / "run-manifest.json", {"arm": "codex-aider-map", "protocol": "direct-region-v1+aider-repomap-v1", "run_id": run_id, "requested_model": config["treatment"]["model"], "requested_reasoning_effort": config["treatment"]["reasoning_effort"], "timeout_seconds": config["treatment"]["timeout_seconds"], "sample_count": target, "retry_cap": config["treatment"]["retry_cap"], "max_regions": config["treatment"]["max_regions"], "codex_executable_sha256": file_sha256(executable), "codex_version": version, "maps_manifest_sha256": EXPECTED_MANIFEST_SHA256, "phase_freeze_sha256": EXPECTED_PHASE_FREEZE_SHA256, "task3_seal_sha256": EXPECTED_TASK3_SEAL_SHA256, "prompt_template_sha256": prompt_sha, "schema_sha256": schema_sha, "evaluator_sha256": evaluator["sha256"], "corpus_task_count": len(selected), "corpus_sha256": corpus_sha, "task_ids": task_ids, "parity": "baseline-command-runner-response-telemetry-retry"})
        (root / "corpus.jsonl").write_bytes(corpus_bytes)
        os.chmod(root / "corpus.jsonl", 0o600)
    isolation = Path(tempfile.mkdtemp(prefix="aider-map-treatment-", dir="/private/tmp"))
    forbidden_paths = [repo_root, repo_root / ".benchmark-runs", repo_root / ".benchmark-work", repo_root / "benchmark_method" / "common" / "official", repo_root / "benchmark_method" / "common" / "inputs", *(Path(task["prepared"]["resolved_path"]) for task in selected if isinstance(task.get("prepared"), dict) and task["prepared"].get("resolved_path"))]
    records: list[dict[str, Any]] = []
    try:
        for task in selected:
            prepared = task.get("prepared")
            if not isinstance(prepared, dict) or not prepared.get("resolved_path"):
                raise LifecycleError("configuration_error: treatment requires baseline prepared task snapshots")
            source = Path(prepared["resolved_path"])
            verify_repository_head(source, task["base_commit"])
            for sample_id in range(1, target + 1):
                existing = load_jsonl(root / "attempts.jsonl")
                if any(item.get("task_id") == task["instance_id"] and item.get("sample_id") == sample_id and item.get("quality_valid") is True for item in existing):
                    continue
                attempt_number = next_attempt_number(existing, task["instance_id"], sample_id, config["treatment"]["retry_cap"])
                snapshot = prepare_isolated_repository(source, task["base_commit"], isolation, task["instance_id"], f"sample-{sample_id}-attempt-{attempt_number}")
                private_home = state = None
                try:
                    private_home, state = create_runtime_dirs(isolation / "runtime" / task["instance_id"] / str(sample_id) / str(attempt_number), auth_source)
                    shutil.copyfile(schema_path, state / "agent-regions.schema.json")
                    plan = plan_attempt(task, config, executable=executable, state_dir=state, schema_path=schema_path, repository=Path(snapshot["path"]), baseline_template=baseline_template, run_id=run_id, sample_id=sample_id, attempt_number=attempt_number)
                    events, stderr = state / "events.jsonl", state / "stderr.log"
                    result = child(plan.command, plan.prompt, state, events, stderr, config["treatment"]["timeout_seconds"], environment=child_environment(executable), working_directory=Path(snapshot["path"]), codex_home=private_home, forbidden_paths=forbidden_paths)
                    result = {"events_path": str(events), "stderr_path": str(stderr), "state_dir": str(state), **result}
                    response_path = state / "response.json"
                    if result.get("response") is None and response_path.is_file():
                        try:
                            result["response"] = json.loads(response_path.read_text(encoding="utf-8"))
                        except json.JSONDecodeError:
                            result["response"] = None
                    raw_events = events.read_text(encoding="utf-8", errors="replace") if events.exists() else ""
                    raw_stderr = stderr.read_text(encoding="utf-8", errors="replace") if stderr.exists() else ""
                    contamination = audit_events(raw_events + "\n" + raw_stderr, forbidden_paths)
                    result["contamination_audit"] = contamination
                    try:
                        navigation = finalize_attempt_telemetry(raw_events, raw_stderr)
                    except Exception as exc:
                        navigation = {"navigation_replay": {"valid": False, "failure_class": "unknown_event_shape", "error": str(exc)}}
                    if not navigation.get("navigation_replay", {}).get("valid"):
                        result["failure_class"] = "navigation_replay_refused"
                    if result.get("sandboxed") is not True:
                        result["failure_class"] = "filesystem_isolation_unproven"
                    metadata = plan.metadata | {"repository_path": str(source), "child_repository_path": snapshot["path"], "child_snapshot": snapshot, "verified_head": task["base_commit"], "codex_executable": str(executable), "codex_version": version, "max_regions": config["treatment"]["max_regions"], "contamination_audit": contamination, "navigation_replay": navigation.get("navigation_replay"), "forbidden_path_count": len(forbidden_paths), "sandboxed": result.get("sandboxed"), "sandbox_profile_sha256": result.get("sandbox_profile_sha256")}
                    record = persist_attempt(root, task, sample_id, attempt_number, result, metadata)
                    attempt_dir = root / record["artifact_paths"]["attempt"]
                    (attempt_dir / "prompt.md").write_bytes(plan.prompt.encode("utf-8"))
                    (attempt_dir / "map-prompt-identity.json").write_text(json.dumps({"metadata": plan.metadata, "final_prompt_sha256": hashlib.sha256(plan.prompt.encode()).hexdigest()}, sort_keys=True), encoding="utf-8")
                    record["artifact_paths"] |= {"prompt": str((attempt_dir / "prompt.md").relative_to(root)), "map_prompt_identity": str((attempt_dir / "map-prompt-identity.json").relative_to(root))}
                    record["artifact_sha256"] |= {"prompt": hashlib.sha256((attempt_dir / "prompt.md").read_bytes()).hexdigest(), "map_prompt_identity": hashlib.sha256((attempt_dir / "map-prompt-identity.json").read_bytes()).hexdigest()}
                    write_json(attempt_dir / "attempt.json", record)
                    _rewrite_record_line(root / "attempts.jsonl", record)
                    records.append(record)
                finally:
                    if private_home: shutil.rmtree(private_home, ignore_errors=True)
                    if state: shutil.rmtree(state, ignore_errors=True)
                    remove_isolated_repository(snapshot)
    finally:
        shutil.rmtree(isolation, ignore_errors=True)
    retained = load_jsonl(root / "attempts.jsonl")
    for task in selected:
        for sample_id in range(1, target + 1):
            slot = [item for item in retained if item.get("task_id") == task["instance_id"] and item.get("sample_id") == sample_id]
            if not any(item.get("quality_valid") is True for item in slot):
                if len(slot) > config["treatment"]["retry_cap"]:
                    raise LifecycleError("retry_cap: treatment sample remained inadmissible")
                # Retain the failed attempt, then resume this immutable slot at
                # the next number. This mirrors the baseline retry policy.
                return run_treatment(repo_root, tasks, config, run_id=run_id, schema_path=schema_path, baseline_template=baseline_template, auth_source=auth_source, limit=limit, samples=samples, child=child)
    return {"run_id": run_id, "root": str(root), "attempts": len(load_jsonl(root / "attempts.jsonl"))}
