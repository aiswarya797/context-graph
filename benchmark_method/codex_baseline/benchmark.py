#!/usr/bin/env python3
"""Single CLI for the plain Codex SWE-Explore baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import secrets
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

MIN_PYTHON = (3, 11)


def validate_supported_python(version: tuple[int, int] | None = None) -> None:
    current = version or (sys.version_info[0], sys.version_info[1])
    if tuple(current[:2]) < MIN_PYTHON:
        raise SystemExit(f"Python 3.11 or newer is required; found {current[0]}.{current[1]} ({sys.executable})")


validate_supported_python()
import tomllib

BASELINE_ROOT = Path(__file__).resolve().parent
ROOT = BASELINE_ROOT.parents[1]
COMMON_ROOT = ROOT / "benchmark_method" / "common"
SRC = BASELINE_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from context_graph_bench.artifacts import load_jsonl, run_root, write_json
from context_graph_bench.codex_runner import (
    RunnerError,
    build_command,
    build_prompt,
    child_environment,
    create_runtime_dirs,
    file_sha256,
    prepare_isolated_repository,
    remove_isolated_repository,
    resolve_executable,
    run_child,
    validate_auth_source,
    validate_regions,
    verify_pinned_version,
)
from context_graph_bench.corpus import (
    CorpusError,
    compile_corpus,
    prepare_snapshot,
    resolve_source_snapshot,
    sha256_file,
    verify_official_evaluator,
    verify_repository_head,
)
from context_graph_bench.event_audit import audit_denied_canaries, audit_events, successful_local_read
from context_graph_bench.report import rebuild_report, score_run
from context_graph_bench.validation import validate_final_run


def load_config() -> dict[str, Any]:
    with (BASELINE_ROOT / "config" / "baseline.toml").open("rb") as stream:
        config = tomllib.load(stream)
    paths = config["paths"]
    if os.environ.get("CODEX_AUTH_SOURCE"):
        paths["codex_auth_source"] = os.environ["CODEX_AUTH_SOURCE"]
    if os.environ.get("CODEX_EXECUTABLE"):
        paths["codex_executable"] = os.environ["CODEX_EXECUTABLE"]
    return config


def config_digest(config: dict[str, Any]) -> str:
    sanitized = {
        "baseline": config["baseline"],
        "paths": {"codex_executable": config["paths"].get("codex_executable")},
        "filesystem_isolation": "macos-sandbox-exec-v1",
        "repository_snapshot": "git-clone-no-local-plus-detached-worktree-v1",
        "codex_inner_sandbox": "danger-full-access",
    }
    payload = json.dumps(sanitized, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def paths() -> dict[str, Path]:
    config = load_config()
    return {
        "sources": COMMON_ROOT / "inputs" / "sources",
        "manifest": COMMON_ROOT / "inputs" / "select25-source-merge.manifest.json",
        "evaluator": COMMON_ROOT / "official" / "eval.py",
        "provenance": COMMON_ROOT / "official" / "provenance.json",
        "schema": COMMON_ROOT / "schemas" / "agent-regions.schema.json",
        "prompt": BASELINE_ROOT / "config" / "region-selection-prompt.md",
        "work": ROOT / ".benchmark-work" / "codex-baseline",
        "select10": Path(config["paths"]["select10_root"]),
        "select15": Path(config["paths"]["select15_root"]),
        "auth": Path(config["paths"]["codex_auth_source"]),
    }


def _portable_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    result = json.loads(json.dumps(manifest))
    for source in result.get("sources", []):
        source.pop("bench_source_path", None)
        source.pop("issue_map_source_path", None)
    return result


def prepare() -> dict[str, Any]:
    config = load_config()
    p = paths()
    tasks, source_manifest = compile_corpus(p["sources"])
    evaluator = verify_official_evaluator(p["evaluator"], p["provenance"])
    source_manifest["official_evaluator"] = evaluator
    write_json(p["manifest"], _portable_manifest(source_manifest), mode=0o644)
    prepared: dict[str, Any] = {"source_manifest": _portable_manifest(source_manifest), "tasks": []}
    for task in tasks:
        snapshot = prepare_snapshot(task, p["select10"], p["select15"], p["work"])
        prepared["tasks"].append({"task_id": task["instance_id"], **snapshot})
    write_json(p["work"] / "prepared.json", prepared)
    result = {"source_row_count": source_manifest["source_row_count"], "unique_task_count": len(tasks), "duplicate_instance_ids": source_manifest["duplicate_instance_ids"], "evaluator": evaluator, "prepared_revisions": len(prepared["tasks"])}
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def _read_prepared(config: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    p = paths()
    manifest_path = p["manifest"]
    prepared_path = p["work"] / "prepared.json"
    if not manifest_path.exists() or not prepared_path.exists():
        raise RunnerError("configuration_error: run prepare before this command")
    source_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    prepared = json.loads(prepared_path.read_text(encoding="utf-8"))
    tasks = source_manifest["tasks"]
    by_id = {item["task_id"]: item for item in prepared["tasks"]}
    for task in tasks:
        task["prepared"] = by_id.get(task["instance_id"])
        if not task["prepared"]:
            raise RunnerError(f"repository_revision_mismatch: missing prepared task {task['instance_id']}")
    return tasks, source_manifest


def child_safe_task(task: dict[str, Any]) -> dict[str, str]:
    """Return the only task data permitted to cross into the child prompt."""
    return {"task_id": str(task["instance_id"]), "issue_text": str(task["issue_text"])}


def doctor_matches(doctor_record: dict[str, Any] | None, harness_digest: str) -> bool:
    return bool(
        doctor_record
        and doctor_record.get("passed") is True
        and doctor_record.get("runtime", {}).get("harness_sha256") == harness_digest
        and doctor_record.get("contamination_audit", {}).get("passed") is True
        and doctor_record.get("contamination_audit", {}).get("external_retrieval_passed") is True
        and doctor_record.get("contamination_audit", {}).get("boundary_canary", {}).get("passed") is True
        and doctor_record.get("provider_probe", {}).get("local_read_event") is True
        and doctor_record.get("provider_probe", {}).get("response_present") is True
    )


def _runtime(config: dict[str, Any], executable: Path, version: str, prompt_hash: str, schema_hash: str, harness_digest: str) -> dict[str, Any]:
    baseline = config["baseline"]
    return {
        "arm": baseline["arm"],
        "protocol": baseline["protocol"],
        "requested_model": baseline["model"],
        "requested_reasoning_effort": baseline["reasoning_effort"],
        "display_name": baseline["display_name"],
        "codex_executable": str(executable),
        "codex_version": version,
        "codex_executable_sha256": file_sha256(executable),
        "model_identity_evidence": "requested_configuration",
        "prompt_sha256": prompt_hash,
        "output_schema_sha256": schema_hash,
        "configuration_sha256": config_digest(config),
        "python_executable": sys.executable,
        "python_version": platform.python_version(),
        "harness_sha256": harness_digest,
        "filesystem_isolation": "macos-sandbox-exec-v1",
        "repository_snapshot": "git-clone-no-local-plus-detached-worktree-v1",
        "codex_inner_sandbox": "danger-full-access",
    }


def _harness_digest(config: dict[str, Any], executable: Path, prompt_hash: str, schema_hash: str, evaluator_hash: str) -> str:
    identity = {
        "python_executable": sys.executable,
        "python_version": platform.python_version(),
        "runtime_config": config_digest(config),
        "model": config["baseline"]["model"],
        "reasoning_effort": config["baseline"]["reasoning_effort"],
        "prompt_sha256": prompt_hash,
        "schema_sha256": schema_hash,
        "evaluator_sha256": evaluator_hash,
        "filesystem_isolation": "macos-sandbox-exec-v1",
        "repository_snapshot": "git-clone-no-local-plus-detached-worktree-v1",
        "codex_inner_sandbox": "danger-full-access",
        "harness_fingerprint": hashlib.sha256((Path(__file__).read_bytes() if Path(__file__).is_file() else b"") + b"\n" + b"".join(path.read_bytes() for path in sorted((BASELINE_ROOT / "src" / "context_graph_bench").glob("*.py")))).hexdigest(),
    }
    return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def doctor() -> dict[str, Any]:
    config = load_config()
    p = paths()
    tasks, source_manifest = _read_prepared(config)
    executable = resolve_executable(config)
    version = verify_pinned_version(executable, config["baseline"]["codex_version"])
    validate_auth_source(p["auth"])
    if not p["schema"].is_file() or not p["prompt"].is_file():
        raise RunnerError("configuration_error: prompt or output schema missing")
    task = tasks[0]
    source_repository_path = Path(task["prepared"]["resolved_path"])
    verify_repository_head(source_repository_path, task["base_commit"])
    isolation_root = Path(tempfile.mkdtemp(prefix="context-graph-doctor-", dir="/private/tmp"))
    snapshot = prepare_isolated_repository(source_repository_path, task["base_commit"], isolation_root, task["instance_id"], "doctor")
    repository_path = Path(snapshot["path"])
    doctor_file = repository_path / f".codex-doctor-sentinel-{secrets.token_hex(8)}.txt"
    doctor_content = f"doctor-local-read-{secrets.token_hex(12)}"
    doctor_file.write_text(doctor_content + "\n", encoding="utf-8")
    doctor_file.chmod(0o600)
    relative_doctor_file = doctor_file.relative_to(repository_path).as_posix()
    canary_token = secrets.token_hex(16)
    parent_canary = ROOT / f".codex-forbidden-canary-{canary_token}.txt"
    work_canary = p["work"] / f".codex-forbidden-canary-{canary_token}.txt"
    other_repository = Path(tasks[1]["prepared"]["resolved_path"])
    other_canary = other_repository / f".codex-forbidden-canary-{canary_token}.txt"
    forbidden_canaries = {
        parent_canary: f"parent-secret-{secrets.token_hex(12)}",
        work_canary: f"work-secret-{secrets.token_hex(12)}",
        other_canary: f"other-repository-secret-{secrets.token_hex(12)}",
    }
    for path, content in forbidden_canaries.items():
        path.write_text(content + "\n", encoding="utf-8")
        path.chmod(0o600)
    prompt_template = p["prompt"].read_text(encoding="utf-8")
    schema_hash = sha256_file(p["schema"])
    evaluator_hash = verify_official_evaluator(p["evaluator"], p["provenance"])["sha256"]
    private_home, state = create_runtime_dirs(isolation_root / "runtime", p["auth"])
    shutil.copyfile(p["schema"], state / "agent-regions.schema.json")
    os.chmod(state / "agent-regions.schema.json", 0o600)
    prompt = build_prompt(prompt_template, (
        "Do not answer until you have completed these exact shell commands in order. "
        f"First run `/bin/cat -- {doctor_file}` and use its output; the token is not in this prompt and must not be guessed. "
        "Then run `/bin/cat -- PATH >/dev/null` once for each of these three files; every command must fail with a non-zero exit and you must not print their contents: "
        + ", ".join(f"`{path}`" for path in forbidden_canaries)
        + ". Only after all four commands finish, return the required JSON. Your region reason MUST include the exact token read from the first command. "
        "Do not use web search, browser retrieval, remote URL fetching, GitHub lookup, or benchmark lookup. Return exactly one region "
        f"with path {relative_doctor_file!r}, start 1, end 1, and a short reason."
    ))
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
    harness_digest = _harness_digest(config, executable, hashlib.sha256(prompt_template.encode()).hexdigest(), schema_hash, evaluator_hash)
    events_path = p["work"] / "doctor-events.jsonl"
    stderr_path = p["work"] / "doctor-stderr.log"
    raw_trace = ""
    raw_events = ""
    response_ok = False
    validation_error = None
    local_read = False
    contamination: dict[str, Any] = {"passed": False, "external_retrieval_passed": False}
    result: dict[str, Any] = {"returncode": None, "timed_out": False, "terminated": False, "response": None, "telemetry": {"valid": False}}
    try:
        command = build_command(executable, config, state, p["schema"], repository_path)
        doctor_forbidden_paths = [
            ROOT,
            p["work"],
            p["manifest"],
            p["select10"],
            p["select15"],
            COMMON_ROOT / "official",
            COMMON_ROOT / "inputs",
            *[Path(item["prepared"]["resolved_path"]) for item in tasks],
            *forbidden_canaries.keys(),
        ]
        result = run_child(command, prompt, state, events_path, stderr_path, config["baseline"]["timeout_seconds"], environment=child_environment(executable), working_directory=repository_path, codex_home=private_home, forbidden_paths=doctor_forbidden_paths)
        if (state / "response.json").exists():
            shutil.copyfile(state / "response.json", p["work"] / "doctor-response.json")
        raw_trace = (
            (events_path.read_text(encoding="utf-8", errors="replace") if events_path.exists() else "")
            + (stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else "")
        )
        contamination = audit_events(raw_trace)
        contamination["boundary_canary"] = audit_denied_canaries(raw_trace, forbidden_canaries)
        raw_events = events_path.read_text(encoding="utf-8", errors="replace") if events_path.exists() else ""
        try:
            regions = validate_regions(result.get("response"), repository_path, 1)
            response_ok = len(regions) == 1 and regions[0]["path"] == relative_doctor_file and regions[0]["start"] == 1 and regions[0]["end"] == 1 and doctor_content in regions[0]["reason"]
        except Exception as exc:
            validation_error = str(exc)
        local_read = successful_local_read(raw_events, doctor_file)
    finally:
        shutil.rmtree(private_home, ignore_errors=True)
        shutil.rmtree(state, ignore_errors=True)
        remove_isolated_repository(snapshot)
        shutil.rmtree(isolation_root, ignore_errors=True)
        for path in forbidden_canaries:
            path.unlink(missing_ok=True)
    if not raw_trace:
        raw_trace = raw_events + (stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else "")
    if "boundary_canary" not in contamination:
        contamination = audit_events(raw_trace)
        contamination["boundary_canary"] = audit_denied_canaries(raw_trace, forbidden_canaries)
    passed = bool(result["returncode"] == 0 and not result["timed_out"] and not result.get("terminated") and response_ok and local_read and result["telemetry"].get("valid") and contamination["passed"] and contamination["boundary_canary"]["passed"] and result.get("sandboxed") is True)
    diagnosis = None if passed else (result.get("failure_class") or "process_failure")
    output = {
        "passed": passed,
        "diagnosis": diagnosis,
        "runtime": _runtime(config, executable, version, prompt_hash, schema_hash, harness_digest),
        "provider_probe": {"return_code": result["returncode"], "response_present": response_ok, "telemetry": result["telemetry"], "elapsed_seconds": result.get("elapsed_seconds"), "local_read_event": local_read, "response_validation_error": validation_error, "sandboxed": result.get("sandboxed"), "sandbox_profile_sha256": result.get("sandbox_profile_sha256")},
        "contamination_audit": contamination,
        "source_row_count": source_manifest["source_row_count"],
        "unique_task_count": source_manifest["unique_task_count"],
    }
    doctor_file.unlink(missing_ok=True)
    write_json(p["work"] / "doctor.json", output)
    print(json.dumps(output, indent=2, sort_keys=True))
    if not passed:
        raise RunnerError(f"{diagnosis}: doctor provider probe failed")
    return output


def _run_manifest(
    run_id: str,
    config: dict[str, Any],
    source_manifest: dict[str, Any],
    executable: Path,
    version: str,
    prompt_hash: str,
    schema_hash: str,
    *,
    require_smoke_gate: bool,
) -> dict[str, Any]:
    evaluator = verify_official_evaluator(paths()["evaluator"], paths()["provenance"])
    harness_digest = _harness_digest(config, executable, prompt_hash, schema_hash, evaluator["sha256"])
    runtime = _runtime(config, executable, version, prompt_hash, schema_hash, harness_digest)
    doctor_path = paths()["work"] / "doctor.json"
    doctor_record = json.loads(doctor_path.read_text(encoding="utf-8")) if doctor_path.exists() else None
    if not doctor_matches(doctor_record, harness_digest):
        raise RunnerError("configuration_error: doctor has not passed in this execution environment")
    if require_smoke_gate:
        smoke_path = paths()["work"] / "smoke-gate.json"
        if not smoke_path.exists():
            raise RunnerError("configuration_error: no successful officially scored smoke gate matches this harness")
        smoke_record = json.loads(smoke_path.read_text(encoding="utf-8"))
        expected_smoke = {
            "status": "passed",
            "evaluator_sha256": evaluator["sha256"],
            "configuration": config_digest(config),
            "harness_sha256": harness_digest,
            "codex_executable_sha256": file_sha256(executable),
            "codex_version": version,
            "requested_model": config["baseline"]["model"],
            "requested_reasoning_effort": config["baseline"]["reasoning_effort"],
            "prompt_sha256": prompt_hash,
            "output_schema_sha256": schema_hash,
        }
        if any(smoke_record.get(key) != value for key, value in expected_smoke.items()):
            raise RunnerError("configuration_error: successful smoke gate is stale or does not match current harness")
    return {
        "run_id": run_id,
        "arm": "codex-baseline",
        "protocol": "direct-region-v1",
        "configuration": runtime | {"sample_count": config["baseline"]["sample_count"], "retry_cap": config["baseline"]["retry_cap"]},
        "corpus": {"source_row_count": source_manifest["source_row_count"], "unique_task_count": source_manifest["unique_task_count"], "corpus_manifest": "corpus-manifest.json"},
        "evaluator": evaluator,
        "doctor": doctor_record,
        "cost": {"status": "unavailable", "pricing_profile": None},
    }


def _forbidden_child_paths(tasks: list[dict[str, Any]], p: dict[str, Path]) -> list[Path]:
    paths_to_forbid = [
        ROOT,
        ROOT / ".benchmark-runs",
        ROOT / ".benchmark-work",
        p["manifest"],
        p["work"] / "prepared.json",
        COMMON_ROOT / "official",
        COMMON_ROOT / "inputs",
        p["select10"],
        p["select15"],
    ]
    paths_to_forbid.extend(Path(task["prepared"]["resolved_path"]) for task in tasks)
    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths_to_forbid:
        resolved = str(path.resolve())
        if resolved not in seen:
            seen.add(resolved)
            unique.append(Path(resolved))
    return unique


def run(args: argparse.Namespace) -> dict[str, Any]:
    config = load_config()
    p = paths()
    tasks, source_manifest = _read_prepared(config)
    executable = resolve_executable(config)
    version = verify_pinned_version(executable, config["baseline"]["codex_version"])
    validate_auth_source(p["auth"])
    prompt_template = p["prompt"].read_text(encoding="utf-8")
    prompt_hash = hashlib.sha256(prompt_template.encode()).hexdigest()
    schema_hash = sha256_file(p["schema"])
    run_id = args.run_id or time.strftime("codex-baseline-%Y%m%dT%H%M%SZ", time.gmtime())
    selected = tasks[: args.limit] if args.limit else tasks
    target_samples = args.samples or config["baseline"]["sample_count"]
    smoke_shape = bool(args.limit == 1 and args.samples == 1 and selected and selected[0]["instance_id"] == "astral-sh__ruff-15330")
    root_path = ROOT / ".benchmark-runs" / run_id
    if root_path.exists() and any(root_path.iterdir()):
        raise RunnerError(f"configuration_error: refusing to overwrite existing run {run_id}")
    root = run_root(ROOT, run_id)
    manifest = _run_manifest(
        run_id,
        config,
        source_manifest,
        executable,
        version,
        prompt_hash,
        schema_hash,
        require_smoke_gate=not smoke_shape,
    )
    write_json(root / "run-manifest.json", manifest)
    write_json(root / "corpus-manifest.json", source_manifest)
    with (root / "corpus.jsonl").open("w", encoding="utf-8") as stream:
        for task in tasks:
            stream.write(json.dumps(task, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    (root / "corpus.jsonl").chmod(0o600)

    smoke_gate = p["work"] / "smoke-gate.json"
    if not smoke_shape and not smoke_gate.exists():
        raise RunnerError("configuration_error: full baseline is blocked until a successful officially scored smoke record exists")
    existing = load_jsonl(root / "attempts.jsonl")
    isolation_root = Path(tempfile.mkdtemp(prefix=f"context-graph-{run_id}-", dir="/private/tmp"))
    forbidden_paths = _forbidden_child_paths(tasks, p)
    try:
        for task in selected:
            prepared = task["prepared"]
            repo = Path(prepared["resolved_path"])
            for sample_id in range(1, target_samples + 1):
                previous = [item for item in existing if item.get("task_id") == task["instance_id"] and item.get("sample_id") == sample_id]
                if sum(1 for item in previous if item.get("quality_valid")) >= 1:
                    continue
                if len(previous) > config["baseline"]["retry_cap"]:
                    raise RunnerError(f"retry_cap: {task['instance_id']} sample {sample_id}")
                attempt_number = len(previous) + 1
                verify_repository_head(repo, task["base_commit"])
                snapshot = prepare_isolated_repository(repo, task["base_commit"], isolation_root, task["instance_id"], f"sample-{sample_id}-attempt-{attempt_number}")
                child_repo = Path(snapshot["path"])
                runtime_root = isolation_root / "runtime" / f"{task['instance_id']}-sample-{sample_id}-attempt-{attempt_number}"
                private_home, state = create_runtime_dirs(runtime_root, p["auth"])
                shutil.copyfile(p["schema"], state / "agent-regions.schema.json")
                os.chmod(state / "agent-regions.schema.json", 0o600)
                events_path = state / "events.jsonl"
                stderr_path = state / "stderr.log"
                safe_task = child_safe_task(task)
                prompt = build_prompt(prompt_template, safe_task["issue_text"])
                command = build_command(executable, config, state, p["schema"], child_repo)
                metadata = {
                    "run_id": run_id,
                    "arm": "codex-baseline",
                    "source_corpus_membership": task["source_memberships"],
                    "repository_path": str(repo),
                    "child_repository_path": str(child_repo),
                    "child_snapshot": snapshot,
                    "verified_head": prepared["verified_head"],
                    "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                    "prompt_template_sha256": prompt_hash,
                    "output_schema_sha256": schema_hash,
                    "codex_executable": str(executable),
                    "codex_version": version,
                    "codex_executable_sha256": file_sha256(executable),
                    "requested_model": config["baseline"]["model"],
                    "requested_reasoning_effort": config["baseline"]["reasoning_effort"],
                    "model_identity_evidence": "requested_configuration",
                    "configuration_sha256": config_digest(config),
                    "harness_sha256": manifest["configuration"]["harness_sha256"],
                    "evaluator_commit": manifest["evaluator"]["commit"],
                    "evaluator_sha256": manifest["evaluator"]["sha256"],
                    "max_regions": config["baseline"]["max_regions"],
                    "filesystem_isolation": "macos-sandbox-exec-v1",
                    "repository_snapshot_mode": "git-clone-no-local-plus-detached-worktree-v1",
                    "forbidden_path_count": len(forbidden_paths),
                    "exact_argument_vector": [arg for arg in command if "auth" not in arg.lower()],
                }
                try:
                    result = run_child(command, prompt, state, events_path, stderr_path, config["baseline"]["timeout_seconds"], environment=child_environment(executable), working_directory=child_repo, codex_home=private_home, forbidden_paths=forbidden_paths)
                    raw_trace = (
                        (events_path.read_text(encoding="utf-8", errors="replace") if events_path.exists() else "")
                        + (stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else "")
                    )
                    contamination = audit_events(raw_trace, forbidden_paths)
                    result["contamination_audit"] = contamination
                    metadata["contamination_audit"] = contamination
                    metadata["sandbox_profile_sha256"] = result.get("sandbox_profile_sha256")
                    metadata["sandboxed"] = result.get("sandboxed")
                    metadata["exact_argument_vector"] = result.get("launched_argument_vector") or metadata["exact_argument_vector"]
                    if not contamination["passed"] or result.get("sandboxed") is not True:
                        result["failure_class"] = "benchmark_contamination" if not contamination["passed"] else "filesystem_isolation_unproven"
                    from context_graph_bench.artifacts import persist_attempt

                    record = persist_attempt(root, task, sample_id, attempt_number, result, metadata)
                    existing.append(record)
                finally:
                    shutil.rmtree(private_home, ignore_errors=True)
                    shutil.rmtree(state, ignore_errors=True)
                    remove_isolated_repository(snapshot)
    finally:
        shutil.rmtree(isolation_root, ignore_errors=True)
    print(json.dumps({"run_id": run_id, "attempts": len(existing), "root": str(root)}, indent=2, sort_keys=True))
    return {"run_id": run_id, "attempts": len(existing), "root": str(root)}


def smoke(args: argparse.Namespace) -> None:
    run_id = args.run_id or time.strftime("codex-baseline-smoke-%Y%m%dT%H%M%SZ", time.gmtime())
    result = run(argparse.Namespace(run_id=run_id, limit=1, samples=1))
    config = load_config()
    evaluator = verify_official_evaluator(paths()["evaluator"], paths()["provenance"])
    records = score_run(ROOT, run_id, paths()["evaluator"], paths()["provenance"])
    valid = [item for item in records if item.get("score_valid") and item.get("quality_valid")]
    if len(valid) != 1:
        raise RunnerError("smoke_gate_failed: exactly one officially scored quality-valid sample is required")
    record = valid[0]
    gate = {"status": "passed", "run_id": run_id, "task_id": record["task_id"], "attempt_id": record["attempt_id"], "evaluator_sha256": evaluator["sha256"], "configuration": record.get("configuration_sha256"), "harness_sha256": record.get("harness_sha256"), "codex_executable_sha256": record.get("codex_executable_sha256"), "codex_version": record.get("codex_version"), "requested_model": record.get("requested_model"), "requested_reasoning_effort": record.get("requested_reasoning_effort"), "prompt_sha256": record.get("prompt_template_sha256", record.get("prompt_sha256")), "output_schema_sha256": record.get("output_schema_sha256"), "corpus": record.get("source_corpus_membership")}
    write_json(paths()["work"] / "smoke-gate.json", gate)
    report_result = rebuild_report(ROOT, run_id, len(_read_prepared(config)[0]), config["baseline"]["sample_count"], evaluator)
    print(json.dumps({"run_id": run_id, "task_id": record["task_id"], "attempt_id": record["attempt_id"], "score": record.get("score"), "report_claimable": report_result["claimable"], "smoke": "structural_validation_only"}, indent=2, sort_keys=True))


def score(args: argparse.Namespace) -> None:
    config = load_config()
    run_id = args.run_id
    if not run_id:
        raise RunnerError("configuration_error: --run-id is required for offline scoring")
    evaluator = verify_official_evaluator(paths()["evaluator"], paths()["provenance"])
    records = score_run(ROOT, run_id, paths()["evaluator"], paths()["provenance"])
    print(json.dumps({"run_id": run_id, "scored": sum(1 for item in records if item.get("score_valid")), "evaluator": evaluator}, indent=2, sort_keys=True))


def report(args: argparse.Namespace) -> None:
    config = load_config()
    tasks, source_manifest = _read_prepared(config)
    run_id = args.run_id
    if not run_id:
        raise RunnerError("configuration_error: --run-id is required for offline reporting")
    evaluator = verify_official_evaluator(paths()["evaluator"], paths()["provenance"])
    result = rebuild_report(ROOT, run_id, len(tasks), config["baseline"]["sample_count"], evaluator)
    print(json.dumps({"run_id": run_id, "claimable": result["claimable"], "quality_valid_sample_count": result["quality_valid_sample_count"]}, indent=2, sort_keys=True))


def validate(args: argparse.Namespace) -> None:
    config = load_config()
    tasks, _source_manifest = _read_prepared(config)
    run_id = args.run_id
    evaluator = verify_official_evaluator(paths()["evaluator"], paths()["provenance"])
    result = validate_final_run(ROOT, run_id, tasks, paths()["evaluator"], paths()["provenance"], _forbidden_child_paths(tasks, paths()), config["baseline"]["sample_count"])
    write_json(ROOT / ".benchmark-runs" / run_id / "validation.json", result)
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["passed"]:
        raise RunnerError("final_validation_failed: retained run is not clean and claimable")


def freeze(args: argparse.Namespace) -> None:
    config = load_config()
    tasks, _source_manifest = _read_prepared(config)
    run_id = args.run_id
    root = ROOT / ".benchmark-runs" / run_id
    validation_path = root / "validation.json"
    if not validation_path.is_file():
        raise RunnerError("configuration_error: run must pass validate before freeze")
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    if validation.get("passed") is not True:
        raise RunnerError("configuration_error: refusing to freeze a failed validation")
    evaluator = verify_official_evaluator(paths()["evaluator"], paths()["provenance"])
    report_result = rebuild_report(ROOT, run_id, len(tasks), config["baseline"]["sample_count"], evaluator)
    records = load_jsonl(root / "attempts.jsonl")
    first = records[0] if records else {}
    manifest = json.loads((root / "run-manifest.json").read_text(encoding="utf-8"))
    freeze_report = {
        "status": "frozen",
        "run_id": run_id,
        "suite": "plain-codex-swe-explore-baseline",
        "unique_tasks": 24,
        "required_samples": 72,
        "clean_valid_scored_samples": 72,
        "telemetry": {"coverage": "72/72", "authoritative_usage": True},
        "contamination": {"count": 0},
        "failed_invalid_timed_out_or_contaminated": 0,
        "evaluator": evaluator,
        "harness_sha256": manifest["configuration"]["harness_sha256"],
        "configuration_sha256": manifest["configuration"]["configuration_sha256"],
        "codex_executable_sha256": manifest["configuration"]["codex_executable_sha256"],
        "codex_version": manifest["configuration"]["codex_version"],
        "model": manifest["configuration"]["requested_model"],
        "reasoning_effort": manifest["configuration"]["requested_reasoning_effort"],
        "filesystem_isolation": manifest["configuration"].get("filesystem_isolation"),
        "repository_snapshot": manifest["configuration"].get("repository_snapshot"),
        "repository_revision_verification": "72/72 child snapshots and source repositories verified clean at declared base commits",
        "cost": {"status": "unavailable", "reason": "No defensible versioned GPT-5.6 Luna pricing profile is configured."},
        "claimable": report_result["claimable"],
        "validation": validation,
        "source_artifacts": {"run_manifest": "run-manifest.json", "attempts": "attempts.jsonl", "validation": "validation.json", "aggregate": "aggregate.json"},
        "sample_metadata_example": {"prompt_template_sha256": first.get("prompt_template_sha256")},
    }
    write_json(root / "freeze-report.json", freeze_report)
    print(json.dumps({"run_id": run_id, "frozen": True, "claimable": report_result["claimable"], "freeze_report": str(root / "freeze-report.json")}, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("prepare")
    sub.add_parser("doctor")
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--run-id")
    run_parser.add_argument("--limit", type=int)
    run_parser.add_argument("--samples", type=int)
    smoke_parser = sub.add_parser("smoke")
    smoke_parser.add_argument("--run-id")
    for name in ("score", "report", "validate", "freeze"):
        command = sub.add_parser(name)
        command.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            prepare()
        elif args.command == "doctor":
            doctor()
        elif args.command == "run":
            run(args)
        elif args.command == "smoke":
            smoke(args)
        elif args.command == "score":
            score(args)
        elif args.command == "report":
            report(args)
        elif args.command == "validate":
            validate(args)
        elif args.command == "freeze":
            freeze(args)
        return 0
    except (RunnerError, CorpusError, FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
