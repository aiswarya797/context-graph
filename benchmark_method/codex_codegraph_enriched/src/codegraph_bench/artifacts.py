"""Immutable raw-attempt retention and separate treatment validity dimensions."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

from .codegraph import write_json
from .codegraph_runner import validate_regions
from .integrity import ATTEMPT_RECORD_SCHEMA
from .schema_validation import SchemaValidationError, validate_instance


VALIDITY_FIELDS = (
    "execution",
    "response",
    "provenance",
    "index",
    "mcp",
    "graph_use",
    "contamination",
    "telemetry",
    "scoring",
    "cost",
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def rewrite_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    if path.is_symlink():
        raise RuntimeError(f"mutation_refused: symlinked JSONL target {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for record in records)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(payload, encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def _validity(result: dict[str, Any], metadata: dict[str, Any], response_valid: bool) -> dict[str, bool]:
    navigation = result.get("navigation") or {}
    contamination = metadata.get("contamination_audit") or {}
    return {
        "execution": result.get("returncode") == 0 and result.get("timed_out") is not True and result.get("terminated") is not True,
        "response": response_valid,
        "provenance": metadata.get("verified_head") == metadata.get("requested_base_commit"),
        "index": metadata.get("index_valid") is True,
        "mcp": navigation.get("mcp_server_connected") is True and navigation.get("tool_available") is True,
        "graph_use": navigation.get("graph_use_valid") is True,
        "contamination": contamination.get("passed") is True and not navigation.get("outside_repository_accesses") and not navigation.get("prohibited_benchmark_accesses"),
        "telemetry": result.get("telemetry", {}).get("valid") is True and result.get("telemetry", {}).get("provider_turn_valid") is True,
        "scoring": False,
        "cost": False,
    }


def diagnostic_scoreable(record: dict[str, Any]) -> bool:
    validity = record.get("validity", {})
    return all(validity.get(field) is True for field in ("execution", "response", "provenance", "index", "mcp", "contamination", "telemetry"))


def treatment_valid(record: dict[str, Any]) -> bool:
    return diagnostic_scoreable(record) and record.get("validity", {}).get("graph_use") is True


def claimable_sample(record: dict[str, Any]) -> bool:
    return treatment_valid(record) and record.get("validity", {}).get("scoring") is True and record.get("score_valid") is True


def sample_slot(records: list[dict[str, Any]], task_id: str, sample_id: int, retry_cap: int) -> dict[str, Any]:
    previous = [
        record
        for record in records
        if record.get("task_id") == task_id and record.get("sample_id") == sample_id
    ]
    adopted = [record for record in previous if treatment_valid(record)]
    if len(adopted) > 1:
        raise RuntimeError(f"sample_reconciliation_refused: duplicate adopted slot {task_id} sample {sample_id}")
    attempt_numbers = [record.get("attempt_number") for record in previous if isinstance(record.get("attempt_number"), int)]
    if len(set(attempt_numbers)) != len(attempt_numbers):
        raise RuntimeError(f"sample_reconciliation_refused: duplicate attempt number for {task_id} sample {sample_id}")
    return {
        "satisfied": len(adopted) == 1,
        "attempt_count": len(previous),
        "next_attempt_number": len(previous) + 1,
        "retry_cap_exhausted": len(previous) > retry_cap,
    }


def validate_attempt_record(record: dict[str, Any]) -> bool:
    try:
        validate_instance(record, ATTEMPT_RECORD_SCHEMA)
    except SchemaValidationError:
        return False
    if record.get("arm") != "codex-codegraph-enriched":
        return False
    attempt_number = record.get("attempt_number")
    if (
        not isinstance(record.get("run_id"), str)
        or not record["run_id"]
        or not isinstance(record.get("task_id"), str)
        or not record["task_id"]
        or not isinstance(record.get("sample_id"), int)
        or isinstance(record.get("sample_id"), bool)
        or not isinstance(attempt_number, int)
        or isinstance(attempt_number, bool)
        or attempt_number < 1
        or record.get("attempt_id") != f"attempt-{attempt_number:03d}"
    ):
        return False
    validity = record.get("validity")
    if not isinstance(validity, dict) or set(validity) != set(VALIDITY_FIELDS) or not all(isinstance(value, bool) for value in validity.values()):
        return False
    if record.get("treatment_valid") != treatment_valid(record):
        return False
    if record.get("claimable_sample") != claimable_sample(record):
        return False
    if record.get("claimable_sample") and not record.get("quality_valid"):
        return False
    if record.get("adopted_for_slot") != treatment_valid(record):
        return False
    if not isinstance(record.get("failure_classes"), list) or not all(
        isinstance(value, str) and value for value in record["failure_classes"]
    ):
        return False
    if not isinstance(record.get("artifact_sha256"), dict):
        return False
    expected_attempt_ref = (
        f"attempts/{record['task_id']}/sample-{record['sample_id']:02d}/{record['attempt_id']}"
    )
    if record.get("artifacts", {}).get("attempt") != expected_attempt_ref:
        return False
    return True


def _scoring_source(repository: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for path in sorted(repository.rglob("*")):
        relative = path.relative_to(repository)
        if not path.is_file() or ".git" in relative.parts:
            continue
        contents = path.read_bytes()
        rows.append(
            {
                "path": relative.as_posix(),
                "bytes": len(contents),
                "sha256": hashlib.sha256(contents).hexdigest(),
                "line_count": len(contents.decode("utf-8", errors="replace").splitlines()),
            }
        )
    payload = json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    return {
        "schema_version": "codegraph-scoring-source-v1",
        "file_count": len(rows),
        "files": rows,
        "manifest_sha256": hashlib.sha256(payload).hexdigest(),
    }


def _failure_classes(
    result: dict[str, Any],
    validity: dict[str, bool],
    navigation: dict[str, Any],
    response_valid: bool,
) -> list[str]:
    failures: list[str] = []
    explicit = result.get("failure_class")
    if isinstance(explicit, str) and explicit:
        failures.append(explicit)
    navigation_failure = navigation.get("failure_class")
    if isinstance(navigation_failure, str) and navigation_failure:
        failures.append(navigation_failure)
    if not response_valid:
        failures.append("invalid_response_schema")
    for field in ("execution", "provenance", "index", "mcp", "graph_use", "contamination", "telemetry"):
        if validity[field] is not True:
            failures.append(f"invalid_{field}")
    return list(dict.fromkeys(failures))


def persist_attempt(
    run_root: Path,
    task: dict[str, Any],
    sample_id: int,
    attempt_number: int,
    result: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    from .integrity import (
        load_treatment_manifest,
        validate_attempt_records,
        verify_bound_run_artifacts,
        verify_corpus_contract,
    )

    manifest = load_treatment_manifest(run_root, expected_run_id=run_root.name)
    verify_corpus_contract(run_root, manifest)
    verify_bound_run_artifacts(run_root, manifest)
    declared_tasks = {row.get("instance_id") for row in manifest["corpus"]["tasks"]}
    declared_task = next(
        (row for row in manifest["corpus"]["tasks"] if row.get("instance_id") == task.get("instance_id")),
        None,
    )
    required_samples = int(manifest["configuration"]["sample_count"])
    if (
        metadata.get("run_id") != manifest["run_id"]
        or declared_task is None
        or metadata.get("requested_base_commit") != declared_task.get("base_commit")
        or (
            declared_task.get("repository_url") is not None
            and metadata.get("repository_url") != declared_task.get("repository_url")
        )
        or metadata.get("evaluator_commit") != manifest["evaluator"].get("commit")
        or metadata.get("evaluator_sha256") != manifest["evaluator"].get("sha256")
        or metadata.get("runtime_provenance") != manifest["codegraph"]
        or not isinstance(sample_id, int)
        or isinstance(sample_id, bool)
        or not 1 <= sample_id <= required_samples
    ):
        raise RuntimeError("mutation_refused: attempt identity is outside the declared treatment run")
    existing_records = load_jsonl(run_root / "attempts.jsonl")
    validate_attempt_records(
        existing_records,
        run_id=manifest["run_id"],
        task_ids=declared_tasks,
        required_samples=required_samples,
        run_root=run_root,
        manifest=manifest,
    )
    attempt_id = f"attempt-{attempt_number:03d}"
    attempt_root = run_root / "attempts" / task["instance_id"] / f"sample-{sample_id:02d}" / attempt_id
    if attempt_root.exists():
        raise RuntimeError(f"configuration_error: refusing to overwrite {attempt_root}")
    attempt_root.mkdir(parents=True, mode=0o700)
    artifacts = {}
    artifact_hashes = {}
    sources = {
        "events": Path(result["events_path"]),
        "stderr": Path(result["stderr_path"]),
        "response": Path(result["state_dir"]) / "response.json",
    }
    destinations = {
        "events": "events.jsonl",
        "stderr": "stderr.log",
        "response": "response.json",
    }
    lifecycle_value = metadata.get("index_lifecycle_path")
    if isinstance(lifecycle_value, str) and lifecycle_value:
        sources["index_lifecycle"] = Path(lifecycle_value)
        destinations["index_lifecycle"] = "index-lifecycle.json"
    for key, source in sources.items():
        destination = attempt_root / destinations[key]
        if source.is_file():
            shutil.copyfile(source, destination)
        else:
            destination.write_bytes(b"")
        os.chmod(destination, 0o600)
        artifacts[key] = str(destination.relative_to(run_root))
        artifact_hashes[key] = sha256_file(destination)
    response_valid = False
    validated_regions = None
    validation_error = None
    if result.get("response") is not None:
        try:
            validated_regions = validate_regions(
                result["response"],
                Path(metadata["repository_path"]),
                int(metadata.get("max_regions", 5)),
            )
            response_valid = True
        except Exception as exc:
            validation_error = str(exc)
    validity = _validity(result, metadata, response_valid)
    navigation = result.get("navigation") or {}
    failure_classes = _failure_classes(result, validity, navigation, response_valid)
    failure_class = failure_classes[0] if failure_classes else None
    scoring_repository = Path(metadata.get("child_repository_path") or metadata["repository_path"])
    scoring_source = _scoring_source(scoring_repository)
    scoring_source_path = attempt_root / "scoring-source.json"
    write_json(scoring_source_path, scoring_source)
    artifacts["scoring_source"] = str(scoring_source_path.relative_to(run_root))
    artifact_hashes["scoring_source"] = sha256_file(scoring_source_path)
    record = {
        **metadata,
        "arm": "codex-codegraph-enriched",
        "task_id": task["instance_id"],
        "sample_id": sample_id,
        "attempt_id": attempt_id,
        "attempt_number": attempt_number,
        "return_code": result.get("returncode"),
        "timeout": bool(result.get("timed_out")),
        "terminated": bool(result.get("terminated")),
        "signal_number": result.get("signal_number"),
        "signal_name": result.get("signal_name"),
        "elapsed_seconds": result.get("elapsed_seconds"),
        "response_present": bool(artifacts["response"] and (run_root / artifacts["response"]).stat().st_size),
        "response_valid": response_valid,
        "validated_regions": validated_regions,
        "validation_error": validation_error,
        "provider_turn_valid": bool(result.get("telemetry", {}).get("provider_turn_valid")),
        "telemetry": result.get("telemetry"),
        "navigation": navigation,
        "failure_class": failure_class,
        "failure_classes": failure_classes,
        "validity": validity,
        "score_valid": False,
        "quality_valid": False,
        "cost_status": "unavailable",
        "artifacts": {"attempt": str(attempt_root.relative_to(run_root)), **artifacts},
        "artifact_sha256": artifact_hashes,
    }
    record["treatment_valid"] = treatment_valid(record)
    record["adopted_for_slot"] = record["treatment_valid"]
    record["claimable_sample"] = claimable_sample(record)
    immutable_input_path = attempt_root / "attempt-input.json"
    validate_instance(record, ATTEMPT_RECORD_SCHEMA)
    write_json(immutable_input_path, record)
    artifacts["attempt_input"] = str(immutable_input_path.relative_to(run_root))
    artifact_hashes["attempt_input"] = sha256_file(immutable_input_path)
    record["artifacts"] = {"attempt": str(attempt_root.relative_to(run_root)), **artifacts}
    record["artifact_sha256"] = artifact_hashes
    validate_instance(record, ATTEMPT_RECORD_SCHEMA)
    write_json(attempt_root / "attempt.json", record)
    updated_records = [*existing_records, record]
    validate_attempt_records(
        updated_records,
        run_id=manifest["run_id"],
        task_ids=declared_tasks,
        required_samples=required_samples,
        run_root=run_root,
        manifest=manifest,
    )
    rewrite_jsonl(run_root / "attempts.jsonl", updated_records)
    return record


def artifacts_match(run_root: Path, record: dict[str, Any]) -> bool:
    keys = ["events", "stderr", "response", "scoring_source", "attempt_input"]
    if "index_lifecycle" in record.get("artifacts", {}):
        keys.append("index_lifecycle")
    for key in keys:
        path = run_root / record.get("artifacts", {}).get(key, "")
        if not path.is_file() or sha256_file(path) != record.get("artifact_sha256", {}).get(key):
            return False
    return True


def scored_artifacts_match(run_root: Path, record: dict[str, Any]) -> bool:
    if not artifacts_match(run_root, record):
        return False
    if record.get("score_valid") is True:
        relative = record.get("score_artifact")
        score_path = run_root / relative if isinstance(relative, str) else Path()
        if not score_path.is_file() or sha256_file(score_path) != record.get("score_sha256"):
            return False
    return True
