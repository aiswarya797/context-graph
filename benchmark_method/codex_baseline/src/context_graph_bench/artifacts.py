"""Raw attempt retention and deterministic run artifact helpers."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.chmod(temporary, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def append_jsonl(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(canonical(value) + "\n")
    os.chmod(path, 0o600)


def attempt_quality_gate(record: dict[str, Any]) -> tuple[bool, str | None]:
    """Independent fail-closed trust gate used by persistence and scoring."""
    if record.get("return_code") != 0 or record.get("timeout") is True or record.get("terminated") is True:
        return False, record.get("failure_class") or ("timeout" if record.get("timeout") else "nonzero_exit")
    if record.get("failure_class") is not None:
        return False, str(record.get("failure_class"))
    if record.get("response_valid") is not True:
        return False, "invalid_response_schema"
    if record.get("provider_turn_valid") is not True or record.get("telemetry", {}).get("valid") is not True:
        return False, "telemetry_unavailable"
    if record.get("contamination_audit", {}).get("passed") is not True:
        return False, "benchmark_contamination"
    if record.get("provenance_valid") is not True:
        return False, "repository_revision_mismatch"
    return True, None


def validate_attempt_record(record: dict[str, Any]) -> bool:
    valid, _failure = attempt_quality_gate(record)
    if record.get("quality_valid") is True and not valid:
        return False
    return True


def run_root(repo_root: Path, run_id: str) -> Path:
    root = repo_root / ".benchmark-runs" / run_id
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    return root


def attempt_root(run_root_path: Path, task_id: str, sample_id: int, attempt_id: str) -> Path:
    path = run_root_path / "attempts" / task_id / f"sample-{sample_id:02d}" / attempt_id
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def persist_attempt(
    run_root_path: Path,
    task: dict[str, Any],
    sample_id: int,
    attempt_number: int,
    result: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    attempt_id = f"attempt-{attempt_number:03d}"
    path = attempt_root(run_root_path, task["instance_id"], sample_id, attempt_id)
    events = Path(result["events_path"])
    stderr = Path(result["stderr_path"])
    shutil.copyfile(events, path / "events.jsonl")
    shutil.copyfile(stderr, path / "stderr.log")
    response_source = Path(result["state_dir"]) / "response.json"
    if response_source.is_file():
        shutil.copyfile(response_source, path / "response.json")
    else:
        (path / "response.json").write_bytes(b"")
    for name in ("events.jsonl", "stderr.log", "response.json"):
        os.chmod(path / name, 0o600)
    response_present = (path / "response.json").stat().st_size > 0
    response_valid = False
    validation_error = None
    validated_regions = None
    if result.get("response") is not None:
        try:
            from .codex_runner import validate_regions

            validated_regions = validate_regions(result["response"], Path(metadata["repository_path"]), int(metadata.get("max_regions", 5)))
            response_valid = True
        except Exception as exc:  # validation class is serialized, never used as a fallback
            validation_error = str(exc)
    failure_class = result.get("failure_class")
    if not response_valid and response_present and failure_class is None:
        failure_class = "invalid_response_schema"
    record = {
        **metadata,
        "task_id": task["instance_id"],
        "sample_id": sample_id,
        "attempt_id": attempt_id,
        "attempt_number": attempt_number,
        "repository_url": task["repository_url"],
        "requested_base_commit": task["base_commit"],
        "verified_head": metadata.get("verified_head"),
        "return_code": result.get("returncode"),
        "timeout": bool(result.get("timed_out")),
        "terminated": bool(result.get("terminated")),
        "signal_number": result.get("signal_number"),
        "signal_name": result.get("signal_name"),
        "response_present": response_present,
        "response_valid": response_valid,
        "validation_error": validation_error,
        "validated_regions": validated_regions,
        "failure_class": failure_class,
        "contamination_audit": metadata.get("contamination_audit", result.get("contamination_audit", {})),
        "provenance_valid": metadata.get("verified_head") == task.get("base_commit"),
        "provider_turn_valid": bool(result.get("telemetry", {}).get("provider_turn_valid")),
        "telemetry": result.get("telemetry"),
        "elapsed_seconds": result.get("elapsed_seconds"),
        "quality_valid": False,
        "score_valid": False,
        "cost_status": "unavailable",
        "artifact_paths": {
            "attempt": str(path.relative_to(run_root_path)),
            "events": str((path / "events.jsonl").relative_to(run_root_path)),
            "stderr": str((path / "stderr.log").relative_to(run_root_path)),
            "response": str((path / "response.json").relative_to(run_root_path)),
        },
        "artifact_sha256": {
            "events": sha256_file(path / "events.jsonl"),
            "stderr": sha256_file(path / "stderr.log"),
            "response": sha256_file(path / "response.json"),
        },
    }
    quality_valid, gate_failure = attempt_quality_gate(record)
    record["quality_valid"] = quality_valid
    if not quality_valid and record.get("failure_class") is None:
        record["failure_class"] = gate_failure
    write_json(path / "attempt.json", record)
    append_jsonl(run_root_path / "attempts.jsonl", record)
    return record


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def raw_artifacts_match(run_root_path: Path, record: dict[str, Any]) -> bool:
    base = run_root_path / record["artifact_paths"]["attempt"]
    for key, relative in record.get("artifact_paths", {}).items():
        if key == "attempt":
            continue
        path = run_root_path / relative
        if not path.is_file() or sha256_file(path) != record.get("artifact_sha256", {}).get(key):
            return False
    return (base / "attempt.json").is_file()
