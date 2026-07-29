"""Fail-closed run ownership, schema, corpus, and sample-slot reconciliation."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .schema_validation import SchemaValidationError, load_schema, validate_instance


SAFE_RUN_ID = re.compile(r"^codex-codegraph-enriched-(?:smoke-)?[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
HISTORICAL_BASELINE_PREFIXES = ("baseline-", "codex-baseline-")
REQUIRED_MANIFEST_FIELDS = {
    "run_id",
    "arm",
    "protocol",
    "configuration",
    "corpus",
    "evaluator",
    "codegraph",
    "indexes",
    "treatment_differences",
}
TREATMENT_DIFFERENCES = [
    "CodeGraph-use prompt addition",
    "pinned immutable CodeGraph index",
    "per-attempt CodeGraph MCP server",
]
ARM_ROOT = Path(__file__).resolve().parents[2]
RUN_MANIFEST_SCHEMA = load_schema(ARM_ROOT / "schemas" / "run-manifest.schema.json")
ATTEMPT_RECORD_SCHEMA = load_schema(ARM_ROOT / "schemas" / "attempt-record.schema.json")
ATTEMPT_ARTIFACT_NAMES = {
    "events": "events.jsonl",
    "stderr": "stderr.log",
    "response": "response.json",
    "scoring_source": "scoring-source.json",
    "attempt_input": "attempt-input.json",
}


class IntegrityError(RuntimeError):
    """Raised before any mutation when saved benchmark state is untrusted."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def validate_run_id(run_id: str, *, smoke: bool | None = None) -> str:
    if not isinstance(run_id, str) or not run_id or Path(run_id).name != run_id:
        raise IntegrityError("mutation_refused: run_id must be one path component")
    if run_id in {".", ".."} or run_id.startswith(HISTORICAL_BASELINE_PREFIXES):
        raise IntegrityError("mutation_refused: baseline and historical run IDs are read-only")
    if not SAFE_RUN_ID.fullmatch(run_id):
        raise IntegrityError("mutation_refused: run_id is not a codex-codegraph-enriched run component")
    is_smoke = run_id.startswith("codex-codegraph-enriched-smoke-")
    if smoke is True and not is_smoke:
        raise IntegrityError("mutation_refused: smoke run_id must start with codex-codegraph-enriched-smoke-")
    if smoke is False and is_smoke:
        raise IntegrityError("mutation_refused: full run_id must not use the smoke namespace")
    return run_id


def resolve_run_root(repository_root: Path, run_id: str, *, smoke: bool | None = None) -> Path:
    validate_run_id(run_id, smoke=smoke)
    runs_root = (repository_root / ".benchmark-runs").resolve()
    candidate = runs_root / run_id
    resolved = candidate.resolve()
    if resolved.parent != runs_root:
        raise IntegrityError("mutation_refused: run root escapes .benchmark-runs")
    if candidate.is_symlink() or (candidate.exists() and resolved != candidate.absolute()):
        raise IntegrityError("mutation_refused: symlinked run roots are not writable benchmark targets")
    return candidate


def resolve_controlled_setup_path(
    repository_root: Path,
    value: str,
    *,
    controlled_root: str,
    field: str,
) -> Path:
    """Resolve a setup override only beneath its arm-specific ignored root."""
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "%" in value
        or value.endswith("/")
        or "//" in value[1:]
        or "/./" in value
    ):
        raise IntegrityError(f"mutation_refused: invalid {field} setup path")
    raw = Path(value)
    if any(part in {".", ".."} for part in raw.parts):
        raise IntegrityError(f"mutation_refused: non-canonical {field} setup path")
    expected_root = repository_root / controlled_root
    candidate = raw if raw.is_absolute() else repository_root / raw
    expected_resolved = expected_root.resolve(strict=False)
    candidate_resolved = candidate.resolve(strict=False)
    if candidate_resolved == expected_resolved or expected_resolved not in candidate_resolved.parents:
        raise IntegrityError(
            f"mutation_refused: {field} must be a descendant of {controlled_root}"
        )
    current = repository_root
    relative = candidate.absolute().relative_to(repository_root.absolute())
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise IntegrityError(f"mutation_refused: symlinked {field} setup path")
    forbidden = (
        repository_root / ".benchmark-runs",
        repository_root / "benchmark_method" / "codex_baseline",
        repository_root / "benchmark_method" / "common",
        repository_root / ".benchmark-work" / "codex-baseline",
    )
    if any(candidate_resolved == root.resolve() or root.resolve() in candidate_resolved.parents for root in forbidden):
        raise IntegrityError(f"mutation_refused: {field} targets a frozen or shared benchmark root")
    return candidate


def validate_run_manifest(manifest: dict[str, Any], *, expected_run_id: str | None = None) -> dict[str, Any]:
    try:
        validate_instance(manifest, RUN_MANIFEST_SCHEMA)
    except SchemaValidationError as exc:
        raise IntegrityError(f"schema_validation_failed: run manifest: {exc}") from exc
    if not REQUIRED_MANIFEST_FIELDS.issubset(manifest):
        raise IntegrityError("schema_validation_failed: malformed run manifest")
    run_id = manifest.get("run_id")
    validate_run_id(run_id)
    if expected_run_id is not None and run_id != expected_run_id:
        raise IntegrityError("mutation_refused: manifest run_id does not match requested run_id")
    if manifest.get("arm") != "codex-codegraph-enriched" or manifest.get("protocol") != "codegraph-region-v1":
        raise IntegrityError("mutation_refused: run is not owned by the codex-codegraph-enriched arm")
    for field in ("configuration", "corpus", "evaluator", "codegraph", "indexes"):
        if not isinstance(manifest.get(field), dict):
            raise IntegrityError(f"schema_validation_failed: run manifest {field} must be an object")
    configuration = manifest["configuration"]
    for field in (
        "requested_model",
        "requested_reasoning_effort",
        "codex_version",
        "sample_count",
        "retry_cap",
        "timeout_seconds",
        "max_regions",
        "output_schema_sha256",
        "configuration_sha256",
        "harness_sha256",
    ):
        if field not in configuration:
            raise IntegrityError(f"schema_validation_failed: run configuration lacks {field}")
    is_smoke = run_id.startswith("codex-codegraph-enriched-smoke-")
    tasks = manifest["corpus"].get("tasks", [])
    task_count = len(tasks)
    task_ids = [task.get("instance_id") for task in tasks if isinstance(task, dict)]
    unique_task_count = manifest["corpus"].get("unique_task_count", task_count)
    if len(task_ids) != task_count or len(set(task_ids)) != task_count or not all(
        isinstance(task_id, str) and task_id for task_id in task_ids
    ):
        raise IntegrityError("schema_validation_failed: corpus tasks must have unique non-empty identities")
    if is_smoke:
        if configuration["sample_count"] != 1 or task_count != 1 or unique_task_count != 1:
            raise IntegrityError("schema_validation_failed: smoke manifests require exactly 1 task x 1 sample")
    elif configuration["sample_count"] != 3 or task_count != 24 or unique_task_count != 24:
        raise IntegrityError("schema_validation_failed: full manifests require exactly 24 unique tasks x 3 samples")
    if (
        not isinstance(configuration["retry_cap"], int)
        or configuration["retry_cap"] < 0
        or not isinstance(configuration["timeout_seconds"], int)
        or configuration["timeout_seconds"] <= 0
        or not isinstance(configuration["max_regions"], int)
        or configuration["max_regions"] <= 0
    ):
        raise IntegrityError("schema_validation_failed: retry/timeout/region configuration is invalid")
    for field in ("output_schema_sha256", "configuration_sha256", "harness_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(configuration.get(field))):
            raise IntegrityError(f"schema_validation_failed: invalid {field}")
    corpus = manifest["corpus"]
    if not isinstance(corpus.get("tasks"), list) or not isinstance(corpus.get("artifact"), dict):
        raise IntegrityError("schema_validation_failed: corpus artifact and tasks are required")
    if corpus["artifact"].get("path") != "corpus.jsonl":
        raise IntegrityError("schema_validation_failed: corpus artifact path differs")
    for digest_owner, field in (
        (corpus["artifact"], "sha256"),
        (manifest["evaluator"], "sha256"),
        (manifest["codegraph"], "source_lock_sha256"),
        (manifest["codegraph"], "runtime_record_sha256"),
    ):
        digest = digest_owner.get(field)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise IntegrityError(f"schema_validation_failed: invalid {field}")
    task2_root_digest = manifest["codegraph"].get("task2_evidence_root_sha256")
    if not re.fullmatch(r"[0-9a-f]{64}", str(task2_root_digest)):
        raise IntegrityError("schema_validation_failed: invalid task2_evidence_root_sha256")
    enrichment = manifest["codegraph"].get("enrichment_authority")
    if (
        not isinstance(enrichment, dict)
        or enrichment.get("index_count") != task_count
        or any(
            not re.fullmatch(r"[0-9a-f]{64}", str(enrichment.get(field)))
            for field in (
                "task4_sealed_root_sha256",
                "task4_candidate_root_sha256",
                "task4_all24_sha256",
                "authority_sha256",
            )
        )
    ):
        raise IntegrityError("schema_validation_failed: enriched authority differs")
    if manifest.get("treatment_differences") != TREATMENT_DIFFERENCES:
        raise IntegrityError("schema_validation_failed: treatment differences contract differs")
    network = manifest["codegraph"].get("mcp_network_isolation")
    if (
        not isinstance(network, dict)
        or network.get("mode") != "sandbox-exec-child-network-deny-v1"
        or network.get("verified") is not True
        or not re.fullmatch(r"[0-9a-f]{64}", str(network.get("profile_sha256")))
    ):
        raise IntegrityError("schema_validation_failed: MCP network isolation is not verified")
    index_records = manifest["indexes"].get("records")
    if not isinstance(index_records, list) or not all(
        isinstance(reference, dict)
        and set(reference) == {"path", "sha256"}
        and isinstance(reference["path"], str)
        and Path(reference["path"]).parent == Path("indexes")
        and re.fullmatch(r"[0-9a-f]{64}", str(reference["sha256"]))
        for reference in index_records
    ):
        raise IntegrityError("schema_validation_failed: index record references are malformed")
    return manifest


def load_treatment_manifest(run_root: Path, *, expected_run_id: str | None = None) -> dict[str, Any]:
    manifest_path = run_root / "run-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise IntegrityError("mutation_refused: treatment run manifest must exist before mutation")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"schema_validation_failed: unreadable run manifest: {exc}") from exc
    return validate_run_manifest(manifest, expected_run_id=expected_run_id)


def verify_corpus_contract(run_root: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    artifact = manifest["corpus"]["artifact"]
    corpus_relative = _normalized_relative(artifact["path"], label="corpus")
    corpus_path = _safe_descendant(run_root, corpus_relative, label="corpus")
    payload = corpus_path.read_bytes()
    if sha256_bytes(payload) != artifact["sha256"] or len(payload) != artifact.get("bytes"):
        raise IntegrityError("scoring_provenance_refused: corpus bytes differ from the run manifest")
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(payload.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise IntegrityError(f"scoring_provenance_refused: malformed corpus row {number}") from exc
        if not isinstance(row, dict):
            raise IntegrityError("scoring_provenance_refused: corpus rows must be objects")
        rows.append(row)
    row_map = {
        row.get("instance_id"): row.get("base_commit")
        for row in rows
        if isinstance(row.get("instance_id"), str) and isinstance(row.get("base_commit"), str)
    }
    task_map = {
        row.get("instance_id"): row.get("base_commit")
        for row in manifest["corpus"]["tasks"]
        if isinstance(row, dict)
    }
    if len(row_map) != len(rows) or row_map != task_map:
        raise IntegrityError("scoring_provenance_refused: corpus task/source identity differs")
    identity = [{"instance_id": key, "base_commit": row_map[key]} for key in sorted(row_map)]
    expected_identity = manifest["corpus"].get("task_identity_sha256")
    actual_identity = sha256_bytes(
        (json.dumps(identity, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    if expected_identity != actual_identity:
        raise IntegrityError("scoring_provenance_refused: task identity digest differs")
    return rows


def verify_bound_run_artifacts(run_root: Path, manifest: dict[str, Any]) -> None:
    for manifest_key, path_key, hash_key in (
        ("codegraph", "source_lock", "source_lock_sha256"),
        ("codegraph", "runtime_record", "runtime_record_sha256"),
        (
            "codegraph",
            "task2_evidence_root",
            "task2_evidence_root_sha256",
        ),
    ):
        owner = manifest[manifest_key]
        relative = owner.get(path_key)
        if relative is None and path_key == "task2_evidence_root":
            continue
        if not isinstance(relative, str) or Path(relative).name != relative:
            raise IntegrityError(f"scoring_provenance_refused: invalid {path_key} artifact path")
        relative_path = _normalized_relative(relative, label=path_key)
        path = _safe_descendant(run_root, relative_path, label=path_key)
        if sha256_bytes(path.read_bytes()) != owner[hash_key]:
            raise IntegrityError(f"scoring_provenance_refused: {path_key} artifact bytes differ")
    enrichment = manifest["codegraph"]["enrichment_authority"]
    for path_key, hash_key in (
        ("task4_sealed_root", "task4_sealed_root_sha256"),
        ("task4_candidate_root", "task4_candidate_root_sha256"),
        ("task4_all24", "task4_all24_sha256"),
    ):
        relative = enrichment.get(path_key)
        if not isinstance(relative, str) or Path(relative).name != relative:
            raise IntegrityError(
                f"scoring_provenance_refused: invalid {path_key} artifact path"
            )
        path = _safe_descendant(
            run_root,
            _normalized_relative(relative, label=path_key),
            label=path_key,
        )
        if sha256_bytes(path.read_bytes()) != enrichment.get(hash_key):
            raise IntegrityError(
                f"scoring_provenance_refused: {path_key} artifact bytes differ"
            )
    seen_indexes: set[str] = set()
    for reference in manifest["indexes"]["records"]:
        relative = reference["path"]
        if relative in seen_indexes:
            raise IntegrityError("scoring_provenance_refused: duplicate index record reference")
        seen_indexes.add(relative)
        relative_path = _normalized_relative(relative, label="index record")
        path = _safe_descendant(run_root, relative_path, label="index record")
        if sha256_bytes(path.read_bytes()) != reference["sha256"]:
            raise IntegrityError("scoring_provenance_refused: index record bytes differ")


def _normalized_relative(value: Any, *, label: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "%" in value
        or value.startswith("/")
        or value.endswith("/")
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise IntegrityError(f"scoring_provenance_refused: non-canonical {label} path")
    relative = Path(value)
    if relative.is_absolute() or relative.as_posix() != value:
        raise IntegrityError(f"scoring_provenance_refused: non-canonical {label} path")
    return relative


def _safe_descendant(root: Path, relative: Path, *, label: str, must_exist: bool = True) -> Path:
    candidate = root / relative
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise IntegrityError(f"scoring_provenance_refused: symlinked {label} path")
    resolved_root = root.resolve()
    resolved = candidate.resolve(strict=False)
    if resolved == resolved_root or resolved_root not in resolved.parents:
        raise IntegrityError(f"scoring_provenance_refused: {label} path escapes its root")
    if must_exist and not candidate.is_file():
        raise IntegrityError(f"scoring_provenance_refused: missing {label} artifact")
    return candidate


def _authority_projection(record: dict[str, Any]) -> dict[str, Any]:
    projection = json.loads(json.dumps(record))
    projection["score_valid"] = False
    projection["quality_valid"] = False
    projection["claimable_sample"] = False
    if isinstance(projection.get("validity"), dict):
        projection["validity"]["scoring"] = False
    for field in ("score", "score_artifact", "score_sha256"):
        projection.pop(field, None)
    projection.get("artifacts", {}).pop("attempt_input", None)
    projection.get("artifact_sha256", {}).pop("attempt_input", None)
    return projection


def _validate_attempt_authority(
    run_root: Path,
    manifest: dict[str, Any],
    record: dict[str, Any],
) -> None:
    expected_attempt = (
        f"attempts/{record['task_id']}/sample-{record['sample_id']:02d}/{record['attempt_id']}"
    )
    attempt_relative = _normalized_relative(record["artifacts"].get("attempt"), label="attempt")
    if attempt_relative.as_posix() != expected_attempt:
        raise IntegrityError("scoring_provenance_refused: attempt directory identity differs")
    attempt_root = _safe_descendant(run_root, attempt_relative, label="attempt", must_exist=False)
    if not attempt_root.is_dir():
        raise IntegrityError("scoring_provenance_refused: attempt directory is missing")
    for key, filename in ATTEMPT_ARTIFACT_NAMES.items():
        expected = f"{expected_attempt}/{filename}"
        relative = _normalized_relative(record["artifacts"].get(key), label=key)
        if relative.as_posix() != expected:
            raise IntegrityError(f"scoring_provenance_refused: substituted {key} artifact path")
        path = _safe_descendant(run_root, relative, label=key)
        if sha256_bytes(path.read_bytes()) != record["artifact_sha256"].get(key):
            raise IntegrityError(f"scoring_provenance_refused: {key} artifact bytes differ")
    if record.get("score_valid") is True:
        score_relative = _normalized_relative(record.get("score_artifact"), label="score")
        if score_relative.as_posix() != f"{expected_attempt}/score.json":
            raise IntegrityError("scoring_provenance_refused: substituted score artifact path")
        score_path = _safe_descendant(run_root, score_relative, label="score")
        if sha256_bytes(score_path.read_bytes()) != record.get("score_sha256"):
            raise IntegrityError("scoring_provenance_refused: score artifact bytes differ")
    input_path = attempt_root / "attempt-input.json"
    try:
        authority = json.loads(input_path.read_text(encoding="utf-8"))
        validate_instance(authority, ATTEMPT_RECORD_SCHEMA)
    except (OSError, json.JSONDecodeError, SchemaValidationError) as exc:
        raise IntegrityError(f"scoring_provenance_refused: invalid attempt-input authority: {exc}") from exc
    if authority != _authority_projection(record):
        raise IntegrityError("scoring_provenance_refused: attempts.jsonl differs from immutable attempt-input")
    task = next(
        (row for row in manifest["corpus"]["tasks"] if row["instance_id"] == record["task_id"]),
        None,
    )
    if task is None:
        raise IntegrityError("scoring_provenance_refused: attempt task is absent from manifest")
    if (
        record.get("requested_base_commit") != task.get("base_commit")
        or record.get("validity", {}).get("provenance")
        is not (
            record.get("verified_head")
            == task.get("base_commit")
        )
        or ("repository_url" in task and record.get("repository_url") != task["repository_url"])
        or record.get("evaluator_commit") != manifest["evaluator"].get("commit")
        or record.get("evaluator_sha256") != manifest["evaluator"].get("sha256")
        or record.get("runtime_provenance") != manifest["codegraph"]
    ):
        raise IntegrityError("scoring_provenance_refused: attempt repository/evaluator/runtime identity differs")
    index_reference = next(
        (
            reference
            for reference in manifest["indexes"]["records"]
            if Path(reference["path"]).stem == record["task_id"]
        ),
        None,
    )
    if index_reference is None:
        raise IntegrityError("scoring_provenance_refused: attempt index record is not bound")
    index_record = json.loads((run_root / index_reference["path"]).read_text(encoding="utf-8"))
    enriched_index = index_record.get("enriched_authority")
    enriched_run = manifest["codegraph"].get("enrichment_authority")
    if (
        record.get("index_identity") != index_record.get("identity")
        or record.get("index_record_sha256") != sha256_bytes(
            (json.dumps(index_record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        or not isinstance(enriched_index, dict)
        or enriched_index.get("task4_sealed_root_sha256")
        != enriched_run.get("task4_sealed_root_sha256")
        or enriched_index.get("task4_candidate_root_sha256")
        != enriched_run.get("task4_candidate_root_sha256")
        or enriched_index.get("task4_all24_sha256")
        != enriched_run.get("task4_all24_sha256")
        or enriched_index.get("task2_runtime_sha256")
        != manifest["codegraph"].get("executable_sha256")
    ):
        raise IntegrityError("scoring_provenance_refused: attempt index identity differs")


def validate_attempt_records(
    records: list[dict[str, Any]],
    *,
    run_id: str,
    task_ids: set[str],
    required_samples: int,
    run_root: Path | None = None,
    manifest: dict[str, Any] | None = None,
) -> None:
    from .artifacts import validate_attempt_record

    references: set[tuple[str, str, str]] = set()
    artifact_references: set[str] = set()
    attempts_by_slot: dict[tuple[str, int], list[int]] = {}
    adopted_by_slot: dict[tuple[str, int], int] = {}
    for record in records:
        try:
            validate_instance(record, ATTEMPT_RECORD_SCHEMA)
        except SchemaValidationError as exc:
            raise IntegrityError(f"schema_validation_failed: attempt record: {exc}") from exc
        if not validate_attempt_record(record):
            raise IntegrityError("schema_validation_failed: invalid attempt record")
        if record.get("run_id") != run_id or record.get("task_id") not in task_ids:
            raise IntegrityError("schema_validation_failed: attempt run/task identity differs")
        sample_id = record.get("sample_id")
        if not isinstance(sample_id, int) or isinstance(sample_id, bool) or not 1 <= sample_id <= required_samples:
            raise IntegrityError("schema_validation_failed: sample_id is outside the declared slots")
        attempt_id = record.get("attempt_id")
        key = (record["task_id"], str(sample_id), str(attempt_id))
        artifact_ref = record.get("artifacts", {}).get("attempt")
        if key in references or not isinstance(artifact_ref, str) or artifact_ref in artifact_references:
            raise IntegrityError("schema_validation_failed: duplicate attempt or artifact reference")
        references.add(key)
        artifact_references.add(artifact_ref)
        slot = (record["task_id"], sample_id)
        attempts_by_slot.setdefault(slot, []).append(record["attempt_number"])
        if record.get("adopted_for_slot") is True:
            adopted_by_slot[slot] = adopted_by_slot.get(slot, 0) + 1
            if adopted_by_slot[slot] > 1:
                raise IntegrityError("sample_reconciliation_refused: duplicate adopted sample slots")
        if run_root is not None:
            if manifest is None:
                raise IntegrityError("schema_validation_failed: manifest required for attempt authority")
            _validate_attempt_authority(run_root, manifest, record)
    for slot, attempts in attempts_by_slot.items():
        if sorted(attempts) != list(range(1, len(attempts) + 1)):
            raise IntegrityError(f"schema_validation_failed: non-contiguous attempt history for {slot[0]} sample {slot[1]}")


def reconcile_sample_slots(
    records: list[dict[str, Any]],
    task_ids: list[str],
    required_samples: int,
) -> dict[str, Any]:
    adopted: dict[tuple[str, int], dict[str, Any]] = {}
    duplicates: list[dict[str, Any]] = []
    for record in records:
        if record.get("claimable_sample") is not True:
            continue
        key = (record["task_id"], record["sample_id"])
        if key in adopted:
            duplicates.append(
                {
                    "task_id": key[0],
                    "sample_id": key[1],
                    "attempt_ids": [adopted[key]["attempt_id"], record["attempt_id"]],
                }
            )
        else:
            adopted[key] = record
    if duplicates:
        raise IntegrityError("sample_reconciliation_refused: duplicate adopted sample slots")
    expected = {(task_id, sample_id) for task_id in task_ids for sample_id in range(1, required_samples + 1)}
    missing = sorted(expected - set(adopted))
    return {
        "adopted": adopted,
        "missing": [{"task_id": task_id, "sample_id": sample_id} for task_id, sample_id in missing],
        "complete": not missing,
    }
