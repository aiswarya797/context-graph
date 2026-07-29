"""Read-only authority for the sealed Task 4 enriched indexes.

The Task 5 harness consumes the frozen Task 2 runtime and the sealed Task 4
indexes.  This module is the only new semantic seam between those authorities:
it verifies the complete Task 4 chain and projects a sealed enriched record
into the shape required by the unchanged Task 2 index-copy/runtime path.
"""

from __future__ import annotations

import hashlib
import json
import stat
import subprocess
from pathlib import Path
from typing import Any

from .codegraph import directory_manifest, sha256_file, sha256_value, source_manifest


TASK4_SEALED_ROOT = (
    ".benchmark-work/codegraph-enriched/"
    "task4-cycle-3-review-v1/sealed-task-evidence-root.json"
)
TASK4_SEALED_ROOT_SHA256 = (
    "fe6ceaa328c20ec15ec776c2cb56187980dadc6303e764c6e25f899ff574b76f"
)
TASK4_CANDIDATE_ROOT_SHA256 = (
    "efd922fc39377b346f6a1c5cb68970b131c9cf1e0d7c6d8a6259c5373b9a6c9a"
)
TASK4_ALL24 = (
    ".benchmark-work/codegraph-enriched/"
    "task4-cycle-3/all24-preparation-result.json"
)
TASK4_ALL24_SHA256 = (
    "902eb0169c39506a3d559b750b6ef5c16cc04d9176318c14cf08d19fd87a9885"
)
TASK4_RUNTIME_STAGE_RECORD = (
    ".benchmark-work/codegraph-enriched/"
    "task4-cycle-3/runtime-stage-record.json"
)
TASK4_RUNTIME_STAGE_RECORD_SHA256 = (
    "d36670ce31442ff4801f821efbfdfe1598df3aefa8509a755f8f2cb6ffb19df1"
)
TASK4_AMENDMENT_SHA256 = (
    "d3a714f73f5f8a4b84702d759756b8462a8bc8c6afbae4536064fa591a455000"
)
TASK4_IMPLEMENTATION_MANIFEST = (
    ".benchmark-work/codegraph-enriched/"
    "task4-cycle-3/candidate-implementation-manifest.json"
)
TASK4_IMPLEMENTATION_MANIFEST_SHA256 = (
    "5ea20e4ce5581eb20cd58c5b58c9d6600a7d2b81e011a661bdb32fa2adf1b0f6"
)
TASK3_SEAL_SHA256 = (
    "8e6e0a6a2cd1c32c25de795633f8f9df95215688390087b282addc75f6d2854f"
)
TASK3_SEALED_ROOT = (
    ".benchmark-work/codegraph-enriched/"
    "task3-cycle-5-review-v1/sealed-task-evidence-root.json"
)
TASK3_IMPLEMENTATION_MANIFEST = (
    ".benchmark-work/codegraph-enriched/"
    "task3-cycle-5/implementation-manifest-final.json"
)
TASK3_IMPLEMENTATION_MANIFEST_SHA256 = (
    "ad91d0430055e3cd29c871bc2e586beedb0af38dd420a0897e5648534a809111"
)
TASK3_BUILDER_ROOT = ".benchmark-tools/codegraph-enriched/source"
TASK1_BUILDER_FIXTURE = "scripts/task1-compatibility-fixture.py"
TASK1_BUILDER_FIXTURE_BYTES = 4355
TASK1_BUILDER_FIXTURE_SHA256 = (
    "a4e9c1aae96a5636d1abc4dfe411dee479b9f0f7a817412a44293b4e5ccc722a"
)
TASK3_IMPLEMENTATION_SHA256 = (
    "476f6831b9b0cd018a81f6b1757a762318287f540ecce834a22e8bf263f41d31"
)
TASK2_RUNTIME_EXECUTABLE_SHA256 = (
    "03e4c791cc0dd91ed264278461bf9a56c0278aa0670d5942fc4732311c66de03"
)
TASK2_CODEGRAPH_COMMIT = "572d22bfbe82602080e457bec655f72e3314f9ef"
TASK2_CODEGRAPH_VERSION = "1.5.0"


class EnrichedAuthorityError(ValueError):
    """The sealed Task 4 authority is absent, inconsistent, or stale."""


def _refuse(reason: str) -> None:
    raise EnrichedAuthorityError(f"enriched_authority_refused: {reason}")


def _canonical(root: Path, relative: str, *, label: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        _refuse(f"{label} path is not repository-relative")
    path = root / relative
    try:
        path.absolute().relative_to(root.absolute())
    except ValueError:
        _refuse(f"{label} path escapes repository")
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            _refuse(f"{label} path uses a symlink")
    return path


def _read_json(path: Path, *, label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        _refuse(f"{label} is missing or symlinked")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EnrichedAuthorityError(
            f"enriched_authority_refused: {label} is not readable JSON"
        ) from exc
    if not isinstance(value, dict):
        _refuse(f"{label} must be an object")
    return value


def _require_digest(path: Path, expected: str, *, label: str) -> None:
    if not isinstance(expected, str) or len(expected) != 64:
        _refuse(f"{label} expected digest is malformed")
    if not path.is_file() or sha256_file(path) != expected:
        _refuse(f"{label} bytes differ")


def _bound_entry(
    manifest: dict[str, Any],
    relative: str,
    *,
    label: str,
) -> dict[str, Any]:
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        _refuse(f"{label} entries are missing")
    matches = [
        entry
        for entry in entries
        if isinstance(entry, dict) and entry.get("path") == relative
    ]
    if len(matches) != 1:
        _refuse(f"{label} does not bind {relative}")
    return matches[0]


def _verify_reference(root: Path, reference: Any, *, label: str) -> Path:
    if not isinstance(reference, dict):
        _refuse(f"{label} reference is malformed")
    path = _canonical(root, reference.get("path"), label=label)
    _require_digest(path, reference.get("sha256"), label=label)
    expected_bytes = reference.get("bytes")
    if (
        not isinstance(expected_bytes, int)
        or isinstance(expected_bytes, bool)
        or expected_bytes < 0
        or path.stat().st_size != expected_bytes
    ):
        _refuse(f"{label} byte count differs")
    return path


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        _refuse(f"repository git command failed: {' '.join(args)}")
    return result.stdout.strip()


def _require_read_only_tree(path: Path) -> None:
    if not path.is_dir() or path.is_symlink():
        _refuse("enriched index directory is missing or symlinked")
    for candidate in [path, *path.rglob("*")]:
        if candidate.is_symlink():
            _refuse("enriched index contains a symlink")
        if stat.S_IMODE(candidate.stat().st_mode) & 0o222:
            _refuse(f"enriched index remains writable: {candidate}")
    if any(
        candidate.name in {"codegraph.db-wal", "codegraph.db-shm"}
        for candidate in path.rglob("*")
    ):
        _refuse("enriched index contains a SQLite sidecar")


def validate_measured_runtime(
    *,
    runtime: dict[str, Any],
    task2_checkout: Path,
    enriched_builder_checkout: Path,
) -> None:
    if runtime.get("executable_sha256") != TASK2_RUNTIME_EXECUTABLE_SHA256:
        _refuse("measured executable differs from frozen Task 2")
    executable = Path(str(runtime.get("executable_path", "")))
    try:
        executable.resolve().relative_to(task2_checkout.resolve())
    except ValueError:
        _refuse("measured executable is outside the frozen Task 2 checkout")
    try:
        executable.resolve().relative_to(enriched_builder_checkout.resolve())
    except ValueError:
        pass
    else:
        _refuse("patched Task 3 builder resolved as measured runtime")
    if not executable.is_file() or sha256_file(executable) != TASK2_RUNTIME_EXECUTABLE_SHA256:
        _refuse("measured executable bytes differ from frozen Task 2")


def _validate_task3_implementation(
    root: Path,
    *,
    task4_seal: dict[str, Any],
) -> dict[str, Any]:
    seal_path = _canonical(
        root,
        TASK3_SEALED_ROOT,
        label="Task 3 sealed root",
    )
    _require_digest(
        seal_path,
        TASK3_SEAL_SHA256,
        label="Task 3 sealed root",
    )
    seal = _read_json(seal_path, label="Task 3 sealed root")
    candidate = seal.get("candidate")
    implementation_reference = (
        candidate.get("implementation_manifest")
        if isinstance(candidate, dict)
        else None
    )
    archive_reference = (
        candidate.get("implementation_archive")
        if isinstance(candidate, dict)
        else None
    )
    if (
        seal.get("schema_version") != "sealed-task-evidence-root-v1"
        or seal.get("task") != 3
        or seal.get("cycle") != 5
        or seal.get("status") != "PASS"
        or seal.get("task3_complete") is not True
        or not isinstance(implementation_reference, dict)
        or implementation_reference.get("path")
        != TASK3_IMPLEMENTATION_MANIFEST
        or implementation_reference.get("sha256")
        != TASK3_IMPLEMENTATION_MANIFEST_SHA256
        or not isinstance(archive_reference, dict)
        or archive_reference.get("sha256") != TASK3_IMPLEMENTATION_SHA256
    ):
        _refuse("Task 3 sealed implementation authority differs")
    manifest_path = _verify_reference(
        root,
        implementation_reference,
        label="Task 3 implementation manifest",
    )
    manifest = _read_json(
        manifest_path,
        label="Task 3 implementation manifest",
    )
    archive = manifest.get("archive")
    files = manifest.get("files")
    if (
        manifest.get("cycle") != 5
        or manifest.get("builder_head") != TASK2_CODEGRAPH_COMMIT
        or not isinstance(archive, dict)
        or archive.get("sha256") != TASK3_IMPLEMENTATION_SHA256
        or not isinstance(files, list)
        or not files
    ):
        _refuse("Task 3 implementation manifest differs")
    builder_root = _canonical(
        root,
        TASK3_BUILDER_ROOT,
        label="Task 3 builder root",
    )
    if (
        not builder_root.is_dir()
        or builder_root.is_symlink()
        or _git(builder_root, "rev-parse", "HEAD") != TASK2_CODEGRAPH_COMMIT
    ):
        _refuse("Task 3 builder revision differs")
    seen: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            _refuse("Task 3 implementation file entry is malformed")
        relative = entry.get("path")
        expected_bytes = entry.get("bytes")
        expected_sha256 = entry.get("sha256")
        if (
            not isinstance(relative, str)
            or not relative
            or relative in seen
            or not isinstance(expected_bytes, int)
            or isinstance(expected_bytes, bool)
            or expected_bytes < 0
            or not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
        ):
            _refuse("Task 3 implementation file entry is malformed")
        seen.add(relative)
        path = _canonical(
            builder_root,
            relative,
            label=f"Task 3 implementation file {relative}",
        )
        if (
            not path.is_file()
            or path.is_symlink()
            or path.stat().st_size != expected_bytes
            or sha256_file(path) != expected_sha256
        ):
            _refuse(f"Task 3 implementation file differs: {relative}")
    task4_reference = task4_seal.get("candidate", {}).get(
        "implementation_manifest"
    )
    if (
        not isinstance(task4_reference, dict)
        or task4_reference.get("path") != TASK4_IMPLEMENTATION_MANIFEST
        or task4_reference.get("sha256")
        != TASK4_IMPLEMENTATION_MANIFEST_SHA256
    ):
        _refuse("Task 4 implementation manifest authority differs")
    task4_manifest_path = _verify_reference(
        root,
        task4_reference,
        label="Task 4 implementation manifest",
    )
    task4_manifest = _read_json(
        task4_manifest_path,
        label="Task 4 implementation manifest",
    )
    task4_files = task4_manifest.get("paths")
    if (
        task4_manifest.get("task") != 4
        or task4_manifest.get("cycle") != 3
        or not isinstance(task4_files, list)
    ):
        _refuse("Task 4 implementation manifest differs")
    builder_prefix = f"{TASK3_BUILDER_ROOT}/"
    for entry in task4_files:
        if not isinstance(entry, dict):
            _refuse("Task 4 implementation file entry is malformed")
        repository_relative = entry.get("path")
        if (
            not isinstance(repository_relative, str)
            or not repository_relative.startswith(builder_prefix)
        ):
            continue
        relative = repository_relative.removeprefix(builder_prefix)
        expected_bytes = entry.get("bytes")
        expected_sha256 = entry.get("sha256")
        if (
            not relative
            or relative in seen
            or not isinstance(expected_bytes, int)
            or isinstance(expected_bytes, bool)
            or expected_bytes < 0
            or not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
        ):
            _refuse("Task 4 implementation file entry is malformed")
        seen.add(relative)
        path = _canonical(
            builder_root,
            relative,
            label=f"Task 4 implementation file {relative}",
        )
        if (
            not path.is_file()
            or path.is_symlink()
            or path.stat().st_size != expected_bytes
            or sha256_file(path) != expected_sha256
        ):
            _refuse(f"Task 4 implementation file differs: {relative}")
    fixture_path = _canonical(
        builder_root,
        TASK1_BUILDER_FIXTURE,
        label="Task 1 builder fixture",
    )
    if (
        not fixture_path.is_file()
        or fixture_path.is_symlink()
        or fixture_path.stat().st_size != TASK1_BUILDER_FIXTURE_BYTES
        or sha256_file(fixture_path) != TASK1_BUILDER_FIXTURE_SHA256
    ):
        _refuse("Task 1 builder fixture differs")
    seen.add(TASK1_BUILDER_FIXTURE)
    raw_status = _git(
        builder_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    status_paths: set[str] = set()
    for line in raw_status.splitlines():
        if not line.startswith("?? ") or len(line) <= 3:
            _refuse("Task 3 builder has a tracked or malformed dirty entry")
        relative = line[3:]
        if relative in status_paths:
            _refuse("Task 3 builder dirty entries are duplicated")
        status_paths.add(relative)
    if status_paths != seen:
        _refuse("Task 3 builder dirty state differs from sealed manifests")
    return {
        "seal_path": seal_path,
        "manifest_path": manifest_path,
        "builder_root": builder_root,
        "file_count": len(files),
        "builder_dirty_path_count": len(status_paths),
        "builder_dirty_paths_sha256": sha256_value(sorted(status_paths)),
        "implementation_sha256": TASK3_IMPLEMENTATION_SHA256,
    }


def load_task4_authority(
    root: Path,
    *,
    runtime: dict[str, Any],
) -> dict[str, Any]:
    seal_path = _canonical(root, TASK4_SEALED_ROOT, label="Task 4 sealed root")
    _require_digest(
        seal_path,
        TASK4_SEALED_ROOT_SHA256,
        label="Task 4 sealed root",
    )
    seal = _read_json(seal_path, label="Task 4 sealed root")
    if (
        seal.get("schema_version") != "sealed-task-evidence-root-v1"
        or seal.get("task") != 4
        or seal.get("cycle") != 3
        or seal.get("status") != "PASS"
        or seal.get("task4_complete") is not True
        or seal.get("task5_started") is not False
        or seal.get("official_smoke_started") is not False
        or seal.get("sample_72_run_started") is not False
    ):
        _refuse("Task 4 sealed root status differs")
    review = seal.get("review")
    if (
        not isinstance(review, dict)
        or review.get("status") != "PASS"
        or review.get("read_only") is not True
        or review.get("reviewer_did_not_edit_repository") is not True
        or review.get("all_criteria_pass") is not True
        or review.get("blocking_findings") != 0
        or review.get("frozen_controls_unchanged") is not True
        or review.get("later_task_work_detected") is not False
    ):
        _refuse("Task 4 independent review is not an unqualified PASS")
    task3_implementation = _validate_task3_implementation(
        root,
        task4_seal=seal,
    )
    candidate_reference = seal.get("candidate", {}).get("candidate_evidence_root")
    candidate_path = _verify_reference(
        root,
        candidate_reference,
        label="Task 4 candidate evidence root",
    )
    if candidate_reference.get("sha256") != TASK4_CANDIDATE_ROOT_SHA256:
        _refuse("Task 4 candidate root identity differs")
    candidate = _read_json(candidate_path, label="Task 4 candidate evidence root")
    all24_entry = _bound_entry(
        candidate,
        TASK4_ALL24,
        label="Task 4 candidate evidence root",
    )
    if all24_entry.get("sha256") != TASK4_ALL24_SHA256:
        _refuse("Task 4 all-24 identity differs")
    all24_path = _verify_reference(root, all24_entry, label="Task 4 all-24 result")
    all24 = _read_json(all24_path, label="Task 4 all-24 result")
    runtime_stage_entry = _bound_entry(
        candidate,
        TASK4_RUNTIME_STAGE_RECORD,
        label="Task 4 candidate evidence root",
    )
    if (
        runtime_stage_entry.get("sha256")
        != TASK4_RUNTIME_STAGE_RECORD_SHA256
    ):
        _refuse("Task 4 runtime stage identity differs")
    runtime_stage_path = _verify_reference(
        root,
        runtime_stage_entry,
        label="Task 4 runtime stage record",
    )
    runtime_stage = _read_json(
        runtime_stage_path,
        label="Task 4 runtime stage record",
    )
    if (
        runtime_stage.get("codegraph_executable_sha256")
        != TASK2_RUNTIME_EXECUTABLE_SHA256
        or not isinstance(runtime_stage.get("node_executable_sha256"), str)
        or len(runtime_stage["node_executable_sha256"]) != 64
        or not isinstance(
            runtime_stage.get("runtime_bundle_manifest_sha256"),
            str,
        )
        or len(runtime_stage["runtime_bundle_manifest_sha256"]) != 64
    ):
        _refuse("Task 4 runtime stage differs from frozen Task 2")
    primary = all24.get("primary_population")
    records = all24.get("records")
    if (
        all24.get("schema_version") != "task4-all24-preparation-result-v1"
        or all24.get("status") != "PASS"
        or not isinstance(primary, dict)
        or any(primary.get(field) != 24 for field in (
            "task_count",
            "ready_count",
            "frozen_count",
            "runtime_compatible_count",
        ))
        or not isinstance(records, list)
        or len(records) != 24
    ):
        _refuse("Task 4 all-24 population is incomplete")
    if runtime.get("executable_sha256") != TASK2_RUNTIME_EXECUTABLE_SHA256:
        _refuse("Task 4 indexes are paired with the wrong measured runtime")
    by_task: dict[str, dict[str, Any]] = {}
    for summary in records:
        if not isinstance(summary, dict):
            _refuse("Task 4 index summary is malformed")
        task_id = summary.get("task_id")
        if not isinstance(task_id, str) or not task_id or task_id in by_task:
            _refuse("Task 4 index task identities are invalid or duplicated")
        by_task[task_id] = summary
    return {
        "seal": seal,
        "seal_path": seal_path,
        "candidate": candidate,
        "candidate_path": candidate_path,
        "all24": all24,
        "all24_path": all24_path,
        "runtime_stage": runtime_stage,
        "runtime_stage_path": runtime_stage_path,
        "task3_implementation": task3_implementation,
        "records_by_task": by_task,
    }


def _validate_enrichment_artifacts(
    root: Path,
    record: dict[str, Any],
    *,
    summary: dict[str, Any],
) -> None:
    enrichment = record.get("enrichment")
    if not isinstance(enrichment, dict):
        _refuse("enrichment evidence is missing")
    for key in (
        "inventory",
        "normalized_facts",
        "materialization",
        "persistence_receipt",
        "semantic_additions",
        "report",
    ):
        _verify_reference(root, enrichment.get(key), label=f"enrichment {key}")
    provenance = enrichment.get("provenance_validation")
    if (
        not isinstance(provenance, dict)
        or provenance.get("all_evidence_resolves_to_inventory") is not True
        or provenance.get("all_extractor_provenance_valid") is not True
        or provenance.get("all_facts_revision_bound") is not True
        or provenance.get("all_refusals_and_rejections_retained") is not True
        or provenance.get("fact_trace_bijection") is not True
        or provenance.get("yield_classification")
        != summary.get("yield_classification")
    ):
        _refuse("enrichment provenance is incomplete")
    report = record.get("report")
    extraction = report.get("extraction") if isinstance(report, dict) else None
    materialization = report.get("materialization") if isinstance(report, dict) else None
    equivalence = report.get("semanticEquivalence") if isinstance(report, dict) else None
    if (
        not isinstance(extraction, dict)
        or extraction.get("completed") is not True
        or extraction.get("enabledExtractorCount") != extraction.get(
            "completedExtractorCount"
        )
        or extraction.get("repeatedRunDeterministic") is not True
        or extraction.get("fatalRejectionCount") != 0
        or not isinstance(materialization, dict)
        or materialization.get("repeatedPersistenceIdempotent") is not True
    ):
        _refuse("enrichment execution was partial, failed, or nondeterministic")
    fact_count = provenance.get("fact_count")
    if not isinstance(fact_count, int) or isinstance(fact_count, bool) or fact_count < 0:
        _refuse("enrichment fact count is malformed")
    if materialization.get("materializedFactCount") != fact_count:
        _refuse("materialized fact count differs from accepted facts")
    classification = summary.get("yield_classification")
    if classification == "fact-bearing":
        if fact_count <= 0 or materialization.get("addedEdgeCount", 0) <= 0:
            _refuse("fact-bearing index has no persisted enrichment")
    elif classification in {"supported-zero-yield", "unsupported-only"}:
        if (
            fact_count != 0
            or materialization.get("addedNodeCount") != 0
            or materialization.get("addedEdgeCount") != 0
            or materialization.get("materializedTraceCount") != 0
            or not isinstance(equivalence, dict)
            or equivalence.get("zeroAddition") is not True
            or equivalence.get("semanticallyEquivalent") is not True
            or equivalence.get("databaseBytesIdentical") is not True
        ):
            _refuse("zero-addition index lacks empty persistence and equivalence")
    else:
        _refuse("unknown enrichment yield classification")


def load_enriched_index(
    root: Path,
    *,
    authority: dict[str, Any],
    runtime: dict[str, Any],
    task_id: str,
    base_commit: str,
    exclude_names: set[str],
) -> dict[str, Any]:
    summary = authority["records_by_task"].get(task_id)
    if not isinstance(summary, dict):
        _refuse(f"Task 4 has no enriched index for {task_id}")
    if summary.get("base_commit") != base_commit:
        _refuse(f"Task 4 revision differs for {task_id}")
    record_path = _verify_reference(
        root,
        summary.get("record"),
        label=f"Task 4 index record {task_id}",
    )
    expected_record_path = (
        root
        / ".benchmark-work"
        / "codegraph-enriched"
        / "task4-cycle-3"
        / "indexes"
        / task_id
        / "index-record.json"
    )
    if record_path != expected_record_path:
        _refuse(f"Task 4 index record path differs for {task_id}")
    record = _read_json(record_path, label=f"Task 4 index record {task_id}")
    if (
        record.get("schema_version") != "codegraph-enriched-index-v1"
        or record.get("task") != 4
        or record.get("cycle") != 3
        or record.get("task_id") != task_id
        or record.get("requested_base_commit") != base_commit
        or record.get("verified_head") != base_commit
        or record.get("ready") is not True
        or record.get("frozen") is not True
    ):
        _refuse(f"Task 4 index record fields differ for {task_id}")
    identity = record.get("identity")
    if (
        not isinstance(identity, dict)
        or identity.get("task_id") != task_id
        or identity.get("base_commit") != base_commit
        or identity.get("task2_codegraph_commit") != TASK2_CODEGRAPH_COMMIT
        or identity.get("task2_runtime_sha256")
        != TASK2_RUNTIME_EXECUTABLE_SHA256
        or identity.get("task3_implementation_sha256")
        != TASK3_IMPLEMENTATION_SHA256
        or identity.get("task4_amendment_sha256")
        != TASK4_AMENDMENT_SHA256
    ):
        _refuse(f"Task 4 enriched identity differs for {task_id}")
    frozen = record.get("frozen_authority")
    if (
        not isinstance(frozen, dict)
        or frozen.get("task2_runtime_sha256")
        != TASK2_RUNTIME_EXECUTABLE_SHA256
        or frozen.get("task3_implementation_sha256")
        != TASK3_IMPLEMENTATION_SHA256
        or frozen.get("task3_seal_sha256") != TASK3_SEAL_SHA256
        or frozen.get("task4_amendment_sha256") != TASK4_AMENDMENT_SHA256
        or not isinstance(frozen.get("task4_implementation"), dict)
        or frozen["task4_implementation"].get("sha256")
        != identity.get("task4_implementation_sha256")
    ):
        _refuse(f"Task 4 frozen authority differs for {task_id}")
    if runtime.get("executable_sha256") != frozen["task2_runtime_sha256"]:
        _refuse(f"Task 4 runtime binding differs for {task_id}")
    repository = Path(str(record.get("repository_path", "")))
    expected_repository = (
        root / ".benchmark-work" / "codegraph" / "sources" / task_id / base_commit
    )
    if repository != expected_repository or not repository.is_dir():
        _refuse(f"Task 4 repository binding differs for {task_id}")
    if _git(repository, "rev-parse", "HEAD") != base_commit:
        _refuse(f"Task 4 repository revision differs for {task_id}")
    if _git(repository, "status", "--porcelain"):
        _refuse(f"Task 4 repository is dirty for {task_id}")
    recorded_source = record.get("source_manifest")
    if (
        not isinstance(recorded_source, dict)
        or source_manifest(repository, exclude_names) != recorded_source
    ):
        _refuse(f"Task 4 source manifest differs for {task_id}")
    index_path = Path(str(record.get("index_path", "")))
    expected_index_path = expected_record_path.parent / "index"
    if index_path != expected_index_path:
        _refuse(f"Task 4 index path differs for {task_id}")
    _require_read_only_tree(index_path)
    current_manifest = directory_manifest(index_path)
    if (
        current_manifest != record.get("index_artifact_manifest")
        or current_manifest.get("sha256") != summary.get("index_manifest_sha256")
    ):
        _refuse(f"Task 4 index bytes differ for {task_id}")
    final_semantic = record.get("final_semantic_graph")
    if (
        not isinstance(final_semantic, dict)
        or final_semantic.get("sha256") != summary.get("semantic_graph_sha256")
        or final_semantic.get("integrity_check") != "ok"
        or final_semantic.get("foreign_key_violation_count") != 0
    ):
        _refuse(f"Task 4 semantic graph differs for {task_id}")
    runtime_validation = record.get("runtime_validation")
    runtime_stage = authority["runtime_stage"]
    expected_runtime_command_prefix = [
        "/usr/bin/sandbox-exec",
        "-p",
        "(version 1) (allow default) (deny network*)",
        runtime_stage["node_executable"],
        runtime_stage["codegraph_executable"],
    ]
    status_record = (
        runtime_validation.get("status_record")
        if isinstance(runtime_validation, dict)
        else None
    )
    mcp_record = (
        runtime_validation.get("mcp_record")
        if isinstance(runtime_validation, dict)
        else None
    )
    mcp_validation = (
        runtime_validation.get("mcp_validation")
        if isinstance(runtime_validation, dict)
        else None
    )
    sidecars = (
        runtime_validation.get("sidecar_lifecycle")
        if isinstance(runtime_validation, dict)
        else None
    )
    if (
        not isinstance(runtime_validation, dict)
        or runtime_validation.get("cleanup_complete") is not True
        or runtime_validation.get("copy_bytes_unchanged") is not True
        or runtime_validation.get("semantic_graph_unchanged") is not True
        or runtime_validation.get("master_unchanged") is not True
        or runtime_validation.get("master_manifest_before") != current_manifest
        or runtime_validation.get("master_manifest_after") != current_manifest
        or not isinstance(runtime_validation.get("status"), dict)
        or not isinstance(status_record, dict)
        or status_record.get("return_code") != 0
        or status_record.get("timed_out") is not False
        or status_record.get("command", [])[:5]
        != expected_runtime_command_prefix
        or not isinstance(mcp_record, dict)
        or mcp_record.get("return_code") != 0
        or mcp_record.get("timed_out") is not False
        or mcp_record.get("command", [])[:5]
        != expected_runtime_command_prefix
        or not isinstance(mcp_validation, dict)
        or mcp_validation.get("response_count") != 3
        or mcp_validation.get("tool_names") != ["codegraph_explore"]
        or mcp_validation.get("codegraph_explore_content_items", 0) < 1
        or not isinstance(sidecars, dict)
        or sidecars.get("after_close") != []
        or sidecars.get("remaining_after_lifecycle") != []
        or sidecars.get("integrity_check") != "ok"
        or sidecars.get("foreign_key_violation_count") != 0
    ):
        _refuse(f"Task 4 runtime validation differs for {task_id}")
    _validate_enrichment_artifacts(root, record, summary=summary)
    projection = {
        "schema_version": "codegraph-enriched-runtime-index-v1",
        "identity": identity,
        "task_id": task_id,
        "repository_path": str(repository),
        "requested_base_commit": base_commit,
        "verified_head": base_commit,
        "codegraph_source_commit": TASK2_CODEGRAPH_COMMIT,
        "codegraph_version": TASK2_CODEGRAPH_VERSION,
        "codegraph_executable_sha256": TASK2_RUNTIME_EXECUTABLE_SHA256,
        "source_manifest_sha256": recorded_source["sha256"],
        "index_path": str(index_path),
        "index_artifact_manifest": current_manifest,
        "status": runtime_validation["status"],
        "duration_seconds": record.get("duration_seconds"),
        "index_bytes": record.get("index_bytes"),
        "ready": True,
        "frozen": True,
        "enriched_authority": {
            "task4_sealed_root_sha256": TASK4_SEALED_ROOT_SHA256,
            "task4_candidate_root_sha256": TASK4_CANDIDATE_ROOT_SHA256,
            "task4_all24_sha256": TASK4_ALL24_SHA256,
            "task4_index_record": {
                "path": summary["record"]["path"],
                "bytes": summary["record"]["bytes"],
                "sha256": summary["record"]["sha256"],
            },
            "task4_amendment_sha256": TASK4_AMENDMENT_SHA256,
            "task3_seal_sha256": TASK3_SEAL_SHA256,
            "task3_implementation_sha256": TASK3_IMPLEMENTATION_SHA256,
            "task2_runtime_sha256": TASK2_RUNTIME_EXECUTABLE_SHA256,
            "yield_classification": summary["yield_classification"],
            "eligibility": summary["eligibility"],
            "semantic_graph_sha256": summary["semantic_graph_sha256"],
            "index_manifest_sha256": summary["index_manifest_sha256"],
            "provenance_validation": record["enrichment"][
                "provenance_validation"
            ],
        },
    }
    projection["runtime_projection_sha256"] = sha256_value(projection)
    return projection


def validate_enriched_index(
    root: Path,
    *,
    authority: dict[str, Any],
    runtime: dict[str, Any],
    record: dict[str, Any],
    task_id: str,
    base_commit: str,
    exclude_names: set[str],
) -> dict[str, Any]:
    expected = load_enriched_index(
        root,
        authority=authority,
        runtime=runtime,
        task_id=task_id,
        base_commit=base_commit,
        exclude_names=exclude_names,
    )
    if record != expected:
        _refuse(f"runtime projection differs for {task_id}")
    return record


def authority_digest(authority: dict[str, Any]) -> str:
    return sha256_value(
        {
            "task4_sealed_root_sha256": TASK4_SEALED_ROOT_SHA256,
            "task4_candidate_root_sha256": TASK4_CANDIDATE_ROOT_SHA256,
            "task4_all24_sha256": TASK4_ALL24_SHA256,
            "task4_runtime_stage_record_sha256": (
                TASK4_RUNTIME_STAGE_RECORD_SHA256
            ),
            "task3_seal_sha256": TASK3_SEAL_SHA256,
            "task3_implementation_manifest_sha256": (
                TASK3_IMPLEMENTATION_MANIFEST_SHA256
            ),
            "task3_implementation_sha256": TASK3_IMPLEMENTATION_SHA256,
            "task3_implementation_file_count": authority[
                "task3_implementation"
            ]["file_count"],
            "task_ids": sorted(authority["records_by_task"]),
        }
    )
