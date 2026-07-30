"""Frozen Task 3 map authority checks for the treatment arm.

This module deliberately reads map artifacts only in the parent harness.  A
measured child receives prompt bytes, never a map path or an Aider runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[4]
MAPS_ROOT = ROOT / ".benchmark-work" / "aider-map" / "maps-v3"
MANIFEST = MAPS_ROOT / "manifest.json"
PHASE_FREEZE = MAPS_ROOT / "phase-freeze.json"
GENERATION_REPORT = ROOT / ".benchmark-work" / "aider-map" / "task3-cycle4" / "generation-report.json"
SOURCE_LOCK = ROOT / ".benchmark-work" / "aider-map" / "task1" / "source-lock.json"
TASK3_SEAL = ROOT / ".benchmark-work" / "aider-map" / "orchestration" / "task3-seal-v2.json"
EXPECTED_MANIFEST_SHA256 = "462ff73cb27a2b2974c85de5354ac3d0efdc71bdad3e5618882890b6e921d21f"
EXPECTED_PHASE_FREEZE_SHA256 = "6bd0cbeb57666edb35b1a3b2bcaf7ea0c83b440a961522df39e1c2102ee5ecc3"
EXPECTED_GENERATION_REPORT_SHA256 = "3942e79678f636645f457d70fe4b999fab9471348c3a265995bf9661fc16e207"
EXPECTED_TASK3_SEAL_SHA256 = "cf80a7afbcd523062afc2b3504e8f5f3e1b5ae9af484e6e6925a4e6f64b332d6"
MAPS_ROOT_RELATIVE = ".benchmark-work/aider-map/maps-v3"
MAPS_MANIFEST_RELATIVE = f"{MAPS_ROOT_RELATIVE}/manifest.json"
PHASE_FREEZE_RELATIVE = f"{MAPS_ROOT_RELATIVE}/phase-freeze.json"
GENERATION_REPORT_RELATIVE = ".benchmark-work/aider-map/task3-cycle4/generation-report.json"
FIRST_VALID_POLICY = "FIRST_TECHNICALLY_VALID_OUTPUT"


class MapBindingError(RuntimeError):
    """Raised before a Codex command can be constructed."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise MapBindingError(f"map_authority_refused: unreadable artifact: {path}") from exc


def _regular(path: Path, label: str) -> None:
    try:
        stat = path.lstat()
    except OSError as exc:
        raise MapBindingError(f"map_authority_refused: missing {label}: {path}") from exc
    if path.is_symlink() or not os.path.isfile(path):
        raise MapBindingError(f"map_authority_refused: {label} is not a regular non-symlink file")
    if stat.st_nlink != 1:
        raise MapBindingError(f"map_authority_refused: {label} has unexpected hard links")


def _load_json(path: Path, label: str) -> dict[str, Any]:
    _regular(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MapBindingError(f"map_authority_refused: malformed {label}") from exc
    if not isinstance(value, dict):
        raise MapBindingError(f"map_authority_refused: {label} is not an object")
    return value


def _inside(root: Path, candidate: Path, label: str) -> Path:
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise MapBindingError(f"map_authority_refused: {label} escapes frozen maps root") from exc
    return resolved


@dataclass(frozen=True)
class BoundMap:
    task_id: str
    base_commit: str
    issue_sha256: str
    map_text: str
    map_sha256: str
    record_sha256: str
    source_lock_sha256: str
    manifest_sha256: str
    phase_freeze_sha256: str
    task3_seal_sha256: str
    artifact_directory: str
    generation_duration_seconds: float | None

    def provenance(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "base_commit": self.base_commit,
            "issue_sha256": self.issue_sha256,
            "map_sha256": self.map_sha256,
            "record_sha256": self.record_sha256,
            "source_lock_sha256": self.source_lock_sha256,
            "maps_manifest_sha256": self.manifest_sha256,
            "phase_freeze_sha256": self.phase_freeze_sha256,
            "task3_seal_sha256": self.task3_seal_sha256,
            "artifact_directory": self.artifact_directory,
            "generation_duration_seconds": self.generation_duration_seconds,
            "map_delivered_from_parent_memory": True,
        }


def _assert_task3_authority(manifest: dict[str, Any], freeze: dict[str, Any]) -> None:
    if sha256_file(MANIFEST) != EXPECTED_MANIFEST_SHA256:
        raise MapBindingError("map_authority_refused: frozen map manifest digest differs")
    if sha256_file(PHASE_FREEZE) != EXPECTED_PHASE_FREEZE_SHA256:
        raise MapBindingError("map_authority_refused: Task 3 phase freeze digest differs")
    if sha256_file(GENERATION_REPORT) != EXPECTED_GENERATION_REPORT_SHA256:
        raise MapBindingError("map_authority_refused: Task 3 generation report digest differs")
    if freeze.get("status") != "FROZEN" or freeze.get("task") != 3 or freeze.get("task_count") != 24:
        raise MapBindingError("map_authority_refused: Task 3 map phase is not frozen")
    if (
        freeze.get("schema_version") != "aider-map-task3-maps-v3-freeze-v1"
        or freeze.get("manifest_sha256") != EXPECTED_MANIFEST_SHA256
        or freeze.get("maps_root") != MAPS_ROOT_RELATIVE
        or freeze.get("phase") != "FROZEN_BEFORE_ANY_COVERAGE_ACCESS"
        or freeze.get("official_attempts") != 24
        or freeze.get("all_first_valid_outputs_frozen") is not True
        or freeze.get("coverage_accessed") is not False
    ):
        raise MapBindingError("map_authority_refused: phase freeze does not bind manifest")
    if (
        manifest.get("schema_version") != "aider-map-task3-maps-v3"
        or manifest.get("status") != "FROZEN"
        or manifest.get("task") != 3
        or manifest.get("map_version") != "maps-v3"
        or manifest.get("selection_policy") != FIRST_VALID_POLICY
        or manifest.get("mandatory_repeat") is not False
        or manifest.get("automatic_retry") is not False
        or manifest.get("coverage_visible_at_selection") is not False
    ):
        raise MapBindingError("map_authority_refused: frozen manifest identity differs")
    source_freeze = manifest.get("source_freeze")
    if not isinstance(source_freeze, dict) or source_freeze.get("receipt_sha256") != freeze.get("source_freeze_receipt_sha256"):
        raise MapBindingError("map_authority_refused: manifest source freeze binding differs")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != 24:
        raise MapBindingError("map_authority_refused: frozen map manifest does not contain 24 entries")
    if len({entry.get("task_id") for entry in entries if isinstance(entry, dict)}) != 24:
        raise MapBindingError("map_authority_refused: frozen map manifest task identities differ")
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or entry.get("selection_policy") != FIRST_VALID_POLICY
            or entry.get("official_attempt_ordinal") != 1
            or entry.get("accepted_immediately") is not True
            or entry.get("selection_signals_inspected") != []
            or entry.get("resume") is not False
        ):
            raise MapBindingError("map_authority_refused: frozen map was not the first technically valid output")
    seal = _load_json(TASK3_SEAL, "Task 3 seal")
    if sha256_file(TASK3_SEAL) != EXPECTED_TASK3_SEAL_SHA256 or seal.get("task") != 3 or seal.get("status") != "PASS":
        raise MapBindingError("map_authority_refused: Task 3 seal is missing or differs")
    generation_report = manifest.get("generation_report")
    report = _load_json(GENERATION_REPORT, "Task 3 generation report")
    sealed_artifacts = seal.get("sealed_artifacts")
    if (
        not isinstance(generation_report, dict)
        or generation_report.get("path") != GENERATION_REPORT_RELATIVE
        or generation_report.get("sha256") != EXPECTED_GENERATION_REPORT_SHA256
        or freeze.get("generation_report_path") != GENERATION_REPORT_RELATIVE
        or freeze.get("generation_report_sha256") != EXPECTED_GENERATION_REPORT_SHA256
        or not isinstance(sealed_artifacts, dict)
        or sealed_artifacts.get("generation_report_sha256") != EXPECTED_GENERATION_REPORT_SHA256
        or sealed_artifacts.get("maps_manifest_sha256") != EXPECTED_MANIFEST_SHA256
        or sealed_artifacts.get("phase_freeze_sha256") != EXPECTED_PHASE_FREEZE_SHA256
    ):
        raise MapBindingError("map_authority_refused: generation report or freeze binding differs")
    if (
        report.get("schema_version") != "aider-map-task3-cycle4-generation-v1"
        or report.get("task") != 3
        or report.get("cycle") != 4
        or report.get("status") != "PASS"
        or report.get("official_attempt_count") != 24
        or report.get("retry_count") != 0
        or report.get("repeat_count") != 0
        or report.get("selection_policy") != FIRST_VALID_POLICY
        or report.get("selection_signals_inspected") != []
        or report.get("entries") != entries
        or report.get("source_freeze") != source_freeze
    ):
        raise MapBindingError("map_authority_refused: Task 3 generation report contents differ")
    invariants = seal.get("verified_invariants")
    if (
        not isinstance(invariants, dict)
        or invariants.get("official_generation_count") != 24
        or invariants.get("official_attempt_ordinals") != [1]
        or invariants.get("retry_count") != 0
        or invariants.get("repeat_count") != 0
        or invariants.get("resume_count") != 0
        or invariants.get("selection_policy") != FIRST_VALID_POLICY
        or invariants.get("selection_signals_inspected") != []
        or invariants.get("exact_unmodified_upstream_return_persisted") is not True
        or invariants.get("phase_freeze_preceded_ground_truth_access") is not True
    ):
        raise MapBindingError("map_authority_refused: Task 3 seal first-valid invariants differ")
    downstream = seal.get("downstream_authority")
    if (
        not isinstance(downstream, dict)
        or downstream.get("task4_must_bind_this_seal") is not True
        or downstream.get("task4_must_use_exact_maps_manifest_path") != MAPS_MANIFEST_RELATIVE
        or downstream.get("task4_must_use_exact_maps_manifest_sha256") != EXPECTED_MANIFEST_SHA256
        or downstream.get("task4_must_use_exact_phase_freeze_path") != PHASE_FREEZE_RELATIVE
        or downstream.get("task4_must_use_exact_phase_freeze_sha256") != EXPECTED_PHASE_FREEZE_SHA256
        or downstream.get("task4_must_use_same_frozen_map_for_all_three_samples") is not True
        or downstream.get("task4_map_regeneration_forbidden") is not True
    ):
        raise MapBindingError("map_authority_refused: Task 3 seal does not authorize these maps")


def bind_map(task: dict[str, Any]) -> BoundMap:
    """Return the one frozen map matching an exact corpus task or refuse.

    This checks immutable aggregate identities before task-specific bytes, so a
    copied or hand-edited map cannot be substituted for an accepted Task 3 map.
    """
    for key in ("instance_id", "base_commit", "issue_text"):
        if not isinstance(task.get(key), str) or not task[key]:
            raise MapBindingError(f"map_authority_refused: task lacks exact {key}")
    manifest = _load_json(MANIFEST, "maps manifest")
    freeze = _load_json(PHASE_FREEZE, "phase freeze")
    _assert_task3_authority(manifest, freeze)
    task_id = task["instance_id"]
    matches = [entry for entry in manifest["entries"] if isinstance(entry, dict) and entry.get("task_id") == task_id]
    if len(matches) != 1:
        raise MapBindingError("map_authority_refused: task does not have exactly one frozen map")
    entry = matches[0]
    issue_sha256 = sha256_bytes(task["issue_text"].encode("utf-8"))
    if entry.get("base_commit") != task["base_commit"]:
        raise MapBindingError("map_authority_refused: map revision differs from task revision")
    if entry.get("issue_sha256") != issue_sha256:
        raise MapBindingError("map_authority_refused: map issue hash differs from exact issue bytes")
    if entry.get("repository_url") != task.get("repository_url"):
        raise MapBindingError("map_authority_refused: map repository URL differs from task")
    relative = entry.get("artifact_directory")
    expected_relative = f"{MAPS_ROOT_RELATIVE}/official/{task_id}"
    if relative != expected_relative:
        raise MapBindingError("map_authority_refused: map artifact directory is not canonical")
    artifact = ROOT / relative
    if artifact.is_symlink() or not artifact.is_dir() or artifact.resolve() != (MAPS_ROOT / "official" / task_id).resolve():
        raise MapBindingError("map_authority_refused: map artifact directory is mutable or non-canonical")
    record_path = artifact / "record.json"
    map_path = artifact / "repo-map.txt"
    record = _load_json(record_path, "map record")
    _regular(map_path, "map text")
    record_digest = sha256_file(record_path)
    map_bytes = map_path.read_bytes()
    map_digest = sha256_bytes(map_bytes)
    if record_digest != entry.get("record_sha256") or map_digest != entry.get("map_sha256"):
        raise MapBindingError("map_authority_refused: map artifact digest differs from frozen manifest")
    repository = record.get("repository")
    issue = record.get("issue")
    if (
        not isinstance(repository, dict)
        or not isinstance(issue, dict)
        or repository.get("revision") != task["base_commit"]
        or repository.get("url") != task.get("repository_url")
        or issue.get("sha256") != issue_sha256
    ):
        raise MapBindingError("map_authority_refused: map record task binding differs")
    map_metadata = record.get("map")
    entry_map_metadata = entry.get("map")
    if (
        not isinstance(map_metadata, dict)
        or not isinstance(entry_map_metadata, dict)
        or map_metadata != entry_map_metadata
        or map_metadata.get("sha256") != map_digest
        or map_metadata.get("returned_string_sha256") != map_digest
    ):
        raise MapBindingError("map_authority_refused: map record does not bind map bytes")
    authority = entry.get("authority")
    record_authority = record.get("authority")
    if not isinstance(authority, dict) or record_authority != authority or not isinstance(authority.get("source_lock_sha256"), str):
        raise MapBindingError("map_authority_refused: source lock binding differs")
    source_lock_digest = authority["source_lock_sha256"]
    if sha256_file(SOURCE_LOCK) != source_lock_digest:
        raise MapBindingError("map_authority_refused: pinned Aider source lock differs")
    try:
        text = map_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MapBindingError("map_authority_refused: map is not UTF-8 prompt text") from exc
    if not text.strip() or "</aider_repo_map>" in text:
        raise MapBindingError("map_authority_refused: empty or delimiter-bearing map")
    no_provider = record.get("no_provider_or_agent_call")
    if (
        not isinstance(no_provider, dict)
        or no_provider.get("provider_or_llm_calls") != 0
        or no_provider.get("aider_coding_agent_started") is not False
        or no_provider.get("mcp_or_codegraph_started") is not False
    ):
        raise MapBindingError("map_authority_refused: map preparation was not provider and agent free")
    if entry.get("no_provider_or_agent_call") != no_provider:
        raise MapBindingError("map_authority_refused: map no-provider authority differs")
    record_configuration = record.get("configuration")
    if (
        not isinstance(record_configuration, dict)
        or record_configuration.get("sha256") != entry.get("configuration_sha256")
        or record.get("semantic_record_sha256") != entry.get("adapter_semantic_record_sha256")
    ):
        raise MapBindingError("map_authority_refused: record configuration or semantic authority differs")
    duration = record.get("duration_seconds")
    if duration is not None and (not isinstance(duration, (int, float)) or isinstance(duration, bool) or duration < 0):
        raise MapBindingError("map_authority_refused: map generation duration is invalid")
    return BoundMap(task_id, task["base_commit"], issue_sha256, text, map_digest, record_digest, source_lock_digest, EXPECTED_MANIFEST_SHA256, EXPECTED_PHASE_FREEZE_SHA256, EXPECTED_TASK3_SEAL_SHA256, relative, duration)
