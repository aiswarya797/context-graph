"""Canonical immutable Task 2 evidence root.

The manifest is created once, after runtime/index preparation and validation,
then becomes the authority for every later doctor, smoke, run, score, report,
and comparison preflight.  Validation never re-hashes edited evidence into a
new authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class Task2EvidenceError(RuntimeError):
    """Task 2 evidence is missing, mutable, or byte-inconsistent."""


TASK2_EVIDENCE_SCHEMA_V1 = "codegraph-task2-evidence-root-v1"
TASK2_EVIDENCE_SCHEMA_V2 = "codegraph-task2-evidence-root-v2"
TASK2_FREEZE_MARKER_SCHEMA_V1 = "codegraph-task2-freeze-marker-v1"


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def _serialized(value: Any) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _mode(path: Path) -> str:
    return f"{stat.S_IMODE(path.stat().st_mode):04o}"


def _relative(root: Path, path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise Task2EvidenceError(f"task2_evidence_escape: {path}") from exc


def _scope_files(root: Path, scopes: list[dict[str, Any]]) -> list[Path]:
    files: set[Path] = set()
    for scope in scopes:
        kind = scope.get("kind")
        value = scope.get("path")
        if not isinstance(value, str) or not value:
            raise Task2EvidenceError("task2_evidence_scope_invalid")
        target = root / value
        if kind == "file":
            if not target.is_file() or target.is_symlink():
                raise Task2EvidenceError(f"task2_evidence_missing: {value}")
            files.add(target.resolve())
        elif kind == "tree":
            if not target.is_dir() or target.is_symlink():
                raise Task2EvidenceError(f"task2_evidence_missing_tree: {value}")
            for path in target.rglob("*"):
                if path.is_symlink():
                    raise Task2EvidenceError(
                        f"task2_evidence_symlink_refused: {_relative(root, path)}"
                    )
                if path.is_file():
                    files.add(path.resolve())
        elif kind == "glob":
            matches = [
                path
                for path in root.glob(value)
                if path.is_file() and not path.is_symlink()
            ]
            if not matches:
                raise Task2EvidenceError(f"task2_evidence_glob_empty: {value}")
            files.update(path.resolve() for path in matches)
        else:
            raise Task2EvidenceError(f"task2_evidence_scope_kind_invalid: {kind}")
    return sorted(files, key=lambda path: _relative(root, path))


def _frozen_files(root: Path, scopes: list[dict[str, Any]]) -> set[Path]:
    frozen: set[Path] = set()
    for scope in scopes:
        if scope.get("freeze", True) is not False:
            frozen.update(_scope_files(root, [scope]))
    return frozen


def _entry(root: Path, path: Path, *, frozen_mode: str = "0400") -> dict[str, Any]:
    return {
        "path": _relative(root, path),
        "bytes": path.stat().st_size,
        "sha256": _sha256(path),
        "mode": frozen_mode,
    }


def _write_new(path: Path, value: Any, mode: int) -> None:
    if path.exists() or path.is_symlink():
        raise Task2EvidenceError(f"task2_evidence_refuses_overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(_serialized(value))
    os.chmod(temporary, mode)
    os.replace(temporary, path)
    os.chmod(path, mode)


def build_task2_freeze_marker(
    *,
    root: Path,
    manifest_path: Path,
    marker_path: Path,
) -> dict[str, Any]:
    """Seal an existing evidence root without making recovery implicit."""
    if marker_path.exists() or marker_path.is_symlink():
        raise Task2EvidenceError("task2_freeze_marker_already_exists")
    manifest = validate_task2_evidence_root(
        root=root,
        manifest_path=manifest_path,
    )
    marker = {
        "schema_version": TASK2_FREEZE_MARKER_SCHEMA_V1,
        "evidence_root_path": _relative(root, manifest_path),
        "evidence_root_bytes": manifest_path.stat().st_size,
        "evidence_root_mode": _mode(manifest_path),
        "evidence_root_sha256": _sha256(manifest_path),
        "evidence_root_schema_version": manifest["schema_version"],
        "evidence_root_entry_count": manifest["entry_count"],
        "policy": "missing-or-changed-root-refuses-without-recovery",
    }
    _write_new(marker_path, marker, 0o400)
    return validate_task2_freeze_marker(
        root=root,
        manifest_path=manifest_path,
        marker_path=marker_path,
    )


def validate_task2_freeze_marker(
    *,
    root: Path,
    manifest_path: Path,
    marker_path: Path,
) -> dict[str, Any]:
    marker, _manifest = validate_task2_freeze_contract(
        root=root,
        manifest_path=manifest_path,
        marker_path=marker_path,
    )
    return marker


def validate_task2_freeze_contract(
    *,
    root: Path,
    manifest_path: Path,
    marker_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate the external create-once seal before touching preparation state."""
    if (
        not marker_path.is_file()
        or marker_path.is_symlink()
        or _mode(marker_path) != "0400"
    ):
        raise Task2EvidenceError("task2_freeze_marker_missing_or_mutable")
    if (
        not manifest_path.is_file()
        or manifest_path.is_symlink()
        or _mode(manifest_path) != "0400"
    ):
        raise Task2EvidenceError("task2_evidence_root_missing_after_freeze")
    try:
        marker_bytes = marker_path.read_bytes()
        marker = json.loads(marker_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        raise Task2EvidenceError("task2_freeze_marker_invalid_json") from exc
    if marker_bytes != _serialized(marker):
        raise Task2EvidenceError("task2_freeze_marker_bytes_noncanonical")
    required = {
        "schema_version",
        "evidence_root_path",
        "evidence_root_bytes",
        "evidence_root_mode",
        "evidence_root_sha256",
        "evidence_root_schema_version",
        "evidence_root_entry_count",
        "policy",
    }
    if (
        not isinstance(marker, dict)
        or set(marker) != required
        or marker["schema_version"] != TASK2_FREEZE_MARKER_SCHEMA_V1
        or marker["evidence_root_path"] != _relative(root, manifest_path)
        or marker["evidence_root_mode"] != "0400"
        or marker["policy"] != "missing-or-changed-root-refuses-without-recovery"
        or not isinstance(marker["evidence_root_bytes"], int)
        or marker["evidence_root_bytes"] < 1
        or not isinstance(marker["evidence_root_sha256"], str)
        or len(marker["evidence_root_sha256"]) != 64
        or not isinstance(marker["evidence_root_schema_version"], str)
        or not isinstance(marker["evidence_root_entry_count"], int)
        or marker["evidence_root_entry_count"] < 1
    ):
        raise Task2EvidenceError("task2_freeze_marker_schema_invalid")
    if (
        manifest_path.stat().st_size != marker["evidence_root_bytes"]
        or _sha256(manifest_path) != marker["evidence_root_sha256"]
    ):
        raise Task2EvidenceError("task2_evidence_root_changed_after_freeze")
    manifest = validate_task2_evidence_root(
        root=root,
        manifest_path=manifest_path,
    )
    if (
        manifest["schema_version"] != marker["evidence_root_schema_version"]
        or manifest["entry_count"] != marker["evidence_root_entry_count"]
    ):
        raise Task2EvidenceError("task2_evidence_root_changed_after_freeze")
    return marker, manifest


def build_task2_evidence_root(
    *,
    root: Path,
    manifest_path: Path,
    scopes: list[dict[str, Any]],
    identities: dict[str, Any],
    predecessor: dict[str, Any] | None = None,
    mutable_exclusions: list[str] | None = None,
) -> dict[str, Any]:
    """Freeze authoritative Task 2 files and create the one root manifest."""
    if manifest_path.exists() or manifest_path.is_symlink():
        raise Task2EvidenceError("task2_evidence_already_frozen")
    files = _scope_files(root, scopes)
    if manifest_path.resolve() in files:
        raise Task2EvidenceError("task2_evidence_manifest_self_reference")
    frozen_files = _frozen_files(root, scopes)
    entries = [
        _entry(
            root,
            path,
            frozen_mode="0400" if path in frozen_files else _mode(path),
        )
        for path in files
    ]
    manifest = {
        "schema_version": TASK2_EVIDENCE_SCHEMA_V2,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "scopes": scopes,
        "identities": identities,
        "entry_count": len(entries),
        "entries": entries,
        "entries_sha256": hashlib.sha256(_canonical(entries)).hexdigest(),
        "freeze_policy": {
            "file_mode": "0400",
            "manifest_mode": "0400",
            "validation": "exact-path-size-mode-sha256-and-scope-membership",
            "authority": "create-once-never-rehash",
            "preserved_mode_scopes": True,
        },
        "predecessor": predecessor,
        "mutable_exclusions": mutable_exclusions or [],
    }
    for path in frozen_files:
        os.chmod(path, 0o400)
    _write_new(manifest_path, manifest, 0o400)
    return validate_task2_evidence_root(root=root, manifest_path=manifest_path)


def validate_task2_evidence_root(
    *,
    root: Path,
    manifest_path: Path,
    expected_schema_version: str = TASK2_EVIDENCE_SCHEMA_V2,
) -> dict[str, Any]:
    """Validate the existing authority without rewriting any evidence."""
    if (
        not manifest_path.is_file()
        or manifest_path.is_symlink()
        or _mode(manifest_path) != "0400"
    ):
        raise Task2EvidenceError("task2_evidence_root_missing_or_mutable")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Task2EvidenceError("task2_evidence_root_invalid_json") from exc
    required = {
        "schema_version",
        "created_at",
        "scopes",
        "identities",
        "entry_count",
        "entries",
        "entries_sha256",
        "freeze_policy",
    }
    if expected_schema_version == TASK2_EVIDENCE_SCHEMA_V2:
        required |= {"predecessor", "mutable_exclusions"}
    if (
        not isinstance(manifest, dict)
        or set(manifest) != required
        or manifest["schema_version"] != expected_schema_version
        or not isinstance(manifest["entries"], list)
        or manifest["entry_count"] != len(manifest["entries"])
        or manifest["entries_sha256"]
        != hashlib.sha256(_canonical(manifest["entries"])).hexdigest()
    ):
        raise Task2EvidenceError("task2_evidence_root_schema_invalid")
    if expected_schema_version == TASK2_EVIDENCE_SCHEMA_V2 and (
        not isinstance(manifest["predecessor"], dict)
        or not isinstance(manifest["mutable_exclusions"], list)
        or not all(
            isinstance(value, str) and value
            for value in manifest["mutable_exclusions"]
        )
    ):
        raise Task2EvidenceError("task2_evidence_root_v2_contract_invalid")
    expected_paths = [entry.get("path") for entry in manifest["entries"]]
    if (
        any(not isinstance(path, str) or not path for path in expected_paths)
        or len(set(expected_paths)) != len(expected_paths)
    ):
        raise Task2EvidenceError("task2_evidence_root_duplicate_or_invalid_path")
    current_files = _scope_files(root, manifest["scopes"])
    frozen_files = _frozen_files(root, manifest["scopes"])
    current_paths = [_relative(root, path) for path in current_files]
    if current_paths != expected_paths:
        raise Task2EvidenceError("task2_evidence_scope_addition_or_removal")
    for path, entry in zip(current_files, manifest["entries"], strict=True):
        if set(entry) != {"path", "bytes", "sha256", "mode"}:
            raise Task2EvidenceError("task2_evidence_entry_schema_invalid")
        if (
            path.stat().st_size != entry["bytes"]
            or _sha256(path) != entry["sha256"]
            or _mode(path) != entry["mode"]
            or (path in frozen_files and entry["mode"] != "0400")
        ):
            raise Task2EvidenceError(
                f"task2_evidence_entry_mismatch: {entry['path']}"
            )
    return manifest
