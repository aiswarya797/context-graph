#!/usr/bin/env python3
"""Materialize immutable Task 2 bootstrap records in a fresh checkout."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from typing import Any


SCHEMA_VERSION = "codex-codegraph-task2-publication-v1"
BUNDLE_RELATIVE = PurePosixPath("reproducibility/codex_codegraph_task2")
EXPECTED_FILES = {
    ".benchmark-tools/codegraph/source-lock.json": {
        "publication_path": (
            "reproducibility/codex_codegraph_task2/source-lock.json"
        ),
        "sha256": (
            "d1fe0e768111f1caa3d2bb16285e5e1bd0263ef6e083292972d9e899bf6ea922"
        ),
        "bytes": 4058,
    },
    ".benchmark-tools/codegraph/upstream-resolution.json": {
        "publication_path": (
            "reproducibility/codex_codegraph_task2/upstream-resolution.json"
        ),
        "sha256": (
            "dec977b5c4635c852b37391b52f5cf3a609489bd8ca2ec8d649290058f1fd427"
        ),
        "bytes": 528,
    },
}
AUTHORITY_SENTINELS = (
    ".benchmark-tools/codegraph/task2-evidence-root-v18.json",
    ".benchmark-tools/codegraph/task2-freeze-marker-v18.json",
    ".benchmark-work/codegraph/setup-logs-v18/active-authority.json",
)
PINNED_REPOSITORY_URL = "https://github.com/colbymchenry/codegraph.git"
PINNED_COMMIT = "572d22bfbe82602080e457bec655f72e3314f9ef"
PINNED_VERSION = "1.5.0"
EXPECTED_EXCLUSIONS = [
    "CodeGraph source clone",
    "CodeGraph dependencies and node_modules",
    "CodeGraph build output",
    "Task 2 indexes",
    "benchmark runs and historical attempts",
]
EXPECTED_INCLUSION_STATEMENT = (
    "The CodeGraph source clone, dependencies, build output, indexes, and "
    "benchmark runs are intentionally not included."
)
MANIFEST_KEYS = {
    "schema_version",
    "copied_files",
    "upstream",
    "task2",
    "intentionally_not_included",
    "inclusion_statement",
}
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_CREATE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


class MaterializationError(RuntimeError):
    """Fail-closed publication-bundle or destination error."""


def _require_safe_open_support() -> None:
    if not getattr(os, "O_DIRECTORY", 0) or not getattr(os, "O_NOFOLLOW", 0):
        raise MaterializationError(
            "platform lacks O_DIRECTORY/O_NOFOLLOW safety support"
        )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _safe_relative(value: Any, *, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise MaterializationError(
            f"{label} must be a non-empty POSIX relative path"
        )
    path = PurePosixPath(value)
    if path.is_absolute() or path == PurePosixPath(".") or ".." in path.parts:
        raise MaterializationError(f"{label} escapes the workspace")
    return path


def _open_root_fd(root: Path, *, label: str) -> int:
    _require_safe_open_support()
    try:
        descriptor = os.open(root, _DIRECTORY_FLAGS)
    except OSError as exc:
        raise MaterializationError(
            f"{label} must be an existing real directory"
        ) from exc
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise MaterializationError(f"{label} must be a real directory")
    return descriptor


def _open_parent_fd(
    root_fd: int,
    parent: PurePosixPath,
    *,
    create: bool,
    missing_ok: bool = False,
) -> int | None:
    current = os.dup(root_fd)
    try:
        for part in parent.parts:
            try:
                following = os.open(part, _DIRECTORY_FLAGS, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    if missing_ok:
                        os.close(current)
                        return None
                    raise MaterializationError(
                        f"required directory is missing: {parent.as_posix()}"
                    )
                try:
                    os.mkdir(part, 0o700, dir_fd=current)
                except FileExistsError:
                    pass
                try:
                    following = os.open(
                        part, _DIRECTORY_FLAGS, dir_fd=current
                    )
                except OSError as exc:
                    raise MaterializationError(
                        f"destination directory race refused: {part}"
                    ) from exc
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise MaterializationError(
                        f"symlink or non-directory path component refused: {part}"
                    ) from exc
                raise MaterializationError(
                    f"cannot open directory component: {part}"
                ) from exc
            os.close(current)
            current = following
        return current
    except Exception:
        try:
            os.close(current)
        except OSError:
            pass
        raise


def _read_regular_at(
    root_fd: int,
    relative: PurePosixPath,
    *,
    label: str,
) -> bytes:
    parent = PurePosixPath(*relative.parts[:-1])
    parent_fd = _open_parent_fd(root_fd, parent, create=False)
    assert parent_fd is not None
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(
                relative.name, _FILE_READ_FLAGS, dir_fd=parent_fd
            )
        except FileNotFoundError as exc:
            raise MaterializationError(f"{label} is missing") from exc
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise MaterializationError(
                    f"{label} must not be a symlink"
                ) from exc
            raise MaterializationError(f"cannot open {label}") from exc
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise MaterializationError(f"{label} must be a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def _load_json_payload(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MaterializationError(f"{label} is malformed JSON") from exc
    if not isinstance(value, dict):
        raise MaterializationError(f"{label} must contain a JSON object")
    return value


def _validate_identity_metadata(
    manifest: dict[str, Any],
    copied_json: dict[str, dict[str, Any]],
) -> None:
    upstream = manifest.get("upstream")
    task2 = manifest.get("task2")
    if upstream != {
        "repository_url": PINNED_REPOSITORY_URL,
        "resolved_commit": PINNED_COMMIT,
        "codegraph_version": PINNED_VERSION,
    }:
        raise MaterializationError(
            "manifest upstream identity differs from the published pin"
        )
    if not isinstance(task2, dict) or set(task2) != {
        "run_id",
        "evidence_root",
        "freeze_marker",
        "active_authority",
        "active_harness_sha256",
    }:
        raise MaterializationError("manifest Task 2 identity is malformed")

    lock = copied_json[".benchmark-tools/codegraph/source-lock.json"]
    resolution = copied_json[
        ".benchmark-tools/codegraph/upstream-resolution.json"
    ]
    if (
        lock.get("repository_url") != PINNED_REPOSITORY_URL
        or lock.get("resolved_commit") != PINNED_COMMIT
        or lock.get("declared_version") != PINNED_VERSION
        or resolution.get("repository_url") != PINNED_REPOSITORY_URL
        or resolution.get("resolved_commit") != PINNED_COMMIT
        or resolution.get("return_code") != 0
    ):
        raise MaterializationError(
            "copied records differ from the published upstream identity"
        )
    if (
        lock.get("upstream_resolution_sha256")
        != EXPECTED_FILES[
            ".benchmark-tools/codegraph/upstream-resolution.json"
        ]["sha256"]
    ):
        raise MaterializationError(
            "source lock does not bind the copied resolution record"
        )

    if (
        task2.get("run_id") != "codex-codegraph-v18-20260727T103813Z"
        or task2.get("active_harness_sha256")
        != "866adb56f6f41437844ae757f3ba2cca7e4fab4da251badf208d6fb398308a5a"
    ):
        raise MaterializationError("manifest Task 2 identity differs")
    for key, path, digest in (
        (
            "evidence_root",
            ".benchmark-tools/codegraph/task2-evidence-root-v18.json",
            "0a71611c62de5c970f1a8904c8cb53d55d1ed6cea6d3f89b1e58b9ceef6a2d0f",
        ),
        (
            "freeze_marker",
            ".benchmark-tools/codegraph/task2-freeze-marker-v18.json",
            "f5da010a9193465e48f78d200c7e1f9f2b892672e8604bcd7e37760be4267c91",
        ),
        (
            "active_authority",
            ".benchmark-work/codegraph/setup-logs-v18/active-authority.json",
            "3bbdd8280d35f60de8892b8dc34a6ee3b5386d7337a5a5f82fcb8906ad42beab",
        ),
    ):
        if task2.get(key) != {"path": path, "sha256": digest}:
            raise MaterializationError(f"manifest {key} identity differs")


def verify_bundle(bundle_root: Path) -> dict[str, Any]:
    """Verify the complete publication bundle without modifying the workspace."""

    bundle_root = _absolute(bundle_root)
    if bundle_root.name != BUNDLE_RELATIVE.name:
        raise MaterializationError("bundle directory name differs")
    workspace = bundle_root.parents[1]
    if bundle_root != workspace.joinpath(*BUNDLE_RELATIVE.parts):
        raise MaterializationError(
            "bundle path differs from its canonical repository path"
        )

    workspace_fd = _open_root_fd(workspace, label="bundle workspace")
    try:
        workspace_stat = os.fstat(workspace_fd)
        manifest_relative = BUNDLE_RELATIVE / "manifest.json"
        manifest_payload = _read_regular_at(
            workspace_fd, manifest_relative, label="manifest.json"
        )
        manifest = _load_json_payload(
            manifest_payload, label="manifest.json"
        )
        if set(manifest) != MANIFEST_KEYS:
            raise MaterializationError("manifest fields differ")
        if manifest.get("schema_version") != SCHEMA_VERSION:
            raise MaterializationError("unsupported manifest schema version")
        if manifest.get("intentionally_not_included") != EXPECTED_EXCLUSIONS:
            raise MaterializationError("manifest exclusion statement differs")
        if (
            manifest.get("inclusion_statement")
            != EXPECTED_INCLUSION_STATEMENT
        ):
            raise MaterializationError("manifest inclusion statement differs")

        rows = manifest.get("copied_files")
        if not isinstance(rows, list) or len(rows) != len(EXPECTED_FILES):
            raise MaterializationError(
                "manifest must bind exactly two copied files"
            )
        copied_json: dict[str, dict[str, Any]] = {}
        payloads: dict[str, bytes] = {}
        for row in rows:
            if not isinstance(row, dict):
                raise MaterializationError(
                    "malformed copied-file manifest row"
                )
            original = _safe_relative(
                row.get("original_path"), label="original_path"
            )
            original_text = original.as_posix()
            expected = EXPECTED_FILES.get(original_text)
            if expected is None:
                raise MaterializationError(
                    "manifest copied-file destination differs"
                )
            publication = _safe_relative(
                row.get("publication_path"), label="publication_path"
            )
            expected_row = {
                "original_path": original_text,
                **expected,
            }
            if row != expected_row:
                raise MaterializationError(
                    "manifest copied-file identity differs"
                )
            if original_text in payloads:
                raise MaterializationError(
                    "duplicate copied-file destination"
                )
            payload = _read_regular_at(
                workspace_fd,
                publication,
                label=publication.as_posix(),
            )
            if (
                len(payload) != expected["bytes"]
                or _sha256(payload) != expected["sha256"]
            ):
                raise MaterializationError(
                    f"copied bytes differ: {publication.as_posix()}"
                )
            copied_json[original_text] = _load_json_payload(
                payload,
                label=f"copied record {publication.as_posix()}",
            )
            payloads[original_text] = payload
        if set(payloads) != set(EXPECTED_FILES):
            raise MaterializationError("manifest copied-file set differs")
        _validate_identity_metadata(manifest, copied_json)
        return {
            "schema_version": SCHEMA_VERSION,
            "bundle_root": str(bundle_root),
            "workspace": str(workspace),
            "workspace_identity": (
                workspace_stat.st_dev,
                workspace_stat.st_ino,
            ),
            "manifest": manifest,
            "payloads": payloads,
        }
    finally:
        os.close(workspace_fd)


def _require_git_root(workspace_fd: int) -> None:
    try:
        marker = os.stat(".git", dir_fd=workspace_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise MaterializationError(
            "workspace must be the Git checkout containing this bundle"
        ) from exc
    if not (stat.S_ISDIR(marker.st_mode) or stat.S_ISREG(marker.st_mode)):
        raise MaterializationError(
            "workspace .git marker must be a real file or directory"
        )


def _sentinel_present(workspace_fd: int, relative: PurePosixPath) -> bool:
    parent = PurePosixPath(*relative.parts[:-1])
    parent_fd = _open_parent_fd(
        workspace_fd, parent, create=False, missing_ok=True
    )
    if parent_fd is None:
        return False
    try:
        try:
            os.stat(relative.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True
    finally:
        os.close(parent_fd)


def _refuse_authoritative_workspace(workspace_fd: int) -> None:
    for value in AUTHORITY_SENTINELS:
        relative = _safe_relative(value, label="authority sentinel")
        if _sentinel_present(workspace_fd, relative):
            raise MaterializationError(
                f"completed Task 2 authority workspace refused: {value}"
            )


def _destination_status_at(
    parent_fd: int,
    name: str,
    payload: bytes,
) -> str:
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(name, _FILE_READ_FLAGS, dir_fd=parent_fd)
        except FileNotFoundError:
            return "absent"
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise MaterializationError(
                    f"destination symlink refused: {name}"
                ) from exc
            raise MaterializationError(
                f"cannot inspect destination: {name}"
            ) from exc
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise MaterializationError(
                f"destination is not a regular file: {name}"
            )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        if b"".join(chunks) != payload:
            raise MaterializationError(
                f"conflicting destination refused: {name}"
            )
        return "already_materialized"
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _destination_status(
    workspace_fd: int,
    relative: PurePosixPath,
    payload: bytes,
) -> str:
    parent = PurePosixPath(*relative.parts[:-1])
    parent_fd = _open_parent_fd(
        workspace_fd, parent, create=False, missing_ok=True
    )
    if parent_fd is None:
        return "absent"
    try:
        return _destination_status_at(parent_fd, relative.name, payload)
    finally:
        os.close(parent_fd)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise OSError("short write")
        written += count


def _create_once_at(
    parent_fd: int,
    name: str,
    payload: bytes,
) -> tuple[str, tuple[int, int] | None]:
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(
                name,
                _FILE_CREATE_FLAGS,
                0o600,
                dir_fd=parent_fd,
            )
        except FileExistsError:
            status = _destination_status_at(parent_fd, name, payload)
            if status == "already_materialized":
                return status, None
            raise
        _write_all(descriptor, payload)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        created = os.fstat(descriptor)
        return "materialized", (created.st_dev, created.st_ino)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _rollback_created(
    created: list[tuple[int, str, tuple[int, int]]],
) -> list[str]:
    errors: list[str] = []
    for parent_fd, name, identity in reversed(created):
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != identity:
                errors.append(f"identity changed before rollback: {name}")
                continue
            os.unlink(name, dir_fd=parent_fd)
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append(f"rollback failed for {name}: {exc}")
    return errors


def materialize(
    bundle_root: Path,
    workspace: Path,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Verify and optionally create the two canonical ignored bootstrap files."""

    verified = verify_bundle(bundle_root)
    workspace = _absolute(workspace)
    if workspace != Path(verified["workspace"]):
        raise MaterializationError(
            "workspace must be the Git checkout containing this bundle"
        )
    workspace_fd = _open_root_fd(workspace, label="workspace")
    created: list[tuple[int, str, tuple[int, int]]] = []
    open_parent_fds: list[int] = []
    try:
        workspace_stat = os.fstat(workspace_fd)
        if (
            workspace_stat.st_dev,
            workspace_stat.st_ino,
        ) != verified["workspace_identity"]:
            raise MaterializationError(
                "workspace identity changed after bundle verification"
            )
        _require_git_root(workspace_fd)
        _refuse_authoritative_workspace(workspace_fd)
        operations: list[dict[str, str]] = []
        statuses: dict[str, str] = {}
        for original_text in EXPECTED_FILES:
            relative = _safe_relative(original_text, label="destination")
            payload = verified["payloads"][original_text]
            status = _destination_status(workspace_fd, relative, payload)
            statuses[original_text] = status
            operations.append(
                {
                    "destination": original_text,
                    "status": (
                        "would_materialize"
                        if status == "absent" and dry_run
                        else status
                    ),
                }
            )

        if not dry_run:
            for operation in operations:
                original_text = operation["destination"]
                if statuses[original_text] == "already_materialized":
                    continue
                _refuse_authoritative_workspace(workspace_fd)
                relative = _safe_relative(
                    original_text, label="destination"
                )
                parent = PurePosixPath(*relative.parts[:-1])
                parent_fd = _open_parent_fd(
                    workspace_fd, parent, create=True
                )
                assert parent_fd is not None
                open_parent_fds.append(parent_fd)
                status, identity = _create_once_at(
                    parent_fd,
                    relative.name,
                    verified["payloads"][original_text],
                )
                operation["status"] = status
                if identity is not None:
                    created.append((parent_fd, relative.name, identity))
            _refuse_authoritative_workspace(workspace_fd)

        return {
            "schema_version": SCHEMA_VERSION,
            "mode": "dry-run" if dry_run else "materialize",
            "workspace": str(workspace),
            "operations": operations,
        }
    except Exception as exc:
        rollback_errors = _rollback_created(created)
        if rollback_errors:
            raise MaterializationError(
                f"{exc}; rollback incomplete: {'; '.join(rollback_errors)}"
            ) from exc
        raise
    finally:
        for descriptor in open_parent_fds:
            os.close(descriptor)
        os.close(workspace_fd)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify and materialize the two immutable Task 2 bootstrap records "
            "in a fresh checkout."
        )
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        help=(
            "repository root containing this bundle; defaults to the bundle's "
            "own checkout"
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the bundle and destination plan without writing",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="alias for a read-only destination plan",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    script = _absolute(Path(__file__))
    bundle_root = script.parent
    workspace = args.workspace or bundle_root.parents[1]
    try:
        result = materialize(
            bundle_root,
            workspace,
            dry_run=bool(args.check or args.dry_run),
        )
    except (MaterializationError, OSError) as exc:
        print(f"materialization_refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
