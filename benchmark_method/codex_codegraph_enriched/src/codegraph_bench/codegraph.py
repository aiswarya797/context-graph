"""Pinned CodeGraph runtime provenance and immutable index handling."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


UPSTREAM_URL = "https://github.com/colbymchenry/codegraph.git"
HEX_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EVIDENCE_ASSERTIONS = {
    "telemetry_disabled_branch",
    "self_update_disabled_branch",
    "direct_stdio_no_daemon_branch",
    "watch_disabled_branch",
    "catch_up_sync_mutates_copy_branch",
    "codegraph_directory_override_branch",
}
NETWORK_DENY_PROFILE = "(version 1) (allow default) (deny network*)"
REQUIRED_CONTROL_ENVIRONMENT = {
    "DO_NOT_TRACK": "1",
    "CODEGRAPH_TELEMETRY": "0",
    "CODEGRAPH_NO_UPDATE_CHECK": "1",
    "CODEGRAPH_NO_DAEMON": "1",
    "CODEGRAPH_NO_WATCH": "1",
}
CONFLICTING_CONTROL_KEYS = {
    "CODEGRAPH_DAEMON_INTERNAL",
    "CODEGRAPH_FORCE_WATCH",
}


class CodeGraphError(RuntimeError):
    """Fail-closed CodeGraph preparation or provenance error."""

    def __init__(self, failure_class: str, message: str):
        super().__init__(f"{failure_class}: {message}")
        self.failure_class = failure_class


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_value(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode() + b"\n")
    os.chmod(temporary, mode)
    os.replace(temporary, path)
    os.chmod(path, mode)


def load_source_lock(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise CodeGraphError("codegraph_source_mismatch", f"source lock missing: {path}")
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CodeGraphError("codegraph_source_mismatch", f"source lock is not valid JSON: {exc}") from exc
    return validate_source_lock(lock)


def validate_source_lock(lock: dict[str, Any]) -> dict[str, Any]:
    required = {
        "schema_version",
        "repository_url",
        "resolved_commit",
        "retrieved_at",
        "declared_version",
        "license",
        "package_metadata_sha256",
        "lockfile_sha256",
        "upstream_resolution_sha256",
        "toolchain",
        "build_entrypoint",
        "install_command",
        "build_command",
        "executable_relative_path",
        "version_command",
        "index_command",
        "status_command",
        "serve_args",
        "telemetry",
        "self_update",
        "runtime_controls",
    }
    if not isinstance(lock, dict) or set(lock) != required:
        raise CodeGraphError("codegraph_source_mismatch", "source lock fields are not exact")
    if lock["schema_version"] != "codegraph-source-lock-v1" or lock["repository_url"] != UPSTREAM_URL:
        raise CodeGraphError("codegraph_source_mismatch", "source repository identity differs")
    if not isinstance(lock["resolved_commit"], str) or not HEX_SHA.fullmatch(lock["resolved_commit"]):
        raise CodeGraphError("codegraph_source_mismatch", "resolved commit must be a lowercase 40-character SHA")
    for field in ("retrieved_at", "declared_version", "license", "executable_relative_path"):
        if not isinstance(lock[field], str) or not lock[field].strip():
            raise CodeGraphError("codegraph_source_mismatch", f"{field} is required")
    for field in ("package_metadata_sha256", "lockfile_sha256", "upstream_resolution_sha256"):
        if not SHA256.fullmatch(str(lock[field])):
            raise CodeGraphError("codegraph_source_mismatch", f"{field} must be sha256")
    try:
        datetime.fromisoformat(lock["retrieved_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise CodeGraphError("codegraph_source_mismatch", "retrieved_at must be ISO-8601") from exc
    for field in ("build_entrypoint", "install_command", "build_command", "version_command", "index_command", "status_command", "serve_args"):
        if not isinstance(lock[field], list) or not lock[field] or not all(isinstance(value, str) and value for value in lock[field]):
            raise CodeGraphError("codegraph_source_mismatch", f"{field} must be a non-empty argument vector")
    for field in ("install_command", "build_command"):
        command = lock[field][0]
        if command != "npm" or Path(command).is_absolute() or "/" in command or "\\" in command:
            raise CodeGraphError(
                "codegraph_source_mismatch",
                f"{field} must use the portable logical npm command",
            )
    toolchain = lock["toolchain"]
    if (
        not isinstance(toolchain, dict)
        or set(toolchain) != {"required_node_range", "node", "npm"}
        or toolchain["required_node_range"] != ">=20 <25"
    ):
        raise CodeGraphError("codegraph_source_mismatch", "toolchain contract is not exact")
    for name, version_pattern in (("node", r"^v\d+\.\d+\.\d+$"), ("npm", r"^\d+\.\d+\.\d+$")):
        record = toolchain[name]
        if (
            not isinstance(record, dict)
            or set(record) != {"logical_command", "version", "executable_sha256"}
            or record["logical_command"] != name
            or not re.fullmatch(version_pattern, str(record["version"]))
            or not SHA256.fullmatch(str(record["executable_sha256"]))
        ):
            raise CodeGraphError("codegraph_source_mismatch", f"{name} toolchain identity is invalid")
    if lock["serve_args"][:2] != ["serve", "--mcp"]:
        raise CodeGraphError("codegraph_source_mismatch", "serve_args must start with serve --mcp")
    telemetry = lock["telemetry"]
    if not isinstance(telemetry, dict) or set(telemetry) != {"disabled", "environment", "source_evidence", "probe"}:
        raise CodeGraphError("codegraph_telemetry_not_disabled", "telemetry evidence fields are not exact")
    if telemetry["disabled"] is not True:
        raise CodeGraphError("codegraph_telemetry_not_disabled", "telemetry is enabled or unverifiable")
    if not isinstance(telemetry["environment"], dict) or not telemetry["environment"]:
        raise CodeGraphError("codegraph_telemetry_not_disabled", "telemetry-disable environment is missing")
    if not all(isinstance(key, str) and key and isinstance(value, str) for key, value in telemetry["environment"].items()):
        raise CodeGraphError("codegraph_telemetry_not_disabled", "telemetry environment must contain string pairs")
    validate_control_environment(telemetry["environment"])
    _validate_control_evidence(telemetry, "telemetry_disabled_branch", "codegraph_telemetry_not_disabled")
    self_update = lock["self_update"]
    if not isinstance(self_update, dict) or set(self_update) != {"disabled", "source_evidence", "probe"}:
        raise CodeGraphError("codegraph_source_mismatch", "self-update evidence fields are not exact")
    if self_update["disabled"] is not True:
        raise CodeGraphError("codegraph_source_mismatch", "runtime self-update is not disabled")
    _validate_control_evidence(self_update, "self_update_disabled_branch", "codegraph_source_mismatch")
    runtime_controls = lock["runtime_controls"]
    expected_assertions = {
        "direct_stdio_no_daemon_branch",
        "watch_disabled_branch",
        "catch_up_sync_mutates_copy_branch",
        "codegraph_directory_override_branch",
    }
    if (
        not isinstance(runtime_controls, dict)
        or set(runtime_controls) != {"source_evidence", "catch_up_sync_may_mutate_copy"}
        or runtime_controls["catch_up_sync_may_mutate_copy"] is not True
        or not isinstance(runtime_controls["source_evidence"], list)
        or {
            row.get("assertion")
            for row in runtime_controls["source_evidence"]
            if isinstance(row, dict)
        }
        != expected_assertions
    ):
        raise CodeGraphError("codegraph_source_mismatch", "runtime control evidence is incomplete")
    for row in runtime_controls["source_evidence"]:
        if (
            set(row) != {"path", "sha256", "assertion"}
            or not isinstance(row["path"], str)
            or Path(row["path"]).is_absolute()
            or ".." in Path(row["path"]).parts
            or not SHA256.fullmatch(str(row["sha256"]))
            or row["assertion"] not in expected_assertions
        ):
            raise CodeGraphError("codegraph_source_mismatch", "runtime control source evidence is invalid")
    return lock


def validate_control_environment(environment: dict[str, str]) -> dict[str, str]:
    """Require every safety control at its one accepted value."""
    missing_or_wrong = {
        key: environment.get(key)
        for key, expected in REQUIRED_CONTROL_ENVIRONMENT.items()
        if environment.get(key) != expected
    }
    conflicts = sorted(key for key in CONFLICTING_CONTROL_KEYS if key in environment)
    if missing_or_wrong or conflicts:
        raise CodeGraphError(
            "codegraph_telemetry_not_disabled",
            f"control environment differs: required={missing_or_wrong}, conflicting={conflicts}",
        )
    return environment


def _validate_control_evidence(control: dict[str, Any], assertion: str, failure_class: str) -> None:
    evidence = control.get("source_evidence")
    if not isinstance(evidence, list) or not evidence:
        raise CodeGraphError(failure_class, "machine-checkable source evidence is required")
    for row in evidence:
        if (
            not isinstance(row, dict)
            or set(row) != {"path", "sha256", "assertion"}
            or not isinstance(row["path"], str)
            or Path(row["path"]).is_absolute()
            or ".." in Path(row["path"]).parts
            or not SHA256.fullmatch(str(row["sha256"]))
            or row["assertion"] != assertion
            or row["assertion"] not in EVIDENCE_ASSERTIONS
        ):
            raise CodeGraphError(failure_class, "invalid source evidence contract")
    probe = control.get("probe")
    if not isinstance(probe, dict) or set(probe) != {
        "command",
        "expected_return_code",
        "expected_stdout_sha256",
        "expected_stderr_sha256",
        "network_policy",
    }:
        raise CodeGraphError(failure_class, "executable probe contract is not exact")
    if (
        not isinstance(probe["command"], list)
        or not probe["command"]
        or not all(isinstance(value, str) and value for value in probe["command"])
        or probe["expected_return_code"] != 0
        or not SHA256.fullmatch(str(probe["expected_stdout_sha256"]))
        or not SHA256.fullmatch(str(probe["expected_stderr_sha256"]))
        or probe["network_policy"] != "deny"
    ):
        raise CodeGraphError(failure_class, "executable probe contract is unverifiable")


def _verify_source_evidence(lock: dict[str, Any], checkout: Path) -> None:
    if sha256_file(checkout / "package.json") != lock["package_metadata_sha256"]:
        raise CodeGraphError("codegraph_source_mismatch", "package metadata bytes differ")
    if sha256_file(checkout / "package-lock.json") != lock["lockfile_sha256"]:
        raise CodeGraphError("codegraph_source_mismatch", "package lock bytes differ")
    for control_name in ("telemetry", "self_update", "runtime_controls"):
        for row in lock[control_name]["source_evidence"]:
            path = checkout / row["path"]
            if not path.is_file() or sha256_file(path) != row["sha256"]:
                failure = "codegraph_telemetry_not_disabled" if control_name == "telemetry" else "codegraph_source_mismatch"
                raise CodeGraphError(failure, f"{control_name} source evidence bytes differ: {row['path']}")


def _verify_probe_record(expected: dict[str, Any], actual: Any, failure_class: str) -> None:
    required = {"command", "return_code", "stdout", "stderr", "network_policy", "verified"}
    if not isinstance(actual, dict) or set(actual) != required:
        raise CodeGraphError(failure_class, "runtime probe record is missing or malformed")
    if (
        actual["command"] != expected["command"]
        or actual["return_code"] != expected["expected_return_code"]
        or actual["network_policy"] != expected["network_policy"]
        or actual["verified"] is not True
    ):
        raise CodeGraphError(failure_class, "runtime probe contract differs")
    for stream in ("stdout", "stderr"):
        artifact = actual[stream]
        if not isinstance(artifact, dict) or set(artifact) != {"path", "bytes", "sha256"}:
            raise CodeGraphError(failure_class, f"runtime probe {stream} artifact is malformed")
        if artifact["sha256"] != expected[f"expected_{stream}_sha256"]:
            raise CodeGraphError(failure_class, f"runtime probe {stream} digest differs")
        path = Path(artifact["path"])
        if (
            not path.is_file()
            or path.stat().st_size != artifact["bytes"]
            or sha256_file(path) != artifact["sha256"]
        ):
            raise CodeGraphError(failure_class, f"runtime probe {stream} raw artifact differs")


def _git(checkout: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(checkout), *args], capture_output=True, text=True, check=False)
    if result.returncode:
        raise CodeGraphError("codegraph_source_mismatch", result.stderr.strip() or "git verification failed")
    return result.stdout.strip()


def _validate_file_artifact(artifact: Any, failure_class: str, label: str) -> Path:
    if (
        not isinstance(artifact, dict)
        or set(artifact) != {"path", "bytes", "sha256"}
        or not isinstance(artifact["path"], str)
        or not isinstance(artifact["bytes"], int)
        or isinstance(artifact["bytes"], bool)
        or artifact["bytes"] < 0
        or not SHA256.fullmatch(str(artifact["sha256"]))
    ):
        raise CodeGraphError(failure_class, f"{label} artifact is malformed")
    path = Path(artifact["path"])
    if (
        not path.is_file()
        or path.stat().st_size != artifact["bytes"]
        or sha256_file(path) != artifact["sha256"]
    ):
        raise CodeGraphError(failure_class, f"{label} artifact bytes differ")
    return path


def _toolchain_record(lock: dict[str, Any], runtime: dict[str, Any], name: str) -> dict[str, Any]:
    value = runtime.get("toolchain", {}).get(name)
    expected = lock["toolchain"][name]
    if (
        not isinstance(value, dict)
        or set(value) != {"logical_command", "resolved_path", "version", "executable_sha256"}
        or value["logical_command"] != expected["logical_command"]
        or value["version"] != expected["version"]
        or value["executable_sha256"] != expected["executable_sha256"]
    ):
        raise CodeGraphError("codegraph_source_mismatch", f"runtime {name} identity differs")
    path = Path(value["resolved_path"])
    if not path.is_file() or sha256_file(path) != value["executable_sha256"]:
        raise CodeGraphError("codegraph_source_mismatch", f"runtime {name} executable bytes differ")
    return value


def validate_runtime(
    lock: dict[str, Any],
    runtime: dict[str, Any],
    checkout: Path,
    executable: Path,
    *,
    require_behavior_probe: bool = True,
) -> dict[str, Any]:
    validate_source_lock(lock)
    if not checkout.is_dir() or not (checkout / ".git").exists():
        raise CodeGraphError("codegraph_source_mismatch", "pinned checkout is missing")
    if _git(checkout, "rev-parse", "HEAD") != lock["resolved_commit"] or _git(checkout, "status", "--porcelain"):
        raise CodeGraphError("codegraph_source_mismatch", "checkout SHA differs or checkout is dirty")
    _verify_source_evidence(lock, checkout)
    if not executable.is_file():
        raise CodeGraphError("codegraph_build_failure", f"build output missing: {executable}")
    expected = {
        "schema_version": "codegraph-runtime-v1",
        "repository_url": lock["repository_url"],
        "source_commit": lock["resolved_commit"],
        "declared_version": lock["declared_version"],
        "executable_path": str(executable.resolve()),
        "executable_sha256": sha256_file(executable),
        "runtime_home": str((checkout.parent / "runtime-home").resolve()),
        "build_entrypoint": lock["build_entrypoint"],
        "install_command": lock["install_command"],
        "build_command": lock["build_command"],
        "telemetry_disabled": True,
        "telemetry_probe": runtime.get("telemetry_probe"),
        "self_update_probe": runtime.get("self_update_probe"),
        "self_update_disabled": True,
        "mcp_network_isolation": {
            "mode": "sandbox-exec-child-network-deny-v1",
            "profile_sha256": hashlib.sha256(NETWORK_DENY_PROFILE.encode()).hexdigest(),
            "verified": True,
        },
    }
    for field, value in expected.items():
        if runtime.get(field) != value:
            failure = "codegraph_version_mismatch" if field == "declared_version" else "codegraph_source_mismatch"
            raise CodeGraphError(failure, f"runtime field mismatch: {field}")
    if runtime.get("reported_version") != lock["declared_version"]:
        raise CodeGraphError("codegraph_version_mismatch", "reported version differs from source lock")
    node = _toolchain_record(lock, runtime, "node")
    npm = _toolchain_record(lock, runtime, "npm")
    if runtime.get("toolchain", {}).get("required_node_range") != lock["toolchain"]["required_node_range"]:
        raise CodeGraphError("codegraph_source_mismatch", "runtime Node range differs")
    if runtime.get("install_command") != lock["install_command"] or runtime.get("build_command") != lock["build_command"]:
        raise CodeGraphError("codegraph_source_mismatch", "runtime command vectors are not portable lock commands")
    bundle_path = _validate_file_artifact(
        runtime.get("runtime_bundle_manifest"),
        "codegraph_source_mismatch",
        "runtime bundle manifest",
    )
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    if (
        bundle.get("schema_version") != "codegraph-runtime-bundle-v1"
        or bundle.get("source_commit") != lock["resolved_commit"]
        or bundle.get("executable_sha256") != runtime["executable_sha256"]
        or bundle.get("node_executable_sha256") != node["executable_sha256"]
        or bundle.get("npm_executable_sha256") != npm["executable_sha256"]
    ):
        raise CodeGraphError("codegraph_source_mismatch", "runtime bundle identity differs")
    behavior = runtime.get("mcp_behavior_probe")
    if require_behavior_probe:
        behavior_path = _validate_file_artifact(
            behavior,
            "codegraph_source_mismatch",
            "MCP behavior probe",
        )
        behavior_value = json.loads(behavior_path.read_text(encoding="utf-8"))
        if (
            behavior_value.get("schema_version") != "codegraph-mcp-behavior-probe-v1"
            or behavior_value.get("verified") is not True
            or behavior_value.get("network_policy") != "deny"
            or behavior_value.get("direct_stdio") is not True
            or behavior_value.get("shared_daemon") is not False
            or behavior_value.get("watcher") is not False
            or behavior_value.get("catch_up_sync_may_mutate_copy") is not True
        ):
            raise CodeGraphError("codegraph_source_mismatch", "MCP behavior probe differs")
    elif behavior is not None:
        _validate_file_artifact(behavior, "codegraph_source_mismatch", "MCP behavior probe")
    _verify_probe_record(lock["telemetry"]["probe"], runtime.get("telemetry_probe"), "codegraph_telemetry_not_disabled")
    _verify_probe_record(lock["self_update"]["probe"], runtime.get("self_update_probe"), "codegraph_source_mismatch")
    if runtime.get("configuration_sha256") != sha256_value(
        {
            "serve_args": lock["serve_args"],
            "telemetry_environment": lock["telemetry"]["environment"],
            "self_update_disabled": True,
            "shared_daemon": False,
            "watcher": False,
            "catch_up_sync_scope": "attempt-copy-only",
            "mcp_network_policy": "deny",
        }
    ):
        raise CodeGraphError("codegraph_source_mismatch", "runtime configuration digest differs")
    return runtime


def source_manifest(repository: Path, excluded_names: set[str] | None = None) -> dict[str, Any]:
    root = repository.resolve()
    excluded = set(excluded_names or ()) | {".git"}
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in excluded or part == ".codegraph" or part.startswith(".codegraph-") for part in relative.parts) or not path.is_file():
            continue
        rows.append({"path": relative.as_posix(), "bytes": path.stat().st_size, "sha256": sha256_file(path)})
    return {"file_count": len(rows), "files": rows, "sha256": sha256_value(rows)}


def index_identity(lock: dict[str, Any], task_id: str, base_commit: str, configuration: dict[str, Any]) -> dict[str, Any]:
    value = {
        "codegraph_commit": lock["resolved_commit"],
        "task_id": task_id,
        "base_commit": base_commit,
        "configuration_sha256": sha256_value(configuration),
    }
    return value | {"identity_sha256": sha256_value(value)}


def parse_status(stdout: str, repository: Path) -> dict[str, Any]:
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise CodeGraphError("codegraph_status_invalid", "status output is not JSON") from exc
    required = {"initialized", "version", "projectPath", "indexPath", "lastIndexed", "fileCount", "nodeCount", "edgeCount", "index"}
    if not isinstance(value, dict) or not required.issubset(value):
        raise CodeGraphError("codegraph_status_invalid", "status JSON lacks required fields")
    if value["initialized"] is not True or Path(str(value["projectPath"])).resolve() != repository.resolve():
        raise CodeGraphError("codegraph_wrong_project", "status project root differs or is not ready")
    if not isinstance(value["index"], dict) or value["index"].get("state") != "complete":
        raise CodeGraphError("codegraph_status_invalid", "index state is not complete")
    for field in ("fileCount", "nodeCount", "edgeCount"):
        if not isinstance(value[field], int) or isinstance(value[field], bool) or value[field] < 0:
            raise CodeGraphError("codegraph_status_invalid", f"invalid graph count: {field}")
    return {
        "ready": True,
        "project_root": str(Path(value["projectPath"]).resolve()),
        "index_path": str(Path(value["indexPath"]).resolve()),
        "version": value["version"],
        "last_indexed": value["lastIndexed"],
        "file_count": value["fileCount"],
        "symbol_count": value["nodeCount"],
        "edge_count": value["edgeCount"],
        "index_state": value["index"]["state"],
        "pending_refs": value["index"].get("pendingRefs"),
        "backend": value.get("backend"),
        "journal_mode": value.get("journalMode"),
    }


def directory_size(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def directory_manifest(path: Path) -> dict[str, Any]:
    if any(item.is_symlink() for item in path.rglob("*")):
        raise CodeGraphError("codegraph_index_stale", "index artifact symlinks are not permitted")
    rows = [
        {
            "path": item.relative_to(path).as_posix(),
            "bytes": item.stat().st_size,
            "sha256": sha256_file(item),
        }
        for item in sorted(path.rglob("*"))
        if item.is_file()
    ]
    return {"file_count": len(rows), "files": rows, "sha256": sha256_value(rows)}


def runtime_bundle_manifest(
    checkout: Path,
    *,
    node_executable: Path,
    npm_executable: Path,
    executable: Path,
) -> dict[str, Any]:
    """Bind every file needed by a staged CodeGraph runtime."""
    roots = ["dist", "node_modules", "package.json", "package-lock.json"]
    rows: list[dict[str, Any]] = []
    for relative_root in roots:
        target = checkout / relative_root
        if target.is_file():
            candidates = [target]
        elif target.is_dir():
            candidates = [path for path in sorted(target.rglob("*")) if path.is_file()]
        else:
            raise CodeGraphError("codegraph_build_failure", f"runtime bundle root missing: {relative_root}")
        for path in candidates:
            if path.is_symlink():
                resolved = path.resolve()
                if not resolved.is_file():
                    raise CodeGraphError("codegraph_build_failure", f"runtime bundle symlink is invalid: {path}")
            rows.append(
                {
                    "path": path.relative_to(checkout).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    return {
        "schema_version": "codegraph-runtime-bundle-v1",
        "source_commit": _git(checkout, "rev-parse", "HEAD"),
        "roots": roots,
        "file_count": len(rows),
        "bytes": sum(row["bytes"] for row in rows),
        "files": rows,
        "manifest_sha256": sha256_value(rows),
        "executable_relative_path": executable.relative_to(checkout).as_posix(),
        "executable_sha256": sha256_file(executable),
        "node_executable_sha256": sha256_file(node_executable),
        "npm_executable_sha256": sha256_file(npm_executable),
    }


def _resolve_locked_tool(
    lock: dict[str, Any],
    name: str,
    *,
    candidates: list[Path],
) -> tuple[Path, str]:
    expected = lock["toolchain"][name]
    version_argument = "--version"
    seen: set[str] = set()
    for candidate in candidates:
        if not str(candidate) or str(candidate) in seen:
            continue
        seen.add(str(candidate))
        path = candidate.resolve()
        if not path.is_file() or sha256_file(path) != expected["executable_sha256"]:
            continue
        result = subprocess.run(
            [str(path), version_argument],
            capture_output=True,
            text=True,
            check=False,
        )
        version = (result.stdout or result.stderr).strip()
        if result.returncode == 0 and version == expected["version"]:
            return path, version
    raise CodeGraphError("codegraph_source_mismatch", f"cannot resolve locked logical tool: {name}")


def refresh_existing_runtime_provenance(
    lock: dict[str, Any],
    checkout: Path,
    runtime_record_path: Path,
) -> dict[str, Any]:
    """Portabilize an already-built runtime without installing or rebuilding it."""
    old = json.loads(runtime_record_path.read_text(encoding="utf-8"))
    old_install = old.get("install_command") or []
    legacy_npm = Path(old_install[0]) if old_install and Path(old_install[0]).is_absolute() else Path()
    legacy_node = legacy_npm.parent / "node" if str(legacy_npm) else Path()
    node_candidates = [legacy_node, Path(shutil.which("node") or "")]
    npm_candidates = [legacy_npm, Path(shutil.which("npm") or "")]
    node_path, node_version = _resolve_locked_tool(lock, "node", candidates=node_candidates)
    npm_path, npm_version = _resolve_locked_tool(lock, "npm", candidates=npm_candidates)
    executable = checkout / lock["executable_relative_path"]
    bundle = runtime_bundle_manifest(
        checkout,
        node_executable=node_path,
        npm_executable=npm_path,
        executable=executable,
    )
    provenance_root = runtime_record_path.parent / "portable-provenance"
    provenance_root.mkdir(parents=True, exist_ok=True)
    bundle_path = provenance_root / "runtime-bundle-manifest.json"
    write_json(bundle_path, bundle)
    for name, path, version in (
        ("node", node_path, node_version),
        ("npm", npm_path, npm_version),
    ):
        stdout_path = provenance_root / f"{name}-version.stdout"
        stderr_path = provenance_root / f"{name}-version.stderr"
        stdout_path.write_text(version + "\n", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        write_json(
            provenance_root / f"{name}-version.step.json",
            {
                "schema_version": "codegraph-toolchain-probe-v1",
                "logical_command": name,
                "resolved_path": str(path),
                "version": version,
                "executable_sha256": sha256_file(path),
                "return_code": 0,
                "stdout": {
                    "path": str(stdout_path),
                    "bytes": stdout_path.stat().st_size,
                    "sha256": sha256_file(stdout_path),
                },
                "stderr": {
                    "path": str(stderr_path),
                    "bytes": 0,
                    "sha256": sha256_file(stderr_path),
                },
            },
        )
    configuration_sha = sha256_value(
        {
            "serve_args": lock["serve_args"],
            "telemetry_environment": lock["telemetry"]["environment"],
            "self_update_disabled": True,
            "shared_daemon": False,
            "watcher": False,
            "catch_up_sync_scope": "attempt-copy-only",
            "mcp_network_policy": "deny",
        }
    )
    runtime = {
        **old,
        "install_command": lock["install_command"],
        "build_command": lock["build_command"],
        "toolchain": {
            "required_node_range": lock["toolchain"]["required_node_range"],
            "node": {
                "logical_command": "node",
                "resolved_path": str(node_path),
                "version": node_version,
                "executable_sha256": sha256_file(node_path),
            },
            "npm": {
                "logical_command": "npm",
                "resolved_path": str(npm_path),
                "version": npm_version,
                "executable_sha256": sha256_file(npm_path),
            },
        },
        "runtime_bundle_manifest": {
            "path": str(bundle_path),
            "bytes": bundle_path.stat().st_size,
            "sha256": sha256_file(bundle_path),
        },
        "mcp_behavior_probe": None,
        "configuration_sha256": configuration_sha,
    }
    write_json(runtime_record_path, runtime)
    return validate_runtime(
        lock,
        runtime,
        checkout,
        executable,
        require_behavior_probe=False,
    )


def _expand(arguments: list[str], repository: Path, index_dir: Path) -> list[str]:
    return [value.replace("{repository}", str(repository)).replace("{index}", str(index_dir)) for value in arguments]


def prepare_index(
    *,
    lock: dict[str, Any],
    runtime: dict[str, Any],
    task_id: str,
    base_commit: str,
    repository: Path,
    index_dir: Path,
    log_dir: Path,
    configuration: dict[str, Any],
    run_process: Any = subprocess.run,
    record_path: Path | None = None,
) -> dict[str, Any]:
    """Create one index. This function is reachable only from codegraph-prepare."""
    head = _git(repository, "rev-parse", "HEAD")
    if head != base_commit or _git(repository, "status", "--porcelain"):
        raise CodeGraphError("repository_revision_mismatch", "repository differs before indexing")
    before = source_manifest(repository, set(configuration.get("exclude_names", [])))
    identity = index_identity(lock, task_id, base_commit, configuration)
    if index_dir.exists():
        raise CodeGraphError("codegraph_index_failure", f"refusing to overwrite index: {index_dir}")
    record_path = record_path or index_dir.with_name(f"{index_dir.name}.record.json")
    attempts_root = index_dir.with_name(f"{index_dir.name}.preparation-attempts")
    attempts_root.mkdir(parents=True, exist_ok=True)
    attempt_number = len([path for path in attempts_root.iterdir() if path.is_dir()]) + 1
    attempt_root = attempts_root / f"attempt-{attempt_number:03d}"
    attempt_root.mkdir(mode=0o700)
    candidate = repository / f".codegraph-benchmark-candidate-{identity['identity_sha256'][:16]}-{attempt_number:03d}"
    if candidate.exists():
        raise CodeGraphError("codegraph_index_failure", f"stale candidate index exists: {candidate}")
    git_exclude = repository / ".git" / "info" / "exclude"
    git_exclude.parent.mkdir(parents=True, exist_ok=True)
    existing_excludes = git_exclude.read_text(encoding="utf-8") if git_exclude.exists() else ""
    if ".codegraph-benchmark-*" not in existing_excludes.splitlines():
        git_exclude.write_text(existing_excludes + "\n.codegraph-benchmark-*\n", encoding="utf-8")
    log_dir = attempt_root / "logs"
    log_dir.mkdir()
    executable = Path(runtime["executable_path"])
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C.UTF-8",
        "HOME": runtime.get("runtime_home", os.environ.get("HOME", "")),
        "NO_COLOR": "1",
        "CODEGRAPH_DIR": candidate.name,
        **lock["telemetry"]["environment"],
    }
    command = [
        "/usr/bin/sandbox-exec",
        "-p",
        NETWORK_DENY_PROFILE,
        str(executable),
        *_expand(lock["index_command"], repository, candidate),
    ]
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    stdout_path = log_dir / "index.stdout"
    stderr_path = log_dir / "index.stderr"
    try:
        result = run_process(command, capture_output=True, text=True, check=False, cwd=repository, env=environment)
    except OSError as exc:
        ended = time.monotonic()
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
        write_json(
            attempt_root / "preparation.json",
            {
                "schema_version": "codegraph-index-preparation-attempt-v1",
                "attempt_number": attempt_number,
                "identity": identity,
                "index_command": command,
                "index_return_code": None,
                "index_stdout": {"path": str(stdout_path), "sha256": sha256_file(stdout_path)},
                "index_stderr": {"path": str(stderr_path), "sha256": sha256_file(stderr_path)},
                "started_at": started_at,
                "ended_at": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": ended - started,
                "succeeded": False,
                "failure_class": "codegraph_index_failure",
            },
        )
        raise CodeGraphError(
            "codegraph_index_failure", f"index command could not start; attempt retained in {attempt_root}"
        ) from exc
    ended = time.monotonic()
    stdout_path.write_text(result.stdout or "", encoding="utf-8")
    stderr_path.write_text(result.stderr or "", encoding="utf-8")
    attempt_record: dict[str, Any] = {
        "schema_version": "codegraph-index-preparation-attempt-v1",
        "attempt_number": attempt_number,
        "identity": identity,
        "index_command": command,
        "index_return_code": result.returncode,
        "index_stdout": {"path": str(stdout_path), "sha256": sha256_file(stdout_path)},
        "index_stderr": {"path": str(stderr_path), "sha256": sha256_file(stderr_path)},
        "started_at": started_at,
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": ended - started,
        "succeeded": False,
        "failure_class": None,
    }
    if result.returncode != 0:
        if candidate.exists():
            os.replace(candidate, attempt_root / "partial-index")
        attempt_record["failure_class"] = "codegraph_index_failure"
        write_json(attempt_root / "preparation.json", attempt_record)
        raise CodeGraphError("codegraph_index_failure", f"index command returned {result.returncode}; attempt retained in {attempt_root}")
    status_command = [
        "/usr/bin/sandbox-exec",
        "-p",
        NETWORK_DENY_PROFILE,
        str(executable),
        *_expand(lock["status_command"], repository, candidate),
    ]
    status_path = log_dir / "status.stdout"
    status_stderr_path = log_dir / "status.stderr"
    try:
        status_result = run_process(
            status_command, capture_output=True, text=True, check=False, cwd=repository, env=environment
        )
    except OSError as exc:
        status_path.write_text("", encoding="utf-8")
        status_stderr_path.write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
        attempt_record.update(
            {
                "status_command": status_command,
                "status_return_code": None,
                "status_stdout": {"path": str(status_path), "sha256": sha256_file(status_path)},
                "status_stderr": {"path": str(status_stderr_path), "sha256": sha256_file(status_stderr_path)},
                "failure_class": "codegraph_status_invalid",
            }
        )
        write_json(attempt_root / "preparation.json", attempt_record)
        raise CodeGraphError(
            "codegraph_status_invalid", f"status command could not start; attempt retained in {attempt_root}"
        ) from exc
    status_path.write_text(status_result.stdout or "", encoding="utf-8")
    status_stderr_path.write_text(status_result.stderr or "", encoding="utf-8")
    attempt_record.update(
        {
            "status_command": status_command,
            "status_return_code": status_result.returncode,
            "status_stdout": {"path": str(status_path), "sha256": sha256_file(status_path)},
            "status_stderr": {"path": str(status_stderr_path), "sha256": sha256_file(status_stderr_path)},
        }
    )
    if status_result.returncode != 0:
        attempt_record["failure_class"] = "codegraph_status_invalid"
        write_json(attempt_root / "preparation.json", attempt_record)
        raise CodeGraphError("codegraph_status_invalid", f"status command returned {status_result.returncode}")
    try:
        status = parse_status(status_result.stdout or "", repository)
    except CodeGraphError as exc:
        attempt_record["failure_class"] = exc.failure_class
        write_json(attempt_root / "preparation.json", attempt_record)
        raise
    after = source_manifest(repository, set(configuration.get("exclude_names", [])))
    if after["sha256"] != before["sha256"]:
        attempt_record["failure_class"] = "codegraph_index_stale"
        write_json(attempt_root / "preparation.json", attempt_record)
        raise CodeGraphError("codegraph_index_stale", "tracked source changed while indexing")
    artifact_manifest = directory_manifest(candidate)
    if not artifact_manifest["files"]:
        attempt_record["failure_class"] = "codegraph_index_failure"
        write_json(attempt_root / "preparation.json", attempt_record)
        raise CodeGraphError("codegraph_index_failure", "index command produced no artifacts")
    index_dir.parent.mkdir(parents=True, exist_ok=True)
    os.replace(candidate, index_dir)
    status["index_path"] = str(index_dir.resolve())
    record = {
        "schema_version": "codegraph-index-v1",
        "identity": identity,
        "task_id": task_id,
        "repository_path": str(repository.resolve()),
        "requested_base_commit": base_commit,
        "verified_head": head,
        "codegraph_source_commit": lock["resolved_commit"],
        "codegraph_version": lock["declared_version"],
        "codegraph_executable_sha256": runtime["executable_sha256"],
        "index_configuration_sha256": identity["configuration_sha256"],
        "index_path": str(index_dir.resolve()),
        "started_at": started_at,
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": ended - started,
        "return_code": result.returncode,
        "stdout": {"path": str(stdout_path), "sha256": sha256_file(stdout_path)},
        "stderr": {"path": str(stderr_path), "sha256": sha256_file(stderr_path)},
        "status": status,
        "status_artifact": {"path": str(status_path), "sha256": sha256_file(status_path)},
        "index_bytes": directory_size(index_dir),
        "index_artifact_manifest": artifact_manifest,
        "source_manifest_sha256": after["sha256"],
        "source_file_count": after["file_count"],
        "ready": True,
        "frozen": True,
    }
    write_json(record_path, record)
    attempt_record.update(
        {
            "succeeded": True,
            "failure_class": None,
            "promoted_index_path": str(index_dir),
            "record_path": str(record_path),
            "index_artifact_manifest": artifact_manifest,
        }
    )
    write_json(attempt_root / "preparation.json", attempt_record)
    for path in index_dir.rglob("*"):
        try:
            path.chmod(0o500 if path.is_dir() else 0o400)
        except OSError:
            pass
    index_dir.chmod(0o500)
    return record


def validate_index(
    record: dict[str, Any],
    *,
    lock: dict[str, Any],
    runtime: dict[str, Any],
    task_id: str,
    base_commit: str,
    repository: Path,
    configuration: dict[str, Any],
) -> dict[str, Any]:
    expected_identity = index_identity(lock, task_id, base_commit, configuration)
    checks = {
        "schema_version": "codegraph-index-v1",
        "identity": expected_identity,
        "task_id": task_id,
        "repository_path": str(repository.resolve()),
        "requested_base_commit": base_commit,
        "verified_head": base_commit,
        "codegraph_source_commit": lock["resolved_commit"],
        "codegraph_version": lock["declared_version"],
        "codegraph_executable_sha256": runtime["executable_sha256"],
        "index_configuration_sha256": expected_identity["configuration_sha256"],
        "ready": True,
        "frozen": True,
    }
    for field, expected in checks.items():
        if record.get(field) != expected:
            failure = "codegraph_index_stale" if field in {"identity", "requested_base_commit", "verified_head", "source_manifest_sha256"} else "codegraph_status_invalid"
            raise CodeGraphError(failure, f"index record differs: {field}")
    if _git(repository, "rev-parse", "HEAD") != base_commit or _git(repository, "status", "--porcelain"):
        raise CodeGraphError("codegraph_index_stale", "repository revision changed after indexing")
    current = source_manifest(repository, set(configuration.get("exclude_names", [])))
    if current["sha256"] != record.get("source_manifest_sha256"):
        raise CodeGraphError("codegraph_index_stale", "source freshness proof differs")
    index_path = Path(record.get("index_path", ""))
    if not index_path.is_dir():
        raise CodeGraphError("codegraph_status_invalid", "index artifacts are missing")
    if directory_manifest(index_path) != record.get("index_artifact_manifest"):
        raise CodeGraphError("codegraph_index_stale", "index artifact additions, removals, or bytes differ")
    for path in [index_path, *index_path.rglob("*")]:
        if path.stat().st_mode & 0o222:
            raise CodeGraphError("codegraph_index_stale", f"index artifact remains writable: {path}")
    return record


def _capture_process(
    name: str,
    command: list[str],
    attempt_root: Path,
    *,
    failure_class: str,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    run_process: Any = subprocess.run,
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    def write_stream(path: Path, value: str) -> None:
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(value, encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)

    stdout_path = attempt_root / f"{name}.stdout"
    stderr_path = attempt_root / f"{name}.stderr"
    attempt_root.mkdir(parents=True, exist_ok=True)
    try:
        result = run_process(
            command,
            capture_output=True,
            text=True,
            check=False,
            cwd=cwd,
            env=env,
        )
    except OSError as exc:
        write_stream(stdout_path, "")
        write_stream(stderr_path, f"{type(exc).__name__}: {exc}\n")
        record = {
            "command": command,
            "return_code": None,
            "spawn_status": "failed",
            "failure_class": failure_class,
            "spawn_error": {"type": type(exc).__name__, "message": str(exc)},
            "stdout": {
                "path": str(stdout_path),
                "bytes": stdout_path.stat().st_size,
                "sha256": sha256_file(stdout_path),
            },
            "stderr": {
                "path": str(stderr_path),
                "bytes": stderr_path.stat().st_size,
                "sha256": sha256_file(stderr_path),
            },
        }
        write_json(attempt_root / f"{name}.step.json", record)
        raise CodeGraphError(failure_class, f"{name} process spawn failed; evidence retained in {attempt_root}") from exc
    write_stream(stdout_path, result.stdout or "")
    write_stream(stderr_path, result.stderr or "")
    record = {
        "command": command,
        "return_code": result.returncode,
        "spawn_status": "completed",
        "failure_class": None,
        "spawn_error": None,
        "stdout": {
            "path": str(stdout_path),
            "bytes": stdout_path.stat().st_size,
            "sha256": sha256_file(stdout_path),
        },
        "stderr": {
            "path": str(stderr_path),
            "bytes": stderr_path.stat().st_size,
            "sha256": sha256_file(stderr_path),
        },
    }
    write_json(attempt_root / f"{name}.step.json", record)
    return result, record


def _semantic_status(status: dict[str, Any]) -> dict[str, Any]:
    return {
        key: status.get(key)
        for key in (
            "ready",
            "version",
            "file_count",
            "symbol_count",
            "edge_count",
            "index_state",
            "pending_refs",
            "backend",
            "journal_mode",
        )
    }


def stage_runtime_bundle(
    *,
    runtime: dict[str, Any],
    checkout: Path,
    stage_root: Path,
) -> dict[str, Any]:
    """Copy the hash-bound runtime and Node binary into one isolated attempt."""
    if stage_root.exists():
        raise CodeGraphError("codegraph_source_mismatch", f"runtime stage already exists: {stage_root}")
    manifest_path = _validate_file_artifact(
        runtime.get("runtime_bundle_manifest"),
        "codegraph_source_mismatch",
        "runtime bundle manifest",
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = manifest.get("files")
    if not isinstance(rows, list) or manifest.get("manifest_sha256") != sha256_value(rows):
        raise CodeGraphError("codegraph_source_mismatch", "runtime bundle manifest rows differ")
    stage_root.mkdir(parents=True, mode=0o700)
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"path", "bytes", "sha256"}
            or not SHA256.fullmatch(str(row.get("sha256")))
        ):
            raise CodeGraphError("codegraph_source_mismatch", "runtime bundle row is malformed")
        source = checkout / row["path"]
        destination = stage_root / row["path"]
        if (
            not source.is_file()
            or source.stat().st_size != row["bytes"]
            or sha256_file(source) != row["sha256"]
        ):
            raise CodeGraphError("codegraph_source_mismatch", f"runtime source differs: {row['path']}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination, follow_symlinks=True)
        if destination.stat().st_size != row["bytes"] or sha256_file(destination) != row["sha256"]:
            raise CodeGraphError("codegraph_source_mismatch", f"runtime stage differs: {row['path']}")
    node_source = Path(runtime["toolchain"]["node"]["resolved_path"])
    node_destination = stage_root / "bin" / "node"
    node_destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(node_source, node_destination)
    node_destination.chmod(0o500)
    if sha256_file(node_destination) != runtime["toolchain"]["node"]["executable_sha256"]:
        raise CodeGraphError("codegraph_source_mismatch", "staged Node bytes differ")
    executable = stage_root / manifest["executable_relative_path"]
    if not executable.is_file() or sha256_file(executable) != runtime["executable_sha256"]:
        raise CodeGraphError("codegraph_source_mismatch", "staged CodeGraph executable differs")
    staged_rows = [
        {
            "path": row["path"],
            "bytes": (stage_root / row["path"]).stat().st_size,
            "sha256": sha256_file(stage_root / row["path"]),
        }
        for row in rows
    ]
    if staged_rows != rows:
        raise CodeGraphError("codegraph_source_mismatch", "staged runtime manifest differs")
    for path in [stage_root, *stage_root.rglob("*")]:
        path.chmod(0o500 if path.is_dir() else 0o400)
    node_destination.chmod(0o500)
    return {
        "stage_root": str(stage_root),
        "node_executable": str(node_destination),
        "codegraph_executable": str(executable),
        "runtime_bundle_manifest_sha256": manifest["manifest_sha256"],
        "node_executable_sha256": sha256_file(node_destination),
        "codegraph_executable_sha256": sha256_file(executable),
    }


def _all_read_only(path: Path) -> bool:
    return all(not (candidate.stat().st_mode & 0o222) for candidate in [path, *path.rglob("*")])


@contextmanager
def attempt_index_copy(
    *,
    record: dict[str, Any],
    lock: dict[str, Any],
    master_repository: Path,
    child_repository: Path,
    attempt_root: Path,
    evidence_root: Path,
    runtime_stage: dict[str, Any],
    run_process: Any = subprocess.run,
) -> Iterator[dict[str, Any]]:
    """Serve only a fresh writable copy and always remove it in ``finally``."""
    if master_repository.resolve() != Path(record["repository_path"]).resolve():
        raise CodeGraphError(
            "codegraph_index_stale",
            "frozen index repository binding differs before attempt copy",
        )
    master = Path(record["index_path"])
    master_before = directory_manifest(master)
    if master_before != record["index_artifact_manifest"] or not _all_read_only(master):
        raise CodeGraphError("codegraph_index_stale", "frozen master bytes or modes differ before copy")
    identity = record["identity"]["identity_sha256"]
    suffix = hashlib.sha256(str(attempt_root.resolve()).encode()).hexdigest()[:12]
    directory_name = f".codegraph-attempt-{identity[:12]}-{suffix}"
    copy_path = child_repository / directory_name
    if copy_path.exists():
        raise CodeGraphError("codegraph_index_stale", f"attempt index copy already exists: {copy_path}")
    lifecycle: dict[str, Any] = {
        "schema_version": "codegraph-attempt-index-lifecycle-v1",
        "task_id": record["task_id"],
        "identity": record["identity"],
        "started_at": datetime.now(timezone.utc).isoformat(),
        "master_path": str(master),
        "master_manifest_before": master_before,
        "master_read_only_before": True,
        "copy_path": str(copy_path),
        "codegraph_directory_name": directory_name,
        "runtime_stage": runtime_stage,
        "network_policy": "deny",
        "catch_up_sync_may_mutate_copy": True,
        "prepared": False,
        "cleanup_complete": False,
        "failure_class": None,
    }
    evidence_root.mkdir(parents=True, exist_ok=True)
    environment = {
        "PATH": str(Path(runtime_stage["node_executable"]).parent),
        "LANG": "C.UTF-8",
        "HOME": str((attempt_root / "codegraph-home").resolve()),
        "NO_COLOR": "1",
        "CODEGRAPH_DIR": directory_name,
        **lock["telemetry"]["environment"],
    }
    validate_control_environment(environment)
    (attempt_root / "codegraph-home").mkdir(parents=True, mode=0o700, exist_ok=True)
    cleanup_error: Exception | None = None
    try:
        shutil.copytree(master, copy_path)
        copy_path.chmod(0o700)
        for path in copy_path.rglob("*"):
            path.chmod(0o700 if path.is_dir() else 0o600)
        copy_initial = directory_manifest(copy_path)
        lifecycle["copy_manifest_initial"] = copy_initial
        if copy_initial != master_before:
            raise CodeGraphError("codegraph_index_stale", "attempt copy bytes differ from frozen master")
        status_command = [
            "/usr/bin/sandbox-exec",
            "-p",
            NETWORK_DENY_PROFILE,
            runtime_stage["node_executable"],
            runtime_stage["codegraph_executable"],
            *_expand(lock["status_command"], child_repository, copy_path),
        ]
        status_result, status_artifacts = _capture_process(
            "pre-serve-status",
            status_command,
            evidence_root,
            failure_class="codegraph_status_invalid",
            cwd=child_repository,
            env=environment,
            run_process=run_process,
        )
        if status_result.returncode:
            raise CodeGraphError(
                "codegraph_status_invalid",
                f"attempt-copy status returned {status_result.returncode}",
            )
        pre_status = parse_status(status_result.stdout or "", child_repository)
        if _semantic_status(pre_status) != _semantic_status(record["status"]):
            raise CodeGraphError("codegraph_index_stale", "attempt-copy semantic status differs")
        lifecycle.update(
            {
                "prepared": True,
                "pre_serve_status": pre_status,
                "pre_serve_status_artifacts": status_artifacts,
                "serve_args": ["serve", "--mcp", "--path", str(child_repository), "--no-watch"],
                "environment": {
                    key: environment[key]
                    for key in sorted(
                        {*REQUIRED_CONTROL_ENVIRONMENT, "CODEGRAPH_DIR", "CODEGRAPH_MCP_TOOLS"}
                    )
                    if key in environment
                },
            }
        )
        yield {
            "index_path": copy_path,
            "codegraph_directory_name": directory_name,
            "environment": environment,
            "serve_args": lifecycle["serve_args"],
            "launcher": [
                runtime_stage["node_executable"],
                runtime_stage["codegraph_executable"],
            ],
            "evidence_path": evidence_root / "lifecycle.json",
        }
    except Exception as exc:
        lifecycle["failure_class"] = (
            exc.failure_class if isinstance(exc, CodeGraphError) else type(exc).__name__
        )
        raise
    finally:
        try:
            if copy_path.exists():
                lifecycle["copy_manifest_post_attempt"] = directory_manifest(copy_path)
                lifecycle["copy_changed_during_attempt"] = (
                    lifecycle.get("copy_manifest_post_attempt")
                    != lifecycle.get("copy_manifest_initial")
                )
        except Exception as exc:
            cleanup_error = exc
            lifecycle["cleanup_capture_error"] = f"{type(exc).__name__}: {exc}"
        try:
            if copy_path.exists():
                shutil.rmtree(copy_path)
        except Exception as exc:
            cleanup_error = cleanup_error or exc
            lifecycle["cleanup_remove_error"] = f"{type(exc).__name__}: {exc}"
        try:
            master_after = directory_manifest(master)
            lifecycle["master_manifest_after"] = master_after
            lifecycle["master_read_only_after"] = _all_read_only(master)
            lifecycle["master_unchanged"] = (
                master_after == master_before and lifecycle["master_read_only_after"]
            )
            if not lifecycle["master_unchanged"]:
                cleanup_error = cleanup_error or CodeGraphError(
                    "codegraph_index_stale", "frozen master changed during attempt"
                )
        except Exception as exc:
            cleanup_error = cleanup_error or exc
            lifecycle["master_validation_error"] = f"{type(exc).__name__}: {exc}"
        lifecycle["cleanup_complete"] = not copy_path.exists()
        lifecycle["ended_at"] = datetime.now(timezone.utc).isoformat()
        write_json(evidence_root / "lifecycle.json", lifecycle)
        if not lifecycle["cleanup_complete"] or cleanup_error is not None:
            raise CodeGraphError(
                "codegraph_index_stale",
                f"attempt index cleanup or master validation failed: {cleanup_error}",
            )


def _probe(
    name: str,
    executable: Path,
    contract: dict[str, Any],
    checkout: Path,
    attempt_root: Path,
    environment: dict[str, str],
    failure_class: str,
) -> dict[str, Any]:
    command = ["/usr/bin/sandbox-exec", "-p", NETWORK_DENY_PROFILE, str(executable), *contract["command"]]
    result, artifact = _capture_process(
        name,
        command,
        attempt_root,
        failure_class=failure_class,
        cwd=checkout,
        env=environment,
    )
    probe = {
        "command": contract["command"],
        "return_code": result.returncode,
        "stdout": artifact["stdout"],
        "stderr": artifact["stderr"],
        "network_policy": "deny",
        "verified": bool(
            result.returncode == contract["expected_return_code"]
            and artifact["stdout"]["sha256"] == contract["expected_stdout_sha256"]
            and artifact["stderr"]["sha256"] == contract["expected_stderr_sha256"]
        ),
    }
    return probe


def prepare_runtime_from_lock(lock: dict[str, Any], checkout: Path, runtime_record_path: Path) -> dict[str, Any]:
    """Build from a resolved lock while retaining every setup process artifact."""
    validate_source_lock(lock)
    checkout.parent.mkdir(parents=True, exist_ok=True)
    attempts_root = runtime_record_path.parent / "preparation-attempts"
    attempts_root.mkdir(parents=True, exist_ok=True)
    attempt_number = len([path for path in attempts_root.iterdir() if path.is_dir()]) + 1
    attempt_root = attempts_root / f"attempt-{attempt_number:03d}"
    attempt_root.mkdir(mode=0o700)
    preparation: dict[str, Any] = {
        "schema_version": "codegraph-runtime-preparation-attempt-v1",
        "attempt_number": attempt_number,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "steps": {},
        "succeeded": False,
        "failure_class": None,
    }
    npm_userconfig = checkout.parent / "npm-userconfig"
    if not npm_userconfig.exists():
        npm_userconfig.write_text("# benchmark-local empty npm user config\n", encoding="utf-8")
    runtime_home = checkout.parent / "runtime-home"
    runtime_home.mkdir(parents=True, exist_ok=True)
    node_path, node_version = _resolve_locked_tool(
        lock,
        "node",
        candidates=[Path(shutil.which("node") or "")],
    )
    npm_path, npm_version = _resolve_locked_tool(
        lock,
        "npm",
        candidates=[Path(shutil.which("npm") or "")],
    )
    tool_path = os.pathsep.join(
        dict.fromkeys(
            [str(node_path.parent), str(npm_path.parent), os.environ.get("PATH", "")]
        )
    )
    environment = {
        "PATH": tool_path,
        "LANG": "C.UTF-8",
        "HOME": str(runtime_home.resolve()),
        "NO_COLOR": "1",
        "NPM_CONFIG_USERCONFIG": str(npm_userconfig.resolve()),
        "NPM_CONFIG_CACHE": str((checkout.parent / "npm-cache").resolve()),
        **lock["telemetry"]["environment"],
    }
    try:
        if not checkout.exists():
            clone, preparation["steps"]["clone"] = _capture_process(
                "clone",
                ["git", "clone", "--no-checkout", lock["repository_url"], str(checkout)],
                attempt_root,
                failure_class="codegraph_build_failure",
            )
            if clone.returncode:
                raise CodeGraphError("codegraph_build_failure", clone.stderr.strip() or "clone failed")
            checked, preparation["steps"]["checkout"] = _capture_process(
                "checkout",
                ["git", "-C", str(checkout), "checkout", "--detach", lock["resolved_commit"]],
                attempt_root,
                failure_class="codegraph_source_mismatch",
            )
            if checked.returncode:
                raise CodeGraphError("codegraph_source_mismatch", checked.stderr.strip() or "checkout failed")
        else:
            preparation["steps"]["clone"] = {
                "reused_locked_bootstrap": True,
                "repository_url": lock["repository_url"],
                "source_commit": lock["resolved_commit"],
            }
        head, preparation["steps"]["head"] = _capture_process(
            "head",
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            attempt_root,
            failure_class="codegraph_source_mismatch",
        )
        status, preparation["steps"]["status"] = _capture_process(
            "status",
            ["git", "-C", str(checkout), "status", "--porcelain"],
            attempt_root,
            failure_class="codegraph_source_mismatch",
        )
        if head.returncode or head.stdout.strip() != lock["resolved_commit"] or status.returncode or status.stdout:
            raise CodeGraphError("codegraph_source_mismatch", "fresh checkout SHA/status differs")
        _verify_source_evidence(lock, checkout)
        install, preparation["steps"]["install"] = _capture_process(
            "install",
            lock["install_command"],
            attempt_root,
            failure_class="codegraph_build_failure",
            cwd=checkout,
            env=environment,
        )
        if install.returncode:
            raise CodeGraphError("codegraph_build_failure", install.stderr.strip() or "lockfile install failed")
        build, preparation["steps"]["build"] = _capture_process(
            "build",
            lock["build_command"],
            attempt_root,
            failure_class="codegraph_build_failure",
            cwd=checkout,
            env=environment,
        )
        if build.returncode:
            raise CodeGraphError("codegraph_build_failure", build.stderr.strip() or "build failed")
        executable = checkout / lock["executable_relative_path"]
        if not executable.is_file():
            raise CodeGraphError("codegraph_build_failure", "declared executable was not produced")
        version, preparation["steps"]["version"] = _capture_process(
            "version",
            [str(executable), *lock["version_command"]],
            attempt_root,
            failure_class="codegraph_version_mismatch",
            cwd=checkout,
            env=environment,
        )
        if version.returncode or version.stdout.strip() != lock["declared_version"]:
            raise CodeGraphError("codegraph_version_mismatch", "runtime version command differs")
        telemetry_probe = _probe(
            "telemetry-probe",
            executable,
            lock["telemetry"]["probe"],
            checkout,
            attempt_root,
            environment,
            "codegraph_telemetry_not_disabled",
        )
        self_update_probe = _probe(
            "self-update-probe",
            executable,
            lock["self_update"]["probe"],
            checkout,
            attempt_root,
            environment,
            "codegraph_source_mismatch",
        )
        if not telemetry_probe["verified"]:
            raise CodeGraphError("codegraph_telemetry_not_disabled", "telemetry runtime probe differs")
        if not self_update_probe["verified"]:
            raise CodeGraphError("codegraph_source_mismatch", "self-update runtime probe differs")
        bundle = runtime_bundle_manifest(
            checkout,
            node_executable=node_path,
            npm_executable=npm_path,
            executable=executable,
        )
        bundle_path = attempt_root / "runtime-bundle-manifest.json"
        write_json(bundle_path, bundle)
        configuration_sha = sha256_value(
            {
                "serve_args": lock["serve_args"],
                "telemetry_environment": lock["telemetry"]["environment"],
                "self_update_disabled": True,
                "shared_daemon": False,
                "watcher": False,
                "catch_up_sync_scope": "attempt-copy-only",
                "mcp_network_policy": "deny",
            }
        )
        runtime = {
            "schema_version": "codegraph-runtime-v1",
            "repository_url": lock["repository_url"],
            "source_commit": lock["resolved_commit"],
            "declared_version": lock["declared_version"],
            "reported_version": version.stdout.strip(),
            "executable_path": str(executable.resolve()),
            "executable_sha256": sha256_file(executable),
            "runtime_home": str(runtime_home.resolve()),
            "build_entrypoint": lock["build_entrypoint"],
            "install_command": lock["install_command"],
            "build_command": lock["build_command"],
            "toolchain": {
                "required_node_range": lock["toolchain"]["required_node_range"],
                "node": {
                    "logical_command": "node",
                    "resolved_path": str(node_path),
                    "version": node_version,
                    "executable_sha256": sha256_file(node_path),
                },
                "npm": {
                    "logical_command": "npm",
                    "resolved_path": str(npm_path),
                    "version": npm_version,
                    "executable_sha256": sha256_file(npm_path),
                },
            },
            "runtime_bundle_manifest": {
                "path": str(bundle_path),
                "bytes": bundle_path.stat().st_size,
                "sha256": sha256_file(bundle_path),
            },
            "mcp_behavior_probe": None,
            "telemetry_disabled": True,
            "telemetry_probe": telemetry_probe,
            "self_update_probe": self_update_probe,
            "self_update_disabled": True,
            "mcp_network_isolation": {
                "mode": "sandbox-exec-child-network-deny-v1",
                "profile_sha256": hashlib.sha256(NETWORK_DENY_PROFILE.encode()).hexdigest(),
                "verified": True,
            },
            "configuration_sha256": configuration_sha,
            "built_at": datetime.now(timezone.utc).isoformat(),
            "preparation_attempt": str(attempt_root),
        }
        preparation["succeeded"] = True
        preparation["runtime_record_sha256"] = sha256_value(runtime)
        write_json(runtime_record_path, runtime)
        return validate_runtime(
            lock,
            runtime,
            checkout,
            executable,
            require_behavior_probe=False,
        )
    except CodeGraphError as exc:
        preparation["failure_class"] = exc.failure_class
        raise
    finally:
        preparation["ended_at"] = datetime.now(timezone.utc).isoformat()
        write_json(attempt_root / "preparation.json", preparation)


def validate_frozen_index_status(
    record: dict[str, Any],
    *,
    lock: dict[str, Any],
    runtime: dict[str, Any],
    repository: Path,
    validation_root: Path,
    run_process: Any = subprocess.run,
) -> dict[str, Any]:
    """Run upstream status against frozen bytes and prove it did not mutate them."""
    index_path = Path(record["index_path"])
    before = directory_manifest(index_path)
    copy_path = repository / f".codegraph-benchmark-validation-{record['identity']['identity_sha256'][:16]}"
    if copy_path.exists():
        raise CodeGraphError("codegraph_index_stale", f"stale validation copy exists: {copy_path}")
    copy_validation_root = validation_root / "copy-validation"
    validation: dict[str, Any] = {
        "schema_version": "codegraph-read-only-validation-v1",
        "task_id": record["task_id"],
        "validated_at": datetime.now(timezone.utc).isoformat(),
        "validation_mode": "ephemeral-writable-copy-of-read-only-master",
        "frozen_master_read_only": _all_read_only(index_path),
        "network_policy": "deny",
        "catch_up_sync_may_mutate_attempt_copy": True,
    }
    primary_error: Exception | None = None
    try:
        if before != record["index_artifact_manifest"] or not validation["frozen_master_read_only"]:
            raise CodeGraphError("codegraph_index_stale", "frozen master differs before validation")
        shutil.copytree(index_path, copy_path)
        copy_path.chmod(0o700)
        for path in copy_path.rglob("*"):
            path.chmod(0o700 if path.is_dir() else 0o600)
        copy_before = directory_manifest(copy_path)
        validation["copy_manifest_before_status"] = copy_before
        if copy_before != before:
            raise CodeGraphError("codegraph_index_stale", "validation copy differs from frozen master")
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "LANG": "C.UTF-8",
            "HOME": runtime["runtime_home"],
            "NO_COLOR": "1",
            "CODEGRAPH_DIR": copy_path.name,
            **lock["telemetry"]["environment"],
        }
        validate_control_environment(environment)
        command = [
            "/usr/bin/sandbox-exec",
            "-p",
            NETWORK_DENY_PROFILE,
            runtime["executable_path"],
            *_expand(lock["status_command"], repository, copy_path),
        ]
        result, artifacts = _capture_process(
            "status-copy",
            command,
            copy_validation_root,
            failure_class="codegraph_status_invalid",
            cwd=repository,
            env=environment,
            run_process=run_process,
        )
        validation.update(
            {
                "command": command,
                "return_code": result.returncode,
                "stdout": artifacts["stdout"],
                "stderr": artifacts["stderr"],
            }
        )
        if result.returncode:
            raise CodeGraphError("codegraph_status_invalid", f"read-only status returned {result.returncode}")
        status = parse_status(result.stdout or "", repository)
        if _semantic_status(status) != _semantic_status(record["status"]):
            raise CodeGraphError("codegraph_index_stale", "read-only semantic status differs")
        validation["status"] = status
        validation["copy_manifest_after_status"] = directory_manifest(copy_path)
        after = directory_manifest(index_path)
        if after != before:
            raise CodeGraphError("codegraph_index_stale", "status against copy mutated frozen master bytes")
        validation["index_artifact_manifest_sha256"] = after["sha256"]
    except Exception as exc:
        primary_error = exc
        validation["failure_class"] = (
            exc.failure_class if isinstance(exc, CodeGraphError) else type(exc).__name__
        )
    finally:
        cleanup_error: Exception | None = None
        try:
            if copy_path.exists():
                shutil.rmtree(copy_path)
        except Exception as exc:
            cleanup_error = exc
        validation["validation_copy_removed"] = not copy_path.exists()
        try:
            master_after_cleanup = directory_manifest(index_path)
            validation["master_unchanged_after_cleanup"] = (
                master_after_cleanup == before and _all_read_only(index_path)
            )
        except Exception as exc:
            cleanup_error = cleanup_error or exc
            validation["master_unchanged_after_cleanup"] = False
        validation["completed_at"] = datetime.now(timezone.utc).isoformat()
        if cleanup_error is not None:
            validation["cleanup_error"] = f"{type(cleanup_error).__name__}: {cleanup_error}"
        write_json(copy_validation_root / "validation.json", validation)
        if cleanup_error is not None or not validation["validation_copy_removed"]:
            raise CodeGraphError(
                "codegraph_index_stale",
                f"validation copy cleanup failed: {cleanup_error}",
            )
    if primary_error is not None:
        raise primary_error
    return validation
