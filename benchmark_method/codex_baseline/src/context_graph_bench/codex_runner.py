"""Pinned Codex child invocation, ephemeral state, prompt, and response checks."""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any

from .telemetry import parse_events, duration_seconds


class RunnerError(RuntimeError):
    """Raised for a local runtime contract failure before a paid call."""


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_runtime_config(config: dict[str, Any]) -> None:
    baseline = config.get("baseline", config)
    if baseline.get("model") != "gpt-5.6-luna":
        raise RunnerError("configuration_error: requested model must be gpt-5.6-luna")
    if baseline.get("reasoning_effort") != "high":
        raise RunnerError("configuration_error: requested reasoning effort must be high")
    if baseline.get("arm") != "codex-baseline":
        raise RunnerError("configuration_error: arm must be codex-baseline")
    if baseline.get("protocol") != "direct-region-v1":
        raise RunnerError("configuration_error: protocol must be direct-region-v1")


def resolve_executable(config: dict[str, Any]) -> Path:
    value = config["paths"].get("codex_executable")
    path = Path(value) if value else Path(shutil.which("codex") or "")
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RunnerError(f"configuration_error: Codex executable is not runnable: {path}")
    resolved = path.resolve()
    if resolved.suffix == ".js":
        native = resolved.parent.parent / "node_modules" / "@openai" / "codex-darwin-arm64" / "vendor" / "aarch64-apple-darwin" / "bin" / "codex"
        if native.is_file() and os.access(native, os.X_OK):
            return native.resolve()
    return resolved


def codex_version(executable: Path) -> str:
    result = subprocess.run([str(executable), "--version"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RunnerError(f"process_failure: Codex version probe failed: {result.stderr.strip()}")
    for token in (result.stdout + "\n" + result.stderr).split():
        if re.fullmatch(r"\d+\.\d+\.\d+(?:[-.][0-9A-Za-z.]+)?", token):
            return token
    raise RunnerError("configuration_error: Codex version output did not contain a version")


def verify_pinned_version(executable: Path, expected: str) -> str:
    actual = codex_version(executable)
    if actual != expected:
        raise RunnerError(f"configuration_error: Codex CLI version drift: expected {expected}, got {actual}")
    return actual


def child_environment(executable: Path) -> dict[str, str]:
    """Keep the pinned Codex installation first when its script resolves node."""
    for parent in executable.resolve().parents:
        if parent.name.startswith("v") and (parent / "bin" / "node").is_file():
            current = os.environ.get("PATH", "")
            return {"PATH": f"{parent / 'bin'}:{current}"}
    return {"PATH": os.environ.get("PATH", "")}


def validate_auth_source(path: Path) -> None:
    try:
        st = path.stat()
    except OSError as exc:
        raise RunnerError(f"missing_auth: authentication source is unavailable: {path}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise RunnerError("missing_auth: authentication source is not a regular file")
    if st.st_uid != os.getuid():
        raise RunnerError("missing_auth: authentication source is not user-owned")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise RunnerError("configuration_error: authentication source permissions are not restrictive")


def create_state_dir(work_root: Path, auth_source: Path) -> Path:
    """Create an ephemeral Codex home linked to the existing login."""
    private_home, _output_dir = create_runtime_dirs(work_root, auth_source)
    return private_home


def create_runtime_dirs(work_root: Path, auth_source: Path) -> tuple[Path, Path]:
    """Create ephemeral Codex runtime and attempt-output directories.

    The credential is copied into the private home so the child never receives
    a symlink back into the parent's Codex state.
    """
    validate_auth_source(auth_source)
    work_root.mkdir(parents=True, exist_ok=True)
    private_home = Path(tempfile.mkdtemp(prefix="codex-private-", dir=work_root))
    output_dir = Path(tempfile.mkdtemp(prefix="codex-attempt-", dir=work_root))
    os.chmod(private_home, 0o700)
    os.chmod(output_dir, 0o700)
    shutil.copyfile(auth_source, private_home / "auth.json")
    os.chmod(private_home / "auth.json", 0o600)
    return private_home, output_dir


def _safe_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RunnerError(result.stderr.strip() or f"git failed: {' '.join(args)}")
    return result.stdout.strip()


def prepare_isolated_repository(
    source_repository: Path,
    base_commit: str,
    isolation_root: Path,
    task_id: str,
    attempt_key: str,
) -> dict[str, Any]:
    """Make a task-only Git clone and a fresh child worktree.

    The clone uses ``--no-local`` so its object database cannot be an
    alternates view of the parent's prepared repository.  The child receives
    only the returned worktree and this task's clone metadata.
    """
    source_repository = source_repository.resolve()
    mirror = isolation_root / "repositories" / _safe_component(task_id)
    worktree = isolation_root / "worktrees" / _safe_component(task_id) / _safe_component(attempt_key)
    mirror.parent.mkdir(parents=True, exist_ok=True)
    worktree.parent.mkdir(parents=True, exist_ok=True)
    if not mirror.exists():
        result = subprocess.run(
            ["git", "clone", "--no-local", "--no-checkout", str(source_repository), str(mirror)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RunnerError(f"repository_snapshot_failure: clone failed: {result.stderr.strip()}")
        _git(mirror, "checkout", "--detach", base_commit)
    head = _git(mirror, "rev-parse", "HEAD")
    status = _git(mirror, "status", "--porcelain")
    if head != base_commit or status:
        raise RunnerError(f"repository_snapshot_failure: task clone is not clean at {base_commit}")
    added = subprocess.run(
        ["git", "-C", str(mirror), "worktree", "add", "--detach", str(worktree), base_commit],
        capture_output=True,
        text=True,
        check=False,
    )
    if added.returncode != 0:
        raise RunnerError(f"repository_snapshot_failure: worktree failed: {added.stderr.strip()}")
    child_head = _git(worktree, "rev-parse", "HEAD")
    child_status = _git(worktree, "status", "--porcelain")
    if child_head != base_commit or child_status:
        raise RunnerError(f"repository_snapshot_failure: child worktree is not clean at {base_commit}")
    return {
        "path": str(worktree),
        "mirror_path": str(mirror),
        "head": child_head,
        "clean": not bool(child_status),
        "clone_mode": "git-clone-no-local",
        "worktree_mode": "git-worktree-detach",
    }


def remove_isolated_repository(snapshot: dict[str, Any]) -> None:
    worktree = Path(snapshot["path"])
    mirror = Path(snapshot["mirror_path"])
    if worktree.exists() and mirror.exists():
        subprocess.run(
            ["git", "-C", str(mirror), "worktree", "remove", "--force", str(worktree)],
            capture_output=True,
            text=True,
            check=False,
        )
    shutil.rmtree(worktree, ignore_errors=True)


def _profile_literal(path: Path | str) -> str:
    value = str(path)
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def sandbox_profile(
    executable: Path,
    repository: Path,
    codex_home: Path,
    state_dir: Path,
    forbidden_paths: list[Path] | None = None,
) -> str:
    """Return the macOS explicit-deny profile for one child.

    macOS rejects ``deny default`` profiles from this host's managed process
    context.  ``allow default`` plus explicit deny rules is supported and is
    enforced by the kernel; the benchmark denies the entire parent Documents
    tree, Codex state, and all caller-supplied benchmark paths.
    """
    runtime_tmp = state_dir / "tmp"
    runtime_tmp.mkdir(parents=True, exist_ok=True)
    denied = [
        Path("/Users/aiswarya/Documents"),
        Path("/Users/aiswarya/.codex"),
        Path("/Users/aiswarya/.ssh"),
        Path("/Users/aiswarya/.config"),
        Path("/Users/aiswarya/.npm"),
        Path("/Users/aiswarya/.cache"),
        *list(forbidden_paths or []),
    ]
    unique_denied: list[Path] = []
    seen: set[str] = set()
    for path in denied:
        resolved = str(path.resolve())
        if resolved not in seen and resolved not in {str(repository.resolve()), str(codex_home.resolve()), str(state_dir.resolve())}:
            seen.add(resolved)
            unique_denied.append(Path(resolved))
    deny_read_rules = " ".join(f"(subpath {_profile_literal(path)})" for path in unique_denied)
    deny_write_rules = "(subpath \"/Users/aiswarya\") (subpath " + _profile_literal(repository) + ") " + " ".join(f"(subpath {_profile_literal(path)})" for path in unique_denied)
    return " ".join(
        [
            "(version 1)",
            "(allow default)",
            "(deny file-read* " + deny_read_rules + ")",
            "(deny file-write* " + deny_write_rules + ")",
        ]
    )


def build_prompt(template: str, problem_statement: str) -> str:
    if "ground_truth" in template.lower() or "ground truth" in template.lower():
        raise RunnerError("configuration_error: region prompt contains ground-truth language")
    prompt = template.replace("{{problem_statement}}", problem_statement)
    prompt += (
        "\n\nHard benchmark boundary: do not use web search, browser retrieval, "
        "remote URL fetching, GitHub issue or pull-request lookup, remote source "
        "lookup, or benchmark dataset lookup. Use only the supplied issue and "
        "the local repository checkout."
    )
    return prompt


def build_command(
    executable: Path,
    config: dict[str, Any],
    state_dir: Path,
    schema_path: Path,
    repo_path: Path,
) -> list[str]:
    baseline = config["baseline"]
    validate_runtime_config(config)
    args = [
        str(executable),
        "exec",
        "--ephemeral",
        "--json",
        "--output-last-message",
        str(state_dir / "response.json"),
        "--output-schema",
        str(state_dir / "agent-regions.schema.json"),
        "--model",
        baseline["model"],
        "-c",
        f"model_reasoning_effort={baseline['reasoning_effort']}",
        "--sandbox",
        "danger-full-access",
        "--add-dir",
        str(state_dir),
        "--add-dir",
        str(repo_path),
        "--disable",
        "browser_use",
        "--disable",
        "browser_use_external",
        "--disable",
        "browser_use_full_cdp_access",
        "--disable",
        "in_app_browser",
        "--disable",
        "computer_use",
        "--disable",
        "standalone_web_search",
        "-c",
        'web_search="disabled"',
        "--disable",
        "plugins",
        "--disable",
        "remote_plugin",
        "--disable",
        "plugin_sharing",
        "--disable",
        "apps",
        "--enable",
        "shell_tool",
        "--ignore-user-config",
        "--ignore-rules",
        "--color",
        "never",
        "-C",
        str(repo_path),
        "-",
    ]
    if "--model" not in args or "gpt-5.6-luna" not in args or "model_reasoning_effort=high" not in args:
        raise RunnerError("configuration_error: constructed invocation does not request pinned model and effort")
    return args


def validate_regions(response: Any, repo_path: Path, max_regions: int = 5) -> list[dict[str, Any]]:
    if not isinstance(response, dict) or set(response) != {"regions"}:
        raise RunnerError("invalid_response_schema: response must contain exactly regions")
    regions = response["regions"]
    if not isinstance(regions, list) or not 1 <= len(regions) <= max_regions:
        raise RunnerError("invalid_response_schema: regions must contain one to five items")
    root = repo_path.resolve()
    seen: set[tuple[str, int, int]] = set()
    validated: list[dict[str, Any]] = []
    for region in regions:
        if not isinstance(region, dict) or set(region) != {"path", "start", "end", "reason"}:
            raise RunnerError("invalid_response_schema: region fields are not exact")
        path = region["path"]
        start = region["start"]
        end = region["end"]
        reason = region["reason"]
        if not isinstance(path, str) or not path or "\\" in path:
            raise RunnerError("invalid_source_region: path is not normalized")
        pure = PurePosixPath(path)
        if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
            raise RunnerError("invalid_source_region: path must be normalized and repository-relative")
        if not isinstance(start, int) or isinstance(start, bool) or not isinstance(end, int) or isinstance(end, bool):
            raise RunnerError("invalid_source_region: bounds must be integers")
        if start < 1 or end < start:
            raise RunnerError("invalid_source_region: line range is invalid")
        if not isinstance(reason, str) or not reason.strip():
            raise RunnerError("invalid_response_schema: reason must be non-empty")
        key = (path, start, end)
        if key in seen:
            raise RunnerError("invalid_response_schema: exact duplicate region")
        seen.add(key)
        candidate = root.joinpath(*pure.parts)
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise RunnerError("invalid_source_region: file does not exist") from exc
        if root != resolved and root not in resolved.parents:
            raise RunnerError("invalid_source_region: symlink escapes repository")
        if not resolved.is_file():
            raise RunnerError("invalid_source_region: path is not a regular file")
        try:
            line_count = len(resolved.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError as exc:
            raise RunnerError("invalid_source_region: file is unreadable") from exc
        if end > line_count:
            raise RunnerError("invalid_source_region: range exceeds end of file")
        validated.append({"path": path, "start": start, "end": end, "reason": reason})
    return validated


def _classify_failure(returncode: int | None, timed_out: bool, stderr: str) -> str | None:
    if timed_out:
        return "timeout"
    lowered = stderr.lower()
    if "401" in lowered or "unauthorized" in lowered or "missing bearer" in lowered:
        return "unauthorized"
    if any(token in lowered for token in ("could not resolve host", "name or service not known", "lookup", "dns", "connection refused", "network is unreachable")):
        return "dns_transport_failure"
    if returncode is not None and returncode < 0:
        return "terminated_by_signal"
    if returncode not in (0, None):
        return "nonzero_exit"
    return None


def run_child(
    command: list[str],
    prompt: str,
    state_dir: Path,
    events_path: Path,
    stderr_path: Path,
    timeout_seconds: float,
    environment: dict[str, str] | None = None,
    working_directory: Path | None = None,
    codex_home: Path | None = None,
    forbidden_paths: list[Path] | None = None,
) -> dict[str, Any]:
    """Run one child and retain both streams, including partial output."""
    env = {
        "PATH": (environment or {}).get("PATH", os.environ.get("PATH", "")),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "HOME": str(codex_home or state_dir),
        "TMPDIR": str(state_dir / "tmp"),
    }
    env.update({key: value for key, value in (environment or {}).items() if key not in {"HOME", "TMPDIR", "CODEX_HOME"}})
    env["CODEX_HOME"] = str(codex_home or state_dir)
    (state_dir / "tmp").mkdir(parents=True, exist_ok=True)
    events_path.parent.mkdir(parents=True, exist_ok=True)
    events_path.touch(mode=0o600, exist_ok=True)
    stderr_path.touch(mode=0o600, exist_ok=True)
    os.chmod(events_path, 0o600)
    os.chmod(stderr_path, 0o600)
    started = time.monotonic()
    launched_command = list(command)
    profile = None
    if working_directory is not None and codex_home is not None:
        profile = sandbox_profile(Path(command[0]), working_directory, codex_home, state_dir, forbidden_paths)
        launched_command = ["/usr/bin/sandbox-exec", "-p", profile, *command]
    process = subprocess.Popen(
        launched_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=str(working_directory) if working_directory else None,
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(prompt.encode("utf-8"), timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        partial_stdout = exc.output if isinstance(exc.output, bytes) else (exc.output or b"").encode()
        partial_stderr = exc.stderr if isinstance(exc.stderr, bytes) else (exc.stderr or b"").encode()
        try:
            os.killpg(process.pid, signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        if not stdout:
            stdout = partial_stdout
        if not stderr:
            stderr = partial_stderr
    ended = time.monotonic()
    events_path.write_bytes(stdout or b"")
    stderr_path.write_bytes(stderr or b"")
    os.chmod(events_path, 0o600)
    os.chmod(stderr_path, 0o600)
    response_path = state_dir / "response.json"
    telemetry = parse_events((stdout or b"").decode("utf-8", errors="replace"))
    response = None
    response_error = None
    if response_path.is_file():
        try:
            response = json.loads(response_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            response_error = str(exc)
    failure = _classify_failure(process.returncode, timed_out, (stderr or b"").decode("utf-8", errors="replace"))
    if failure is None and process.returncode == 0 and response is None:
        failure = "missing_response"
    if failure is None and not telemetry.get("valid"):
        failure = telemetry.get("failure_class") or "telemetry_unavailable"
    signal_number = -process.returncode if isinstance(process.returncode, int) and process.returncode < 0 else None
    return {
        "returncode": process.returncode,
        "timed_out": timed_out,
        "terminated": bool(signal_number),
        "signal_number": signal_number,
        "signal_name": signal.Signals(signal_number).name if signal_number else None,
        "elapsed_seconds": duration_seconds(started, ended),
        "response": response,
        "response_error": response_error,
        "telemetry": telemetry,
        "failure_class": failure,
        "state_dir": str(state_dir),
        "events_path": str(events_path),
        "stderr_path": str(stderr_path),
        "last_observed_event": telemetry.get("last_event_number"),
        "last_observed_timestamp": telemetry.get("last_event_timestamp"),
        "sandboxed": profile is not None,
        "sandbox_profile_sha256": hashlib.sha256(profile.encode()).hexdigest() if profile else None,
        "launched_argument_vector": [arg for arg in launched_command if "auth" not in arg.lower()],
    }
