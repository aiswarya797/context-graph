"""Concrete per-attempt Codex + CodeGraph MCP command and process runner."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any


CODEGRAPH_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = CODEGRAPH_ROOT.parents[1]
BASELINE_SRC = REPOSITORY_ROOT / "benchmark_method" / "codex_baseline" / "src"
if str(BASELINE_SRC) not in sys.path:
    sys.path.insert(0, str(BASELINE_SRC))

from context_graph_bench.codex_runner import (  # noqa: E402
    RunnerError,
    build_command as build_baseline_command,
    build_prompt as build_baseline_prompt,
    validate_regions,
)
from context_graph_bench.telemetry import duration_seconds, parse_events  # noqa: E402

from .codegraph_events import parse_navigation_events
from .codegraph import NETWORK_DENY_PROFILE


REQUIRED_PROMPT_TEXT = """Use the CodeGraph `codegraph_explore` tool before using built-in repository
search or file-reading tools. Query CodeGraph using the issue below and use the
returned graph context to select the strongest source regions.

You may use built-in search or file reading only when CodeGraph's results are
insufficient. Do not return the final regions without first successfully
querying CodeGraph."""
SAFE_ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")
UNIX_SOCKET_PATH_MAX_BYTES = 103


def build_treatment_prompt(template: str, issue_text: str) -> str:
    if REQUIRED_PROMPT_TEXT not in template:
        raise RunnerError("configuration_error: CodeGraph treatment prompt text differs")
    return build_baseline_prompt(template, issue_text)


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_array(values: list[str]) -> str:
    return "[" + ",".join(_toml_string(value) for value in values) + "]"


def _toml_table(values: dict[str, str]) -> str:
    if not values or not all(SAFE_ENV_KEY.fullmatch(key) and isinstance(value, str) for key, value in values.items()):
        raise RunnerError("configuration_error: MCP environment must contain non-empty safe string pairs")
    return "{" + ",".join(f"{key}={_toml_string(values[key])}" for key in sorted(values)) + "}"


def _mcp_socket_path(state_dir: Path) -> Path:
    attempt_identity = hashlib.sha256(
        str(state_dir.resolve()).encode()
    ).hexdigest()[:24]
    path = Path("/private/tmp") / f"context-graph-codegraph-{attempt_identity}.sock"
    if len(os.fsencode(path)) > UNIX_SOCKET_PATH_MAX_BYTES:
        raise RunnerError(
            "configuration_error: private MCP socket path exceeds AF_UNIX limit"
        )
    return path


def build_codegraph_command(
    codex_executable: Path,
    config: dict[str, Any],
    state_dir: Path,
    schema_path: Path,
    repository: Path,
    *,
    codegraph_launcher: list[str],
    serve_args: list[str],
    mcp_environment: dict[str, str],
) -> list[str]:
    baseline_config = {
        "baseline": {
            "arm": "codex-baseline",
            "protocol": "direct-region-v1",
            "model": config["treatment"]["model"],
            "display_name": config["treatment"]["display_name"],
            "reasoning_effort": config["treatment"]["reasoning_effort"],
            "codex_version": config["treatment"]["codex_version"],
            "sample_count": config["treatment"]["sample_count"],
            "retry_cap": config["treatment"]["retry_cap"],
            "timeout_seconds": config["treatment"]["timeout_seconds"],
            "max_regions": config["treatment"]["max_regions"],
        },
        "paths": {"codex_executable": str(codex_executable)},
    }
    args = build_baseline_command(codex_executable, baseline_config, state_dir, schema_path, repository)
    if (
        not codegraph_launcher
        or not all(Path(value).is_absolute() for value in codegraph_launcher)
        or not serve_args
        or serve_args[:2] != ["serve", "--mcp"]
    ):
        raise RunnerError("configuration_error: staged MCP launcher and serve --mcp arguments are required")
    network_wrapper = Path("/usr/bin/sandbox-exec")
    proxy = Path("/usr/bin/nc")
    if not network_wrapper.is_file() or not proxy.is_file():
        raise RunnerError(
            "configuration_error: process-split MCP transport is unavailable"
        )
    _toml_table(mcp_environment)
    mcp_socket = _mcp_socket_path(state_dir)
    overrides = [
        "--enable",
        "non_prefixed_mcp_tool_names",
        "-c",
        "suppress_unstable_features_warning=true",
        "-c",
        f"mcp_servers.codegraph.command={_toml_string(str(proxy))}",
        "-c",
        f"mcp_servers.codegraph.args={_toml_array(['-U', str(mcp_socket)])}",
        "-c",
        f"mcp_servers.codegraph.cwd={_toml_string(str(repository))}",
        "-c",
        "mcp_servers.codegraph.enabled=true",
    ]
    insert_at = args.index("--ignore-user-config")
    result = [*args[:insert_at], *overrides, *args[insert_at:]]
    joined = "\n".join(result).lower()
    if "resume" in result or "session" in joined or "--ephemeral" not in result:
        raise RunnerError("configuration_error: measured attempts must be session-ephemeral")
    if str(REPOSITORY_ROOT / ".benchmark-runs") in joined:
        raise RunnerError("configuration_error: prior benchmark outputs leaked into child arguments")
    if str(mcp_socket).lower() not in joined or str(proxy).lower() not in joined:
        raise RunnerError("configuration_error: MCP Unix transport is not exact")
    return result


def child_environment(codex_executable: Path, telemetry_environment: dict[str, str]) -> dict[str, str]:
    path_entries = [str(codex_executable.parent), "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    environment = {"PATH": os.pathsep.join(path_entries), "LANG": "C.UTF-8", **telemetry_environment}
    if any("TOKEN" in key or "SECRET" in key or "PASSWORD" in key for key in environment):
        raise RunnerError("configuration_error: secret-like environment key is not permitted for MCP")
    return environment


def _profile_literal(path: Path | str) -> str:
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def codegraph_sandbox_profile(
    repository: Path,
    codex_home: Path,
    state_dir: Path,
    mcp_roots: list[Path],
    forbidden_paths: list[Path],
    writable_index_root: Path,
) -> str:
    """Match baseline parent isolation while allowing only the attempt index."""
    allowed = {
        str(path.resolve())
        for path in [repository, codex_home, state_dir, writable_index_root, *mcp_roots]
    }
    denied: list[Path] = []
    candidates = [
        Path("/Users/aiswarya/Documents"),
        REPOSITORY_ROOT,
        REPOSITORY_ROOT / ".benchmark-runs",
        REPOSITORY_ROOT / "benchmark_method",
        REPOSITORY_ROOT / "benchmark_method" / "common",
        REPOSITORY_ROOT / ".benchmark-work" / "codex-baseline",
        REPOSITORY_ROOT / ".benchmark-work" / "codegraph",
        REPOSITORY_ROOT / ".benchmark-tools" / "codegraph",
        Path("/Users/aiswarya/.codex"),
        Path("/Users/aiswarya/.ssh"),
        Path("/Users/aiswarya/.config"),
        Path("/Users/aiswarya/.npm"),
        Path("/Users/aiswarya/.cache"),
        *forbidden_paths,
    ]
    for path in candidates:
        resolved = str(path.resolve())
        if resolved not in allowed and not any(Path(root) in Path(resolved).parents for root in allowed):
            denied.append(Path(resolved))
    read_rules = " ".join(f"(subpath {_profile_literal(path)})" for path in sorted(set(denied), key=str))
    write_rules = " ".join(
        f"(subpath {_profile_literal(path)})"
        for path in sorted(
            {
                Path("/Users/aiswarya"),
                repository.resolve(),
                *(path.resolve() for path in mcp_roots),
                *set(denied),
            },
            key=str,
        )
    )
    allowed_writes = " ".join(
        f"(subpath {_profile_literal(path)})"
        for path in sorted(
            {
                codex_home.resolve(),
                state_dir.resolve(),
                writable_index_root.resolve(),
            },
            key=str,
        )
    )
    return " ".join(
        [
            "(version 1)",
            "(allow default)",
            f"(deny file-read* {read_rules})",
            f"(deny file-write* {write_rules})",
            f"(allow file-write* {allowed_writes})",
        ]
    )


def isolation_guarantees() -> dict[str, Any]:
    """Stable treatment guarantees compared against the frozen baseline."""
    return {
        "parent_documents_read_denied": True,
        "parent_home_write_denied": True,
        "task_repository_write_denied": True,
        "private_codex_home_write_allowed": True,
        "private_state_write_allowed": True,
        "attempt_index_copy_write_allowed": True,
        "staged_runtime_write_denied": True,
        "baseline_guarantees_preserved": True,
        "git_remote_provenance_neutralized": True,
    }


def run_isolation_canaries(
    *,
    profile: str,
    repository: Path,
    codex_home: Path,
    state_dir: Path,
    writable_index_root: Path,
    staged_runtime_root: Path,
    denied_read_path: Path,
    denied_write_path: Path,
) -> dict[str, Any]:
    """Exercise the profile without launching Codex."""
    probes = [
        ("deny_parent_read", ["/bin/cat", str(denied_read_path)], False),
        (
            "deny_parent_write",
            ["/usr/bin/touch", str(denied_write_path)],
            False,
        ),
        (
            "deny_repository_write",
            ["/usr/bin/touch", str(repository / ".sandbox-write-canary")],
            False,
        ),
        (
            "allow_private_state_write",
            ["/usr/bin/touch", str(state_dir / ".sandbox-write-canary")],
            True,
        ),
        (
            "allow_private_home_write",
            ["/usr/bin/touch", str(codex_home / ".sandbox-write-canary")],
            True,
        ),
        (
            "allow_attempt_index_write",
            ["/usr/bin/touch", str(writable_index_root / ".sandbox-write-canary")],
            True,
        ),
        (
            "deny_staged_runtime_write",
            ["/usr/bin/touch", str(staged_runtime_root / ".sandbox-write-canary")],
            False,
        ),
    ]
    records: list[dict[str, Any]] = []
    try:
        for name, command, should_succeed in probes:
            result = subprocess.run(
                ["/usr/bin/sandbox-exec", "-p", profile, *command],
                capture_output=True,
                text=True,
                check=False,
            )
            observed = result.returncode == 0
            records.append(
                {
                    "name": name,
                    "command": command,
                    "expected_success": should_succeed,
                    "return_code": result.returncode,
                    "observed_success": observed,
                    "passed": observed is should_succeed,
                    "stdout_sha256": hashlib.sha256((result.stdout or "").encode()).hexdigest(),
                    "stderr_sha256": hashlib.sha256((result.stderr or "").encode()).hexdigest(),
                }
            )
    finally:
        cleanup = [
            denied_write_path,
            repository / ".sandbox-write-canary",
            state_dir / ".sandbox-write-canary",
            codex_home / ".sandbox-write-canary",
            writable_index_root / ".sandbox-write-canary",
            staged_runtime_root / ".sandbox-write-canary",
        ]
        for path in cleanup:
            if path.is_file():
                path.unlink()
    return {
        "schema_version": "codegraph-isolation-canaries-v1",
        "passed": all(record["passed"] for record in records),
        "profile_sha256": hashlib.sha256(profile.encode()).hexdigest(),
        "guarantees": isolation_guarantees(),
        "probes": records,
    }


def _classify_failure(returncode: int | None, timed_out: bool, stderr: str) -> str | None:
    if timed_out:
        return "timeout"
    if returncode not in (0, None):
        lower = stderr.lower()
        if "mcp" in lower and ("startup" in lower or "failed to start" in lower or "connection" in lower):
            return "mcp_startup_failure"
        if "401" in lower or "unauthorized" in lower:
            return "auth_failure"
        if "resolve host" in lower or "dns" in lower:
            return "transport_failure"
        return "nonzero_exit"
    return None


def run_codegraph_child(
    command: list[str],
    prompt: str,
    *,
    state_dir: Path,
    events_path: Path,
    stderr_path: Path,
    timeout_seconds: float,
    environment: dict[str, str],
    repository: Path,
    codex_home: Path,
    mcp_roots: list[Path],
    forbidden_paths: list[Path],
    expected_project: Path,
    writable_index_root: Path,
    mcp_server_command: list[str],
    mcp_environment: dict[str, str],
) -> dict[str, Any]:
    env = {
        "PATH": environment.get("PATH", ""),
        "LANG": environment.get("LANG", "C.UTF-8"),
        "HOME": str(codex_home),
        "CODEX_HOME": str(codex_home),
        "TMPDIR": str(state_dir / "tmp"),
        **{key: value for key, value in environment.items() if key not in {"HOME", "CODEX_HOME", "TMPDIR"}},
    }
    (state_dir / "tmp").mkdir(parents=True, exist_ok=True)
    events_path.parent.mkdir(parents=True, exist_ok=True)
    profile = codegraph_sandbox_profile(
        repository,
        codex_home,
        state_dir,
        mcp_roots,
        forbidden_paths,
        writable_index_root,
    )
    if (
        not mcp_server_command
        or not all(isinstance(value, str) and value for value in mcp_server_command)
        or not mcp_environment
        or not all(
            SAFE_ENV_KEY.fullmatch(key) and isinstance(value, str)
            for key, value in mcp_environment.items()
        )
    ):
        raise RunnerError(
            "configuration_error: exact MCP server command and environment "
            "are required"
        )
    socket_path = _mcp_socket_path(state_dir)
    if socket_path.exists() or socket_path.is_symlink():
        raise RunnerError("configuration_error: fresh MCP socket path is required")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen(1)
        listener.settimeout(0.5)
    except BaseException:
        listener.close()
        socket_path.unlink(missing_ok=True)
        raise
    server_stderr_digest = hashlib.sha256()
    server_stderr_bytes = 0
    bridge_errors: list[str] = []
    stop_bridge = threading.Event()
    server_command = [
        "/usr/bin/sandbox-exec",
        "-p",
        NETWORK_DENY_PROFILE,
        *mcp_server_command,
    ]
    server: subprocess.Popen[bytes] | None = None
    stderr_thread: threading.Thread | None = None
    bridge_thread: threading.Thread | None = None
    transport_closed = False

    def close_mcp_transport() -> None:
        nonlocal transport_closed
        if transport_closed:
            return
        transport_closed = True
        stop_bridge.set()
        listener.close()
        if server is not None and server.poll() is None:
            try:
                os.killpg(server.pid, signal.SIGTERM)
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(server.pid, signal.SIGKILL)
                server.wait()
            except ProcessLookupError:
                server.wait()
        if bridge_thread is not None:
            bridge_thread.join(timeout=5)
        if stderr_thread is not None:
            stderr_thread.join(timeout=5)
        socket_path.unlink(missing_ok=True)

    try:
        server = subprocess.Popen(
            server_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=repository,
            env={**env, **mcp_environment},
            start_new_session=True,
        )
    except Exception as error:
        close_mcp_transport()
        raise RunnerError(
            "mcp_startup_failure: CodeGraph MCP process spawn failed"
        ) from error

    def drain_server_stderr() -> None:
        nonlocal server_stderr_bytes
        assert server is not None
        assert server.stderr is not None
        while chunk := os.read(server.stderr.fileno(), 65536):
            server_stderr_digest.update(chunk)
            server_stderr_bytes += len(chunk)

    def relay_mcp() -> None:
        assert server is not None
        connection: socket.socket | None = None
        try:
            while not stop_bridge.is_set():
                try:
                    connection, _address = listener.accept()
                    break
                except TimeoutError:
                    continue
            if connection is None:
                return
            assert server.stdin is not None
            assert server.stdout is not None

            def socket_to_server() -> None:
                try:
                    while data := connection.recv(65536):
                        server.stdin.write(data)
                        server.stdin.flush()
                except (BrokenPipeError, OSError, ValueError):
                    pass
                finally:
                    try:
                        server.stdin.close()
                    except OSError:
                        pass

            def server_to_socket() -> None:
                try:
                    while data := os.read(server.stdout.fileno(), 65536):
                        connection.sendall(data)
                except (BrokenPipeError, OSError, ValueError):
                    pass
                finally:
                    try:
                        connection.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

            inbound = threading.Thread(target=socket_to_server, daemon=True)
            outbound = threading.Thread(target=server_to_socket, daemon=True)
            inbound.start()
            outbound.start()
            inbound.join()
            outbound.join()
        except OSError as error:
            if not stop_bridge.is_set():
                bridge_errors.append(str(error))
        finally:
            if connection is not None:
                connection.close()

    launched = ["/usr/bin/sandbox-exec", "-p", profile, *command]
    started = time.monotonic()
    try:
        stderr_thread = threading.Thread(
            target=drain_server_stderr,
            daemon=True,
        )
        bridge_thread = threading.Thread(target=relay_mcp, daemon=True)
        stderr_thread.start()
        bridge_thread.start()
        process = subprocess.Popen(
            launched,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=repository,
            env=env,
            start_new_session=True,
        )
    except Exception as error:
        close_mcp_transport()
        raise RunnerError(
            "codex_launch_failure: Codex process spawn failed"
        ) from error
    timed_out = False
    try:
        stdout, stderr = process.communicate(prompt.encode(), timeout=timeout_seconds)
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
        stdout = stdout or partial_stdout
        stderr = stderr or partial_stderr
    finally:
        close_mcp_transport()
    ended = time.monotonic()
    events_path.write_bytes(stdout or b"")
    stderr_path.write_bytes(stderr or b"")
    os.chmod(events_path, 0o600)
    os.chmod(stderr_path, 0o600)
    raw = (stdout or b"").decode(errors="replace")
    telemetry = parse_events(raw)
    navigation = parse_navigation_events(
        raw,
        repository,
        expected_project=expected_project,
        allowed_runtime_roots=[state_dir, codex_home, *mcp_roots],
        forbidden_paths=forbidden_paths,
    )
    response = None
    response_error = None
    response_path = state_dir / "response.json"
    if response_path.is_file():
        try:
            response = json.loads(response_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            response_error = str(exc)
    failure = _classify_failure(process.returncode, timed_out, (stderr or b"").decode(errors="replace"))
    if failure is None and bridge_errors:
        failure = "mcp_transport_failure"
    if failure is None and not telemetry.get("valid"):
        failure = telemetry.get("failure_class") or "telemetry_unavailable"
    if failure is None and response is None:
        failure = "missing_response"
    signal_number = -process.returncode if process.returncode < 0 else None
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
        "navigation": navigation,
        "failure_class": failure,
        "state_dir": str(state_dir),
        "events_path": str(events_path),
        "stderr_path": str(stderr_path),
        "sandboxed": True,
        "sandbox_profile_sha256": hashlib.sha256(profile.encode()).hexdigest(),
        "sandbox_guarantees": isolation_guarantees(),
        "launched_argument_vector": launched,
        "mcp_transport": "prelaunched-network-denied-stdio-over-private-unix-v1",
        "mcp_server_argument_vector": server_command,
        "mcp_server_returncode": server.returncode if server else None,
        "mcp_server_stderr_bytes": server_stderr_bytes,
        "mcp_server_stderr_sha256": server_stderr_digest.hexdigest(),
        "mcp_bridge_errors": bridge_errors,
    }


def fresh_runtime_dirs(root: Path, auth_source: Path) -> tuple[Path, Path]:
    private_home = root / "codex-home"
    state = root / "state"
    if private_home.exists() or state.exists():
        raise RunnerError("configuration_error: fresh attempt runtime already exists")
    private_home.mkdir(parents=True, mode=0o700)
    state.mkdir(parents=True, mode=0o700)
    shutil.copyfile(auth_source, private_home / "auth.json")
    os.chmod(private_home / "auth.json", 0o600)
    return private_home, state


def neutralize_git_provenance(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Remove inherited local remotes/alternates from the private clone."""
    mirror = Path(snapshot["mirror_path"])
    worktree = Path(snapshot["path"])
    before = subprocess.run(
        ["git", "-C", str(worktree), "remote", "-v"],
        capture_output=True,
        text=True,
        check=False,
    )
    names = subprocess.run(
        ["git", "-C", str(mirror), "remote"],
        capture_output=True,
        text=True,
        check=False,
    )
    if before.returncode or names.returncode:
        raise RunnerError("repository_snapshot_failure: cannot inspect private Git provenance")
    for name in names.stdout.splitlines():
        removed = subprocess.run(
            ["git", "-C", str(mirror), "remote", "remove", name.strip()],
            capture_output=True,
            text=True,
            check=False,
        )
        if removed.returncode:
            raise RunnerError("repository_snapshot_failure: cannot remove private Git remote")
    common_dir_result = subprocess.run(
        ["git", "-C", str(worktree), "rev-parse", "--git-common-dir"],
        capture_output=True,
        text=True,
        check=False,
    )
    if common_dir_result.returncode:
        raise RunnerError("repository_snapshot_failure: cannot resolve private Git common dir")
    common_dir = Path(common_dir_result.stdout.strip())
    if not common_dir.is_absolute():
        common_dir = (worktree / common_dir).resolve()
    alternates = common_dir / "objects" / "info" / "alternates"
    if alternates.exists():
        raise RunnerError("repository_snapshot_failure: private Git clone uses object alternates")
    after = subprocess.run(
        ["git", "-C", str(worktree), "remote", "-v"],
        capture_output=True,
        text=True,
        check=False,
    )
    if after.returncode or after.stdout.strip():
        raise RunnerError("repository_snapshot_failure: private Git remote provenance remains")
    return {
        "schema_version": "codegraph-private-git-provenance-v1",
        "before": before.stdout.splitlines(),
        "after": [],
        "alternates_present": False,
        "neutralized": True,
    }
