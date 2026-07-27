from __future__ import annotations

import sys
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(REPO / "benchmark_method" / "codex_baseline" / "src"))

from codegraph_bench.codegraph_runner import (
    REQUIRED_PROMPT_TEXT,
    RunnerError,
    _mcp_socket_path,
    build_codegraph_command,
    build_treatment_prompt,
    codegraph_sandbox_profile,
    isolation_guarantees,
    neutralize_git_provenance,
    run_codegraph_child,
    run_isolation_canaries,
)
from context_graph_bench.codex_runner import build_command as build_baseline_command


class RunnerTests(unittest.TestCase):
    def setUp(self):
        with (ROOT / "config" / "codegraph.toml").open("rb") as stream:
            self.config = tomllib.load(stream)

    def test_prompt_preserves_exact_contract(self):
        template = (ROOT / "config" / "codegraph-region-selection-prompt.md").read_text(encoding="utf-8")
        prompt = build_treatment_prompt(template, "routing issue")
        self.assertIn(REQUIRED_PROMPT_TEXT, prompt)
        self.assertIn("routing issue", prompt)
        self.assertIn("Hard benchmark boundary", prompt)

    def test_prompt_contract_drift_refuses(self):
        with self.assertRaisesRegex(RunnerError, "treatment prompt text differs"):
            build_treatment_prompt("Issue: {{problem_statement}}", "issue")

    def test_command_is_baseline_plus_explicit_mcp_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            repo = root / "repo"
            state.mkdir()
            repo.mkdir()
            codex = Path("/opt/codex")
            codegraph = Path("/opt/codegraph/bin/codegraph")
            command = build_codegraph_command(
                codex,
                self.config,
                state,
                REPO / "benchmark_method" / "common" / "schemas" / "agent-regions.schema.json",
                repo,
                codegraph_launcher=[Path("/opt/node").as_posix(), str(codegraph)],
                serve_args=["serve", "--mcp", "--index", "/index"],
                mcp_environment={"CODEGRAPH_TELEMETRY": "0"},
            )
            baseline_config = {
                "baseline": self.config["treatment"] | {"arm": "codex-baseline", "protocol": "direct-region-v1"},
                "paths": {"codex_executable": str(codex)},
            }
            baseline = build_baseline_command(codex, baseline_config, state, Path("/schema"), repo)
            start = command.index("non_prefixed_mcp_tool_names") - 1
            marker = command.index("--ignore-user-config")
            stripped = command[:start] + command[marker:]
            self.assertEqual(stripped, baseline)
            self.assertEqual(
                command[start : start + 2],
                ["--enable", "non_prefixed_mcp_tool_names"],
            )
            self.assertIn("suppress_unstable_features_warning=true", command)
            self.assertIn("mcp_servers.codegraph.command=\"/usr/bin/nc\"", command)
            self.assertIn(
                f'mcp_servers.codegraph.args=["-U","{_mcp_socket_path(state)}"]',
                command,
            )
            self.assertIn("mcp_servers.codegraph.enabled=true", command)
            self.assertNotIn("mcp_servers.codegraph.command=\"/usr/bin/sandbox-exec\"", command)
            self.assertIn("--ephemeral", command)
            self.assertIn("--ignore-rules", command)
            self.assertNotIn("resume", command)

    def test_secret_like_mcp_env_key_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.joinpath("state").mkdir()
            root.joinpath("repo").mkdir()
            with self.assertRaisesRegex(RunnerError, "safe string pairs"):
                build_codegraph_command(
                    Path("/codex"),
                    self.config,
                    root / "state",
                    Path("/schema"),
                    root / "repo",
                    codegraph_launcher=["/node", "/codegraph"],
                    serve_args=["serve", "--mcp"],
                    mcp_environment={"bad-key": "secret"},
                )

    def test_sandbox_profile_preserves_baseline_guarantees_and_only_private_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repo"
            codex_home = root / "private-home"
            state = root / "private-state"
            runtime = root / "staged-runtime"
            lifecycle = root / "harness-owned-lifecycle"
            index = repository / ".attempt-index"
            for path in (repository, codex_home, state, runtime, lifecycle, index):
                path.mkdir(parents=True, exist_ok=True)
            profile = codegraph_sandbox_profile(
                repository,
                codex_home,
                state,
                [runtime],
                [REPO / ".benchmark-runs", lifecycle],
                index,
            )
            self.assertIn('(deny file-write* (subpath "/Users/aiswarya")', profile)
            self.assertIn(f'(subpath "{repository.resolve()}")', profile)
            self.assertIn(f'(subpath "{runtime.resolve()}")', profile)
            self.assertIn(f'(subpath "{lifecycle.resolve()}")', profile)
            self.assertIn(f'(allow file-write* (subpath "{codex_home.resolve()}")', profile)
            self.assertIn(f'(subpath "{state.resolve()}")', profile)
            self.assertIn(f'(subpath "{index.resolve()}")', profile)
            self.assertTrue(isolation_guarantees()["baseline_guarantees_preserved"])

    def test_isolation_canaries_require_exact_allow_and_deny_outcomes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                name: root / name
                for name in ("repo", "home", "state", "index", "runtime")
            }
            for path in paths.values():
                path.mkdir()
            denied_read = root / "parent-secret"
            denied_read.write_text("secret", encoding="utf-8")
            denied_write = root / "parent-write"

            def fake_run(command, **kwargs):
                target = Path(command[-1])
                allowed = target.is_relative_to(paths["home"]) or target.is_relative_to(
                    paths["state"]
                ) or target.is_relative_to(paths["index"])
                return SimpleNamespace(
                    returncode=0 if allowed else 1,
                    stdout="",
                    stderr="" if allowed else "operation denied",
                )

            with patch(
                "codegraph_bench.codegraph_runner.subprocess.run",
                side_effect=fake_run,
            ):
                result = run_isolation_canaries(
                    profile="fixture-profile",
                    repository=paths["repo"],
                    codex_home=paths["home"],
                    state_dir=paths["state"],
                    writable_index_root=paths["index"],
                    staged_runtime_root=paths["runtime"],
                    denied_read_path=denied_read,
                    denied_write_path=denied_write,
                )
            self.assertTrue(result["passed"])
            self.assertEqual(len(result["probes"]), 7)

    def test_mcp_server_launch_failure_removes_private_socket(self):
        class FakeListener:
            def __init__(self):
                self.closed = False

            def bind(self, path):
                Path(path).touch()

            def listen(self, _backlog):
                pass

            def settimeout(self, _seconds):
                pass

            def close(self):
                self.closed = True

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                name: root / name
                for name in ("repo", "home", "state", "runtime", "index")
            }
            for path in paths.values():
                path.mkdir()
            socket_path = _mcp_socket_path(paths["state"])
            listener = FakeListener()
            with (
                patch(
                    "codegraph_bench.codegraph_runner.socket.socket",
                    return_value=listener,
                ),
                patch(
                    "codegraph_bench.codegraph_runner.subprocess.Popen",
                    side_effect=OSError("spawn refused"),
                ),
            ):
                with self.assertRaisesRegex(
                    RunnerError,
                    "mcp_startup_failure",
                ):
                    run_codegraph_child(
                        ["/codex"],
                        "prompt",
                        state_dir=paths["state"],
                        events_path=paths["state"] / "events.jsonl",
                        stderr_path=paths["state"] / "stderr.log",
                        timeout_seconds=1,
                        environment={"PATH": "/usr/bin", "LANG": "C.UTF-8"},
                        repository=paths["repo"],
                        codex_home=paths["home"],
                        mcp_roots=[paths["runtime"]],
                        forbidden_paths=[],
                        expected_project=paths["repo"],
                        writable_index_root=paths["index"],
                        mcp_server_command=["/node", "/codegraph", "serve"],
                        mcp_environment={"CODEGRAPH_TELEMETRY": "0"},
                    )
            self.assertFalse(socket_path.exists())
            self.assertTrue(listener.closed)

    def test_mcp_socket_path_is_short_unique_and_attempt_bound(self):
        long_state = Path("/private/tmp") / ("long-attempt-segment-" * 12)
        other_state = Path("/private/tmp") / ("other-attempt-segment-" * 12)
        socket_path = _mcp_socket_path(long_state)
        self.assertEqual(socket_path.parent, Path("/private/tmp"))
        self.assertLessEqual(len(str(socket_path).encode()), 103)
        self.assertEqual(socket_path, _mcp_socket_path(long_state))
        self.assertNotEqual(socket_path, _mcp_socket_path(other_state))

    def test_private_git_snapshot_removes_remotes_and_has_no_alternates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            (source / "file.txt").write_text("fixture\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(source), "add", "file.txt"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(source),
                    "-c",
                    "user.name=Bench",
                    "-c",
                    "user.email=bench@example.invalid",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                check=True,
            )
            commit = subprocess.run(
                ["git", "-C", str(source), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            mirror = root / "mirror.git"
            worktree = root / "worktree"
            subprocess.run(["git", "clone", "-q", "--mirror", str(source), str(mirror)], check=True)
            subprocess.run(
                ["git", "--git-dir", str(mirror), "worktree", "add", "-q", "--detach", str(worktree), commit],
                check=True,
            )
            provenance = neutralize_git_provenance(
                {"mirror_path": str(mirror), "path": str(worktree)}
            )
            self.assertEqual(provenance["after"], [])
            self.assertFalse(provenance["alternates_present"])
            self.assertEqual(
                subprocess.run(
                    ["git", "-C", str(worktree), "remote"],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout,
                "",
            )


if __name__ == "__main__":
    unittest.main()
