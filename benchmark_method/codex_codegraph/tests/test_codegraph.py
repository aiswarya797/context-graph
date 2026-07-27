from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import hashlib
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from codegraph_bench.codegraph import (
    _capture_process,
    attempt_index_copy,
    CodeGraphError,
    directory_manifest,
    index_identity,
    parse_status,
    prepare_index,
    runtime_bundle_manifest,
    sha256_file,
    sha256_value,
    source_manifest,
    stage_runtime_bundle,
    validate_control_environment,
    validate_frozen_index_status,
    validate_index,
    validate_runtime,
    validate_source_lock,
)


def source_lock() -> dict:
    expected_stdout = hashlib.sha256(b"1.2.3\n").hexdigest()
    expected_stderr = hashlib.sha256(b"").hexdigest()
    probe = {
        "command": ["--version"],
        "expected_return_code": 0,
        "expected_stdout_sha256": expected_stdout,
        "expected_stderr_sha256": expected_stderr,
        "network_policy": "deny",
    }
    return {
        "schema_version": "codegraph-source-lock-v1",
        "repository_url": "https://github.com/colbymchenry/codegraph.git",
        "resolved_commit": "a" * 40,
        "retrieved_at": "2026-07-27T00:00:00Z",
        "declared_version": "1.2.3",
        "license": "MIT",
        "package_metadata_sha256": hashlib.sha256(b"package\n").hexdigest(),
        "lockfile_sha256": hashlib.sha256(b"lock\n").hexdigest(),
        "upstream_resolution_sha256": hashlib.sha256(b"resolution\n").hexdigest(),
        "toolchain": {
            "required_node_range": ">=20 <25",
            "node": {
                "logical_command": "node",
                "version": "v22.17.0",
                "executable_sha256": "1" * 64,
            },
            "npm": {
                "logical_command": "npm",
                "version": "10.9.2",
                "executable_sha256": "2" * 64,
            },
        },
        "build_entrypoint": ["package.json", "bin"],
        "install_command": ["npm", "ci"],
        "build_command": ["npm", "ci"],
        "executable_relative_path": "bin/codegraph",
        "version_command": ["--version"],
        "index_command": ["init", "{repository}"],
        "status_command": ["status", "{repository}", "--json"],
        "serve_args": ["serve", "--mcp", "--path", "{repository}", "--no-watch"],
        "telemetry": {
            "disabled": True,
            "environment": {
                "DO_NOT_TRACK": "1",
                "CODEGRAPH_TELEMETRY": "0",
                "CODEGRAPH_NO_UPDATE_CHECK": "1",
                "CODEGRAPH_NO_DAEMON": "1",
                "CODEGRAPH_NO_WATCH": "1",
                "CODEGRAPH_MCP_TOOLS": "explore",
            },
            "source_evidence": [
                {
                    "path": "evidence.txt",
                    "sha256": hashlib.sha256(b"controls\n").hexdigest(),
                    "assertion": "telemetry_disabled_branch",
                }
            ],
            "probe": probe,
        },
        "self_update": {
            "disabled": True,
            "source_evidence": [
                {
                    "path": "evidence.txt",
                    "sha256": hashlib.sha256(b"controls\n").hexdigest(),
                    "assertion": "self_update_disabled_branch",
                }
            ],
            "probe": probe,
        },
        "runtime_controls": {
            "catch_up_sync_may_mutate_copy": True,
            "source_evidence": [
                {
                    "path": "evidence.txt",
                    "sha256": hashlib.sha256(b"controls\n").hexdigest(),
                    "assertion": assertion,
                }
                for assertion in (
                    "direct_stdio_no_daemon_branch",
                    "watch_disabled_branch",
                    "catch_up_sync_mutates_copy_branch",
                    "codegraph_directory_override_branch",
                )
            ],
        },
    }


def git_repository(root: Path) -> str:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "module.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (root / "package.json").write_text("package\n", encoding="utf-8")
    (root / "package-lock.json").write_text("lock\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "module.py", "package.json", "package-lock.json"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=Bench", "-c", "user.email=bench@example.invalid", "commit", "-qm", "fixture"],
        check=True,
    )
    return subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()


def upstream_status(repository: Path, index_dir: Path) -> str:
    return json.dumps({
        "initialized": True,
        "version": "1.2.3",
        "projectPath": str(repository),
        "indexPath": str(index_dir),
        "lastIndexed": "2026-07-27T00:00:00Z",
        "fileCount": 1,
        "nodeCount": 1,
        "edgeCount": 0,
        "index": {"state": "complete", "pendingRefs": 0},
    })


class SourceAndRuntimeTests(unittest.TestCase):
    def test_missing_executable_spawn_is_classified_after_durable_step_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary)
            with self.assertRaisesRegex(CodeGraphError, "codegraph_build_failure.*evidence retained"):
                _capture_process(
                    "build",
                    [str(attempt / "missing-codegraph")],
                    attempt,
                    failure_class="codegraph_build_failure",
                )
            record = json.loads((attempt / "build.step.json").read_text())
            self.assertEqual(record["spawn_status"], "failed")
            self.assertEqual(record["failure_class"], "codegraph_build_failure")
            self.assertEqual(record["return_code"], None)
            self.assertEqual((attempt / "build.stdout").read_bytes(), b"")
            self.assertIn("FileNotFoundError", (attempt / "build.stderr").read_text())

    def test_source_lock_is_exact_and_pinned(self):
        self.assertEqual(validate_source_lock(source_lock())["resolved_commit"], "a" * 40)
        bad = source_lock() | {"resolved_commit": "main"}
        with self.assertRaisesRegex(CodeGraphError, "codegraph_source_mismatch"):
            validate_source_lock(bad)

    def test_unverifiable_telemetry_refuses(self):
        bad = source_lock()
        bad["telemetry"] = bad["telemetry"] | {"disabled": False}
        with self.assertRaisesRegex(CodeGraphError, "codegraph_telemetry_not_disabled"):
            validate_source_lock(bad)

    def test_conflicting_runtime_control_environment_refuses(self):
        with self.assertRaisesRegex(CodeGraphError, "conflicting=.*CODEGRAPH_DAEMON_INTERNAL"):
            validate_control_environment(
                source_lock()["telemetry"]["environment"]
                | {"CODEGRAPH_DAEMON_INTERNAL": "1"}
            )

    def test_runtime_bundle_replays_under_a_different_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "source"
            checkout.mkdir()
            (checkout / "dist").mkdir()
            executable = checkout / "dist" / "cli.js"
            executable.write_text("console.log('fixture')\n", encoding="utf-8")
            (checkout / "node_modules" / "fixture").mkdir(parents=True)
            (checkout / "node_modules" / "fixture" / "index.js").write_text(
                "module.exports = 1\n", encoding="utf-8"
            )
            (checkout / "package.json").write_text('{"name":"fixture"}\n', encoding="utf-8")
            (checkout / "package-lock.json").write_text('{"lockfileVersion":3}\n', encoding="utf-8")
            commit = git_repository(checkout)
            node = root / "toolchain-a" / "node"
            node.parent.mkdir()
            node.write_bytes(b"portable-node-fixture")
            node.chmod(0o500)
            manifest = runtime_bundle_manifest(
                checkout,
                node_executable=node,
                npm_executable=node,
                executable=executable,
            )
            manifest_path = root / "runtime-bundle.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            runtime = {
                "source_commit": commit,
                "executable_sha256": sha256_file(executable),
                "runtime_bundle_manifest": {
                    "path": str(manifest_path),
                    "bytes": manifest_path.stat().st_size,
                    "sha256": sha256_file(manifest_path),
                },
                "toolchain": {
                    "node": {
                        "resolved_path": str(node),
                        "executable_sha256": sha256_file(node),
                    }
                },
            }
            staged = stage_runtime_bundle(
                runtime=runtime,
                checkout=checkout,
                stage_root=root / "unrelated-root-b" / "runtime",
            )
            self.assertNotIn(str(checkout), staged["codegraph_executable"])
            self.assertEqual(staged["runtime_bundle_manifest_sha256"], manifest["manifest_sha256"])
            self.assertEqual(sha256_file(Path(staged["node_executable"])), sha256_file(node))

    def test_irrelevant_environment_and_trust_me_prose_do_not_prove_controls(self):
        irrelevant = source_lock()
        irrelevant["telemetry"] = irrelevant["telemetry"] | {"environment": {"UNRELATED_SETTING": "trust me"}}
        with self.assertRaisesRegex(CodeGraphError, "control environment differs"):
            validate_source_lock(irrelevant)
        prose = source_lock()
        prose["telemetry"] = {
            "disabled": True,
            "environment": {"CODEGRAPH_TELEMETRY": "0"},
            "verification": "trust me",
        }
        with self.assertRaisesRegex(CodeGraphError, "telemetry evidence fields are not exact"):
            validate_source_lock(prose)

    def test_runtime_binds_clean_checkout_hash_and_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary) / "source"
            checkout.mkdir()
            git_repository(checkout)
            executable = checkout / "bin" / "codegraph"
            executable.parent.mkdir()
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            (checkout / "evidence.txt").write_text("controls\n", encoding="utf-8")
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            subprocess.run(["git", "-C", str(checkout), "add", "bin/codegraph", "evidence.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(checkout), "-c", "user.name=Bench", "-c", "user.email=bench@example.invalid", "commit", "-qm", "runtime"],
                check=True,
            )
            commit = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
            lock = source_lock() | {"resolved_commit": commit}
            lock["toolchain"] = {
                **lock["toolchain"],
                "node": {
                    **lock["toolchain"]["node"],
                    "executable_sha256": sha256_file(executable),
                },
                "npm": {
                    **lock["toolchain"]["npm"],
                    "executable_sha256": sha256_file(executable),
                },
            }
            configuration = sha256_value(
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
            stdout = Path(temporary) / "probe.stdout"
            stderr = Path(temporary) / "probe.stderr"
            stdout.write_text("1.2.3\n", encoding="utf-8")
            stderr.write_text("", encoding="utf-8")
            probe_record = {
                "command": ["--version"],
                "return_code": 0,
                "stdout": {"path": str(stdout), "bytes": stdout.stat().st_size, "sha256": sha256_file(stdout)},
                "stderr": {"path": str(stderr), "bytes": stderr.stat().st_size, "sha256": sha256_file(stderr)},
                "network_policy": "deny",
                "verified": True,
            }
            bundle_path = Path(temporary) / "runtime-bundle.json"
            bundle_path.write_text(
                json.dumps(
                    {
                        "schema_version": "codegraph-runtime-bundle-v1",
                        "source_commit": commit,
                        "executable_sha256": sha256_file(executable),
                        "node_executable_sha256": sha256_file(executable),
                        "npm_executable_sha256": sha256_file(executable),
                    }
                ),
                encoding="utf-8",
            )
            behavior_path = Path(temporary) / "mcp-behavior.json"
            behavior_path.write_text(
                json.dumps(
                    {
                        "schema_version": "codegraph-mcp-behavior-probe-v1",
                        "verified": True,
                        "network_policy": "deny",
                        "direct_stdio": True,
                        "shared_daemon": False,
                        "watcher": False,
                        "catch_up_sync_may_mutate_copy": True,
                    }
                ),
                encoding="utf-8",
            )
            runtime = {
                "schema_version": "codegraph-runtime-v1",
                "repository_url": lock["repository_url"],
                "source_commit": commit,
                "declared_version": "1.2.3",
                "reported_version": "1.2.3",
                "executable_path": str(executable.resolve()),
                "executable_sha256": sha256_file(executable),
                "runtime_home": str((checkout.parent / "runtime-home").resolve()),
                "build_entrypoint": lock["build_entrypoint"],
                "install_command": lock["install_command"],
                "build_command": lock["build_command"],
                "toolchain": {
                    "required_node_range": ">=20 <25",
                    "node": {
                        "logical_command": "node",
                        "resolved_path": str(executable),
                        "version": "v22.17.0",
                        "executable_sha256": sha256_file(executable),
                    },
                    "npm": {
                        "logical_command": "npm",
                        "resolved_path": str(executable),
                        "version": "10.9.2",
                        "executable_sha256": sha256_file(executable),
                    },
                },
                "runtime_bundle_manifest": {
                    "path": str(bundle_path),
                    "bytes": bundle_path.stat().st_size,
                    "sha256": sha256_file(bundle_path),
                },
                "mcp_behavior_probe": {
                    "path": str(behavior_path),
                    "bytes": behavior_path.stat().st_size,
                    "sha256": sha256_file(behavior_path),
                },
                "telemetry_disabled": True,
                "telemetry_probe": probe_record,
                "self_update_probe": probe_record,
                "self_update_disabled": True,
                "mcp_network_isolation": {
                    "mode": "sandbox-exec-child-network-deny-v1",
                    "profile_sha256": hashlib.sha256(
                        "(version 1) (allow default) (deny network*)".encode()
                    ).hexdigest(),
                    "verified": True,
                },
                "configuration_sha256": configuration,
            }
            self.assertIs(validate_runtime(lock, runtime, checkout, executable), runtime)
            (checkout / "dirty.txt").write_text("dirty", encoding="utf-8")
            with self.assertRaisesRegex(CodeGraphError, "checkout SHA differs or checkout is dirty"):
                validate_runtime(lock, runtime, checkout, executable)

    def test_missing_build_output_is_classified(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            commit = git_repository(checkout)
            (checkout / "evidence.txt").write_text("controls\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(checkout), "add", "evidence.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(checkout), "-c", "user.name=Bench", "-c", "user.email=bench@example.invalid", "commit", "-qm", "evidence"],
                check=True,
            )
            commit = subprocess.run(
                ["git", "-C", str(checkout), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            lock = source_lock() | {"resolved_commit": commit}
            with self.assertRaisesRegex(CodeGraphError, "codegraph_build_failure"):
                validate_runtime(lock, {}, checkout, checkout / "missing")


class IndexTests(unittest.TestCase):
    def _frozen_attempt_fixture(self, root: Path) -> tuple[dict, dict, dict, Path, Path]:
        master_repository = root / "master-repository"
        child_repository = root / "child-repository"
        master_repository.mkdir()
        child_repository.mkdir()
        master = root / "frozen-index"
        master.mkdir()
        (master / "graph.db").write_bytes(b"frozen graph bytes")
        artifact_manifest = directory_manifest(master)
        (master / "graph.db").chmod(0o400)
        master.chmod(0o500)
        record = {
            "task_id": "task",
            "repository_path": str(master_repository),
            "index_path": str(master),
            "identity": {"identity_sha256": "a" * 64},
            "index_artifact_manifest": artifact_manifest,
            "status": parse_status(
                upstream_status(master_repository, master),
                master_repository,
            ),
        }
        lock = source_lock()
        runtime = {
            "runtime_home": str(root / "runtime-home"),
            "executable_path": str(root / "fixture-codegraph"),
        }
        return record, lock, runtime, master_repository, child_repository

    @staticmethod
    def _attempt_runtime_stage(root: Path) -> dict:
        return {
            "stage_root": str(root / "runtime-stage"),
            "node_executable": str(root / "runtime-stage" / "bin" / "node"),
            "codegraph_executable": str(root / "runtime-stage" / "dist" / "cli.js"),
            "runtime_bundle_manifest_sha256": "b" * 64,
            "node_executable_sha256": "c" * 64,
            "codegraph_executable_sha256": "d" * 64,
        }

    def test_status_unknown_format_fails_closed(self):
        with self.assertRaisesRegex(CodeGraphError, "codegraph_status_invalid"):
            parse_status("ready=yes", Path("/repo"))

    def test_status_wrong_project_is_distinct(self):
        value = json.dumps({
            "initialized": True, "version": "1.2.3", "projectPath": "/other",
            "indexPath": "/other/.codegraph", "lastIndexed": "now",
            "fileCount": 1, "nodeCount": 1, "edgeCount": 0,
            "index": {"state": "complete", "pendingRefs": 0},
        })
        with self.assertRaisesRegex(CodeGraphError, "codegraph_wrong_project"):
            parse_status(value, Path("/repo"))

    def test_index_identity_changes_with_revision(self):
        lock = source_lock()
        first = index_identity(lock, "task", "1" * 40, {"version": 1})
        second = index_identity(lock, "task", "2" * 40, {"version": 1})
        self.assertNotEqual(first["identity_sha256"], second["identity_sha256"])

    def test_source_manifest_excludes_benchmark_control_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "module.py").write_text("pass\n", encoding="utf-8")
            output = root / ".benchmark-runs"
            output.mkdir()
            (output / "ground_truth.json").write_text("{}", encoding="utf-8")
            manifest = source_manifest(root, {".benchmark-runs"})
            self.assertEqual([row["path"] for row in manifest["files"]], ["module.py"])

    def test_prepare_and_freshness_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repo"
            repository.mkdir()
            commit = git_repository(repository)
            lock = source_lock() | {"resolved_commit": "b" * 40}
            executable = root / "codegraph"
            executable.write_text("fixture", encoding="utf-8")
            runtime = {"executable_path": str(executable), "executable_sha256": sha256_file(executable)}
            index_dir = root / "index"
            config = {"exclude_names": [".git"], "version": 1}
            calls = []

            def fake_run(command, **kwargs):
                calls.append(command)
                candidate = repository / kwargs["env"]["CODEGRAPH_DIR"]
                if "init" in command:
                    candidate.mkdir()
                    candidate.joinpath("graph.db").write_text("graph", encoding="utf-8")
                    return SimpleNamespace(returncode=0, stdout="indexed", stderr="")
                return SimpleNamespace(returncode=0, stdout=upstream_status(repository, candidate), stderr="")

            record = prepare_index(
                lock=lock,
                runtime=runtime,
                task_id="task",
                base_commit=commit,
                repository=repository,
                index_dir=index_dir,
                log_dir=root / "logs",
                configuration=config,
                run_process=fake_run,
            )
            self.assertTrue(record["ready"])
            self.assertEqual(len(calls), 2)
            self.assertEqual(
                validate_index(
                    record,
                    lock=lock,
                    runtime=runtime,
                    task_id="task",
                    base_commit=commit,
                    repository=repository,
                    configuration=config,
                )["identity"],
                record["identity"],
            )
            (repository / "module.py").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(CodeGraphError, "codegraph_index_stale"):
                validate_index(
                    record,
                    lock=lock,
                    runtime=runtime,
                    task_id="task",
                    base_commit=commit,
                    repository=repository,
                    configuration=config,
                )
            os.chmod(index_dir, 0o700)
            for path in index_dir.rglob("*"):
                path.chmod(0o700 if path.is_dir() else 0o600)

    def test_failed_preparation_is_retained_and_retry_promotes_fresh_index(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repo"
            repository.mkdir()
            commit = git_repository(repository)
            lock = source_lock() | {"resolved_commit": "b" * 40}
            executable = root / "codegraph"
            executable.write_text("fixture", encoding="utf-8")
            runtime = {"executable_path": str(executable), "executable_sha256": sha256_file(executable)}
            index_dir = root / "index"
            config = {"exclude_names": [".git"], "version": 1}

            def failing(command, **kwargs):
                return SimpleNamespace(returncode=9, stdout="partial", stderr="index exploded")

            with self.assertRaisesRegex(CodeGraphError, "codegraph_index_failure"):
                prepare_index(
                    lock=lock,
                    runtime=runtime,
                    task_id="task",
                    base_commit=commit,
                    repository=repository,
                    index_dir=index_dir,
                    log_dir=root / "ignored",
                    configuration=config,
                    run_process=failing,
                )
            failed_record = json.loads(
                (root / "index.preparation-attempts" / "attempt-001" / "preparation.json").read_text()
            )
            self.assertFalse(failed_record["succeeded"])
            self.assertEqual(failed_record["failure_class"], "codegraph_index_failure")
            self.assertEqual((root / "index.preparation-attempts" / "attempt-001" / "logs" / "index.stderr").read_text(), "index exploded")
            self.assertFalse(index_dir.exists())

            def succeeding(command, **kwargs):
                candidate = repository / kwargs["env"]["CODEGRAPH_DIR"]
                if "init" in command:
                    candidate.mkdir()
                    candidate.joinpath("graph.db").write_text("complete graph", encoding="utf-8")
                    return SimpleNamespace(returncode=0, stdout="indexed", stderr="")
                return SimpleNamespace(returncode=0, stdout=upstream_status(repository, candidate), stderr="")

            record = prepare_index(
                lock=lock,
                runtime=runtime,
                task_id="task",
                base_commit=commit,
                repository=repository,
                index_dir=index_dir,
                log_dir=root / "ignored",
                configuration=config,
                run_process=succeeding,
            )
            self.assertEqual((index_dir / "graph.db").read_text(), "complete graph")
            self.assertTrue(
                json.loads(
                    (root / "index.preparation-attempts" / "attempt-002" / "preparation.json").read_text()
                )["succeeded"]
            )
            self.assertTrue(record["ready"])
            os.chmod(index_dir, 0o700)
            (index_dir / "graph.db").chmod(0o600)

    def test_index_spawn_failure_is_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repo"
            repository.mkdir()
            commit = git_repository(repository)
            lock = source_lock() | {"resolved_commit": "b" * 40}
            executable = root / "codegraph"
            executable.write_text("fixture", encoding="utf-8")
            runtime = {"executable_path": str(executable), "executable_sha256": sha256_file(executable)}

            def cannot_spawn(command, **kwargs):
                raise OSError("sandbox unavailable")

            with self.assertRaisesRegex(CodeGraphError, "attempt retained"):
                prepare_index(
                    lock=lock,
                    runtime=runtime,
                    task_id="task",
                    base_commit=commit,
                    repository=repository,
                    index_dir=root / "index",
                    log_dir=root / "ignored",
                    configuration={"exclude_names": [".git"], "version": 1},
                    run_process=cannot_spawn,
                )
            attempt_root = root / "index.preparation-attempts" / "attempt-001"
            record = json.loads((attempt_root / "preparation.json").read_text())
            self.assertEqual(record["failure_class"], "codegraph_index_failure")
            self.assertIn("sandbox unavailable", (attempt_root / "logs" / "index.stderr").read_text())

    def test_index_artifact_mutation_truncation_and_addition_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repo"
            repository.mkdir()
            commit = git_repository(repository)
            lock = source_lock() | {"resolved_commit": "b" * 40}
            executable = root / "codegraph"
            executable.write_text("fixture", encoding="utf-8")
            runtime = {"executable_path": str(executable), "executable_sha256": sha256_file(executable)}
            index_dir = root / "index"
            config = {"exclude_names": [".git"], "version": 1}

            def fake_run(command, **kwargs):
                candidate = repository / kwargs["env"]["CODEGRAPH_DIR"]
                if "init" in command:
                    candidate.mkdir()
                    candidate.joinpath("graph.db").write_bytes(b"immutable graph bytes")
                    return SimpleNamespace(returncode=0, stdout="indexed", stderr="")
                return SimpleNamespace(returncode=0, stdout=upstream_status(repository, candidate), stderr="")

            record = prepare_index(
                lock=lock,
                runtime=runtime,
                task_id="task",
                base_commit=commit,
                repository=repository,
                index_dir=index_dir,
                log_dir=root / "ignored",
                configuration=config,
                run_process=fake_run,
            )
            os.chmod(index_dir, 0o700)
            graph = index_dir / "graph.db"
            graph.chmod(0o600)
            original = graph.read_bytes()
            for mutate, restore in (
                (lambda: graph.write_bytes(b""), lambda: graph.write_bytes(original)),
                (
                    lambda: (index_dir / "unexpected.bin").write_bytes(b"x"),
                    lambda: (index_dir / "unexpected.bin").unlink(),
                ),
            ):
                mutate()
                with self.assertRaisesRegex(CodeGraphError, "index artifact additions, removals, or bytes differ"):
                    validate_index(
                        record,
                        lock=lock,
                        runtime=runtime,
                        task_id="task",
                        base_commit=commit,
                        repository=repository,
                        configuration=config,
                    )
                restore()
            graph.chmod(0o400)
            index_dir.chmod(0o500)
            self.assertIs(
                validate_index(
                    record,
                    lock=lock,
                    runtime=runtime,
                    task_id="task",
                    base_commit=commit,
                    repository=repository,
                    configuration=config,
                ),
                record,
            )

    def test_attempt_copy_success_and_exception_cleanup_preserve_master(self):
        for raise_inside in (False, True):
            with self.subTest(raise_inside=raise_inside), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                record, lock, _runtime, master_repository, child_repository = (
                    self._frozen_attempt_fixture(root)
                )
                before = directory_manifest(Path(record["index_path"]))

                def fake_run(command, **kwargs):
                    copy = child_repository / kwargs["env"]["CODEGRAPH_DIR"]
                    return SimpleNamespace(
                        returncode=0,
                        stdout=upstream_status(child_repository, copy),
                        stderr="",
                    )

                with self.assertRaisesRegex(RuntimeError, "attempt failed") if raise_inside else nullcontext():
                    with attempt_index_copy(
                        record=record,
                        lock=lock,
                        master_repository=master_repository,
                        child_repository=child_repository,
                        attempt_root=root / "attempt",
                        evidence_root=root / "evidence",
                        runtime_stage=self._attempt_runtime_stage(root),
                        run_process=fake_run,
                    ) as prepared:
                        Path(prepared["index_path"], "catchup.tmp").write_text(
                            "copy-only mutation", encoding="utf-8"
                        )
                        if raise_inside:
                            raise RuntimeError("attempt failed")
                lifecycle = json.loads((root / "evidence" / "lifecycle.json").read_text())
                self.assertTrue(lifecycle["cleanup_complete"])
                self.assertTrue(lifecycle["copy_changed_during_attempt"])
                self.assertTrue(lifecycle["master_unchanged"])
                self.assertFalse(Path(lifecycle["copy_path"]).exists())
                self.assertEqual(directory_manifest(Path(record["index_path"])), before)

    def test_attempt_copy_semantic_divergence_cleans_up(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record, lock, _runtime, master_repository, child_repository = (
                self._frozen_attempt_fixture(root)
            )

            def divergent(command, **kwargs):
                copy = child_repository / kwargs["env"]["CODEGRAPH_DIR"]
                status = json.loads(upstream_status(child_repository, copy))
                status["nodeCount"] = 99
                return SimpleNamespace(returncode=0, stdout=json.dumps(status), stderr="")

            with self.assertRaisesRegex(CodeGraphError, "semantic status differs"):
                with attempt_index_copy(
                    record=record,
                    lock=lock,
                    master_repository=master_repository,
                    child_repository=child_repository,
                    attempt_root=root / "attempt",
                    evidence_root=root / "evidence",
                    runtime_stage=self._attempt_runtime_stage(root),
                    run_process=divergent,
                ):
                    self.fail("semantic divergence must refuse before yield")
            lifecycle = json.loads((root / "evidence" / "lifecycle.json").read_text())
            self.assertTrue(lifecycle["cleanup_complete"])
            self.assertFalse(Path(lifecycle["copy_path"]).exists())

    def test_attempt_copy_byte_divergence_refuses_before_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record, lock, _runtime, master_repository, child_repository = (
                self._frozen_attempt_fixture(root)
            )
            record["index_artifact_manifest"] = record["index_artifact_manifest"] | {
                "sha256": "0" * 64
            }
            with self.assertRaisesRegex(CodeGraphError, "frozen master bytes or modes differ"):
                with attempt_index_copy(
                    record=record,
                    lock=lock,
                    master_repository=master_repository,
                    child_repository=child_repository,
                    attempt_root=root / "attempt",
                    evidence_root=root / "evidence",
                    runtime_stage=self._attempt_runtime_stage(root),
                ):
                    self.fail("byte divergence must refuse before yield")
            self.assertFalse(any(child_repository.glob(".codegraph-attempt-*")))

    def test_frozen_status_semantic_failure_always_removes_validation_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record, lock, runtime, repository, _child = self._frozen_attempt_fixture(root)
            Path(runtime["runtime_home"]).mkdir()

            def divergent(command, **kwargs):
                copy = repository / kwargs["env"]["CODEGRAPH_DIR"]
                status = json.loads(upstream_status(repository, copy))
                status["edgeCount"] = 77
                return SimpleNamespace(returncode=0, stdout=json.dumps(status), stderr="")

            with self.assertRaisesRegex(CodeGraphError, "semantic status differs"):
                validate_frozen_index_status(
                    record,
                    lock=lock,
                    runtime=runtime,
                    repository=repository,
                    validation_root=root / "validation",
                    run_process=divergent,
                )
            validation = json.loads(
                (root / "validation" / "copy-validation" / "validation.json").read_text()
            )
            self.assertTrue(validation["validation_copy_removed"])
            self.assertTrue(validation["master_unchanged_after_cleanup"])


if __name__ == "__main__":
    unittest.main()
