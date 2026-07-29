from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("codegraph_benchmark_smoke_tests", ROOT / "benchmark.py")
assert SPEC and SPEC.loader
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


class SmokeGateTests(unittest.TestCase):
    def config(self, temporary: Path):
        return benchmark.load_config()

    def valid_doctor_fixture(self, root: Path):
        doctor_root = root / "doctor"
        doctor_root.mkdir()
        evidence_root = root / "task2-root.json"
        evidence_root.write_text("{}\n", encoding="utf-8")
        codex = root / "codex"
        codex.write_bytes(b"codex")
        bundle = root / "runtime-bundle.json"
        bundle.write_text(
            json.dumps({"manifest_sha256": "d" * 64}) + "\n",
            encoding="utf-8",
        )
        identity = {"identity_sha256": "a" * 64}
        runtime = {
            "executable_sha256": "c" * 64,
            "runtime_bundle_manifest": {"path": str(bundle)},
            "toolchain": {
                "node": {"executable_sha256": "e" * 64},
            },
        }
        record = {
            "schema_version": "codegraph-doctor-v1",
            "passed": True,
            "return_code": 0,
            "response_valid": True,
            "telemetry": {"valid": True},
            "navigation": {"graph_use_valid": True},
            "contamination_audit": {"passed": True},
            "real_envelope_integration": benchmark.LIVE_CODEGRAPH_ENVELOPE,
            "runtime": {
                "codex_version": "0.145.0",
                "codex_executable_sha256": benchmark.file_sha256(codex),
                "codegraph_source_commit": "b" * 40,
                "codegraph_executable_sha256": "c" * 64,
                "index_identity": identity,
                "task2_evidence_root_sha256": benchmark.sha256_file(
                    evidence_root
                ),
                "task2_evidence_entry_count": 10,
                "runtime_stage": {
                    "stage_root": "/private/tmp/doctor-stage",
                    "node_executable": (
                        "/private/tmp/doctor-stage/bin/node"
                    ),
                    "codegraph_executable": (
                        "/private/tmp/doctor-stage/dist/bin/codegraph.js"
                    ),
                    "runtime_bundle_manifest_sha256": "d" * 64,
                    "node_executable_sha256": "e" * 64,
                    "codegraph_executable_sha256": "c" * 64,
                },
            },
        }
        return doctor_root, evidence_root, codex, identity, runtime, record

    def test_attempt_repository_validation_uses_frozen_index_source_and_checks_measured_parity(self):
        master = Path("/benchmark/index-source")
        measured = Path("/benchmark/measured-worktree")
        task = {
            "instance_id": "task",
            "base_commit": "a" * 40,
            "prepared": {"resolved_path": str(measured)},
        }
        record = {
            "source_manifest_sha256": "b" * 64,
        }
        config = {
            "index": {
                "configuration_version": 1,
                "exclude_names": [".git"],
                "directory_prefix": ".codegraph-",
            },
            "runtime": {
                "telemetry": False,
                "shared_daemon": False,
                "network_during_attempt": False,
            },
        }
        with (
            mock.patch.object(
                benchmark,
                "_task_repository",
                return_value=master,
            ),
            mock.patch.object(
                benchmark,
                "verify_repository_head",
            ) as verify_repository_head,
            mock.patch.object(
                benchmark,
                "_require_task4_authority",
                return_value={"records_by_task": {"task": {}}},
            ),
            mock.patch.object(
                benchmark,
                "validate_enriched_index",
            ) as validate_enriched_index,
            mock.patch.object(
                benchmark,
                "source_manifest",
                return_value={"sha256": "b" * 64},
            ) as source_manifest,
        ):
            repositories = benchmark._validate_attempt_repositories(
                config,
                task,
                record,
                {"resolved_commit": "c" * 40},
                {"executable_sha256": "d" * 64},
            )

        self.assertEqual(
            repositories,
            {
                "measured_repository": measured,
                "index_master_repository": master,
            },
        )
        verify_repository_head.assert_called_once_with(measured, "a" * 40)
        self.assertEqual(
            validate_enriched_index.call_args.kwargs["record"],
            record,
        )
        self.assertEqual(
            validate_enriched_index.call_args.kwargs["task_id"],
            "task",
        )
        source_manifest.assert_called_once_with(
            measured,
            {".git"},
        )

    def test_attempt_repository_validation_refuses_measured_source_drift(self):
        task = {
            "instance_id": "task",
            "base_commit": "a" * 40,
            "prepared": {"resolved_path": "/benchmark/measured-worktree"},
        }
        config = {
            "index": {
                "configuration_version": 1,
                "exclude_names": [".git"],
                "directory_prefix": ".codegraph-",
            },
            "runtime": {
                "telemetry": False,
                "shared_daemon": False,
                "network_during_attempt": False,
            },
        }
        with (
            mock.patch.object(
                benchmark,
                "_task_repository",
                return_value=Path("/benchmark/index-source"),
            ),
            mock.patch.object(
                benchmark,
                "verify_repository_head",
            ),
            mock.patch.object(
                benchmark,
                "_require_task4_authority",
                return_value={"records_by_task": {"task": {}}},
            ),
            mock.patch.object(
                benchmark,
                "validate_enriched_index",
            ),
            mock.patch.object(
                benchmark,
                "source_manifest",
                return_value={"sha256": "c" * 64},
            ),
        ):
            with self.assertRaisesRegex(
                benchmark.CodeGraphError,
                "measured repository source differs",
            ):
                benchmark._validate_attempt_repositories(
                    config,
                    task,
                    {"source_manifest_sha256": "b" * 64},
                    {"resolved_commit": "d" * 40},
                    {"executable_sha256": "e" * 64},
                )

    def test_full_run_remains_fail_closed_without_verified_smoke_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            with mock.patch.object(benchmark, "_smoke_gate_path", return_value=Path(temporary) / "smoke-gate.json"):
                with self.assertRaisesRegex(benchmark.RunnerError, "smoke_gate_required"):
                    benchmark._require_smoke_gate(
                        config,
                        {"resolved_commit": "a" * 40},
                        {},
                        [{"instance_id": "task", "base_commit": "b" * 40}],
                        "codex-codegraph-enriched-full",
                    )

    def test_irrelevant_gate_binding_and_missing_manual_ack_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            gate_path = Path(temporary) / "smoke-gate.json"
            gate_path.parent.mkdir(parents=True, exist_ok=True)
            gate_path.write_text(
                json.dumps(
                    {
                        "schema_version": "codegraph-smoke-gate-v2",
                        "passed": True,
                        "smoke_run_id": "codex-codegraph-enriched-smoke-fixture",
                        "binding": {"trust": "me"},
                        "manual_inspection": {"acknowledged": True},
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(benchmark, "_smoke_gate_path", return_value=gate_path), mock.patch.object(
                benchmark, "_current_gate_binding", return_value={"exact": "binding"}
            ):
                with self.assertRaisesRegex(benchmark.RunnerError, "binding differs"):
                    benchmark._require_smoke_gate(
                        config,
                        {},
                        {},
                        [{"instance_id": "task", "base_commit": "b" * 40}],
                        "codex-codegraph-enriched-full",
                    )
            gate = json.loads(gate_path.read_text())
            gate["binding"] = {"exact": "binding"}
            gate["manual_inspection"] = {"acknowledged": False}
            gate_path.write_text(json.dumps(gate), encoding="utf-8")
            with mock.patch.object(benchmark, "_smoke_gate_path", return_value=gate_path):
                with self.assertRaisesRegex(benchmark.RunnerError, "manual inspection"):
                    benchmark._require_smoke_gate(
                        config,
                        {},
                        {},
                        [{"instance_id": "task", "base_commit": "b" * 40}],
                        "codex-codegraph-enriched-full",
                    )

    def test_gate_creation_requires_explicit_manual_ack_before_any_io(self):
        with self.assertRaisesRegex(benchmark.RunnerError, "ack-manual-inspection"):
            benchmark.create_smoke_gate(
                argparse.Namespace(
                    run_id="codex-codegraph-enriched-smoke-fixture",
                    ack_manual_inspection=False,
                    inspected_manifest_sha256=None,
                )
            )

    def test_gate_creation_requires_exact_inspected_manifest_digest(self):
        with self.assertRaisesRegex(
            benchmark.RunnerError,
            "inspected-manifest-sha256",
        ):
            benchmark.create_smoke_gate(
                argparse.Namespace(
                    run_id="codex-codegraph-enriched-smoke-fixture",
                    ack_manual_inspection=True,
                    inspected_manifest_sha256="not-a-sha",
                )
            )

    def test_attempt_launch_failures_get_stable_class_and_raw_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            result = benchmark._retained_failure_result(
                state,
                benchmark.RunnerError(
                    "mcp_startup_failure: fixture spawn refused"
                ),
                started=0.0,
            )
            self.assertEqual(
                result["failure_class"],
                "mcp_startup_failure",
            )
            self.assertTrue(Path(result["events_path"]).is_file())
            self.assertIn(
                "fixture spawn refused",
                Path(result["stderr_path"]).read_text(encoding="utf-8"),
            )

    def test_stale_doctor_evidence_root_refuses_smoke(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            doctor_root = root / "doctor"
            doctor_root.mkdir()
            evidence_root = root / "task2-root.json"
            evidence_root.write_text("{}\n", encoding="utf-8")
            codex = root / "codex"
            codex.write_bytes(b"codex")
            identity = {"identity_sha256": "a" * 64}
            record = {
                "schema_version": "codegraph-doctor-v1",
                "passed": True,
                "return_code": 0,
                "response_valid": True,
                "telemetry": {"valid": True},
                "navigation": {"graph_use_valid": True},
                "contamination_audit": {"passed": True},
                "real_envelope_integration": (
                    benchmark.LIVE_CODEGRAPH_ENVELOPE
                ),
                "runtime": {
                    "codex_version": "0.145.0",
                    "codex_executable_sha256": (
                        benchmark.file_sha256(codex)
                    ),
                    "codegraph_source_commit": "b" * 40,
                    "codegraph_executable_sha256": "c" * 64,
                    "index_identity": identity,
                    "task2_evidence_root_sha256": "0" * 64,
                    "task2_evidence_entry_count": 10,
                },
            }
            (doctor_root / "doctor.json").write_text(
                json.dumps(record),
                encoding="utf-8",
            )
            with (
                mock.patch.object(
                    benchmark,
                    "paths",
                    return_value={
                        "enriched_doctor": doctor_root,
                        "task2_evidence_root": evidence_root,
                    },
                ),
                mock.patch.object(
                    benchmark,
                    "_load_doctor_preparation",
                    return_value=(
                        {},
                        {"identity": identity},
                    ),
                ),
            ):
                with self.assertRaisesRegex(
                    benchmark.RunnerError,
                    "current passing CodeGraph doctor required",
                ):
                    benchmark._require_current_doctor(
                        {},
                        task2_evidence={"entry_count": 10},
                        lock={"resolved_commit": "b" * 40},
                        runtime={"executable_sha256": "c" * 64},
                        codex=codex,
                        codex_version="0.145.0",
                    )

    def test_missing_runtime_stage_refuses_before_smoke(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                doctor_root,
                evidence_root,
                codex,
                identity,
                runtime,
                record,
            ) = self.valid_doctor_fixture(root)
            del record["runtime"]["runtime_stage"]
            (doctor_root / "doctor.json").write_text(
                json.dumps(record),
                encoding="utf-8",
            )
            with (
                mock.patch.object(
                    benchmark,
                    "paths",
                    return_value={
                        "enriched_doctor": doctor_root,
                        "task2_evidence_root": evidence_root,
                    },
                ),
                mock.patch.object(
                    benchmark,
                    "_load_doctor_preparation",
                    return_value=({}, {"identity": identity}),
                ),
                self.assertRaisesRegex(
                    benchmark.RunnerError,
                    "current passing CodeGraph doctor required",
                ),
            ):
                benchmark._require_current_doctor(
                    {},
                    task2_evidence={"entry_count": 10},
                    lock={"resolved_commit": "b" * 40},
                    runtime=runtime,
                    codex=codex,
                    codex_version="0.145.0",
                )

    def test_mismatched_runtime_stage_refuses_before_smoke(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                doctor_root,
                evidence_root,
                codex,
                identity,
                runtime,
                record,
            ) = self.valid_doctor_fixture(root)
            record["runtime"]["runtime_stage"][
                "runtime_bundle_manifest_sha256"
            ] = "0" * 64
            (doctor_root / "doctor.json").write_text(
                json.dumps(record),
                encoding="utf-8",
            )
            with (
                mock.patch.object(
                    benchmark,
                    "paths",
                    return_value={
                        "enriched_doctor": doctor_root,
                        "task2_evidence_root": evidence_root,
                    },
                ),
                mock.patch.object(
                    benchmark,
                    "_load_doctor_preparation",
                    return_value=({}, {"identity": identity}),
                ),
                self.assertRaisesRegex(
                    benchmark.RunnerError,
                    "current passing CodeGraph doctor required",
                ),
            ):
                benchmark._require_current_doctor(
                    {},
                    task2_evidence={"entry_count": 10},
                    lock={"resolved_commit": "b" * 40},
                    runtime=runtime,
                    codex=codex,
                    codex_version="0.145.0",
                )

    def test_inspection_recomputes_official_score_and_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary)
            with (
                mock.patch.object(
                    benchmark,
                    "paths",
                    return_value={
                        "evaluator": run_root / "eval.py",
                        "provenance": run_root / "provenance.json",
                    },
                ),
                mock.patch.object(
                    benchmark,
                    "score_run",
                    return_value=[{"attempt_id": "attempt-001"}],
                ) as score_run,
                mock.patch.object(
                    benchmark,
                    "rebuild_report",
                    return_value={"claimable": True},
                ) as rebuild_report,
                mock.patch.object(
                    benchmark,
                    "_build_smoke_inspection_manifest",
                    return_value={"artifact_count": 1},
                ),
            ):
                records, report, inspection = (
                    benchmark._prepare_smoke_inspection(
                        {},
                        run_root,
                        {"run_id": "codex-codegraph-enriched-smoke-fixture"},
                    )
                )
            self.assertEqual(records[0]["attempt_id"], "attempt-001")
            self.assertTrue(report["claimable"])
            self.assertEqual(inspection["artifact_count"], 1)
            score_run.assert_called_once()
            rebuild_report.assert_called_once()

    def test_smoke_manifest_projects_selected_task_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_root = root / "run"
            run_root.mkdir()
            files = {}
            for name in (
                "prompt",
                "schema",
                "source_lock",
                "runtime_record",
                "task2_evidence_root",
                "evaluator",
                "provenance",
                "task4_all24",
                "task4_sealed_root",
            ):
                files[name] = root / name
                files[name].write_text(f"{name}\n", encoding="utf-8")
            candidate = root / "task4-candidate-source.json"
            candidate.write_text("{}\n", encoding="utf-8")
            files["task4_sealed_root"].write_text(
                json.dumps(
                    {
                        "candidate": {
                            "candidate_evidence_root": {
                                "path": candidate.name,
                            }
                        }
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            codex = root / "codex"
            codex.write_bytes(b"codex")
            config = {
                "paths": {"codex_executable": str(codex)},
                "treatment": {
                    "model": "gpt-5.6-luna",
                    "reasoning_effort": "high",
                    "codex_version": "0.145.0",
                    "retry_cap": 2,
                    "timeout_seconds": 900,
                    "max_regions": 5,
                },
            }
            task = {
                "instance_id": "task",
                "repository_url": "https://example.invalid/repo.git",
                "base_commit": "a" * 40,
                "language": "Python",
                "issue_text": "issue",
                "source_memberships": ["select15"],
                "weight": 1.0,
            }
            with (
                mock.patch.object(
                    benchmark,
                    "paths",
                    return_value=files,
                ),
                mock.patch.object(
                    benchmark,
                    "verify_official_evaluator",
                    return_value={"commit": "e", "sha256": "f" * 64},
                ),
                mock.patch.object(
                    benchmark,
                    "resolve_executable",
                    return_value=codex,
                ),
                mock.patch.object(
                    benchmark,
                    "verify_pinned_version",
                    return_value="0.145.0",
                ),
                mock.patch.object(
                    benchmark,
                    "config_digest",
                    return_value="1" * 64,
                ),
                mock.patch.object(
                    benchmark,
                    "_harness_digest",
                    return_value="2" * 64,
                ),
                mock.patch.object(
                    benchmark,
                    "_require_task4_authority",
                    return_value={
                        "records_by_task": {"task": {}},
                        "task3_implementation": {"file_count": 23},
                    },
                ),
                mock.patch.object(benchmark, "ROOT", root),
            ):
                manifest = benchmark._run_manifest(
                    "codex-codegraph-enriched-smoke-fixture",
                    config,
                    [task],
                    {
                        "source_row_count": 25,
                        "unique_task_count": 24,
                    },
                    {
                        "repository_url": "https://example.invalid/cg.git",
                        "resolved_commit": "b" * 40,
                        "declared_version": "1.0.0",
                    },
                    {
                        "executable_sha256": "c" * 64,
                        "mcp_network_isolation": {
                            "mode": "deny",
                            "verified": True,
                        },
                    },
                    [{"task_id": "task"}],
                    run_root,
                    b'{"instance_id":"task"}\n',
                    1,
                )
            self.assertEqual(manifest["corpus"]["source_row_count"], 25)
            self.assertEqual(manifest["corpus"]["unique_task_count"], 1)
            self.assertEqual(len(manifest["corpus"]["tasks"]), 1)

    def test_setup_failure_retains_partial_artifact_identities(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary)
            partial = run_root / "source-lock.json"
            partial.write_text("lock\n", encoding="utf-8")
            record = benchmark._retain_setup_failure(
                run_root,
                "codex-codegraph-enriched-smoke-fixture",
                benchmark.RunnerError(
                    "schema_validation_failed: fixture"
                ),
            )
            self.assertFalse(record["provider_launch_reached"])
            self.assertEqual(
                record["partial_artifacts"][0]["sha256"],
                benchmark.sha256_file(partial),
            )
            with self.assertRaisesRegex(
                benchmark.RunnerError,
                "evidence already exists",
            ):
                benchmark._retain_setup_failure(
                    run_root,
                    "codex-codegraph-enriched-smoke-fixture",
                    benchmark.RunnerError("again"),
                )

    def test_non_smoke_one_by_one_and_removed_dimension_flags_refuse(self):
        with self.assertRaisesRegex(benchmark.RunnerError, "24 unique tasks x 3 samples"):
            benchmark._validate_run_dimensions([{"instance_id": "only"}], 1, smoke=False)
        for flag in ("--limit", "--samples"):
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "benchmark.py"),
                    "run",
                    "--run-id",
                    "codex-codegraph-enriched-reduced",
                    flag,
                    "1",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            with self.subTest(flag=flag):
                self.assertEqual(result.returncode, 2)
                self.assertIn("unrecognized arguments", result.stderr)


if __name__ == "__main__":
    unittest.main()
