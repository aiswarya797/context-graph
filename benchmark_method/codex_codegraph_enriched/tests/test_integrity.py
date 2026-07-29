from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
sys.path.insert(0, str(ROOT / "src"))

from codegraph_bench.integrity import (
    IntegrityError,
    ATTEMPT_RECORD_SCHEMA,
    RUN_MANIFEST_SCHEMA,
    resolve_controlled_setup_path,
    resolve_run_root,
    validate_attempt_records,
    validate_run_manifest,
    validate_run_id,
)
from codegraph_bench.schema_validation import SchemaValidationError, validate_instance
from benchmark_method.codex_codegraph_enriched.tests.task5_test_support import (
    bind_enriched_authority,
)


BASELINE_RUN_ID = "baseline-20260725-final-20260725T204500Z"


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix().encode()
        digest.update(relative)
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()


class MutationBoundaryTests(unittest.TestCase):
    def test_baseline_score_refuses_before_byte_for_byte_write(self):
        baseline = REPO / ".benchmark-runs" / BASELINE_RUN_ID
        self.assertTrue(baseline.is_dir())
        before = tree_digest(baseline)
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "benchmark.py"),
                "score",
                "--run-id",
                BASELINE_RUN_ID,
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("baseline and historical run IDs are read-only", result.stderr)
        self.assertEqual(tree_digest(baseline), before)

    def test_run_id_must_be_one_safe_treatment_component(self):
        for value in ("../codex-codegraph-enriched-x", "codex-codegraph-enriched/x", ".", "baseline-old", "/tmp/x"):
            with self.subTest(value=value), self.assertRaises(IntegrityError):
                validate_run_id(value)
        self.assertEqual(validate_run_id("codex-codegraph-enriched-20260727"), "codex-codegraph-enriched-20260727")
        self.assertEqual(validate_run_id("codex-codegraph-enriched-smoke-20260727", smoke=True), "codex-codegraph-enriched-smoke-20260727")

    def test_symlinked_run_root_refuses_containment(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            runs = repository / ".benchmark-runs"
            outside = Path(temporary) / "outside"
            runs.mkdir(parents=True)
            outside.mkdir()
            (runs / "codex-codegraph-enriched-linked").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(IntegrityError, "escapes .benchmark-runs|symlinked run roots"):
                resolve_run_root(repository, "codex-codegraph-enriched-linked")

    def test_setup_overrides_cannot_target_frozen_baseline_and_do_not_write(self):
        baseline = REPO / ".benchmark-runs" / BASELINE_RUN_ID
        before = tree_digest(baseline)
        overrides = {
            "CODEGRAPH_SOURCE_LOCK": baseline / "freeze-report.json",
            "CODEGRAPH_SOURCE_CHECKOUT": baseline,
            "CODEGRAPH_RUNTIME_RECORD": baseline / "validation.json",
            "CODEGRAPH_INDEX_ROOT": baseline,
        }
        for variable, target in overrides.items():
            environment = dict(os.environ)
            environment[variable] = str(target)
            result = subprocess.run(
                [sys.executable, str(ROOT / "benchmark.py"), "codegraph-prepare"],
                cwd=REPO,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            with self.subTest(variable=variable):
                self.assertEqual(result.returncode, 2)
                self.assertIn("task2_evidence_refused", result.stderr)
                self.assertEqual(tree_digest(baseline), before)

    def test_setup_paths_reject_traversal_absolute_escape_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            controlled = repository / ".benchmark-tools" / "codegraph"
            outside = Path(temporary) / "outside"
            controlled.mkdir(parents=True)
            outside.mkdir()
            (controlled / "linked").symlink_to(outside, target_is_directory=True)
            self.assertEqual(
                resolve_controlled_setup_path(
                    repository,
                    str(controlled / "runtime" / "runtime.json"),
                    controlled_root=".benchmark-tools/codegraph",
                    field="fixture",
                ),
                controlled / "runtime" / "runtime.json",
            )
            for value in (
                ".benchmark-tools/codegraph/../escape",
                str(outside / "escape"),
                ".benchmark-tools/codegraph/linked/runtime.json",
                ".benchmark-runs/baseline/freeze-report.json",
            ):
                with self.subTest(value=value), self.assertRaises(IntegrityError):
                    resolve_controlled_setup_path(
                        repository,
                        value,
                        controlled_root=".benchmark-tools/codegraph",
                        field="fixture",
                    )


class SchemaBoundaryTests(unittest.TestCase):
    def base_record(self):
        return {
            "run_id": "codex-codegraph-enriched-fixture",
            "arm": "codex-codegraph-enriched",
            "task_id": "task",
            "sample_id": 1,
            "attempt_id": "attempt-001",
            "attempt_number": 1,
            "validity": {
                "execution": True,
                "response": True,
                "provenance": True,
                "index": True,
                "mcp": True,
                "graph_use": True,
                "contamination": True,
                "telemetry": True,
                "scoring": False,
                "cost": False,
            },
            "treatment_valid": True,
            "adopted_for_slot": True,
            "claimable_sample": False,
            "quality_valid": False,
            "score_valid": False,
            "failure_class": None,
            "failure_classes": [],
            "navigation": {},
            "index_identity": {},
            "runtime_provenance": {},
            "artifact_sha256": {},
            "artifacts": {"attempt": "attempts/task/sample-01/attempt-001"},
        }

    def test_duplicate_attempt_and_artifact_references_refuse(self):
        record = self.base_record()
        with self.assertRaisesRegex(IntegrityError, "duplicate attempt or artifact reference"):
            validate_attempt_records(
                [record, dict(record)],
                run_id=record["run_id"],
                task_ids={"task"},
                required_samples=3,
            )

    def test_checked_in_attempt_schema_and_boundary_reject_boolean_integer_and_missing_authorities(self):
        for mutation in (
            {"sample_id": True},
            {"attempt_number": True},
            {"navigation": None},
            {"index_identity": None},
            {"runtime_provenance": None},
        ):
            record = self.base_record()
            for key, value in mutation.items():
                if value is None:
                    record.pop(key)
                else:
                    record[key] = value
            with self.subTest(mutation=mutation):
                with self.assertRaises(SchemaValidationError):
                    validate_instance(record, ATTEMPT_RECORD_SCHEMA)
                with self.assertRaisesRegex(IntegrityError, "schema_validation_failed"):
                    validate_attempt_records(
                        [record],
                        run_id="codex-codegraph-enriched-fixture",
                        task_ids={"task"},
                        required_samples=3,
                    )

    def test_run_manifest_schema_and_boundary_reject_boolean_sample_count_and_reduced_full_run(self):
        tasks = [{"instance_id": f"task-{number:02d}", "base_commit": f"{number:040x}"} for number in range(24)]
        manifest = {
            "run_id": "codex-codegraph-enriched-fixture",
            "arm": "codex-codegraph-enriched",
            "protocol": "codegraph-region-v1",
            "configuration": {
                "requested_model": "gpt-5.6-luna",
                "requested_reasoning_effort": "high",
                "codex_version": "0.145.0",
                "sample_count": True,
                "retry_cap": 2,
                "timeout_seconds": 900,
                "max_regions": 5,
                "output_schema_sha256": "a" * 64,
                "configuration_sha256": "b" * 64,
                "harness_sha256": "c" * 64,
            },
            "corpus": {
                "unique_task_count": 24,
                "tasks": tasks,
                "artifact": {"path": "corpus.jsonl"},
                "task_identity_sha256": "d" * 64,
                "source_manifest_sha256": "e" * 64,
            },
            "evaluator": {"commit": "pinned", "sha256": "f" * 64},
            "codegraph": {
                "source_lock": "source-lock.json",
                "source_lock_sha256": "1" * 64,
                "runtime_record": "codegraph-runtime.json",
                "runtime_record_sha256": "2" * 64,
                "mcp_network_isolation": {
                    "mode": "sandbox-exec-child-network-deny-v1",
                    "profile_sha256": "3" * 64,
                    "verified": True,
                },
            },
            "indexes": {"records": []},
            "treatment_differences": [
                "CodeGraph-use prompt addition",
                "pinned immutable CodeGraph index",
                "per-attempt CodeGraph MCP server",
            ],
        }
        with self.assertRaises(SchemaValidationError):
            validate_instance(manifest, RUN_MANIFEST_SCHEMA)
        with self.assertRaisesRegex(IntegrityError, "schema_validation_failed"):
            validate_run_manifest(manifest)
        manifest["configuration"]["sample_count"] = 1
        manifest["corpus"]["tasks"] = tasks[:1]
        manifest["corpus"]["unique_task_count"] = 1
        with tempfile.TemporaryDirectory() as temporary:
            bind_enriched_authority(
                Path(temporary),
                manifest["codegraph"],
                index_count=1,
            )
        with self.assertRaisesRegex(IntegrityError, "24 unique tasks x 3 samples"):
            validate_run_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
