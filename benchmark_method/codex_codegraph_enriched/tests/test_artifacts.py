from __future__ import annotations

import json
import hashlib
import copy
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from codegraph_bench.artifacts import diagnostic_scoreable, persist_attempt, sample_slot, treatment_valid, validate_attempt_record
from codegraph_bench.codegraph import sha256_value
from codegraph_bench.integrity import IntegrityError, load_treatment_manifest, validate_attempt_records
from benchmark_method.codex_codegraph_enriched.tests.task5_test_support import (
    bind_enriched_authority,
    enriched_index_authority,
)


class ArtifactValidityTests(unittest.TestCase):
    def attempt(
        self,
        root: Path,
        graph_valid: bool,
        *,
        verified_head: str | None = None,
    ):
        verified_head = verified_head or "a" * 40
        repository = root / "repo"
        repository.mkdir(exist_ok=True)
        (repository / "module.py").write_text("def f():\n    return 1\n", encoding="utf-8")
        state = root / ("state-valid" if graph_valid else "state-no-use")
        state.mkdir()
        response = {"regions": [{"path": "module.py", "start": 1, "end": 2, "reason": "implementation"}]}
        (state / "response.json").write_text(json.dumps(response), encoding="utf-8")
        (state / "events.jsonl").write_text("{}\n", encoding="utf-8")
        (state / "stderr.log").write_text("", encoding="utf-8")
        navigation = {
            "mcp_server_connected": True,
            "tool_available": True,
            "graph_use_valid": graph_valid,
            "failure_class": None if graph_valid else "codegraph_not_used",
            "outside_repository_accesses": [],
            "prohibited_benchmark_accesses": [],
        }
        result = {
            "returncode": 0,
            "timed_out": False,
            "terminated": False,
            "elapsed_seconds": 1.0,
            "response": response,
            "telemetry": {"valid": True, "provider_turn_valid": True, "usage": {}},
            "navigation": navigation,
            "failure_class": None,
            "state_dir": str(state),
            "events_path": str(state / "events.jsonl"),
            "stderr_path": str(state / "stderr.log"),
        }
        run_root = root / "codex-codegraph-enriched-smoke-fixture"
        run_root.mkdir(exist_ok=True)
        corpus_row = {"instance_id": "task", "base_commit": "a" * 40}
        corpus_payload = (json.dumps(corpus_row, sort_keys=True) + "\n").encode()
        (run_root / "corpus.jsonl").write_bytes(corpus_payload)
        identity = [{"instance_id": "task", "base_commit": "a" * 40}]
        source_lock = run_root / "source-lock.json"
        runtime_record = run_root / "codegraph-runtime.json"
        source_lock.write_text("{}\n", encoding="utf-8")
        runtime_record.write_text("{}\n", encoding="utf-8")
        manifest = {
            "run_id": run_root.name,
            "arm": "codex-codegraph-enriched",
            "protocol": "codegraph-region-v1",
            "configuration": {
                "requested_model": "gpt-5.6-luna",
                "requested_reasoning_effort": "high",
                "codex_version": "0.145.0",
                "sample_count": 1,
                "retry_cap": 2,
                "timeout_seconds": 900,
                "max_regions": 5,
                "output_schema_sha256": "1" * 64,
                "configuration_sha256": "2" * 64,
                "harness_sha256": "3" * 64,
            },
            "corpus": {
                "unique_task_count": 1,
                "tasks": [corpus_row],
                "artifact": {
                    "path": "corpus.jsonl",
                    "bytes": len(corpus_payload),
                    "sha256": hashlib.sha256(corpus_payload).hexdigest(),
                },
                "task_identity_sha256": hashlib.sha256(
                    (json.dumps(identity, sort_keys=True, separators=(",", ":")) + "\n").encode()
                ).hexdigest(),
                "source_manifest_sha256": "4" * 64,
            },
            "evaluator": {"commit": "x", "sha256": "5" * 64},
            "codegraph": {
                "source_lock": source_lock.name,
                "source_lock_sha256": hashlib.sha256(source_lock.read_bytes()).hexdigest(),
                "runtime_record": runtime_record.name,
                "runtime_record_sha256": hashlib.sha256(runtime_record.read_bytes()).hexdigest(),
                "mcp_network_isolation": {
                    "mode": "sandbox-exec-child-network-deny-v1",
                    "profile_sha256": "8" * 64,
                    "verified": True,
                },
            },
            "indexes": {
                "records": [
                    {
                        "path": "indexes/task.json",
                        "sha256": "0" * 64,
                    }
                ]
            },
            "treatment_differences": [
                "CodeGraph-use prompt addition",
                "pinned immutable CodeGraph index",
                "per-attempt CodeGraph MCP server",
            ],
        }
        authority = bind_enriched_authority(
            run_root,
            manifest["codegraph"],
            index_count=1,
        )
        index_record = {
            "task_id": "task",
            "identity": {"identity_sha256": "b" * 64},
            "enriched_authority": enriched_index_authority(authority),
        }
        index_record_path = run_root / "indexes" / "task.json"
        index_record_path.parent.mkdir()
        index_record_path.write_text(json.dumps(index_record), encoding="utf-8")
        manifest["indexes"]["records"][0]["sha256"] = hashlib.sha256(
            index_record_path.read_bytes()
        ).hexdigest()
        (run_root / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        metadata = {
            "run_id": run_root.name,
            "repository_path": str(repository),
            "repository_url": "https://example.invalid/repo.git",
            "requested_base_commit": "a" * 40,
            "verified_head": verified_head,
            "max_regions": 5,
            "index_valid": True,
            "index_identity": index_record["identity"],
            "index_record_sha256": sha256_value(index_record),
            "runtime_provenance": manifest["codegraph"],
            "evaluator_commit": manifest["evaluator"]["commit"],
            "evaluator_sha256": manifest["evaluator"]["sha256"],
            "contamination_audit": {"passed": True},
        }
        task = {
            "instance_id": "task",
            "base_commit": "a" * 40,
            "repository_url": "https://example.invalid/repo.git",
            "prepared": {"resolved_path": str(repository)},
        }
        return persist_attempt(run_root, task, 1, 1, result, metadata)

    def test_graph_validity_is_separate_from_diagnostic_scoring(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            no_use = self.attempt(root, False)
            self.assertTrue(diagnostic_scoreable(no_use))
            self.assertFalse(treatment_valid(no_use))
            self.assertEqual(no_use["failure_class"], "codegraph_not_used")
            self.assertTrue(validate_attempt_record(no_use))

    def test_success_is_treatment_valid_but_not_claimable_before_scoring(self):
        with tempfile.TemporaryDirectory() as temporary:
            record = self.attempt(Path(temporary), True)
            self.assertTrue(treatment_valid(record))
            self.assertFalse(record["claimable_sample"])
            self.assertFalse(record["validity"]["scoring"])
            self.assertTrue(validate_attempt_record(record))

    def test_revision_mismatch_is_retained_as_non_claimable_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            record = self.attempt(
                Path(temporary),
                True,
                verified_head="b" * 40,
            )
            self.assertFalse(record["validity"]["provenance"])
            self.assertFalse(record["treatment_valid"])
            self.assertIn(
                "invalid_provenance",
                record["failure_classes"],
            )

    def test_resume_skips_satisfied_slot_and_retains_failed_attempts(self):
        failed = {"task_id": "task", "sample_id": 1, "claimable_sample": False}
        valid = {
            "task_id": "task",
            "sample_id": 1,
            "claimable_sample": True,
            "treatment_valid": True,
            "score_valid": True,
            "validity": {
                "execution": True,
                "response": True,
                "provenance": True,
                "index": True,
                "mcp": True,
                "graph_use": True,
                "contamination": True,
                "telemetry": True,
                "scoring": True,
                "cost": False,
            },
        }
        slot = sample_slot([failed, valid], "task", 1, 2)
        self.assertTrue(slot["satisfied"])
        self.assertEqual(slot["attempt_count"], 2)
        self.assertEqual(slot["next_attempt_number"], 3)
        self.assertFalse(slot["retry_cap_exhausted"])

    def test_retry_cap_exhaustion_is_explicit(self):
        failures = [{"task_id": "task", "sample_id": 1, "claimable_sample": False} for _ in range(3)]
        self.assertTrue(sample_slot(failures, "task", 1, 2)["retry_cap_exhausted"])

    def test_attempt_input_rejects_mutable_identity_and_artifact_path_substitution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = self.attempt(root, True)
            run_root = root / "codex-codegraph-enriched-smoke-fixture"
            manifest = load_treatment_manifest(run_root, expected_run_id=run_root.name)
            mutations = (
                ("navigation", {"graph_use_valid": False}),
                ("repository_path", "/substituted/repository"),
                ("evaluator_sha256", "0" * 64),
                ("runtime_provenance", {}),
                ("index_identity", {}),
            )
            for field, value in mutations:
                changed = copy.deepcopy(record)
                changed[field] = value
                with self.subTest(field=field), self.assertRaisesRegex(
                    IntegrityError, "attempts.jsonl differs|identity differs"
                ):
                    validate_attempt_records(
                        [changed],
                        run_id=run_root.name,
                        task_ids={"task"},
                        required_samples=1,
                        run_root=run_root,
                        manifest=manifest,
                    )
            for value in (
                "/tmp/response.json",
                "../response.json",
                "attempts/task/sample-01/attempt-002/response.json",
                "attempts/task/sample-01/attempt-001/../response.json",
            ):
                changed = copy.deepcopy(record)
                changed["artifacts"]["response"] = value
                with self.subTest(path=value), self.assertRaisesRegex(
                    IntegrityError, "non-canonical|substituted"
                ):
                    validate_attempt_records(
                        [changed],
                        run_id=run_root.name,
                        task_ids={"task"},
                        required_samples=1,
                        run_root=run_root,
                        manifest=manifest,
                    )

    def test_attempt_artifact_symlink_and_same_path_response_substitution_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = self.attempt(root, True)
            run_root = root / "codex-codegraph-enriched-smoke-fixture"
            manifest = load_treatment_manifest(run_root, expected_run_id=run_root.name)
            response = run_root / record["artifacts"]["response"]
            response.write_text('{"regions":[]}\n', encoding="utf-8")
            with self.assertRaisesRegex(IntegrityError, "response artifact bytes differ"):
                validate_attempt_records(
                    [record],
                    run_id=run_root.name,
                    task_ids={"task"},
                    required_samples=1,
                    run_root=run_root,
                    manifest=manifest,
                )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = self.attempt(root, True)
            run_root = root / "codex-codegraph-enriched-smoke-fixture"
            manifest = load_treatment_manifest(run_root, expected_run_id=run_root.name)
            response = run_root / record["artifacts"]["response"]
            outside = root / "outside-response.json"
            outside.write_bytes(response.read_bytes())
            response.unlink()
            response.symlink_to(outside)
            with self.assertRaisesRegex(IntegrityError, "symlinked response path"):
                validate_attempt_records(
                    [record],
                    run_id=run_root.name,
                    task_ids={"task"},
                    required_samples=1,
                    run_root=run_root,
                    manifest=manifest,
                )


if __name__ == "__main__":
    unittest.main()
