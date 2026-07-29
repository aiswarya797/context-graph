from __future__ import annotations

import sys
import json
import tempfile
import unittest
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(REPO / "benchmark_method" / "codex_baseline" / "src"))

from codegraph_bench.report import METRICS, build_report, score_run
from codegraph_bench.artifacts import rewrite_jsonl, sha256_file
from codegraph_bench.codegraph import sha256_value
from benchmark_method.codex_codegraph_enriched.tests.task5_test_support import (
    bind_enriched_authority,
    enriched_index_authority,
)
from codegraph_bench.integrity import IntegrityError
from codegraph_bench.report import ReportError


def record(task_id: str, attempt: int, *, graph: bool = True, score: float = 1.0, fallback: int = 0):
    validity = {
        "execution": True,
        "response": True,
        "provenance": True,
        "index": True,
        "mcp": True,
        "graph_use": graph,
        "contamination": True,
        "telemetry": True,
        "scoring": True,
        "cost": False,
    }
    return {
        "run_id": "codex-codegraph-enriched-fixture",
        "arm": "codex-codegraph-enriched",
        "task_id": task_id,
        "attempt_id": f"attempt-{attempt:03d}",
        "sample_id": attempt,
        "attempt_number": 1,
        "score_valid": True,
        "quality_valid": graph,
        "treatment_valid": graph,
        "claimable_sample": graph,
        "adopted_for_slot": graph,
        "failure_class": None if graph else "codegraph_not_used",
        "failure_classes": [] if graph else ["codegraph_not_used", "invalid_graph_use"],
        "score": {metric: score for metric in METRICS},
        "validity": validity,
        "elapsed_seconds": 2.0,
        "telemetry": {
            "valid": True,
            "usage": {
                "input_tokens": 100,
                "cached_input_tokens": 20,
                "cache_write_input_tokens": 0,
                "uncached_input_tokens": 80,
                "output_tokens": 10,
                "reasoning_output_tokens": 2,
            },
        },
        "navigation": {
            "fallback_navigation_after_graph": fallback,
            "built_in_navigation_before_graph": 0,
        },
    }


class ReportTests(unittest.TestCase):
    def test_response_valid_no_use_attempt_is_officially_scored_only_as_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "codex-codegraph-enriched-smoke-fixture"
            run_root.mkdir()
            repository = run_root / "repo"
            repository.mkdir()
            (repository / "module.py").write_text("a\nb\nc\nd\ndef second():\n    pass\n", encoding="utf-8")
            attempt_relative = "attempts/fixture__tiny-1/sample-01/attempt-001"
            attempt = run_root / attempt_relative
            attempt.mkdir(parents=True)
            response = attempt / "response.json"
            events = attempt / "events.jsonl"
            stderr = attempt / "stderr.log"
            response.write_text(
                json.dumps({"regions": [{"path": "module.py", "start": 5, "end": 6, "reason": "second function"}]}),
                encoding="utf-8",
            )
            events.write_text("{}\n", encoding="utf-8")
            stderr.write_text("", encoding="utf-8")
            corpus_row = {
                "instance_id": "fixture__tiny-1",
                "base_commit": "fixture",
                "problem_statement": "Fix the second function.",
                "ground_truth": {
                    "read_core_files": ["module.py"],
                    "read_core_regions": [{"path": "module.py", "start": 5, "end": 6}],
                    "read_optional_files_map": {},
                    "read_optional_regions_map": {},
                    "main_files": ["module.py"],
                },
            }
            corpus_payload = (json.dumps(corpus_row) + "\n").encode()
            (run_root / "corpus.jsonl").write_bytes(corpus_payload)
            task_identity = [{"instance_id": "fixture__tiny-1", "base_commit": "fixture"}]
            evaluator_provenance = json.loads(
                (REPO / "benchmark_method" / "common" / "official" / "provenance.json").read_text()
            )
            evaluator = {
                "commit": evaluator_provenance["commit"],
                "sha256": evaluator_provenance["sha256"],
            }
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
                    "output_schema_sha256": "a" * 64,
                    "configuration_sha256": "b" * 64,
                    "harness_sha256": "c" * 64,
                },
                "corpus": {
                    "unique_task_count": 1,
                    "tasks": [task_identity[0]],
                    "artifact": {
                        "path": "corpus.jsonl",
                        "bytes": len(corpus_payload),
                        "sha256": hashlib.sha256(corpus_payload).hexdigest(),
                    },
                    "task_identity_sha256": hashlib.sha256(
                        (json.dumps(task_identity, sort_keys=True, separators=(",", ":")) + "\n").encode()
                    ).hexdigest(),
                    "source_manifest_sha256": "d" * 64,
                },
                "evaluator": evaluator,
                "codegraph": {
                    "source_lock": source_lock.name,
                    "source_lock_sha256": hashlib.sha256(source_lock.read_bytes()).hexdigest(),
                    "runtime_record": runtime_record.name,
                    "runtime_record_sha256": hashlib.sha256(runtime_record.read_bytes()).hexdigest(),
                    "mcp_network_isolation": {
                        "mode": "sandbox-exec-child-network-deny-v1",
                        "profile_sha256": "e" * 64,
                        "verified": True,
                    },
                },
                "indexes": {
                    "records": [
                        {
                            "path": "indexes/fixture__tiny-1.json",
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
                "task_id": "fixture__tiny-1",
                "identity": {"identity_sha256": "f" * 64},
                "enriched_authority": enriched_index_authority(authority),
            }
            index_path = run_root / "indexes" / "fixture__tiny-1.json"
            index_path.parent.mkdir()
            index_path.write_text(json.dumps(index_record), encoding="utf-8")
            manifest["indexes"]["records"][0]["sha256"] = hashlib.sha256(
                index_path.read_bytes()
            ).hexdigest()
            (run_root / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            validity = {
                "execution": True,
                "response": True,
                "provenance": True,
                "index": True,
                "mcp": True,
                "graph_use": False,
                "contamination": True,
                "telemetry": True,
                "scoring": False,
                "cost": False,
            }
            attempt_record = {
                "run_id": run_root.name,
                "arm": "codex-codegraph-enriched",
                "task_id": "fixture__tiny-1",
                "attempt_id": "attempt-001",
                "attempt_number": 1,
                "sample_id": 1,
                "quality_valid": False,
                "score_valid": False,
                "treatment_valid": False,
                "claimable_sample": False,
                "adopted_for_slot": False,
                "failure_class": "codegraph_not_used",
                "failure_classes": ["codegraph_not_used", "invalid_graph_use"],
                "validity": validity,
                "repository_path": str(repository),
                "requested_base_commit": "fixture",
                "verified_head": "fixture",
                "evaluator_commit": evaluator["commit"],
                "evaluator_sha256": evaluator["sha256"],
                "max_regions": 5,
                "index_identity": index_record["identity"],
                "index_record_sha256": sha256_value(index_record),
                "runtime_provenance": manifest["codegraph"],
                "navigation": {},
                "artifacts": {
                    "attempt": attempt_relative,
                    "response": f"{attempt_relative}/response.json",
                    "events": f"{attempt_relative}/events.jsonl",
                    "stderr": f"{attempt_relative}/stderr.log",
                },
                "artifact_sha256": {
                    "response": sha256_file(response),
                    "events": sha256_file(events),
                    "stderr": sha256_file(stderr),
                },
            }
            module_contents = (repository / "module.py").read_bytes()
            source_rows = [
                {
                    "path": "module.py",
                    "bytes": len(module_contents),
                    "sha256": hashlib.sha256(module_contents).hexdigest(),
                    "line_count": len(module_contents.decode().splitlines()),
                }
            ]
            scoring_source = {
                "schema_version": "codegraph-scoring-source-v1",
                "file_count": 1,
                "files": source_rows,
                "manifest_sha256": hashlib.sha256(
                    json.dumps(source_rows, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                ).hexdigest(),
            }
            source_path = attempt / "scoring-source.json"
            source_path.write_text(json.dumps(scoring_source), encoding="utf-8")
            attempt_record["artifacts"]["scoring_source"] = f"{attempt_relative}/scoring-source.json"
            attempt_record["artifact_sha256"]["scoring_source"] = sha256_file(source_path)
            input_path = attempt / "attempt-input.json"
            input_path.write_text(json.dumps(attempt_record), encoding="utf-8")
            attempt_record["artifacts"].update(
                {
                    "attempt_input": f"{attempt_relative}/attempt-input.json",
                }
            )
            attempt_record["artifact_sha256"].update(
                {"attempt_input": sha256_file(input_path)}
            )
            rewrite_jsonl(run_root / "attempts.jsonl", [attempt_record])
            scored = score_run(
                run_root,
                REPO / "benchmark_method" / "common" / "official" / "eval.py",
                REPO / "benchmark_method" / "common" / "official" / "provenance.json",
            )
            self.assertTrue(scored[0]["score_valid"])
            self.assertTrue(scored[0]["validity"]["scoring"])
            self.assertFalse(scored[0]["claimable_sample"])
            self.assertTrue(json.loads((attempt / "score.json").read_text())["diagnostic"])

            corpus_original = (run_root / "corpus.jsonl").read_bytes()
            (run_root / "corpus.jsonl").write_bytes(corpus_original + b"\n")
            with self.assertRaisesRegex(IntegrityError, "corpus bytes differ"):
                score_run(
                    run_root,
                    REPO / "benchmark_method" / "common" / "official" / "eval.py",
                    REPO / "benchmark_method" / "common" / "official" / "provenance.json",
                )
            (run_root / "corpus.jsonl").write_bytes(corpus_original)

            repository_original = (repository / "module.py").read_bytes()
            (repository / "module.py").write_bytes(repository_original + b"# drift\n")
            with self.assertRaisesRegex(ReportError, "repository bytes drifted"):
                score_run(
                    run_root,
                    REPO / "benchmark_method" / "common" / "official" / "eval.py",
                    REPO / "benchmark_method" / "common" / "official" / "provenance.json",
                )
            (repository / "module.py").write_bytes(repository_original)

            response_original = response.read_bytes()
            response.write_bytes(response_original + b"\n")
            with self.assertRaisesRegex(IntegrityError, "response artifact bytes differ"):
                score_run(
                    run_root,
                    REPO / "benchmark_method" / "common" / "official" / "eval.py",
                    REPO / "benchmark_method" / "common" / "official" / "provenance.json",
                )
            response.write_bytes(response_original)

    def test_equal_task_claimability_adoption_tokens_and_index_overhead(self):
        tasks = [f"task-{number:02d}" for number in range(24)]
        records = [record(task, sample, fallback=1 if sample == 1 else 0) for task in tasks for sample in range(1, 4)]
        failed_retry = record(tasks[0], 1, graph=False, score=0.0)
        failed_retry["attempt_id"] = "attempt-002"
        failed_retry["attempt_number"] = 2
        records.append(failed_retry)
        indexes = [
            {
                "task_id": task,
                "ready": True,
                "frozen": True,
                "duration_seconds": 3.0,
                "index_bytes": 1000,
            }
            for task in tasks
        ]
        report = build_report(records, tasks, indexes, 3, {"commit": "x", "sha256": "y"})
        self.assertTrue(report["claimable"])
        self.assertEqual(report["claimable_sample_count"], 72)
        self.assertEqual(report["adoption"]["no_use_attempts"], 1)
        self.assertEqual(report["fallback"]["fallback_navigation_calls"], 24)
        self.assertEqual(report["telemetry"]["totals"]["claim_aligned_total_tokens"], 72 * 110)
        self.assertFalse(report["telemetry"]["cache_free"])
        self.assertEqual(report["timing"]["index_preparation_seconds"]["total"], 72.0)
        self.assertEqual(report["indexes"]["disk_bytes"]["total"], 24000.0)
        self.assertEqual(report["intent_to_treat"]["response_valid_scored_attempts"], 73)

    def test_report_includes_complete_attempt_artifact_identities(self):
        value = record("task", 1)
        value["artifacts"] = {
            "attempt": "attempts/task/sample-01/attempt-001",
            "events": "attempts/task/sample-01/attempt-001/events.jsonl",
            "stderr": "attempts/task/sample-01/attempt-001/stderr.log",
        }
        value["artifact_sha256"] = {
            "events": "a" * 64,
            "stderr": "b" * 64,
        }
        value["score_artifact"] = (
            "attempts/task/sample-01/attempt-001/score.json"
        )
        value["score_sha256"] = "c" * 64
        indexes = [
            {
                "task_id": "task",
                "ready": True,
                "frozen": True,
                "duration_seconds": 1,
                "index_bytes": 1,
            }
        ]
        report = build_report([value], ["task"], indexes, 1, {})
        self.assertEqual(
            report["artifact_identities"],
            [
                {
                    "task_id": "task",
                    "sample_id": 1,
                    "attempt_id": "attempt-001",
                    "artifacts": {
                        "events": {
                            "path": value["artifacts"]["events"],
                            "sha256": "a" * 64,
                        },
                        "stderr": {
                            "path": value["artifacts"]["stderr"],
                            "sha256": "b" * 64,
                        },
                    },
                    "score": {
                        "path": value["score_artifact"],
                        "sha256": "c" * 64,
                    },
                }
            ],
        )

    def test_missing_sample_and_index_refuse_claimability(self):
        tasks = ["one", "two"]
        records = [record("one", sample) for sample in range(1, 4)] + [record("two", sample) for sample in range(1, 3)]
        report = build_report(records, tasks, [{"task_id": "one", "ready": True, "frozen": True, "duration_seconds": 1, "index_bytes": 1}], 3, {})
        self.assertFalse(report["claimable"])
        self.assertEqual(
            report["claimability_gaps"],
            [{"task_id": "two", "valid_samples": 2, "required": 3, "missing_sample_ids": [3]}],
        )

    def test_low_quality_score_does_not_become_failure(self):
        records = [record("task", sample, score=0.0) for sample in range(1, 4)]
        indexes = [{"task_id": "task", "ready": True, "frozen": True, "duration_seconds": 1, "index_bytes": 1}]
        report = build_report(records, ["task"], indexes, 3, {})
        self.assertTrue(report["claimable"])
        self.assertEqual(report["official_metrics"]["f1_score"], 0.0)
        self.assertEqual(report["attempts"]["retries"], 0)

    def test_three_claimable_records_for_sample_one_cannot_claim_three_slots(self):
        records = [record("task", 1) for _ in range(3)]
        for number, value in enumerate(records, 1):
            value["attempt_id"] = f"attempt-{number:03d}"
            value["attempt_number"] = number
        indexes = [{"task_id": "task", "ready": True, "frozen": True, "duration_seconds": 1, "index_bytes": 1}]
        with self.assertRaisesRegex(IntegrityError, "duplicate adopted sample slots"):
            build_report(records, ["task"], indexes, 3, {})


if __name__ == "__main__":
    unittest.main()
