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

from codegraph_bench.comparison import ComparisonRefused, compare_runs
from codegraph_bench.codegraph import directory_manifest
from benchmark_method.codex_codegraph_enriched.tests.task5_test_support import (
    bind_enriched_authority,
    enriched_index_authority,
)


TASKS = {f"task-{number:02d}": f"{number:040x}" for number in range(24)}


def write(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def jsonl(path: Path, rows):
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def treatment_attempt(task: str, sample: int):
    validity = {
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
    }
    return {
        "run_id": "codex-codegraph-enriched-fixture",
        "arm": "codex-codegraph-enriched",
        "task_id": task,
        "sample_id": sample,
        "attempt_id": "attempt-001",
        "attempt_number": 1,
        "quality_valid": True,
        "score_valid": True,
        "treatment_valid": True,
        "claimable_sample": True,
        "adopted_for_slot": True,
        "failure_class": None,
        "failure_classes": [],
        "max_regions": 5,
        "elapsed_seconds": 8.0,
        "validity": validity,
        "artifacts": {"attempt": f"attempts/{task}/sample-{sample:02d}/attempt-001"},
        "artifact_sha256": {},
        "telemetry": {"usage": {"input_tokens": 80, "output_tokens": 10}},
    }


def canonical_sha(value) -> str:
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return hashlib.sha256(payload).hexdigest()


def authority_record(record):
    authority = copy.deepcopy(record)
    authority["score_valid"] = False
    authority["quality_valid"] = False
    authority["claimable_sample"] = False
    authority["validity"]["scoring"] = False
    authority.pop("score_artifact", None)
    authority.pop("score_sha256", None)
    authority.get("artifacts", {}).pop("attempt_input", None)
    authority.get("artifact_sha256", {}).pop("attempt_input", None)
    return authority


class ComparisonTests(unittest.TestCase):
    def fixture(self, root: Path):
        baseline = root / "baseline"
        treatment = root / "codex-codegraph-enriched-fixture"
        baseline.mkdir()
        treatment.mkdir()
        baseline_config = {
            "requested_model": "gpt-5.6-luna",
            "requested_reasoning_effort": "high",
            "codex_version": "0.145.0",
            "sample_count": 3,
            "retry_cap": 2,
            "timeout_seconds": 900,
            "max_regions": 5,
            "output_schema_sha256": "f" * 64,
            "configuration_sha256": "baseline-config",
        }
        treatment_config = baseline_config | {
            "configuration_sha256": "9" * 64,
            "harness_sha256": "a" * 64,
        }
        source_lock = treatment / "source-lock.json"
        runtime_record = treatment / "codegraph-runtime.json"
        source_lock.write_text("{}\n", encoding="utf-8")
        runtime_record.write_text("{}\n", encoding="utf-8")
        write(
            baseline / "run-manifest.json",
            {
                "run_id": "baseline",
                "arm": "codex-baseline",
                "configuration": baseline_config,
                "evaluator": {"sha256": "e" * 64},
            },
        )
        write(
            treatment / "run-manifest.json",
            {
                "run_id": treatment.name,
                "arm": "codex-codegraph-enriched",
                "protocol": "codegraph-region-v1",
                "configuration": treatment_config,
                "corpus": {},
                "evaluator": {"commit": "eval-commit", "sha256": "e" * 64},
                "codegraph": {
                    "source_lock": source_lock.name,
                    "source_lock_sha256": hashlib.sha256(source_lock.read_bytes()).hexdigest(),
                    "runtime_record": runtime_record.name,
                    "runtime_record_sha256": hashlib.sha256(runtime_record.read_bytes()).hexdigest(),
                    "mcp_network_isolation": {
                        "mode": "sandbox-exec-child-network-deny-v1",
                        "profile_sha256": "c" * 64,
                        "verified": True,
                    },
                },
                "indexes": {"records": []},
                "treatment_differences": [
                    "CodeGraph-use prompt addition",
                    "pinned immutable CodeGraph index",
                    "per-attempt CodeGraph MCP server",
                ],
            },
        )
        corpus = [{"instance_id": task, "base_commit": commit} for task, commit in TASKS.items()]
        jsonl(baseline / "corpus.jsonl", corpus)
        jsonl(treatment / "corpus.jsonl", corpus)
        corpus_payload = (treatment / "corpus.jsonl").read_bytes()
        identity = [{"instance_id": task, "base_commit": TASKS[task]} for task in sorted(TASKS)]
        treatment_manifest = json.loads((treatment / "run-manifest.json").read_text())
        treatment_manifest["corpus"] = {
            "unique_task_count": 24,
            "tasks": corpus,
            "artifact": {
                "path": "corpus.jsonl",
                "bytes": len(corpus_payload),
                "sha256": hashlib.sha256(corpus_payload).hexdigest(),
            },
            "task_identity_sha256": hashlib.sha256(
                (json.dumps(identity, sort_keys=True, separators=(",", ":")) + "\n").encode()
            ).hexdigest(),
            "source_manifest_sha256": "d" * 64,
        }
        authority = bind_enriched_authority(
            treatment,
            treatment_manifest["codegraph"],
            index_count=24,
        )
        index_refs = []
        for task in TASKS:
            index_dir = root / "indexes" / task
            index_dir.mkdir(parents=True)
            (index_dir / "graph.db").write_text(task, encoding="utf-8")
            relative = f"indexes/{task}.json"
            index_record = {
                "task_id": task,
                "identity": {"identity_sha256": hashlib.sha256(task.encode()).hexdigest()},
                "index_path": str(index_dir),
                "index_artifact_manifest": directory_manifest(index_dir),
                "enriched_authority": enriched_index_authority(authority),
            }
            write(
                treatment / relative,
                index_record,
            )
            index_refs.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256((treatment / relative).read_bytes()).hexdigest(),
                }
            )
        treatment_manifest["indexes"] = {"record_count": 24, "records": index_refs}
        write(treatment / "run-manifest.json", treatment_manifest)
        baseline_attempts = []
        treatment_attempts = []
        for task in TASKS:
            for sample in range(1, 4):
                baseline_attempts.append(
                    {
                        "task_id": task,
                        "sample_id": sample,
                        "quality_valid": True,
                        "score_valid": True,
                        "max_regions": 5,
                        "elapsed_seconds": 10.0,
                        "telemetry": {"usage": {"input_tokens": 100, "output_tokens": 10}},
                    }
                )
                attempt = treatment_attempt(task, sample)
                index_record = json.loads((treatment / f"indexes/{task}.json").read_text())
                attempt.update(
                    {
                        "requested_base_commit": TASKS[task],
                        "verified_head": TASKS[task],
                        "evaluator_commit": treatment_manifest["evaluator"]["commit"],
                        "evaluator_sha256": treatment_manifest["evaluator"]["sha256"],
                        "runtime_provenance": treatment_manifest["codegraph"],
                        "index_identity": index_record["identity"],
                        "index_record_sha256": canonical_sha(index_record),
                        "navigation": {},
                    }
                )
                attempt_root = treatment / attempt["artifacts"]["attempt"]
                raw_artifacts = {
                    "events": "events.jsonl",
                    "stderr": "stderr.log",
                    "response": "response.json",
                    "scoring_source": "scoring-source.json",
                }
                for key, name in raw_artifacts.items():
                    artifact_path = attempt_root / name
                    write(artifact_path, {"artifact": key})
                    attempt["artifacts"][key] = str(artifact_path.relative_to(treatment))
                    attempt["artifact_sha256"][key] = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
                input_path = attempt_root / "attempt-input.json"
                write(input_path, authority_record(attempt))
                attempt["artifacts"]["attempt_input"] = str(input_path.relative_to(treatment))
                attempt["artifact_sha256"]["attempt_input"] = hashlib.sha256(input_path.read_bytes()).hexdigest()
                score_path = attempt_root / "score.json"
                write(score_path, {"score": True})
                attempt["score_artifact"] = str(score_path.relative_to(treatment))
                attempt["score_sha256"] = hashlib.sha256(score_path.read_bytes()).hexdigest()
                treatment_attempts.append(attempt)
        jsonl(baseline / "attempts.jsonl", baseline_attempts)
        jsonl(treatment / "attempts.jsonl", treatment_attempts)
        task_means = {task: {"precision": 0.5} for task in TASKS}
        write(
            baseline / "aggregate.json",
            {
                "claimable": True,
                "official_metrics": {"precision": 0.5},
                "task_means": task_means,
                "telemetry": {"coverage_complete": True, "usage_totals": {"input_tokens": 7200, "output_tokens": 720}},
            },
        )
        write(
            treatment / "aggregate.json",
            {
                "claimable": True,
                "official_metrics": {"precision": 0.6},
                "task_means": {task: {"precision": 0.6} for task in TASKS},
                "telemetry": {"coverage_complete": True, "totals": {"input_tokens": 5760, "output_tokens": 720}},
                "timing": {},
                "indexes": {},
                "adoption": {},
                "fallback": {},
                "intent_to_treat": {},
                "cost": {"status": "unavailable"},
                "treatment_differences": ["prompt", "index", "mcp"],
            },
        )
        write(baseline / "freeze-report.json", {"claimable": True})
        write(baseline / "validation.json", {"passed": True})
        return baseline, treatment

    def test_matched_comparison_reports_operands_and_token_reductions(self):
        with tempfile.TemporaryDirectory() as temporary:
            baseline, treatment = self.fixture(Path(temporary))
            result = compare_runs(
                baseline,
                treatment,
                expected_baseline_configuration_sha256="baseline-config",
                expected_timeout_seconds=900,
            )
            self.assertTrue(result["matched"])
            self.assertAlmostEqual(result["official_quality"]["macro_deltas"]["precision"]["delta"], 0.1)
            self.assertAlmostEqual(result["tokens"]["equal_weighted_mean_reduction_pct"], 100 * 20 / 110)
            self.assertAlmostEqual(result["timing"]["equal_weighted_mean_reduction_pct"], 20.0)
            self.assertEqual(len(result["tokens"]["per_task_median_reductions"]), 24)

    def test_task_revision_mismatch_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            baseline, treatment = self.fixture(Path(temporary))
            rows = [{"instance_id": task, "base_commit": ("f" * 40 if index == 0 else commit)} for index, (task, commit) in enumerate(TASKS.items())]
            jsonl(treatment / "corpus.jsonl", rows)
            with self.assertRaisesRegex(ComparisonRefused, "corpus bytes differ"):
                compare_runs(baseline, treatment, expected_baseline_configuration_sha256="baseline-config", expected_timeout_seconds=900)

    def test_evaluator_mismatch_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            baseline, treatment = self.fixture(Path(temporary))
            manifest = json.loads((treatment / "run-manifest.json").read_text())
            manifest["evaluator"]["sha256"] = "a" * 64
            write(treatment / "run-manifest.json", manifest)
            with self.assertRaisesRegex(ComparisonRefused, "attempt repository/evaluator/runtime identity differs"):
                compare_runs(baseline, treatment, expected_baseline_configuration_sha256="baseline-config", expected_timeout_seconds=900)

    def test_unproven_baseline_timeout_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            baseline, treatment = self.fixture(Path(temporary))
            with self.assertRaisesRegex(ComparisonRefused, "cannot prove timeout identity"):
                compare_runs(baseline, treatment, expected_baseline_configuration_sha256="different", expected_timeout_seconds=900)

    def test_missing_telemetry_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            baseline, treatment = self.fixture(Path(temporary))
            report = json.loads((treatment / "aggregate.json").read_text())
            report["telemetry"]["coverage_complete"] = False
            write(treatment / "aggregate.json", report)
            with self.assertRaisesRegex(ComparisonRefused, "telemetry coverage is incomplete"):
                compare_runs(baseline, treatment, expected_baseline_configuration_sha256="baseline-config", expected_timeout_seconds=900)


if __name__ == "__main__":
    unittest.main()
