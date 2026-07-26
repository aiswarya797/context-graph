import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from context_graph_bench.report import METRICS, build_aggregate, write_markdown, score_record
from context_graph_bench.artifacts import attempt_quality_gate, validate_attempt_record


def record(task_id, sample_id, value=1.0, telemetry=True):
    return {
        "task_id": task_id,
        "sample_id": sample_id,
        "attempt_id": f"{task_id}-{sample_id}",
        "quality_valid": True,
        "score_valid": True,
        "score": {metric: value for metric in METRICS},
        "telemetry": {"valid": telemetry, "usage": {"input_tokens": 10, "cached_input_tokens": 1, "output_tokens": 2, "reasoning_output_tokens": 1, "uncached_input_tokens": 9}} if telemetry else {"valid": False},
        "elapsed_seconds": 1.0,
        "attempt_number": 1,
        "return_code": 0,
        "timeout": False,
        "terminated": False,
        "failure_class": None,
        "response_valid": True,
        "provider_turn_valid": True,
        "contamination_audit": {"passed": True, "external_retrieval_passed": True},
        "provenance_valid": True,
    }


class ReportTests(unittest.TestCase):
    def test_every_failure_class_forces_quality_false(self):
        item = record("task", 1)
        for failure in ("benchmark_contamination", "timeout", "anything"):
            changed = dict(item)
            changed["failure_class"] = failure
            changed["quality_valid"] = True
            self.assertFalse(attempt_quality_gate(changed)[0], failure)
            self.assertFalse(validate_attempt_record(changed), failure)

    def test_contaminated_attempt_cannot_be_scored_or_reported(self):
        item = record("task", 1)
        item["failure_class"] = "benchmark_contamination"
        item["quality_valid"] = True
        self.assertFalse(attempt_quality_gate(item)[0])
        aggregate, _ = build_aggregate([item], 1, 1, {"commit": "c", "sha256": "d"}, ["task"])
        self.assertEqual(aggregate["quality_valid_sample_count"], 0)
    def test_24_tasks_by_three_samples_is_claimable_and_equal_weighted(self):
        task_ids = [f"task-{index:02d}" for index in range(24)]
        records = [record(task_id, sample, 1.0 if task_id != "task-00" else 0.0) for task_id in task_ids for sample in (1, 2, 3)]
        aggregate, summary = build_aggregate(records, 24, 3, {"commit": "c", "sha256": "d"}, task_ids)
        self.assertTrue(aggregate["claimable"])
        self.assertEqual(aggregate["quality_valid_sample_count"], 72)
        self.assertAlmostEqual(aggregate["official_metrics"]["precision"], 23 / 24)
        self.assertEqual(len(summary["tasks"]), 24)

    def test_missing_sample_is_non_claimable_and_identifies_gap(self):
        task_ids = [f"task-{index:02d}" for index in range(24)]
        records = [record(task_id, sample) for task_id in task_ids for sample in (1, 2, 3)]
        records.pop()
        aggregate, _ = build_aggregate(records, 24, 3, {"commit": "c", "sha256": "d"}, task_ids)
        self.assertFalse(aggregate["claimable"])
        self.assertTrue(any(gap["task_id"] == "task-23" for gap in aggregate["claimability_gaps"]))

    def test_telemetry_invalid_quality_sample_is_excluded_from_quality_aggregate(self):
        task_ids = [f"task-{index:02d}" for index in range(24)]
        records = [record(task_id, sample) for task_id in task_ids for sample in (1, 2, 3)]
        records[0]["telemetry"] = {"valid": False}
        aggregate, _ = build_aggregate(records, 24, 3, {"commit": "c", "sha256": "d"}, task_ids)
        self.assertFalse(aggregate["claimable"])
        self.assertEqual(aggregate["quality_valid_sample_count"], 71)
        self.assertEqual(aggregate["telemetry"]["valid_quality_samples"], 71)
        self.assertTrue(aggregate["telemetry"]["coverage_complete"])

    def test_published_reference_is_non_comparable_and_markdown_has_no_delta(self):
        task_ids = [f"task-{index:02d}" for index in range(24)]
        records = [record(task_id, sample) for task_id in task_ids for sample in (1, 2, 3)]
        aggregate, _ = build_aggregate(records, 24, 3, {"commit": "c", "sha256": "d"}, task_ids)
        self.assertEqual(aggregate["published_gpt54_reference"]["status"], "non_comparable_external_context")
        markdown = write_markdown(aggregate)
        self.assertNotIn("delta", markdown.lower())
        self.assertNotIn("should be higher", markdown.lower())

    def test_failed_attempts_remain_visible(self):
        task_ids = [f"task-{index:02d}" for index in range(24)]
        records = [record(task_id, sample) for task_id in task_ids for sample in (1, 2, 3)]
        records.append({"task_id": "task-00", "quality_valid": False, "failure_class": "timeout", "attempt_number": 2})
        aggregate, _ = build_aggregate(records, 24, 3, {"commit": "c", "sha256": "d"}, task_ids)
        self.assertEqual(aggregate["attempts"]["total"], 73)
        self.assertEqual(aggregate["attempts"]["failed_or_invalid"], 1)
        self.assertEqual(aggregate["attempts"]["failure_classes"]["timeout"], 1)


if __name__ == "__main__":
    unittest.main()
