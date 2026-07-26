import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from context_graph_bench.codex_runner import RunnerError, validate_regions
from context_graph_bench.corpus import verify_official_evaluator
from context_graph_bench.report import METRICS, ReportError, score_record


ROOT = Path(__file__).parents[3]
FIXTURES = Path(__file__).parent / "fixtures"
EVALUATOR = ROOT / "benchmark_method/common/official/eval.py"
PROVENANCE = ROOT / "benchmark_method/common/official/provenance.json"


class OfficialEvaluatorTests(unittest.TestCase):
    def _bundle(self):
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        repo = root / "repo"
        shutil.copytree(FIXTURES / "tiny_repo", repo)
        attempt = root / "attempts/fixture__tiny-1/sample-01/attempt-001"
        attempt.mkdir(parents=True)
        for name in ("events.jsonl", "stderr.log", "response.json"):
            source = FIXTURES / ("codex_events/golden.jsonl" if name == "events.jsonl" else "stderr/unauthorized.log" if name == "stderr.log" else "golden-response.json")
            if name == "events.jsonl":
                source = FIXTURES / "golden-events.jsonl"
            shutil.copyfile(source, attempt / name)
        (attempt / "attempt.json").write_text("{}")
        corpus = root / "corpus.jsonl"
        shutil.copyfile(FIXTURES / "golden-bench.jsonl", corpus)
        hashes = {"events": hashlib.sha256((attempt / "events.jsonl").read_bytes()).hexdigest(), "stderr": hashlib.sha256((attempt / "stderr.log").read_bytes()).hexdigest(), "response": hashlib.sha256((attempt / "response.json").read_bytes()).hexdigest()}
        record = {
            "task_id": "fixture__tiny-1",
            "attempt_id": "attempt-001",
            "repository_path": str(repo),
            "quality_valid": True,
            "return_code": 0,
            "timeout": False,
            "terminated": False,
            "failure_class": None,
            "response_valid": True,
            "provider_turn_valid": True,
            "telemetry": {"valid": True},
            "contamination_audit": {"passed": True, "external_retrieval_passed": True},
            "provenance_valid": True,
            "artifact_paths": {"attempt": str(attempt.relative_to(root)), "events": str((attempt / "events.jsonl").relative_to(root)), "stderr": str((attempt / "stderr.log").relative_to(root)), "response": str((attempt / "response.json").relative_to(root))},
            "artifact_sha256": hashes,
        }
        return directory, root, corpus, record

    def test_pinned_evaluator_and_adapter_match_direct_call(self):
        directory, root, corpus, record = self._bundle()
        try:
            provenance = verify_official_evaluator(EVALUATOR, PROVENANCE)
            score = score_record(root, record, corpus, EVALUATOR, PROVENANCE)
            self.assertTrue(score["score_valid"])
            self.assertEqual(score["evaluator_sha256"], provenance["sha256"])
            expected = json.loads((FIXTURES / "golden-expected.json").read_text())
            self.assertEqual(score["score"], expected)
            spec = __import__("importlib.util").util.spec_from_file_location("official", EVALUATOR)
            module = __import__("importlib.util").util.module_from_spec(spec)
            spec.loader.exec_module(module)
            direct = module.ExploreEvaluator(corpus, file_line_counts={"fixture__tiny-1": {"module.py": 7}}).evaluate(lambda _issue, _id: [("module.py", 5, 6)], "fixture__tiny-1", METRICS)["fixture__tiny-1"]
            self.assertEqual(score["score"], direct)
        finally:
            directory.cleanup()

    def test_five_regions_pass_and_six_fail_before_evaluator(self):
        five = {"regions": [{"path": "module.py", "start": index, "end": index, "reason": str(index)} for index in range(1, 6)]}
        self.assertEqual(len(validate_regions(five, FIXTURES / "tiny_repo")), 5)
        six = {"regions": [{"path": "module.py", "start": index, "end": index, "reason": str(index)} for index in range(1, 7)]}
        with self.assertRaises(RunnerError):
            validate_regions(six, FIXTURES / "tiny_repo")

    def test_missing_mapping_is_evaluator_failure_not_zero_score(self):
        directory, root, corpus, record = self._bundle()
        try:
            corpus.write_text(json.dumps({"instance_id": "other", "ground_truth": {}}) + "\n")
            with self.assertRaises(ReportError):
                score_record(root, record, corpus, EVALUATOR, PROVENANCE)
        finally:
            directory.cleanup()


if __name__ == "__main__":
    unittest.main()
