import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from context_graph_bench.event_audit import audit_events, successful_local_read


ROOT = Path(__file__).parents[3]
BENCHMARK = ROOT / "benchmark_method/codex_baseline/benchmark.py"


class EventAuditTests(unittest.TestCase):
    def test_external_retrieval_event_is_contamination(self):
        for item_type in ("web_search", "remote_fetch"):
            event = {"type": "item.completed", "item": {"type": item_type}}
            audit = audit_events(json.dumps(event))
            self.assertFalse(audit["passed"])
            self.assertFalse(audit["external_retrieval_passed"])

    def test_forbidden_benchmark_path_is_contamination(self):
        protected = Path("/private/tmp/benchmark-output")
        audit = audit_events(f'{{"type":"agent_message","text":"{protected}"}}', [protected])
        self.assertFalse(audit["passed"])
        self.assertEqual(audit["forbidden_hits"], [str(protected)])

    def test_normal_local_event_passes(self):
        audit = audit_events(json.dumps({"type": "item.completed", "item": {"type": "command_execution"}}))
        self.assertTrue(audit["passed"])

    def test_real_read_evidence_requires_completed_command(self):
        path = Path("/tmp/doctor-sentinel")
        message = {"type": "item.completed", "item": {"type": "agent_message", "text": str(path)}}
        self.assertFalse(successful_local_read(json.dumps(message), path))
        event = {"type": "item.completed", "item": {"type": "command_execution", "command": f"cat {path}", "output": "ok"}}
        self.assertTrue(successful_local_read(json.dumps(event), path))

    def test_child_safe_task_and_prompt_contain_no_ground_truth(self):
        module = runpy.run_path(str(BENCHMARK))
        task = {"instance_id": "task", "issue_text": "issue", "ground_truth": {"gold": "do-not-share"}}
        safe = module["child_safe_task"](task)
        self.assertEqual(safe, {"task_id": "task", "issue_text": "issue"})
        self.assertNotIn("ground_truth", json.dumps(safe))
        prompt = module["build_prompt"]("Issue: {{problem_statement}}", safe["issue_text"])
        self.assertNotIn("do-not-share", prompt)

    def test_doctor_gate_matches_harness(self):
        module = runpy.run_path(str(BENCHMARK))
        doctor = {
            "passed": True,
            "runtime": {"harness_sha256": "same"},
            "contamination_audit": {"passed": True, "external_retrieval_passed": True, "boundary_canary": {"passed": True}},
            "provider_probe": {"local_read_event": True, "response_present": True},
        }
        self.assertTrue(module["doctor_matches"](doctor, "same"))
        self.assertFalse(module["doctor_matches"](doctor, "changed"))

    def test_python_version_gate_requires_311(self):
        module = runpy.run_path(str(BENCHMARK))
        with self.assertRaises(SystemExit):
            module["validate_supported_python"]((3, 10))
        module["validate_supported_python"]((3, 11))

    def test_cli_help_resolves_from_unrelated_working_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(["python3", str(BENCHMARK), "--help"], cwd=directory, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("doctor", result.stdout)
