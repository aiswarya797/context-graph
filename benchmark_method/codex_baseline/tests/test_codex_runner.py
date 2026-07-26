import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from context_graph_bench.codex_runner import (
    RunnerError,
    build_command,
    create_state_dir,
    run_child,
    validate_regions,
    validate_auth_source,
)


FIXTURES = Path(__file__).parent / "fixtures"


def config():
    return {"baseline": {"arm": "codex-baseline", "protocol": "direct-region-v1", "model": "gpt-5.6-luna", "reasoning_effort": "high"}}


class CodexRunnerTests(unittest.TestCase):
    def test_exact_model_effort_and_output_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            command = build_command(Path(sys.executable), config(), state, state / "schema.json", FIXTURES / "tiny_repo")
            self.assertEqual(command[0], sys.executable)
            self.assertEqual(command[1:4], ["exec", "--ephemeral", "--json"])
            self.assertIn("--output-last-message", command)
            self.assertIn("--output-schema", command)
            self.assertIn("--model", command)
            self.assertIn("gpt-5.6-luna", command)
            self.assertIn("model_reasoning_effort=high", command)
            self.assertIn("--sandbox", command)
            self.assertIn("danger-full-access", command)
            self.assertIn("--ignore-user-config", command)
            self.assertIn("--ignore-rules", command)

    def test_fresh_home_links_auth_and_missing_auth_fails_before_spawn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            auth = root / "auth.json"
            auth.write_text("secret")
            auth.chmod(0o600)
            state = create_state_dir(root / "work", auth)
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
            self.assertTrue((state / "auth.json").is_file())
            self.assertFalse((state / "auth.json").is_symlink())
            self.assertEqual((state / "auth.json").read_text(), "secret")
            with self.assertRaises(RunnerError):
                create_state_dir(root / "work", root / "missing-auth.json")

    def test_ordered_valid_regions_are_unchanged(self):
        response = {"regions": [{"path": "module.py", "start": 5, "end": 6, "reason": "second"}, {"path": "module.py", "start": 1, "end": 2, "reason": "first"}]}
        self.assertEqual(validate_regions(response, FIXTURES / "tiny_repo"), response["regions"])

    def test_invalid_schema_paths_ranges_duplicates_and_sixth_region_fail(self):
        cases = [
            {"regions": []},
            {"regions": [{"path": "../outside", "start": 1, "end": 1, "reason": "x"}]},
            {"regions": [{"path": "/tmp/outside", "start": 1, "end": 1, "reason": "x"}]},
            {"regions": [{"path": "module.py", "start": 0, "end": 1, "reason": "x"}]},
            {"regions": [{"path": "module.py", "start": 5, "end": 2, "reason": "x"}]},
            {"regions": [{"path": "module.py", "start": 1, "end": 100, "reason": "x"}]},
            {"regions": [{"path": "missing.py", "start": 1, "end": 1, "reason": "x"}]},
            {"regions": [{"path": "module.py", "start": 1, "end": 1, "reason": "x", "extra": 1}]},
            {"regions": [{"path": "module.py", "start": 1, "end": 1, "reason": "x"}, {"path": "module.py", "start": 1, "end": 1, "reason": "same"}]},
        ]
        sixth = {"regions": [{"path": "module.py", "start": 1, "end": 1, "reason": str(i)} for i in range(6)]}
        cases.append(sixth)
        for response in cases:
            with self.assertRaises(RunnerError):
                validate_regions(response, FIXTURES / "tiny_repo")

    def test_symlink_escape_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            (root / "inside.py").write_text("x\n")
            (root / "escape.py").symlink_to(Path(directory) / "outside.py")
            (Path(directory) / "outside.py").write_text("secret\n")
            with self.assertRaises(RunnerError):
                validate_regions({"regions": [{"path": "escape.py", "start": 1, "end": 1, "reason": "x"}]}, root)

    def test_partial_streams_survive_and_timeout_is_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            state.mkdir()
            script = "import pathlib,sys,time; print('{\"type\":\"turn.started\"}',flush=True); print('partial-error',file=sys.stderr,flush=True); time.sleep(5)"
            result = run_child([sys.executable, "-c", script], "prompt", state, root / "events.jsonl", root / "stderr.log", 0.1)
            self.assertTrue(result["timed_out"])
            self.assertEqual(result["failure_class"], "timeout")
            self.assertIn("turn.started", (root / "events.jsonl").read_text())
            self.assertIn("partial-error", (root / "stderr.log").read_text())

    def test_unauthorized_and_dns_failures_remain_distinct(self):
        for message, expected in (("401 Unauthorized", "unauthorized"), ("lookup api.openai.com: no such host", "dns_transport_failure")):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                state = root / "state"
                state.mkdir()
                script = f"import sys; print({message!r}, file=sys.stderr); raise SystemExit(1)"
                result = run_child([sys.executable, "-c", script], "prompt", state, root / "events.jsonl", root / "stderr.log", 1)
                self.assertEqual(result["failure_class"], expected)

    def test_sigterm_is_signal_termination_not_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            state.mkdir()
            script = "import os,signal; os.kill(os.getpid(), signal.SIGTERM)"
            result = run_child([sys.executable, "-c", script], "prompt", state, root / "events.jsonl", root / "stderr.log", 1)
            self.assertFalse(result["timed_out"])
            self.assertTrue(result["terminated"])
            self.assertEqual(result["signal_number"], 15)
            self.assertEqual(result["signal_name"], "SIGTERM")
            self.assertEqual(result["failure_class"], "terminated_by_signal")


if __name__ == "__main__":
    unittest.main()
