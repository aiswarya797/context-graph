from __future__ import annotations

import hashlib
import json
import sys
import tomllib
import unittest
from pathlib import Path


ARM_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ARM_ROOT.parents[1]
TASK2_ROOT = REPOSITORY_ROOT / "benchmark_method/codex_codegraph"
TASK2_PACKAGE_SHA256 = (
    "6e16dbf79a0ac53e9cc74d859d7500cf8eba59692bc485a4488254dbb76fca0a"
)
sys.path.insert(0, str(ARM_ROOT / "src"))

from codegraph_bench.codegraph_events import parse_navigation_events  # noqa: E402


UNCHANGED_RUNTIME_FILES = (
    "config/codegraph-region-selection-prompt.md",
    "src/codegraph_bench/codegraph.py",
    "src/codegraph_bench/codegraph_events.py",
    "src/codegraph_bench/codegraph_runner.py",
    "src/codegraph_bench/schema_validation.py",
    "src/codegraph_bench/task2_evidence.py",
    "src/codegraph_bench/task_metadata.py",
)


class Task5ParityTests(unittest.TestCase):
    def test_measured_prompt_runtime_runner_parser_and_controls_are_exact(self):
        for relative in UNCHANGED_RUNTIME_FILES:
            with self.subTest(relative=relative):
                self.assertEqual(
                    (ARM_ROOT / relative).read_bytes(),
                    (TASK2_ROOT / relative).read_bytes(),
                )

    def test_frozen_model_timeout_retry_sandbox_and_mcp_request_match(self):
        enriched = tomllib.loads(
            (ARM_ROOT / "config/codegraph.toml").read_text(encoding="utf-8")
        )
        task2 = tomllib.loads(
            (TASK2_ROOT / "config/codegraph.toml").read_text(
                encoding="utf-8"
            )
        )
        for section, fields in {
            "treatment": (
                "protocol",
                "model",
                "reasoning_effort",
                "codex_version",
                "sample_count",
                "retry_cap",
                "timeout_seconds",
                "max_regions",
                "required_tool",
                "mcp_server_name",
            ),
            "index": (
                "configuration_version",
                "exclude_names",
                "directory_prefix",
            ),
            "runtime": (
                "network_during_attempt",
                "shared_daemon",
                "self_update",
                "telemetry",
            ),
        }.items():
            for field in fields:
                with self.subTest(section=section, field=field):
                    self.assertEqual(
                        enriched[section][field],
                        task2[section][field],
                    )

    def test_parser_outputs_match_frozen_task2_fixture_expectations(self):
        fixture_root = ARM_ROOT / "tests/fixtures/codegraph_events"
        repository = ARM_ROOT / "tests/fixtures/tiny_repo"
        successful = parse_navigation_events(
            (fixture_root / "successful.jsonl").read_text(encoding="utf-8"),
            repository,
            expected_project=Path("/repo"),
            allowed_runtime_roots=[Path("/runtime")],
        )
        failed = parse_navigation_events(
            (fixture_root / "tool-failed.jsonl").read_text(encoding="utf-8"),
            repository,
            expected_project=Path("/repo"),
            allowed_runtime_roots=[Path("/runtime")],
        )
        unknown = parse_navigation_events(
            (fixture_root / "unknown-shape.jsonl").read_text(encoding="utf-8"),
            repository,
            expected_project=Path("/repo"),
            allowed_runtime_roots=[Path("/runtime")],
        )
        self.assertTrue(successful["graph_use_valid"])
        self.assertEqual(failed["failure_class"], "codegraph_tool_failure")
        self.assertEqual(unknown["failure_class"], "unknown_event_shape")

    def test_task2_package_digest_is_independent_of_new_arm(self):
        rows = []
        for path in sorted(TASK2_ROOT.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                rows.append(
                    {
                        "path": path.relative_to(TASK2_ROOT).as_posix(),
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
                )
        digest = hashlib.sha256(
            (
                json.dumps(
                    rows,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode()
        ).hexdigest()
        self.assertEqual(
            digest,
            TASK2_PACKAGE_SHA256,
        )
        self.assertTrue(rows)


if __name__ == "__main__":
    unittest.main()
