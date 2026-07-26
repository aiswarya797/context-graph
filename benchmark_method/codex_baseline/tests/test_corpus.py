import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

sys_path = Path(__file__).parents[1] / "src"
import sys
sys.path.insert(0, str(sys_path))

from context_graph_bench.corpus import (
    CorpusError,
    compile_corpus,
    verify_official_evaluator,
    verify_repository_head,
)


ROOT = Path(__file__).parents[3]
BASELINE = ROOT / "benchmark_method/codex_baseline"
COMMON = ROOT / "benchmark_method/common"
BENCHMARK = BASELINE / "benchmark.py"
SOURCES = COMMON / "inputs/sources"
EVALUATOR = COMMON / "official/eval.py"
PROVENANCE = COMMON / "official/provenance.json"


class CorpusTests(unittest.TestCase):
    def test_baseline_layout_is_self_contained_and_command_is_cwd_independent(self):
        expected_files = (
            BENCHMARK,
            BASELINE / "config/baseline.toml",
            BASELINE / "config/region-selection-prompt.md",
            BASELINE / "schemas/attempt-record.schema.json",
            BASELINE / "schemas/run-manifest.schema.json",
            BASELINE / "src/context_graph_bench/__init__.py",
            COMMON / "inputs/select25-source-merge.manifest.json",
            COMMON / "schemas/agent-regions.schema.json",
            COMMON / "schemas/pricing-profile.schema.json",
            EVALUATOR,
            PROVENANCE,
        )
        for path in expected_files:
            self.assertTrue(path.is_file(), path)
        self.assertFalse((ROOT / "/".join(("benchmark_method", "benchmark.py"))).exists())

        probe = (
            "import runpy; "
            "module = runpy.run_path(%r); "
            "paths = module['paths'](); "
            "required = ('manifest', 'evaluator', 'provenance', 'schema', 'prompt'); "
            "assert paths['sources'].is_dir() and all(paths[name].is_file() for name in required), paths; "
            "assert paths['work'].name == 'codex-baseline'; "
            "print(paths['evaluator'])"
        ) % str(BENCHMARK)
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                ["python3", "-c", probe],
                cwd=directory,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("benchmark_method/common/official/eval.py", result.stdout)

    def test_no_live_code_path_uses_old_baseline_layout(self):
        old_paths = tuple(
            "/".join(("benchmark_method", suffix))
            for suffix in (
                "benchmark.py",
                "config/",
                "src/",
                "tests/",
                "official/",
                "inputs/",
                "schemas/",
            )
        )
        live_files = [
            BENCHMARK,
            BASELINE / "src/context_graph_bench/report.py",
            ROOT / "pyproject.toml",
        ]
        for path in live_files:
            contents = path.read_text(encoding="utf-8")
            for old_path in old_paths:
                self.assertNotIn(old_path, contents, path)

    def test_current_sources_are_25_rows_24_unique_and_keep_duplicate_membership(self):
        tasks, manifest = compile_corpus(SOURCES)
        self.assertEqual(manifest["source_row_count"], 25)
        self.assertEqual(manifest["unique_task_count"], 24)
        self.assertEqual(list(manifest["duplicate_instance_ids"]), ["pydata__xarray-4629"])
        self.assertEqual(len(manifest["duplicate_instance_ids"]["pydata__xarray-4629"]), 2)
        self.assertEqual(len(tasks), 24)

    def test_identical_duplicate_deduplicates_and_conflicting_duplicate_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = {"instance_id": "x", "repo": "a/b", "base_commit": "abc", "problem_statement": "same", "ground_truth": {}}
            for name in ("select10", "select15"):
                (root / f"bench.{name}.jsonl").write_text(json.dumps(row) + "\n")
                (root / f"issue_map.{name}.json").write_text(json.dumps({"x": "same"}))
            tasks, manifest = compile_corpus(root)
            self.assertEqual(len(tasks), 1)
            self.assertEqual(manifest["source_row_count"], 2)
            row["base_commit"] = "different"
            (root / "bench.select15.jsonl").write_text(json.dumps(row) + "\n")
            with self.assertRaises(CorpusError):
                compile_corpus(root)

    def test_evaluator_digest_is_hard_gate(self):
        provenance = verify_official_evaluator(EVALUATOR, PROVENANCE)
        self.assertEqual(provenance["sha256"], "feea0a7fe67b08e68c940e10887d5b4feaae0b8c58e256eb09f253e65492d745")
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "eval.py"
            shutil.copyfile(EVALUATOR, changed)
            changed.write_bytes(changed.read_bytes() + b"\n")
            with self.assertRaises(CorpusError):
                verify_official_evaluator(changed, PROVENANCE)

    def test_parent_context_compiler_metadata_cannot_validate_select10_snapshot(self):
        source_only = Path("/Users/aiswarya/Documents/Context Compiler/.benchmark-data/select10/repos/python-xarray")
        with self.assertRaises(CorpusError):
            verify_repository_head(source_only, "a41edc7bf5302f2ea327943c0c48c532b12009bc")

    def test_prepared_snapshot_has_exact_head_and_clean_tree(self):
        prepared = json.loads((ROOT / ".benchmark-work/codex-baseline/prepared.json").read_text())
        for item in prepared["tasks"]:
            result = verify_repository_head(Path(item["resolved_path"]), item["requested_base_commit"])
            self.assertEqual(result["verified_head"], item["requested_base_commit"])

    def test_manifest_rebuild_is_deterministic(self):
        first = compile_corpus(SOURCES)[1]
        second = compile_corpus(SOURCES)[1]
        self.assertEqual(json.dumps(first, sort_keys=True, separators=(",", ":")), json.dumps(second, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    unittest.main()
