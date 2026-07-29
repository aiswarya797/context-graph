from __future__ import annotations

import argparse
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("codegraph_benchmark_authority_tests", ROOT / "benchmark.py")
assert SPEC and SPEC.loader
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)

sys.path.insert(0, str(ROOT / "src"))
from codegraph_bench.task2_evidence import (
    Task2EvidenceError,
    build_task2_evidence_root,
    validate_task2_evidence_root,
)


class CanonicalAuthorityTests(unittest.TestCase):
    def test_v18_uses_fresh_downstream_paths_and_pinned_v17_tail(self):
        config = benchmark.load_config()
        chain = benchmark._task2_authority_chain()
        self.assertEqual(
            benchmark.CANONICAL_TASK2_EVIDENCE_ROOT.name,
            "task2-evidence-root-v18.json",
        )
        self.assertEqual(
            benchmark.CANONICAL_TASK2_FREEZE_MARKER.name,
            "task2-freeze-marker-v18.json",
        )
        self.assertEqual(
            benchmark.CANONICAL_PATH_VALUES["setup_logs"],
            ".benchmark-work/codegraph/setup-logs-v18",
        )
        self.assertEqual(
            benchmark.CANONICAL_PATH_VALUES["doctor"],
            ".benchmark-work/codegraph/v18/doctor",
        )
        self.assertEqual(chain[-1]["generation"], "v17")
        self.assertEqual(
            chain[-1]["path"],
            benchmark.PREDECESSOR_TASK2_EVIDENCE_ROOT,
        )
        self.assertEqual(
            chain[-1]["sha256"],
            "380667527091c487e97e52d0f2e5ca757859ccf8a0c60d9c32cd0a1b51b49881",
        )
        self.assertEqual(
            benchmark._smoke_gate_path(config),
            benchmark.ROOT
            / ".benchmark-work/codegraph-enriched/smoke-gate.json",
        )

    def test_every_authority_environment_override_refuses(self):
        for variable in sorted(benchmark.AUTHORITY_OVERRIDE_ENVIRONMENT):
            with self.subTest(variable=variable), mock.patch.dict(
                os.environ, {variable: "/private/tmp/redirect"}, clear=False
            ):
                with self.assertRaisesRegex(benchmark.RunnerError, variable):
                    benchmark.load_config()

    def test_each_config_authority_path_and_root_key_refuse(self):
        config = benchmark.load_config()
        for key in benchmark.CANONICAL_PATH_VALUES:
            with self.subTest(key=key):
                mutated = {
                    **config,
                    "paths": {**config["paths"], key: f"./alternate/{key}"},
                }
                with self.assertRaisesRegex(benchmark.RunnerError, "canonical path differs"):
                    benchmark.paths(mutated)
        for key in ("task2_evidence_root", "task2_freeze_marker"):
            with self.subTest(key=key):
                mutated = {
                    **config,
                    "paths": {
                        **config["paths"],
                        key: ".benchmark-tools/codegraph/substitute.json",
                    },
                }
                with self.assertRaisesRegex(benchmark.RunnerError, "harness-owned"):
                    benchmark.paths(mutated)

    def test_symlink_component_refuses_even_when_target_is_inside_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            link = root / "linked"
            link.symlink_to(real, target_is_directory=True)
            with mock.patch.object(benchmark, "ROOT", root):
                with self.assertRaisesRegex(benchmark.RunnerError, "uses symlink"):
                    benchmark._assert_no_symlink_components(link / "authority.json")

    def test_downstream_override_refuses_before_scoring_or_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            sentinel = Path(temporary) / "sentinel"
            sentinel.write_text("unchanged\n", encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {"CODEGRAPH_SOURCE_LOCK": str(Path(temporary) / "alternate.json")},
                clear=False,
            ), mock.patch.object(benchmark, "score_run") as score_run:
                with self.assertRaisesRegex(benchmark.RunnerError, "authority environment override"):
                    benchmark.score(argparse.Namespace(run_id="codex-codegraph-enriched-authority-test"))
            score_run.assert_not_called()
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged\n")

    def test_prepare_refuses_missing_root_after_freeze_before_mutable_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "task2-evidence.freeze.json"
            marker.write_text("{}\n", encoding="utf-8")
            marker.chmod(0o400)
            evidence_root = root / "task2-evidence-root.json"
            predecessor = root / "task2-evidence-root-v2.json"

            with (
                mock.patch.object(benchmark, "load_config", return_value={}),
                mock.patch.object(
                    benchmark,
                    "paths",
                    return_value={
                        "task2_evidence_root": evidence_root,
                        "task2_freeze_marker": marker,
                    },
                ),
                mock.patch.object(
                    benchmark,
                    "PREDECESSOR_TASK2_EVIDENCE_ROOT",
                    predecessor,
                ),
                mock.patch.object(benchmark, "load_tasks") as load_tasks,
                mock.patch.object(benchmark, "_load_locked_source") as load_source,
            ):
                with self.assertRaisesRegex(
                    benchmark.RunnerError,
                    "frozen Task 2 authority is incomplete",
                ):
                    benchmark.codegraph_prepare()

            load_tasks.assert_not_called()
            load_source.assert_not_called()
            self.assertFalse(evidence_root.exists())

    def _copied_history(
        self,
        root: Path,
        *,
        present: set[int] | None = None,
    ) -> tuple[dict[str, object], ...]:
        source_chain = benchmark._task2_authority_chain()
        if present is None:
            present = set(range(len(source_chain)))
        copied: list[dict[str, object]] = []
        for index, entry in enumerate(source_chain):
            destination = root / f"{entry['generation']}.json"
            if index in present:
                shutil.copyfile(Path(entry["path"]), destination)
                destination.chmod(0o400)
            copied.append({**entry, "path": destination})
        root.chmod(0o555)
        return tuple(copied)

    def test_predecessor_state_matrix_true_genesis(self):
        with tempfile.TemporaryDirectory() as temporary:
            chain = self._copied_history(Path(temporary), present=set())
            predecessor = benchmark._task2_predecessor_authority(chain=chain)
        self.assertEqual(
            predecessor,
            {
                "kind": "genesis",
                "path": None,
                "bytes": 0,
                "mode": None,
                "sha256": None,
                "schema_version": None,
            },
        )

    def test_predecessor_state_matrix_complete_chain(self):
        with tempfile.TemporaryDirectory() as temporary:
            chain = self._copied_history(Path(temporary))
            predecessor = benchmark._task2_predecessor_authority(chain=chain)
        self.assertEqual(predecessor["kind"], "successor")
        self.assertEqual(predecessor["path"], str(chain[-1]["path"]))
        self.assertEqual(predecessor["sha256"], chain[-1]["sha256"])

    def test_predecessor_state_matrix_representative_partial_combinations_refuse(self):
        # The unchanged Task 2 suite retains the exhaustive 2^N matrix. This
        # copied Task 5 suite samples its boundary states while Task 5's own
        # authority tests cover the new Task 4 seam.
        chain_size = len(benchmark._task2_authority_chain())
        full_mask = (1 << chain_size) - 1
        masks = {
            1,
            full_mask - 1,
            sum(1 << index for index in range(0, chain_size, 2)),
        }
        for mask in sorted(masks):
            present = {
                index for index in range(chain_size) if mask & (1 << index)
            }
            with (
                self.subTest(mask=f"{mask:0{chain_size}b}"),
                tempfile.TemporaryDirectory() as temporary,
            ):
                chain = self._copied_history(
                    Path(temporary),
                    present=present,
                )
                with self.assertRaisesRegex(
                    benchmark.RunnerError,
                    "historical authority is incomplete",
                ):
                    benchmark._task2_predecessor_authority(chain=chain)

    def test_predecessor_state_matrix_each_digest_mismatch_refuses(self):
        chain_size = len(benchmark._task2_authority_chain())
        for index in range(chain_size):
            with (
                self.subTest(index=index),
                tempfile.TemporaryDirectory() as temporary,
            ):
                chain = self._copied_history(Path(temporary))
                path = Path(chain[index]["path"])
                path.chmod(0o600)
                path.write_bytes(path.read_bytes() + b"x")
                path.chmod(0o400)
                with self.assertRaisesRegex(
                    benchmark.RunnerError,
                    "history digest differs",
                ):
                    benchmark._task2_predecessor_authority(chain=chain)

    def test_predecessor_state_matrix_each_mode_mismatch_refuses(self):
        chain_size = len(benchmark._task2_authority_chain())
        for index in range(chain_size):
            with (
                self.subTest(index=index),
                tempfile.TemporaryDirectory() as temporary,
            ):
                chain = self._copied_history(Path(temporary))
                Path(chain[index]["path"]).chmod(0o600)
                with self.assertRaisesRegex(
                    benchmark.RunnerError,
                    "history mode differs",
                ):
                    benchmark._task2_predecessor_authority(chain=chain)

    def test_predecessor_state_matrix_each_symlink_refuses(self):
        chain_size = len(benchmark._task2_authority_chain())
        for index in range(chain_size):
            with (
                self.subTest(index=index),
                tempfile.TemporaryDirectory() as temporary,
            ):
                chain = self._copied_history(Path(temporary))
                path = Path(chain[index]["path"])
                source = Path(benchmark._task2_authority_chain()[index]["path"])
                Path(temporary).chmod(0o755)
                path.unlink()
                path.symlink_to(source)
                Path(temporary).chmod(0o555)
                with self.assertRaisesRegex(
                    benchmark.RunnerError,
                    "missing or symlinked",
                ):
                    benchmark._task2_predecessor_authority(chain=chain)

    def test_predecessor_refuses_path_swap_during_descriptor_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            chain = self._copied_history(root)
            target = Path(chain[0]["path"])
            real_open = os.open
            swapped = False

            def swapping_open(path, flags, *args, **kwargs):
                nonlocal swapped
                fd = real_open(path, flags, *args, **kwargs)
                if path == target.name and not swapped:
                    swapped = True
                    root.chmod(0o755)
                    target.unlink()
                    target.write_text("{}\n", encoding="utf-8")
                    target.chmod(0o400)
                    root.chmod(0o555)
                return fd

            with mock.patch.object(benchmark.os, "open", side_effect=swapping_open):
                with self.assertRaisesRegex(
                    benchmark.RunnerError,
                    "authority directory changed during scan",
                ):
                    benchmark._task2_predecessor_authority(chain=chain)

    def test_prepare_reaches_task4_validation_after_frozen_task2_pair(self):
        class PreparationReached(Exception):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence_root = root / "task2-root.json"
            marker = root / "task2-marker.json"
            evidence_root.write_text("{}\n", encoding="utf-8")
            marker.write_text("{}\n", encoding="utf-8")
            with (
                mock.patch.object(benchmark, "load_config", return_value={}),
                mock.patch.object(
                    benchmark,
                    "paths",
                    return_value={
                        "task2_evidence_root": evidence_root,
                        "task2_freeze_marker": marker,
                    },
                ),
                mock.patch.object(
                    benchmark,
                    "_require_task2_evidence",
                    return_value={"entry_count": 504},
                ),
                mock.patch.object(
                    benchmark,
                    "_load_runtime",
                    return_value=({}, {"executable_sha256": "a" * 64}),
                ),
                mock.patch.object(
                    benchmark,
                    "_require_task4_authority",
                    return_value={"records_by_task": {}},
                ),
                mock.patch.object(
                    benchmark,
                    "load_tasks",
                    side_effect=PreparationReached,
                ),
            ):
                with self.assertRaises(PreparationReached):
                    benchmark.codegraph_prepare()

    def test_prepare_refuses_incomplete_frozen_pair_before_task4_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence_root = root / "task2-root.json"
            evidence_root.write_text("{}\n", encoding="utf-8")
            with (
                mock.patch.object(benchmark, "load_config", return_value={}),
                mock.patch.object(
                    benchmark,
                    "paths",
                    return_value={
                        "task2_evidence_root": evidence_root,
                        "task2_freeze_marker": root / "missing-marker.json",
                    },
                ),
                mock.patch.object(
                    benchmark,
                    "_require_task2_evidence",
                ) as require_task2,
                mock.patch.object(
                    benchmark,
                    "_require_task4_authority",
                ) as require_task4,
            ):
                with self.assertRaisesRegex(
                    benchmark.RunnerError,
                    "frozen Task 2 authority is incomplete",
                ):
                    benchmark.codegraph_prepare()
            require_task2.assert_not_called()
            require_task4.assert_not_called()

    def test_scope_contract_rejects_coordinated_reduced_root(self):
        expected = [
            {"kind": "tree", "path": "indexes"},
            {"kind": "tree", "path": "setup-logs"},
        ]
        reduced = {
            "scopes": [{"kind": "tree", "path": "indexes"}],
        }
        with self.assertRaisesRegex(
            benchmark.RunnerError,
            "scope contract differs",
        ):
            benchmark._require_task2_scope_contract(reduced, expected)

    def test_authority_directory_must_be_sealed(self):
        with tempfile.TemporaryDirectory() as temporary:
            authority = Path(temporary) / "authority"
            authority.mkdir(mode=0o755)
            with self.assertRaisesRegex(
                benchmark.RunnerError,
                "authority directory is not sealed",
            ):
                benchmark._require_task2_authority_directory(authority)
            authority.chmod(0o555)
            benchmark._require_task2_authority_directory(authority)
            authority.chmod(0o755)

    def test_authority_root_and_marker_receive_immutable_flags(self):
        with tempfile.TemporaryDirectory() as temporary:
            authority = Path(temporary) / "authority"
            authority.mkdir(mode=0o755)
            evidence_root = authority / "root.json"
            marker = authority / "marker.json"
            evidence_root.write_text("{}\n", encoding="utf-8")
            marker.write_text("{}\n", encoding="utf-8")
            evidence_root.chmod(0o400)
            marker.chmod(0o400)
            try:
                benchmark._seal_task2_authority_files(evidence_root, marker)
                benchmark._require_task2_authority_files(evidence_root, marker)
            finally:
                authority.chmod(0o755)
                if hasattr(os, "chflags"):
                    os.chflags(evidence_root, 0)
                    os.chflags(marker, 0)


class ActiveInputMutationTests(unittest.TestCase):
    def _fixture(self, temporary: str) -> tuple[Path, Path]:
        root = Path(temporary)
        (root / "modules").mkdir()
        files = {
            "benchmark.py": "print('benchmark')\n",
            "codegraph.toml": "[runtime]\ntelemetry=false\n",
            "prompt.md": "Use the graph.\n",
            "schema.json": '{"type":"object"}\n',
            "modules/artifacts.py": "VALUE = 1\n",
            "modules/integrity.py": "VALUE = 2\n",
        }
        for relative, contents in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
        manifest = root / "task2-root-v2.json"
        build_task2_evidence_root(
            root=root,
            manifest_path=manifest,
            scopes=[
                {"kind": "file", "path": "benchmark.py", "freeze": False},
                {"kind": "file", "path": "codegraph.toml", "freeze": False},
                {"kind": "file", "path": "prompt.md", "freeze": False},
                {"kind": "file", "path": "schema.json", "freeze": False},
                {"kind": "glob", "path": "modules/*.py", "freeze": False},
            ],
            identities={"active_harness_sha256": "a" * 64},
            predecessor={"path": "legacy.json", "sha256": "b" * 64},
            mutable_exclusions=["attempt outputs"],
        )
        return root, manifest

    def test_each_authoritative_input_byte_mutation_refuses(self):
        for relative in (
            "benchmark.py",
            "codegraph.toml",
            "prompt.md",
            "schema.json",
            "modules/artifacts.py",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                root, manifest = self._fixture(temporary)
                path = root / relative
                path.write_bytes(path.read_bytes() + b"# mutation\n")
                with self.assertRaisesRegex(Task2EvidenceError, "entry_mismatch"):
                    validate_task2_evidence_root(root=root, manifest_path=manifest)

    def test_unexpected_module_and_root_substitution_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, manifest = self._fixture(temporary)
            (root / "modules" / "unexpected.py").write_text("VALUE = 3\n", encoding="utf-8")
            with self.assertRaisesRegex(Task2EvidenceError, "addition_or_removal"):
                validate_task2_evidence_root(root=root, manifest_path=manifest)
        with tempfile.TemporaryDirectory() as temporary:
            root, manifest = self._fixture(temporary)
            substitute = root / "substitute.json"
            shutil.copyfile(manifest, substitute)
            manifest.unlink()
            manifest.symlink_to(substitute)
            with self.assertRaisesRegex(Task2EvidenceError, "missing_or_mutable"):
                validate_task2_evidence_root(root=root, manifest_path=manifest)


if __name__ == "__main__":
    unittest.main()
