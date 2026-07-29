from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ARM_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ARM_ROOT / "src"))

from codegraph_bench.task7_freeze import (  # noqa: E402
    TreatmentFreezeError,
    freeze_payload,
    validate_treatment_freeze,
    write_treatment_freeze,
)

SPEC = importlib.util.spec_from_file_location(
    "codegraph_benchmark_task7_tests",
    ARM_ROOT / "benchmark.py",
)
assert SPEC and SPEC.loader
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


def treatment() -> dict[str, object]:
    return {
        "contract": {"sha256": "a" * 64},
        "official_smoke": {
            "run_id": "codex-codegraph-enriched-smoke-task7-v1",
            "sample_count": 1,
            "task": {
                "instance_id": "astral-sh__ruff-15330",
                "base_commit": "b2a0d68d70ee690ea871fe9b3317be43075ddb33",
            },
        },
    }


class Task7FreezeTests(unittest.TestCase):
    def test_write_once_freeze_is_canonical_read_only_and_revalidates(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "treatment-freeze-v1.json"
            expected = treatment()

            written = write_treatment_freeze(path, expected)

            self.assertEqual(written, freeze_payload(expected))
            self.assertEqual(
                validate_treatment_freeze(path, expected),
                written,
            )
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
            self.assertEqual(
                path.read_bytes(),
                (
                    json.dumps(
                        written,
                        ensure_ascii=False,
                        sort_keys=True,
                        indent=2,
                    )
                    + "\n"
                ).encode(),
            )
            with self.assertRaisesRegex(
                TreatmentFreezeError,
                "already exists",
            ):
                write_treatment_freeze(path, expected)

    def test_freeze_refuses_missing_writable_symlink_malformed_and_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = root / "missing.json"
            with self.assertRaisesRegex(TreatmentFreezeError, "missing"):
                validate_treatment_freeze(missing, treatment())

            path = root / "freeze.json"
            write_treatment_freeze(path, treatment())
            os.chmod(path, 0o600)
            with self.assertRaisesRegex(TreatmentFreezeError, "read-only"):
                validate_treatment_freeze(path, treatment())

            os.chmod(path, 0o400)
            with self.assertRaisesRegex(TreatmentFreezeError, "differ"):
                validate_treatment_freeze(
                    path,
                    {
                        **treatment(),
                        "contract": {"sha256": "c" * 64},
                    },
                )

            os.chmod(path, 0o600)
            path.write_text("{}\n", encoding="utf-8")
            os.chmod(path, 0o400)
            with self.assertRaisesRegex(
                TreatmentFreezeError,
                "fields differ",
            ):
                validate_treatment_freeze(path, treatment())

            target = root / "target.json"
            write_treatment_freeze(target, treatment())
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(TreatmentFreezeError, "symlink"):
                validate_treatment_freeze(link, treatment())

    def test_smoke_task_and_run_id_are_selected_from_exact_freeze(self):
        frozen = freeze_payload(treatment())
        tasks = [
            {
                "instance_id": "other",
                "base_commit": "d" * 40,
            },
            {
                "instance_id": "astral-sh__ruff-15330",
                "base_commit": "b2a0d68d70ee690ea871fe9b3317be43075ddb33",
            },
        ]

        selected = benchmark._select_predeclared_smoke_task(
            tasks,
            frozen,
            "codex-codegraph-enriched-smoke-task7-v1",
        )

        self.assertEqual(selected["instance_id"], "astral-sh__ruff-15330")
        with self.assertRaisesRegex(benchmark.RunnerError, "run_id differs"):
            benchmark._select_predeclared_smoke_task(
                tasks,
                frozen,
                "codex-codegraph-enriched-smoke-other",
            )
        with self.assertRaisesRegex(benchmark.RunnerError, "task differs"):
            benchmark._select_predeclared_smoke_task(
                tasks[:1],
                frozen,
                "codex-codegraph-enriched-smoke-task7-v1",
            )
        with self.assertRaisesRegex(benchmark.RunnerError, "task differs"):
            benchmark._select_predeclared_smoke_task(
                [tasks[1], dict(tasks[1])],
                frozen,
                "codex-codegraph-enriched-smoke-task7-v1",
            )

    def test_frozen_smoke_manifest_requires_exact_run_and_task(self):
        frozen = freeze_payload(treatment())
        manifest = {
            "run_id": "codex-codegraph-enriched-smoke-task7-v1",
            "configuration": {"sample_count": 1},
            "corpus": {
                "tasks": [
                    {
                        "instance_id": "astral-sh__ruff-15330",
                        "base_commit": (
                            "b2a0d68d70ee690ea871fe9b3317be43075ddb33"
                        ),
                    }
                ]
            },
        }

        selected = benchmark._validate_frozen_smoke_manifest(
            frozen,
            manifest["run_id"],
            manifest,
        )

        self.assertEqual(selected, manifest["corpus"]["tasks"][0])
        with self.assertRaisesRegex(
            benchmark.RunnerError,
            "manifest differs",
        ):
            benchmark._validate_frozen_smoke_manifest(
                frozen,
                "codex-codegraph-enriched-smoke-other",
                manifest,
            )
        manifest["corpus"]["tasks"][0]["instance_id"] = "other"
        with self.assertRaisesRegex(
            benchmark.RunnerError,
            "task differs",
        ):
            benchmark._validate_frozen_smoke_manifest(
                frozen,
                manifest["run_id"],
                manifest,
            )

    def test_full_run_gate_refuses_valid_shape_wrong_frozen_smoke_task(self):
        frozen = freeze_payload(treatment())
        smoke_run_id = "codex-codegraph-enriched-smoke-task7-v1"
        manifest = {
            "run_id": smoke_run_id,
            "configuration": {"sample_count": 1},
            "corpus": {
                "tasks": [
                    {
                        "instance_id": "other",
                        "base_commit": "d" * 40,
                    }
                ]
            },
        }
        gate = {
            "schema_version": "codegraph-smoke-gate-v2",
            "passed": True,
            "smoke_run_id": smoke_run_id,
            "binding": {
                "harness_sha256": "e" * 64,
                "real_task": manifest["corpus"]["tasks"][0],
            },
            "manual_inspection": {"acknowledged": True},
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gate_path = root / "smoke-gate.json"
            gate_path.write_text(
                json.dumps(gate) + "\n",
                encoding="utf-8",
            )
            with (
                mock.patch.object(
                    benchmark,
                    "_smoke_gate_path",
                    return_value=gate_path,
                ),
                mock.patch.object(
                    benchmark,
                    "resolve_run_root",
                    return_value=root,
                ),
                mock.patch.object(
                    benchmark,
                    "load_treatment_manifest",
                    return_value=manifest,
                ),
                mock.patch.object(
                    benchmark,
                    "verify_corpus_contract",
                ),
                mock.patch.object(
                    benchmark,
                    "verify_bound_run_artifacts",
                ),
                mock.patch.object(
                    benchmark,
                    "_require_run_treatment_freeze",
                    return_value=frozen,
                ),
            ):
                with self.assertRaisesRegex(
                    benchmark.RunnerError,
                    "official smoke task differs",
                ):
                    benchmark._require_smoke_gate(
                        {},
                        {},
                        {},
                        [
                            {
                                "instance_id": (
                                    "astral-sh__ruff-15330"
                                ),
                                "base_commit": (
                                    "b2a0d68d70ee690ea871fe9b3317be43075ddb33"
                                ),
                            }
                        ],
                        "codex-codegraph-enriched-full-v1",
                    )

    def test_run_binding_requires_exact_copied_freeze_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            live = root / "live-freeze.json"
            frozen = write_treatment_freeze(live, treatment())
            run_root = root / "run"
            run_root.mkdir()
            copied = run_root / "treatment-freeze.json"
            copied.write_bytes(live.read_bytes())
            manifest = {
                "treatment_freeze": {
                    "path": "treatment-freeze.json",
                    "sha256": benchmark.sha256_file(live),
                    "treatment_sha256": frozen["treatment_sha256"],
                }
            }

            benchmark._validate_run_treatment_freeze(
                run_root,
                manifest,
                live,
                frozen,
            )

            copied.write_bytes(b"{}\n")
            with self.assertRaisesRegex(
                benchmark.RunnerError,
                "run copy differs",
            ):
                benchmark._validate_run_treatment_freeze(
                    run_root,
                    manifest,
                    live,
                    frozen,
                )

            copied.write_bytes(live.read_bytes())
            manifest["treatment_freeze"]["treatment_sha256"] = "f" * 64
            with self.assertRaisesRegex(
                benchmark.RunnerError,
                "binding differs",
            ):
                benchmark._validate_run_treatment_freeze(
                    run_root,
                    manifest,
                    live,
                    frozen,
                )

    def test_production_smoke_refuses_before_runner_when_freeze_is_missing(self):
        args = argparse.Namespace(
            run_id="codex-codegraph-enriched-smoke-task7-v1"
        )
        original = benchmark._task7_treatment_freeze_path
        with tempfile.TemporaryDirectory() as temporary:
            try:
                benchmark._task7_treatment_freeze_path = (
                    lambda: Path(temporary) / "missing.json"
                )
                with self.assertRaisesRegex(
                    benchmark.TreatmentFreezeError,
                    "missing",
                ):
                    benchmark.run(args, smoke=True)
            finally:
                benchmark._task7_treatment_freeze_path = original


if __name__ == "__main__":
    unittest.main()
