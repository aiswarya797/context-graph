from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ARM_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ARM_ROOT.parents[1]
sys.path.insert(0, str(ARM_ROOT / "src"))

from codegraph_bench.codegraph import (  # noqa: E402
    attempt_index_copy,
    directory_manifest,
    load_source_lock,
    stage_runtime_bundle,
)
from codegraph_bench import task5_authority  # noqa: E402
from codegraph_bench.task5_authority import (  # noqa: E402
    EnrichedAuthorityError,
    TASK2_RUNTIME_EXECUTABLE_SHA256,
    load_enriched_index,
    load_task4_authority,
    validate_enriched_index,
    validate_measured_runtime,
)


TASK_ID = "pallets__flask-5014"
BASE_COMMIT = "7ee9ceb71e868944a46e1ff00b506772a53a4f1d"
ZERO_YIELD_TASK_ID = "axios__axios-4731"
ZERO_YIELD_COMMIT = "c30252f685e8f4326722de84923fcbc8cf557f06"


class Task5AuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runtime = json.loads(
            (
                REPOSITORY_ROOT
                / ".benchmark-tools/codegraph/runtime/runtime.json"
            ).read_text(encoding="utf-8")
        )
        config = tomllib.loads(
            (ARM_ROOT / "config/codegraph.toml").read_text(encoding="utf-8")
        )
        cls.exclude_names = set(config["index"]["exclude_names"])

    def authority(self) -> dict:
        return load_task4_authority(
            REPOSITORY_ROOT,
            runtime=self.runtime,
        )

    def projection(
        self,
        task_id: str = TASK_ID,
        base_commit: str = BASE_COMMIT,
    ) -> dict:
        return load_enriched_index(
            REPOSITORY_ROOT,
            authority=self.authority(),
            runtime=self.runtime,
            task_id=task_id,
            base_commit=base_commit,
            exclude_names=self.exclude_names,
        )

    def test_sealed_authority_accepts_all_24_and_both_yield_classes(self):
        authority = self.authority()
        self.assertEqual(len(authority["records_by_task"]), 24)
        fact_bearing = self.projection()
        zero_yield = self.projection(
            ZERO_YIELD_TASK_ID,
            ZERO_YIELD_COMMIT,
        )
        self.assertEqual(
            fact_bearing["enriched_authority"]["yield_classification"],
            "fact-bearing",
        )
        self.assertEqual(
            zero_yield["enriched_authority"]["yield_classification"],
            "supported-zero-yield",
        )
        self.assertEqual(
            fact_bearing["codegraph_executable_sha256"],
            TASK2_RUNTIME_EXECUTABLE_SHA256,
        )

    def test_original_or_tampered_index_projection_is_refused(self):
        authority = self.authority()
        expected = self.projection()
        original_task2_record = next(
            json.loads(path.read_text(encoding="utf-8"))
            for path in (
                REPOSITORY_ROOT / ".benchmark-work/codegraph/indexes"
            ).glob("*/*.record.json")
            if json.loads(path.read_text(encoding="utf-8")).get("task_id")
            == TASK_ID
        )
        with self.assertRaisesRegex(
            EnrichedAuthorityError,
            "runtime projection differs",
        ):
            validate_enriched_index(
                REPOSITORY_ROOT,
                authority=authority,
                runtime=self.runtime,
                record=original_task2_record,
                task_id=TASK_ID,
                base_commit=BASE_COMMIT,
                exclude_names=self.exclude_names,
            )
        changed = copy.deepcopy(expected)
        changed["enriched_authority"]["yield_classification"] = (
            "supported-zero-yield"
        )
        with self.assertRaisesRegex(
            EnrichedAuthorityError,
            "runtime projection differs",
        ):
            validate_enriched_index(
                REPOSITORY_ROOT,
                authority=authority,
                runtime=self.runtime,
                record=changed,
                task_id=TASK_ID,
                base_commit=BASE_COMMIT,
                exclude_names=self.exclude_names,
            )

    def test_wrong_revision_and_wrong_runtime_are_refused(self):
        authority = self.authority()
        with self.assertRaisesRegex(
            EnrichedAuthorityError,
            "revision differs",
        ):
            load_enriched_index(
                REPOSITORY_ROOT,
                authority=authority,
                runtime=self.runtime,
                task_id=TASK_ID,
                base_commit="0" * 40,
                exclude_names=self.exclude_names,
            )
        changed_runtime = dict(self.runtime)
        changed_runtime["executable_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            EnrichedAuthorityError,
            "wrong measured runtime",
        ):
            load_task4_authority(
                REPOSITORY_ROOT,
                runtime=changed_runtime,
            )

    def test_patched_builder_and_changed_runtime_bytes_are_refused(self):
        with self.assertRaisesRegex(
            EnrichedAuthorityError,
            "outside the frozen Task 2 checkout",
        ):
            validate_measured_runtime(
                runtime={
                    **self.runtime,
                    "executable_path": str(
                        REPOSITORY_ROOT
                        / ".benchmark-tools/codegraph-enriched/source"
                        / "dist/bin/codegraph.js"
                    ),
                },
                task2_checkout=(
                    REPOSITORY_ROOT / ".benchmark-tools/codegraph/source"
                ),
                enriched_builder_checkout=(
                    REPOSITORY_ROOT
                    / ".benchmark-tools/codegraph-enriched/source"
                ),
            )
        changed = dict(self.runtime)
        changed["executable_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            EnrichedAuthorityError,
            "measured executable differs",
        ):
            validate_measured_runtime(
                runtime=changed,
                task2_checkout=(
                    REPOSITORY_ROOT / ".benchmark-tools/codegraph/source"
                ),
                enriched_builder_checkout=(
                    REPOSITORY_ROOT
                    / ".benchmark-tools/codegraph-enriched/source"
                ),
            )

    def test_current_task3_builder_file_mismatch_is_refused(self):
        original_sha256 = task5_authority.sha256_file
        target = (
            REPOSITORY_ROOT
            / ".benchmark-tools/codegraph-enriched/source"
            / "src/enrichment/extractors/guards.ts"
        )

        def changed_digest(path: Path) -> str:
            if path == target:
                return "0" * 64
            return original_sha256(path)

        with (
            mock.patch.object(
                task5_authority,
                "sha256_file",
                side_effect=changed_digest,
            ),
            self.assertRaisesRegex(
                EnrichedAuthorityError,
                "Task 3 implementation file differs",
            ),
        ):
            self.authority()

    def test_unexpected_dirty_task3_builder_entry_is_refused(self):
        original_git = task5_authority._git
        builder = (
            REPOSITORY_ROOT
            / ".benchmark-tools/codegraph-enriched/source"
        )

        def dirty_builder(repository: Path, *args: str) -> str:
            value = original_git(repository, *args)
            if repository == builder and args == (
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ):
                return f"{value}\n?? unexpected-task5-dirty-entry"
            return value

        with (
            mock.patch.object(
                task5_authority,
                "_git",
                side_effect=dirty_builder,
            ),
            self.assertRaisesRegex(
                EnrichedAuthorityError,
                "builder dirty state differs from sealed manifests",
            ),
        ):
            self.authority()

    def test_dirty_source_and_missing_provenance_fail_closed(self):
        authority = self.authority()
        original_git = task5_authority._git

        def dirty_git(repository: Path, *args: str) -> str:
            if args == ("status", "--porcelain"):
                return " M source.py"
            return original_git(repository, *args)

        with mock.patch.object(
            task5_authority,
            "_git",
            side_effect=dirty_git,
        ), self.assertRaisesRegex(
            EnrichedAuthorityError,
            "repository is dirty",
        ):
            load_enriched_index(
                REPOSITORY_ROOT,
                authority=authority,
                runtime=self.runtime,
                task_id=TASK_ID,
                base_commit=BASE_COMMIT,
                exclude_names=self.exclude_names,
            )

        summary = authority["records_by_task"][TASK_ID]
        record_path = REPOSITORY_ROOT / summary["record"]["path"]
        original_read = task5_authority._read_json

        def missing_provenance(path: Path, *, label: str) -> dict:
            value = original_read(path, label=label)
            if path == record_path:
                value = copy.deepcopy(value)
                value["enrichment"]["provenance_validation"][
                    "all_evidence_resolves_to_inventory"
                ] = False
            return value

        with mock.patch.object(
            task5_authority,
            "_read_json",
            side_effect=missing_provenance,
        ), self.assertRaisesRegex(
            EnrichedAuthorityError,
            "enrichment provenance is incomplete",
        ):
            load_enriched_index(
                REPOSITORY_ROOT,
                authority=authority,
                runtime=self.runtime,
                task_id=TASK_ID,
                base_commit=BASE_COMMIT,
                exclude_names=self.exclude_names,
            )

    def test_mutable_index_and_sqlite_sidecars_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            index = Path(temporary) / "index"
            index.mkdir()
            database = index / "codegraph.db"
            database.write_bytes(b"fixture")
            with self.assertRaisesRegex(
                EnrichedAuthorityError,
                "remains writable",
            ):
                task5_authority._require_read_only_tree(index)
            os.chmod(database, 0o400)
            os.chmod(index, 0o500)
            task5_authority._require_read_only_tree(index)
            os.chmod(index, 0o700)
            sidecar = index / "codegraph.db-wal"
            sidecar.write_bytes(b"sidecar")
            os.chmod(sidecar, 0o400)
            os.chmod(index, 0o500)
            with self.assertRaisesRegex(
                EnrichedAuthorityError,
                "SQLite sidecar",
            ):
                task5_authority._require_read_only_tree(index)
            os.chmod(index, 0o700)

    def test_production_copy_lifecycle_uses_exact_staged_runtime(self):
        record = self.projection()
        lock = load_source_lock(
            REPOSITORY_ROOT / ".benchmark-tools/codegraph/source-lock.json"
        )
        source = Path(record["repository_path"])
        master_before = directory_manifest(Path(record["index_path"]))
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            child = scratch / "child"
            cloned = subprocess.run(
                [
                    "git",
                    "clone",
                    "--no-local",
                    "--no-checkout",
                    str(source),
                    str(child),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(cloned.returncode, 0, cloned.stderr)
            checked = subprocess.run(
                [
                    "git",
                    "-C",
                    str(child),
                    "checkout",
                    "--detach",
                    BASE_COMMIT,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)
            runtime_stage = stage_runtime_bundle(
                runtime=self.runtime,
                checkout=(
                    REPOSITORY_ROOT / ".benchmark-tools/codegraph/source"
                ),
                stage_root=scratch / "runtime",
            )
            attempt_root = scratch / "attempt"
            attempt_root.mkdir()
            evidence_root = scratch / "evidence"

            def frozen_status(_command: list[str], **kwargs: object):
                copy_path = child / kwargs["env"]["CODEGRAPH_DIR"]
                status = record["status"]
                return SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps(
                        {
                            "initialized": True,
                            "version": status["version"],
                            "projectPath": str(child),
                            "indexPath": str(copy_path),
                            "lastIndexed": status["last_indexed"],
                            "fileCount": status["file_count"],
                            "nodeCount": status["symbol_count"],
                            "edgeCount": status["edge_count"],
                            "backend": status["backend"],
                            "journalMode": status["journal_mode"],
                            "index": {
                                "state": status["index_state"],
                                "pendingRefs": status["pending_refs"],
                            },
                        }
                    ),
                    stderr="",
                )

            with attempt_index_copy(
                record=record,
                lock=lock,
                master_repository=source,
                child_repository=child,
                attempt_root=attempt_root,
                evidence_root=evidence_root,
                runtime_stage=runtime_stage,
                run_process=frozen_status,
            ) as lifecycle:
                self.assertTrue(lifecycle["index_path"].is_dir())
                self.assertEqual(
                    Path(lifecycle["launcher"][1]).read_bytes(),
                    Path(runtime_stage["codegraph_executable"]).read_bytes(),
                )
            lifecycle_record = json.loads(
                (evidence_root / "lifecycle.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertTrue(lifecycle_record["prepared"])
            self.assertTrue(lifecycle_record["cleanup_complete"])
            self.assertTrue(lifecycle_record["master_unchanged"])
            self.assertFalse(Path(lifecycle_record["copy_path"]).exists())
        self.assertEqual(
            directory_manifest(Path(record["index_path"])),
            master_before,
        )


if __name__ == "__main__":
    unittest.main()
