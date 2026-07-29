from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from codegraph_bench.task2_evidence import (
    Task2EvidenceError,
    build_task2_evidence_root,
    build_task2_freeze_marker,
    validate_task2_freeze_marker,
    validate_task2_evidence_root,
)


class Task2EvidenceTests(unittest.TestCase):
    def _fixture(self, temporary: str) -> tuple[Path, Path]:
        root = Path(temporary)
        evidence = root / "evidence"
        evidence.mkdir()
        (evidence / "duration.json").write_text('{"duration_seconds":1}\n', encoding="utf-8")
        (evidence / "status.stdout").write_text('{"ready":true}\n', encoding="utf-8")
        (evidence / "raw.stderr").write_text("", encoding="utf-8")
        manifest = root / "task2-evidence-root.json"
        build_task2_evidence_root(
            root=root,
            manifest_path=manifest,
            scopes=[{"kind": "tree", "path": "evidence"}],
            identities={"locked_commit": "a" * 40},
            predecessor={"path": "legacy.json", "sha256": "b" * 64},
            mutable_exclusions=["attempt outputs"],
        )
        return root, manifest

    def test_create_once_root_validates_and_refuses_rehash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, manifest = self._fixture(temporary)
            self.assertEqual(validate_task2_evidence_root(root=root, manifest_path=manifest)["entry_count"], 3)
            with self.assertRaisesRegex(Task2EvidenceError, "already_frozen"):
                build_task2_evidence_root(
                    root=root,
                    manifest_path=manifest,
                    scopes=[{"kind": "tree", "path": "evidence"}],
                    identities={},
                    predecessor={"path": "legacy.json", "sha256": "b" * 64},
                    mutable_exclusions=["attempt outputs"],
                )

    def test_dangling_manifest_symlink_refuses_before_evidence_modes_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            target = evidence / "status.json"
            target.write_text('{"ready":true}\n', encoding="utf-8")
            target.chmod(0o600)
            manifest = root / "task2-evidence-root.json"
            manifest.symlink_to(root / "missing.json")

            with self.assertRaisesRegex(
                Task2EvidenceError,
                "already_frozen",
            ):
                build_task2_evidence_root(
                    root=root,
                    manifest_path=manifest,
                    scopes=[{"kind": "tree", "path": "evidence"}],
                    identities={"locked_commit": "a" * 40},
                    predecessor={"kind": "genesis"},
                    mutable_exclusions=["attempt outputs"],
                )
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_duration_status_and_raw_byte_mutations_refuse(self):
        for filename in ("duration.json", "status.stdout", "raw.stderr"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                root, manifest = self._fixture(temporary)
                target = root / "evidence" / filename
                target.chmod(0o600)
                target.write_bytes(target.read_bytes() + b"x")
                target.chmod(0o400)
                with self.assertRaisesRegex(Task2EvidenceError, "entry_mismatch"):
                    validate_task2_evidence_root(root=root, manifest_path=manifest)

    def test_mode_addition_and_removal_refuse(self):
        for mutation, error in (
            ("mode", "entry_mismatch"),
            ("addition", "scope_addition_or_removal"),
            ("removal", "scope_addition_or_removal"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root, manifest = self._fixture(temporary)
                target = root / "evidence" / "status.stdout"
                if mutation == "mode":
                    target.chmod(0o600)
                elif mutation == "addition":
                    added = root / "evidence" / "unexpected.log"
                    added.write_text("unexpected\n", encoding="utf-8")
                    added.chmod(0o400)
                else:
                    os.unlink(target)
                with self.assertRaisesRegex(Task2EvidenceError, error):
                    validate_task2_evidence_root(root=root, manifest_path=manifest)

    def test_freeze_marker_refuses_missing_root_without_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, manifest = self._fixture(temporary)
            marker = root / "task2-evidence.freeze.json"
            frozen = build_task2_freeze_marker(
                root=root,
                manifest_path=manifest,
                marker_path=marker,
            )
            marker_bytes = marker.read_bytes()

            self.assertEqual(frozen["evidence_root_sha256"], self._sha256(manifest))
            manifest.unlink()

            with self.assertRaisesRegex(
                Task2EvidenceError,
                "task2_evidence_root_missing_after_freeze",
            ):
                validate_task2_freeze_marker(
                    root=root,
                    manifest_path=manifest,
                    marker_path=marker,
                )
            self.assertEqual(marker.read_bytes(), marker_bytes)
            self.assertFalse(manifest.exists())

    def test_freeze_marker_is_write_once_and_detects_root_substitution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, manifest = self._fixture(temporary)
            marker = root / "task2-evidence.freeze.json"
            build_task2_freeze_marker(
                root=root,
                manifest_path=manifest,
                marker_path=marker,
            )
            with self.assertRaisesRegex(
                Task2EvidenceError,
                "task2_freeze_marker_already_exists",
            ):
                build_task2_freeze_marker(
                    root=root,
                    manifest_path=manifest,
                    marker_path=marker,
                )

            manifest.chmod(0o600)
            manifest.write_bytes(manifest.read_bytes() + b" ")
            manifest.chmod(0o400)
            with self.assertRaisesRegex(
                Task2EvidenceError,
                "task2_evidence_root_changed_after_freeze",
            ):
                validate_task2_freeze_marker(
                    root=root,
                    manifest_path=manifest,
                    marker_path=marker,
                )

    def test_freeze_marker_rejects_semantic_preserving_byte_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, manifest = self._fixture(temporary)
            marker = root / "task2-evidence.freeze.json"
            build_task2_freeze_marker(
                root=root,
                manifest_path=manifest,
                marker_path=marker,
            )
            marker.chmod(0o600)
            marker.write_bytes(b"\n" + marker.read_bytes())
            marker.chmod(0o400)

            with self.assertRaisesRegex(
                Task2EvidenceError,
                "task2_freeze_marker_bytes_noncanonical",
            ):
                validate_task2_freeze_marker(
                    root=root,
                    manifest_path=manifest,
                    marker_path=marker,
                )

    @staticmethod
    def _sha256(path: Path) -> str:
        import hashlib

        return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    unittest.main()
