from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import tempfile
import unittest
from unittest import mock


BUNDLE_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = BUNDLE_ROOT / "materialize.py"
SPEC = importlib.util.spec_from_file_location("task2_materialize", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load materializer")
MATERIALIZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATERIALIZER)


class MaterializerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name) / "workspace"
        self.bundle = (
            self.workspace / "reproducibility" / "codex_codegraph_task2"
        )
        self.bundle.parent.mkdir(parents=True)
        shutil.copytree(BUNDLE_ROOT, self.bundle)
        (self.workspace / ".git").mkdir()

    def _manifest(self) -> dict:
        return json.loads(
            (self.bundle / "manifest.json").read_text(encoding="utf-8")
        )

    def _write_manifest(self, value: dict) -> None:
        (self.bundle / "manifest.json").write_text(
            json.dumps(value, indent=2) + "\n",
            encoding="utf-8",
        )

    def _destination(self, name: str) -> Path:
        return self.workspace / ".benchmark-tools" / "codegraph" / name

    def test_valid_bundle_passes(self) -> None:
        result = MATERIALIZER.verify_bundle(self.bundle)
        self.assertEqual(
            result["schema_version"],
            "codex-codegraph-task2-publication-v1",
        )
        self.assertEqual(len(result["payloads"]), 2)

    def test_missing_file_fails(self) -> None:
        (self.bundle / "source-lock.json").unlink()
        with self.assertRaisesRegex(
            MATERIALIZER.MaterializationError, "missing"
        ):
            MATERIALIZER.verify_bundle(self.bundle)

    def test_modified_copied_byte_fails(self) -> None:
        path = self.bundle / "source-lock.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(
            MATERIALIZER.MaterializationError, "copied bytes differ"
        ):
            MATERIALIZER.verify_bundle(self.bundle)

    def test_manifest_hash_mismatch_fails(self) -> None:
        manifest = self._manifest()
        manifest["copied_files"][0]["sha256"] = "0" * 64
        self._write_manifest(manifest)
        with self.assertRaisesRegex(
            MATERIALIZER.MaterializationError,
            "manifest copied-file identity differs",
        ):
            MATERIALIZER.verify_bundle(self.bundle)

    def test_modified_lock_and_matching_manifest_still_fail_pinned_hash(self) -> None:
        path = self.bundle / "source-lock.json"
        lock = json.loads(path.read_text(encoding="utf-8"))
        lock["install_command"] = ["npm", "install"]
        payload = (json.dumps(lock, indent=2) + "\n").encode()
        path.write_bytes(payload)
        manifest = self._manifest()
        manifest["copied_files"][0]["bytes"] = len(payload)
        manifest["copied_files"][0]["sha256"] = hashlib.sha256(
            payload
        ).hexdigest()
        self._write_manifest(manifest)
        with self.assertRaisesRegex(
            MATERIALIZER.MaterializationError,
            "manifest copied-file identity differs",
        ):
            MATERIALIZER.verify_bundle(self.bundle)

    def test_path_escape_fails(self) -> None:
        manifest = self._manifest()
        manifest["copied_files"][0]["original_path"] = "../escape.json"
        self._write_manifest(manifest)
        with self.assertRaisesRegex(
            MATERIALIZER.MaterializationError, "escapes"
        ):
            MATERIALIZER.verify_bundle(self.bundle)

    def test_symlink_input_fails(self) -> None:
        source = self.bundle / "source-lock.json"
        external = Path(self.temporary.name) / "external-source-lock.json"
        shutil.copyfile(source, external)
        source.unlink()
        source.symlink_to(external)
        with self.assertRaisesRegex(
            MATERIALIZER.MaterializationError, "symlink"
        ):
            MATERIALIZER.verify_bundle(self.bundle)

    def test_symlink_destination_fails(self) -> None:
        destination = self._destination("source-lock.json")
        destination.parent.mkdir(parents=True)
        external = Path(self.temporary.name) / "external-destination.json"
        external.write_bytes(b"external")
        destination.symlink_to(external)
        with self.assertRaisesRegex(
            MATERIALIZER.MaterializationError, "symlink"
        ):
            MATERIALIZER.materialize(self.bundle, self.workspace)

    def test_symlink_destination_parent_fails_without_escape(self) -> None:
        external = Path(self.temporary.name) / "external-directory"
        external.mkdir()
        (self.workspace / ".benchmark-tools").symlink_to(
            external, target_is_directory=True
        )
        with self.assertRaisesRegex(
            MATERIALIZER.MaterializationError,
            "symlink or non-directory path component refused",
        ):
            MATERIALIZER.materialize(self.bundle, self.workspace)
        self.assertEqual(list(external.iterdir()), [])

    def test_absent_destinations_materialize_correctly(self) -> None:
        result = MATERIALIZER.materialize(self.bundle, self.workspace)
        self.assertEqual(
            [row["status"] for row in result["operations"]],
            ["materialized", "materialized"],
        )
        for name in ("source-lock.json", "upstream-resolution.json"):
            destination = self._destination(name)
            self.assertEqual(
                destination.read_bytes(),
                (self.bundle / name).read_bytes(),
            )
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o400)

    def test_identical_destinations_are_not_rewritten(self) -> None:
        MATERIALIZER.materialize(self.bundle, self.workspace)
        destinations = [
            self._destination("source-lock.json"),
            self._destination("upstream-resolution.json"),
        ]
        before = [
            (path.stat().st_ino, path.stat().st_mtime_ns, path.stat().st_mode)
            for path in destinations
        ]
        result = MATERIALIZER.materialize(self.bundle, self.workspace)
        after = [
            (path.stat().st_ino, path.stat().st_mtime_ns, path.stat().st_mode)
            for path in destinations
        ]
        self.assertEqual(before, after)
        self.assertEqual(
            [row["status"] for row in result["operations"]],
            ["already_materialized", "already_materialized"],
        )

    def test_conflicting_destination_fails(self) -> None:
        destination = self._destination("source-lock.json")
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b"conflict")
        with self.assertRaisesRegex(
            MATERIALIZER.MaterializationError, "conflicting destination"
        ):
            MATERIALIZER.materialize(self.bundle, self.workspace)
        self.assertFalse(self._destination("upstream-resolution.json").exists())

    def test_completed_authority_workspace_is_refused(self) -> None:
        sentinel = self.workspace / MATERIALIZER.AUTHORITY_SENTINELS[0]
        sentinel.parent.mkdir(parents=True)
        sentinel.write_bytes(b"authoritative")
        with self.assertRaisesRegex(
            MATERIALIZER.MaterializationError,
            "completed Task 2 authority workspace refused",
        ):
            MATERIALIZER.materialize(self.bundle, self.workspace)
        self.assertFalse(self._destination("source-lock.json").exists())

    def test_dry_run_writes_nothing(self) -> None:
        result = MATERIALIZER.materialize(
            self.bundle,
            self.workspace,
            dry_run=True,
        )
        self.assertEqual(
            [row["status"] for row in result["operations"]],
            ["would_materialize", "would_materialize"],
        )
        self.assertFalse((self.workspace / ".benchmark-tools").exists())

    def test_workspace_must_be_checkout_containing_bundle(self) -> None:
        other = Path(self.temporary.name) / "other-checkout"
        other.mkdir()
        (other / ".git").mkdir()
        with self.assertRaisesRegex(
            MATERIALIZER.MaterializationError,
            "checkout containing this bundle",
        ):
            MATERIALIZER.materialize(self.bundle, other)
        self.assertFalse((other / ".benchmark-tools").exists())

    def test_workspace_replacement_after_verification_is_refused(self) -> None:
        original_verify = MATERIALIZER.verify_bundle
        displaced = Path(self.temporary.name) / "displaced-workspace"

        def verify_then_replace(bundle: Path) -> dict:
            verified = original_verify(bundle)
            self.workspace.rename(displaced)
            self.workspace.mkdir()
            (self.workspace / ".git").mkdir()
            return verified

        with mock.patch.object(
            MATERIALIZER,
            "verify_bundle",
            side_effect=verify_then_replace,
        ):
            with self.assertRaisesRegex(
                MATERIALIZER.MaterializationError,
                "workspace identity changed",
            ):
                MATERIALIZER.materialize(self.bundle, self.workspace)
        self.assertFalse((self.workspace / ".benchmark-tools").exists())

    def test_malformed_manifest_json_fails(self) -> None:
        (self.bundle / "manifest.json").write_bytes(b"{not-json")
        with self.assertRaisesRegex(
            MATERIALIZER.MaterializationError, "malformed JSON"
        ):
            MATERIALIZER.verify_bundle(self.bundle)

    def test_malformed_copied_json_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            MATERIALIZER.MaterializationError,
            "malformed JSON",
        ):
            MATERIALIZER._load_json_payload(
                b"not-json\n",
                label="copied record",
            )

    def test_verified_payload_is_not_reread_during_materialization(self) -> None:
        verified = MATERIALIZER.verify_bundle(self.bundle)
        expected = verified["payloads"][
            ".benchmark-tools/codegraph/source-lock.json"
        ]
        (self.bundle / "source-lock.json").write_bytes(b"changed-after-verify")
        with mock.patch.object(
            MATERIALIZER,
            "verify_bundle",
            return_value=verified,
        ):
            MATERIALIZER.materialize(self.bundle, self.workspace)
        self.assertEqual(
            self._destination("source-lock.json").read_bytes(),
            expected,
        )

    def test_second_create_failure_rolls_back_first_file(self) -> None:
        original = MATERIALIZER._create_once_at
        call_count = 0

        def fail_second(parent_fd: int, name: str, payload: bytes):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise MATERIALIZER.MaterializationError(
                    "injected second-file failure"
                )
            return original(parent_fd, name, payload)

        with mock.patch.object(
            MATERIALIZER,
            "_create_once_at",
            side_effect=fail_second,
        ):
            with self.assertRaisesRegex(
                MATERIALIZER.MaterializationError,
                "injected second-file failure",
            ):
                MATERIALIZER.materialize(self.bundle, self.workspace)
        self.assertFalse(self._destination("source-lock.json").exists())
        self.assertFalse(
            self._destination("upstream-resolution.json").exists()
        )

    def test_no_network_is_required(self) -> None:
        with mock.patch.object(
            socket,
            "socket",
            side_effect=AssertionError("network access attempted"),
        ):
            result = MATERIALIZER.materialize(self.bundle, self.workspace)
        self.assertEqual(
            [row["status"] for row in result["operations"]],
            ["materialized", "materialized"],
        )


if __name__ == "__main__":
    unittest.main()
