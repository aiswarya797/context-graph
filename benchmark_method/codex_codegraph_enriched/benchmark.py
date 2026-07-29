#!/usr/bin/env python3
"""Pinned upstream CodeGraph treatment arm for SWE-Explore."""

from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import json
import os
import platform
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if sys.version_info < (3, 11):
    raise SystemExit(f"Python 3.11 or newer is required; found {platform.python_version()} ({sys.executable})")
import tomllib

ARM_ROOT = Path(__file__).resolve().parent
ROOT = ARM_ROOT.parents[1]
COMMON_ROOT = ROOT / "benchmark_method" / "common"
BASELINE_ROOT = ROOT / "benchmark_method" / "codex_baseline"
SRC = ARM_ROOT / "src"
BASELINE_SRC = BASELINE_ROOT / "src"
for source in (SRC, BASELINE_SRC):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from codegraph_bench.artifacts import claimable_sample, load_jsonl, persist_attempt, sample_slot
from codegraph_bench.codegraph import (
    CodeGraphError,
    NETWORK_DENY_PROFILE,
    directory_manifest,
    index_identity,
    load_source_lock,
    prepare_index,
    prepare_runtime_from_lock,
    refresh_existing_runtime_provenance,
    runtime_bundle_manifest,
    sha256_file,
    sha256_value,
    source_manifest,
    stage_runtime_bundle,
    attempt_index_copy,
    validate_index,
    validate_frozen_index_status,
    validate_runtime,
    write_json,
)
from codegraph_bench.codegraph_events import (
    LIVE_CODEGRAPH_ENVELOPE,
    REAL_ENVELOPE_INTEGRATION,
)
from codegraph_bench.codegraph_runner import (
    RunnerError,
    build_codegraph_command,
    build_treatment_prompt,
    child_environment,
    codegraph_sandbox_profile,
    fresh_runtime_dirs,
    isolation_guarantees,
    neutralize_git_provenance,
    run_isolation_canaries,
    run_codegraph_child,
)
from codegraph_bench.comparison import ComparisonRefused, compare_runs
from codegraph_bench.integrity import (
    IntegrityError,
    load_treatment_manifest,
    resolve_run_root,
    resolve_controlled_setup_path,
    sha256_bytes,
    validate_attempt_records,
    validate_run_id,
    validate_run_manifest,
    verify_bound_run_artifacts,
    verify_corpus_contract,
)
from codegraph_bench.report import ReportError, rebuild_report, score_run
from codegraph_bench.task_metadata import TaskMetadataError, load_prepared_tasks, portable_task
from codegraph_bench.task2_evidence import (
    Task2EvidenceError,
    build_task2_evidence_root,
    build_task2_freeze_marker,
    validate_task2_freeze_contract,
)
from codegraph_bench.task5_authority import (
    TASK2_RUNTIME_EXECUTABLE_SHA256,
    TASK4_ALL24,
    TASK4_ALL24_SHA256,
    TASK4_CANDIDATE_ROOT_SHA256,
    TASK4_SEALED_ROOT,
    TASK4_SEALED_ROOT_SHA256,
    authority_digest,
    load_enriched_index,
    load_task4_authority,
    validate_enriched_index,
    validate_measured_runtime,
)
from codegraph_bench.task7_freeze import (
    TreatmentFreezeError,
    validate_treatment_freeze,
    write_treatment_freeze,
)
from context_graph_bench.codex_runner import (
    file_sha256,
    prepare_isolated_repository,
    remove_isolated_repository,
    resolve_executable,
    validate_auth_source,
    verify_pinned_version,
)
from context_graph_bench.corpus import CorpusError, verify_official_evaluator, verify_repository_head
from context_graph_bench.event_audit import audit_events


CANONICAL_PATH_VALUES = {
    "source_lock": ".benchmark-tools/codegraph/source-lock.json",
    "upstream_resolution": ".benchmark-tools/codegraph/upstream-resolution.json",
    "source_checkout": ".benchmark-tools/codegraph/source",
    "runtime_record": ".benchmark-tools/codegraph/runtime/runtime.json",
    "indexes": ".benchmark-work/codegraph/indexes",
    "sources": ".benchmark-work/codegraph/sources",
    "setup_logs": ".benchmark-work/codegraph/setup-logs-v18",
    "doctor": ".benchmark-work/codegraph/v18/doctor",
}
ENRICHED_CANONICAL_PATH_VALUES = {
    "enriched_builder_checkout": ".benchmark-tools/codegraph-enriched/source",
    "enriched_indexes": ".benchmark-work/codegraph-enriched/task4-cycle-3/indexes",
    "task4_all24": TASK4_ALL24,
    "task4_sealed_root": TASK4_SEALED_ROOT,
    "enriched_doctor": ".benchmark-work/codegraph-enriched/doctor",
}
TASK7_FREEZE_VERSION = 1
TASK7_OFFICIAL_SMOKE_RUN_ID = (
    "codex-codegraph-enriched-smoke-task7-v1"
)
TASK7_OFFICIAL_SMOKE_TASK = {
    "instance_id": "astral-sh__ruff-15330",
    "base_commit": "b2a0d68d70ee690ea871fe9b3317be43075ddb33",
}
TASK7_START_RECEIPT = (
    ".benchmark-work/codegraph-enriched/"
    "task7-cycle-1/task7-start-receipt.json"
)
TASK7_START_RECEIPT_SHA256 = (
    "529989f84ce4c72d4e77aee85a87856f5e5c675c37bd153f91e42277e99c4494"
)
TASK_SEALED_AUTHORITIES = (
    (
        1,
        ".benchmark-work/codegraph-enriched/"
        "task1-review-amendment-v1/sealed-task-evidence-root.json",
        "74e2dcc3c6e25f1b880c83ba6bc2775e5d959e1821957a3815a5555ab853f2b4",
    ),
    (
        2,
        ".benchmark-work/codegraph-enriched/"
        "task2-cycle-2-review-v1/sealed-task-evidence-root.json",
        "c1816f093dbbbb24b687f40ee59926747af19b5eadc9ce417bda601f2c040e26",
    ),
    (
        3,
        ".benchmark-work/codegraph-enriched/"
        "task3-cycle-5-review-v1/sealed-task-evidence-root.json",
        "8e6e0a6a2cd1c32c25de795633f8f9df95215688390087b282addc75f6d2854f",
    ),
    (
        4,
        ".benchmark-work/codegraph-enriched/"
        "task4-cycle-3-review-v1/sealed-task-evidence-root.json",
        "fe6ceaa328c20ec15ec776c2cb56187980dadc6303e764c6e25f899ff574b76f",
    ),
    (
        5,
        ".benchmark-work/codegraph-enriched/"
        "task5-cycle-3-review-v1/sealed-task-evidence-root.json",
        "90aeaa03288664f001cca28ae924df680efc1b78b5eeb14a340deb032f27de49",
    ),
    (
        6,
        ".benchmark-work/codegraph-enriched/"
        "task6-cycle-5-review-v1/sealed-task-evidence-root.json",
        "2bc507d4adfce3a80b68cd5b6a4947346a39e0cfd86681e344e9cb43488b6eb6",
    ),
)
TASK6_RETRIEVAL_PARITY = (
    ".benchmark-work/codegraph-enriched/"
    "task6-cycle-5/direct-retrieval-parity.json"
)
TASK6_RETRIEVAL_PARITY_SHA256 = (
    "51651a10049b9a651f1e366bd960ed73795b6a294308a4d8dde0d4b81dffd085"
)
TASK6_LIVE_DOCTOR = (
    ".benchmark-work/codegraph-enriched/"
    "task6-cycle-5/live-doctor/doctor.json"
)
TASK6_LIVE_DOCTOR_SHA256 = (
    "43487d12e693983d262896606bfd95a8ffb504d4409ed02fbcbe701fc321c626"
)
TASK6_MCP_TRANSCRIPT = (
    ".benchmark-work/codegraph-enriched/"
    "task6-cycle-5/direct-mcp/original/transcript.json"
)
TASK6_MCP_TRANSCRIPT_SHA256 = (
    "ab819413e21e356b41ded978f1a05b511e2cc91e8324aced117a5a9d08f9cbe2"
)
CANONICAL_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root-v18.json"
)
CANONICAL_TASK2_FREEZE_MARKER = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-freeze-marker-v18.json"
)
PREDECESSOR_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root-v17.json"
)
PREDECESSOR_TASK2_EVIDENCE_SHA256 = (
    "380667527091c487e97e52d0f2e5ca757859ccf8a0c60d9c32cd0a1b51b49881"
)
V16_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root-v16.json"
)
V16_TASK2_EVIDENCE_SHA256 = (
    "e2e2dee4d2d8ef8b8ded8ef763bf49e332c611824cb005b00871e3f92270a801"
)
V15_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root-v15.json"
)
V15_TASK2_EVIDENCE_SHA256 = (
    "9928271638cd0685b425f74e2f7b72be2521b3f7f7054d09334d7f114732350c"
)
V14_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root-v14.json"
)
V14_TASK2_EVIDENCE_SHA256 = (
    "d9175879390e3003873139abbbc4077ac97056ccb7d78d3840a8bf2ecc6a77ca"
)
V13_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root-v13.json"
)
V13_TASK2_EVIDENCE_SHA256 = (
    "7467249e81e193612243159af59da4b7311077fc7b8bae70e356b7012f7a05ae"
)
V12_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root-v12.json"
)
V12_TASK2_EVIDENCE_SHA256 = (
    "159803cedb61784d296b14d0ac9d13d7b79fd181c72c19f96c2f48105e53b609"
)
V11_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root-v11.json"
)
V11_TASK2_EVIDENCE_SHA256 = (
    "3ee7a49ce6a33af63b9999d879fdf696b03f855108884140f153ffe1c557390d"
)
V10_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root-v10.json"
)
V10_TASK2_EVIDENCE_SHA256 = (
    "6980b90289e7497d7bb8a27e1b414e9a376baa6749d3bf99b3e9af72a7a103aa"
)
V9_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root-v9.json"
)
V9_TASK2_EVIDENCE_SHA256 = (
    "7d594b780a4e20e826824dee4e872a23b099005772188ff7357e225d47e0b597"
)
V8_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root-v8.json"
)
V8_TASK2_EVIDENCE_SHA256 = (
    "897f170577e20afcfd13c88554261e761fff2f2ff243d5bfff50ea5606e817f1"
)
V7_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root-v7.json"
)
V7_TASK2_EVIDENCE_SHA256 = (
    "e31cb681675dd1d3c56ea7a424211a21605c7fb59b9b9009e1de14c3f94a8aad"
)
V6_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root-v6.json"
)
V6_TASK2_EVIDENCE_SHA256 = (
    "d13f76932a0777c7a1c9d8a114f4797549a41ee471151a7e47fd6f543a1e4ee3"
)
V5_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root-v5.json"
)
V5_TASK2_EVIDENCE_SHA256 = (
    "4a15fcd94fbe0e1c6722c8eeb5c27492be30ee426651aa56562098779ea109b0"
)
V4_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root-v4.json"
)
V4_TASK2_EVIDENCE_SHA256 = (
    "33451e63cc8e9cfb12963a725b5321ea6e4d8ab8a0ba235cb11ad651899eb26d"
)
V3_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root-v3.json"
)
V3_TASK2_EVIDENCE_SHA256 = (
    "054a3617b8c3ebded957d6fc12038cb94f47ef78293fe5808076f573812774e9"
)
INTERMEDIATE_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root-v2.json"
)
INTERMEDIATE_TASK2_EVIDENCE_SHA256 = (
    "711a6258f946209c91d56f5369a53da822279fb394324a0c2825e947ab9d93aa"
)
LEGACY_TASK2_EVIDENCE_ROOT = (
    ROOT / ".benchmark-tools" / "codegraph" / "task2-evidence-root.json"
)
LEGACY_TASK2_EVIDENCE_SHA256 = (
    "c8b1d2a18e4be414c2055983f8be48bc1b0957c51b11d5d0b9ce2071e92d135c"
)
AUTHORITY_OVERRIDE_ENVIRONMENT = {
    "CODEGRAPH_SOURCE_LOCK",
    "CODEGRAPH_SOURCE_CHECKOUT",
    "CODEGRAPH_RUNTIME_RECORD",
    "CODEGRAPH_INDEX_ROOT",
    "CODEGRAPH_UPSTREAM_RESOLUTION",
    "CODEGRAPH_SOURCE_ROOT",
    "CODEGRAPH_SETUP_LOGS",
    "CODEGRAPH_DOCTOR_ROOT",
    "CODEGRAPH_TASK2_EVIDENCE_ROOT",
    "CODEGRAPH_TASK2_FREEZE_MARKER",
    "CODEGRAPH_ENRICHED_BUILDER",
    "CODEGRAPH_ENRICHED_INDEX_ROOT",
    "CODEGRAPH_TASK4_ALL24",
    "CODEGRAPH_TASK4_SEALED_ROOT",
    "CODEGRAPH_ENRICHED_DOCTOR_ROOT",
}


def _reject_authority_redirects(config: dict[str, Any]) -> None:
    present = sorted(key for key in AUTHORITY_OVERRIDE_ENVIRONMENT if key in os.environ)
    if present:
        raise RunnerError(
            "task2_evidence_refused: authority environment override present: "
            + ", ".join(present)
        )
    configured = config.get("paths")
    if not isinstance(configured, dict):
        raise RunnerError("task2_evidence_refused: paths configuration is missing")
    for key in ("task2_evidence_root", "task2_freeze_marker"):
        if key in configured:
            raise RunnerError(
                f"task2_evidence_refused: {key} is harness-owned"
            )
    for key, expected in CANONICAL_PATH_VALUES.items():
        if configured.get(key) != expected:
            raise RunnerError(
                f"task2_evidence_refused: canonical path differs for {key}"
            )
    for key, expected in ENRICHED_CANONICAL_PATH_VALUES.items():
        if configured.get(key) != expected:
            raise RunnerError(
                f"enriched_authority_refused: canonical path differs for {key}"
            )


def _assert_no_symlink_components(path: Path) -> None:
    current = ROOT
    try:
        relative = path.absolute().relative_to(ROOT.absolute())
    except ValueError as exc:
        raise RunnerError(
            f"task2_evidence_refused: canonical authority escapes workspace: {path}"
        ) from exc
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise RunnerError(
                f"task2_evidence_refused: canonical authority uses symlink: {current}"
            )


def load_config() -> dict[str, Any]:
    with (ARM_ROOT / "config" / "codegraph.toml").open("rb") as stream:
        config = tomllib.load(stream)
    for key, environment in (
        ("codex_executable", "CODEX_EXECUTABLE"),
        ("codex_auth_source", "CODEX_AUTH_SOURCE"),
    ):
        if os.environ.get(environment):
            config["paths"][key] = os.environ[environment]
    _reject_authority_redirects(config)
    return config


def paths(config: dict[str, Any]) -> dict[str, Path]:
    _reject_authority_redirects(config)
    controlled = {
        key: ROOT / relative
        for key, relative in CANONICAL_PATH_VALUES.items()
    }
    controlled.update(
        {
            key: ROOT / relative
            for key, relative in ENRICHED_CANONICAL_PATH_VALUES.items()
        }
    )
    controlled["task2_evidence_root"] = CANONICAL_TASK2_EVIDENCE_ROOT
    controlled["task2_freeze_marker"] = CANONICAL_TASK2_FREEZE_MARKER
    for path in controlled.values():
        _assert_no_symlink_components(path)
    return {
        "manifest": COMMON_ROOT / "inputs" / "select25-source-merge.manifest.json",
        "baseline_prepared": ROOT / ".benchmark-work" / "codex-baseline" / "prepared.json",
        "schema": COMMON_ROOT / "schemas" / "agent-regions.schema.json",
        "evaluator": COMMON_ROOT / "official" / "eval.py",
        "provenance": COMMON_ROOT / "official" / "provenance.json",
        "prompt": ARM_ROOT / "config" / "codegraph-region-selection-prompt.md",
        "auth": Path(config["paths"]["codex_auth_source"]),
        **controlled,
    }


def config_digest(config: dict[str, Any]) -> str:
    value = {
        "treatment": config["treatment"],
        "index": config["index"],
        "runtime": config["runtime"],
        "codex_executable": config["paths"]["codex_executable"],
        "enriched_authority": ENRICHED_CANONICAL_PATH_VALUES,
        "filesystem_isolation": "macos-sandbox-exec-codegraph-v2",
        "repository_snapshot": "git-clone-no-local-plus-detached-worktree-v1",
    }
    return sha256_value(value)


def load_tasks(config: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    p = paths(config)
    return load_prepared_tasks(p["manifest"], p["baseline_prepared"])


def _load_locked_source(config: dict[str, Any]) -> dict[str, Any]:
    p = paths(config)
    lock = load_source_lock(p["source_lock"])
    if not p["upstream_resolution"].is_file() or sha256_file(p["upstream_resolution"]) != lock["upstream_resolution_sha256"]:
        raise CodeGraphError("codegraph_source_mismatch", "immutable upstream resolution artifact differs")
    resolution = json.loads(p["upstream_resolution"].read_text(encoding="utf-8"))
    expected = {
        "repository_url": lock["repository_url"],
        "resolved_commit": lock["resolved_commit"],
        "retrieved_at": lock["retrieved_at"],
        "return_code": 0,
    }
    if any(resolution.get(field) != value for field, value in expected.items()):
        raise CodeGraphError("codegraph_source_mismatch", "upstream resolution identity differs from source lock")
    return lock


def _load_runtime(config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    p = paths(config)
    lock = _load_locked_source(config)
    if not p["runtime_record"].is_file():
        raise CodeGraphError("codegraph_build_failure", "runtime record missing; run codegraph-prepare")
    runtime = json.loads(p["runtime_record"].read_text(encoding="utf-8"))
    executable = Path(runtime.get("executable_path", ""))
    validate_runtime(lock, runtime, p["source_checkout"], executable)
    validate_measured_runtime(
        runtime=runtime,
        task2_checkout=p["source_checkout"],
        enriched_builder_checkout=p["enriched_builder_checkout"],
    )
    return lock, runtime


def _require_task4_authority(
    config: dict[str, Any],
    *,
    runtime: dict[str, Any],
) -> dict[str, Any]:
    p = paths(config)
    if (
        p["task4_sealed_root"] != ROOT / TASK4_SEALED_ROOT
        or p["task4_all24"] != ROOT / TASK4_ALL24
    ):
        raise RunnerError(
            "enriched_authority_refused: canonical Task 4 paths differ"
        )
    try:
        return load_task4_authority(ROOT, runtime=runtime)
    except ValueError as exc:
        raise RunnerError(str(exc)) from exc


def _require_task2_evidence(config: dict[str, Any]) -> dict[str, Any]:
    p = paths(config)
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("CODEGRAPH_")
    }
    command = [
        sys.executable,
        str(ROOT / "benchmark_method" / "codex_codegraph" / "benchmark.py"),
        "codegraph-prepare",
    ]
    control = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if control.returncode:
        raise RunnerError(
            "task2_evidence_refused: frozen Task 2 harness validation failed: "
            + (control.stderr or control.stdout).strip()
        )
    try:
        control_result = json.loads(control.stdout)
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "task2_evidence_refused: frozen Task 2 validation output is malformed"
        ) from exc
    if (
        control_result.get("revalidated_without_rehash") is not True
        or control_result.get("task2_evidence_root_sha256")
        != sha256_file(p["task2_evidence_root"])
        or control_result.get("task2_freeze_marker_sha256")
        != sha256_file(p["task2_freeze_marker"])
    ):
        raise RunnerError(
            "task2_evidence_refused: frozen Task 2 validation identity differs"
        )
    try:
        _marker, manifest = validate_task2_freeze_contract(
            root=ROOT,
            manifest_path=p["task2_evidence_root"],
            marker_path=p["task2_freeze_marker"],
        )
    except Task2EvidenceError as exc:
        raise RunnerError(f"task2_evidence_refused: {exc}") from exc
    _require_task2_authority_files(
        p["task2_evidence_root"],
        p["task2_freeze_marker"],
    )
    return manifest


def _mode(path: Path) -> str:
    return f"{stat.S_IMODE(path.stat().st_mode):04o}"


def _require_task2_authority_directory(path: Path) -> None:
    if (
        not path.is_dir()
        or path.is_symlink()
        or stat.S_IMODE(path.stat().st_mode) != 0o555
    ):
        raise RunnerError(
            "task2_evidence_refused: authority directory is not sealed"
        )


def _task2_immutable_flag() -> int:
    flag = getattr(stat, "UF_IMMUTABLE", None)
    if not isinstance(flag, int) or not hasattr(os, "chflags"):
        raise RunnerError(
            "task2_evidence_refused: immutable file flags are unsupported"
        )
    return flag


def _require_task2_authority_files(
    evidence_root: Path,
    marker: Path,
) -> None:
    if evidence_root.parent != marker.parent:
        raise RunnerError(
            "task2_evidence_refused: authority files do not share a directory"
        )
    _require_task2_authority_directory(evidence_root.parent)
    immutable = _task2_immutable_flag()
    for path in (evidence_root, marker):
        if (
            not path.is_file()
            or path.is_symlink()
            or not (path.stat().st_flags & immutable)
        ):
            raise RunnerError(
                f"task2_evidence_refused: authority file is not immutable: {path}"
            )


def _seal_task2_authority_files(
    evidence_root: Path,
    marker: Path,
) -> None:
    if evidence_root.parent != marker.parent:
        raise RunnerError(
            "task2_evidence_refused: authority files do not share a directory"
        )
    immutable = _task2_immutable_flag()
    for path in (evidence_root, marker):
        if not path.is_file() or path.is_symlink():
            raise RunnerError(
                f"task2_evidence_refused: authority file missing before seal: {path}"
            )
    for path in (evidence_root, marker):
        os.chflags(path, path.stat().st_flags | immutable)
    os.chmod(evidence_root.parent, 0o555)
    _require_task2_authority_files(evidence_root, marker)


def _require_task2_scope_contract(
    manifest: dict[str, Any],
    expected_scopes: list[dict[str, Any]],
) -> None:
    if manifest.get("scopes") != expected_scopes:
        raise RunnerError(
            "task2_evidence_refused: scope contract differs"
        )


def _authority_file(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RunnerError(
            f"task2_evidence_refused: authoritative file missing or symlinked: {path}"
        )
    return {
        "path": str(path.resolve()),
        "bytes": path.stat().st_size,
        "mode": _mode(path),
        "sha256": sha256_file(path),
    }


def _descriptor_sha256(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _stable_stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _task2_authority_chain() -> tuple[dict[str, Any], ...]:
    return (
        {
            "generation": "v1",
            "path": LEGACY_TASK2_EVIDENCE_ROOT,
            "sha256": LEGACY_TASK2_EVIDENCE_SHA256,
            "schema_version": "codegraph-task2-evidence-root-v1",
        },
        {
            "generation": "v2",
            "path": INTERMEDIATE_TASK2_EVIDENCE_ROOT,
            "sha256": INTERMEDIATE_TASK2_EVIDENCE_SHA256,
            "schema_version": "codegraph-task2-evidence-root-v2",
        },
        {
            "generation": "v3",
            "path": V3_TASK2_EVIDENCE_ROOT,
            "sha256": V3_TASK2_EVIDENCE_SHA256,
            "schema_version": "codegraph-task2-evidence-root-v2",
        },
        {
            "generation": "v4",
            "path": V4_TASK2_EVIDENCE_ROOT,
            "sha256": V4_TASK2_EVIDENCE_SHA256,
            "schema_version": "codegraph-task2-evidence-root-v2",
        },
        {
            "generation": "v5",
            "path": V5_TASK2_EVIDENCE_ROOT,
            "sha256": V5_TASK2_EVIDENCE_SHA256,
            "schema_version": "codegraph-task2-evidence-root-v2",
        },
        {
            "generation": "v6",
            "path": V6_TASK2_EVIDENCE_ROOT,
            "sha256": V6_TASK2_EVIDENCE_SHA256,
            "schema_version": "codegraph-task2-evidence-root-v2",
        },
        {
            "generation": "v7",
            "path": V7_TASK2_EVIDENCE_ROOT,
            "sha256": V7_TASK2_EVIDENCE_SHA256,
            "schema_version": "codegraph-task2-evidence-root-v2",
        },
        {
            "generation": "v8",
            "path": V8_TASK2_EVIDENCE_ROOT,
            "sha256": V8_TASK2_EVIDENCE_SHA256,
            "schema_version": "codegraph-task2-evidence-root-v2",
        },
        {
            "generation": "v9",
            "path": V9_TASK2_EVIDENCE_ROOT,
            "sha256": V9_TASK2_EVIDENCE_SHA256,
            "schema_version": "codegraph-task2-evidence-root-v2",
        },
        {
            "generation": "v10",
            "path": V10_TASK2_EVIDENCE_ROOT,
            "sha256": V10_TASK2_EVIDENCE_SHA256,
            "schema_version": "codegraph-task2-evidence-root-v2",
        },
        {
            "generation": "v11",
            "path": V11_TASK2_EVIDENCE_ROOT,
            "sha256": V11_TASK2_EVIDENCE_SHA256,
            "schema_version": "codegraph-task2-evidence-root-v2",
        },
        {
            "generation": "v12",
            "path": V12_TASK2_EVIDENCE_ROOT,
            "sha256": V12_TASK2_EVIDENCE_SHA256,
            "schema_version": "codegraph-task2-evidence-root-v2",
        },
        {
            "generation": "v13",
            "path": V13_TASK2_EVIDENCE_ROOT,
            "sha256": V13_TASK2_EVIDENCE_SHA256,
            "schema_version": "codegraph-task2-evidence-root-v2",
        },
        {
            "generation": "v14",
            "path": V14_TASK2_EVIDENCE_ROOT,
            "sha256": V14_TASK2_EVIDENCE_SHA256,
            "schema_version": "codegraph-task2-evidence-root-v2",
        },
        {
            "generation": "v15",
            "path": V15_TASK2_EVIDENCE_ROOT,
            "sha256": V15_TASK2_EVIDENCE_SHA256,
            "schema_version": "codegraph-task2-evidence-root-v2",
        },
        {
            "generation": "v16",
            "path": V16_TASK2_EVIDENCE_ROOT,
            "sha256": V16_TASK2_EVIDENCE_SHA256,
            "schema_version": "codegraph-task2-evidence-root-v2",
        },
        {
            "generation": "v17",
            "path": PREDECESSOR_TASK2_EVIDENCE_ROOT,
            "sha256": PREDECESSOR_TASK2_EVIDENCE_SHA256,
            "schema_version": "codegraph-task2-evidence-root-v2",
        },
    )


def _task2_predecessor_authority(
    *,
    chain: tuple[dict[str, Any], ...] | None = None,
) -> dict[str, Any]:
    chain = _task2_authority_chain() if chain is None else chain
    directory_fds: dict[Path, int] = {}
    directory_states: dict[Path, tuple[int, ...]] = {}
    missing_directories: set[Path] = set()
    opened: list[tuple[dict[str, Any], Path, int]] = []
    absent = 0
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    try:
        for entry in chain:
            path = Path(entry["path"])
            parent = path.parent
            if parent in directory_fds or parent in missing_directories:
                continue
            try:
                directory_fd = os.open(
                    parent,
                    os.O_RDONLY | directory_flag | nofollow | cloexec,
                )
            except FileNotFoundError:
                missing_directories.add(parent)
                continue
            except OSError as error:
                raise RunnerError(
                    "task2_evidence_refused: authority directory missing "
                    f"or symlinked: {parent}"
                ) from error
            directory_fds[parent] = directory_fd
            directory_states[parent] = _stable_stat_identity(
                os.fstat(directory_fd)
            )

        for entry in chain:
            path = Path(entry["path"])
            parent = path.parent
            if parent in missing_directories:
                absent += 1
                continue
            try:
                fd = os.open(
                    path.name,
                    os.O_RDONLY | nofollow | cloexec,
                    dir_fd=directory_fds[parent],
                )
            except FileNotFoundError:
                absent += 1
                continue
            except OSError as error:
                if error.errno in (errno.ELOOP, errno.ENOTDIR):
                    detail = "missing or symlinked"
                else:
                    detail = "unreadable"
                raise RunnerError(
                    "task2_evidence_refused: authoritative file "
                    f"{detail}: {path}"
                ) from error
            opened.append((entry, path, fd))

        for parent, directory_fd in directory_fds.items():
            if _stable_stat_identity(os.fstat(directory_fd)) != directory_states[
                parent
            ]:
                raise RunnerError(
                    "task2_evidence_refused: authority directory changed "
                    f"during scan: {parent}"
                )

        if absent == len(chain):
            return {
                "kind": "genesis",
                "path": None,
                "bytes": 0,
                "mode": None,
                "sha256": None,
                "schema_version": None,
            }
        if absent:
            raise RunnerError(
                "task2_evidence_refused: historical authority is incomplete"
            )

        verified: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for entry, path, fd in opened:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise RunnerError(
                    "task2_evidence_refused: authoritative file missing "
                    f"or symlinked: {path}"
                )
            authority = {
                "path": str(path),
                "bytes": before.st_size,
                "mode": f"{stat.S_IMODE(before.st_mode):04o}",
                "sha256": _descriptor_sha256(fd),
            }
            if _stable_stat_identity(os.fstat(fd)) != _stable_stat_identity(
                before
            ):
                raise RunnerError(
                    "task2_evidence_refused: authoritative file changed "
                    f"during scan: {path}"
                )
            if authority["mode"] != "0400":
                raise RunnerError(
                    "task2_evidence_refused: "
                    f"{entry['generation']} history mode differs"
                )
            if authority["sha256"] != entry["sha256"]:
                raise RunnerError(
                    "task2_evidence_refused: "
                    f"{entry['generation']} history digest differs"
                )
            verified.append((entry, authority))

        for parent, directory_fd in directory_fds.items():
            current = os.fstat(directory_fd)
            if _stable_stat_identity(current) != directory_states[parent]:
                raise RunnerError(
                    "task2_evidence_refused: authority directory changed "
                    f"during scan: {parent}"
                )
            if stat.S_IMODE(current.st_mode) != 0o555:
                raise RunnerError(
                    "task2_evidence_refused: authority directory is not "
                    f"sealed: {parent}"
                )
    finally:
        for _entry, _path, fd in opened:
            os.close(fd)
        for directory_fd in directory_fds.values():
            os.close(directory_fd)

    immediate, predecessor = verified[-1]
    return {
        "kind": "successor",
        "path": str(Path(immediate["path"])),
        "bytes": predecessor["bytes"],
        "mode": predecessor["mode"],
        "sha256": predecessor["sha256"],
        "schema_version": immediate["schema_version"],
    }


def _harness_input_paths(config: dict[str, Any]) -> list[Path]:
    p = paths(config)
    candidates = [
        Path(__file__),
        ARM_ROOT / "config" / "codegraph.toml",
        p["prompt"],
        p["schema"],
        ARM_ROOT / "schemas" / "attempt-record.schema.json",
        ARM_ROOT / "schemas" / "run-manifest.schema.json",
        p["manifest"],
        p["baseline_prepared"],
        p["evaluator"],
        p["provenance"],
        BASELINE_ROOT / "benchmark.py",
        *sorted((ARM_ROOT / "src" / "codegraph_bench").glob("*.py")),
    ]
    unique = {path.resolve(): path for path in candidates}
    return [unique[key] for key in sorted(unique, key=str)]


def _runtime_bundle_authority(
    checkout: Path,
    runtime: dict[str, Any],
) -> dict[str, Any]:
    descriptor = runtime.get("runtime_bundle_manifest")
    if not isinstance(descriptor, dict):
        raise RunnerError("task2_evidence_refused: runtime bundle descriptor missing")
    manifest_path = Path(str(descriptor.get("path", "")))
    manifest_file = _authority_file(manifest_path)
    if (
        manifest_file["bytes"] != descriptor.get("bytes")
        or manifest_file["sha256"] != descriptor.get("sha256")
    ):
        raise RunnerError("task2_evidence_refused: runtime bundle descriptor differs")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    current_manifest = runtime_bundle_manifest(
        checkout,
        node_executable=Path(runtime["toolchain"]["node"]["resolved_path"]),
        npm_executable=Path(runtime["toolchain"]["npm"]["resolved_path"]),
        executable=Path(runtime["executable_path"]),
    )
    if (
        current_manifest.get("files") != manifest.get("files")
        or current_manifest.get("manifest_sha256") != manifest.get("manifest_sha256")
    ):
        raise RunnerError("task2_evidence_refused: runtime bundle membership differs")
    rows: list[dict[str, Any]] = []
    for frozen in manifest.get("files", []):
        relative = frozen.get("path")
        if (
            not isinstance(relative, str)
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
        ):
            raise RunnerError("task2_evidence_refused: runtime bundle path invalid")
        logical = checkout / relative
        if not logical.is_file():
            raise RunnerError(
                f"task2_evidence_refused: runtime bundle file missing: {relative}"
            )
        row = {
            "path": relative,
            "resolved_path": str(logical.resolve()),
            "bytes": logical.stat().st_size,
            "mode": _mode(logical),
            "sha256": sha256_file(logical),
            "symlink_target": os.readlink(logical) if logical.is_symlink() else None,
        }
        if row["bytes"] != frozen.get("bytes") or row["sha256"] != frozen.get(
            "sha256"
        ):
            raise RunnerError(
                f"task2_evidence_refused: runtime bundle bytes differ: {relative}"
            )
        rows.append(row)
    if len(rows) != manifest.get("file_count"):
        raise RunnerError("task2_evidence_refused: runtime bundle membership differs")
    return {
        "checkout": str(checkout.resolve()),
        "manifest": manifest_file,
        "manifest_sha256": manifest.get("manifest_sha256"),
        "entries": rows,
    }


def _active_authority_contract(config: dict[str, Any]) -> dict[str, Any]:
    p = paths(config)
    predecessor = _task2_predecessor_authority()
    lock = json.loads(p["source_lock"].read_text(encoding="utf-8"))
    runtime = json.loads(p["runtime_record"].read_text(encoding="utf-8"))
    index_manifest_path = p["setup_logs"] / "index-manifest.json"
    index_manifest = json.loads(index_manifest_path.read_text(encoding="utf-8"))
    harness_files = [_authority_file(path) for path in _harness_input_paths(config)]
    index_records: list[dict[str, Any]] = []
    record_rows: list[dict[str, Any]] = []
    identities: list[str] = []
    for item in index_manifest.get("indexes", []):
        record_path = Path(item["record"])
        record = json.loads(record_path.read_text(encoding="utf-8"))
        index_records.append(record)
        record_rows.append(
            {
                "record": _authority_file(record_path),
                "task_id": record["task_id"],
                "identity_sha256": record["identity"]["identity_sha256"],
                "master_path": str(Path(record["index_path"]).resolve()),
                "master_manifest_sha256": record["index_artifact_manifest"]["sha256"],
                "source_manifest_sha256": record["source_manifest_sha256"],
            }
        )
        identities.append(record["identity"]["identity_sha256"])
    toolchain = {
        name: _authority_file(Path(runtime["toolchain"][name]["resolved_path"]))
        | {
            "logical_command": runtime["toolchain"][name]["logical_command"],
            "version": runtime["toolchain"][name]["version"],
        }
        for name in ("node", "npm")
    }
    canonical_paths = {
        **{
            key: str((ROOT / value).resolve())
            for key, value in CANONICAL_PATH_VALUES.items()
        },
        "task2_evidence_root": str(CANONICAL_TASK2_EVIDENCE_ROOT),
        "task2_freeze_marker": str(CANONICAL_TASK2_FREEZE_MARKER),
        "predecessor_task2_evidence_root": str(
            PREDECESSOR_TASK2_EVIDENCE_ROOT
        ),
        "intermediate_task2_evidence_root": str(
            INTERMEDIATE_TASK2_EVIDENCE_ROOT
        ),
        "legacy_task2_evidence_root": str(LEGACY_TASK2_EVIDENCE_ROOT),
        "task2_authority_chain": [
            {
                **entry,
                "path": str(entry["path"]),
            }
            for entry in _task2_authority_chain()
        ],
        "index_manifest": str(index_manifest_path.resolve()),
    }
    mutable_exclusions = [
        ".benchmark-runs/** per-attempt events/responses/scores/reports",
        ".benchmark-work/codegraph/attempt-lifecycle/** post-freeze attempt evidence",
        ".benchmark-work/codegraph/v18/doctor/capture-*/** Task 3 doctor outputs",
        ".benchmark-work/codegraph/v18/smoke-gate.json downstream manual gate",
        "/private/tmp/context-graph-*/** private runtime/worktree/index copies",
    ]
    config_sha = config_digest(config)
    active_harness_sha = sha256_value(
        {"config_digest": config_sha, "files": harness_files}
    )
    doctor_prepared = json.loads(
        (p["doctor"] / "doctor-prepared.json").read_text(encoding="utf-8")
    )
    doctor_record = json.loads(
        Path(doctor_prepared["index_record"]).read_text(encoding="utf-8")
    )
    scopes = _task2_scopes(
        config,
        index_records,
        doctor_record,
        predecessor=predecessor,
    )
    return {
        "schema_version": "codegraph-active-authority-v4",
        "canonical_paths": canonical_paths,
        "config_digest": config_sha,
        "active_harness_sha256": active_harness_sha,
        "harness_files": harness_files,
        "scope_contract": {
            "count": len(scopes),
            "sha256": sha256_value(scopes),
            "scopes": scopes,
        },
        "source": {
            "source_lock": _authority_file(p["source_lock"]),
            "upstream_resolution": _authority_file(p["upstream_resolution"]),
            "checkout": str(p["source_checkout"].resolve()),
            "resolved_commit": lock["resolved_commit"],
        },
        "runtime": {
            "record": _authority_file(p["runtime_record"]),
            "configuration_sha256": runtime["configuration_sha256"],
            "executable": _authority_file(Path(runtime["executable_path"])),
            "behavior_probe": _authority_file(
                Path(runtime["mcp_behavior_probe"]["path"])
            ),
            "bundle": _runtime_bundle_authority(p["source_checkout"], runtime),
            "toolchain": toolchain,
        },
        "indexes": {
            "aggregate": _authority_file(index_manifest_path),
            "task_count": index_manifest.get("task_count"),
            "identity_sha256": sorted(identities),
            "records": sorted(record_rows, key=lambda row: row["task_id"]),
        },
        "predecessor": predecessor,
        "mutable_exclusions": mutable_exclusions,
    }


def _task2_scopes(
    config: dict[str, Any],
    index_records: list[dict[str, Any]],
    doctor_record: dict[str, Any],
    predecessor: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    p = paths(config)
    predecessor = predecessor or _task2_predecessor_authority()
    scopes: list[dict[str, str]] = [
        {"kind": "file", "path": p["source_lock"].relative_to(ROOT).as_posix()},
        {"kind": "file", "path": p["upstream_resolution"].relative_to(ROOT).as_posix()},
        {"kind": "tree", "path": ".benchmark-tools/codegraph/resolution-attempts"},
        {"kind": "tree", "path": ".benchmark-tools/codegraph/bootstrap"},
        {"kind": "tree", "path": ".benchmark-tools/codegraph/runtime"},
        {"kind": "tree", "path": p["indexes"].relative_to(ROOT).as_posix()},
        {"kind": "tree", "path": p["setup_logs"].relative_to(ROOT).as_posix()},
        {"kind": "glob", "path": ".benchmark-work/codegraph/sources/*/*.snapshot.json"},
        {"kind": "glob", "path": ".benchmark-work/codegraph/sources/*/*.clone.stdout"},
        {"kind": "glob", "path": ".benchmark-work/codegraph/sources/*/*.clone.stderr"},
        {"kind": "glob", "path": ".benchmark-work/codegraph/sources/*/*.checkout.stdout"},
        {"kind": "glob", "path": ".benchmark-work/codegraph/sources/*/*.checkout.stderr"},
        {
            "kind": "file",
            "path": (p["doctor"] / "doctor-prepared.json").relative_to(ROOT).as_posix(),
        },
        {"kind": "tree", "path": (p["doctor"] / "indexes").relative_to(ROOT).as_posix()},
        {
            "kind": "glob",
            "path": "benchmark_method/codex_codegraph/src/codegraph_bench/*.py",
            "freeze": False,
        },
        {
            "kind": "tree",
            "path": "benchmark_method/codex_codegraph/schemas",
            "freeze": False,
        },
    ]
    if predecessor["path"] is not None:
        scopes.append(
            {
                "kind": "file",
                "path": Path(predecessor["path"]).relative_to(ROOT).as_posix(),
                "freeze": False,
            }
        )
    scopes.extend(
        {
            "kind": "file",
            "path": path.relative_to(ROOT).as_posix(),
            "freeze": False,
        }
        for path in _harness_input_paths(config)
    )
    for candidate in (
        ROOT / ".benchmark-tools/codegraph/install-attempt-001-rejected.json",
        ROOT / ".benchmark-tools/codegraph/npm-userconfig",
    ):
        if candidate.is_file():
            scopes.append({"kind": "file", "path": candidate.relative_to(ROOT).as_posix()})
    for record in [*index_records, doctor_record]:
        scopes.append(
            {
                "kind": "tree",
                "path": Path(record["index_path"]).relative_to(ROOT).as_posix(),
            }
        )
        attempts = Path(record["index_path"]).with_name(
            f"{Path(record['index_path']).name}.preparation-attempts"
        )
        if attempts.is_dir():
            scopes.append({"kind": "tree", "path": attempts.relative_to(ROOT).as_posix()})
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str, bool]] = set()
    for scope in scopes:
        key = (scope["kind"], scope["path"], scope.get("freeze", True))
        if key not in seen:
            seen.add(key)
            unique.append(scope)
    return unique


def _index_configuration(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "configuration_version": config["index"]["configuration_version"],
        "exclude_names": config["index"]["exclude_names"],
        "directory_prefix": config["index"]["directory_prefix"],
        "telemetry_disabled": config["runtime"]["telemetry"] is False,
        "shared_daemon": config["runtime"]["shared_daemon"],
        "network_during_attempt": config["runtime"]["network_during_attempt"],
    }


def _index_path(config: dict[str, Any], task: dict[str, Any], lock: dict[str, Any]) -> Path:
    identity = index_identity(lock, task["instance_id"], task["base_commit"], _index_configuration(config))
    repository = _task_repository(config, task)
    return repository / f"{config['index']['directory_prefix']}{identity['identity_sha256'][:20]}"


def _index_record_path(config: dict[str, Any], task: dict[str, Any], lock: dict[str, Any]) -> Path:
    identity = index_identity(lock, task["instance_id"], task["base_commit"], _index_configuration(config))
    return paths(config)["indexes"] / task["instance_id"] / f"{identity['identity_sha256']}.record.json"


def _task_repository(config: dict[str, Any], task: dict[str, Any]) -> Path:
    return paths(config)["sources"] / task["instance_id"] / task["base_commit"]


def _ensure_task_snapshot(config: dict[str, Any], task: dict[str, Any]) -> Path:
    source = Path(task["prepared"]["resolved_path"])
    verify_repository_head(source, task["base_commit"])
    destination = _task_repository(config, task)
    record_path = destination.parent / f"{task['base_commit']}.snapshot.json"
    if not destination.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        started_at = datetime.now(timezone.utc).isoformat()
        started = time.monotonic()
        result = subprocess.run(
            ["git", "clone", "--no-local", "--no-checkout", str(source), str(destination)],
            capture_output=True,
            text=True,
            check=False,
        )
        clone_stdout = destination.parent / f"{task['base_commit']}.clone.stdout"
        clone_stderr = destination.parent / f"{task['base_commit']}.clone.stderr"
        clone_stdout.write_text(result.stdout or "", encoding="utf-8")
        clone_stderr.write_text(result.stderr or "", encoding="utf-8")
        if result.returncode:
            write_json(record_path, {
                "schema_version": "codegraph-task-snapshot-v1",
                "task_id": task["instance_id"],
                "base_commit": task["base_commit"],
                "source_path": str(source),
                "destination": str(destination),
                "return_code": result.returncode,
                "stdout": {"path": str(clone_stdout), "sha256": sha256_file(clone_stdout)},
                "stderr": {"path": str(clone_stderr), "sha256": sha256_file(clone_stderr)},
                "started_at": started_at,
                "ended_at": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": time.monotonic() - started,
                "ready": False,
            })
            raise CodeGraphError("repository_revision_mismatch", f"task snapshot clone failed: {task['instance_id']}")
        checked = subprocess.run(
            ["git", "-C", str(destination), "checkout", "--detach", task["base_commit"]],
            capture_output=True,
            text=True,
            check=False,
        )
        checkout_stdout = destination.parent / f"{task['base_commit']}.checkout.stdout"
        checkout_stderr = destination.parent / f"{task['base_commit']}.checkout.stderr"
        checkout_stdout.write_text(checked.stdout or "", encoding="utf-8")
        checkout_stderr.write_text(checked.stderr or "", encoding="utf-8")
        write_json(record_path, {
            "schema_version": "codegraph-task-snapshot-v1",
            "task_id": task["instance_id"],
            "base_commit": task["base_commit"],
            "source_path": str(source),
            "destination": str(destination),
            "clone_command": ["git", "clone", "--no-local", "--no-checkout", str(source), str(destination)],
            "checkout_command": ["git", "-C", str(destination), "checkout", "--detach", task["base_commit"]],
            "return_code": checked.returncode,
            "stdout": {"path": str(checkout_stdout), "sha256": sha256_file(checkout_stdout)},
            "stderr": {"path": str(checkout_stderr), "sha256": sha256_file(checkout_stderr)},
            "started_at": started_at,
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": time.monotonic() - started,
            "ready": checked.returncode == 0,
        })
        if checked.returncode:
            raise CodeGraphError("repository_revision_mismatch", f"task snapshot checkout failed: {task['instance_id']}")
    verify_repository_head(destination, task["base_commit"])
    return destination


def _load_index(config: dict[str, Any], task: dict[str, Any], lock: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    del lock
    authority = _require_task4_authority(config, runtime=runtime)
    try:
        return load_enriched_index(
            ROOT,
            authority=authority,
            runtime=runtime,
            task_id=task["instance_id"],
            base_commit=task["base_commit"],
            exclude_names=set(_index_configuration(config)["exclude_names"]),
        )
    except ValueError as exc:
        raise CodeGraphError(
            "codegraph_index_stale",
            str(exc),
        ) from exc


def _validate_attempt_repositories(
    config: dict[str, Any],
    task: dict[str, Any],
    index_record: dict[str, Any],
    lock: dict[str, Any],
    runtime: dict[str, Any],
) -> dict[str, Path]:
    measured_repository = Path(task["prepared"]["resolved_path"])
    verify_repository_head(measured_repository, task["base_commit"])
    index_master_repository = _task_repository(config, task)
    del lock
    authority = _require_task4_authority(config, runtime=runtime)
    try:
        validate_enriched_index(
            ROOT,
            authority=authority,
            runtime=runtime,
            record=index_record,
            task_id=task["instance_id"],
            base_commit=task["base_commit"],
            exclude_names=set(_index_configuration(config)["exclude_names"]),
        )
    except ValueError as exc:
        raise CodeGraphError("codegraph_index_stale", str(exc)) from exc
    measured_manifest = source_manifest(
        measured_repository,
        set(_index_configuration(config)["exclude_names"]),
    )
    if measured_manifest["sha256"] != index_record["source_manifest_sha256"]:
        raise CodeGraphError(
            "codegraph_index_stale",
            "measured repository source differs from frozen index source",
        )
    return {
        "measured_repository": measured_repository,
        "index_master_repository": index_master_repository,
    }


def codegraph_prepare() -> dict[str, Any]:
    """Read-only validation of the already sealed Task 2 runtime and Task 4 indexes."""
    config = load_config()
    p = paths(config)
    marker_present = (
        p["task2_freeze_marker"].exists()
        or p["task2_freeze_marker"].is_symlink()
    )
    root_present = (
        p["task2_evidence_root"].exists()
        or p["task2_evidence_root"].is_symlink()
    )
    if not marker_present or not root_present:
        raise RunnerError(
            "task2_evidence_refused: frozen Task 2 authority is incomplete"
        )
    frozen = _require_task2_evidence(config)
    lock, runtime = _load_runtime(config)
    authority = _require_task4_authority(config, runtime=runtime)
    tasks, _manifest = load_tasks(config)
    records = [
        _load_index(config, task, lock, runtime)
        for task in tasks
    ]
    if len(records) != 24 or len({record["task_id"] for record in records}) != 24:
        raise RunnerError(
            "enriched_authority_refused: Task 4 index population is incomplete"
        )
    result = {
        "schema_version": "codegraph-enriched-preparation-v1",
        "arm": "codex-codegraph-enriched",
        "frozen_task2_evidence_root": str(p["task2_evidence_root"]),
        "task2_evidence_entry_count": frozen["entry_count"],
        "task2_evidence_root_sha256": sha256_file(p["task2_evidence_root"]),
        "task2_freeze_marker_sha256": sha256_file(p["task2_freeze_marker"]),
        "task2_runtime_executable_sha256": runtime["executable_sha256"],
        "task4_sealed_root": TASK4_SEALED_ROOT,
        "task4_sealed_root_sha256": TASK4_SEALED_ROOT_SHA256,
        "task4_candidate_root_sha256": TASK4_CANDIDATE_ROOT_SHA256,
        "task4_all24": TASK4_ALL24,
        "task4_all24_sha256": TASK4_ALL24_SHA256,
        "enriched_authority_sha256": authority_digest(authority),
        "index_count": len(records),
        "task_ids": sorted(record["task_id"] for record in records),
        "revalidated_without_build_or_mutation": True,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def _doctor_repository(config: dict[str, Any]) -> tuple[Path, str]:
    p = paths(config)
    fixture = ARM_ROOT / "tests" / "fixtures" / "tiny_repo"
    repository = p["enriched_doctor"] / "tiny-repo"
    expected_files = {
        path.relative_to(fixture).as_posix(): path.read_bytes()
        for path in fixture.rglob("*")
        if path.is_file()
    }
    if not repository.exists():
        repository.mkdir(parents=True, mode=0o700)
        for relative, contents in expected_files.items():
            destination = repository / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(contents)
        subprocess.run(["git", "init", "-q", str(repository)], check=True)
        subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
        }
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "-c",
                "user.name=CodeGraph benchmark",
                "-c",
                "user.email=benchmark@example.invalid",
                "commit",
                "-qm",
                "tiny doctor fixture",
            ],
            check=True,
            env=environment,
        )
    for relative, contents in expected_files.items():
        path = repository / relative
        if not path.is_file() or path.read_bytes() != contents:
            raise CodeGraphError("repository_revision_mismatch", f"doctor fixture drift: {relative}")
    head = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    verify_repository_head(repository, head)
    return repository, head


def _prepare_doctor_index(
    config: dict[str, Any],
    lock: dict[str, Any],
    runtime: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    repository, head = _doctor_repository(config)
    task = {
        "instance_id": "codegraph-doctor-tiny",
        "base_commit": head,
        "issue_text": "Locate the route_request implementation and return its strongest source region.",
        "prepared": {"resolved_path": str(repository), "verified_head": head},
    }
    identity = index_identity(lock, task["instance_id"], head, _index_configuration(config))
    index_path = repository / f"{config['index']['directory_prefix']}{identity['identity_sha256'][:20]}"
    record_path = paths(config)["enriched_doctor"] / "indexes" / f"{identity['identity_sha256']}.record.json"
    if record_path.is_file():
        record = json.loads(record_path.read_text(encoding="utf-8"))
        validate_index(
            record,
            lock=lock,
            runtime=runtime,
            task_id=task["instance_id"],
            base_commit=head,
            repository=repository,
            configuration=_index_configuration(config),
        )
    else:
        record = prepare_index(
            lock=lock,
            runtime=runtime,
            task_id=task["instance_id"],
            base_commit=head,
            repository=repository,
            index_dir=index_path,
            log_dir=paths(config)["enriched_doctor"] / "setup-logs",
            configuration=_index_configuration(config),
            record_path=record_path,
        )
    prepared_path = paths(config)["enriched_doctor"] / "doctor-prepared.json"
    expected_prepared = {
        "task": task,
        "index_record": str(record_path),
        "index_identity": record["identity"],
    }
    if prepared_path.is_file():
        if json.loads(prepared_path.read_text(encoding="utf-8")) != expected_prepared:
            raise CodeGraphError(
                "codegraph_index_stale",
                "immutable doctor preparation identity differs",
            )
    else:
        write_json(prepared_path, expected_prepared)
    return task, record


def _load_doctor_preparation(
    config: dict[str, Any],
    lock: dict[str, Any],
    runtime: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    prepared_path = paths(config)["enriched_doctor"] / "doctor-prepared.json"
    if not prepared_path.is_file():
        raise CodeGraphError("codegraph_index_failure", "tiny doctor index missing; run codegraph-prepare")
    prepared = json.loads(prepared_path.read_text(encoding="utf-8"))
    task = prepared.get("task")
    record_path = Path(prepared.get("index_record", ""))
    if not isinstance(task, dict) or not record_path.is_file():
        raise CodeGraphError("codegraph_status_invalid", "tiny doctor preparation is malformed")
    record = json.loads(record_path.read_text(encoding="utf-8"))
    validate_index(
        record,
        lock=lock,
        runtime=runtime,
        task_id=task["instance_id"],
        base_commit=task["base_commit"],
        repository=Path(task["prepared"]["resolved_path"]),
        configuration=_index_configuration(config),
    )
    return task, record


def _run_mcp_behavior_probe(
    config: dict[str, Any],
    lock: dict[str, Any],
    runtime: dict[str, Any],
    task: dict[str, Any],
    index_record: dict[str, Any],
) -> dict[str, Any]:
    """Drive direct stdio MCP on a disposable copy; never launch Codex."""
    p = paths(config)
    probe_root = p["runtime_record"].parent / "mcp-behavior-probe"
    probe_path = probe_root / "probe.json"
    if probe_path.is_file():
        probe = json.loads(probe_path.read_text(encoding="utf-8"))
        if (
            probe.get("schema_version") == "codegraph-mcp-behavior-probe-v1"
            and probe.get("verified") is True
        ):
            runtime["mcp_behavior_probe"] = {
                "path": str(probe_path),
                "bytes": probe_path.stat().st_size,
                "sha256": sha256_file(probe_path),
            }
            if runtime != json.loads(p["runtime_record"].read_text(encoding="utf-8")):
                raise CodeGraphError(
                    "codegraph_source_mismatch",
                    "verified MCP probe binding differs from immutable runtime record",
                )
            return probe
        probe_path.unlink()
    isolation_root = Path(
        tempfile.mkdtemp(prefix="context-graph-codegraph-behavior-", dir="/private/tmp")
    )
    snapshot: dict[str, Any] | None = None
    try:
        master_repository = Path(task["prepared"]["resolved_path"])
        snapshot = prepare_isolated_repository(
            master_repository,
            task["base_commit"],
            isolation_root,
            task["instance_id"],
            "task2-mcp-behavior",
        )
        git_provenance = neutralize_git_provenance(snapshot)
        child_repo = Path(snapshot["path"])
        stage = stage_runtime_bundle(
            runtime=runtime,
            checkout=p["source_checkout"],
            stage_root=isolation_root / "staged-codegraph-runtime",
        )
        codex_home = isolation_root / "canary-codex-home"
        state = isolation_root / "canary-state"
        codex_home.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        lifecycle_root = probe_root / "index-lifecycle"
        with attempt_index_copy(
            record=index_record,
            lock=lock,
            master_repository=master_repository,
            child_repository=child_repo,
            attempt_root=isolation_root / "attempt",
            evidence_root=lifecycle_root,
            runtime_stage=stage,
        ) as binding:
            profile = codegraph_sandbox_profile(
                child_repo,
                codex_home,
                state,
                [Path(stage["stage_root"]), Path(binding["index_path"])],
                _forbidden_paths(config),
                Path(binding["index_path"]),
            )
            canaries = run_isolation_canaries(
                profile=profile,
                repository=child_repo,
                codex_home=codex_home,
                state_dir=state,
                writable_index_root=Path(binding["index_path"]),
                staged_runtime_root=Path(stage["stage_root"]),
                denied_read_path=ROOT / "task2.md",
                denied_write_path=ROOT / ".task2-sandbox-canary",
            )
            request_lines = [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "codegraph-task2-probe", "version": "1"},
                    },
                },
                {"jsonrpc": "2.0", "method": "initialized", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "codegraph_explore",
                        "arguments": {"query": "route_request"},
                    },
                },
            ]
            request_payload = "".join(
                json.dumps(value, separators=(",", ":")) + "\n"
                for value in request_lines
            )
            environment = {
                **binding["environment"],
                "CODEGRAPH_MCP_DEBUG": "1",
            }
            command = [
                "/usr/bin/sandbox-exec",
                "-p",
                NETWORK_DENY_PROFILE,
                *binding["launcher"],
                *binding["serve_args"],
            ]
            started_at = datetime.now(timezone.utc).isoformat()
            started = time.monotonic()
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=child_repo,
                env=environment,
            )
            if process.stdin is None or process.stdout is None or process.stderr is None:
                process.kill()
                raise CodeGraphError(
                    "codegraph_source_mismatch",
                    "direct MCP behavior probe pipes are unavailable",
                )
            response_lines: list[str] = []
            response_selector = selectors.DefaultSelector()
            response_selector.register(process.stdout, selectors.EVENT_READ)

            def send_and_receive(request: dict[str, Any]) -> dict[str, Any]:
                process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
                process.stdin.flush()
                if not response_selector.select(timeout=30):
                    raise CodeGraphError(
                        "codegraph_source_mismatch",
                        f"direct MCP response timed out for request {request.get('id')}",
                    )
                line = process.stdout.readline()
                response_lines.append(line)
                value = json.loads(line)
                if value.get("id") != request.get("id"):
                    raise CodeGraphError(
                        "codegraph_source_mismatch",
                        "direct MCP response identity differs",
                    )
                return value

            watch_canary = child_repo / ".task2-watch-canary.ts"
            index_before_watch_canary: dict[str, Any] | None = None
            index_after_watch_canary: dict[str, Any] | None = None
            try:
                send_and_receive(request_lines[0])
                process.stdin.write(
                    json.dumps(request_lines[1], separators=(",", ":")) + "\n"
                )
                process.stdin.flush()
                time.sleep(0.25)
                index_before_watch_canary = directory_manifest(Path(binding["index_path"]))
                watch_canary.write_text(
                    "export const task2WatchCanary = true;\n",
                    encoding="utf-8",
                )
                time.sleep(3)
                send_and_receive(request_lines[2])
                send_and_receive(request_lines[3])
                process.stdin.close()
                process.stdin = None
                stdout_remainder, stderr_text = process.communicate(timeout=60)
                if stdout_remainder:
                    response_lines.append(stdout_remainder)
                index_after_watch_canary = directory_manifest(Path(binding["index_path"]))
            except Exception:
                process.kill()
                process.communicate()
                raise
            finally:
                response_selector.close()
                if watch_canary.exists():
                    watch_canary.unlink()
            process_stdout = "".join(response_lines)
            probe_root.mkdir(parents=True, exist_ok=True)
            stdout_path = probe_root / "mcp.stdout"
            stderr_path = probe_root / "mcp.stderr"
            request_path = probe_root / "mcp.stdin"
            stdout_path.write_text(process_stdout, encoding="utf-8")
            stderr_path.write_text(stderr_text, encoding="utf-8")
            request_path.write_text(request_payload, encoding="utf-8")
            responses = [
                json.loads(line)
                for line in process_stdout.splitlines()
                if line.strip()
            ]
            by_id = {
                value.get("id"): value
                for value in responses
                if isinstance(value, dict) and "id" in value
            }
            tools = (
                by_id.get(2, {})
                .get("result", {})
                .get("tools", [])
            )
            tool_names = sorted(
                value.get("name")
                for value in tools
                if isinstance(value, dict) and isinstance(value.get("name"), str)
            )
            daemon_artifacts = [
                path.relative_to(binding["index_path"]).as_posix()
                for path in Path(binding["index_path"]).rglob("*")
                if path.name in {"daemon.pid", "daemon.sock", "daemon.log"}
            ]
            in_context = {
                "return_code": process.returncode,
                "started_at": started_at,
                "ended_at": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": time.monotonic() - started,
                "command": command,
                "request": {
                    "path": str(request_path),
                    "bytes": request_path.stat().st_size,
                    "sha256": sha256_file(request_path),
                },
                "stdout": {
                    "path": str(stdout_path),
                    "bytes": stdout_path.stat().st_size,
                    "sha256": sha256_file(stdout_path),
                },
                "stderr": {
                    "path": str(stderr_path),
                    "bytes": stderr_path.stat().st_size,
                    "sha256": sha256_file(stderr_path),
                },
                "initialize_response": 1 in by_id,
                "tools_list_response": 2 in by_id,
                "tool_call_response": 3 in by_id and "result" in by_id[3],
                "tool_names": tool_names,
                "direct_mode_stderr": "Direct mode: CODEGRAPH_NO_DAEMON set" in stderr_text,
                "watch_control_environment": environment["CODEGRAPH_NO_WATCH"] == "1",
                "watch_control_argument": "--no-watch" in binding["serve_args"],
                "watch_canary_index_unchanged": (
                    index_before_watch_canary == index_after_watch_canary
                ),
                "daemon_artifacts": daemon_artifacts,
                "canaries": canaries,
                "git_provenance": git_provenance,
            }
        lifecycle_path = lifecycle_root / "lifecycle.json"
        lifecycle = json.loads(lifecycle_path.read_text(encoding="utf-8"))
        probe = {
            "schema_version": "codegraph-mcp-behavior-probe-v1",
            "verified": bool(
                in_context["return_code"] == 0
                and in_context["initialize_response"]
                and in_context["tools_list_response"]
                and in_context["tool_call_response"]
                and in_context["tool_names"] == ["codegraph_explore"]
                and in_context["direct_mode_stderr"]
                and in_context["watch_control_environment"]
                and in_context["watch_control_argument"]
                and in_context["watch_canary_index_unchanged"]
                and not in_context["daemon_artifacts"]
                and in_context["canaries"]["passed"]
                and in_context["git_provenance"]["neutralized"]
                and lifecycle["cleanup_complete"]
                and lifecycle["master_unchanged"]
            ),
            "network_policy": "deny",
            "direct_stdio": in_context["direct_mode_stderr"],
            "shared_daemon": False,
            "watcher": False,
            "catch_up_sync_may_mutate_copy": True,
            "catch_up_copy_changed_observed": lifecycle.get(
                "copy_changed_during_attempt"
            ),
            "runtime_stage": stage,
            "mcp": in_context,
            "index_lifecycle": {
                "path": str(lifecycle_path),
                "bytes": lifecycle_path.stat().st_size,
                "sha256": sha256_file(lifecycle_path),
            },
            "isolation_guarantees": isolation_guarantees(),
        }
        if not probe["verified"]:
            write_json(probe_path, probe)
            raise CodeGraphError(
                "codegraph_source_mismatch",
                "network-denied MCP behavior/isolation probe did not close every gate",
            )
        write_json(probe_path, probe)
        runtime["mcp_behavior_probe"] = {
            "path": str(probe_path),
            "bytes": probe_path.stat().st_size,
            "sha256": sha256_file(probe_path),
        }
        write_json(p["runtime_record"], runtime)
        return probe
    finally:
        if snapshot is not None:
            remove_isolated_repository(snapshot)
        shutil.rmtree(isolation_root, ignore_errors=True)


def _harness_file_rows() -> list[dict[str, Any]]:
    harness_rows = []
    for path in sorted(
        [
            ARM_ROOT / "benchmark.py",
            *(ARM_ROOT / "config").rglob("*"),
            *(ARM_ROOT / "schemas").rglob("*"),
            *(ARM_ROOT / "src").rglob("*.py"),
        ]
    ):
        if path.is_file() and "__pycache__" not in path.parts:
            harness_rows.append(
                {
                    "path": path.relative_to(ARM_ROOT).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    return harness_rows


def _harness_digest(
    config: dict[str, Any],
    lock: dict[str, Any],
    runtime: dict[str, Any],
    evaluator: dict[str, str],
    harness_files: list[dict[str, Any]] | None = None,
) -> str:
    authority = _require_task4_authority(config, runtime=runtime)
    task2_active = json.loads(
        (paths(config)["setup_logs"] / "active-authority.json").read_text(
            encoding="utf-8"
        )
    )
    value = {
        "active_harness_sha256": task2_active["active_harness_sha256"],
        "task5_harness_sha256": sha256_value(
            harness_files
            if harness_files is not None
            else _harness_file_rows()
        ),
        "task4_authority_sha256": authority_digest(authority),
        "configuration_sha256": config_digest(config),
        "source_lock_sha256": sha256_file(paths(config)["source_lock"]),
        "runtime_record_sha256": sha256_file(paths(config)["runtime_record"]),
        "task2_evidence_root_sha256": sha256_file(
            CANONICAL_TASK2_EVIDENCE_ROOT
        ),
        "runtime_configuration_sha256": runtime["configuration_sha256"],
        "evaluator_sha256": evaluator["sha256"],
        "codegraph_commit": lock["resolved_commit"],
    }
    return sha256_value(value)


def _task7_treatment_freeze_path() -> Path:
    return (
        ROOT
        / ".benchmark-work"
        / "codegraph-enriched"
        / f"task7-cycle-{TASK7_FREEZE_VERSION}"
        / f"treatment-freeze-v{TASK7_FREEZE_VERSION}.json"
    )


def _repository_file_identity(
    relative: str,
    *,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    if (
        not isinstance(relative, str)
        or not relative
        or Path(relative).is_absolute()
        or Path(relative).as_posix() != relative
        or any(part in {"", ".", ".."} for part in Path(relative).parts)
    ):
        raise RunnerError(
            "treatment_freeze_refused: authority path is not canonical"
        )
    path = ROOT / relative
    _assert_no_symlink_components(path)
    if not path.is_file() or path.is_symlink():
        raise RunnerError(
            f"treatment_freeze_refused: authority is missing: {relative}"
        )
    digest = sha256_file(path)
    if expected_sha256 is not None and digest != expected_sha256:
        raise RunnerError(
            f"treatment_freeze_refused: authority bytes differ: {relative}"
        )
    return {
        "path": relative,
        "bytes": path.stat().st_size,
        "sha256": digest,
    }


def _task7_treatment_identity(
    config: dict[str, Any],
    tasks: list[dict[str, Any]],
    source_manifest_record: dict[str, Any],
    lock: dict[str, Any],
    runtime: dict[str, Any],
    indexes: list[dict[str, Any]],
) -> dict[str, Any]:
    if len(tasks) != 24 or len(indexes) != 24:
        raise RunnerError(
            "treatment_freeze_refused: treatment requires 24 tasks and indexes"
        )
    task_rows = [
        {
            "instance_id": task["instance_id"],
            "base_commit": task["base_commit"],
        }
        for task in tasks
    ]
    if (
        len({row["instance_id"] for row in task_rows}) != 24
        or sum(
            row == TASK7_OFFICIAL_SMOKE_TASK
            for row in task_rows
        )
        != 1
    ):
        raise RunnerError(
            "treatment_freeze_refused: predeclared smoke task differs"
        )
    index_rows = sorted(
        (
            {
                "task_id": record["task_id"],
                "base_commit": record["requested_base_commit"],
                "identity_sha256": record["identity"][
                    "identity_sha256"
                ],
                "index_artifact_manifest_sha256": record[
                    "index_artifact_manifest"
                ]["sha256"],
                "runtime_projection_sha256": record[
                    "runtime_projection_sha256"
                ],
            }
            for record in indexes
        ),
        key=lambda row: row["task_id"],
    )
    if {
        (row["task_id"], row["base_commit"])
        for row in index_rows
    } != {
        (row["instance_id"], row["base_commit"])
        for row in task_rows
    }:
        raise RunnerError(
            "treatment_freeze_refused: task/index revisions differ"
        )
    evaluator = verify_official_evaluator(
        paths(config)["evaluator"],
        paths(config)["provenance"],
    )
    codex = resolve_executable(
        {
            "paths": {
                "codex_executable": config["paths"][
                    "codex_executable"
                ]
            }
        }
    )
    codex_version = verify_pinned_version(
        codex,
        config["treatment"]["codex_version"],
    )
    task6_doctor = _require_sealed_task6_doctor(
        runtime=runtime,
        codex=codex,
        codex_version=codex_version,
    )
    task4_authority = _require_task4_authority(
        config,
        runtime=runtime,
    )
    sealed_tasks = [
        {
            "task": task,
            **_repository_file_identity(
                relative,
                expected_sha256=expected,
            ),
        }
        for task, relative, expected in TASK_SEALED_AUTHORITIES
    ]
    sealed_by_task = {
        row["task"]: row
        for row in sealed_tasks
    }
    start_receipt = _repository_file_identity(
        TASK7_START_RECEIPT,
        expected_sha256=TASK7_START_RECEIPT_SHA256,
    )
    retrieval_parity = _repository_file_identity(
        TASK6_RETRIEVAL_PARITY,
        expected_sha256=TASK6_RETRIEVAL_PARITY_SHA256,
    )
    p = paths(config)
    task3 = task4_authority["task3_implementation"]
    runtime_bundle = _runtime_bundle_authority(
        p["source_checkout"],
        runtime,
    )
    harness_files = _harness_file_rows()
    mcp_transcript_identity = _repository_file_identity(
        TASK6_MCP_TRANSCRIPT,
        expected_sha256=TASK6_MCP_TRANSCRIPT_SHA256,
    )
    mcp_transcript = json.loads(
        (ROOT / TASK6_MCP_TRANSCRIPT).read_text(encoding="utf-8")
    )
    if not isinstance(mcp_transcript.get("tool_schema"), dict):
        raise RunnerError(
            "treatment_freeze_refused: MCP tool schema is missing"
        )
    return {
        "contract": _repository_file_identity(
            "task3.md",
            expected_sha256=(
                "4dbbdddea792025d360e3bf712ae198f491da03d472065ee80b3b27135a271fe"
            ),
        ),
        "ordered_task_authority": {
            "sealed_tasks": sealed_tasks,
            "task7_start_receipt": start_receipt,
        },
        "builder_and_extractors": {
            "upstream_commit": lock["resolved_commit"],
            "declared_version": lock["declared_version"],
            "task3_seal_sha256": sealed_by_task[3]["sha256"],
            "task3_implementation_sha256": task3[
                "implementation_sha256"
            ],
            "task3_implementation_manifest": _authority_file(
                task3["manifest_path"]
            ),
            "builder_dirty_path_count": task3[
                "builder_dirty_path_count"
            ],
            "builder_dirty_paths_sha256": task3[
                "builder_dirty_paths_sha256"
            ],
        },
        "runtime": {
            "task2_evidence_root": _authority_file(
                p["task2_evidence_root"]
            ),
            "task2_freeze_marker": _authority_file(
                p["task2_freeze_marker"]
            ),
            "task2_executable": _authority_file(
                Path(runtime["executable_path"])
            ),
            "task2_executable_sha256": (
                TASK2_RUNTIME_EXECUTABLE_SHA256
            ),
            "runtime_record": _authority_file(p["runtime_record"]),
            "runtime_configuration_sha256": runtime[
                "configuration_sha256"
            ],
            "runtime_bundle": runtime_bundle,
        },
        "retrieval_parity": {
            "task1_seal_sha256": sealed_by_task[1]["sha256"],
            "task6_result": retrieval_parity,
            "retrieval_ranking_rendering_frozen_by_task2_runtime": True,
        },
        "doctor": task6_doctor,
        "mcp_contract": {
            "task6_transcript": mcp_transcript_identity,
            "tool_schema_sha256": sha256_value(
                mcp_transcript["tool_schema"]
            ),
        },
        "indexes": {
            "task4_seal_sha256": sealed_by_task[4]["sha256"],
            "task4_authority_sha256": authority_digest(
                task4_authority
            ),
            "count": len(index_rows),
            "records": index_rows,
        },
        "harness": {
            "files": harness_files,
            "files_sha256": sha256_value(harness_files),
            "harness_sha256": _harness_digest(
                config,
                lock,
                runtime,
                evaluator,
                harness_files,
            ),
            "configuration_sha256": config_digest(config),
            "configuration": _authority_file(
                ARM_ROOT / "config" / "codegraph.toml"
            ),
            "prompt": _authority_file(p["prompt"]),
            "response_schema": _authority_file(p["schema"]),
            "run_manifest_schema": _authority_file(
                ARM_ROOT / "schemas" / "run-manifest.schema.json"
            ),
            "parser": _authority_file(
                ARM_ROOT
                / "src"
                / "codegraph_bench"
                / "codegraph_events.py"
            ),
            "runner": _authority_file(
                ARM_ROOT
                / "src"
                / "codegraph_bench"
                / "codegraph_runner.py"
            ),
            "evaluator": evaluator,
            "retry_cap": config["treatment"]["retry_cap"],
        },
        "corpus_and_execution": {
            "manifest": _authority_file(p["manifest"]),
            "prepared_tasks": _authority_file(
                p["baseline_prepared"]
            ),
            "source_manifest_sha256": sha256_value(
                source_manifest_record
            ),
            "task_identity_sha256": sha256_value(
                sorted(
                    task_rows,
                    key=lambda row: row["instance_id"],
                )
            ),
            "task_count": 24,
            "sample_count_per_task": 3,
            "model": config["treatment"]["model"],
            "reasoning_effort": config["treatment"][
                "reasoning_effort"
            ],
            "codex_version": codex_version,
            "codex_executable_sha256": file_sha256(codex),
            "sandbox": "macos-sandbox-exec-codegraph-v2",
            "timeout_seconds": config["treatment"][
                "timeout_seconds"
            ],
            "max_regions": config["treatment"]["max_regions"],
            "response_schema_sha256": sha256_file(p["schema"]),
        },
        "official_smoke": {
            "run_id": TASK7_OFFICIAL_SMOKE_RUN_ID,
            "sample_count": 1,
            "task": TASK7_OFFICIAL_SMOKE_TASK,
        },
        "post_score_policy": {
            "treatment_changes_forbidden": True,
            "score_guided_changes_forbidden": True,
            "only_proven_harness_defect_may_restart_versioned_smoke": True,
        },
    }


def _load_task7_treatment_freeze(
    config: dict[str, Any],
    tasks: list[dict[str, Any]],
    source_manifest_record: dict[str, Any],
    lock: dict[str, Any],
    runtime: dict[str, Any],
    indexes: list[dict[str, Any]],
) -> dict[str, Any]:
    expected = _task7_treatment_identity(
        config,
        tasks,
        source_manifest_record,
        lock,
        runtime,
        indexes,
    )
    return validate_treatment_freeze(
        _task7_treatment_freeze_path(),
        expected,
    )


def create_treatment_freeze() -> dict[str, Any]:
    config = load_config()
    _require_task2_evidence(config)
    tasks, source_manifest_record = load_tasks(config)
    lock, runtime = _load_runtime(config)
    indexes = [
        _load_index(config, task, lock, runtime)
        for task in tasks
    ]
    treatment = _task7_treatment_identity(
        config,
        tasks,
        source_manifest_record,
        lock,
        runtime,
        indexes,
    )
    frozen = write_treatment_freeze(
        _task7_treatment_freeze_path(),
        treatment,
    )
    result = {
        "path": str(
            _task7_treatment_freeze_path().relative_to(ROOT)
        ),
        "sha256": sha256_file(_task7_treatment_freeze_path()),
        "treatment_sha256": frozen["treatment_sha256"],
        "status": frozen["status"],
        "task_count": 24,
        "official_smoke": frozen["treatment"]["official_smoke"],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def check_treatment_freeze() -> dict[str, Any]:
    config = load_config()
    _require_task2_evidence(config)
    tasks, source_manifest_record = load_tasks(config)
    lock, runtime = _load_runtime(config)
    indexes = [
        _load_index(config, task, lock, runtime)
        for task in tasks
    ]
    frozen = _load_task7_treatment_freeze(
        config,
        tasks,
        source_manifest_record,
        lock,
        runtime,
        indexes,
    )
    result = {
        "path": str(
            _task7_treatment_freeze_path().relative_to(ROOT)
        ),
        "sha256": sha256_file(_task7_treatment_freeze_path()),
        "treatment_sha256": frozen["treatment_sha256"],
        "status": "PASS",
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def _select_predeclared_smoke_task(
    tasks: list[dict[str, Any]],
    frozen: dict[str, Any],
    run_id: str,
) -> dict[str, Any]:
    smoke = frozen.get("treatment", {}).get("official_smoke")
    if not isinstance(smoke, dict) or smoke.get("run_id") != run_id:
        raise RunnerError(
            "treatment_freeze_refused: official smoke run_id differs"
        )
    if smoke.get("sample_count") != 1:
        raise RunnerError(
            "treatment_freeze_refused: official smoke sample count differs"
        )
    expected = smoke.get("task")
    matches = [
        task
        for task in tasks
        if isinstance(expected, dict)
        and task.get("instance_id") == expected.get("instance_id")
        and task.get("base_commit") == expected.get("base_commit")
    ]
    if len(matches) != 1:
        raise RunnerError(
            "treatment_freeze_refused: official smoke task differs"
        )
    return matches[0]


def _validate_frozen_smoke_manifest(
    frozen: dict[str, Any],
    run_id: str,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    smoke = frozen.get("treatment", {}).get("official_smoke")
    tasks = manifest.get("corpus", {}).get("tasks")
    if (
        not isinstance(smoke, dict)
        or smoke.get("run_id") != run_id
        or smoke.get("sample_count") != 1
        or manifest.get("run_id") != run_id
        or manifest.get("configuration", {}).get("sample_count") != 1
        or not isinstance(tasks, list)
        or len(tasks) != 1
    ):
        raise RunnerError(
            "treatment_freeze_refused: official smoke manifest differs"
        )
    expected = smoke.get("task")
    actual = tasks[0]
    if (
        not isinstance(expected, dict)
        or not isinstance(actual, dict)
        or {
            "instance_id": actual.get("instance_id"),
            "base_commit": actual.get("base_commit"),
        }
        != expected
    ):
        raise RunnerError(
            "treatment_freeze_refused: official smoke task differs"
        )
    return actual


def _validate_run_treatment_freeze(
    run_root: Path,
    manifest: dict[str, Any],
    live_path: Path,
    frozen: dict[str, Any],
) -> None:
    binding = manifest.get("treatment_freeze")
    expected = {
        "path": "treatment-freeze.json",
        "sha256": sha256_file(live_path),
        "treatment_sha256": frozen["treatment_sha256"],
    }
    if binding != expected:
        raise RunnerError(
            "treatment_freeze_refused: run binding differs"
        )
    copied = run_root / "treatment-freeze.json"
    live_bytes = live_path.read_bytes()
    copied_bytes = (
        copied.read_bytes()
        if copied.is_file() and not copied.is_symlink()
        else None
    )
    if (
        copied.is_symlink()
        or not copied.is_file()
        or copied_bytes != live_bytes
        or (
            copied_bytes is not None
            and sha256_bytes(copied_bytes) != expected["sha256"]
        )
    ):
        raise RunnerError(
            "treatment_freeze_refused: run copy differs"
        )


def _require_run_treatment_freeze(
    config: dict[str, Any],
    run_root: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    tasks, source_manifest_record = load_tasks(config)
    lock, runtime = _load_runtime(config)
    indexes = [
        _load_index(config, task, lock, runtime)
        for task in tasks
    ]
    frozen = _load_task7_treatment_freeze(
        config,
        tasks,
        source_manifest_record,
        lock,
        runtime,
        indexes,
    )
    _validate_run_treatment_freeze(
        run_root,
        manifest,
        _task7_treatment_freeze_path(),
        frozen,
    )
    return frozen


def _forbidden_paths(config: dict[str, Any]) -> list[Path]:
    p = paths(config)
    return [
        Path("/Users/aiswarya/Documents"),
        ROOT,
        ROOT / ".benchmark-runs",
        p["baseline_prepared"],
        ROOT / ".benchmark-work" / "codex-baseline",
        COMMON_ROOT / "inputs",
        COMMON_ROOT / "official",
        p["source_lock"],
        p["upstream_resolution"],
        p["source_checkout"],
        p["runtime_record"].parent,
        p["indexes"],
        p["enriched_indexes"],
        p["sources"],
        p["setup_logs"],
        p["doctor"],
        p["enriched_doctor"],
        p["task4_all24"],
        p["task4_sealed_root"],
        p["enriched_builder_checkout"],
    ]


def _serve_args(lock: dict[str, Any], repository: Path, index_path: Path) -> list[str]:
    return [
        value.replace("{repository}", str(repository)).replace("{index}", str(index_path))
        for value in lock["serve_args"]
    ]


def doctor() -> dict[str, Any]:
    """Capture a real MCP trace; failure artifacts are retained for Task 3."""
    config = load_config()
    task2_evidence = _require_task2_evidence(config)
    p = paths(config)
    lock, runtime = _load_runtime(config)
    task, index_record = _load_doctor_preparation(config, lock, runtime)
    codex = resolve_executable({"paths": {"codex_executable": config["paths"]["codex_executable"]}})
    version = verify_pinned_version(codex, config["treatment"]["codex_version"])
    validate_auth_source(p["auth"])
    p["enriched_doctor"].mkdir(parents=True, exist_ok=True)
    capture = p["enriched_doctor"] / time.strftime("capture-%Y%m%dT%H%M%SZ", time.gmtime())
    capture.mkdir(mode=0o700)
    isolation_root = Path(tempfile.mkdtemp(prefix="context-graph-codegraph-doctor-", dir="/private/tmp"))
    repository = Path(task["prepared"]["resolved_path"])
    snapshot = prepare_isolated_repository(repository, task["base_commit"], isolation_root, task["instance_id"], "doctor")
    git_provenance = neutralize_git_provenance(snapshot)
    child_repo = Path(snapshot["path"])
    private_home, state = fresh_runtime_dirs(isolation_root / "runtime", p["auth"])
    runtime_stage = stage_runtime_bundle(
        runtime=runtime,
        checkout=p["source_checkout"],
        stage_root=isolation_root / "staged-codegraph-runtime",
    )
    shutil.copyfile(p["schema"], state / "agent-regions.schema.json")
    prompt = build_treatment_prompt(p["prompt"].read_text(encoding="utf-8"), task["issue_text"])
    try:
        with attempt_index_copy(
            record=index_record,
            lock=lock,
            master_repository=repository,
            child_repository=child_repo,
            attempt_root=isolation_root / "index-attempt",
            evidence_root=capture / "index-lifecycle",
            runtime_stage=runtime_stage,
        ) as index_binding:
            mcp_environment = {
                key: value
                for key, value in index_binding["environment"].items()
                if key.startswith("CODEGRAPH_") or key == "DO_NOT_TRACK"
            }
            command = build_codegraph_command(
                codex,
                config,
                state,
                p["schema"],
                child_repo,
                codegraph_launcher=index_binding["launcher"],
                serve_args=index_binding["serve_args"],
                mcp_environment=mcp_environment,
            )
            result = run_codegraph_child(
                command,
                prompt,
                state_dir=state,
                events_path=state / "events.jsonl",
                stderr_path=state / "stderr.log",
                timeout_seconds=float(config["treatment"]["timeout_seconds"]),
                environment=child_environment(codex, mcp_environment),
                repository=child_repo,
                codex_home=private_home,
                mcp_roots=[
                    Path(runtime_stage["stage_root"]),
                    Path(index_binding["index_path"]),
                ],
                forbidden_paths=_forbidden_paths(config),
                expected_project=child_repo,
                writable_index_root=Path(index_binding["index_path"]),
                mcp_server_command=[
                    *index_binding["launcher"],
                    *index_binding["serve_args"],
                ],
                mcp_environment=mcp_environment,
            )
        shutil.copyfile(state / "events.jsonl", capture / "events.jsonl")
        shutil.copyfile(state / "stderr.log", capture / "stderr.log")
        if (state / "response.json").is_file():
            shutil.copyfile(state / "response.json", capture / "response.json")
        raw = (capture / "events.jsonl").read_text(encoding="utf-8", errors="replace")
        contamination = audit_events(raw, _forbidden_paths(config))
        response_valid = False
        if result.get("response") is not None:
            try:
                from codegraph_bench.codegraph_runner import validate_regions

                validate_regions(result["response"], child_repo, int(config["treatment"]["max_regions"]))
                response_valid = True
            except Exception:
                response_valid = False
        passed = bool(
            result.get("returncode") == 0
            and result.get("failure_class") is None
            and result.get("telemetry", {}).get("valid") is True
            and result.get("navigation", {}).get("graph_use_valid") is True
            and response_valid
            and contamination.get("passed") is True
            and result.get("navigation", {}).get(
                "real_envelope_integration"
            )
            == LIVE_CODEGRAPH_ENVELOPE
        )
        record = {
            "schema_version": "codegraph-doctor-v1",
            "passed": passed,
            "capture": str(capture),
            "runtime": {
                "codex_version": version,
                "codex_executable_sha256": file_sha256(codex),
                "codegraph_source_commit": lock["resolved_commit"],
                "codegraph_executable_sha256": runtime["executable_sha256"],
                "index_identity": index_record["identity"],
                "task2_evidence_root_sha256": sha256_file(
                    p["task2_evidence_root"]
                ),
                "task2_evidence_entry_count": task2_evidence["entry_count"],
                "runtime_stage": runtime_stage,
                "git_provenance": git_provenance,
            },
            "return_code": result.get("returncode"),
            "telemetry": result.get("telemetry"),
            "navigation": result.get("navigation"),
            "response_valid": response_valid,
            "contamination_audit": contamination,
            "real_envelope_integration": result.get("navigation", {}).get(
                "real_envelope_integration"
            ),
            "mcp_transport": {
                "mode": result.get("mcp_transport"),
                "server_argument_vector": result.get(
                    "mcp_server_argument_vector"
                ),
                "server_return_code": result.get("mcp_server_returncode"),
                "server_stderr_bytes": result.get(
                    "mcp_server_stderr_bytes"
                ),
                "server_stderr_sha256": result.get(
                    "mcp_server_stderr_sha256"
                ),
                "bridge_errors": result.get("mcp_bridge_errors"),
            },
            "index_lifecycle": {
                "path": str(capture / "index-lifecycle" / "lifecycle.json"),
                "sha256": sha256_file(
                    capture / "index-lifecycle" / "lifecycle.json"
                ),
            },
        }
        write_json(capture / "doctor.json", record)
        write_json(p["enriched_doctor"] / "doctor.json", record)
        print(json.dumps(record, indent=2, sort_keys=True))
        if not passed:
            raise RunnerError("codegraph_doctor_failed: retained trace does not close every doctor gate")
        return record
    finally:
        shutil.rmtree(private_home, ignore_errors=True)
        shutil.rmtree(state, ignore_errors=True)
        remove_isolated_repository(snapshot)
        shutil.rmtree(isolation_root, ignore_errors=True)


def _expected_runtime_stage_digests(
    runtime: dict[str, Any],
) -> dict[str, str]:
    descriptor = runtime.get("runtime_bundle_manifest")
    toolchain = runtime.get("toolchain")
    node = toolchain.get("node") if isinstance(toolchain, dict) else None
    if not isinstance(descriptor, dict) or not isinstance(node, dict):
        raise RunnerError(
            "configuration_error: current passing CodeGraph doctor required"
        )
    manifest_path = Path(str(descriptor.get("path", "")))
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RunnerError(
            "configuration_error: current passing CodeGraph doctor required"
        ) from exc
    expected = {
        "runtime_bundle_manifest_sha256": manifest.get("manifest_sha256"),
        "node_executable_sha256": node.get("executable_sha256"),
        "codegraph_executable_sha256": runtime.get("executable_sha256"),
    }
    if any(
        not isinstance(value, str) or len(value) != 64
        for value in expected.values()
    ):
        raise RunnerError(
            "configuration_error: current passing CodeGraph doctor required"
        )
    return expected


def _runtime_stage_matches(
    saved_stage: Any,
    expected_digests: dict[str, str],
) -> bool:
    if not isinstance(saved_stage, dict):
        return False
    if any(
        saved_stage.get(key) != value
        for key, value in expected_digests.items()
    ):
        return False
    stage_root = Path(str(saved_stage.get("stage_root", "")))
    node_executable = Path(str(saved_stage.get("node_executable", "")))
    codegraph_executable = Path(
        str(saved_stage.get("codegraph_executable", ""))
    )
    return bool(
        stage_root.is_absolute()
        and node_executable.is_absolute()
        and codegraph_executable.is_absolute()
        and node_executable.is_relative_to(stage_root)
        and codegraph_executable.is_relative_to(stage_root)
    )


def _require_current_doctor(
    config: dict[str, Any],
    *,
    task2_evidence: dict[str, Any],
    lock: dict[str, Any],
    runtime: dict[str, Any],
    codex: Path,
    codex_version: str,
) -> dict[str, Any]:
    p = paths(config)
    doctor_path = p["enriched_doctor"] / "doctor.json"
    try:
        record = json.loads(doctor_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RunnerError(
            "configuration_error: current passing CodeGraph doctor required"
        ) from exc
    _task, index_record = _load_doctor_preparation(
        config,
        lock,
        runtime,
    )
    expected_runtime = {
        "codex_version": codex_version,
        "codex_executable_sha256": file_sha256(codex),
        "codegraph_source_commit": lock["resolved_commit"],
        "codegraph_executable_sha256": runtime["executable_sha256"],
        "index_identity": index_record["identity"],
        "task2_evidence_root_sha256": sha256_file(
            p["task2_evidence_root"]
        ),
        "task2_evidence_entry_count": task2_evidence["entry_count"],
    }
    saved_runtime = record.get("runtime")
    expected_runtime_stage = _expected_runtime_stage_digests(runtime)
    if (
        record.get("schema_version") != "codegraph-doctor-v1"
        or record.get("passed") is not True
        or not isinstance(saved_runtime, dict)
        or any(
            saved_runtime.get(key) != value
            for key, value in expected_runtime.items()
        )
        or not _runtime_stage_matches(
            saved_runtime.get("runtime_stage"),
            expected_runtime_stage,
        )
        or record.get("return_code") != 0
        or record.get("response_valid") is not True
        or record.get("telemetry", {}).get("valid") is not True
        or record.get("navigation", {}).get("graph_use_valid") is not True
        or record.get("contamination_audit", {}).get("passed") is not True
        or record.get("real_envelope_integration")
        != LIVE_CODEGRAPH_ENVELOPE
    ):
        raise RunnerError(
            "configuration_error: current passing CodeGraph doctor required"
        )
    return record


def _require_sealed_task6_doctor(
    *,
    runtime: dict[str, Any],
    codex: Path,
    codex_version: str,
) -> dict[str, Any]:
    seal_reference = next(
        (
            (relative, digest)
            for task, relative, digest in TASK_SEALED_AUTHORITIES
            if task == 6
        ),
        None,
    )
    if seal_reference is None:
        raise RunnerError(
            "task6_doctor_refused: Task 6 seal authority is missing"
        )
    seal_identity = _repository_file_identity(
        seal_reference[0],
        expected_sha256=seal_reference[1],
    )
    seal = json.loads(
        (ROOT / seal_identity["path"]).read_text(encoding="utf-8")
    )
    if (
        seal.get("schema_version") != "sealed-task-evidence-root-v1"
        or seal.get("task") != 6
        or seal.get("cycle") != 5
        or seal.get("status") != "PASS"
        or seal.get("task6_complete") is not True
        or seal.get("review", {}).get("status") != "PASS"
        or seal.get("review", {}).get("all_criteria_pass") is not True
    ):
        raise RunnerError(
            "task6_doctor_refused: Task 6 seal is not PASS"
        )
    doctor_identity = _repository_file_identity(
        TASK6_LIVE_DOCTOR,
        expected_sha256=TASK6_LIVE_DOCTOR_SHA256,
    )
    doctor = json.loads(
        (ROOT / doctor_identity["path"]).read_text(encoding="utf-8")
    )
    result = doctor.get("result")
    navigation = (
        result.get("navigation")
        if isinstance(result, dict)
        else None
    )
    telemetry = (
        result.get("telemetry")
        if isinstance(result, dict)
        else None
    )
    expected_stage = _expected_runtime_stage_digests(runtime)
    if (
        doctor.get("schema_version") != "task6-live-doctor-v1"
        or doctor.get("passed") is not True
        or doctor.get("response_valid") is not True
        or doctor.get("navigation_replay_exact") is not True
        or doctor.get("unknown_envelope_refused") is not True
        or doctor.get("codex_version") != codex_version
        or doctor.get("codex_executable_sha256")
        != file_sha256(codex)
        or doctor.get("task2_codegraph_executable_sha256")
        != runtime.get("executable_sha256")
        or not _runtime_stage_matches(
            doctor.get("runtime_stage"),
            expected_stage,
        )
        or not isinstance(result, dict)
        or result.get("returncode") != 0
        or result.get("timed_out") is not False
        or result.get("terminated") is not False
        or not isinstance(navigation, dict)
        or navigation.get("graph_use_valid") is not True
        or navigation.get("mcp_server_connected") is not True
        or navigation.get("tool_available") is not True
        or navigation.get("outside_repository_accesses") != []
        or navigation.get("prohibited_benchmark_accesses") != []
        or not isinstance(telemetry, dict)
        or telemetry.get("valid") is not True
        or telemetry.get("provider_turn_valid") is not True
        or doctor.get("contamination_audit", {}).get("passed")
        is not True
    ):
        raise RunnerError(
            "task6_doctor_refused: sealed live doctor differs"
        )
    references: list[dict[str, Any]] = []

    def collect(value: Any) -> None:
        if not isinstance(value, (dict, list)):
            return
        if isinstance(value, list):
            for item in value:
                collect(item)
            return
        if (
            set(("path", "bytes", "sha256")).issubset(value)
            and isinstance(value.get("path"), str)
            and value["path"].startswith(
                ".benchmark-work/codegraph-enriched/"
            )
        ):
            references.append(value)
        for item in value.values():
            collect(item)

    collect(doctor)
    for reference in references:
        identity = _repository_file_identity(reference["path"])
        if (
            identity["bytes"] != reference["bytes"]
            or identity["sha256"] != reference["sha256"]
        ):
            raise RunnerError(
                "task6_doctor_refused: retained artifact differs"
            )
    return {
        "seal": seal_identity,
        "doctor": doctor_identity,
        "retained_reference_count": len(references),
        "passed": True,
    }


def _run_manifest(
    run_id: str,
    config: dict[str, Any],
    tasks: list[dict[str, Any]],
    source_manifest: dict[str, Any],
    lock: dict[str, Any],
    runtime: dict[str, Any],
    index_records: list[dict[str, Any]],
    run_root: Path,
    corpus_payload: bytes,
    sample_count: int,
    treatment_freeze: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evaluator = verify_official_evaluator(paths(config)["evaluator"], paths(config)["provenance"])
    codex = resolve_executable({"paths": {"codex_executable": config["paths"]["codex_executable"]}})
    version = verify_pinned_version(codex, config["treatment"]["codex_version"])
    prompt_sha = sha256_file(paths(config)["prompt"])
    schema_sha = sha256_file(paths(config)["schema"])
    index_artifacts = []
    for record in index_records:
        destination = run_root / "indexes" / f"{record['task_id']}.json"
        write_json(destination, record)
        index_artifacts.append(
            {
                "path": str(destination.relative_to(run_root)),
                "sha256": sha256_file(destination),
            }
        )
    source_lock_destination = run_root / "source-lock.json"
    runtime_destination = run_root / "codegraph-runtime.json"
    task2_root_destination = run_root / "task2-evidence-root.json"
    task4_seal_destination = run_root / "task4-sealed-evidence-root.json"
    task4_all24_destination = run_root / "task4-all24-preparation.json"
    task4_candidate_destination = run_root / "task4-candidate-evidence-root.json"
    shutil.copyfile(paths(config)["source_lock"], source_lock_destination)
    shutil.copyfile(paths(config)["runtime_record"], runtime_destination)
    shutil.copyfile(paths(config)["task2_evidence_root"], task2_root_destination)
    shutil.copyfile(paths(config)["task4_sealed_root"], task4_seal_destination)
    shutil.copyfile(paths(config)["task4_all24"], task4_all24_destination)
    task4_seal = json.loads(
        paths(config)["task4_sealed_root"].read_text(encoding="utf-8")
    )
    task4_candidate_source = ROOT / task4_seal["candidate"][
        "candidate_evidence_root"
    ]["path"]
    shutil.copyfile(task4_candidate_source, task4_candidate_destination)
    manifest = {
        "run_id": run_id,
        "arm": "codex-codegraph-enriched",
        "protocol": "codegraph-region-v1",
        "configuration": {
            "requested_model": config["treatment"]["model"],
            "requested_reasoning_effort": config["treatment"]["reasoning_effort"],
            "codex_version": version,
            "codex_executable_sha256": file_sha256(codex),
            "sample_count": sample_count,
            "retry_cap": config["treatment"]["retry_cap"],
            "timeout_seconds": config["treatment"]["timeout_seconds"],
            "max_regions": config["treatment"]["max_regions"],
            "output_schema_sha256": schema_sha,
            "prompt_sha256": prompt_sha,
            "configuration_sha256": config_digest(config),
            "harness_sha256": _harness_digest(config, lock, runtime, evaluator),
            "filesystem_isolation": "macos-sandbox-exec-codegraph-v2",
            "filesystem_isolation_guarantees": isolation_guarantees(),
            "repository_snapshot": "git-clone-no-local-plus-detached-worktree-v1",
        },
        "corpus": {
            "source_row_count": source_manifest["source_row_count"],
            "unique_task_count": len(tasks),
            "tasks": [portable_task(task) for task in tasks],
            "artifact": {
                "path": "corpus.jsonl",
                "bytes": len(corpus_payload),
                "sha256": sha256_bytes(corpus_payload),
            },
            "task_identity_sha256": sha256_bytes(
                (
                    json.dumps(
                        [
                            {"instance_id": task["instance_id"], "base_commit": task["base_commit"]}
                            for task in sorted(tasks, key=lambda row: row["instance_id"])
                        ],
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode()
            ),
            "source_manifest_sha256": sha256_value(source_manifest),
        },
        "evaluator": evaluator,
        "codegraph": {
            "repository_url": lock["repository_url"],
            "source_commit": lock["resolved_commit"],
            "declared_version": lock["declared_version"],
            "executable_sha256": runtime["executable_sha256"],
            "source_lock": str(source_lock_destination.relative_to(run_root)),
            "runtime_record": str(runtime_destination.relative_to(run_root)),
            "source_lock_sha256": sha256_file(source_lock_destination),
            "runtime_record_sha256": sha256_file(runtime_destination),
            "task2_evidence_root": str(task2_root_destination.relative_to(run_root)),
            "task2_evidence_root_sha256": sha256_file(task2_root_destination),
            "enrichment_authority": {
                "task4_sealed_root": str(
                    task4_seal_destination.relative_to(run_root)
                ),
                "task4_sealed_root_sha256": sha256_file(
                    task4_seal_destination
                ),
                "task4_candidate_root": str(
                    task4_candidate_destination.relative_to(run_root)
                ),
                "task4_candidate_root_sha256": sha256_file(
                    task4_candidate_destination
                ),
                "task4_all24": str(
                    task4_all24_destination.relative_to(run_root)
                ),
                "task4_all24_sha256": sha256_file(
                    task4_all24_destination
                ),
                "authority_sha256": authority_digest(
                    _require_task4_authority(config, runtime=runtime)
                ),
                "index_count": len(index_records),
            },
            "telemetry_disabled": True,
            "self_update_disabled": True,
            "shared_daemon": False,
            "mcp_network_isolation": runtime["mcp_network_isolation"],
        },
        "indexes": {"record_count": len(index_records), "records": index_artifacts, "immutable_reuse": True},
        "cost": {"status": "unavailable", "pricing_profile": None},
        "treatment_differences": [
            "CodeGraph-use prompt addition",
            "pinned immutable CodeGraph index",
            "per-attempt CodeGraph MCP server",
        ],
    }
    if treatment_freeze is not None:
        treatment_freeze_destination = (
            run_root / "treatment-freeze.json"
        )
        shutil.copyfile(
            _task7_treatment_freeze_path(),
            treatment_freeze_destination,
        )
        os.chmod(treatment_freeze_destination, 0o400)
        manifest["treatment_freeze"] = {
            "path": "treatment-freeze.json",
            "sha256": sha256_file(treatment_freeze_destination),
            "treatment_sha256": treatment_freeze[
                "treatment_sha256"
            ],
        }
    return manifest


def _retain_setup_failure(
    run_root: Path,
    run_id: str,
    error: Exception,
) -> dict[str, Any]:
    failure_path = run_root / "setup-failure.json"
    if failure_path.exists() or failure_path.is_symlink():
        raise RunnerError(
            "configuration_error: setup failure evidence already exists"
        )
    artifacts = []
    for path in sorted(run_root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(run_root).as_posix()
        artifacts.append(
            {
                "path": relative,
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    record = {
        "schema_version": "codegraph-run-setup-failure-v1",
        "run_id": run_id,
        "failure_class": _attempt_exception_class(error),
        "error": str(error),
        "provider_launch_reached": False,
        "retained_at": datetime.now(timezone.utc).isoformat(),
        "partial_artifacts": artifacts,
    }
    write_json(failure_path, record)
    return record


def _validate_run_dimensions(tasks: list[dict[str, Any]], sample_count: int, *, smoke: bool) -> None:
    unique_ids = {task.get("instance_id") for task in tasks}
    if smoke:
        if len(tasks) != 1 or len(unique_ids) != 1 or sample_count != 1:
            raise RunnerError("configuration_error: smoke requires exactly 1 unique task x 1 sample")
    elif len(tasks) != 24 or len(unique_ids) != 24 or sample_count != 3:
        raise RunnerError("configuration_error: full run requires exactly 24 unique tasks x 3 samples")


def _corpus_payload(tasks: list[dict[str, Any]]) -> bytes:
    return "".join(
        json.dumps(
            {key: value for key, value in task.items() if key != "prepared"},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
        for task in tasks
    ).encode()


def _write_corpus(run_root: Path, payload: bytes) -> None:
    (run_root / "corpus.jsonl").write_bytes(payload)
    os.chmod(run_root / "corpus.jsonl", 0o600)


def _smoke_gate_path(config: dict[str, Any]) -> Path:
    return paths(config)["enriched_doctor"].parent / "smoke-gate.json"


def _smoke_inspection_path(run_root: Path) -> Path:
    return run_root / "inspection-manifest.json"


def _inspection_file_identity(
    run_root: Path,
    relative_value: str,
) -> dict[str, Any]:
    if (
        not isinstance(relative_value, str)
        or not relative_value
        or relative_value.startswith("/")
        or relative_value.endswith("/")
        or "\\" in relative_value
        or "%" in relative_value
        or any(part in {"", ".", ".."} for part in relative_value.split("/"))
    ):
        raise RunnerError(
            "smoke_inspection_refused: artifact path is not canonical"
        )
    relative = Path(relative_value)
    if relative.is_absolute() or relative.as_posix() != relative_value:
        raise RunnerError(
            "smoke_inspection_refused: artifact path is not canonical"
        )
    candidate = run_root / relative
    current = run_root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise RunnerError(
                "smoke_inspection_refused: symlinked artifact path"
            )
    resolved_root = run_root.resolve()
    resolved = candidate.resolve(strict=False)
    if (
        resolved == resolved_root
        or resolved_root not in resolved.parents
        or not candidate.is_file()
    ):
        raise RunnerError(
            "smoke_inspection_refused: artifact is missing or escapes run"
        )
    return {
        "path": relative_value,
        "bytes": candidate.stat().st_size,
        "sha256": sha256_file(candidate),
    }


def _build_smoke_inspection_manifest(
    run_root: Path,
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    relative_paths = {
        "run-manifest.json",
        "corpus.jsonl",
        manifest["codegraph"]["source_lock"],
        manifest["codegraph"]["runtime_record"],
        manifest["codegraph"]["task2_evidence_root"],
        "attempts.jsonl",
        "valid-samples.jsonl",
        "diagnostic-scores.jsonl",
        "aggregate.json",
        "report.md",
    }
    treatment_freeze = manifest.get("treatment_freeze")
    if isinstance(treatment_freeze, dict) and isinstance(
        treatment_freeze.get("path"),
        str,
    ):
        relative_paths.add(treatment_freeze["path"])
    relative_paths.update(
        reference["path"] for reference in manifest["indexes"]["records"]
    )
    for record in records:
        relative_paths.update(
            value
            for key, value in record["artifacts"].items()
            if key != "attempt" and isinstance(value, str)
        )
        attempt_root = record["artifacts"]["attempt"]
        relative_paths.add(f"{attempt_root}/attempt.json")
        if isinstance(record.get("score_artifact"), str):
            relative_paths.add(record["score_artifact"])
    identities = [
        _inspection_file_identity(run_root, relative)
        for relative in sorted(relative_paths)
    ]
    return {
        "schema_version": "codegraph-smoke-inspection-v1",
        "run_id": manifest["run_id"],
        "artifact_count": len(identities),
        "artifacts": identities,
        "inspection_scope": (
            "run inputs, source/runtime/index provenance, raw events, stderr, "
            "response, scoring source, lifecycle, official score, aggregate, "
            "and report"
        ),
    }


def _prepare_smoke_inspection(
    config: dict[str, Any],
    run_root: Path,
    manifest: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    records = score_run(
        run_root,
        paths(config)["evaluator"],
        paths(config)["provenance"],
    )
    report = rebuild_report(
        run_root,
        paths(config)["evaluator"],
        paths(config)["provenance"],
    )
    inspection = _build_smoke_inspection_manifest(
        run_root,
        manifest,
        records,
    )
    return records, report, inspection


def create_smoke_inspection(args: argparse.Namespace) -> dict[str, Any]:
    config = load_config()
    _require_task2_evidence(config)
    run_root = resolve_run_root(ROOT, args.run_id, smoke=True)
    manifest = load_treatment_manifest(
        run_root,
        expected_run_id=args.run_id,
    )
    verify_corpus_contract(run_root, manifest)
    verify_bound_run_artifacts(run_root, manifest)
    frozen = _require_run_treatment_freeze(
        config,
        run_root,
        manifest,
    )
    _validate_frozen_smoke_manifest(
        frozen,
        args.run_id,
        manifest,
    )
    records, report, inspection = _prepare_smoke_inspection(
        config,
        run_root,
        manifest,
    )
    adopted = [record for record in records if claimable_sample(record)]
    if report.get("claimable") is not True or len(adopted) != 1:
        raise RunnerError(
            "smoke_inspection_refused: smoke is not officially claimable"
        )
    inspection_path = _smoke_inspection_path(run_root)
    write_json(inspection_path, inspection)
    result = {
        "run_id": args.run_id,
        "inspection_manifest": str(inspection_path),
        "inspection_manifest_sha256": sha256_file(inspection_path),
        "artifact_count": inspection["artifact_count"],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def _current_gate_binding(
    config: dict[str, Any],
    lock: dict[str, Any],
    runtime: dict[str, Any],
    task: dict[str, Any],
) -> dict[str, Any]:
    evaluator = verify_official_evaluator(paths(config)["evaluator"], paths(config)["provenance"])
    codex = resolve_executable({"paths": {"codex_executable": config["paths"]["codex_executable"]}})
    index_record = _load_index(config, task, lock, runtime)
    return {
        "configuration_sha256": config_digest(config),
        "harness_sha256": _harness_digest(config, lock, runtime, evaluator),
        "source_lock_sha256": sha256_file(paths(config)["source_lock"]),
        "runtime_record_sha256": sha256_file(paths(config)["runtime_record"]),
        "task2_evidence_root_sha256": sha256_file(
            paths(config)["task2_evidence_root"]
        ),
        "codegraph_source_commit": lock["resolved_commit"],
        "codegraph_executable_sha256": runtime["executable_sha256"],
        "mcp_network_isolation": runtime["mcp_network_isolation"],
        "codex_version": verify_pinned_version(codex, config["treatment"]["codex_version"]),
        "codex_executable_sha256": file_sha256(codex),
        "evaluator_commit": evaluator["commit"],
        "evaluator_sha256": evaluator["sha256"],
        "output_schema_sha256": sha256_file(paths(config)["schema"]),
        "index_identity_sha256": index_record["identity"]["identity_sha256"],
        "index_artifact_manifest_sha256": index_record["index_artifact_manifest"]["sha256"],
        "real_task": {"instance_id": task["instance_id"], "base_commit": task["base_commit"]},
    }


def create_smoke_gate(args: argparse.Namespace) -> dict[str, Any]:
    if args.ack_manual_inspection is not True:
        raise RunnerError("smoke_gate_refused: --ack-manual-inspection is required")
    if (
        not isinstance(args.inspected_manifest_sha256, str)
        or len(args.inspected_manifest_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in args.inspected_manifest_sha256
        )
    ):
        raise RunnerError(
            "smoke_gate_refused: --inspected-manifest-sha256 is required"
        )
    config = load_config()
    _require_task2_evidence(config)
    run_root = resolve_run_root(ROOT, args.run_id, smoke=True)
    manifest = load_treatment_manifest(run_root, expected_run_id=args.run_id)
    verify_corpus_contract(run_root, manifest)
    verify_bound_run_artifacts(run_root, manifest)
    frozen = _require_run_treatment_freeze(
        config,
        run_root,
        manifest,
    )
    task = _validate_frozen_smoke_manifest(
        frozen,
        args.run_id,
        manifest,
    )
    if manifest["configuration"]["sample_count"] != 1 or len(manifest["corpus"]["tasks"]) != 1:
        raise RunnerError("smoke_gate_refused: smoke must contain exactly one real task and one declared sample")
    records, report, current_inspection = _prepare_smoke_inspection(
        config,
        run_root,
        manifest,
    )
    inspection_path = _smoke_inspection_path(run_root)
    if not inspection_path.is_file() or inspection_path.is_symlink():
        raise RunnerError(
            "smoke_gate_refused: generate and inspect the smoke manifest first"
        )
    try:
        inspected = json.loads(inspection_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RunnerError(
            "smoke_gate_refused: inspection manifest is unreadable"
        ) from exc
    inspection_sha256 = sha256_file(inspection_path)
    if (
        inspected != current_inspection
        or inspection_sha256 != args.inspected_manifest_sha256
    ):
        raise RunnerError(
            "smoke_gate_refused: inspected artifact manifest differs"
        )
    validate_attempt_records(
        records,
        run_id=args.run_id,
        task_ids={task["instance_id"]},
        required_samples=1,
        run_root=run_root,
        manifest=manifest,
    )
    adopted = [record for record in records if claimable_sample(record)]
    if report.get("claimable") is not True or len(adopted) != 1 or adopted[0].get("sample_id") != 1:
        raise RunnerError("smoke_gate_refused: official scoring or sample-slot validity is incomplete")
    record = adopted[0]
    required_validity = ("execution", "response", "provenance", "index", "mcp", "graph_use", "contamination", "telemetry", "scoring")
    if not all(record.get("validity", {}).get(field) is True for field in required_validity):
        raise RunnerError("smoke_gate_refused: graph, telemetry, contamination, or provenance validity is incomplete")
    lock, runtime = _load_runtime(config)
    binding = _current_gate_binding(config, lock, runtime, task)
    gate = {
        "schema_version": "codegraph-smoke-gate-v2",
        "passed": True,
        "smoke_run_id": args.run_id,
        "treatment_freeze": {
            "sha256": sha256_file(
                _task7_treatment_freeze_path()
            ),
            "treatment_sha256": frozen["treatment_sha256"],
        },
        "binding": binding,
        "inspection_manifest": str(inspection_path.relative_to(run_root)),
        "inspection_manifest_sha256": inspection_sha256,
        "inspection_artifact_count": current_inspection["artifact_count"],
        "navigation": {
            "graph_use_valid": record["validity"]["graph_use"],
            "successful_tool_call_count": record.get("navigation", {}).get("successful_tool_call_count"),
        },
        "manual_inspection": {
            "acknowledged": True,
            "scope": "raw events, response, source/index/tool provenance, official score, telemetry, and contamination",
        },
    }
    write_json(_smoke_gate_path(config), gate)
    print(json.dumps(gate, indent=2, sort_keys=True))
    return gate


def _require_smoke_gate(
    config: dict[str, Any],
    lock: dict[str, Any],
    runtime: dict[str, Any],
    tasks: list[dict[str, Any]],
    full_run_id: str,
) -> dict[str, Any]:
    gate_path = _smoke_gate_path(config)
    if not gate_path.is_file():
        raise RunnerError("smoke_gate_required: a manually acknowledged real-task smoke gate is missing")
    gate = json.loads(gate_path.read_text(encoding="utf-8"))
    if gate.get("schema_version") != "codegraph-smoke-gate-v2" or gate.get("passed") is not True:
        raise RunnerError("smoke_gate_required: smoke gate schema/status differs")
    smoke_run_id = gate.get("smoke_run_id")
    validate_run_id(smoke_run_id, smoke=True)
    if smoke_run_id == full_run_id:
        raise RunnerError("smoke_gate_required: smoke and full run IDs must be distinct")
    if gate.get("manual_inspection", {}).get("acknowledged") is not True:
        raise RunnerError("smoke_gate_required: manual inspection was not acknowledged")
    gate_binding = gate.get("binding")
    if (
        not isinstance(gate_binding, dict)
        or "harness_sha256" not in gate_binding
        or not isinstance(gate_binding.get("real_task"), dict)
    ):
        raise RunnerError(
            "smoke_gate_required: smoke binding differs from current "
            "harness/runtime/task"
        )
    smoke_root = resolve_run_root(ROOT, smoke_run_id, smoke=True)
    smoke_manifest = load_treatment_manifest(smoke_root, expected_run_id=smoke_run_id)
    verify_corpus_contract(smoke_root, smoke_manifest)
    verify_bound_run_artifacts(smoke_root, smoke_manifest)
    frozen = _require_run_treatment_freeze(
        config,
        smoke_root,
        smoke_manifest,
    )
    smoke_task = _validate_frozen_smoke_manifest(
        frozen,
        smoke_run_id,
        smoke_manifest,
    )
    selected_task = _select_predeclared_smoke_task(
        tasks,
        frozen,
        smoke_run_id,
    )
    if (
        selected_task.get("instance_id")
        != smoke_task.get("instance_id")
        or selected_task.get("base_commit")
        != smoke_task.get("base_commit")
    ):
        raise RunnerError(
            "smoke_gate_required: frozen smoke task differs from corpus"
        )
    expected = _current_gate_binding(
        config,
        lock,
        runtime,
        smoke_task,
    )
    if gate.get("binding") != expected:
        raise RunnerError(
            "smoke_gate_required: smoke binding differs from current "
            "harness/runtime/task"
        )
    if gate.get("treatment_freeze") != {
        "sha256": sha256_file(_task7_treatment_freeze_path()),
        "treatment_sha256": frozen["treatment_sha256"],
    }:
        raise RunnerError(
            "smoke_gate_required: treatment freeze differs"
        )
    smoke_records = load_jsonl(smoke_root / "attempts.jsonl")
    smoke_task_id = expected["real_task"]["instance_id"]
    validate_attempt_records(
        smoke_records,
        run_id=smoke_run_id,
        task_ids={smoke_task_id},
        required_samples=1,
        run_root=smoke_root,
        manifest=smoke_manifest,
    )
    adopted = [record for record in smoke_records if claimable_sample(record)]
    if len(adopted) != 1:
        raise RunnerError("smoke_gate_required: smoke no longer has one adopted claimable sample")
    record = adopted[0]
    current_inspection = _build_smoke_inspection_manifest(
        smoke_root,
        smoke_manifest,
        smoke_records,
    )
    inspection_relative = gate.get("inspection_manifest")
    if inspection_relative != "inspection-manifest.json":
        raise RunnerError(
            "smoke_gate_required: inspection manifest path differs"
        )
    inspection_path = smoke_root / inspection_relative
    try:
        inspected = json.loads(inspection_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RunnerError(
            "smoke_gate_required: inspection manifest is unreadable"
        ) from exc
    if (
        inspection_path.is_symlink()
        or inspected != current_inspection
        or sha256_file(inspection_path)
        != gate.get("inspection_manifest_sha256")
        or current_inspection["artifact_count"]
        != gate.get("inspection_artifact_count")
    ):
        raise RunnerError(
            "smoke_gate_required: inspected smoke artifact identities differ"
        )
    score_path = smoke_root / record.get("score_artifact", "")
    if not score_path.is_file() or sha256_file(score_path) != record.get(
        "score_sha256"
    ):
        raise RunnerError("smoke_gate_required: official smoke score artifact differs")
    return gate


def _attempt_exception_class(error: Exception) -> str:
    if isinstance(error, CodeGraphError):
        return error.failure_class
    if isinstance(error, RunnerError):
        prefix = str(error).partition(":")[0]
        if (
            prefix
            and all(
                character.islower()
                or character.isdigit()
                or character == "_"
                for character in prefix
            )
        ):
            return prefix
    if isinstance(error, (OSError, subprocess.SubprocessError)):
        return "process_spawn_failure"
    return "attempt_preparation_failure"


def _retained_failure_result(
    state: Path,
    error: Exception,
    *,
    started: float,
) -> dict[str, Any]:
    state.mkdir(parents=True, exist_ok=True)
    events_path = state / "events.jsonl"
    stderr_path = state / "stderr.log"
    events_path.touch(exist_ok=True)
    prior = (
        stderr_path.read_text(encoding="utf-8", errors="replace")
        if stderr_path.is_file()
        else ""
    )
    failure_class = _attempt_exception_class(error)
    stderr_path.write_text(
        prior
        + (
            "\n" if prior and not prior.endswith("\n") else ""
        )
        + f"{failure_class}: {error}\n",
        encoding="utf-8",
    )
    os.chmod(events_path, 0o600)
    os.chmod(stderr_path, 0o600)
    return {
        "returncode": None,
        "timed_out": False,
        "terminated": False,
        "signal_number": None,
        "signal_name": None,
        "elapsed_seconds": time.monotonic() - started,
        "response": None,
        "response_error": str(error),
        "telemetry": {
            "valid": False,
            "provider_turn_valid": False,
            "failure_class": failure_class,
            "usage": {},
        },
        "navigation": {
            "graph_use_valid": False,
            "mcp_server_connected": False,
            "tool_available": False,
            "failure_class": failure_class,
            "outside_repository_accesses": [],
            "prohibited_benchmark_accesses": [],
        },
        "failure_class": failure_class,
        "state_dir": str(state),
        "events_path": str(events_path),
        "stderr_path": str(stderr_path),
        "launched_argument_vector": [],
    }


def _stage_attempt_result(
    result: dict[str, Any],
    destination_state: Path,
) -> dict[str, Any]:
    destination_state.mkdir(parents=True, exist_ok=True)
    staged = dict(result)
    for key, filename in (
        ("events_path", "events.jsonl"),
        ("stderr_path", "stderr.log"),
    ):
        source = Path(result[key])
        destination = destination_state / filename
        if source.resolve() != destination.resolve():
            if source.is_file():
                shutil.copyfile(source, destination)
            else:
                destination.write_bytes(b"")
        elif not destination.exists():
            destination.write_bytes(b"")
        os.chmod(destination, 0o600)
        staged[key] = str(destination)
    source_response = Path(result["state_dir"]) / "response.json"
    destination_response = destination_state / "response.json"
    if (
        source_response.is_file()
        and source_response.resolve() != destination_response.resolve()
    ):
        shutil.copyfile(source_response, destination_response)
        os.chmod(destination_response, 0o600)
    staged["state_dir"] = str(destination_state)
    return staged


def run(args: argparse.Namespace, *, smoke: bool = False) -> dict[str, Any]:
    config = load_config()
    freeze_path = _task7_treatment_freeze_path()
    if freeze_path.is_symlink():
        raise TreatmentFreezeError(
            "treatment_freeze_refused: freeze path is a symlink"
        )
    if not freeze_path.is_file():
        raise TreatmentFreezeError(
            "treatment_freeze_refused: freeze is missing"
        )
    task2_evidence = _require_task2_evidence(config)
    p = paths(config)
    all_tasks, source_manifest = load_tasks(config)
    samples = 1 if smoke else int(config["treatment"]["sample_count"])
    if REAL_ENVELOPE_INTEGRATION != LIVE_CODEGRAPH_ENVELOPE:
        raise RunnerError("task1_integration_pending: capture and fixture-test the real Codex 0.145.0 MCP envelope in Task 3")
    run_id = args.run_id or time.strftime(
        "codex-codegraph-enriched-smoke-%Y%m%dT%H%M%SZ" if smoke else "codex-codegraph-enriched-%Y%m%dT%H%M%SZ",
        time.gmtime(),
    )
    run_root = resolve_run_root(ROOT, run_id, smoke=smoke)
    lock, runtime = _load_runtime(config)
    all_indexes = [
        _load_index(config, task, lock, runtime)
        for task in all_tasks
    ]
    treatment_freeze = _load_task7_treatment_freeze(
        config,
        all_tasks,
        source_manifest,
        lock,
        runtime,
        all_indexes,
    )
    if smoke:
        tasks = [
            _select_predeclared_smoke_task(
                all_tasks,
                treatment_freeze,
                run_id,
            )
        ]
    else:
        tasks = all_tasks
    index_by_task = {
        record["task_id"]: record
        for record in all_indexes
    }
    indexes = [
        index_by_task[task["instance_id"]]
        for task in tasks
    ]
    _validate_run_dimensions(tasks, samples, smoke=smoke)
    if not smoke:
        _require_smoke_gate(config, lock, runtime, tasks, run_id)
    codex = resolve_executable({"paths": {"codex_executable": config["paths"]["codex_executable"]}})
    codex_version = verify_pinned_version(
        codex,
        config["treatment"]["codex_version"],
    )
    validate_auth_source(p["auth"])
    run_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    manifest_path = run_root / "run-manifest.json"
    if manifest_path.is_file():
        manifest = load_treatment_manifest(run_root, expected_run_id=run_id)
        verify_corpus_contract(run_root, manifest)
        verify_bound_run_artifacts(run_root, manifest)
        _validate_run_treatment_freeze(
            run_root,
            manifest,
            freeze_path,
            treatment_freeze,
        )
        evaluator = verify_official_evaluator(p["evaluator"], p["provenance"])
        expected_tasks = [portable_task(task) for task in tasks]
        resume_checks = {
            "configuration_sha256": (
                manifest.get("configuration", {}).get("configuration_sha256"),
                config_digest(config),
            ),
            "harness_sha256": (
                manifest.get("configuration", {}).get("harness_sha256"),
                _harness_digest(config, lock, runtime, evaluator),
            ),
            "codegraph_source_commit": (
                manifest.get("codegraph", {}).get("source_commit"),
                lock["resolved_commit"],
            ),
            "codegraph_executable_sha256": (
                manifest.get("codegraph", {}).get("executable_sha256"),
                runtime["executable_sha256"],
            ),
            "tasks": (manifest.get("corpus", {}).get("tasks"), expected_tasks),
        }
        for field, operands in resume_checks.items():
            if operands[0] != operands[1]:
                raise RunnerError(f"configuration_error: refusing to resume with different {field}")
    else:
        if any(run_root.iterdir()):
            raise RunnerError("configuration_error: refusing non-empty run directory without a manifest")
        try:
            corpus_payload = _corpus_payload(tasks)
            manifest = _run_manifest(
                run_id,
                config,
                tasks,
                source_manifest,
                lock,
                runtime,
                indexes,
                run_root,
                corpus_payload,
                samples,
                treatment_freeze,
            )
            validate_run_manifest(manifest, expected_run_id=run_id)
            _write_corpus(run_root, corpus_payload)
            write_json(manifest_path, manifest)
            _validate_run_treatment_freeze(
                run_root,
                manifest,
                freeze_path,
                treatment_freeze,
            )
        except Exception as error:
            _retain_setup_failure(run_root, run_id, error)
            raise
    existing = load_jsonl(run_root / "attempts.jsonl")
    validate_attempt_records(
        existing,
        run_id=run_id,
        task_ids={task["instance_id"] for task in tasks},
        required_samples=samples,
        run_root=run_root,
        manifest=manifest,
    )
    isolation_root = Path(tempfile.mkdtemp(prefix=f"context-graph-{run_id}-", dir="/private/tmp"))
    prompt_template = p["prompt"].read_text(encoding="utf-8")
    index_by_task = {
        record["task_id"]: record
        for record in indexes
    }
    try:
        for task in tasks:
            repository = Path(task["prepared"]["resolved_path"])
            index_record = index_by_task[task["instance_id"]]
            for sample_id in range(1, samples + 1):
                slot = sample_slot(existing, task["instance_id"], sample_id, int(config["treatment"]["retry_cap"]))
                if slot["satisfied"]:
                    continue
                if slot["retry_cap_exhausted"]:
                    raise RunnerError(f"retry_cap: {task['instance_id']} sample {sample_id}")
                attempt_number = int(slot["next_attempt_number"])
                started = time.monotonic()
                attempt_isolation_root = (
                    isolation_root
                    / "attempts"
                    / task["instance_id"]
                    / f"sample-{sample_id:02d}"
                    / f"attempt-{attempt_number:03d}"
                )
                inflight_root = (
                    run_root
                    / ".inflight"
                    / task["instance_id"]
                    / f"sample-{sample_id:02d}"
                    / f"attempt-{attempt_number:03d}"
                )
                state = inflight_root / "state"
                state.mkdir(parents=True, mode=0o700)
                private_home: Path | None = None
                snapshot: dict[str, Any] | None = None
                child_repo = repository
                lifecycle_evidence_root = (
                    ROOT
                    / ".benchmark-work"
                    / "codegraph"
                    / "attempt-lifecycle"
                    / run_id
                    / task["instance_id"]
                    / f"sample-{sample_id:02d}-attempt-{attempt_number:03d}"
                )
                lifecycle_path = lifecycle_evidence_root / "lifecycle.json"
                prompt: str | None = None
                command: list[str] = []
                metadata = {
                    "run_id": run_id,
                    "repository_url": task["repository_url"],
                    "repository_path": str(repository),
                    "child_repository_path": str(repository),
                    "requested_base_commit": task["base_commit"],
                    "verified_head": None,
                    "source_corpus_membership": task["source_memberships"],
                    "prompt_sha256": None,
                    "prompt_template_sha256": sha256_file(p["prompt"]),
                    "output_schema_sha256": sha256_file(p["schema"]),
                    "requested_model": config["treatment"]["model"],
                    "requested_reasoning_effort": config["treatment"][
                        "reasoning_effort"
                    ],
                    "codex_version": config["treatment"]["codex_version"],
                    "codex_executable_sha256": file_sha256(codex),
                    "max_regions": config["treatment"]["max_regions"],
                    "timeout_seconds": config["treatment"][
                        "timeout_seconds"
                    ],
                    "configuration_sha256": config_digest(config),
                    "harness_sha256": manifest["configuration"][
                        "harness_sha256"
                    ],
                    "evaluator_commit": manifest["evaluator"]["commit"],
                    "evaluator_sha256": manifest["evaluator"]["sha256"],
                    "runtime_provenance": manifest["codegraph"],
                    "index_identity": index_record["identity"],
                    "index_record_sha256": sha256_value(index_record),
                    "index_valid": False,
                    "task2_evidence_root_sha256": sha256_file(
                        p["task2_evidence_root"]
                    ),
                    "task2_evidence_entry_count": task2_evidence[
                        "entry_count"
                    ],
                    "runtime_stage": None,
                    "git_provenance": {
                        "neutralized": False,
                        "failure_stage": "before_repository_snapshot",
                    },
                    "contamination_audit": {
                        "passed": False,
                        "forbidden_hits": [],
                    },
                    "filesystem_isolation": (
                        "macos-sandbox-exec-codegraph-v2"
                    ),
                    "filesystem_isolation_guarantees": (
                        isolation_guarantees()
                    ),
                    "exact_argument_vector": [],
                }
                try:
                    attempt_repositories = _validate_attempt_repositories(
                        config,
                        task,
                        index_record,
                        lock,
                        runtime,
                    )
                    metadata["verified_head"] = task["base_commit"]
                    snapshot = prepare_isolated_repository(
                        repository,
                        task["base_commit"],
                        isolation_root,
                        task["instance_id"],
                        (
                            f"sample-{sample_id}-attempt-"
                            f"{attempt_number}"
                        ),
                    )
                    child_repo = Path(snapshot["path"])
                    metadata["child_repository_path"] = str(child_repo)
                    metadata["git_provenance"] = (
                        neutralize_git_provenance(snapshot)
                    )
                    runtime_stage = stage_runtime_bundle(
                        runtime=runtime,
                        checkout=p["source_checkout"],
                        stage_root=(
                            attempt_isolation_root
                            / "staged-codegraph-runtime"
                        ),
                    )
                    metadata["runtime_stage"] = runtime_stage
                    private_home, state = fresh_runtime_dirs(
                        isolation_root
                        / "runtime"
                        / task["instance_id"]
                        / (
                            f"sample-{sample_id}-attempt-"
                            f"{attempt_number}"
                        ),
                        p["auth"],
                    )
                    shutil.copyfile(
                        p["schema"],
                        state / "agent-regions.schema.json",
                    )
                    prompt = build_treatment_prompt(
                        prompt_template,
                        task["issue_text"],
                    )
                    metadata["prompt_sha256"] = hashlib.sha256(
                        prompt.encode()
                    ).hexdigest()
                    with attempt_index_copy(
                        record=index_record,
                        lock=lock,
                        master_repository=attempt_repositories[
                            "index_master_repository"
                        ],
                        child_repository=child_repo,
                        attempt_root=attempt_isolation_root / "index-copy",
                        evidence_root=lifecycle_evidence_root,
                        runtime_stage=runtime_stage,
                    ) as index_binding:
                        mcp_environment = {
                            key: value
                            for key, value in index_binding["environment"].items()
                            if key.startswith("CODEGRAPH_") or key == "DO_NOT_TRACK"
                        }
                        command = build_codegraph_command(
                            codex,
                            config,
                            state,
                            p["schema"],
                            child_repo,
                            codegraph_launcher=index_binding["launcher"],
                            serve_args=index_binding["serve_args"],
                            mcp_environment=mcp_environment,
                        )
                        result = run_codegraph_child(
                            command,
                            prompt,
                            state_dir=state,
                            events_path=state / "events.jsonl",
                            stderr_path=state / "stderr.log",
                            timeout_seconds=float(config["treatment"]["timeout_seconds"]),
                            environment=child_environment(codex, mcp_environment),
                            repository=child_repo,
                            codex_home=private_home,
                            mcp_roots=[
                                Path(runtime_stage["stage_root"]),
                                Path(index_binding["index_path"]),
                            ],
                            forbidden_paths=[
                                *_forbidden_paths(config),
                                lifecycle_evidence_root,
                            ],
                            expected_project=child_repo,
                            writable_index_root=Path(index_binding["index_path"]),
                            mcp_server_command=[
                                *index_binding["launcher"],
                                *index_binding["serve_args"],
                            ],
                            mcp_environment=mcp_environment,
                        )
                        actual_serve_args = list(index_binding["serve_args"])
                    lifecycle = json.loads(lifecycle_path.read_text(encoding="utf-8"))
                    lifecycle_valid = bool(
                        lifecycle.get("prepared")
                        and lifecycle.get("cleanup_complete")
                        and lifecycle.get("master_unchanged")
                    )
                    raw = (state / "events.jsonl").read_text(encoding="utf-8", errors="replace")
                    contamination = audit_events(raw, _forbidden_paths(config))
                    metadata.update(
                        {
                        "index_valid": lifecycle_valid,
                        "index_lifecycle_path": str(lifecycle_path),
                        "mcp_command": {
                            "executable_sha256": runtime["executable_sha256"],
                            "launcher": index_binding["launcher"],
                            "serve_args": actual_serve_args,
                            "codegraph_directory_name": lifecycle[
                                "codegraph_directory_name"
                            ],
                        },
                        "task2_evidence_root_sha256": sha256_file(
                            p["task2_evidence_root"]
                        ),
                        "task2_evidence_entry_count": task2_evidence["entry_count"],
                        "runtime_stage": runtime_stage,
                        "git_provenance": metadata["git_provenance"],
                        "contamination_audit": contamination,
                        "exact_argument_vector": result.get("launched_argument_vector", command),
                        }
                    )
                except Exception as error:
                    if lifecycle_path.is_file():
                        metadata["index_lifecycle_path"] = str(
                            lifecycle_path
                        )
                        try:
                            lifecycle = json.loads(
                                lifecycle_path.read_text(encoding="utf-8")
                            )
                            metadata["index_valid"] = bool(
                                lifecycle.get("prepared")
                                and lifecycle.get("cleanup_complete")
                                and lifecycle.get("master_unchanged")
                            )
                        except (OSError, json.JSONDecodeError):
                            metadata["index_valid"] = False
                    result = _retained_failure_result(
                        state,
                        error,
                        started=started,
                    )
                    raw = Path(result["events_path"]).read_text(
                        encoding="utf-8",
                        errors="replace",
                    )
                    metadata["contamination_audit"] = audit_events(
                        raw,
                        _forbidden_paths(config),
                    )
                result = _stage_attempt_result(
                    result,
                    inflight_root / "state",
                )
                persisted = False
                try:
                    record = persist_attempt(run_root, task, sample_id, attempt_number, result, metadata)
                    existing.append(record)
                    persisted = True
                finally:
                    if private_home is not None:
                        shutil.rmtree(private_home, ignore_errors=True)
                    if (
                        persisted
                        or inflight_root.resolve()
                        not in state.resolve().parents
                    ):
                        shutil.rmtree(state, ignore_errors=True)
                    if snapshot is not None:
                        remove_isolated_repository(snapshot)
                    if persisted:
                        shutil.rmtree(inflight_root, ignore_errors=True)
    finally:
        shutil.rmtree(isolation_root, ignore_errors=True)
        inflight = run_root / ".inflight"
        if inflight.is_dir() and not any(
            path.is_file() for path in inflight.rglob("*")
        ):
            shutil.rmtree(inflight, ignore_errors=True)
    result = {"run_id": run_id, "attempt_count": len(existing), "run_root": str(run_root)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def score(args: argparse.Namespace) -> dict[str, Any]:
    config = load_config()
    run_root = resolve_run_root(ROOT, args.run_id)
    _require_task2_evidence(config)
    manifest = load_treatment_manifest(
        run_root,
        expected_run_id=args.run_id,
    )
    verify_corpus_contract(run_root, manifest)
    verify_bound_run_artifacts(run_root, manifest)
    frozen = _require_run_treatment_freeze(
        config,
        run_root,
        manifest,
    )
    if args.run_id.startswith(
        "codex-codegraph-enriched-smoke-"
    ):
        _validate_frozen_smoke_manifest(
            frozen,
            args.run_id,
            manifest,
        )
    records = score_run(run_root, paths(config)["evaluator"], paths(config)["provenance"])
    result = {"run_id": args.run_id, "scored": sum(1 for record in records if record.get("score_valid"))}
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def report(args: argparse.Namespace) -> dict[str, Any]:
    config = load_config()
    run_root = resolve_run_root(ROOT, args.run_id)
    _require_task2_evidence(config)
    manifest = load_treatment_manifest(
        run_root,
        expected_run_id=args.run_id,
    )
    verify_corpus_contract(run_root, manifest)
    verify_bound_run_artifacts(run_root, manifest)
    frozen = _require_run_treatment_freeze(
        config,
        run_root,
        manifest,
    )
    if args.run_id.startswith(
        "codex-codegraph-enriched-smoke-"
    ):
        _validate_frozen_smoke_manifest(
            frozen,
            args.run_id,
            manifest,
        )
    result = rebuild_report(run_root, paths(config)["evaluator"], paths(config)["provenance"])
    print(json.dumps({"run_id": args.run_id, "claimable": result["claimable"]}, indent=2, sort_keys=True))
    return result


def _baseline_config_digest() -> tuple[str, int]:
    path = BASELINE_ROOT / "benchmark.py"
    spec = importlib.util.spec_from_file_location("frozen_baseline_benchmark", path)
    if spec is None or spec.loader is None:
        raise ComparisonRefused("comparison_refused: cannot load frozen baseline configuration")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    config = module.load_config()
    return module.config_digest(config), int(config["baseline"]["timeout_seconds"])


def compare(args: argparse.Namespace) -> dict[str, Any]:
    config = load_config()
    _require_task2_evidence(config)
    baseline_digest, timeout = _baseline_config_digest()
    if (
        not isinstance(args.baseline_run_id, str)
        or Path(args.baseline_run_id).name != args.baseline_run_id
        or not args.baseline_run_id.startswith(("baseline-", "codex-baseline-"))
    ):
        raise ComparisonRefused("comparison_refused: baseline run_id must be one explicit historical component")
    runs_root = (ROOT / ".benchmark-runs").resolve()
    baseline_root = runs_root / args.baseline_run_id
    if baseline_root.resolve().parent != runs_root:
        raise ComparisonRefused("comparison_refused: baseline root escapes .benchmark-runs")
    treatment_root = resolve_run_root(ROOT, args.codegraph_run_id, smoke=False)
    load_treatment_manifest(treatment_root, expected_run_id=args.codegraph_run_id)
    result = compare_runs(
        baseline_root,
        treatment_root,
        expected_baseline_configuration_sha256=baseline_digest,
        expected_timeout_seconds=timeout,
        output_path=treatment_root / f"comparison-to-{args.baseline_run_id}.json",
    )
    print(json.dumps({"matched": True, "baseline_run_id": args.baseline_run_id, "codegraph_run_id": args.codegraph_run_id}, indent=2))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("codegraph-prepare", aliases=["prepare"])
    sub.add_parser("codegraph-doctor", aliases=["doctor"])
    sub.add_parser("treatment-freeze")
    sub.add_parser("treatment-freeze-check")
    run_parser = sub.add_parser("codegraph-run", aliases=["run"])
    run_parser.add_argument("--run-id")
    smoke_parser = sub.add_parser("smoke")
    smoke_parser.add_argument("--run-id")
    smoke_inspection_parser = sub.add_parser("smoke-inspection")
    smoke_inspection_parser.add_argument("--run-id", required=True)
    smoke_gate_parser = sub.add_parser("smoke-gate")
    smoke_gate_parser.add_argument("--run-id", required=True)
    smoke_gate_parser.add_argument("--ack-manual-inspection", action="store_true")
    smoke_gate_parser.add_argument(
        "--inspected-manifest-sha256",
        required=True,
    )
    for name in ("score", "report"):
        command = sub.add_parser(name)
        command.add_argument("--run-id", required=True)
    compare_parser = sub.add_parser("compare")
    compare_parser.add_argument("--baseline-run-id", required=True)
    compare_parser.add_argument("--codegraph-run-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command in {"codegraph-prepare", "prepare"}:
            codegraph_prepare()
        elif args.command in {"codegraph-doctor", "doctor"}:
            doctor()
        elif args.command == "treatment-freeze":
            create_treatment_freeze()
        elif args.command == "treatment-freeze-check":
            check_treatment_freeze()
        elif args.command in {"codegraph-run", "run"}:
            run(args)
        elif args.command == "smoke":
            run(args, smoke=True)
        elif args.command == "smoke-inspection":
            create_smoke_inspection(args)
        elif args.command == "smoke-gate":
            create_smoke_gate(args)
        elif args.command == "score":
            score(args)
        elif args.command == "report":
            report(args)
        elif args.command == "compare":
            compare(args)
        return 0
    except (
        CodeGraphError,
        RunnerError,
        CorpusError,
        TaskMetadataError,
        ReportError,
        ComparisonRefused,
        IntegrityError,
        TreatmentFreezeError,
        FileNotFoundError,
        ValueError,
    ) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
