"""Write-once Task 7 treatment-freeze encoding and validation."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from .codegraph import sha256_value


SCHEMA_VERSION = "codegraph-enriched-treatment-freeze-v1"
FREEZE_VERSION = 1


class TreatmentFreezeError(RuntimeError):
    """The Task 7 treatment freeze is absent, mutable, or stale."""


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode()


def freeze_payload(treatment: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(treatment, dict) or not treatment:
        raise TreatmentFreezeError(
            "treatment_freeze_refused: treatment identity is missing"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "version": FREEZE_VERSION,
        "status": "FROZEN",
        "treatment": treatment,
        "treatment_sha256": sha256_value(treatment),
    }


def write_treatment_freeze(
    path: Path,
    treatment: dict[str, Any],
) -> dict[str, Any]:
    if path.is_symlink():
        raise TreatmentFreezeError(
            "treatment_freeze_refused: freeze path is a symlink"
        )
    if path.exists():
        raise TreatmentFreezeError(
            "treatment_freeze_refused: freeze already exists"
        )
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise TreatmentFreezeError(
            "treatment_freeze_refused: freeze parent is missing or symlinked"
        )
    payload = freeze_payload(treatment)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o400)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_json_bytes(payload))
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    os.chmod(path, 0o400)
    return validate_treatment_freeze(path, treatment)


def validate_treatment_freeze(
    path: Path,
    treatment: dict[str, Any],
) -> dict[str, Any]:
    if path.is_symlink():
        raise TreatmentFreezeError(
            "treatment_freeze_refused: freeze path is a symlink"
        )
    if not path.is_file():
        raise TreatmentFreezeError(
            "treatment_freeze_refused: freeze is missing"
        )
    if stat.S_IMODE(path.stat().st_mode) != 0o400:
        raise TreatmentFreezeError(
            "treatment_freeze_refused: freeze is not read-only"
        )
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TreatmentFreezeError(
            "treatment_freeze_refused: freeze is unreadable"
        ) from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "version",
        "status",
        "treatment",
        "treatment_sha256",
    }:
        raise TreatmentFreezeError(
            "treatment_freeze_refused: freeze fields differ"
        )
    if (
        payload.get("schema_version") != SCHEMA_VERSION
        or payload.get("version") != FREEZE_VERSION
        or payload.get("status") != "FROZEN"
    ):
        raise TreatmentFreezeError(
            "treatment_freeze_refused: freeze identity differs"
        )
    expected = freeze_payload(treatment)
    if payload != expected:
        raise TreatmentFreezeError(
            "treatment_freeze_refused: treatment bytes differ"
        )
    if raw != _json_bytes(expected):
        raise TreatmentFreezeError(
            "treatment_freeze_refused: freeze encoding differs"
        )
    return payload
