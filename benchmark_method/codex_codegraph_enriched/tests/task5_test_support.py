from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def _write_json(path: Path, value: dict[str, Any]) -> str:
    path.write_text(
        json.dumps(value, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bind_enriched_authority(
    run_root: Path,
    codegraph: dict[str, Any],
    *,
    index_count: int,
    executable_sha256: str = "9" * 64,
) -> dict[str, Any]:
    """Add the immutable Task 2/Task 4 artifacts required by a run fixture."""

    task2 = run_root / "task2-evidence-root.json"
    task4_seal = run_root / "task4-sealed-root.json"
    task4_candidate = run_root / "task4-candidate-root.json"
    task4_all24 = run_root / "task4-all24.json"
    task2_sha = _write_json(task2, {"fixture": "task2"})
    seal_sha = _write_json(task4_seal, {"fixture": "task4-seal"})
    candidate_sha = _write_json(
        task4_candidate,
        {"fixture": "task4-candidate"},
    )
    all24_sha = _write_json(task4_all24, {"fixture": "task4-all24"})
    authority = {
        "task4_sealed_root": task4_seal.name,
        "task4_sealed_root_sha256": seal_sha,
        "task4_candidate_root": task4_candidate.name,
        "task4_candidate_root_sha256": candidate_sha,
        "task4_all24": task4_all24.name,
        "task4_all24_sha256": all24_sha,
        "authority_sha256": "a" * 64,
        "index_count": index_count,
    }
    codegraph.update(
        {
            "executable_sha256": executable_sha256,
            "task2_evidence_root": task2.name,
            "task2_evidence_root_sha256": task2_sha,
            "enrichment_authority": authority,
        }
    )
    return authority


def enriched_index_authority(
    authority: dict[str, Any],
    *,
    executable_sha256: str = "9" * 64,
) -> dict[str, Any]:
    return {
        "task4_sealed_root_sha256": authority[
            "task4_sealed_root_sha256"
        ],
        "task4_candidate_root_sha256": authority[
            "task4_candidate_root_sha256"
        ],
        "task4_all24_sha256": authority["task4_all24_sha256"],
        "task2_runtime_sha256": executable_sha256,
    }
