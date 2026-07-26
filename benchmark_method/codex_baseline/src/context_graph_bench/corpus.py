"""Immutable input handling, duplicate-safe corpus compilation, and snapshots."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

EXPECTED_EVALUATOR_SHA256 = "feea0a7fe67b08e68c940e10887d5b4feaae0b8c58e256eb09f253e65492d745"
EXPECTED_EVALUATOR_COMMIT = "3c12dc5a551937038afcbdb6eb6bbf19f3ddd8c1"
TASK_KEYS = ("instance_id", "repo", "base_commit", "problem_statement", "ground_truth")


class CorpusError(RuntimeError):
    """Raised when an input or repository provenance gate fails."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, json.JSONDecodeError) as exc:
        raise CorpusError(f"cannot load JSONL {path}: {exc}") from exc


def _issue_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("problem_statement", "issue", "text", "body"):
            if isinstance(value.get(key), str):
                return value[key]
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _source_entry(source_name: str, source_path: Path, issue_map_path: Path) -> dict[str, Any]:
    rows = load_jsonl(source_path)
    try:
        issue_map = json.loads(issue_map_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CorpusError(f"cannot load issue map {issue_map_path}: {exc}") from exc
    if not isinstance(issue_map, dict):
        raise CorpusError(f"issue map is not an object: {issue_map_path}")
    return {
        "name": source_name,
        "bench_path": source_path.name,
        "issue_map_path": issue_map_path.name,
        "bench_sha256": sha256_file(source_path),
        "issue_map_sha256": sha256_file(issue_map_path),
        "bench_source_path": str(source_path),
        "issue_map_source_path": str(issue_map_path),
        "rows": rows,
        "issue_map": issue_map,
    }


def load_sources(sources_dir: Path) -> list[dict[str, Any]]:
    return [
        _source_entry("select10", sources_dir / "bench.select10.jsonl", sources_dir / "issue_map.select10.json"),
        _source_entry("select15", sources_dir / "bench.select15.jsonl", sources_dir / "issue_map.select15.json"),
    ]


def _comparison_record(row: dict[str, Any], issue_text: str) -> dict[str, Any]:
    return {
        "instance_id": row.get("instance_id"),
        "repo": row.get("repo"),
        "base_commit": row.get("base_commit"),
        "problem_statement": row.get("problem_statement", ""),
        "issue_text": issue_text,
        "ground_truth": row.get("ground_truth"),
    }


def compile_corpus(sources_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    sources = load_sources(sources_dir)
    merged: dict[str, dict[str, Any]] = {}
    memberships: dict[str, list[dict[str, Any]]] = {}
    source_rows = 0
    for source in sources:
        for row_index, row in enumerate(source["rows"]):
            source_rows += 1
            instance_id = row.get("instance_id")
            if not isinstance(instance_id, str) or not instance_id:
                raise CorpusError(f"missing instance_id in {source['name']} row {row_index}")
            issue_text = _issue_value(source["issue_map"].get(instance_id, row.get("problem_statement", "")))
            candidate = _comparison_record(row, issue_text)
            if instance_id in merged:
                prior = merged[instance_id]["comparison"]
                if canonical_json(prior) != canonical_json(candidate):
                    raise CorpusError(f"conflicting duplicate task content: {instance_id}")
            else:
                merged[instance_id] = {"comparison": candidate, "row": row}
            memberships.setdefault(instance_id, []).append({
                "source": source["name"],
                "source_row": row_index,
                "bench_path": source["bench_path"],
                "issue_map_path": source["issue_map_path"],
            })

    tasks: list[dict[str, Any]] = []
    for instance_id in sorted(merged):
        item = merged[instance_id]
        row = item["row"]
        comparison = item["comparison"]
        tasks.append({
            "instance_id": instance_id,
            "repo": row["repo"],
            "repository_url": f"https://github.com/{row['repo']}.git",
            "base_commit": row["base_commit"],
            "repo_dir": row.get("repo_dir"),
            "repo_path": row.get("repo_path"),
            "language": row.get("language"),
            "problem_statement": row.get("problem_statement", ""),
            "issue_text": comparison["issue_text"],
            "ground_truth": row.get("ground_truth"),
            "source_memberships": memberships[instance_id],
            "weight": 1.0,
        })
    source_manifest = {
        "suite_name": "Select-25 source merge",
        "source_row_count": source_rows,
        "unique_task_count": len(tasks),
        "duplicate_instance_ids": {key: value for key, value in memberships.items() if len(value) > 1},
        "sources": [{key: value for key, value in source.items() if key not in {"rows", "issue_map"}} for source in sources],
        "tasks": tasks,
    }
    return tasks, source_manifest


def verify_official_evaluator(path: Path, provenance_path: Path) -> dict[str, str]:
    if not path.is_file():
        raise CorpusError(f"official evaluator missing: {path}")
    digest = sha256_file(path)
    if digest != EXPECTED_EVALUATOR_SHA256:
        raise CorpusError(f"official evaluator digest drift: {digest}")
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    if provenance.get("commit") != EXPECTED_EVALUATOR_COMMIT or provenance.get("sha256") != EXPECTED_EVALUATOR_SHA256:
        raise CorpusError("official evaluator provenance drift")
    return {"commit": EXPECTED_EVALUATOR_COMMIT, "sha256": digest}


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=False)
    if result.returncode:
        raise CorpusError(result.stderr.strip() or f"git failed in {repo}: {' '.join(args)}")
    return result.stdout.strip()


def verify_repository_head(repo: Path, base_commit: str) -> dict[str, Any]:
    if not (repo / ".git").exists():
        raise CorpusError(f"repository has no independent .git metadata: {repo}")
    top = Path(_git(repo, "rev-parse", "--show-toplevel")).resolve()
    if top != repo.resolve():
        raise CorpusError(f"parent repository metadata cannot validate snapshot: {repo} -> {top}")
    head = _git(repo, "rev-parse", "HEAD")
    if head != base_commit:
        raise CorpusError(f"HEAD mismatch for {repo}: expected {base_commit}, got {head}")
    status = _git(repo, "status", "--porcelain")
    if status:
        raise CorpusError(f"modified tracked files in snapshot: {repo}")
    return {"resolved_path": str(repo.resolve()), "requested_base_commit": base_commit, "verified_head": head, "clean": True}


def _safe_name(repo_url: str) -> str:
    return repo_url.removeprefix("https://github.com/").removesuffix(".git").replace("/", "--")


def prepare_snapshot(task: dict[str, Any], source_root: Path, select15_root: Path, work_root: Path) -> dict[str, Any]:
    repo_dir = Path(task.get("repo_dir") or "")
    source = source_root / repo_dir if repo_dir.parts and repo_dir.parts[0] == "repos" else source_root / repo_dir
    if any(m["source"] == "select15" for m in task.get("source_memberships", [])):
        source = select15_root / Path(*repo_dir.parts[1:]) if repo_dir.parts and repo_dir.parts[0] == "repos" else select15_root / repo_dir
    if source.exists() and (source / ".git").exists():
        try:
            return verify_repository_head(source, task["base_commit"])
        except CorpusError:
            pass

    mirror = work_root / "mirrors" / f"{_safe_name(task['repository_url'])}.git"
    worktree = work_root / "worktrees" / task["instance_id"]
    mirror.parent.mkdir(parents=True, exist_ok=True)
    if not mirror.exists():
        subprocess.run(["git", "init", "--bare", str(mirror)], check=True, capture_output=True, text=True)
        subprocess.run(["git", "--git-dir", str(mirror), "remote", "add", "origin", task["repository_url"]], check=True, capture_output=True, text=True)
    fetch = subprocess.run(["git", "--git-dir", str(mirror), "fetch", "--depth=1", "origin", task["base_commit"]], capture_output=True, text=True, check=False)
    if fetch.returncode:
        raise CorpusError(f"cannot fetch {task['repository_url']} at {task['base_commit']}: {fetch.stderr.strip()}")
    if worktree.exists():
        try:
            verified = verify_repository_head(worktree, task["base_commit"])
            return verified | {"source_snapshot": "shared_git_worktree"}
        except CorpusError:
            shutil.rmtree(worktree)
    worktree.parent.mkdir(parents=True, exist_ok=True)
    added = subprocess.run(["git", "--git-dir", str(mirror), "worktree", "add", "--detach", str(worktree), task["base_commit"]], capture_output=True, text=True, check=False)
    if added.returncode:
        raise CorpusError(f"cannot create detached worktree for {task['instance_id']}: {added.stderr.strip()}")
    return verify_repository_head(worktree, task["base_commit"]) | {"source_snapshot": "shared_git_worktree"}


def resolve_source_snapshot(task: dict[str, Any], select10_root: Path, select15_root: Path) -> Path:
    repo_dir = Path(task.get("repo_dir") or "")
    if any(m["source"] == "select15" for m in task.get("source_memberships", [])):
        return select15_root / Path(*repo_dir.parts[1:]) if repo_dir.parts and repo_dir.parts[0] == "repos" else select15_root / repo_dir
    return select10_root / repo_dir
