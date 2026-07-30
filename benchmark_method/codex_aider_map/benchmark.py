#!/usr/bin/env python3
"""Codex plus frozen Aider RepoMap treatment CLI.

Task 4 wires no paid execution: provider-backed doctor/smoke/run remain
explicitly gated until Task 5 supplies a real observed event envelope.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import tomllib

ARM_ROOT = Path(__file__).resolve().parent
ROOT = ARM_ROOT.parents[1]
BASELINE_SRC = ROOT / "benchmark_method" / "codex_baseline" / "src"
SRC = ARM_ROOT / "src"
for source in (SRC, BASELINE_SRC):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from aider_map_bench.binding import MapBindingError, bind_map
from aider_map_bench.attempt import finalize_attempt_telemetry, plan_attempt
from aider_map_bench.lifecycle import LifecycleError, audit_attempt, compare as lifecycle_compare, inspect_smoke as lifecycle_inspect_smoke, report as lifecycle_report, run_treatment, score as lifecycle_score, smoke_gate as lifecycle_smoke_gate
from aider_map_bench.navigation import replay_navigation
from aider_map_bench.prompt import build_treatment_prompt
from context_graph_bench.codex_runner import RunnerError
from context_graph_bench.corpus import compile_corpus, verify_official_evaluator


def load_config() -> dict[str, Any]:
    with (ARM_ROOT / "config" / "aider-map.toml").open("rb") as stream:
        return tomllib.load(stream)


def _tasks() -> list[dict[str, Any]]:
    tasks, _manifest = compile_corpus(ROOT / "benchmark_method" / "common" / "inputs" / "sources")
    return tasks


def _prepared_tasks() -> list[dict[str, Any]]:
    prepared = json.loads((ROOT / ".benchmark-work" / "codex-baseline" / "prepared.json").read_text(encoding="utf-8"))
    by_id = {item["task_id"]: item for item in prepared.get("tasks", [])}
    tasks = _tasks()
    for task in tasks:
        task["prepared"] = by_id.get(task["instance_id"])
        if not task["prepared"]:
            raise RunnerError("configuration_error: baseline prepared task is missing")
    return tasks


def preparation_validation() -> dict[str, Any]:
    bindings = [bind_map(task) for task in _tasks()]
    return {"status": "passed", "task_count": len(bindings), "map_manifest_sha256": bindings[0].manifest_sha256 if bindings else None, "phase_freeze_sha256": bindings[0].phase_freeze_sha256 if bindings else None, "all_exact_task_bindings": len({item.task_id for item in bindings}) == 24}


def inspect_prompt(task_id: str) -> dict[str, Any]:
    task = next((item for item in _tasks() if item["instance_id"] == task_id), None)
    if task is None:
        raise RunnerError("configuration_error: unknown task")
    bound = bind_map(task)
    template = (ROOT / "benchmark_method" / "codex_baseline" / "config" / "region-selection-prompt.md").read_text(encoding="utf-8")
    _prompt, metadata = build_treatment_prompt(template, task["issue_text"], bound)
    return {"task_id": task_id, "map": bound.provenance(), "prompt": metadata}


def replay(args: argparse.Namespace) -> dict[str, Any]:
    result = replay_navigation(Path(args.events).read_text(encoding="utf-8"))
    if not result.get("valid"):
        raise RunnerError("navigation_replay_refused: " + result.get("error", "unknown event"))
    return result


def preflight_operation(command: str) -> dict[str, Any]:
    """Safe half of each lifecycle operation; execution uses lifecycle.py."""
    return {"operation": command, "execution_mode": "preflight_only_not_executed", "preflight": preparation_validation(), "executor": "aider_map_bench.lifecycle.run_treatment" if command in {"doctor", "smoke", "run"} else "offline baseline helper"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("prepare")
    inspect = sub.add_parser("inspect-prompt")
    inspect.add_argument("--task-id", required=True)
    replay_parser = sub.add_parser("replay-navigation")
    replay_parser.add_argument("--events", required=True)
    for name in ("doctor", "smoke", "run"):
        command = sub.add_parser(name)
        command.add_argument("--run-id")
        command.add_argument("--limit", type=int)
        command.add_argument("--samples", type=int)
        command.add_argument("--execute", action="store_true")
    inspect_smoke = sub.add_parser("inspect-smoke")
    inspect_smoke.add_argument("--attempt-record")
    gate = sub.add_parser("smoke-gate")
    gate.add_argument("--attempt-record")
    for name in ("score", "report"):
        command = sub.add_parser(name)
        command.add_argument("--run-id")
    compare = sub.add_parser("compare")
    compare.add_argument("--baseline-run-id")
    compare.add_argument("--treatment-run-id")
    audit = sub.add_parser("audit")
    audit.add_argument("--attempt-record")
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            result = preparation_validation()
        elif args.command == "inspect-prompt":
            result = inspect_prompt(args.task_id)
        elif args.command == "replay-navigation":
            result = replay(args)
        elif args.command == "audit" and args.attempt_record:
            result = audit_attempt(Path(args.attempt_record))
        elif args.command == "inspect-smoke" and args.attempt_record:
            result = lifecycle_inspect_smoke(Path(args.attempt_record))
        elif args.command == "smoke-gate" and args.attempt_record:
            result = lifecycle_smoke_gate(Path(args.attempt_record))
        elif args.command == "compare" and args.baseline_run_id and args.treatment_run_id:
            baseline = [json.loads(line) for line in (ROOT / ".benchmark-runs" / args.baseline_run_id / "attempts.jsonl").read_text().splitlines() if line.strip()]
            treatment = [json.loads(line) for line in (ROOT / ".benchmark-runs" / args.treatment_run_id / "attempts.jsonl").read_text().splitlines() if line.strip()]
            result = lifecycle_compare(baseline, treatment)
        elif args.command == "score" and args.run_id:
            result = {"run_id": args.run_id, "records": lifecycle_score(ROOT, args.run_id, ROOT / "benchmark_method" / "common" / "official" / "eval.py", ROOT / "benchmark_method" / "common" / "official" / "provenance.json")}
        elif args.command == "report" and args.run_id:
            evaluator = verify_official_evaluator(ROOT / "benchmark_method" / "common" / "official" / "eval.py", ROOT / "benchmark_method" / "common" / "official" / "provenance.json")
            result = lifecycle_report(ROOT, args.run_id, 24, load_config()["treatment"]["sample_count"], evaluator)
        elif args.command in {"doctor", "smoke", "run"} and args.execute:
            run_id = args.run_id or f"codex-aider-map-{args.command}"
            result = run_treatment(ROOT, _prepared_tasks(), load_config(), run_id=run_id, schema_path=ROOT / "benchmark_method" / "common" / "schemas" / "agent-regions.schema.json", baseline_template=(ROOT / "benchmark_method" / "codex_baseline" / "config" / "region-selection-prompt.md").read_text(encoding="utf-8"), auth_source=Path(load_config()["paths"]["codex_auth_source"]), limit=args.limit or (1 if args.command in {"doctor", "smoke"} else None), samples=args.samples or 1)
        else:
            result = preflight_operation(args.command)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (RunnerError, MapBindingError, LifecycleError, ValueError, FileNotFoundError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
