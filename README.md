# Context Graph benchmark method

This repository contains two completed SWE-Explore benchmark arms:

- Implementation 1: the frozen plain-Codex baseline.
- Implementation 2: a separate orchestration layer around the real, pinned
  upstream CodeGraph MCP tool.

It does not implement CodeGraph itself, OKFs, retrieval, embeddings, or
generated context.

The plain baseline-only public entrypoint is:

```bash
python3 benchmark_method/codex_baseline/benchmark.py prepare
python3 benchmark_method/codex_baseline/benchmark.py doctor
python3 benchmark_method/codex_baseline/benchmark.py smoke --run-id codex-baseline-smoke-<timestamp>
python3 benchmark_method/codex_baseline/benchmark.py score --run-id <run-id>
python3 benchmark_method/codex_baseline/benchmark.py report --run-id <run-id>
```

The baseline is self-contained under `benchmark_method/codex_baseline/`.
The treatment arm is self-contained under
`benchmark_method/codex_codegraph/`. Immutable cross-experiment inputs and the
untouched official evaluator live under `benchmark_method/common/`.

The CodeGraph arm's ordered entrypoints are:

```bash
python3 benchmark_method/codex_codegraph/benchmark.py codegraph-prepare
python3 benchmark_method/codex_codegraph/benchmark.py codegraph-doctor
python3 benchmark_method/codex_codegraph/benchmark.py smoke --run-id <smoke-run-id>
python3 benchmark_method/codex_codegraph/benchmark.py score --run-id <smoke-run-id>
python3 benchmark_method/codex_codegraph/benchmark.py report --run-id <smoke-run-id>
python3 benchmark_method/codex_codegraph/benchmark.py smoke-inspection --run-id <smoke-run-id>
python3 benchmark_method/codex_codegraph/benchmark.py smoke-gate \
  --run-id <smoke-run-id> \
  --ack-manual-inspection \
  --inspected-manifest-sha256 <inspection-sha256>
python3 benchmark_method/codex_codegraph/benchmark.py codegraph-run --run-id <run-id>
python3 benchmark_method/codex_codegraph/benchmark.py score --run-id <run-id>
python3 benchmark_method/codex_codegraph/benchmark.py report --run-id <run-id>
python3 benchmark_method/codex_codegraph/benchmark.py compare \
  --baseline-run-id <baseline-run-id> \
  --codegraph-run-id <run-id>
```

Each execution remains in `.benchmark-runs/<run-id>/`. Historical run
artifacts are immutable and are not rewritten by path changes.

Smoke runs are structural validation records, not published aggregates.

## Current validated result

- Frozen baseline:
  `baseline-20260725-final-20260725T204500Z`
- CodeGraph treatment:
  `codex-codegraph-v18-20260727T103813Z`
- Treatment claimability: 24 tasks × 3 valid samples; 72/72 claimable.
- Retained treatment attempts: 73, including one schema-invalid first attempt
  and its bounded successful retry.
- Matched comparison: true.
- CodeGraph aggregate SHA-256:
  `37760d3fb9e11b2691b5f28757bafb317cedd2069ed9b1524a0beef7af1dacbc`
- Comparison SHA-256:
  `af677e8df239f38a54f6a1e6c4be1f954661e02eac9fb9c5fc019ac46ca79f5c`

The treatment improved equal-task precision, recall, F1, context efficiency,
and file/region noise rates. It reduced pooled total tokens by 1.711%, but the
contract's equal-weighted per-task-median estimator reports 4.211% more tokens
and 1.986% slower agent execution. Cost remains unavailable because exact
versioned cache and long-context billing semantics were not proven.

Source benchmark repositories are external inputs. Runtime state, detached
worktrees, raw provider logs, and run reports live under ignored directories.
No credentials or repository checkouts belong in Git.
