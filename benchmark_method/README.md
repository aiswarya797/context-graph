# Benchmark method layout

This directory contains immutable benchmark inputs and the official evaluator
under `common/`, plus the self-contained plain Codex baseline under
`codex_baseline/`.

The baseline-only entrypoint is:

```bash
python3 benchmark_method/codex_baseline/benchmark.py prepare
python3 benchmark_method/codex_baseline/benchmark.py doctor
python3 benchmark_method/codex_baseline/benchmark.py run
python3 benchmark_method/codex_baseline/benchmark.py score --run-id <run-id>
python3 benchmark_method/codex_baseline/benchmark.py report --run-id <run-id>
```

The CodeGraph treatment arm now has a separate orchestrator under
`benchmark_method/codex_codegraph/`; its README defines the ordered
prepare/doctor/smoke/inspection/gate/full-run workflow. Each execution remains
an immutable result under `.benchmark-runs/<run-id>/`; ignored preparation
state stays under its arm-specific `.benchmark-work/` root.

The current validated pair is:

- baseline: `baseline-20260725-final-20260725T204500Z`;
- CodeGraph: `codex-codegraph-v18-20260727T103813Z`;
- CodeGraph aggregate:
  `37760d3fb9e11b2691b5f28757bafb317cedd2069ed9b1524a0beef7af1dacbc`;
- matched comparison:
  `af677e8df239f38a54f6a1e6c4be1f954661e02eac9fb9c5fc019ac46ca79f5c`.

The treatment has 72/72 claimable samples over 24 tasks. One initial invalid
response and its bounded retry remain preserved in the 73-attempt run record.
Cost is deliberately unavailable because exact versioned cache and
long-context billing semantics were not proven.
