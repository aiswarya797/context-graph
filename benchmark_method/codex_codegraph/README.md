# Codex + CodeGraph benchmark arm

This is the concrete `codex-codegraph` SWE-Explore arm. It wraps one pinned
upstream CodeGraph executable; it does not copy or reimplement CodeGraph.

The implementation is intentionally separate from the frozen plain-Codex
baseline. It reuses the baseline corpus, response schema, official evaluator,
Codex process isolation, and provider telemetry parser without changing them.

Operational order:

```bash
python3 benchmark_method/codex_codegraph/benchmark.py codegraph-prepare
python3 benchmark_method/codex_codegraph/benchmark.py codegraph-doctor
python3 benchmark_method/codex_codegraph/benchmark.py smoke \
  --run-id codex-codegraph-smoke-<timestamp>
python3 benchmark_method/codex_codegraph/benchmark.py score \
  --run-id codex-codegraph-smoke-<timestamp>
python3 benchmark_method/codex_codegraph/benchmark.py report \
  --run-id codex-codegraph-smoke-<timestamp>
python3 benchmark_method/codex_codegraph/benchmark.py smoke-inspection \
  --run-id codex-codegraph-smoke-<timestamp>
python3 benchmark_method/codex_codegraph/benchmark.py smoke-gate \
  --run-id codex-codegraph-smoke-<timestamp> \
  --ack-manual-inspection \
  --inspected-manifest-sha256 <printed-inspection-sha256>
python3 benchmark_method/codex_codegraph/benchmark.py codegraph-run --run-id <run-id>
python3 benchmark_method/codex_codegraph/benchmark.py score --run-id <run-id>
python3 benchmark_method/codex_codegraph/benchmark.py report --run-id <run-id>
python3 benchmark_method/codex_codegraph/benchmark.py compare \
  --baseline-run-id <baseline-run-id> --codegraph-run-id <run-id>
```

`codegraph-prepare` is the only command allowed to build the pinned runtime or
create indexes. Measured commands only validate and consume frozen indexes.
Every measured attempt gets a new Codex home, repository snapshot, and MCP
process.

The event parser accepts the retained, provenance-bound Codex 0.145.0 live
CodeGraph envelope in `tests/fixtures/codegraph_events/`. Unknown MCP shapes
fail closed. A smoke gate is valid only after official score/report
recomputation and explicit acknowledgement of the complete inspection-manifest
digest.
