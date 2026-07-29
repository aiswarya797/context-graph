# Codex + CodeGraph benchmark arm

This is the concrete `codex-codegraph-enriched` SWE-Explore arm. It launches
the exact frozen Task 2 CodeGraph executable against the sealed Task 4
enriched indexes. The patched builder is never a measured MCP runtime.

The implementation is intentionally separate from the frozen plain-Codex
baseline. It reuses the baseline corpus, response schema, official evaluator,
Codex process isolation, and provider telemetry parser without changing them.

Operational order:

```bash
python3 benchmark_method/codex_codegraph_enriched/benchmark.py codegraph-prepare
python3 benchmark_method/codex_codegraph_enriched/benchmark.py codegraph-doctor
python3 benchmark_method/codex_codegraph_enriched/benchmark.py treatment-freeze
python3 benchmark_method/codex_codegraph_enriched/benchmark.py treatment-freeze-check
python3 benchmark_method/codex_codegraph_enriched/benchmark.py smoke \
  --run-id codex-codegraph-enriched-smoke-task7-v1
python3 benchmark_method/codex_codegraph_enriched/benchmark.py score \
  --run-id codex-codegraph-enriched-smoke-task7-v1
python3 benchmark_method/codex_codegraph_enriched/benchmark.py report \
  --run-id codex-codegraph-enriched-smoke-task7-v1
python3 benchmark_method/codex_codegraph_enriched/benchmark.py smoke-inspection \
  --run-id codex-codegraph-enriched-smoke-task7-v1
python3 benchmark_method/codex_codegraph_enriched/benchmark.py smoke-gate \
  --run-id codex-codegraph-enriched-smoke-task7-v1 \
  --ack-manual-inspection \
  --inspected-manifest-sha256 <printed-inspection-sha256>
python3 benchmark_method/codex_codegraph_enriched/benchmark.py codegraph-run --run-id <run-id>
python3 benchmark_method/codex_codegraph_enriched/benchmark.py score --run-id <run-id>
python3 benchmark_method/codex_codegraph_enriched/benchmark.py report --run-id <run-id>
python3 benchmark_method/codex_codegraph_enriched/benchmark.py compare \
  --baseline-run-id <baseline-run-id> --codegraph-run-id <run-id>
```

`codegraph-prepare` is read-only in this arm: it validates the frozen Task 2
runtime plus all 24 sealed Task 4 index authorities. It never builds or
reseals either authority. Every measured attempt gets a new Codex home,
repository snapshot, disposable index copy, and MCP process.

The event parser accepts the retained, provenance-bound Codex 0.145.0 live
CodeGraph envelope in `tests/fixtures/codegraph_events/`. Unknown MCP shapes
fail closed. A smoke gate is valid only after official score/report
recomputation and explicit acknowledgement of the complete inspection-manifest
digest.
