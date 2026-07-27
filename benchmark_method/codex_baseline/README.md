# Plain Codex baseline

`codex_baseline/benchmark.py` and the `codex_baseline` package are
baseline-only. They contain no CodeGraph integration, OKF, retrieval, generic
arm interface, or shared orchestration. The CodeGraph treatment is implemented
separately under `benchmark_method/codex_codegraph/`. The baseline
implementation and protocol remain frozen and unchanged.

The baseline protocol is `direct-region-v1`: Codex receives issue text and a
read-only pinned repository, then returns one to five ordered evidence regions.
Local validation rejects invalid paths and ranges without changing the answer.
Only the untouched pinned `official/eval.py` scores validated regions.

The operational ladder is intentionally small. Python 3.11 or newer is
required; the CLI reports its interpreter and version during `doctor` and
fails clearly under an older interpreter.

1. From the repository root:

   ```bash
   python3 -m unittest discover \
     -s benchmark_method/codex_baseline/tests \
     -p 'test_*.py' \
     -v
   ```
2. `python3 benchmark_method/codex_baseline/benchmark.py prepare` and repository revision preflight.
3. `python3 benchmark_method/codex_baseline/benchmark.py doctor`, which verifies
   that the ordinary Codex child can read the checkout, emit valid telemetry,
   and return the required output schema.
4. `python3 benchmark_method/codex_baseline/benchmark.py smoke --run-id
   codex-baseline-smoke-<timestamp>` runs exactly one task and one sample,
   scores it with the untouched official evaluator, and writes the hard smoke
   gate. A normal multi-task run is refused until that gate matches the current
   harness identity.
5. Resume until three quality-valid samples exist for all 24 unique tasks.
6. `score` and `report` offline from saved artifacts.

The current contract requires Python 3.11+, Codex CLI `0.145.0`, model `gpt-5.6-luna`, and
`model_reasoning_effort=high`. Version drift is a hard preflight failure.

Each child receives the issue text, pinned read-only checkout, response schema,
and current-attempt output directory. It uses an ephemeral `CODEX_HOME` linked
to the existing Codex login. Web search, browser retrieval, remote URL
fetches, GitHub lookup, and benchmark lookup are disabled and any such event
invalidates the attempt.

Each execution is stored in its own `.benchmark-runs/<run-id>/` directory.
Those result artifacts are the immutable source for later scoring and report
rebuilds. Smoke runs are structural validation only and are not published
baseline results. The separate CodeGraph treatment does not alter the frozen
baseline implementation or protocol.
