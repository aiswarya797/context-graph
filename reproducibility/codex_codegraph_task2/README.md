# Task 2 CodeGraph reproduction bundle

This tracked publication bundle preserves the two immutable bootstrap records
needed by the unchanged Task 2 preparation workflow:

- `source-lock.json`
- `upstream-resolution.json`

They are byte-identical copies of the authoritative local records. The
manifest binds their original and publication paths, byte counts, SHA-256
digests, pinned upstream identity, and completed Task 2 authority identities.

## What is intentionally not committed

The full upstream CodeGraph repository is not vendored. The local CodeGraph
clone, `node_modules`, build outputs, frozen indexes, raw benchmark runs, and
historical attempts remain ignored and local-only.

The unchanged Task 2 preparation command clones:

```text
https://github.com/colbymchenry/codegraph.git
```

It checks out the immutable commit:

```text
572d22bfbe82602080e457bec655f72e3314f9ef
```

The published source lock records CodeGraph version `1.5.0`, Node
`v22.17.0`, npm `10.9.2`, and the corresponding executable hashes. Exact
source/build reproduction may require those versions and hashes; do not weaken
the unchanged provenance checks.

## Fresh-checkout workflow

Do not run the materializer in the completed authoritative Task 2 workspace.
It deliberately refuses any workspace containing the v18 evidence root, freeze
marker, or active-authority record.

From a fresh checkout, first perform a read-only check:

```bash
python3 reproducibility/codex_codegraph_task2/materialize.py --check
```

Then materialize the two records into the canonical ignored locations:

```bash
python3 reproducibility/codex_codegraph_task2/materialize.py
```

The materializer:

- verifies `manifest.json` and both publication copies;
- requires the destination to be the Git checkout that contains this bundle;
- rejects malformed JSON, symlinks, path escapes, missing files, and hash
  mismatches;
- creates only `.benchmark-tools/codegraph/source-lock.json` and
  `.benchmark-tools/codegraph/upstream-resolution.json` when absent;
- leaves byte-identical existing destinations untouched;
- rejects conflicting destinations;
- rolls back a newly created first record if the second record cannot be
  created safely;
- never clones, installs, builds, indexes, or starts a benchmark.

After materialization, use the unchanged Task 2 preparation workflow to
reconstruct source acquisition, the pinned CodeGraph checkout, the build, and
index preparation:

```bash
CODEX_EXECUTABLE=/absolute/path/to/codex \
CODEX_AUTH_SOURCE=/absolute/path/to/auth.json \
python3 benchmark_method/codex_codegraph/benchmark.py codegraph-prepare
```

The existing frozen Task 2 configuration contains machine-local defaults and
supports `CODEX_EXECUTABLE` and `CODEX_AUTH_SOURCE`. Those overrides replace
only the executable and authentication-source defaults. They do not make the
measured runner's sandbox policy portable.

Preparation clones the pinned upstream repository and locally creates its
dependencies, build output, and one ignored index per exact task revision.
Those products remain outside Git.

## Measured-run portability boundary

The frozen measured runner contains machine-specific `/Users/aiswarya/...`
sandbox-denial paths. Under another home directory, executing a new measured
run is therefore not currently guaranteed to provide isolation equivalent to
Task 2, even when `CODEX_EXECUTABLE` and `CODEX_AUTH_SOURCE` are supplied.

Do not edit the frozen runner or
`benchmark_method/codex_codegraph/config/codegraph.toml` to change those paths.
Doing so would create a different harness, not reproduce Task 2. A portable
runner must be implemented and validated in the future as a new harness and
version.

## Three different reproduction claims

1. **Published source/build/index setup:** this bundle makes the immutable
   source pin and resolution evidence available to the unchanged preparation
   workflow. Subject to the recorded toolchain and external repository
   availability, source acquisition, the pinned checkout, the build, and index
   preparation can be reconstructed.
2. **Historical 72-sample run:** the completed run depends on large ignored
   indexes, sealed authority evidence, raw attempts, and provider execution.
   Those artifacts are not published here, so the historical run is not fully
   reproducible from Git alone.
3. **A new benchmark run:** the publication bundle does not establish
   equivalent measured-run isolation on an arbitrary machine. Any future
   portable runner is a new harness/version, and any new run is a new
   experiment—not a reproduction or replacement of
   `codex-codegraph-v18-20260727T103813Z`.

The materializer uses only the Python standard library and performs no network
access.
