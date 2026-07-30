"""Parity-locked baseline invocation seam for the RepoMap treatment."""

from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path
from typing import Any

from context_graph_bench.codex_runner import RunnerError, build_command as build_baseline_command


ROOT = Path(__file__).resolve().parents[4]
FROZEN_BASELINE_CONFIG = ROOT / "benchmark_method" / "codex_baseline" / "config" / "baseline.toml"
FROZEN_BASELINE_CONFIG_SHA256 = "0f6644d349d120ac1a82e33fbcb52089c76bfc1f9e54e596aa0976886bab2f7e"
PARITY_TREATMENT_FIELDS = ("model", "reasoning_effort", "codex_version", "sample_count", "retry_cap", "timeout_seconds", "max_regions")
PARITY_PATH_FIELDS = ("codex_executable", "codex_auth_source", "select10_root", "select15_root")


def frozen_baseline_config() -> dict[str, Any]:
    """Load the sole command authority, refusing changed baseline bytes."""
    try:
        raw = FROZEN_BASELINE_CONFIG.read_bytes()
    except OSError as exc:
        raise RunnerError("configuration_error: frozen baseline configuration is unavailable") from exc
    if hashlib.sha256(raw).hexdigest() != FROZEN_BASELINE_CONFIG_SHA256:
        raise RunnerError("configuration_error: frozen baseline configuration digest differs")
    parsed = tomllib.loads(raw.decode("utf-8"))
    if not isinstance(parsed.get("baseline"), dict) or not isinstance(parsed.get("paths"), dict):
        raise RunnerError("configuration_error: frozen baseline configuration is malformed")
    return parsed


def baseline_equivalent_config(config: dict[str, Any]) -> dict[str, Any]:
    """Bind treatment knobs to frozen baseline bytes before command construction."""
    treatment = config.get("treatment")
    paths = config.get("paths")
    if not isinstance(treatment, dict) or not isinstance(paths, dict):
        raise RunnerError("configuration_error: treatment configuration is incomplete")
    if treatment.get("arm") != "codex-aider-map" or treatment.get("protocol") != "direct-region-v1+aider-repomap-v1":
        raise RunnerError("configuration_error: treatment identity drift")
    frozen = frozen_baseline_config()
    baseline, baseline_paths = frozen["baseline"], frozen["paths"]
    for field in PARITY_TREATMENT_FIELDS:
        if treatment.get(field) != baseline.get(field):
            raise RunnerError(f"configuration_error: treatment {field} differs from frozen baseline")
    for field in PARITY_PATH_FIELDS:
        if paths.get(field) != baseline_paths.get(field):
            raise RunnerError(f"configuration_error: treatment path {field} differs from frozen baseline")
    # Preserve the treatment identity in the caller's config/attempt metadata,
    # but send the unmodified frozen baseline configuration to its command builder.
    return {"baseline": dict(baseline), "paths": dict(baseline_paths)}


def build_treatment_command(executable: Path, config: dict[str, Any], state_dir: Path, schema_path: Path, repository: Path) -> list[str]:
    """Use the untouched baseline command builder: no MCP or Aider process seam."""
    command = build_baseline_command(executable, baseline_equivalent_config(config), state_dir, schema_path, repository)
    rendered = "\n".join(command).lower()
    # Baseline deliberately disables plugins, so only an enabling/command surface is prohibited.
    # Do not scan filesystem paths: the isolated runtime itself is named
    # ``aider-map-treatment-*``. Only a Codex configuration/argument surface
    # can introduce a provider, agent, or MCP process.
    if "--enable\nplugins" in rendered or any("mcp_servers" in arg or arg.lower() in {"aider", "codegraph"} for arg in command):
        raise RunnerError("configuration_error: treatment command introduced a forbidden provider or MCP surface")
    return command


def assert_command_parity(executable: Path, config: dict[str, Any], state_dir: Path, schema_path: Path, repository: Path) -> list[str]:
    baseline = build_baseline_command(executable, frozen_baseline_config(), state_dir, schema_path, repository)
    treatment = build_treatment_command(executable, config, state_dir, schema_path, repository)
    if treatment != baseline:
        raise RunnerError("configuration_error: treatment Codex command differs from baseline")
    return treatment
