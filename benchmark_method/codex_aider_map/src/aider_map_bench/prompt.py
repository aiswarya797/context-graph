"""Byte-preserving neutral RepoMap prompt construction."""

from __future__ import annotations

import hashlib
from typing import Any

from context_graph_bench.codex_runner import RunnerError, build_prompt as build_baseline_prompt

from .binding import BoundMap


ISSUE_MARKER = "Issue:\n{{problem_statement}}"
NEUTRAL_WRAPPER_PREFIX = """A precomputed Aider RepoMap for this exact repository revision appears below.
It is a partial ranked view, not an authoritative list of relevant files.
Use it if useful. Normal read-only repository inspection remains available,
and omitted files may still matter.

<aider_repo_map>
"""
NEUTRAL_WRAPPER_SUFFIX = """
</aider_repo_map>
"""


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def build_treatment_prompt(template: str, issue_text: str, bound_map: BoundMap) -> tuple[str, dict[str, Any]]:
    """Build a treatment prompt whose only delta is wrapper plus map bytes."""
    if template.count(ISSUE_MARKER) != 1:
        raise RunnerError("configuration_error: baseline prompt lacks one exact issue marker")
    if not isinstance(issue_text, str) or sha256(issue_text.encode("utf-8")) != bound_map.issue_sha256:
        raise RunnerError("map_authority_refused: prompt issue bytes differ from bound map")
    map_section = NEUTRAL_WRAPPER_PREFIX + bound_map.map_text + NEUTRAL_WRAPPER_SUFFIX
    treatment_template = template.replace(ISSUE_MARKER, map_section + "\n" + ISSUE_MARKER)
    baseline = build_baseline_prompt(template, issue_text)
    prompt = build_baseline_prompt(treatment_template, issue_text)
    recovered = prompt.replace(map_section + "\n", "", 1)
    if recovered != baseline:
        raise RunnerError("configuration_error: treatment prompt is not baseline-parity exact after map removal")
    metadata = {
        "baseline_prompt_template_sha256": sha256(template.encode("utf-8")),
        "baseline_final_prompt_sha256": sha256(baseline.encode("utf-8")),
        "neutral_wrapper_prefix_sha256": sha256(NEUTRAL_WRAPPER_PREFIX.encode("utf-8")),
        "neutral_wrapper_suffix_sha256": sha256(NEUTRAL_WRAPPER_SUFFIX.encode("utf-8")),
        "map_sha256": bound_map.map_sha256,
        "issue_sha256": bound_map.issue_sha256,
        "final_prompt_sha256": sha256(prompt.encode("utf-8")),
        "final_prompt_byte_count": len(prompt.encode("utf-8")),
        "prompt_parity_after_map_removal": True,
        "map_section_occurrences": prompt.count("<aider_repo_map>"),
        "issue_occurrences": prompt.count(issue_text),
    }
    if metadata["map_section_occurrences"] != 1 or metadata["issue_occurrences"] != 1:
        raise RunnerError("configuration_error: prompt map or issue is not delivered exactly once")
    return prompt, metadata
