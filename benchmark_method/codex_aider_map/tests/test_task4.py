from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT / "benchmark_method" / "codex_aider_map" / "src"), str(ROOT / "benchmark_method" / "codex_baseline" / "src")]

from aider_map_bench.binding import BoundMap, MapBindingError, bind_map
from aider_map_bench.attempt import finalize_attempt_telemetry, persist_attempt_inputs, plan_attempt
from aider_map_bench.lifecycle import LifecycleError, audit_attempt, compare, execute_attempt, next_attempt_number, run_treatment, smoke_gate
import aider_map_bench.lifecycle as lifecycle
from aider_map_bench.navigation import replay_navigation
from aider_map_bench.prompt import NEUTRAL_WRAPPER_PREFIX, build_treatment_prompt
from aider_map_bench.runner import assert_command_parity, frozen_baseline_config
from context_graph_bench.codex_runner import RunnerError, build_command as build_baseline_command
from context_graph_bench.corpus import compile_corpus

_SPEC = importlib.util.spec_from_file_location("aider_map_treatment_cli", ROOT / "benchmark_method" / "codex_aider_map" / "benchmark.py")
assert _SPEC and _SPEC.loader
treatment_cli = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(treatment_cli)


class Task4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks, _ = compile_corpus(ROOT / "benchmark_method" / "common" / "inputs" / "sources")
        cls.task = next(task for task in cls.tasks if task["instance_id"] == "astral-sh__ruff-15330")
        cls.template = (ROOT / "benchmark_method" / "codex_baseline" / "config" / "region-selection-prompt.md").read_text()
        cls.frozen_schema = ROOT / "benchmark_method" / "common" / "schemas" / "agent-regions.schema.json"
        cls.frozen_auth_source = Path(treatment_cli.load_config()["paths"]["codex_auth_source"])

    @contextmanager
    def synthetic_runtime(self, root: Path):
        """Provide a real lifecycle seam with only the provider boundary faked."""
        source, child_repo = root / "source", root / "child"
        source.mkdir(); child_repo.mkdir()
        (source / ".git").mkdir()
        (source / "x.py").write_text("one\n")
        (child_repo / "x.py").write_text("one\n")
        schema = self.frozen_schema
        task = dict(self.task, prepared={"resolved_path": str(source)})
        snapshot = {"path": str(child_repo), "mirror_path": str(root / "mirror"), "head": task["base_commit"], "clean": True}

        def fake_runtime(work, auth):
            home, state = work / "home", work / "state"
            home.mkdir(parents=True); state.mkdir(parents=True)
            return home, state

        with patch.object(lifecycle, "resolve_executable", return_value=Path("/bin/echo")), patch.object(lifecycle, "file_sha256", return_value="1da3f4e0e96028b8a771814293c3033dafd1971f943f6c7e79b0897fe705f590"), patch.object(lifecycle, "verify_pinned_version", return_value="0.145.0"), patch.object(lifecycle, "verify_official_evaluator", return_value={"sha256":"feea0a7fe67b08e68c940e10887d5b4feaae0b8c58e256eb09f253e65492d745"}), patch.object(lifecycle, "validate_auth_source"), patch.object(lifecycle, "verify_repository_head"), patch.object(lifecycle, "prepare_isolated_repository", return_value=snapshot), patch.object(lifecycle, "remove_isolated_repository"), patch.object(lifecycle, "create_runtime_dirs", side_effect=fake_runtime):
            yield task, schema

    @staticmethod
    def valid_child(command, prompt, state, events, stderr, timeout, **kwargs):
        events.write_text("\n".join([json.dumps({"type":"thread.started"}), json.dumps({"type":"item.completed", "item":{"id":"1","type":"command_execution","command":"cat x.py","aggregated_output":"one","exit_code":0,"status":"completed"}}), json.dumps({"type":"item.completed", "item":{"type":"agent_message"}}), json.dumps({"type":"turn.completed", "usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":1,"reasoning_output_tokens":0}})]))
        stderr.write_text("")
        (state / "response.json").write_text(json.dumps({"regions":[{"path":"x.py","start":1,"end":1,"reason":"evidence"}]}))
        return {"returncode":0,"timed_out":False,"sandboxed":True,"telemetry":{"valid":True,"provider_turn_valid":True}}

    def test_all_real_maps_bind_exact_corpus_inputs(self) -> None:
        bindings = [bind_map(task) for task in self.tasks]
        self.assertEqual(24, len(bindings))
        self.assertEqual(24, len({item.task_id for item in bindings}))
        self.assertTrue(all(item.map_text.strip() for item in bindings))
        self.assertTrue(all(item.manifest_sha256 == "462ff73cb27a2b2974c85de5354ac3d0efdc71bdad3e5618882890b6e921d21f" for item in bindings))
        self.assertTrue(all(item.phase_freeze_sha256 == "6bd0cbeb57666edb35b1a3b2bcaf7ea0c83b440a961522df39e1c2102ee5ecc3" for item in bindings))
        self.assertTrue(all(item.task3_seal_sha256 == "cf80a7afbcd523062afc2b3504e8f5f3e1b5ae9af484e6e6925a4e6f64b332d6" for item in bindings))
        manifest = json.loads((ROOT / ".benchmark-work" / "aider-map" / "maps-v3" / "manifest.json").read_text(encoding="utf-8"))
        entries = {entry["task_id"]: entry for entry in manifest["entries"]}
        for task, bound in zip(self.tasks, bindings, strict=True):
            with self.subTest(task_id=task["instance_id"]):
                entry = entries[task["instance_id"]]
                prompt, metadata = build_treatment_prompt(self.template, task["issue_text"], bound)
                self.assertEqual(task["instance_id"], bound.task_id)
                self.assertEqual(task["base_commit"], bound.base_commit)
                self.assertEqual(hashlib.sha256(task["issue_text"].encode()).hexdigest(), bound.issue_sha256)
                self.assertEqual(bound.map_sha256, metadata["map_sha256"])
                self.assertEqual(f".benchmark-work/aider-map/maps-v3/official/{bound.task_id}", bound.artifact_directory)
                self.assertEqual("FIRST_TECHNICALLY_VALID_OUTPUT", entry["selection_policy"])
                self.assertEqual(1, entry["official_attempt_ordinal"])
                self.assertTrue(entry["accepted_immediately"])
                self.assertEqual([], entry["selection_signals_inspected"])
                self.assertFalse(entry["resume"])
                self.assertEqual(bound.map_sha256, entry["map"]["returned_string_sha256"])
                self.assertTrue(metadata["prompt_parity_after_map_removal"])
                self.assertEqual(1, metadata["map_section_occurrences"])
                self.assertEqual(1, metadata["issue_occurrences"])
                self.assertEqual(1, prompt.count(NEUTRAL_WRAPPER_PREFIX))

    def test_all_72_sample_plans_reuse_the_per_task_frozen_map_identity(self) -> None:
        config = treatment_cli.load_config()
        sample_identities = []
        for task in self.tasks:
            plans = [
                plan_attempt(
                    task,
                    config,
                    executable=Path("/bin/echo"),
                    state_dir=Path("/private/tmp/task4-cycle3-state"),
                    schema_path=self.frozen_schema,
                    repository=Path("/private/tmp/task4-cycle3-repository"),
                    baseline_template=self.template,
                    run_id="task4-cycle3-binding-only",
                    sample_id=sample_id,
                    attempt_number=1,
                )
                for sample_id in (1, 2, 3)
            ]
            identities = {(plan.bound_map.map_sha256, plan.bound_map.record_sha256, plan.bound_map.artifact_directory) for plan in plans}
            with self.subTest(task_id=task["instance_id"]):
                self.assertEqual(1, len(identities))
                self.assertEqual([1, 2, 3], [plan.metadata["sample_id"] for plan in plans])
                self.assertTrue(all(plan.metadata["map"]["map_sha256"] == plans[0].bound_map.map_sha256 for plan in plans))
            sample_identities.extend((task["instance_id"], plan.metadata["sample_id"], plan.bound_map.map_sha256) for plan in plans)
        self.assertEqual(72, len(sample_identities))
        self.assertEqual(24, len({task_id for task_id, _, _ in sample_identities}))

    def test_prompt_delta_is_only_neutral_map_section(self) -> None:
        bound = bind_map(self.task)
        prompt, metadata = build_treatment_prompt(self.template, self.task["issue_text"], bound)
        self.assertTrue(metadata["prompt_parity_after_map_removal"])
        self.assertEqual(1, prompt.count(NEUTRAL_WRAPPER_PREFIX))
        self.assertEqual(1, prompt.count(self.task["issue_text"]))
        self.assertEqual(bound.map_sha256, metadata["map_sha256"])

    def test_wrong_issue_refuses_before_prompt(self) -> None:
        bound = bind_map(self.task)
        altered = dict(self.task, issue_text=self.task["issue_text"] + "x")
        with self.assertRaises(RunnerError):
            build_treatment_prompt(self.template, altered["issue_text"], bound)

    def test_real_map_tamper_refuses(self) -> None:
        bound = bind_map(self.task)
        real_read_bytes = Path.read_bytes
        with patch.object(Path, "read_bytes", new=lambda path: b"tampered" if path.name == "repo-map.txt" else real_read_bytes(path)):
            with self.assertRaises(MapBindingError):
                bind_map(self.task)
        self.assertTrue(bound.map_text)

    def test_command_is_exact_baseline_command_and_has_normal_shell(self) -> None:
        config = treatment_cli.load_config()
        executable, state, schema, repository = Path("/bin/echo"), Path("/tmp/state"), Path("/tmp/schema.json"), Path("/tmp/repo")
        command = assert_command_parity(executable, config, state, schema, repository)
        self.assertEqual(build_baseline_command(executable, frozen_baseline_config(), state, schema, repository), command)
        self.assertIn("shell_tool", command)
        self.assertNotIn("mcp_servers.codegraph", "\n".join(command))
        self.assertNotIn("aider", "\n".join(command).lower())

    def test_production_refuses_parity_or_schema_mutations_before_child(self) -> None:
        base = treatment_cli.load_config()
        calls = 0

        def never_child(*args, **kwargs):
            nonlocal calls
            calls += 1
            raise AssertionError("configuration refusal must precede the child seam")

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.synthetic_runtime(root) as (task, schema):
                cases = []
                model = json.loads(json.dumps(base)); model["treatment"]["model"] = "other-model"; cases.append(("model", model, schema))
                timeout = json.loads(json.dumps(base)); timeout["treatment"]["timeout_seconds"] += 1; cases.append(("timeout", timeout, schema))
                executable = json.loads(json.dumps(base)); executable["paths"]["codex_executable"] = "/tmp/not-the-frozen-codex"; cases.append(("path", executable, schema))
                bad_schema = root / "bad-schema.json"; bad_schema.write_text("{}")
                cases.append(("schema", base, bad_schema))
                for name, config, selected_schema in cases:
                    with self.subTest(name=name), self.assertRaises((RunnerError, LifecycleError)):
                        run_treatment(root, [task], config, run_id=f"mutation-{name}", schema_path=selected_schema, baseline_template=self.template, auth_source=self.frozen_auth_source, samples=1, child=never_child)
        self.assertEqual(0, calls)

    def test_navigation_replay_counts_commands_and_refuses_unknown(self) -> None:
        events = "\n".join([
            json.dumps({"type": "thread.started"}),
            json.dumps({"type": "item.completed", "item": {"id": "1", "type": "command_execution", "command": "rg token src", "aggregated_output": "x", "exit_code": 0, "status": "completed"}}),
            json.dumps({"type": "item.completed", "item": {"id": "2", "type": "command_execution", "command": "sed -n '1,5p' src/x.py", "aggregated_output": "x", "exit_code": 0, "status": "completed"}}),
            json.dumps({"type": "item.completed", "item": {"type": "agent_message"}}),
            json.dumps({"type": "turn.completed", "usage": {"input_tokens": 1}}),
        ])
        replay = replay_navigation(events)
        self.assertTrue(replay["valid"])
        self.assertEqual(2, replay["repository_navigation_calls"])
        self.assertEqual(1, replay["search_calls"])
        self.assertEqual(1, replay["source_read_calls"])
        self.assertFalse(replay_navigation('{"type":"provider.magic"}')["valid"])
        malformed_completed = json.dumps({"type": "item.completed", "item": {"id": "1", "type": "command_execution", "command": "rg token src"}})
        self.assertFalse(replay_navigation(malformed_completed)["valid"])

    def test_all_72_frozen_baseline_event_streams_replay_with_bound_counts(self) -> None:
        events_root = ROOT / ".benchmark-runs" / "baseline-20260725-final-20260725T204500Z" / "attempts"
        streams = sorted(events_root.glob("**/events.jsonl"))
        self.assertEqual(72, len(streams))
        replays = [replay_navigation(stream.read_text(encoding="utf-8")) for stream in streams]
        self.assertTrue(all(replay["valid"] for replay in replays), [replay for replay in replays if not replay["valid"]])
        aggregate = {key: sum(replay[key] for replay in replays) for key in ("total_tool_calls", "repository_navigation_calls", "search_calls", "source_read_calls", "other_inspection_calls")}
        self.assertEqual({"total_tool_calls": 651, "repository_navigation_calls": 651, "search_calls": 121, "source_read_calls": 404, "other_inspection_calls": 126}, aggregate)
        representative = replay_navigation((events_root / "axios__axios-4731" / "sample-02" / "attempt-001" / "events.jsonl").read_text(encoding="utf-8"))
        self.assertTrue(representative["valid"])
        self.assertEqual({"repository_navigation_calls": 6, "search_calls": 1, "source_read_calls": 5, "other_inspection_calls": 0}, {key: representative[key] for key in ("repository_navigation_calls", "search_calls", "source_read_calls", "other_inspection_calls")})

    def test_navigation_replay_counts_other_inspection(self) -> None:
        events = "\n".join([
            json.dumps({"type":"item.completed", "item":{"id":"1","type":"command_execution","command":"pwd","aggregated_output":"/repo","exit_code":0,"status":"completed"}}),
            json.dumps({"type":"item.completed", "item":{"type":"agent_message"}}),
        ])
        replay = replay_navigation(events)
        self.assertTrue(replay["valid"])
        self.assertEqual(1, replay["total_tool_calls"])
        self.assertEqual(1, replay["repository_navigation_calls"])
        self.assertEqual(1, replay["other_inspection_calls"])
        self.assertFalse(replay_navigation('{not-json')["valid"])

    def test_attempt_plan_persists_prompt_and_never_leaks_map_to_child(self) -> None:
        config = treatment_cli.load_config()
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            schema = root / "schema.json"
            schema.write_text("{}")
            plan = plan_attempt(self.task, config, executable=Path("/bin/echo"), state_dir=root / "state", schema_path=schema, repository=root / "repo", baseline_template=self.template, run_id="dry", sample_id=1, attempt_number=1)
            persisted = persist_attempt_inputs(plan, root / "attempt")
        self.assertFalse(plan.metadata["child_receives_map_path"])
        self.assertTrue(plan.metadata["child_receives_map_text_only_in_prompt"])
        self.assertEqual(plan.prompt_metadata["final_prompt_sha256"], persisted["prompt_sha256"])
        self.assertEqual(0, plan.metadata["aider_agent_in_child"])

    def test_replay_retains_raw_identity_and_refuses_unknown(self) -> None:
        events = json.dumps({"type": "turn.completed", "usage": {"input_tokens": 1}})
        result = finalize_attempt_telemetry(events, "stderr")
        self.assertTrue(result["raw_events_retained"])
        with self.assertRaises(RunnerError):
            finalize_attempt_telemetry('{"type":"mystery"}', "")

    def test_injected_executor_retains_raw_prompt_map_response_and_admission(self) -> None:
        config = treatment_cli.load_config()
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            schema = root / "schema.json"
            schema.write_text("{}")
            repository = root / "repo"
            repository.mkdir()
            (repository / "x.py").write_text("one\n")
            state = root / "state"
            state.mkdir()
            def fake_child(command, prompt, state_dir, events, stderr, timeout, **kwargs):
                events.write_text("\n".join([json.dumps({"type":"thread.started"}), json.dumps({"type":"item.completed", "item":{"id":"1","type":"command_execution","command":"cat x.py","aggregated_output":"one","exit_code":0,"status":"completed"}}), json.dumps({"type":"item.completed", "item":{"type":"agent_message"}}), json.dumps({"type":"turn.completed", "usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":1,"reasoning_output_tokens":0}})]))
                stderr.write_text("stderr")
                (state_dir / "response.json").write_text(json.dumps({"regions":[{"path":"x.py","start":1,"end":1,"reason":"evidence"}]}))
                return {"returncode": 0, "timed_out": False, "telemetry": {"valid": True}}
            record = execute_attempt(self.task, config, executable=Path("/bin/echo"), state_dir=state, schema_path=schema, repository=repository, private_home=root / "home", baseline_template=self.template, attempt_root=root / "attempt", run_id="dry", sample_id=1, attempt_number=1, child=fake_child)
        self.assertTrue(record["quality_valid"])

    def test_retry_slots_and_comparison_fail_closed(self) -> None:
        prior = [{"metadata": {"task_id": "t", "sample_id": 1}, "quality_valid": False}]
        self.assertEqual(2, next_attempt_number(prior, "t", 1, 2))
        with self.assertRaises(LifecycleError):
            next_attempt_number(prior + [{"metadata": {"task_id": "t", "sample_id": 1}, "quality_valid": True}], "t", 1, 2)
        matched = compare([{"task_id": "t", "sample_id": 1, "quality_valid": True}], [{"metadata": {"task_id": "t", "sample_id": 1}, "quality_valid": True}])
        self.assertTrue(matched["matched"])
        with self.assertRaises(LifecycleError):
            compare([{"task_id": "t", "sample_id": 1, "quality_valid": True}], [])

    def test_real_retry_retains_unknown_navigation_attempt_then_admits_attempt_two(self) -> None:
        config = treatment_cli.load_config()
        calls = 0

        def child(command, prompt, state, events, stderr, timeout, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                events.write_text(json.dumps({"type": "provider.unknown"}))
            else:
                self.valid_child(command, prompt, state, events, stderr, timeout, **kwargs)
                return {"returncode":0,"timed_out":False,"sandboxed":True,"telemetry":{"valid":True,"provider_turn_valid":True}}
            stderr.write_text("unknown navigation retained")
            (state / "response.json").write_text(json.dumps({"regions":[{"path":"x.py","start":1,"end":1,"reason":"evidence"}]}))
            return {"returncode":0,"timed_out":False,"sandboxed":True,"telemetry":{"valid":True,"provider_turn_valid":True}}

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.synthetic_runtime(root) as (task, schema):
                result = run_treatment(root, [task], config, run_id="retry", schema_path=schema, baseline_template=self.template, auth_source=self.frozen_auth_source, samples=1, child=child)
            run = root / ".benchmark-runs" / "retry"
            records = [json.loads(line) for line in (run / "attempts.jsonl").read_text().splitlines()]
            attempts = [run / record["artifact_paths"]["attempt"] for record in records]
            raw_artifacts_retained = [all((attempt / name).is_file() for name in ("events.jsonl", "stderr.log", "response.json")) for attempt in attempts]
        self.assertEqual(2, result["attempts"])
        self.assertEqual(2, calls)
        self.assertEqual(["attempt-001", "attempt-002"], [record["attempt_id"] for record in records])
        self.assertFalse(records[0]["quality_valid"])
        self.assertEqual("navigation_replay_refused", records[0]["failure_class"])
        self.assertTrue(records[1]["quality_valid"])
        self.assertEqual(1, sum(record["quality_valid"] for record in records))
        self.assertEqual([True, True], raw_artifacts_retained)

    def test_baseline_golden_events_replay(self) -> None:
        fixture = (ROOT / "benchmark_method" / "codex_baseline" / "tests" / "fixtures" / "golden-events.jsonl").read_text()
        replay = replay_navigation(fixture)
        self.assertTrue(replay["valid"])
        self.assertEqual(0, replay["repository_navigation_calls"])

    def test_frozen_authority_refusals(self) -> None:
        import aider_map_bench.binding as binding
        missing = Path("/private/tmp/no-such-aider-map-authority.json")
        for name in ("MANIFEST", "PHASE_FREEZE", "GENERATION_REPORT", "TASK3_SEAL", "SOURCE_LOCK"):
            with self.subTest(name=name), patch.object(binding, name, missing):
                with self.assertRaises(MapBindingError):
                    bind_map(self.task)
        with self.assertRaises(MapBindingError):
            bind_map(dict(self.task, base_commit="0" * 40))
        with self.assertRaises(MapBindingError):
            bind_map(dict(self.task, issue_text=self.task["issue_text"] + "changed"))
        original_load_json = binding._load_json
        manifest = json.loads(binding.MANIFEST.read_text(encoding="utf-8"))
        for field, value in (("selection_policy", "BEST_COVERAGE_OUTPUT"), ("official_attempt_ordinal", 2), ("accepted_immediately", False), ("selection_signals_inspected", ["coverage"]), ("resume", True), ("automatic_retry", True), ("coverage_visible_at_selection", True)):
            with self.subTest(field=field):
                tampered = json.loads(json.dumps(manifest))
                target = tampered["entries"][0] if field in {"selection_policy", "official_attempt_ordinal", "accepted_immediately", "selection_signals_inspected", "resume"} else tampered
                target[field] = value

                def load_json(path, label):
                    return tampered if path == binding.MANIFEST else original_load_json(path, label)

                with patch.object(binding, "_load_json", side_effect=load_json), self.assertRaises(MapBindingError):
                    bind_map(self.task)
        report = json.loads(binding.GENERATION_REPORT.read_text(encoding="utf-8"))
        for field, value in (("selection_policy", "BEST_COVERAGE_OUTPUT"), ("official_attempt_count", 23), ("entries", []), ("source_freeze", {})):
            with self.subTest(generation_report_field=field):
                tampered = json.loads(json.dumps(report))
                tampered[field] = value

                def load_json(path, label):
                    return tampered if path == binding.GENERATION_REPORT else original_load_json(path, label)

                with patch.object(binding, "_load_json", side_effect=load_json), self.assertRaises(MapBindingError):
                    bind_map(self.task)

    def test_real_resume_refuses_stale_manifest_and_corpus_bytes(self) -> None:
        config = treatment_cli.load_config()
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.synthetic_runtime(root) as (task, schema):
                run_treatment(root, [task], config, run_id="resume", schema_path=schema, baseline_template=self.template, auth_source=self.frozen_auth_source, samples=1, child=self.valid_child)
                run = root / ".benchmark-runs" / "resume"
                manifest = run / "run-manifest.json"
                original_manifest = manifest.read_bytes()
                stale = json.loads(original_manifest)
                stale["timeout_seconds"] += 1
                manifest.write_text(json.dumps(stale))
                with self.assertRaisesRegex(LifecycleError, "stale or foreign"):
                    run_treatment(root, [task], config, run_id="resume", schema_path=schema, baseline_template=self.template, auth_source=self.frozen_auth_source, samples=1, child=self.valid_child)
                manifest.write_bytes(original_manifest)
                corpus = run / "corpus.jsonl"
                original_corpus = corpus.read_bytes()
                corpus.write_bytes(original_corpus + b" ")
                with self.assertRaisesRegex(LifecycleError, "mismatched corpus"):
                    run_treatment(root, [task], config, run_id="resume", schema_path=schema, baseline_template=self.template, auth_source=self.frozen_auth_source, samples=1, child=self.valid_child)

    def test_production_refuses_nonempty_partial_run_root_without_manifest(self) -> None:
        config = treatment_cli.load_config()
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            partial = root / ".benchmark-runs" / "partial"
            partial.mkdir(parents=True)
            (partial / "untracked.txt").write_text("not a run")
            with self.synthetic_runtime(root) as (task, schema):
                with self.assertRaisesRegex(LifecycleError, "nonempty run root lacks run manifest"):
                    run_treatment(root, [task], config, run_id="partial", schema_path=schema, baseline_template=self.template, auth_source=self.frozen_auth_source, samples=1, child=self.valid_child)

    def test_flat_persisted_attempt_audit_rejects_independent_prompt_identity_and_corpus_tampering(self) -> None:
        config = treatment_cli.load_config()
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.synthetic_runtime(root) as (task, schema):
                result = run_treatment(root, [task], config, run_id="synthetic", schema_path=schema, baseline_template=self.template, auth_source=self.frozen_auth_source, samples=1, child=self.valid_child)
            run = root / ".benchmark-runs" / "synthetic"
            record = json.loads((run / "attempts.jsonl").read_text().splitlines()[0])
            attempt = run / record["artifact_paths"]["attempt"]
            attempt_record = attempt / "attempt.json"
            original_prompt = (attempt / "prompt.md").read_bytes()
            original_identity = (attempt / "map-prompt-identity.json").read_bytes()
            original_corpus = (run / "corpus.jsonl").read_bytes()
            clean = audit_attempt(attempt_record)
            (attempt / "prompt.md").write_bytes(original_prompt + b"tamper")
            prompt_tampered = audit_attempt(attempt_record)
            (attempt / "prompt.md").write_bytes(original_prompt)
            identity = json.loads(original_identity)
            identity["metadata"]["child_receives_map_path"] = True
            (attempt / "map-prompt-identity.json").write_text(json.dumps(identity))
            identity_tampered = audit_attempt(attempt_record)
            (attempt / "map-prompt-identity.json").write_bytes(original_identity)
            (attempt / "map-prompt-identity.json").write_bytes(b"{")
            malformed_identity = audit_attempt(attempt_record)
            (attempt / "map-prompt-identity.json").write_bytes(original_identity)
            (run / "corpus.jsonl").write_bytes(original_corpus + b" ")
            corpus_tampered = audit_attempt(attempt_record)
            (run / "corpus.jsonl").write_bytes(original_corpus)
        self.assertEqual(1, result["attempts"])
        self.assertEqual("attempt-001", record["attempt_id"])
        self.assertIn("prompt", record["artifact_paths"])
        self.assertTrue(record["quality_valid"])
        self.assertTrue(clean["response_valid"])
        self.assertTrue(clean["passed"], clean)
        self.assertFalse(prompt_tampered["passed"])
        self.assertFalse(identity_tampered["passed"])
        self.assertFalse(malformed_identity["passed"])
        self.assertIn("malformed_map_prompt_identity", malformed_identity["audit_error"])
        self.assertFalse(corpus_tampered["passed"])

    def test_no_argument_operations_report_preflight_only(self) -> None:
        for command in ("doctor", "smoke", "inspect-smoke", "smoke-gate", "run", "score", "report", "compare", "audit"):
            self.assertEqual(0, treatment_cli.main([command]))


if __name__ == "__main__":
    unittest.main()
