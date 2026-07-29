from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(REPO / "benchmark_method" / "codex_baseline" / "src"))

from codegraph_bench.codegraph_events import (
    LIVE_CODEGRAPH_ENVELOPE,
    REAL_ENVELOPE_INTEGRATION,
    parse_navigation_events,
)
from context_graph_bench.telemetry import parse_events


FIXTURES = ROOT / "tests" / "fixtures" / "codegraph_events"
TINY_REPO = ROOT / "tests" / "fixtures" / "tiny_repo"
LIVE_MISSING_TOOL_FIXTURE = (
    "codex-0.145.0-live-missing-codegraph-2c98ead63ed2.min.jsonl"
)
LIVE_FIXTURE_SHA256 = "d26e98c7e494eb4bc076401bf7ca578037900509614aa2914b311119715d060f"
LIVE_CODEGRAPH_FIXTURE = (
    "codex-0.145.0-live-codegraph-65618298ef2b.min.jsonl"
)
LIVE_CODEGRAPH_FIXTURE_SHA256 = (
    "cd922aabdf26f825351f8b5f8228c8e12159f62242d4ff201ed0e2d08ba11b44"
)
LIVE_PROVENANCE = json.loads(
    (FIXTURES / "codex-0.145.0-live-provenance.json").read_text(
        encoding="utf-8"
    )
)


def live_codegraph_trace(content: str, *, query: str = "route_request") -> str:
    arguments = {
        "projectPath": "/repo",
        "query": query,
        "maxFiles": 12,
    }
    return "\n".join(
        [
            json.dumps(
                {
                    "type": "item.started",
                    "item": {
                        "id": "cg",
                        "type": "mcp_tool_call",
                        "server": "codegraph",
                        "tool": "codegraph_explore",
                        "arguments": arguments,
                        "result": None,
                        "error": None,
                        "status": "in_progress",
                    },
                }
            ),
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {
                        "id": "cg",
                        "type": "mcp_tool_call",
                        "server": "codegraph",
                        "tool": "codegraph_explore",
                        "arguments": arguments,
                        "result": {
                            "content": [{"type": "text", "text": content}],
                            "structured_content": None,
                        },
                        "error": None,
                        "status": "completed",
                    },
                }
            ),
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {
                        "id": "answer",
                        "type": "agent_message",
                        "text": '{"regions":[]}',
                    },
                }
            ),
        ]
    )


class CodeGraphEventTests(unittest.TestCase):
    def parse(self, name: str):
        return parse_navigation_events(
            (FIXTURES / name).read_text(encoding="utf-8"),
            TINY_REPO,
            expected_project=Path("/repo"),
            allowed_runtime_roots=[Path("/runtime")],
        )

    def test_success_requires_completed_call_and_counts_fallback(self):
        summary = self.parse("successful.jsonl")
        self.assertTrue(summary["graph_use_valid"])
        self.assertEqual(summary["successful_tool_call_count"], 1)
        self.assertEqual(summary["fallback_navigation_after_graph"], 1)
        self.assertEqual(summary["queries"], ["find request routing"])
        self.assertEqual(summary["returned_paths"], ["src/module.py"])
        self.assertIsNone(summary["real_envelope_integration"])

    def test_connected_without_call_is_not_used(self):
        summary = self.parse("not-used.jsonl")
        self.assertEqual(summary["failure_class"], "codegraph_not_used")
        self.assertEqual(summary["built_in_navigation_before_graph"], 1)

    def test_failed_call_is_tool_failure(self):
        summary = self.parse("tool-failed.jsonl")
        self.assertEqual(summary["failure_class"], "codegraph_tool_failure")
        self.assertEqual(summary["failed_tool_call_count"], 1)

    def test_wrong_project_is_distinct(self):
        self.assertEqual(self.parse("wrong-project.jsonl")["failure_class"], "codegraph_wrong_project")

    def test_unknown_mcp_shape_fails_closed(self):
        text = (FIXTURES / "unknown-shape.jsonl").read_text(encoding="utf-8")
        summary = self.parse("unknown-shape.jsonl")
        self.assertEqual(summary["failure_class"], "unknown_event_shape")
        self.assertFalse(summary["graph_use_valid"])
        self.assertTrue(parse_events(text)["valid"], "navigation refusal must not corrupt independent provider usage")

    def test_prior_response_access_is_contamination(self):
        summary = self.parse("benchmark-output-access.jsonl")
        self.assertEqual(summary["failure_class"], "benchmark_output_access")

    def test_repository_file_named_response_json_is_not_automatically_contamination(self):
        text = "\n".join(
            [
                '{"type":"item.completed","item":{"type":"mcp_server_status","server":"codegraph","status":"connected","tools":["codegraph_explore"]}}',
                '{"type":"item.completed","item":{"type":"mcp_tool_call","server":"codegraph","tool":"codegraph_explore","arguments":{"query":"fixture"},"result":{"content":"src/module.py:1","is_error":false,"project_root":"/repo","paths":["src/module.py"]},"status":"completed"}}',
                '{"type":"item.completed","item":{"id":"answer","type":"agent_message","text":"{\\"regions\\":[]}"}}',
            ]
        )
        summary = parse_navigation_events(text, TINY_REPO, expected_project=Path("/repo"))
        self.assertTrue(summary["graph_use_valid"])

    def test_missing_server_is_startup_failure(self):
        summary = parse_navigation_events('{"type":"turn.completed","usage":{}}', Path("/repo"))
        self.assertEqual(summary["failure_class"], "mcp_startup_failure")

    def test_live_0145_missing_codegraph_trace_is_retained_as_negative_evidence(self):
        fixture = FIXTURES / LIVE_MISSING_TOOL_FIXTURE
        payload = fixture.read_bytes()
        self.assertEqual(hashlib.sha256(payload).hexdigest(), LIVE_FIXTURE_SHA256)
        provenance = LIVE_PROVENANCE["fixtures"][LIVE_MISSING_TOOL_FIXTURE]
        self.assertEqual(provenance["fixture_sha256"], LIVE_FIXTURE_SHA256)
        self.assertIn(
            provenance["source_capture_sha256"][:12],
            LIVE_MISSING_TOOL_FIXTURE,
        )
        summary = parse_navigation_events(
            payload.decode(),
            TINY_REPO,
            expected_project=Path("/repo"),
            allowed_runtime_roots=[Path("/runtime")],
        )
        self.assertEqual(summary["parser_envelope"], "codex-0.145.0-observed-partial-mcp-v1")
        self.assertIsNone(summary["real_envelope_integration"])
        self.assertEqual(summary["failure_class"], "mcp_startup_failure")
        self.assertEqual(summary["built_in_navigation_before_graph"], 1)
        self.assertEqual(summary["unknown_mcp_events"], [])
        self.assertEqual(summary["outside_repository_accesses"], [])
        self.assertFalse(summary["graph_use_valid"])

    def test_live_envelope_integration_gate_is_closed(self):
        self.assertEqual(REAL_ENVELOPE_INTEGRATION, LIVE_CODEGRAPH_ENVELOPE)

    def test_live_0145_codegraph_call_uses_observed_envelope(self):
        content = (
            "**Exploration: route_request**\n\n"
            "**`src/module.py`** — route_request(function)\n\n"
            "```python\n1\\tdef route_request(path: str) -> str:\n```\n"
        )
        text = "\n".join(
            [
                '{"type":"item.completed","item":{"id":"note","type":"agent_message","text":"Calling CodeGraph first."}}',
                json.dumps(
                    {
                        "type": "item.started",
                        "item": {
                            "id": "cg",
                            "type": "mcp_tool_call",
                            "server": "codegraph",
                            "tool": "codegraph_explore",
                            "arguments": {
                                "projectPath": "/repo",
                                "query": "route_request",
                                "maxFiles": 12,
                            },
                            "result": None,
                            "error": None,
                            "status": "in_progress",
                        },
                    }
                ),
                json.dumps(
                    {
                        "type": "item.completed",
                        "item": {
                            "id": "cg",
                            "type": "mcp_tool_call",
                            "server": "codegraph",
                            "tool": "codegraph_explore",
                            "arguments": {
                                "projectPath": "/repo",
                                "query": "route_request",
                                "maxFiles": 12,
                            },
                            "result": {
                                "content": [{"type": "text", "text": content}],
                                "structured_content": None,
                            },
                            "error": None,
                            "status": "completed",
                        },
                    }
                ),
                '{"type":"item.completed","item":{"id":"answer","type":"agent_message","text":"{\\"regions\\":[]}"}}',
            ]
        )
        summary = parse_navigation_events(
            text,
            TINY_REPO,
            expected_project=Path("/repo"),
        )
        self.assertTrue(summary["graph_use_valid"])
        self.assertEqual(
            summary["real_envelope_integration"],
            "codex-0.145.0-live-codegraph-mcp-v1",
        )
        self.assertEqual(summary["returned_paths"], ["src/module.py"])
        self.assertEqual(summary["final_response_event_position"], 4)

    def test_live_result_source_text_is_not_filesystem_access(self):
        content = (
            "**Exploration: route_request**\n\n"
            "**`src/module.py`** — route_request(function)\n\n"
            "References: https://pypi.org/simple and "
            "<https://github.com/example/project>.\n"
            "</summary>\n"
            "# /// script\n"
        )
        summary = parse_navigation_events(
            live_codegraph_trace(
                content,
                query="explain https://example.com/summary",
            ),
            TINY_REPO,
            expected_project=Path("/repo"),
        )
        self.assertTrue(summary["graph_use_valid"])
        self.assertEqual(summary["outside_repository_accesses"], [])
        self.assertEqual(summary["prohibited_benchmark_accesses"], [])
        self.assertEqual(summary["returned_paths"], ["src/module.py"])

    def test_command_output_source_text_is_not_filesystem_access(self):
        graph_events = live_codegraph_trace(
            "**`src/module.py`** — route_request(function)\n"
        ).splitlines()
        command = json.dumps(
            {
                "type": "item.completed",
                "item": {
                    "id": "fallback",
                    "type": "command_execution",
                    "command": "sed -n '1,80p' src/module.py",
                    "aggregated_output": (
                        "https://pypi.org/simple\n"
                        "<https://github.com/example/project>\n"
                        "</summary>\n"
                        "# /// script\n"
                    ),
                    "exit_code": 0,
                    "status": "completed",
                },
            }
        )
        summary = parse_navigation_events(
            "\n".join([*graph_events[:2], command, graph_events[2]]),
            TINY_REPO,
            expected_project=Path("/repo"),
        )
        self.assertTrue(summary["graph_use_valid"])
        self.assertEqual(summary["outside_repository_accesses"], [])
        self.assertEqual(summary["fallback_navigation_after_graph"], 1)

    def test_command_absolute_and_relative_traversal_paths_remain_outside_access(self):
        for command, expected in (
            ("cat /etc/passwd", Path("/etc/passwd").resolve()),
            (
                "cat ../sibling/secret.txt",
                (TINY_REPO / "../sibling/secret.txt").resolve(),
            ),
            (
                "sed -n '1p' ../../control/secret.txt",
                (TINY_REPO / "../../control/secret.txt").resolve(),
            ),
            (
                "cat src/../../sibling/secret.txt",
                (TINY_REPO / "src/../../sibling/secret.txt").resolve(),
            ),
            (
                "cat ./../sibling/secret.txt",
                (TINY_REPO / "./../sibling/secret.txt").resolve(),
            ),
            (
                "cd .. && cat sibling/secret.txt",
                (TINY_REPO / "..").resolve(),
            ),
            (
                "cat src/module.py 2>/tmp/outside.log",
                Path("/tmp/outside.log").resolve(),
            ),
        ):
            text = "\n".join(
                [
                    json.dumps(
                        {
                            "type": "item.completed",
                            "item": {
                                "id": "read",
                                "type": "command_execution",
                                "command": command,
                                "aggregated_output": "",
                                "exit_code": 0,
                                "status": "completed",
                            },
                        }
                    ),
                    live_codegraph_trace(
                        "**`src/module.py`** — route_request(function)\n"
                    ),
                ]
            )
            summary = parse_navigation_events(
                text,
                TINY_REPO,
                expected_project=Path("/repo"),
            )
            with self.subTest(command=command):
                self.assertEqual(summary["failure_class"], "outside_repo_access")
                self.assertIn(
                    str(expected),
                    summary["outside_repository_accesses"],
                )

    def test_exact_dev_null_output_redirection_is_an_allowed_sink(self):
        for command in (
            "rg route_request src 2>/dev/null",
            "/bin/zsh -lc 'rg route_request src 2>/dev/null'",
            "rg route_request src >/dev/null",
            "rg route_request src 1>>/dev/null",
            "rg route_request src 2> /dev/null",
            "rg route_request src &>/dev/null",
            "rg route_request src 2>&1",
        ):
            graph_events = live_codegraph_trace(
                "**`src/module.py`** — route_request(function)\n"
            ).splitlines()
            fallback = json.dumps(
                {
                    "type": "item.completed",
                    "item": {
                        "id": "read",
                        "type": "command_execution",
                        "command": command,
                        "aggregated_output": "",
                        "exit_code": 0,
                        "status": "completed",
                    },
                }
            )
            summary = parse_navigation_events(
                "\n".join([*graph_events[:2], fallback, graph_events[2]]),
                TINY_REPO,
                expected_project=Path("/repo"),
            )
            with self.subTest(command=command):
                self.assertTrue(summary["graph_use_valid"])
                self.assertEqual(summary["outside_repository_accesses"], [])
                self.assertEqual(summary["fallback_navigation_after_graph"], 1)

    def test_dev_null_is_allowed_only_as_an_exact_output_redirection_target(self):
        for command, expected in (
            ("cat /dev/null", Path("/dev/null")),
            ("rg route_request /dev/null", Path("/dev/null")),
            ("cat src/module.py </dev/null", Path("/dev/null")),
            ("cat src/module.py < /dev/null", Path("/dev/null")),
            ("cat src/module.py 0</dev/null", Path("/dev/null")),
            ("cat src/module.py <>/dev/null", Path("/dev/null")),
            ("cat src/module.py 2>/dev/./null", Path("/dev/null")),
            ("cat src/module.py 2>/dev/null.extra", Path("/dev/null.extra")),
            ("cat src/module.py 2>/dev//null", Path("/dev/null")),
            ("cat src/module.py 2>/dev/null/../null", Path("/dev/null")),
        ):
            text = "\n".join(
                [
                    json.dumps(
                        {
                            "type": "item.completed",
                            "item": {
                                "id": "read",
                                "type": "command_execution",
                                "command": command,
                                "aggregated_output": "",
                                "exit_code": 0,
                                "status": "completed",
                            },
                        }
                    ),
                    live_codegraph_trace(
                        "**`src/module.py`** — route_request(function)\n"
                    ),
                ]
            )
            summary = parse_navigation_events(
                text,
                TINY_REPO,
                expected_project=Path("/repo"),
            )
            with self.subTest(command=command):
                self.assertEqual(summary["failure_class"], "outside_repo_access")
                self.assertIn(
                    str(expected.resolve()),
                    summary["outside_repository_accesses"],
                )

    def test_other_output_redirections_remain_path_accesses(self):
        for command, expected in (
            ("cat src/module.py &>/tmp/outside.log", Path("/tmp/outside.log")),
            (
                "cat src/module.py 2>../outside.log",
                TINY_REPO / "../outside.log",
            ),
            (
                "cat src/module.py 2>/dev/null 3>/tmp/outside.log",
                Path("/tmp/outside.log"),
            ),
        ):
            text = "\n".join(
                [
                    json.dumps(
                        {
                            "type": "item.completed",
                            "item": {
                                "id": "read",
                                "type": "command_execution",
                                "command": command,
                                "aggregated_output": "",
                                "exit_code": 0,
                                "status": "completed",
                            },
                        }
                    ),
                    live_codegraph_trace(
                        "**`src/module.py`** — route_request(function)\n"
                    ),
                ]
            )
            summary = parse_navigation_events(
                text,
                TINY_REPO,
                expected_project=Path("/repo"),
            )
            with self.subTest(command=command):
                self.assertEqual(summary["failure_class"], "outside_repo_access")
                self.assertIn(
                    str(expected.resolve()),
                    summary["outside_repository_accesses"],
                )

    def test_benchmark_output_redirection_remains_benchmark_access(self):
        command = "cat src/module.py >.benchmark-work/out"
        text = "\n".join(
            [
                json.dumps(
                    {
                        "type": "item.completed",
                        "item": {
                            "id": "read",
                            "type": "command_execution",
                            "command": command,
                            "aggregated_output": "",
                            "exit_code": 0,
                            "status": "completed",
                        },
                    }
                ),
                live_codegraph_trace(
                    "**`src/module.py`** — route_request(function)\n"
                ),
            ]
        )
        summary = parse_navigation_events(
            text,
            TINY_REPO,
            expected_project=Path("/repo"),
        )
        self.assertEqual(summary["failure_class"], "benchmark_output_access")

    def test_forbidden_output_redirection_remains_ground_truth_access(self):
        forbidden = Path("/private/benchmark/ground_truth/prepared.json")
        command = f"cat src/module.py >{forbidden}"
        text = "\n".join(
            [
                json.dumps(
                    {
                        "type": "item.completed",
                        "item": {
                            "id": "read",
                            "type": "command_execution",
                            "command": command,
                            "aggregated_output": "",
                            "exit_code": 0,
                            "status": "completed",
                        },
                    }
                ),
                live_codegraph_trace(
                    "**`src/module.py`** — route_request(function)\n"
                ),
            ]
        )
        summary = parse_navigation_events(
            text,
            TINY_REPO,
            expected_project=Path("/repo"),
            forbidden_paths=[forbidden],
        )
        self.assertEqual(summary["failure_class"], "ground_truth_access")
        self.assertIn(
            str(forbidden.resolve()),
            summary["prohibited_benchmark_accesses"],
        )

    def test_inline_bold_code_in_result_is_not_a_path_header(self):
        content = (
            "**`src/module.py`** — route_request(function)\n\n"
            "```markdown\n"
            "**`docs/missing.md`** — example prose, not a result header\n"
            "**`src/module.py`** — existing repository path inside source\n"
            "**`../secret.py`** — traversal-looking source text\n"
            "**`/etc/passwd`** — absolute-looking source text\n"
            "```\n"
        )
        summary = parse_navigation_events(
            live_codegraph_trace(content),
            TINY_REPO,
            expected_project=Path("/repo"),
        )
        self.assertTrue(summary["graph_use_valid"])
        self.assertEqual(summary["returned_paths"], ["src/module.py"])

    def test_exact_forbidden_path_in_tool_response_remains_ground_truth_access(self):
        forbidden = Path("/private/benchmark/ground_truth/prepared.json")
        summary = parse_navigation_events(
            live_codegraph_trace(
                "**`src/module.py`** — route_request(function)\n"
                f"Source fixture: {forbidden}\n"
            ),
            TINY_REPO,
            expected_project=Path("/repo"),
            forbidden_paths=[forbidden],
        )
        self.assertEqual(summary["failure_class"], "ground_truth_access")
        self.assertIn(
            str(forbidden.resolve()),
            summary["prohibited_benchmark_accesses"],
        )

    def test_live_0145_success_fixture_is_bound_to_passed_doctor_capture(self):
        fixture = FIXTURES / LIVE_CODEGRAPH_FIXTURE
        payload = fixture.read_bytes()
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            LIVE_CODEGRAPH_FIXTURE_SHA256,
        )
        provenance = LIVE_PROVENANCE["fixtures"][LIVE_CODEGRAPH_FIXTURE]
        self.assertEqual(
            provenance["fixture_sha256"],
            LIVE_CODEGRAPH_FIXTURE_SHA256,
        )
        self.assertIn(
            provenance["source_capture_sha256"][:12],
            LIVE_CODEGRAPH_FIXTURE,
        )
        summary = parse_navigation_events(
            payload.decode(),
            TINY_REPO,
            expected_project=Path("/repo"),
        )
        self.assertTrue(summary["graph_use_valid"])
        self.assertEqual(summary["tool_call_count"], 1)
        self.assertEqual(summary["successful_tool_call_count"], 1)
        self.assertEqual(summary["built_in_navigation_before_graph"], 0)
        self.assertEqual(summary["unknown_mcp_events"], [])
        self.assertEqual(summary["outside_repository_accesses"], [])
        self.assertEqual(summary["returned_paths"], ["src/module.py"])
        self.assertEqual(
            summary["real_envelope_integration"],
            "codex-0.145.0-live-codegraph-mcp-v1",
        )

    def test_live_0145_call_lifecycle_must_be_complete_and_correlated(self):
        source = [
            json.loads(line)
            for line in (FIXTURES / LIVE_CODEGRAPH_FIXTURE)
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        started = next(
            event
            for event in source
            if event.get("type") == "item.started"
        )
        completed = next(
            event
            for event in source
            if event.get("type") == "item.completed"
            and event.get("item", {}).get("type") == "mcp_tool_call"
        )
        cases = {
            "missing-start": [event for event in source if event is not started],
            "missing-completion": [
                event for event in source if event is not completed
            ],
            "duplicate-completion": [
                *source[:-2],
                completed,
                *source[-2:],
            ],
        }
        changed = json.loads(json.dumps(source))
        next(
            event
            for event in changed
            if event.get("type") == "item.completed"
            and event.get("item", {}).get("type") == "mcp_tool_call"
        )["item"]["arguments"]["query"] = "different"
        cases["changed-arguments"] = changed
        for name, events in cases.items():
            with self.subTest(name=name):
                summary = parse_navigation_events(
                    "\n".join(
                        json.dumps(event, separators=(",", ":"))
                        for event in events
                    ),
                    TINY_REPO,
                    expected_project=Path("/repo"),
                )
                self.assertEqual(
                    summary["failure_class"],
                    "unknown_event_shape",
                )
                self.assertFalse(summary["graph_use_valid"])

    def test_live_0145_optional_arguments_follow_pinned_tool_schema(self):
        content = "**`src/module.py`** — route_request(function)"
        for arguments in (
            {"query": "route_request"},
            {
                "projectPath": "/repo",
                "query": "route_request",
                "maxFiles": 12,
            },
        ):
            with self.subTest(arguments=arguments):
                text = "\n".join(
                    [
                        json.dumps(
                            {
                                "type": "item.started",
                                "item": {
                                    "id": "cg",
                                    "type": "mcp_tool_call",
                                    "server": "codegraph",
                                    "tool": "codegraph_explore",
                                    "arguments": arguments,
                                    "result": None,
                                    "error": None,
                                    "status": "in_progress",
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "type": "item.completed",
                                "item": {
                                    "id": "cg",
                                    "type": "mcp_tool_call",
                                    "server": "codegraph",
                                    "tool": "codegraph_explore",
                                    "arguments": arguments,
                                    "result": {
                                        "content": [
                                            {"type": "text", "text": content}
                                        ],
                                        "structured_content": None,
                                    },
                                    "error": None,
                                    "status": "completed",
                                },
                            }
                        ),
                        '{"type":"item.completed","item":{"id":"answer","type":"agent_message","text":"answer"}}',
                    ]
                )
                summary = parse_navigation_events(
                    text,
                    TINY_REPO,
                    expected_project=Path("/repo"),
                )
                self.assertTrue(summary["graph_use_valid"])

    def test_missing_or_blank_query_fails_closed(self):
        for arguments in ({}, {"query": "   "}):
            text = "\n".join(
                [
                    '{"type":"item.completed","item":{"type":"mcp_server_status","server":"codegraph","status":"connected","tools":["codegraph_explore"]}}',
                    json.dumps(
                        {
                            "type": "item.completed",
                            "item": {
                                "type": "mcp_tool_call",
                                "server": "codegraph",
                                "tool": "codegraph_explore",
                                "arguments": arguments,
                                "result": {
                                    "content": "src/module.py:1",
                                    "is_error": False,
                                    "project_root": "/repo",
                                    "paths": ["src/module.py"],
                                },
                                "status": "completed",
                            },
                        }
                    ),
                    '{"type":"item.completed","item":{"type":"agent_message","text":"answer"}}',
                ]
            )
            with self.subTest(arguments=arguments):
                self.assertEqual(
                    parse_navigation_events(text, TINY_REPO, expected_project=Path("/repo"))["failure_class"],
                    "unknown_event_shape",
                )

    def test_successful_call_after_final_response_refuses(self):
        text = "\n".join(
            [
                '{"type":"item.completed","item":{"type":"mcp_server_status","server":"codegraph","status":"connected","tools":["codegraph_explore"]}}',
                '{"type":"item.completed","item":{"type":"agent_message","text":"answer"}}',
                '{"type":"item.completed","item":{"type":"mcp_tool_call","server":"codegraph","tool":"codegraph_explore","arguments":{"query":"route"},"result":{"content":"src/module.py:1","is_error":false,"project_root":"/repo","paths":["src/module.py"]},"status":"completed"}}',
            ]
        )
        summary = parse_navigation_events(text, TINY_REPO, expected_project=Path("/repo"))
        self.assertEqual(summary["failure_class"], "codegraph_call_after_final_response")

    def test_absolute_traversal_and_nonexistent_returned_paths_refuse(self):
        for returned in (
            "/etc/passwd",
            "../secret.py",
            "src/missing.py",
            "src/module.py/",
            "src//module.py",
            "./src/module.py",
            "src/./module.py",
            "src/%2e%2e/module.py",
            "src%2Fmodule.py",
        ):
            text = "\n".join(
                [
                    '{"type":"item.completed","item":{"type":"mcp_server_status","server":"codegraph","status":"connected","tools":["codegraph_explore"]}}',
                    json.dumps(
                        {
                            "type": "item.completed",
                            "item": {
                                "type": "mcp_tool_call",
                                "server": "codegraph",
                                "tool": "codegraph_explore",
                                "arguments": {"query": "route"},
                                "result": {
                                    "content": "result",
                                    "is_error": False,
                                    "project_root": "/repo",
                                    "paths": [returned],
                                },
                                "status": "completed",
                            },
                        }
                    ),
                    '{"type":"item.completed","item":{"type":"agent_message","text":"answer"}}',
                ]
            )
            with self.subTest(returned=returned):
                self.assertEqual(
                    parse_navigation_events(text, TINY_REPO, expected_project=Path("/repo"))["failure_class"],
                    "unknown_event_shape",
                )

    def test_unknown_navigation_and_mutation_item_shapes_refuse(self):
        for item in (
            {"type": "file_search", "query": "route"},
            {
                "id": "mutation",
                "type": "command_execution",
                "command": "python -c 'open(\"x\",\"w\").write(\"x\")'",
                "aggregated_output": "",
                "exit_code": 0,
                "status": "completed",
            },
        ):
            text = "\n".join(
                [
                    '{"type":"item.completed","item":{"type":"mcp_server_status","server":"codegraph","status":"connected","tools":["codegraph_explore"]}}',
                    json.dumps({"type": "item.completed", "item": item}),
                    '{"type":"item.completed","item":{"type":"mcp_tool_call","server":"codegraph","tool":"codegraph_explore","arguments":{"query":"route"},"result":{"content":"src/module.py:1","is_error":false,"project_root":"/repo","paths":["src/module.py"]},"status":"completed"}}',
                    '{"type":"item.completed","item":{"type":"agent_message","text":"answer"}}',
                ]
            )
            with self.subTest(item=item):
                self.assertEqual(
                    parse_navigation_events(text, TINY_REPO, expected_project=Path("/repo"))["failure_class"],
                    "unknown_event_shape",
                )


if __name__ == "__main__":
    unittest.main()
