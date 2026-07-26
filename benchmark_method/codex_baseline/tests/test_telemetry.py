import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from context_graph_bench.telemetry import duration_seconds, parse_events, price_usage


FIXTURES = Path(__file__).parent / "fixtures"


class TelemetryTests(unittest.TestCase):
    def test_complete_terminal_usage_and_components(self):
        result = parse_events((FIXTURES / "codex_events/complete.jsonl").read_text())
        self.assertTrue(result["valid"])
        self.assertEqual(result["usage"]["input_tokens"], 100)
        self.assertEqual(result["usage"]["cached_input_tokens"], 25)
        self.assertEqual(result["usage"]["cache_write_input_tokens"], 5)
        self.assertEqual(result["usage"]["reasoning_output_tokens"], 12)
        self.assertEqual(result["usage"]["uncached_input_tokens"], 75)
        self.assertEqual(result["usage"]["provider_total_tokens"], 152)

    def test_malformed_missing_unknown_and_missing_terminal_fail_closed(self):
        for name in ("malformed.jsonl", "missing-usage.jsonl", "unknown.jsonl"):
            self.assertFalse(parse_events((FIXTURES / "codex_events" / name).read_text())["valid"])
        self.assertEqual(parse_events('{"type":"turn.started"}')["failure_class"], "missing_turn_completed")

    def test_decreasing_and_contradictory_usage_fail(self):
        decreasing = '\n'.join([
            '{"type":"turn.started","usage":{"input_tokens":10,"cached_input_tokens":1,"output_tokens":1,"reasoning_output_tokens":1}}',
            '{"type":"turn.completed","usage":{"input_tokens":9,"cached_input_tokens":1,"output_tokens":1,"reasoning_output_tokens":1}}',
        ])
        self.assertFalse(parse_events(decreasing)["valid"])
        contradictory = '{"type":"turn.completed","usage":{"input_tokens":2,"cached_input_tokens":3,"output_tokens":1,"reasoning_output_tokens":1}}'
        self.assertFalse(parse_events(contradictory)["valid"])

    def test_no_token_estimation_and_cost_mismatch_is_unavailable(self):
        result = price_usage({"input_tokens": 10, "cached_input_tokens": 2, "output_tokens": 3, "reasoning_output_tokens": 1}, {"model": "other", "currency": "USD"}, "gpt-5.6-luna")
        self.assertEqual(result["cost_status"], "unavailable")
        self.assertAlmostEqual(duration_seconds(1.0, 1.25), 0.25)
        with self.assertRaises(ValueError):
            duration_seconds(2.0, 1.0)


if __name__ == "__main__":
    unittest.main()
