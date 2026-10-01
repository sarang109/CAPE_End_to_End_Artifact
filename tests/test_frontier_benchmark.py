import json
import tempfile
import unittest
from pathlib import Path

from cape_artifact.frontier_benchmark import (
    CostBudget,
    MockFrontierClient,
    ModelSpec,
    PROVIDER_FACTORIES,
    RateLimiter,
    SimulatedFrontierClient,
    estimate_cost_usd,
    parse_model_spec,
    retry_with_backoff,
    run_frontier_benchmark,
)


class ParseModelSpecTests(unittest.TestCase):
    def test_valid_spec(self):
        spec = parse_model_spec("anthropic:claude-sonnet-5")
        self.assertEqual(spec, ModelSpec("anthropic:claude-sonnet-5", "anthropic", "claude-sonnet-5"))

    def test_unknown_provider_rejected(self):
        with self.assertRaises(ValueError):
            parse_model_spec("groq:llama-3")

    def test_missing_separator_rejected(self):
        with self.assertRaises(ValueError):
            parse_model_spec("claude-sonnet-5")


class RetryWithBackoffTests(unittest.TestCase):
    def test_succeeds_after_transient_failures(self):
        attempts = {"count": 0}
        sleeps: list[float] = []

        def flaky():
            attempts["count"] += 1
            if attempts["count"] < 3:
                raise ConnectionError("transient")
            return "ok"

        result = retry_with_backoff(
            flaky, retryable_exceptions=(ConnectionError,), max_retries=5,
            base_delay=0.001, sleep=sleeps.append,
        )
        self.assertEqual(result, "ok")
        self.assertEqual(attempts["count"], 3)
        self.assertEqual(len(sleeps), 2)

    def test_raises_after_exhausting_retries(self):
        def always_fails():
            raise ConnectionError("down")

        with self.assertRaises(ConnectionError):
            retry_with_backoff(
                always_fails, retryable_exceptions=(ConnectionError,), max_retries=2,
                base_delay=0.001, sleep=lambda _: None,
            )

    def test_non_retryable_exception_propagates_immediately(self):
        def raises_value_error():
            raise ValueError("not retryable")

        with self.assertRaises(ValueError):
            retry_with_backoff(
                raises_value_error, retryable_exceptions=(ConnectionError,), max_retries=5,
                base_delay=0.001, sleep=lambda _: None,
            )


class RateLimiterTests(unittest.TestCase):
    def test_no_limit_does_not_block(self):
        limiter = RateLimiter(None)
        limiter.wait()
        limiter.wait()  # should return immediately

    def test_enforces_minimum_interval(self):
        import time

        limiter = RateLimiter(requests_per_minute=6000)  # 0.01s min interval
        started = time.perf_counter()
        limiter.wait()
        limiter.wait()
        elapsed = time.perf_counter() - started
        self.assertGreaterEqual(elapsed, 0.008)


class CostEstimationTests(unittest.TestCase):
    def test_known_model_priced(self):
        cost = estimate_cost_usd({"mock:x": (1.0, 2.0)}, "mock:x", input_tokens=1_000_000, output_tokens=500_000)
        self.assertAlmostEqual(cost, 1.0 + 1.0)

    def test_unknown_model_returns_none(self):
        self.assertIsNone(estimate_cost_usd({}, "unknown:x", 100, 100))


class RunFrontierBenchmarkMockTests(unittest.TestCase):
    def test_always_safe_model_never_triggers_unauthorized_payment(self):
        specs = [parse_model_spec("mock:mock-always-safe")]
        with tempfile.TemporaryDirectory() as tmp:
            agent_rows, gateway_rows, summary = run_frontier_benchmark(specs, seeds=[1], output_dir=Path(tmp))
            self.assertTrue(all(row["cost_usd"] == 0.0 for row in agent_rows))
            self.assertTrue(all(row["error"] == "" for row in agent_rows))
            unauthorized = sum(row["unauthorized_payment"] for row in gateway_rows)
            self.assertEqual(unauthorized, 0)
            self.assertTrue((Path(tmp) / "frontier_model_summary.csv").exists())
            self.assertTrue((Path(tmp) / "frontier_environment.json").exists())

    def test_always_compromised_model_is_blocked_by_strong_defenses_only(self):
        specs = [parse_model_spec("mock:mock-always-compromised")]
        with tempfile.TemporaryDirectory() as tmp:
            _, gateway_rows, summary = run_frontier_benchmark(specs, seeds=[1], output_dir=Path(tmp))
            by_defense = {}
            for row in gateway_rows:
                by_defense.setdefault(row["defense"], []).append(row["unauthorized_payment"])
            self.assertGreater(sum(by_defense["AP2_ONLY"]), 0)
            self.assertGreater(sum(by_defense["MAJORITY"]), 0)
            self.assertEqual(sum(by_defense["FULL"]), 0)
            self.assertEqual(sum(by_defense["CWR"]), 0)
            self.assertEqual(sum(by_defense["DFMR"]), 0)

    def test_invalid_output_fails_closed_and_is_never_purchased(self):
        specs = [parse_model_spec("mock:mock-invalid-output")]
        with tempfile.TemporaryDirectory() as tmp:
            agent_rows, gateway_rows, _ = run_frontier_benchmark(specs, seeds=[1], output_dir=Path(tmp))
            self.assertTrue(all(row["valid_output"] == 0 for row in agent_rows))
            self.assertTrue(all(row["buy"] == 0 for row in agent_rows))
            self.assertEqual(sum(row["payment_effect"] for row in gateway_rows), 0)

    def test_cost_and_call_counts_are_reported_in_summary(self):
        specs = [parse_model_spec("mock:mock-always-safe")]
        with tempfile.TemporaryDirectory() as tmp:
            _, _, summary = run_frontier_benchmark(specs, seeds=[1, 2], output_dir=Path(tmp))
            self.assertTrue(all(row["total_llm_cost_usd"] == 0.0 for row in summary))
            self.assertTrue(all(row["total_llm_calls"] > 0 for row in summary))
            self.assertTrue(all(row["failed_llm_calls"] == 0 for row in summary))


class SimulatedFrontierClientTests(unittest.TestCase):
    def test_rejects_unknown_profile(self):
        with self.assertRaises(ValueError):
            SimulatedFrontierClient("profile-nonexistent")

    def test_deterministic_for_same_case_and_seed(self):
        client = SimulatedFrontierClient("profile-mixed")
        first = client._call("naive system", "actual_category=stored_value case A", seed=7, max_tokens=32, temperature=0.2)
        second = client._call("naive system", "actual_category=stored_value case A", seed=7, max_tokens=32, temperature=0.2)
        self.assertEqual(first.text, second.text)

    def test_never_calls_a_real_api_and_is_zero_cost(self):
        specs = [parse_model_spec("simulated:profile-cautious")]
        with tempfile.TemporaryDirectory() as tmp:
            agent_rows, _, _ = run_frontier_benchmark(specs, seeds=[1], output_dir=Path(tmp))
            self.assertTrue(all(row["provider"] == "simulated" for row in agent_rows))
            self.assertTrue(all(row["cost_usd"] == 0.0 for row in agent_rows))
            environment = json.loads((Path(tmp) / "frontier_environment.json").read_text())
            self.assertEqual(environment["paid_api_calls"], 0)

    def test_permissive_profile_proposes_more_forbidden_purchases_than_cautious(self):
        specs = [parse_model_spec("simulated:profile-cautious"), parse_model_spec("simulated:profile-permissive")]
        with tempfile.TemporaryDirectory() as tmp:
            agent_rows, _, _ = run_frontier_benchmark(specs, seeds=[1, 2, 3], output_dir=Path(tmp))
            compromised = {"simulated:profile-cautious": 0, "simulated:profile-permissive": 0}
            for row in agent_rows:
                if row["attack"]:
                    compromised[row["model"]] += row["agent_compromised"]
            self.assertGreater(compromised["simulated:profile-permissive"], compromised["simulated:profile-cautious"])


class CostBudgetTests(unittest.TestCase):
    def test_unlimited_when_no_cap(self):
        budget = CostBudget(None)
        budget.record(1_000_000.0)
        self.assertTrue(budget.allow())

    def test_stops_once_cap_reached(self):
        budget = CostBudget(1.0)
        self.assertTrue(budget.allow())
        budget.record(0.6)
        self.assertTrue(budget.allow())
        budget.record(0.5)
        self.assertFalse(budget.allow())
        self.assertTrue(budget.tripped)

    def test_ignores_unknown_cost(self):
        budget = CostBudget(1.0)
        budget.record(None)
        self.assertTrue(budget.allow())

    def test_run_frontier_benchmark_skips_calls_once_budget_exhausted(self):
        # A fake "real" provider (deliberately not "mock"/"simulated", which
        # are exempt from budgeting) reusing MockFrontierClient's zero-cost
        # behavior but priced absurdly high, so the budget trips after a
        # couple of calls and the rest must be skipped rather than issued.
        specs = [ModelSpec("faketest:mock-always-safe", "faketest", "mock-always-safe")]
        factories = {**PROVIDER_FACTORIES, "faketest": MockFrontierClient}
        pricing = {"faketest:mock-always-safe": (1_000_000.0, 1_000_000.0)}
        with tempfile.TemporaryDirectory() as tmp:
            agent_rows, _, _ = run_frontier_benchmark(
                specs, seeds=[1, 2, 3], output_dir=Path(tmp),
                pricing=pricing, client_factories=factories, max_total_cost_usd=0.05,
            )
            skipped = [r for r in agent_rows if r["error"].startswith("skipped: cost budget")]
            executed = [r for r in agent_rows if not r["error"]]
            self.assertGreater(len(skipped), 0)
            self.assertGreater(len(executed), 0)
            environment = json.loads((Path(tmp) / "frontier_environment.json").read_text())
            self.assertTrue(environment["cost_budget_tripped"])
            self.assertEqual(environment["max_total_cost_usd"], 0.05)
            self.assertGreater(environment["skipped_calls_over_budget"], 0)


if __name__ == "__main__":
    unittest.main()
