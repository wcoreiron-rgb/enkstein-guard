import argparse
import asyncio
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


os.environ["ENKSTEIN_POLICY_PACK"] = "/nonexistent/guard-stage-tests"
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "deployment"))
sys.path.insert(0, str(ROOT / "deployment/acceptance"))

import ai_security_load as load  # noqa: E402
import ai_security_characterization_upstream as upstream  # noqa: E402
import characterize_ai_security as characterization  # noqa: E402


def agent_summary(actor, phase, offered, statuses=None):
    statuses = statuses or {"ok": offered}
    actual = sum(statuses.values())
    values = [float(number + 1) for number in range(actual)]
    return {
        "type": "summary", "actor": actor, "phase": phase,
        "offered_calls": offered, "actual_calls": actual,
        "successful_calls": statuses.get("ok", 0),
        "error_calls": actual - statuses.get("ok", 0), "statuses": statuses,
        "total_latencies_ms": values, "queue_latencies_ms": values,
        "rpc_latencies_ms": values,
        "elapsed_seconds": 1.0,
        "offered_window_seconds": 1.0 if phase == "measurement" else None,
        "drain_seconds": 0.0 if phase == "measurement" else None,
    }


def counter_snapshot(*, inspection=0, business=0, unknown=0):
    digest = "a" * 64
    return {
        "schema": characterization.UPSTREAM_SCHEMA,
        "sequence": inspection + business + unknown,
        "requests": inspection + business + unknown,
        "inspection": inspection, "business": business, "unknown": unknown,
        "models": {"synthetic-security": inspection, "synthetic-model": business,
                   "unknown": unknown},
        "header_hashes": {
            "inspection": {digest: inspection} if inspection else {},
            "business": {digest: business} if business else {},
            "unknown": {digest: unknown} if unknown else {},
        },
    }


class AICapacityPlanTests(unittest.TestCase):
    def test_model_only_bootstrap_does_not_ingest_undeclared_collection(self):
        config = characterization.characterization_config(
            characterization.CharacterizationParameters())
        deployment = object.__new__(characterization.AISecurityCharacterization)
        deployment.config = config
        deployment.compose = mock.Mock()
        deployment.guard_cli = mock.Mock()
        deployment.wait_ready = mock.Mock(return_value={"ready": True})
        deployment.secrets = {c["credential"]: "synthetic-credential" for c in config["connectors"]}
        with tempfile.TemporaryDirectory() as temporary:
            deployment.run = Path(temporary)
            (deployment.run / "credentials").mkdir()
            for agent in config["agents"]:
                (deployment.run / "credentials" / (agent["id"] + ".token")).write_text("synthetic-token")
            self.assertEqual(deployment.up(), {"ready": True})
        calls = [call.args[:2] for call in deployment.guard_cli.call_args_list]
        self.assertNotIn(("retrieval", "ingest"), calls)
        self.assertEqual(calls.count(("connector", "secret-set")), 4)

    def test_serialized_deployment_config_passes_real_cli_validation(self):
        config = characterization.characterization_config(
            characterization.CharacterizationParameters())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "guard.json"
            path.write_text(json.dumps(config))
            process = subprocess.run(
                [sys.executable, "-m", "enkstein_guard", "--config", str(path),
                 "config", "validate"], cwd=ROOT, env=os.environ.copy(),
                capture_output=True, text=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["status"], "ok")

    def test_default_plan_is_valid_and_performs_no_docker_work(self):
        output = io.StringIO()
        with (mock.patch.object(characterization.subprocess, "run",
                               side_effect=AssertionError("docker forbidden")),
              mock.patch.object(characterization.subprocess, "Popen",
                                side_effect=AssertionError("docker forbidden")),
              redirect_stdout(output)):
            self.assertEqual(characterization.main([]), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan["schema"], "enkstein-ai-security-characterization-plan-v1")
        self.assertFalse(plan["docker_executed"])
        self.assertEqual(plan["parameters"]["actor_count"], 2)
        self.assertEqual(plan["parameters"]["history_capacity"], 32)
        self.assertEqual(plan["parameters"]["warmup_offered_calls"], 32)
        self.assertEqual(plan["parameters"]["measurement_offered_calls"], 40)
        self.assertFalse(plan["production_accepted"])
        self.assertFalse(plan["live_model_robustness"])

    def test_supported_extremes_build_tenant_split_production_configs(self):
        for actors, history in ((2, 16), (64, 256)):
            with self.subTest(actors=actors, history=history):
                parameters = characterization.CharacterizationParameters(
                    actors=actors, per_actor_history=history,
                    duration_seconds=1, rate_per_actor=1)
                config = characterization.characterization_config(parameters)
                self.assertEqual(config["profile"], "production-linux-peer-bound")
                self.assertEqual(len(config["agents"]), actors)
                self.assertEqual({agent["tenant"] for agent in config["agents"]}, {"a", "b"})
                self.assertEqual(sum(agent["tenant"] == "a" for agent in config["agents"]), actors // 2)
                self.assertEqual(len({agent["uid"] for agent in config["agents"]}), actors)
                self.assertTrue(all(agent["routes"] == [agent["tenant"] + ".business"]
                                    for agent in config["agents"]))
                self.assertEqual(config["security_history"], {
                    "capacity": actors * history,
                    "ttl_seconds": 3600,
                    "per_actor_capacity": history,
                })
                self.assertLessEqual(config["security_history"]["capacity"], 100_000)
                credentials = [item["credential"] for item in config["connectors"]]
                self.assertEqual(len(credentials), len(set(credentials)))
                self.assertEqual({item["model"] for item in config["connectors"]},
                                 {"synthetic-model", "synthetic-security"})

    def test_strict_parameter_bounds_reject_invalid_or_empty_plans(self):
        invalid = (
            {"actors": 1}, {"actors": 3}, {"actors": 66},
            {"per_actor_history": 15}, {"per_actor_history": 257},
            {"duration_seconds": 0}, {"duration_seconds": 601},
            {"rate_per_actor": 0}, {"rate_per_actor": 3.1},
            {"duration_seconds": 1, "rate_per_actor": 0.1},
            {"max_inflight": 0}, {"max_inflight": 17},
        )
        for changes in invalid:
            values = {"actors": 2, "per_actor_history": 16,
                      "duration_seconds": 10, "rate_per_actor": 2,
                      "max_inflight": 4, **changes}
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                characterization.CharacterizationParameters(**values)

    def test_run_mode_is_explicit_and_delegates_only_after_validation(self):
        observed = {}

        def fake(parameters, config, report):
            observed.update(parameters=parameters, config=config, report=report)
            return 7

        with mock.patch.object(characterization, "execute_characterization", side_effect=fake):
            code = characterization.main([
                "--run", "--actors", "4", "--per-actor-history", "32",
                "--duration", "5", "--rate-per-actor", "1", "--report", "result.json",
            ])
        self.assertEqual(code, 7)
        self.assertEqual(observed["parameters"].history_capacity, 128)
        self.assertEqual(observed["config"]["security_history"]["capacity"], 128)
        self.assertEqual(observed["report"], "result.json")

    def test_aggregate_keeps_missing_and_error_results_explicit(self):
        results = {
            "a": {"returncode": 0, "stderr": "", "summary": agent_summary(
                "a", "measurement", 2, {"ok": 1, "denied": 1})},
            "b": {"returncode": 1, "stderr": "synthetic failure", "summary": None},
        }
        aggregate = characterization.aggregate_agent_results(
            results, {"a": 2, "b": 2}, "measurement")
        self.assertFalse(aggregate["complete"])
        self.assertEqual(aggregate["offered_calls"], 4)
        self.assertEqual(aggregate["actual_calls"], 2)
        self.assertEqual(aggregate["statuses"], {"denied": 1, "ok": 1})
        self.assertEqual(aggregate["error_calls"], 1)
        self.assertEqual(aggregate["actors"]["b"]["stderr"], "synthetic failure")

    def test_aggregate_marks_only_exact_consistent_participation_complete(self):
        results = {}
        for actor in ("a", "b"):
            results[actor] = {"returncode": 0, "stderr": "",
                              "summary": agent_summary(actor, "warmup", 2)}
        aggregate = characterization.aggregate_agent_results(
            results, {"a": 2, "b": 2}, "warmup")
        self.assertTrue(aggregate["complete"])
        self.assertEqual(aggregate["offered_calls"], 4)
        self.assertEqual(aggregate["actual_calls"], 4)
        self.assertEqual(aggregate["successful_calls"], 4)
        self.assertEqual(aggregate["total_p95_ms"], 2.0)

    def test_aggregate_rejects_actor_spoofing_and_bool_counts(self):
        spoofed = agent_summary("other", "measurement", 1)
        aggregate = characterization.aggregate_agent_results(
            {"agent-a": {"returncode": 0, "stderr": "", "summary": spoofed}},
            {"agent-a": 1}, "measurement")
        self.assertFalse(aggregate["complete"])
        self.assertFalse(aggregate["actors"]["agent-a"]["internally_consistent"])

        boolean = agent_summary("agent-a", "measurement", 1)
        boolean["actual_calls"] = True
        aggregate = characterization.aggregate_agent_results(
            {"agent-a": {"returncode": 0, "stderr": "", "summary": boolean}},
            {"agent-a": 1}, "measurement")
        self.assertFalse(aggregate["complete"])

    def test_counter_snapshots_are_strict_and_deltas_cannot_regress(self):
        before = counter_snapshot(inspection=1, business=1)
        after = counter_snapshot(inspection=3, business=2)
        delta = characterization.upstream_counter_delta(before, after)
        self.assertEqual(delta["requests"], 3)
        self.assertEqual(delta["inspection"], 2)
        self.assertEqual(delta["business"], 1)
        with self.assertRaisesRegex(ValueError, "counter_regression"):
            characterization.upstream_counter_delta(after, before)
        malformed = counter_snapshot()
        malformed["requests"] = False
        with self.assertRaisesRegex(ValueError, "counter_value"):
            characterization.parse_upstream_counters(malformed)

    def test_upstream_parser_rejects_wrong_path_and_counter_file_has_no_request_values(self):
        head = (b"POST /v1/chat/completions HTTP/1.1\r\n"
                b"content-length: 2\r\nx-api-key: private-value\r\n\r\n")
        length, headers = upstream.parse_request_head(head)
        self.assertEqual(length, 2)
        self.assertEqual(headers["x-api-key"], "private-value")
        with self.assertRaisesRegex(ValueError, "method_or_path"):
            upstream.parse_request_head(head.replace(b"POST ", b"GET ", 1))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "stats.json"
            store = upstream.CounterStore(str(path))
            for number in range(20):
                store.record("business", upstream.BUSINESS_MODEL,
                             "private-value-%d" % number)
            encoded = path.read_text()
            value = json.loads(encoded)
            self.assertNotIn("private-value", encoded)
            self.assertLessEqual(len(value["header_hashes"]["business"]), 17)
            self.assertEqual(sum(value["header_hashes"]["business"].values()), 20)

    def test_non_ok_measurement_is_complete_but_errors_stay_explicit(self):
        parameters = characterization.CharacterizationParameters(
            actors=2, per_actor_history=16, duration_seconds=1, rate_per_actor=1)
        config = characterization.characterization_config(parameters)
        snapshots = iter((
            counter_snapshot(),
            counter_snapshot(inspection=32, business=32),
            counter_snapshot(inspection=34, business=33),
        ))

        class FakeDeployment:
            def __init__(self, *args, **kwargs):
                pass

            def up(self):
                return {"ready": True}

            def header(self, name):
                return {"report": name}

            def upstream_counters(self):
                return next(snapshots)

            def warmup(self):
                return {actor: {"returncode": 0, "stderr": "",
                                "summary": agent_summary(actor, "warmup", 16)}
                        for actor in ("agent-a-01", "agent-b-01")}

            def measurement(self):
                return ({
                    "agent-a-01": {"returncode": 0, "stderr": "",
                                   "summary": agent_summary(
                                       "agent-a-01", "measurement", 1)},
                    "agent-b-01": {"returncode": 0, "stderr": "",
                                   "summary": agent_summary(
                                       "agent-b-01", "measurement", 1,
                                       {"denied": 1})},
                }, [{"guard": {"rss": 1}}])

            def status(self):
                return {"security_history": {"records": 32}}

            def down(self):
                pass

            def redact(self, value):
                return value

        written = {}

        def write(name, report):
            written.update(name=name, report=report)
            return Path(name)

        with (mock.patch.object(characterization, "AISecurityCharacterization",
                               FakeDeployment),
              mock.patch.object(characterization, "write_report", side_effect=write),
              redirect_stdout(io.StringIO())):
            code = characterization.execute_characterization(
                parameters, config, "synthetic.json")
        self.assertEqual(code, 0)
        self.assertTrue(written["report"]["complete"])
        self.assertTrue(written["report"]["observed_errors"])
        self.assertEqual(written["report"]["observed_error_counts"], {"denied": 1})
        self.assertFalse(written["report"]["production_accepted"])
        self.assertTrue(written["report"]["measurement"]["counters_complete"])

    def test_load_summary_reports_every_status_and_latency(self):
        value = load.summary("measurement", "agent-a", 4, [3, 4, 5],
                             [1, 1, 1], [2, 3, 4],
                             {"ok": 2, "busy:rate_limited": 1}, 1.25, 1, 0.25)
        self.assertEqual(value["offered_calls"], 4)
        self.assertEqual(value["actual_calls"], 3)
        self.assertEqual(value["successful_calls"], 2)
        self.assertEqual(value["error_calls"], 1)
        self.assertEqual(value["total_p50_ms"], 4)
        self.assertEqual(value["rpc_p95_ms"], 4)
        self.assertEqual(value["offered_window_seconds"], 1)
        self.assertEqual(value["drain_seconds"], 0.25)
        self.assertFalse(value["production_accepted"])
        self.assertIn("characterization:warmup", json.dumps(
            load.benign_payload("warmup", "agent-a", 1)))


class AILoadFixtureTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def fixture_args(token, **changes):
        values = {
            "phase": "measurement", "actor": "agent-a", "route": "a.business",
            "token_file": str(token), "warmup_count": 16, "duration": 1,
            "rate": 1, "max_inflight": 2,
        }
        values.update(changes)
        return argparse.Namespace(**values)

    async def test_each_attempt_gets_unique_request_id_without_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            token = Path(temporary) / "token"
            token.write_text("synthetic-agent-token")
            args = self.fixture_args(token)
            fixture = load.Load(load.validate_args(args))
            with (mock.patch.object(load, "new_request_id",
                                    side_effect=("req-one", "req-two")),
                  mock.patch.object(load, "guarded_request",
                                    new=mock.AsyncMock(return_value={"status": "ok"})) as request):
                await fixture.one(1)
                await fixture.one(2)
            self.assertEqual(request.await_count, 2)
            self.assertEqual([call.kwargs["request_id"] for call in request.await_args_list],
                             ["req-one", "req-two"])
            self.assertEqual(fixture.statuses, {"ok": 2})
            self.assertEqual(len(fixture.total_latencies), 2)
            self.assertEqual(len(fixture.queue_latencies), 2)
            self.assertEqual(len(fixture.rpc_latencies), 2)

    async def test_total_latency_includes_inflight_queue_and_reports_rpc_separately(self):
        with tempfile.TemporaryDirectory() as temporary:
            token = Path(temporary) / "token"
            token.write_text("synthetic-agent-token")
            fixture = load.Load(load.validate_args(
                self.fixture_args(token, max_inflight=1)))
            entered = asyncio.Event()
            release = asyncio.Event()
            calls = 0

            async def guarded(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 1:
                    entered.set()
                    await release.wait()
                return {"status": "ok"}

            with (mock.patch.object(load, "new_request_id",
                                    side_effect=("req-one", "req-two")),
                  mock.patch.object(load, "guarded_request", new=guarded)):
                first = asyncio.create_task(fixture.one(1))
                await entered.wait()
                second = asyncio.create_task(fixture.one(2))
                await asyncio.sleep(0.015)
                release.set()
                await asyncio.gather(first, second)
            self.assertGreater(max(fixture.queue_latencies), 10)
            self.assertTrue(all(
                total + 0.1 >= queue + rpc
                for total, queue, rpc in zip(
                    fixture.total_latencies, fixture.queue_latencies,
                    fixture.rpc_latencies)))

    async def test_measurement_waits_for_offered_window_and_reports_drain(self):
        with tempfile.TemporaryDirectory() as temporary:
            token = Path(temporary) / "token"
            token.write_text("synthetic-agent-token")
            fixture = load.Load(self.fixture_args(token, duration=0.03, rate=1))

            async def completed(sequence):
                fixture.statuses["ok"] = 1
                fixture.total_latencies.append(1)
                fixture.queue_latencies.append(0)
                fixture.rpc_latencies.append(1)

            fixture.one = completed
            output = io.StringIO()
            started = asyncio.get_running_loop().time()
            with (mock.patch.object(load, "scheduled_count", return_value=1),
                  redirect_stdout(output)):
                await fixture.run()
            elapsed = asyncio.get_running_loop().time() - started
            value = json.loads(output.getvalue())
            self.assertGreaterEqual(elapsed, 0.025)
            self.assertEqual(value["offered_window_seconds"], 0.03)
            self.assertEqual(value["drain_seconds"], 0)

            fixture = load.Load(self.fixture_args(token, duration=0.01, rate=1))

            async def drained(sequence):
                await asyncio.sleep(0.025)
                fixture.statuses["ok"] = 1
                fixture.total_latencies.append(25)
                fixture.queue_latencies.append(0)
                fixture.rpc_latencies.append(25)

            fixture.one = drained
            output = io.StringIO()
            with (mock.patch.object(load, "scheduled_count", return_value=1),
                  redirect_stdout(output)):
                await fixture.run()
            value = json.loads(output.getvalue())
            self.assertGreater(value["drain_seconds"], 0)


if __name__ == "__main__":
    unittest.main()
