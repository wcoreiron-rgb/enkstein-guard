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

import ai_security_endurance_load as actor_load  # noqa: E402
import test_ai_security_endurance as endurance  # noqa: E402


def histogram(count, bucket=1):
    return {"unit": "milliseconds_ceiling", "maximum_bucket_ms": 120000,
            "count": count, "buckets": [[bucket, count]] if count else []}


def actor_result(actor, phase, offered, duration=30, status="ok"):
    statuses = {status: offered}
    summary = {
        "type": "summary", "actor": actor, "phase": phase,
        "offered_calls": offered, "actual_calls": offered,
        "successful_calls": offered if status == "ok" else 0,
        "error_calls": 0 if status == "ok" else offered,
        "statuses": statuses, "unique_request_ids": offered,
        "pending_cancelled": 0, "retries": 0,
        "configured_max_inflight": 4, "elapsed_seconds": float(duration),
        "offered_window_seconds": duration if phase == "measurement" else None,
        "drain_seconds": 0.0 if phase == "measurement" else None,
        "total_histogram": histogram(offered),
        "queue_histogram": histogram(offered),
        "rpc_histogram": histogram(offered),
    }
    windows = ([{"type": "window", "phase": phase, "actor": actor,
                 "window_index": 0, "seconds": float(duration), "requests": offered,
                 "statuses": statuses, "p95_ms": 1.0, "p99_ms": 1.0,
                 "max_ms": 1.0}] if phase == "measurement" else [])
    return {"summary": summary, "windows": windows, "returncode": 0, "stderr": ""}


def passing_evidence():
    deployment_sha = "d" * 64
    return {
        "schema": "enkstein-guard.evidence/v1",
        "candidate": {"wheel_sha256": "a" * 64, "installed_matches_wheel": True},
        "image": {"id": "sha256:" + "b" * 64},
        "dependencies": {"lock": {"matches_lock": True, "lock_sha256": "c" * 64}},
        "configuration": [{"sha256": "e" * 64, "policy_version": "p",
                           "preserved": "configurations/guard.json"}],
        "revision": {name: {"sha256": deployment_sha if name == "deployment" else "f" * 64}
                     for name in ("source", "tests", "tools", "deployment", "definitions")},
    }


def report_fixture(duration=10800, full=True):
    measured_calls = duration * 8
    evidence = passing_evidence()
    validation = {
        "checks": {"inspection_matches_successful": True,
                   "business_matches_successful": True, "unknown_is_zero": True,
                   "inspection_credential_hashes_exact": True,
                   "business_credential_hashes_exact": True,
                   "credential_hash_sets_distinct": True,
                   "no_missing_or_overflow_hash_bucket": True},
        "complete": True, "inspection_hashes": ["a", "b"],
        "business_hashes": ["c", "d"],
    }
    sample_times = [*range(0, duration, 60), duration]
    samples = [{
        "elapsed_seconds": float(elapsed),
        "guard": {"process": {"rss_kib": 1024 + index, "fds": 10, "threads": 4},
                  "paths": {"/state": {"bytes": 4096 + index}}},
        "egress": {"process": {"rss_kib": 1024, "fds": 8, "threads": 2}},
        "status": {"security_history": {"records": 256}},
    } for index, elapsed in enumerate(sample_times)]
    return {
        "duration_seconds": duration, "full_acceptance_eligible": full,
        "full_acceptance_passed": False,
        "measurement_timed_out": False,
        "progress_file": "/tmp/synthetic-ai-endurance-progress.jsonl",
        "warmup": {"complete": True, "actual_calls": 256,
                   "successful_calls": 256, "error_calls": 0},
        "measurement": {"complete": True, "actual_calls": measured_calls,
                        "successful_calls": measured_calls, "error_calls": 0,
                        "actors_complete": 4, "total_p95_ms": 10.0,
                        "total_p99_ms": 20.0, "window_p99_ms_max": 30.0},
        "actual_measurement_elapsed_seconds": float(duration),
        "samples": samples,
        "status_after_warmup": {"security_history": {"records": 256}},
        "final_status": {
            "security_history": {"records": 256},
            "config": {"security_engine_count": 2},
            "retention": {name: {"failures": 0}
                          for name in ("outcomes", "audit", "vault", "settlement")},
        },
        "counter_validation": {"warmup": validation, "measurement": validation},
        "audit_verify": {"verified": True},
        "outcome_archives": {"verified": True},
        "topology_validation": {"complete": True, "checks": {}},
        "evidence": evidence,
        "target_binding": {
            "sha256": endurance.sha256_file(endurance.TARGETS_PATH),
            "deployment_revision_sha256": "d" * 64,
        },
    }


class AIEndurancePlanTests(unittest.TestCase):
    def test_default_plan_is_fixed_full_profile_and_has_no_process_side_effects(self):
        output = io.StringIO()
        with (mock.patch.object(endurance.subprocess, "run",
                               side_effect=AssertionError("subprocess forbidden")),
              mock.patch.object(endurance.subprocess, "Popen",
                                side_effect=AssertionError("subprocess forbidden")),
              redirect_stdout(output)):
            self.assertEqual(endurance.main([]), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan["schema"], "enkstein-guard.ai-security-endurance-plan/v1")
        self.assertFalse(plan["docker_executed"])
        self.assertEqual(plan["run_class"], "full_endurance")
        self.assertTrue(plan["full_acceptance_eligible"])
        self.assertFalse(plan["full_acceptance_passed"])
        self.assertEqual(plan["parameters"]["actors"], 4)
        self.assertEqual(plan["parameters"]["warmup_calls"], 256)
        self.assertEqual(plan["parameters"]["measured_calls"], 86400)
        self.assertEqual(plan["parameters"]["history_capacity"], 256)
        self.assertFalse(plan["real_model_robustness"])
        self.assertTrue(plan["synthetic_counter_fsync_overhead"])
        self.assertFalse(plan["duplicate_execution_claim"])

    def test_explicit_short_duration_is_smoke_only(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(endurance.main(["--duration", "30"]), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan["run_class"], "short_smoke")
        self.assertFalse(plan["full_acceptance_eligible"])
        self.assertEqual(plan["parameters"]["measured_calls"], 240)

    def test_duration_validation_rejects_nonexact_and_full_override_cases(self):
        for duration in (29, 10800, 10801):
            with self.subTest(duration=duration), self.assertRaises(ValueError):
                endurance.EnduranceParameters(duration, explicit_duration=True)
        with self.assertRaises(ValueError):
            endurance.EnduranceParameters(30, explicit_duration=False)
        with self.assertRaises(ValueError):
            endurance.EnduranceParameters(float("nan"), explicit_duration=True)

    def test_targets_are_exact_and_relaxation_is_rejected(self):
        targets = endurance.load_targets()
        self.assertEqual([item["id"] for item in targets["targets"]],
                         list(endurance.EXPECTED_REQUIREMENTS))
        targets["targets"][1]["requirements"]["p99_ms_max"] = 999999
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "targets.json"
            path.write_text(json.dumps(targets))
            with self.assertRaisesRegex(ValueError, "targets_changed"):
                endurance.load_targets(path)

    def test_raw_public_config_serializes_and_passes_real_cli_validation(self):
        config = endurance.endurance_config()
        self.assertEqual(config["service"]["max_requests_per_second"], 40)
        self.assertEqual(config["outcomes"]["capacity"], 200000)
        self.assertEqual(config["security_history"], {
            "capacity": 256, "ttl_seconds": 21600, "per_actor_capacity": 64})
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "guard.json"
            path.write_text(json.dumps(config))
            process = subprocess.run(
                [sys.executable, "-m", "enkstein_guard", "--config", str(path),
                 "config", "validate"], cwd=ROOT, env=os.environ.copy(),
                capture_output=True, text=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(json.loads(process.stdout)["status"], "ok")

    def test_config_preserves_fixed_isolated_ai_topology(self):
        config = endurance.endurance_config()
        self.assertEqual(len(config["agents"]), 4)
        self.assertEqual(len({item["uid"] for item in config["agents"]}), 4)
        self.assertEqual({item["tenant"] for item in config["agents"]}, {"a", "b"})
        self.assertTrue(all(item["routes"] == [item["tenant"] + ".business"]
                            for item in config["agents"]))
        self.assertTrue(all(item["privacy"] == "tokenize" for item in config["routes"]))
        self.assertEqual(len(config["security_engines"]), 2)
        self.assertEqual(len(config["connectors"]), 4)
        self.assertEqual(len({item["credential"] for item in config["connectors"]}), 4)
        self.assertEqual({item["model"] for item in config["connectors"]},
                         {"synthetic-model", "synthetic-security"})
        self.assertEqual(config["egress"]["mode"], "proxy")
        checked = endurance.topology_checks(
            config, {"ready": True},
            {"peer_bound": True,
             "preflight": {"network_interfaces": ["lo"],
                           "egress_proxy_healthy": True},
             "config": {"security_engine_count": 2}})
        self.assertTrue(checked["complete"])

    def test_run_delegates_only_after_plan_validation(self):
        observed = {}

        def fake(parameters, config, targets):
            observed.update(parameters=parameters, config=config, targets=targets)
            return 7

        with mock.patch.object(endurance, "execute", side_effect=fake):
            self.assertEqual(endurance.main(["--run", "--duration", "30"]), 7)
        self.assertEqual(observed["parameters"].measured_calls, 240)
        self.assertEqual(len(observed["config"]["agents"]), 4)

    def test_histogram_and_agent_summary_are_strict(self):
        malformed = histogram(1)
        malformed["count"] = True
        with self.assertRaisesRegex(ValueError, "histogram"):
            endurance._parse_histogram(malformed, 1)
        results = {actor: actor_result(actor, "measurement", 60)
                   for actor in ("agent-a-01", "agent-a-02", "agent-b-01", "agent-b-02")}
        aggregate = endurance.aggregate_phase(
            results, {actor: 60 for actor in results}, "measurement", 30)
        self.assertTrue(aggregate["complete"])
        self.assertEqual(aggregate["actual_calls"], 240)
        self.assertEqual(aggregate["total_p99_ms"], 1)
        self.assertEqual(aggregate["window_p99_ms_max"], 1)
        results["agent-a-01"]["summary"]["total_histogram"]["count"] = True
        aggregate = endurance.aggregate_phase(
            results, {actor: 60 for actor in results}, "measurement", 30)
        self.assertFalse(aggregate["complete"])

        results["agent-a-01"] = actor_result("agent-a-01", "measurement", 60)
        results["agent-a-01"]["summary"]["elapsed_seconds"] = 29.999
        aggregate = endurance.aggregate_phase(
            results, {actor: 60 for actor in results}, "measurement", 30)
        self.assertFalse(aggregate["complete"])

    def test_counter_validation_requires_exact_distinct_hash_sets(self):
        phase = {"successful_calls": 4}
        delta = {
            "inspection": 4, "business": 4, "unknown": 0,
            "header_hashes": {
                "inspection": {"a" * 64: 2, "b" * 64: 2},
                "business": {"c" * 64: 2, "d" * 64: 2}, "unknown": {},
            },
        }
        self.assertTrue(endurance.counter_checks(delta, phase)["complete"])
        delta["header_hashes"]["business"] = {"a" * 64: 4}
        self.assertFalse(endurance.counter_checks(delta, phase)["complete"])

    def test_full_target_evaluation_uses_all_measurements_and_identities(self):
        report = report_fixture()
        verdicts = endurance.evaluate_verdicts(report, endurance.load_targets())
        self.assertEqual(set(verdicts), set(endurance.EXPECTED_REQUIREMENTS))
        self.assertTrue(all(value["passed"] for value in verdicts.values()), verdicts)
        report["samples"][1]["guard"]["process"]["fds"] = 257
        verdicts = endurance.evaluate_verdicts(report, endurance.load_targets())
        self.assertFalse(verdicts["AE-04"]["passed"])

    def test_short_smoke_is_distinct_and_cannot_pass_full_target(self):
        report = report_fixture(duration=30, full=False)
        report["verdicts"] = endurance.evaluate_verdicts(report, endurance.load_targets())
        self.assertFalse(report["verdicts"]["AE-01"]["passed"])
        verdict = endurance.short_smoke_verdict(report)
        self.assertTrue(verdict["passed"], verdict)
        self.assertFalse(report["full_acceptance_passed"])

    def test_missing_identity_and_measurement_fail_ae08(self):
        report = report_fixture()
        report["evidence"]["candidate"]["wheel_sha256"] = None
        report["samples"] = []
        verdict = endurance.evaluate_verdicts(report, endurance.load_targets())["AE-08"]
        self.assertFalse(verdict["passed"])
        self.assertIn("samples", verdict["measured"]["missing_measurements"])

    def test_missing_retention_counter_fails_ae06_and_ae08(self):
        report = report_fixture()
        del report["final_status"]["retention"]["audit"]
        verdicts = endurance.evaluate_verdicts(report, endurance.load_targets())
        self.assertFalse(verdicts["AE-06"]["passed"])
        self.assertFalse(verdicts["AE-08"]["passed"])
        self.assertIn("retention.audit.failures",
                      verdicts["AE-08"]["measured"]["missing_measurements"])

    def test_missing_middle_sample_metric_and_coverage_fail_closed(self):
        report = report_fixture()
        del report["samples"][90]["egress"]["process"]["fds"]
        verdicts = endurance.evaluate_verdicts(report, endurance.load_targets())
        self.assertFalse(verdicts["AE-03"]["passed"])
        self.assertFalse(verdicts["AE-04"]["passed"])
        self.assertFalse(verdicts["AE-05"]["passed"])
        self.assertFalse(verdicts["AE-08"]["passed"])
        self.assertIn("samples[90].egress.fds",
                      verdicts["AE-08"]["measured"]["missing_measurements"])

        report = report_fixture()
        del report["samples"][90]
        verdicts = endurance.evaluate_verdicts(report, endurance.load_targets())
        self.assertFalse(verdicts["AE-08"]["passed"])
        self.assertIn("samples.coverage",
                      verdicts["AE-08"]["measured"]["missing_measurements"])

    def test_missing_definitions_revision_and_malformed_latency_fail_closed(self):
        report = report_fixture()
        del report["evidence"]["revision"]["definitions"]
        report["measurement"]["total_p95_ms"] = "not-a-number"
        verdicts = endurance.evaluate_verdicts(report, endurance.load_targets())
        self.assertFalse(verdicts["AE-02"]["passed"])
        self.assertFalse(verdicts["AE-08"]["passed"])

    def test_ae01_requires_clean_successful_warmup(self):
        report = report_fixture()
        report["warmup"].update(successful_calls=255, error_calls=1)
        verdicts = endurance.evaluate_verdicts(report, endurance.load_targets())
        self.assertFalse(verdicts["AE-01"]["passed"])

    def test_measurement_deadline_kills_owned_runs_and_persists_progress(self):
        class Clock:
            now = 0.0

            def monotonic(self):
                return self.now

            def sleep(self, seconds):
                self.now += seconds

        class HungRun:
            def __init__(self):
                self.result_timeouts = []

            def poll(self):
                return None

            def result(self, timeout):
                self.result_timeouts.append(timeout)
                return {"summary": None, "windows": [], "returncode": -9,
                        "stderr": "deadline"}

        clock, run = Clock(), HungRun()
        deployment = object.__new__(endurance.AISecurityEnduranceDeployment)
        deployment.parameters = endurance.EnduranceParameters(30, explicit_duration=True)
        deployment.start_phase = mock.Mock(return_value={"agent-a-01": run})
        deployment.sample_with_status = lambda started: {
            "elapsed_seconds": round(clock.now - started, 3)}
        deployment.guard_cli = mock.Mock(return_value=(0, {"status": "ok"}))
        with tempfile.TemporaryDirectory() as temporary:
            deployment.progress_path = Path(temporary) / "progress.jsonl"
            deployment.progress_path.touch(mode=0o600)
            with (mock.patch.object(endurance.time, "monotonic", side_effect=clock.monotonic),
                  mock.patch.object(endurance.time, "sleep", side_effect=clock.sleep)):
                results, samples, _, elapsed, timed_out = deployment.measurement()
            lines = deployment.progress_path.read_text().splitlines()
        self.assertTrue(timed_out)
        self.assertEqual(run.result_timeouts, [0])
        self.assertEqual(results["agent-a-01"]["returncode"], -9)
        self.assertGreaterEqual(elapsed, 30 + endurance.ACTOR_DRAIN_SECONDS
                                + endurance.PHASE_STARTUP_GRACE_SECONDS)
        self.assertEqual(len(lines), len(samples))
        self.assertTrue(all(json.loads(line)["elapsed_seconds"] >= 0 for line in lines))

    def test_partial_run_still_writes_fail_closed_report(self):
        class FailedDeployment:
            def __init__(self, *args, **kwargs):
                self.progress_path = Path("/tmp/synthetic-progress.jsonl")

            def up(self):
                raise RuntimeError("synthetic_start_failure")

            def redact(self, value):
                return value

            def logs(self):
                return "synthetic logs"

            def down(self):
                pass

        written = {}

        def write(name, report):
            written.update(name=name, report=report)
            return Path(name)

        with (mock.patch.object(endurance, "AISecurityEnduranceDeployment", FailedDeployment),
              mock.patch.object(endurance, "write_report", side_effect=write),
              redirect_stdout(io.StringIO())):
            code = endurance.execute(
                endurance.EnduranceParameters(30, explicit_duration=True),
                endurance.endurance_config(), endurance.load_targets())
        self.assertEqual(code, 1)
        self.assertEqual(written["name"], endurance.SMOKE_REPORT)
        self.assertIn("synthetic_start_failure", written["report"]["error"])
        self.assertEqual(len(written["report"]["verdicts"]), 8)
        self.assertFalse(any(item["passed"] for item in written["report"]["verdicts"].values()))


class AIEnduranceLoadTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def args(token, **changes):
        values = {"phase": "measurement", "actor": "agent-a-01",
                  "route": "a.business", "token_file": str(token), "duration": 30}
        values.update(changes)
        return argparse.Namespace(**values)

    def test_fixed_count_and_histogram_are_bounded_and_recomputable(self):
        self.assertEqual(actor_load.scheduled_count(30), 60)
        self.assertEqual(actor_load.scheduled_count(10800), 21600)
        with self.assertRaises(ValueError):
            actor_load.scheduled_count(29)
        value = actor_load.Histogram()
        for latency in (0.1, 1.2, 2.9, 3.0):
            value.add(latency)
        self.assertEqual(value.percentile(.95), 3)
        self.assertEqual(value.report()["count"], 4)

    async def test_each_call_uses_one_unique_id_and_never_retries(self):
        with tempfile.TemporaryDirectory() as temporary:
            token = Path(temporary) / "token"
            token.write_text("synthetic-agent-token")
            load = actor_load.Load(self.args(token))
            with (mock.patch.object(actor_load, "new_request_id",
                                    side_effect=("req-one", "req-two")),
                  mock.patch.object(actor_load, "guarded_request",
                                    new=mock.AsyncMock(return_value={"status": "ok"})) as request):
                await load.one(1)
                await load.one(2)
        self.assertEqual(request.await_count, 2)
        self.assertEqual([call.kwargs["request_id"] for call in request.await_args_list],
                         ["req-one", "req-two"])
        self.assertEqual(load.statuses, {"ok": 2})
        self.assertEqual(len(load.request_ids), 2)

    async def test_duplicate_client_id_is_explicit_and_not_dispatched_twice(self):
        with tempfile.TemporaryDirectory() as temporary:
            token = Path(temporary) / "token"
            token.write_text("synthetic-agent-token")
            load = actor_load.Load(self.args(token))
            with (mock.patch.object(actor_load, "new_request_id", return_value="same"),
                  mock.patch.object(actor_load, "guarded_request",
                                    new=mock.AsyncMock(return_value={"status": "ok"})) as request):
                await load.one(1)
                await load.one(2)
        self.assertEqual(request.await_count, 1)
        self.assertEqual(load.statuses, {"client_error:duplicate_request_id": 1, "ok": 1})


if __name__ == "__main__":
    unittest.main()
