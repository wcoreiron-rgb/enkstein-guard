"""Offline contracts for the opt-in physical AGT deployment harness."""

from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "deployment"))
sys.path.insert(0, str(ROOT / "deployment/acceptance"))

import agt_policy_agent as agent  # noqa: E402
import test_agt_policy_profile as profile  # noqa: E402
from enkstein_guard.productconfig import validate  # noqa: E402
from enkstein_guard.providers import chat_request_allowed  # noqa: E402


class AGTPolicyProfileContractTests(unittest.TestCase):
    def test_configuration_is_strict_two_tenant_bound_and_source_validated_only(self):
        raw = profile.agt_policy_config()
        config = validate(raw)
        self.assertEqual(config["profile"], "production-linux-peer-bound")
        self.assertEqual(len(config["tenants"]), 2)
        self.assertEqual(len(config["agents"]), 2)
        self.assertEqual(len(config["routes"]), 2)
        self.assertEqual(len(config["policy_engines"]), 2)
        self.assertNotIn("security_engines", {
            key for key, value in raw.items() if key == "security_engines" and value})

        for tenant in ("a", "b"):
            route = next(item for item in config["routes"] if item["tenant"] == tenant)
            actor = next(item for item in config["agents"] if item["tenant"] == tenant)
            engine = next(item for item in config["policy_engines"] if item["tenant"] == tenant)
            binding = engine["bindings"][0]
            self.assertEqual(route["name"], tenant + ".model")
            self.assertEqual(route["privacy"], "tokenize")
            self.assertEqual(route["policy_engine"], engine["name"])
            self.assertEqual(actor["routes"], [route["name"]])
            self.assertEqual((binding["agent"], binding["route"]),
                             (actor["id"], route["name"]))
            self.assertEqual(binding["conditions"], [{
                "field": "max_tokens", "operator": "eq", "value": 64,
            }])
            connector = next(item for item in config["connectors"]
                             if item["name"] == route["connector"])
            self.assertEqual(connector["endpoint"],
                             "https://upstream.acceptance.test/v1/chat/completions")
            self.assertEqual(connector["model"], "synthetic-model")
            self.assertEqual(connector["credential"], "key-" + tenant)

        plan = profile.plan()
        self.assertEqual(plan["source_validation_context"],
                         "source_bootstrap_only_not_installed_candidate")
        self.assertFalse(plan["production_accepted"])
        self.assertFalse(plan["docker_executed"])

    def test_agent_scenarios_cover_exact_type_privacy_and_authorization_boundaries(self):
        scenarios = {name: (route, payload)
                     for name, route, payload in agent.scenarios("a")}
        self.assertEqual(set(scenarios), {"allowed", *agent.DENIED_SCENARIOS})
        self.assertTrue(chat_request_allowed(scenarios["allowed"][1]))
        self.assertIs(type(scenarios["allowed"][1]["max_tokens"]), int)
        self.assertIs(type(scenarios["bool"][1]["max_tokens"]), bool)
        self.assertIs(type(scenarios["float"][1]["max_tokens"]), float)
        self.assertIsNone(scenarios["null"][1]["max_tokens"])
        self.assertNotIn("max_tokens", scenarios["missing"][1])
        self.assertEqual(scenarios["cross_tenant"][0], "b.model")
        self.assertEqual(scenarios["identity_spoof"][0], "b.model")
        self.assertEqual(scenarios["privacy"][1]["max_tokens"], 64)
        self.assertEqual(scenarios["privacy"][1]["seed"], 4111111111111111)
        self.assertIn("[[EGV:" + "0" * 64 + "]]",
                      scenarios["privacy"][1]["messages"][0]["content"])
        self.assertTrue(chat_request_allowed(scenarios["privacy"][1]))

        statuses = {name: "denied" for name in agent.DENIED_SCENARIOS}
        statuses["allowed"] = "ok"
        checks = agent.verdict_checks(statuses)
        self.assertEqual(set(checks), agent.CHECK_NAMES - {
            "egress_socket_absent", "guard_state_absent", "direct_network_denied",
        })
        self.assertTrue(all(value is True for value in checks.values()))
        statuses["bool"] = "ok"
        self.assertFalse(agent.verdict_checks(statuses)["bool_denied"])

    def test_expected_check_set_and_literal_boolean_pass_are_exact(self):
        checks = {name: True for name in profile.EXPECTED_CHECKS}
        self.assertTrue(profile.exact_checks_passed(checks))
        changed = dict(checks)
        changed[next(iter(changed))] = 1
        self.assertFalse(profile.exact_checks_passed(changed))
        missing = dict(checks)
        missing.pop(next(iter(missing)))
        self.assertFalse(profile.exact_checks_passed(missing))
        self.assertFalse(profile.exact_checks_passed({**checks, "unexpected": True}))
        self.assertEqual(
            {"agent_%s_%s" % (tenant, name)
             for tenant in ("a", "b") for name in agent.CHECK_NAMES},
            {name for name in profile.EXPECTED_CHECKS if name.startswith("agent_")},
        )
        self.assertIn("pinned_agt_distribution_and_api_probed", profile.EXPECTED_CHECKS)

    def test_image_probe_targets_imported_pinned_sdk_and_frozen_verdict_api(self):
        deployment = object.__new__(profile.AGTPolicyDeployment)
        deployment.compose = mock.Mock(return_value=SimpleNamespace(
            returncode=0,
            stdout=json.dumps({
                "version": "5.0.0", "module_sha256": profile.AGT_POLICY_MODULE_SHA256,
                "site_packages": True, "api_probe": True,
            }) + "\n",
        ))
        result = deployment.agt_image_probe()
        self.assertEqual(result["version"], "5.0.0")
        command = deployment.compose.call_args.args
        self.assertEqual(command[:5], ("exec", "-T", "guard", "python", "-c"))
        probe_source = command[5]
        self.assertIn("PolicyEngine", probe_source)
        self.assertIn("engine.freeze()", probe_source)
        self.assertIn("check_violation", probe_source)
        self.assertIn("module_sha256", probe_source)
        packages = {"agent-governance-toolkit-control-plane": "5.0.0"}
        self.assertTrue(profile.valid_agt_image_probe(packages, result))
        metadata_only = {"version": "5.0.0"}
        self.assertFalse(profile.valid_agt_image_probe(packages, metadata_only))
        self.assertFalse(profile.valid_agt_image_probe(
            packages, {**result, "api_probe": False}))
        self.assertFalse(profile.valid_agt_image_probe(
            packages, {**result, "module_sha256": "a" * 64}))

    def test_default_main_is_plan_only_and_explicit_run_delegates(self):
        output = io.StringIO()
        with (mock.patch.object(
                profile, "AGTPolicyDeployment",
                side_effect=AssertionError("Docker deployment forbidden in plan mode")),
              redirect_stdout(output)):
            self.assertEqual(profile.main([]), 0)
        result = json.loads(output.getvalue())
        self.assertTrue(result["explicit_run_required"])
        self.assertFalse(result["docker_executed"])

        with mock.patch.object(profile, "execute", return_value=7) as execute:
            self.assertEqual(profile.main(["--run"]), 7)
        execute.assert_called_once_with()

    def test_fresh_import_performs_no_process_or_docker_work(self):
        path = ROOT / "deployment/test_agt_policy_profile.py"
        spec = importlib.util.spec_from_file_location("agt_profile_import_probe", path)
        module = importlib.util.module_from_spec(spec)
        with (mock.patch.object(subprocess, "run",
                               side_effect=AssertionError("subprocess forbidden")),
              mock.patch.object(subprocess, "Popen",
                                side_effect=AssertionError("subprocess forbidden"))):
            spec.loader.exec_module(module)
        self.assertEqual(module.REPORT, "container-agt-policy-profile")
        self.assertFalse(module.plan()["docker_executed"])

    def test_failed_profile_preserves_run_state_and_writes_failure_evidence(self):
        deployment = SimpleNamespace(
            run_all=mock.Mock(side_effect=RuntimeError("fixture failure")),
            logs=mock.Mock(return_value="fixture diagnostic"),
            header=mock.Mock(return_value={"schema": "fixture evidence"}),
            compose=mock.Mock(return_value=SimpleNamespace(returncode=0)),
            down=mock.Mock(side_effect=AssertionError("failed state must not be deleted")),
            redact=lambda text: text,
            project="own-fixture-project", run=Path("/fixture-owned-run"),
        )
        with (mock.patch.object(profile, "AGTPolicyDeployment", return_value=deployment),
              mock.patch.object(profile, "write_report", return_value=Path("/fixture-report")) as write,
              redirect_stdout(io.StringIO())):
            self.assertEqual(profile.execute(), 1)
        report = write.call_args.args[1]
        self.assertFalse(report["passed"])
        self.assertEqual(report["error"], "fixture failure")
        self.assertEqual(report["evidence"], {"schema": "fixture evidence"})
        self.assertTrue(report["retained_failed_run"]["volumes_preserved"])
        deployment.compose.assert_called_once_with("stop", check=False)
        deployment.down.assert_not_called()


if __name__ == "__main__":
    unittest.main()
