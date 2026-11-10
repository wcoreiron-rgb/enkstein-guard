"""Product configuration, host, and CLI contracts for optional local AGT policy."""

import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from enkstein_guard.agt_policy import AGTPolicyError
from enkstein_guard.cli import cmd_doctor, cmd_policy
from enkstein_guard.contracts import Action, ControlResult
from enkstein_guard.host import GuardHost, HostError, StateLayout, admin_request, initialize_state
from enkstein_guard.identities import IdentityStore
from enkstein_guard.outcomes import new_request_id
from enkstein_guard.productconfig import ConfigError, validate
from enkstein_guard.service import guarded_request
from test_host import DECLARED, make_config


def route(data, name):
    return next(item for item in data["routes"] if item["name"] == name)


def configured(root):
    data = make_config(root)
    route(data, "crm.lookup")["policy_engine"] = "local-abac"
    data["policy_engines"] = [{
        "name": "local-abac",
        "kind": "agt",
        "tenant": "tenant-a",
        "bindings": [{
            "agent": "agent-a",
            "route": "crm.lookup",
            "conditions": [{"field": "note", "operator": "eq", "value": "lookup"}],
        }],
    }]
    return data


class AGTPolicyConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-agt-config-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def errors(self, data):
        with self.assertRaises(ConfigError) as caught:
            validate(data)
        return {(item["path"], item["code"]) for item in caught.exception.errors}

    def test_default_is_empty_and_does_not_require_optional_runtime(self):
        config = validate(make_config(self.root))
        self.assertEqual(config["policy_engines"], [])
        self.assertTrue(all(item["policy_engine"] is None for item in config["routes"]))
        self.assertEqual(config.summary()["policy_engine_count"], 0)

    def test_valid_definition_is_deep_normalized_and_fingerprinted(self):
        data = configured(self.root)
        route(data, "ticket.comment")["controls"] = ["local_prompt", "sensitivity"]
        config = validate(data)
        data["policy_engines"][0]["bindings"][0]["conditions"][0]["value"] = "changed"
        data["agents"][0]["routes"].clear()
        data["agents"][0]["groups"].clear()
        route(data, "ticket.comment")["controls"].clear()
        boundary_rule = route(data, "ticket.comment")["task_boundaries"][0]["fields"][0]
        boundary_rule["path"].clear()
        boundary_rule["choices"].clear()
        data["approvers"][0]["tenants"].clear()
        declared = data["sensitivity"]["declared_context"][0]
        data["sensitivity"]["declared_context"].clear()
        declared.update(name="poisoned", level="public", file="/poisoned")
        self.assertEqual(
            config["policy_engines"][0]["bindings"][0]["conditions"][0]["value"],
            "lookup",
        )
        self.assertIn("crm.lookup", config.agent("agent-a")["routes"])
        self.assertEqual(config.agent("agent-a")["groups"], ["support"])
        normalized_route = config.route("ticket.comment")
        self.assertEqual(normalized_route["controls"], ["local_prompt", "sensitivity"])
        self.assertEqual(normalized_route["task_boundaries"][0]["fields"][0]["path"], ["ticket"])
        self.assertEqual(normalized_route["task_boundaries"][0]["fields"][0]["choices"], ["INC-42"])
        self.assertEqual(config["approvers"][0]["tenants"], ["tenant-a"])
        self.assertEqual(config["sensitivity"]["declared_context"], [{
            "name": "routing", "level": "restricted",
            "file": str(self.root / "declared.txt"),
        }])
        summary = config.summary()
        self.assertEqual(summary["policy_engine_count"], 1)
        self.assertEqual(summary["policy_engine_route_count"], 1)
        self.assertEqual(summary["policy_engines"][0]["conditions"], 1)

        changed = configured(self.root)
        changed["policy_engines"][0]["bindings"][0]["conditions"][0]["value"] = "other"
        self.assertNotEqual(config.reload_key(), validate(changed).reload_key())

    def test_strict_shape_condition_types_and_duplicate_bindings_are_rejected(self):
        unknown = configured(self.root)
        unknown["policy_engines"][0]["extra"] = True
        self.assertIn(("$.policy_engines[0].extra", "unknown_field"), self.errors(unknown))

        field = configured(self.root)
        field["policy_engines"][0]["bindings"][0]["conditions"][0]["field"] = "args.__class__"
        self.assertIn((
            "$.policy_engines[0].bindings[0].conditions[0].field",
            "invalid_policy_field",
        ), self.errors(field))

        numeric = configured(self.root)
        numeric["policy_engines"][0]["bindings"][0]["conditions"][0].update(
            operator="gte", value=True)
        self.assertIn((
            "$.policy_engines[0].bindings[0].conditions[0].value",
            "numeric_policy_value_required",
        ), self.errors(numeric))

        duplicate = configured(self.root)
        duplicate["policy_engines"][0]["bindings"].append(
            copy.deepcopy(duplicate["policy_engines"][0]["bindings"][0]))
        self.assertIn(("$.policy_engines[0].bindings[1]", "duplicate_policy_binding"),
                      self.errors(duplicate))

    def test_unknown_cross_tenant_ungranted_unused_and_internal_bindings_are_rejected(self):
        unknown = configured(self.root)
        unknown["policy_engines"][0]["bindings"][0]["agent"] = "missing"
        self.assertIn(("$.policy_engines[0].bindings[0].agent", "unknown_agent"),
                      self.errors(unknown))

        cross = configured(self.root)
        cross["policy_engines"][0]["tenant"] = "tenant-b"
        errors = self.errors(cross)
        self.assertIn(("$.routes[5].policy_engine", "cross_tenant_policy_engine"), errors)
        self.assertIn(("$.policy_engines[0].bindings[0].agent", "cross_tenant_policy_binding"), errors)

        ungranted = configured(self.root)
        ungranted["policy_engines"][0]["bindings"][0]["route"] = "forum.post"
        self.assertIn(("$.policy_engines[0].bindings[0].route", "route_policy_engine_mismatch"),
                      self.errors(ungranted))

        unused = configured(self.root)
        route(unused, "crm.lookup")["policy_engine"] = None
        self.assertIn(("$.policy_engines[0]", "unused_policy_engine"), self.errors(unused))

        internal = configured(self.root)
        route(internal, "crm.lookup")["operation"] = "security.assess"
        self.assertIn(("$.routes[5].policy_engine", "internal_security_route_policy_forbidden"),
                      self.errors(internal))

    def test_cli_explain_and_doctor_are_discoverable_without_condition_values(self):
        path = self.root / "config.json"
        path.write_text(json.dumps(configured(self.root)))
        arguments = SimpleNamespace(config=str(path), route=None)

        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(cmd_policy(arguments), 0)
        policy = json.loads(output.getvalue())
        selected = next(item for item in policy["routes"] if item["name"] == "crm.lookup")
        self.assertEqual(selected["policy_engine"], "local-abac")
        self.assertIn("agt.local-abac", selected["required_controls"])
        self.assertEqual(policy["policy_engines"][0]["bindings"], 1)
        self.assertNotIn("lookup", json.dumps(policy["policy_engines"]))

        packages = {
            "cryptography": "test", "nemoguardrails": "not_installed",
            "cisco-aidefense-sdk": "not_installed",
            "agent-governance-toolkit-control-plane": "not_installed",
        }
        output = io.StringIO()
        with patch("enkstein_guard.cli._optional_packages", return_value=packages), \
                redirect_stdout(output):
            self.assertEqual(cmd_doctor(arguments, None), 0)
        doctor = json.loads(output.getvalue())
        self.assertEqual(doctor["controls"]["agt_policy_engine"]["state"], "unavailable")
        self.assertIn("agt_policy_engine_unavailable",
                      doctor["mandatory_enforcement_status"]["reasons"])
        self.assertEqual(doctor["agt_policy"]["live_vendor_validation"], "not_performed")


class AGTPolicyHostTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-agt-host-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("sock", "admin"):
            (self.root / name).mkdir(mode=0o700)
        (self.root / "declared.txt").write_text(DECLARED)
        self.host = None

    async def asyncTearDown(self):
        if self.host is not None:
            await self.host.stop()

    def prepare(self, data):
        config = validate(data)
        initialize_state(config)
        identities = IdentityStore(*StateLayout(config).identities)
        token_file = self.root / "agent.token"
        identities.issue("agent", "agent-a", token_file)
        return config, token_file.read_text().strip()

    async def test_required_control_receives_prepared_payload_and_may_only_deny(self):
        config, credential = self.prepare(configured(self.root))
        seen = []

        def build(definition, *, agents, routes):
            self.assertEqual(definition["name"], "local-abac")
            self.assertTrue(any(item["name"] == "crm.lookup" for item in routes))

            async def control(operation):
                payload = operation.payload()
                seen.append((operation.context.tenant_id, operation.context.agent_id,
                             operation.route, payload))
                allowed = payload.get("note") == "lookup"
                return ControlResult(
                    "agt.local-abac", operation.context.tenant_id,
                    operation.context.operation_id, Action.ALLOW if allowed else Action.DENY)
            return control

        with patch("enkstein_guard.agt_policy.build_policy_control", side_effect=build):
            self.host = await GuardHost(config).start()

        allowed = await guarded_request(
            config["paths"]["socket"], credential, "crm.lookup",
            {"email": "jane@example.com", "note": "lookup"},
            request_id=new_request_id(), timeout=10)
        self.assertEqual(allowed["status"], "ok")
        self.assertEqual(seen[0][:3], ("tenant-a", "agent-a", "crm.lookup"))
        self.assertNotIn("jane@example.com", json.dumps(seen[0][3]))

        denied = await guarded_request(
            config["paths"]["socket"], credential, "crm.lookup",
            {"email": "jane@example.com", "note": "wrong"},
            request_id=new_request_id(), timeout=10)
        self.assertEqual((denied["status"], denied["reason"]), ("denied", "policy_denied"))

        calls = len(seen)
        privacy_denied = await guarded_request(
            config["paths"]["socket"], credential, "crm.lookup",
            {"card": 4111111111111111, "note": "lookup"},
            request_id=new_request_id(), timeout=10)
        self.assertEqual(privacy_denied["status"], "denied")
        self.assertEqual(len(seen), calls)

    async def test_configured_build_failure_rejects_service_start_with_fixed_reason(self):
        config, _ = self.prepare(configured(self.root))
        with patch("enkstein_guard.agt_policy.build_policy_control",
                   side_effect=AGTPolicyError("agt_policy_sdk_unavailable")):
            with self.assertRaisesRegex(HostError, "^agt_policy_sdk_unavailable$"):
                await GuardHost(config).start()

    async def test_default_configuration_never_builds_optional_policy(self):
        config, _ = self.prepare(make_config(self.root))
        with patch("enkstein_guard.agt_policy.build_policy_control",
                   side_effect=AssertionError("optional policy must stay unloaded")):
            self.host = await GuardHost(config).start()
        self.assertEqual(self.host.config.summary()["policy_engine_count"], 0)

    async def test_raw_mutation_cannot_remove_approver_authority_or_declared_privacy(self):
        raw = make_config(self.root)
        config = validate(raw)
        raw["approvers"][0]["tenants"].clear()
        raw["sensitivity"]["declared_context"].clear()

        initialize_state(config)
        identities = IdentityStore(*StateLayout(config).identities)
        credentials = {}
        for kind, name in (("agent", "agent-a"), ("approver", "alice")):
            token_file = self.root / (name + ".token")
            identities.issue(kind, name, token_file)
            credentials[name] = token_file.read_text().strip()
        self.host = await GuardHost(config).start()

        withheld = await guarded_request(
            config["paths"]["socket"], credentials["agent-a"], "vault.write",
            {"note": "routing phrase is " + DECLARED},
            request_id=new_request_id(), timeout=10)
        self.assertEqual((withheld["status"], withheld["reason"]),
                         ("response_withheld", "sensitivity"))

        payload = {"ticket": "INC-42", "reason": "resolved"}
        request_id = new_request_id()
        pending = await guarded_request(
            config["paths"]["socket"], credentials["agent-a"], "ticket.close",
            payload, request_id=request_id, timeout=10)
        self.assertEqual(pending["status"], "approval_required")
        approved = await admin_request(config["paths"]["admin_socket"], "approvals.decide", {
            "ticket": pending["ticket"],
            "approver_credential": credentials["alice"],
            "action_digest": pending["action_digest"],
            "decision": "approve",
        })
        self.assertEqual(approved["status"], "ok")
        executed = await guarded_request(
            config["paths"]["socket"], credentials["agent-a"], "ticket.close",
            payload, request_id=request_id, approval=pending["ticket"], timeout=10)
        self.assertEqual(executed["status"], "ok")


if __name__ == "__main__":
    unittest.main()
