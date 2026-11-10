import copy
import importlib.metadata
import math
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from enkstein_guard.agt_policy import (
    AGTPolicyError,
    build_policy_control,
    validate_policy_engine,
)
from enkstein_guard.productconfig import ConfigError, validate
from test_ai_security_host import configured as configured_security_engine
from test_host import make_config


def route(data, name):
    return next(item for item in data["routes"] if item["name"] == name)


def configured(root):
    data = make_config(root)
    route(data, "ticket.comment")["policy_engine"] = "local-gate"
    data["policy_engines"] = [{
        "name": "local-gate",
        "kind": "agt",
        "tenant": "tenant-a",
        "bindings": [{
            "agent": "agent-a",
            "route": "ticket.comment",
            "conditions": [{"field": "ticket", "operator": "eq", "value": "INC-42"}],
        }],
    }]
    return data


class AGTPolicyConfigurationSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-agt-policy-security-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def errors(self, data):
        with self.assertRaises(ConfigError) as caught:
            validate(data)
        return {(item["path"], item["code"]) for item in caught.exception.errors}

    def test_tenant_agent_route_and_grant_widening_are_rejected(self):
        cases = []

        foreign_engine = configured(self.root)
        foreign_engine["policy_engines"][0]["tenant"] = "tenant-b"
        cases.append((foreign_engine, "cross_tenant_policy_binding"))

        foreign_agent = configured(self.root)
        foreign_agent["policy_engines"][0]["bindings"][0]["agent"] = "agent-b"
        cases.append((foreign_agent, "cross_tenant_policy_binding"))

        ungranted = configured(self.root)
        ungranted["policy_engines"][0]["bindings"][0]["route"] = "b.read"
        cases.append((ungranted, "route_not_granted_to_agent"))

        not_selected = configured(self.root)
        not_selected["policy_engines"][0]["bindings"][0]["route"] = "forum.post"
        cases.append((not_selected, "route_policy_engine_mismatch"))

        unknown_agent = configured(self.root)
        unknown_agent["policy_engines"][0]["bindings"][0]["agent"] = "missing-agent"
        cases.append((unknown_agent, "unknown_agent"))

        unknown_route = configured(self.root)
        unknown_route["policy_engines"][0]["bindings"][0]["route"] = "missing.route"
        cases.append((unknown_route, "unknown_route"))

        for data, expected in cases:
            with self.subTest(expected=expected):
                self.assertIn(expected, {code for _, code in self.errors(data)})

    def test_internal_inspector_unused_engine_and_duplicate_binding_are_rejected(self):
        internal = configured_security_engine(self.root)
        route(internal, "security.inspect")["policy_engine"] = "local-gate"
        internal["policy_engines"] = [{
            "name": "local-gate",
            "kind": "agt",
            "tenant": "tenant-a",
            "bindings": [{
                "agent": "agent-a",
                "route": "security.inspect",
                "conditions": [{"field": "approved", "operator": "eq", "value": True}],
            }],
        }]
        codes = {code for _, code in self.errors(internal)}
        self.assertIn("internal_security_route_policy_forbidden", codes)

        unused = configured(self.root)
        route(unused, "ticket.comment")["policy_engine"] = None
        self.assertIn("unused_policy_engine", {code for _, code in self.errors(unused)})

        duplicate = configured(self.root)
        duplicate["policy_engines"][0]["bindings"].append(
            copy.deepcopy(duplicate["policy_engines"][0]["bindings"][0])
        )
        self.assertIn("duplicate_policy_binding", {code for _, code in self.errors(duplicate)})

    def test_unknown_schema_operator_endpoint_and_plugin_fields_are_rejected(self):
        additions = (
            ("engine-schema", lambda data: data["policy_engines"][0].update(
                {"schema_version": 1})),
            ("engine-endpoint", lambda data: data["policy_engines"][0].update(
                {"endpoint": "https://policy.invalid"})),
            ("engine-plugin", lambda data: data["policy_engines"][0].update(
                {"plugin": "arbitrary.py"})),
            ("binding-role", lambda data: data["policy_engines"][0]["bindings"][0].update(
                {"role": "admin"})),
            ("condition-code", lambda data: data["policy_engines"][0]["bindings"][0][
                "conditions"][0].update({"code": "payload.approved"})),
        )
        for name, mutate in additions:
            with self.subTest(name=name):
                data = configured(self.root)
                mutate(data)
                self.assertIn("unknown_field", {code for _, code in self.errors(data)})

        operator = configured(self.root)
        operator["policy_engines"][0]["bindings"][0]["conditions"][0]["operator"] = "contains"
        self.assertIn("unsupported_value", {code for _, code in self.errors(operator)})

        kind = configured(self.root)
        kind["policy_engines"][0]["kind"] = "python"
        self.assertIn("unsupported_value", {code for _, code in self.errors(kind)})

    def test_field_grammar_missing_null_and_nonscalar_values_are_strict(self):
        invalid_fields = (
            "", ".approved", "approved.", "a..b", "items[0]", "items.*",
            "__class__", "safe.__dict__", "9starts-with-number",
            ".".join("part" for _ in range(9)), "a" * 65,
        )
        for index, field in enumerate(invalid_fields):
            with self.subTest(field=field):
                data = configured(self.root)
                data["policy_engines"][0]["bindings"][0]["conditions"][0]["field"] = field
                self.assertIn("invalid_policy_field", {code for _, code in self.errors(data)})

        invalid_values = (None, [], {}, math.nan, math.inf, -math.inf, "x" * 257)
        for index, value in enumerate(invalid_values):
            with self.subTest(value=index):
                data = configured(self.root)
                data["policy_engines"][0]["bindings"][0]["conditions"][0]["value"] = value
                self.assertIn("policy_scalar_required", {code for _, code in self.errors(data)})

        for operator, value in (("lte", True), ("gte", False), ("lte", "1")):
            with self.subTest(operator=operator, value=value):
                data = configured(self.root)
                condition = data["policy_engines"][0]["bindings"][0]["conditions"][0]
                condition.update(operator=operator, value=value)
                self.assertIn("numeric_policy_value_required",
                              {code for _, code in self.errors(data)})

        for missing in ("field", "operator", "value"):
            with self.subTest(missing=missing):
                data = configured(self.root)
                del data["policy_engines"][0]["bindings"][0]["conditions"][0][missing]
                self.assertIn("required_field_missing", {code for _, code in self.errors(data)})

    def test_valid_normalization_is_deep_and_not_aliased_to_mutable_input(self):
        raw = configured(self.root)
        normalized = validate(raw)
        expected = copy.deepcopy(normalized["policy_engines"])

        raw["policy_engines"][0]["tenant"] = "tenant-b"
        raw["policy_engines"][0]["bindings"][0]["agent"] = "agent-b"
        raw["policy_engines"][0]["bindings"][0]["conditions"][0]["field"] = "poisoned"
        raw["agents"][0]["routes"].clear()
        route(raw, "ticket.comment")["policy_engine"] = None

        self.assertEqual(normalized["policy_engines"], expected)
        self.assertEqual(normalized.route("ticket.comment")["policy_engine"], "local-gate")
        self.assertIn("ticket.comment", normalized.agent("agent-a")["routes"])


class AGTPolicyPublicAPISecurityTests(unittest.TestCase):
    def setUp(self):
        self.agents = [{
            "id": "agent-a",
            "tenant": "tenant-a",
            "principal": "principal-a",
            "routes": ["orders.read"],
        }]
        self.routes = [{
            "name": "orders.read",
            "tenant": "tenant-a",
            "operation": "orders.read",
            "policy_engine": "orders-gate",
        }]
        self.definition = {
            "name": "orders-gate",
            "kind": "agt",
            "tenant": "tenant-a",
            "bindings": [{
                "agent": "agent-a",
                "route": "orders.read",
                "conditions": [{
                    "field": "order.approved",
                    "operator": "eq",
                    "value": True,
                }],
            }],
        }

    def test_public_compiler_rejects_embedded_dunder_segment(self):
        definition = copy.deepcopy(self.definition)
        definition["bindings"][0]["conditions"][0]["field"] = "order.safe__class"
        with self.assertRaisesRegex(AGTPolicyError, "^agt_policy_invalid$"):
            validate_policy_engine(definition, agents=self.agents, routes=self.routes)

    def test_public_compiler_snapshot_is_detached_from_all_inputs(self):
        normalized = validate_policy_engine(
            self.definition, agents=self.agents, routes=self.routes
        )
        expected = copy.deepcopy(normalized)

        self.definition["bindings"][0]["conditions"][0]["value"] = False
        self.agents[0]["routes"].clear()
        self.routes[0]["policy_engine"] = None

        self.assertEqual(normalized, expected)

    def test_missing_and_incompatible_sdk_errors_are_fixed_and_non_sensitive(self):
        secret = "synthetic-sensitive-sdk-detail"
        with mock.patch.object(
                importlib.metadata, "version", side_effect=RuntimeError(secret)):
            with self.assertRaisesRegex(
                    AGTPolicyError, "^agt_policy_sdk_unavailable$") as caught:
                build_policy_control(
                    self.definition, agents=self.agents, routes=self.routes
                )
        self.assertNotIn(secret, str(caught.exception))

        with mock.patch.object(importlib.metadata, "version", return_value="4.0.0"):
            with self.assertRaisesRegex(
                    AGTPolicyError, "^agt_policy_sdk_incompatible$"):
                build_policy_control(
                    self.definition, agents=self.agents, routes=self.routes
                )


if __name__ == "__main__":
    unittest.main()
