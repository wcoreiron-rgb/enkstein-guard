from copy import deepcopy
import builtins
import importlib.metadata
import json
import math
import unittest
from unittest import mock

from enkstein_guard.agt_policy import (
    AGTPolicyError,
    build_policy_control,
    validate_policy_engine,
)


class AGTPolicyDefinitionTests(unittest.TestCase):
    def setUp(self):
        self.agents = [
            {
                "id": "agent-a",
                "tenant": "tenant-a",
                "principal": "principal-a",
                "routes": ["orders.read", "orders.write"],
            },
            {
                "id": "agent-b",
                "tenant": "tenant-b",
                "principal": "principal-b",
                "routes": ["foreign.read"],
            },
        ]
        self.routes = [
            {
                "name": "orders.read",
                "tenant": "tenant-a",
                "operation": "records.read",
                "policy_engine": "orders-policy",
            },
            {
                "name": "orders.write",
                "tenant": "tenant-a",
                "operation": "records.write",
                "policy_engine": None,
            },
            {
                "name": "foreign.read",
                "tenant": "tenant-b",
                "operation": "records.read",
                "policy_engine": "foreign-policy",
            },
            {
                "name": "security.inspect",
                "tenant": "tenant-a",
                "operation": "security.assess",
                "policy_engine": "orders-policy",
            },
        ]
        self.definition = {
            "name": "orders-policy",
            "kind": "agt",
            "tenant": "tenant-a",
            "bindings": [{
                "agent": "agent-a",
                "route": "orders.read",
                "conditions": [
                    {"field": "approved", "operator": "eq", "value": True},
                    {"field": "order.amount", "operator": "lte", "value": 100},
                    {"field": "order.risk", "operator": "gte", "value": 0.25},
                    {"field": "note", "operator": "eq", "value": ""},
                ],
            }],
        }

    def assert_invalid(self, definition=None, *, agents=None, routes=None):
        with self.assertRaisesRegex(AGTPolicyError, "^agt_policy_invalid$"):
            validate_policy_engine(
                self.definition if definition is None else definition,
                agents=self.agents if agents is None else agents,
                routes=self.routes if routes is None else routes,
            )

    def test_valid_definition_returns_detached_json_normal_form_without_sdk(self):
        original_import = builtins.__import__

        def guarded_import(name, *args, **kwargs):
            if name.startswith("agent_control_plane"):
                raise AssertionError("pure validation imported optional AGT SDK")
            return original_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=guarded_import):
            normalized = validate_policy_engine(
                self.definition,
                agents=self.agents,
                routes=self.routes,
            )

        self.assertEqual(normalized, self.definition)
        self.assertIsNot(normalized, self.definition)
        self.assertIsNot(normalized["bindings"], self.definition["bindings"])
        self.assertEqual(json.loads(json.dumps(normalized, allow_nan=False)), normalized)
        self.definition["bindings"][0]["conditions"][0]["value"] = False
        self.assertIs(normalized["bindings"][0]["conditions"][0]["value"], True)

    def test_exact_schema_limits_fields_operators_and_values(self):
        cases = []

        extra = deepcopy(self.definition)
        extra["shadow_mode"] = False
        cases.append(extra)
        wrong_kind = deepcopy(self.definition)
        wrong_kind["kind"] = "nemo"
        cases.append(wrong_kind)
        no_bindings = deepcopy(self.definition)
        no_bindings["bindings"] = []
        cases.append(no_bindings)
        too_many_bindings = deepcopy(self.definition)
        too_many_bindings["bindings"] *= 257
        cases.append(too_many_bindings)
        duplicate = deepcopy(self.definition)
        duplicate["bindings"] *= 2
        cases.append(duplicate)
        no_conditions = deepcopy(self.definition)
        no_conditions["bindings"][0]["conditions"] = []
        cases.append(no_conditions)
        too_many_conditions = deepcopy(self.definition)
        too_many_conditions["bindings"][0]["conditions"] *= 17
        cases.append(too_many_conditions)
        condition_extra = deepcopy(self.definition)
        condition_extra["bindings"][0]["conditions"][0]["code"] = "return True"
        cases.append(condition_extra)

        for field in (
            "",
            "order..amount",
            "order.*",
            "order.0",
            "order.__class__",
            "order.foo__bar",
            "a.b.c.d.e.f.g.h.i",
            "a" * 65,
            "order/amount",
        ):
            item = deepcopy(self.definition)
            item["bindings"][0]["conditions"][0]["field"] = field
            cases.append(item)
        for operator, value in (
            ("ne", True),
            ("lte", True),
            ("gte", "10"),
            ("eq", None),
            ("eq", []),
            ("eq", math.nan),
            ("eq", math.inf),
            ("eq", "x" * 257),
        ):
            item = deepcopy(self.definition)
            item["bindings"][0]["conditions"][0].update(
                {"operator": operator, "value": value}
            )
            cases.append(item)

        for index, definition in enumerate(cases):
            with self.subTest(index=index):
                self.assert_invalid(definition)

    def test_binding_must_preserve_tenant_grant_route_and_policy_selection(self):
        unknown_agent = deepcopy(self.definition)
        unknown_agent["bindings"][0]["agent"] = "missing"
        self.assert_invalid(unknown_agent)

        unknown_route = deepcopy(self.definition)
        unknown_route["bindings"][0]["route"] = "missing"
        self.assert_invalid(unknown_route)

        foreign_agent = deepcopy(self.definition)
        foreign_agent["bindings"][0].update(
            {"agent": "agent-b", "route": "foreign.read"}
        )
        self.assert_invalid(foreign_agent)

        missing_grant = deepcopy(self.definition)
        missing_grant["bindings"][0]["route"] = "orders.write"
        agents = deepcopy(self.agents)
        agents[0]["routes"] = ["orders.read"]
        self.assert_invalid(missing_grant, agents=agents)

        unselected = deepcopy(self.definition)
        unselected["bindings"][0]["route"] = "orders.write"
        self.assert_invalid(unselected)

        internal = deepcopy(self.definition)
        internal["bindings"][0]["route"] = "security.inspect"
        agents = deepcopy(self.agents)
        agents[0]["routes"].append("security.inspect")
        self.assert_invalid(internal, agents=agents)

        routes = deepcopy(self.routes)
        routes[0]["tenant"] = "tenant-b"
        self.assert_invalid(routes=routes)

    def test_agent_and_route_registries_fail_closed_on_ambiguous_inputs(self):
        duplicate_agents = deepcopy(self.agents)
        duplicate_agents.append(deepcopy(self.agents[0]))
        self.assert_invalid(agents=duplicate_agents)

        duplicate_routes = deepcopy(self.routes)
        duplicate_routes.append(deepcopy(self.routes[0]))
        self.assert_invalid(routes=duplicate_routes)

        bad_grants = deepcopy(self.agents)
        bad_grants[0]["routes"].append("orders.read")
        self.assert_invalid(agents=bad_grants)

    def test_sdk_unavailable_and_incompatible_errors_are_fixed(self):
        with mock.patch.object(
                importlib.metadata,
                "version",
                side_effect=importlib.metadata.PackageNotFoundError("missing")):
            with self.assertRaisesRegex(
                    AGTPolicyError, "^agt_policy_sdk_unavailable$"):
                build_policy_control(
                    self.definition,
                    agents=self.agents,
                    routes=self.routes,
                )

        with mock.patch.object(importlib.metadata, "version", return_value="4.9.0"):
            with self.assertRaisesRegex(
                    AGTPolicyError, "^agt_policy_sdk_incompatible$"):
                build_policy_control(
                    self.definition,
                    agents=self.agents,
                    routes=self.routes,
                )


if __name__ == "__main__":
    unittest.main()
