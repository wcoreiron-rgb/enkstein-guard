import copy
import json
import math
from pathlib import Path
import tempfile
import unittest

from enkstein_guard.productconfig import ConfigError, load, validate


def production():
    return {
        "schema_version": 2,
        "profile": "production-linux-peer-bound",
        "deployment": {"guard_uid": 10001},
        "paths": {"state_directory": "/state", "key_directory": "/state-keys", "socket": "/run/guard/guard.sock",
                  "admin_socket": "/run/guard-admin/admin.sock", "archive_directory": "/archive"},
        "service": {"socket_group": 10001, "max_connections": 16, "per_peer_connections": 4, "max_requests_per_second": 10},
        "outcomes": {"capacity": 100000, "max_request_age_seconds": 3600},
        "retention": {"outcome_archive_age_seconds": 7200, "outcome_archive_interval_seconds": 600},
        "tenants": [{"id": "tenant-a"}, {"id": "tenant-b"}],
        "backend_inventory": {"schema_version": 1, "backends": [{
            "backend_id": "example-ai", "account_id": "primary-prod", "data_domain": "example-ai-primary-prod",
            "tenants": ["tenant-a", "tenant-b"], "hosts": ["https://ai.example.test"]}]},
        "connectors": [{"name": "hatz", "type": "chat_completions", "endpoint": "https://ai.example.test/v1/chat/completions",
                        "model": "m", "credential": "hatz-key", "authentication": "x-api-key",
                        "data_domain": "example-ai-primary-prod"},
                       {"name": "tickets", "type": "fixture"}],
        "routes": [{"name": "model.chat", "tenant": "tenant-a", "operation": "model.call", "connector": "hatz",
                    "clearance": "internal", "produces": "internal", "privacy": "tokenize"},
                   {"name": "ticket.close", "tenant": "tenant-a", "operation": "ticket.close", "connector": "tickets",
                    "resource": "ticket", "destination": "ticket-service", "clearance": "confidential",
                    "produces": "confidential", "approval": "required"}],
        "agents": [{"id": "agent-a", "tenant": "tenant-a", "principal": "bot", "uid": 11001,
                    "routes": ["model.chat", "ticket.close"]},
                   {"id": "agent-b", "tenant": "tenant-b", "principal": "bot-b", "uid": 11002, "routes": []}],
        "approvers": [{"id": "alice", "tenants": ["tenant-a"]}],
        "egress": {"mode": "proxy", "socket": "/run/guard-egress/egress.sock", "client_uids": [10001],
                   "allow": [{"host": "ai.example.test", "port": 443}]},
    }


class ProductConfigTests(unittest.TestCase):
    def codes(self, data):
        with self.assertRaises(ConfigError) as caught:
            validate(data)
        return {(e["path"], e["code"]) for e in caught.exception.errors}

    def test_valid_production_config_derives_connector_bindings(self):
        config = validate(production())
        self.assertTrue(config.production)
        route = config.route("model.chat")
        self.assertEqual((route["resource"], route["destination"]), ("m", "ai.example.test"))
        self.assertEqual(route["controls"], ["local_prompt", "sensitivity"])
        self.assertTrue(config.connector("tickets")["synthetic"])
        self.assertEqual(config["backend_inventory"]["backends"][0]["hosts"], ["https://ai.example.test"])
        changed = production()
        changed["backend_inventory"]["backends"][0]["account_id"] = "replacement-prod"
        self.assertNotEqual(config.reload_key(), validate(changed).reload_key())

    def test_peer_binding_rules(self):
        data = production()
        del data["agents"][0]["uid"]
        self.assertIn(("$.agents[0].uid", "peer_binding_required_in_production"), self.codes(data))
        data = production()
        data["agents"][1]["uid"] = 11001
        self.assertIn(("$.agents[1]", "shared_agent_uid_forbidden"), self.codes(data))
        data = production()
        data["agents"][1]["uid"] = 10001
        self.assertIn(("$.agents[1].uid", "agent_uid_must_differ_from_guard_uid"), self.codes(data))
        data = production()
        data["agents"].append(dict(data["agents"][0], uid=11003))
        codes = self.codes(data)
        self.assertIn(("$.agents[2]", "duplicate_agent"), codes)
        self.assertIn(("$.agents[2]", "duplicate_identity"), codes)
        data = production()
        del data["deployment"]
        self.assertIn(("$.deployment.guard_uid", "required_in_production"), self.codes(data))
        data = production()
        data["service"]["max_connections"] = 4
        self.assertIn(("$.service.max_connections", "peer_reservations_exceed_capacity"), self.codes(data))
        data = production()
        del data["service"]["socket_group"]
        self.assertIn(("$.service.socket_group", "required_in_production"), self.codes(data))

    def test_development_profile_allows_unbound_agents(self):
        data = production()
        data["profile"] = "development"
        del data["agents"][0]["uid"]
        validate(data)

    def test_egress_rules(self):
        data = production()
        data["egress"]["mode"] = "direct_development_only"
        self.assertIn(("$.egress.mode", "direct_egress_forbidden_in_production"), self.codes(data))
        data = production()
        data["egress"] = {"mode": "none"}
        self.assertIn(("$.egress.mode", "network_connectors_require_egress"), self.codes(data))
        data = production()
        data["egress"]["allow"] = []
        self.assertIn(("$.connectors[0]", "destination_not_on_egress_allowlist"), self.codes(data))
        data = production()
        data["egress"]["client_uids"] = [11001]
        codes = self.codes(data)
        self.assertIn(("$.egress.client_uids[0]", "agent_uid_cannot_use_egress"), codes)
        data = production()
        data["egress"]["socket"] = "/run/guard/egress.sock"
        self.assertIn(("$.egress.socket", "egress_socket_directory_must_be_separate"), self.codes(data))

    def test_policy_rules(self):
        data = production()
        data["routes"][0]["controls"] = ["local_prompt"]
        self.assertIn(("$.routes[0].controls", "sensitivity_control_required_in_production"), self.codes(data))
        data = production()
        data["approvers"] = []
        self.assertIn(("$.routes[1].approval", "no_approver_for_tenant"), self.codes(data))
        data = production()
        data["agents"][1]["routes"] = ["model.chat"]
        self.assertIn(("$.agents[1].routes[0]", "cross_tenant_route_grant"), self.codes(data))
        data = production()
        data["routes"][0]["resource"] = "other-model"
        self.assertIn(("$.routes[0].resource", "must_match_connector_binding"), self.codes(data))
        data = production()
        data["routes"][0]["clearance"] = "secret"
        self.assertIn(("$.routes[0].clearance", "unsupported_value"), self.codes(data))
        data = production()
        data["approvers"][0]["id"] = "agent-a"
        self.assertIn(("$.approvers", "approver_and_agent_ids_must_differ"), self.codes(data))

    def test_paths_and_unknown_fields(self):
        data = production()
        data["paths"]["key_directory"] = "/state/keys"
        self.assertIn(("$.paths.key_directory", "keys_must_be_separate_from_state"), self.codes(data))
        data = production()
        data["paths"]["admin_socket"] = "/run/guard/admin.sock"
        self.assertIn(("$.paths.admin_socket", "admin_socket_directory_must_be_separate"), self.codes(data))
        data = production()
        data["paths"]["state_directory"] = "relative/state"
        self.assertIn(("$.paths.state_directory", "absolute_path_required"), self.codes(data))
        data = production()
        data["api_key"] = "must-not-be-accepted"
        self.assertIn(("$.api_key", "unknown_field"), self.codes(data))
        data = production()
        data["connectors"][0]["api_key"] = "must-not-be-accepted"
        self.assertIn(("$.connectors[0].api_key", "unknown_field"), self.codes(data))
        data = production()
        data["schema_version"] = 1
        self.assertIn(("$.schema_version", "unsupported_schema_version"), self.codes(data))

    def test_duplicate_json_keys_and_size(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            path.write_text('{"schema_version": 2, "schema_version": 2}')
            with self.assertRaises(ConfigError) as caught:
                load(path)
            self.assertEqual(caught.exception.errors[0]["code"], "invalid_or_duplicate_json")
            path.write_text(" " * 1_048_577)
            with self.assertRaises(ConfigError):
                load(path)

    def test_round_trip_label_floor_in_production(self):
        data = production()
        data["routes"][0]["produces"] = "public"
        self.assertIn(("$.routes[0].produces", "produces_below_destination_clearance"), self.codes(data))
        data = production()
        data["routes"].append({"name": "ticket.read", "tenant": "tenant-a", "operation": "ticket.read",
                               "connector": "tickets", "resource": "ticket", "destination": "ticket-service",
                               "clearance": "public", "produces": "internal"})
        # The read route shares a destination that receives confidential writes.
        self.assertIn(("$.routes[2].produces", "produces_below_destination_clearance"), self.codes(data))
        data["routes"][2]["produces"] = "confidential"
        validate(data)
        data["connectors"].append({"name": "kb", "type": "retrieval_local", "collection": "kb"})
        data["routes"].append({"name": "kb.search", "tenant": "tenant-a", "operation": "retrieve", "connector": "kb",
                               "clearance": "confidential"})
        validate(data)  # read-only retrieval labels per document
        development = production()
        development["profile"] = "development"
        development["routes"][0]["produces"] = "public"
        validate(development)

    def test_endpoint_and_allowlist_hosts_must_be_canonical(self):
        for endpoint in ("https://ai.example.test./v1/chat/completions",
                         "https://[2001:0db8:0:0::1]/v1/chat/completions",
                         "https://bücher.example/v1/chat/completions"):
            with self.subTest(endpoint=endpoint):
                data = production()
                data["connectors"][0]["endpoint"] = endpoint
                self.assertIn(("$.connectors[0].endpoint", "endpoint_host_not_canonical"), self.codes(data))
        data = production()
        data["egress"]["allow"].append({"host": "AI.Example.Test.", "port": 443})
        self.assertIn(("$.egress.allow[1]", "duplicate_egress_rule"), self.codes(data))
        data = production()
        data["egress"]["allow"].append({"host": "not a host", "port": 443})
        self.assertIn(("$.egress.allow[1].host", "invalid_egress_host"), self.codes(data))

    def aliased(self):
        """Production config with two host names for one notes backend."""
        data = production()
        data["connectors"] += [
            {"name": "notes-a", "type": "chat_completions", "endpoint": "https://notes.example.test/v1/chat/completions",
             "model": "m", "credential": "notes-a-key", "data_domain": "notes-backend"},
            {"name": "notes-b", "type": "chat_completions", "endpoint": "https://notes-alias.example.test/v1/chat/completions",
             "model": "m", "credential": "notes-b-key", "data_domain": "notes-backend"}]
        data["backend_inventory"]["backends"].append({
            "backend_id": "notes-api", "account_id": "notes-prod", "data_domain": "notes-backend",
            "tenants": ["tenant-a", "tenant-b"],
            "hosts": ["https://notes.example.test", "https://notes-alias.example.test"]})
        data["egress"]["allow"] += [{"host": "notes.example.test", "port": 443},
                                    {"host": "notes-alias.example.test", "port": 443}]
        data["routes"] += [
            {"name": "notes.write", "tenant": "tenant-a", "operation": "notes.write", "connector": "notes-a",
             "clearance": "confidential", "produces": "confidential"},
            {"name": "notes.read", "tenant": "tenant-a", "operation": "notes.read", "connector": "notes-b",
             "clearance": "internal", "produces": "internal"}]
        return data

    def test_declared_data_domain_joins_aliases_for_the_round_trip_rule(self):
        data = self.aliased()
        self.assertIn(("$.routes[3].produces", "produces_below_destination_clearance"), self.codes(data))
        data["routes"][3]["produces"] = "confidential"
        validate(data)
        # A domain shared across tenants carries the highest clearance of all of them.
        data["connectors"].append({"name": "notes-tenant-b", "type": "chat_completions", "model": "m",
                                   "endpoint": "https://notes.example.test/v1/chat/completions",
                                   "credential": "notes-tb-key", "data_domain": "notes-backend"})
        data["routes"].append({"name": "b.notes", "tenant": "tenant-b", "operation": "notes.read",
                               "connector": "notes-tenant-b", "clearance": "internal", "produces": "internal"})
        self.assertIn(("$.routes[4].produces", "produces_below_destination_clearance"), self.codes(data))
        data["connectors"][2]["data_domain"] = "Not Valid"
        self.assertIn(("$.connectors[2].data_domain", "invalid_identifier"), self.codes(data))

    def test_production_network_connectors_require_trusted_inventory_admission(self):
        data = production()
        del data["backend_inventory"]
        self.assertIn(("$.backend_inventory", "required_for_production_network_connectors"), self.codes(data))
        data = self.aliased()
        data["backend_inventory"]["backends"][1]["hosts"].pop()
        self.assertIn(("$.connectors[3]", "connector_host_not_in_inventory"), self.codes(data))
        data = self.aliased()
        del data["connectors"][2]["data_domain"]
        self.assertIn(("$.connectors[2].data_domain", "connector_data_domain_required"), self.codes(data))
        data = self.aliased()
        data["connectors"][2]["data_domain"] = "other-backend"
        self.assertIn(("$.connectors[2].data_domain", "connector_data_domain_mismatch"), self.codes(data))
        data = production()
        data["backend_inventory"]["backends"][0]["tenants"] = ["tenant-b"]
        self.assertIn(("$.routes[0].tenant", "backend_tenant_not_permitted"), self.codes(data))

    def test_data_domain_spellings_differing_only_by_case_are_one_backend(self):
        data = self.aliased()
        data["connectors"][2]["data_domain"], data["connectors"][3]["data_domain"] = "Notes-Backend", "notes-backend"
        self.assertIn(("$.connectors[2].data_domain", "connector_data_domain_mismatch"), self.codes(data))

    def test_data_domain_only_joins_backends_never_splits_one(self):
        # Declaring a domain on one of two connectors to the same host must not
        # separate the other connector's routes from it.
        data = self.aliased()
        data["connectors"].append({"name": "notes-a2", "type": "chat_completions", "model": "m",
                                   "endpoint": "https://notes.example.test/v1/chat/completions",
                                   "credential": "notes-a2-key", "data_domain": "notes-backend"})
        data["routes"][2]["clearance"] = data["routes"][2]["produces"] = "restricted"
        data["routes"].append({"name": "notes.peek", "tenant": "tenant-a", "operation": "notes.read",
                               "connector": "notes-a2", "clearance": "public", "produces": "public"})
        self.assertIn(("$.routes[4].produces", "produces_below_destination_clearance"), self.codes(data))
        # Two different domain labels on one host are still one backend.
        data = self.aliased()
        data["connectors"][3]["endpoint"] = "https://notes.example.test/v1/chat/completions"
        data["connectors"][2]["data_domain"], data["connectors"][3]["data_domain"] = "one", "two"
        codes = self.codes(data)
        self.assertIn(("$.connectors[2].data_domain", "connector_data_domain_mismatch"), codes)
        self.assertIn(("$.connectors[3].data_domain", "connector_data_domain_mismatch"), codes)

    def test_fixture_destinations_differing_only_by_case_share_a_backend(self):
        data = production()
        data["routes"].append({"name": "ticket.peek", "tenant": "tenant-a", "operation": "ticket.read",
                               "connector": "tickets", "resource": "ticket", "destination": "Ticket-Service",
                               "clearance": "public", "produces": "internal"})
        self.assertIn(("$.routes[2].produces", "produces_below_destination_clearance"), self.codes(data))

    def test_outcome_capacity_validated_against_rate_retention_and_interval(self):
        data = production()
        del data["service"]["max_requests_per_second"]
        self.assertIn(("$.service.max_requests_per_second", "required_in_production"), self.codes(data))
        data = production()
        data["service"]["max_requests_per_second"] = 50  # 50 req/s for 8,400 s needs 462,000 records
        with self.assertRaises(ConfigError) as caught:
            validate(data)
        error = next(e for e in caught.exception.errors if e["code"] == "outcome_capacity_insufficient_for_request_rate")
        self.assertEqual(error["path"], "$.outcomes.capacity")
        self.assertEqual(error["detail"]["required_capacity"], math.ceil(50 * (7200 + 600 + 300) * 1.1))
        self.assertLess(error["detail"]["sustainable_requests_per_second"], 50)
        data["outcomes"]["capacity"] = 1_000_000
        validate(data)
        # One tenant's agents may not need more than its reserved share.
        data = production()
        data["agents"] += [{"id": "agent-a%d" % n, "tenant": "tenant-a", "principal": "bot%d" % n, "uid": 11010 + n,
                            "routes": []} for n in range(6)]
        data["service"]["max_connections"] = 64
        data["service"]["max_requests_per_second"] = 20
        self.assertIn(("$.outcomes.capacity", "outcome_capacity_insufficient_for_request_rate"), self.codes(data))
        data = production()
        data["retention"]["scheduled"] = False
        self.assertIn(("$.retention.scheduled", "scheduled_retention_required_in_production"), self.codes(data))
        data = production()
        data["profile"] = "development"
        data["service"]["max_requests_per_second"] = 50
        config = validate(data)  # development reports instead of refusing
        self.assertEqual([w["code"] for w in config.warnings], ["outcome_capacity_insufficient_for_request_rate"])
        del data["service"]["max_requests_per_second"]
        self.assertEqual([w["code"] for w in validate(data).warnings], ["request_rate_not_configured"])

    def test_time_bound_ids_required_in_production(self):
        data = production()
        data["outcomes"] = {"time_bound_request_ids": False}
        self.assertIn(("$.outcomes.time_bound_request_ids", "required_in_production"), self.codes(data))

    def test_shipped_examples_validate(self):
        root = Path(__file__).resolve().parent.parent / "examples"
        if not (root / "guard.production.json").exists():
            self.skipTest("examples not present beside the tests")
        self.assertTrue(load(root / "guard.production.json").production)
        self.assertFalse(load(root / "guard.development.json").production)

    def test_errors_do_not_echo_values(self):
        data = production()
        data["connectors"][0]["endpoint"] = "https://user:synthetic-password@ai.example.test/v1/chat/completions"
        with self.assertRaises(ConfigError) as caught:
            validate(data)
        self.assertNotIn("synthetic-password", json.dumps(caught.exception.errors))
