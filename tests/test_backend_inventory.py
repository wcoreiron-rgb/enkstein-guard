import unittest

from enkstein_guard.backend_inventory import (
    InventoryError,
    resolve_production_connectors,
    validate_inventory,
)


def inventory():
    return {
        "schema_version": 1,
        "backends": [{
            "backend_id": "notes-api",
            "account_id": "corp-prod",
            "data_domain": "notes-corp-prod",
            "tenants": ["tenant-a", "tenant-b"],
            "hosts": ["https://notes.example.test", "https://notes-alias.example.test"],
        }, {
            "backend_id": "virustotal",
            "account_id": "security-prod",
            "data_domain": "virustotal-security-prod",
            "tenants": ["tenant-a"],
            "hosts": ["https://www.virustotal.com"],
        }],
    }


def chat(name, host, domain="notes-corp-prod"):
    return {"name": name, "type": "chat_completions",
            "endpoint": f"https://{host}/v1/chat/completions", "model": "m",
            "credential": name + "-key", "data_domain": domain}


class BackendInventoryTests(unittest.TestCase):
    def codes(self, data):
        with self.assertRaises(InventoryError) as caught:
            validate_inventory(data)
        return {(error["path"], error["code"]) for error in caught.exception.errors}

    def test_declared_aliases_have_one_clearance_group_and_preserve_destination(self):
        connectors = [chat("notes-primary", "notes.example.test"),
                      chat("notes-secondary", "notes-alias.example.test")]
        bindings = resolve_production_connectors(inventory(), connectors)
        self.assertEqual(bindings["notes-primary"].group_key, bindings["notes-secondary"].group_key)
        self.assertEqual(bindings["notes-primary"].destination_host, "notes.example.test")
        self.assertEqual(bindings["notes-secondary"].destination_host, "notes-alias.example.test")

    def test_undeclared_connector_host_is_rejected(self):
        with self.assertRaises(InventoryError) as caught:
            resolve_production_connectors(inventory(), [chat("omitted", "omitted.example.test")])
        self.assertEqual(caught.exception.errors, (
            {"path": "$.connectors[0]", "code": "connector_host_not_in_inventory"},))

    def test_missing_and_case_variant_data_domains_are_rejected(self):
        connector = chat("notes", "notes.example.test")
        del connector["data_domain"]
        with self.assertRaises(InventoryError) as caught:
            resolve_production_connectors(inventory(), [connector])
        self.assertEqual(caught.exception.errors[0]["code"], "connector_data_domain_required")
        connector["data_domain"] = "Notes-Corp-Prod"
        with self.assertRaises(InventoryError) as caught:
            resolve_production_connectors(inventory(), [connector])
        self.assertEqual(caught.exception.errors[0]["code"], "connector_data_domain_mismatch")

    def test_duplicate_host_and_conflicting_domain_are_rejected(self):
        data = inventory()
        data["backends"].append({
            "backend_id": "notes-other",
            "account_id": "other-prod",
            "data_domain": "notes-other-prod",
            "tenants": ["tenant-a"],
            "hosts": ["https://notes.example.test"],
        })
        codes = self.codes(data)
        self.assertIn(("$.backend_inventory.backends[2].hosts[0]", "ambiguous_inventory_host"), codes)
        self.assertIn(("$.backend_inventory.backends[2].hosts[0]", "conflicting_host_data_domain"), codes)
        data = inventory()
        data["backends"][0]["hosts"].append("https://notes.example.test")
        self.assertIn(("$.backend_inventory.backends[0].hosts[2]", "duplicate_inventory_host"), self.codes(data))

    def test_conflicting_data_domain_identity_is_rejected(self):
        data = inventory()
        data["backends"].append({
            "backend_id": "other-api",
            "account_id": "other-prod",
            "data_domain": "notes-corp-prod",
            "tenants": ["tenant-a"],
            "hosts": ["https://other.example.test"],
        })
        self.assertIn(("$.backend_inventory.backends[2].data_domain", "data_domain_identity_conflict"),
                      self.codes(data))

    def test_hosts_are_exact_canonical_https_origins(self):
        variants = ("https://NOTES.example.test", "https://notes.example.test.",
                    "https://notes.example.test/", "https://notes.example.test:443",
                    "http://notes.example.test", "notes.example.test")
        for value in variants:
            with self.subTest(value=value):
                data = inventory()
                data["backends"][0]["hosts"] = [value]
                self.assertIn(("$.backend_inventory.backends[0].hosts[0]", "canonical_https_origin_required"),
                              self.codes(data))

    def test_schema_version_is_a_json_integer_not_boolean(self):
        data = inventory()
        data["schema_version"] = True
        self.assertIn(("$.backend_inventory.schema_version", "unsupported_schema_version"), self.codes(data))

    def test_cross_tenant_routes_share_classification_but_keep_tenant_scope(self):
        connectors = [chat("a-notes", "notes.example.test"),
                      chat("b-notes", "notes-alias.example.test")]
        routes = [{"name": "a", "connector": "a-notes", "tenant": "tenant-a"},
                  {"name": "b", "connector": "b-notes", "tenant": "tenant-b"}]
        bindings = resolve_production_connectors(inventory(), connectors, routes=routes)
        self.assertEqual(bindings["a-notes"].group_key, bindings["b-notes"].group_key)
        routes[1]["tenant"] = "tenant-c"
        with self.assertRaises(InventoryError) as caught:
            resolve_production_connectors(inventory(), connectors, routes=routes)
        self.assertIn({"path": "$.routes[1].tenant", "code": "backend_tenant_not_permitted"},
                      caught.exception.errors)

    def test_fixed_host_connector_uses_the_same_inventory_admission(self):
        connector = {"name": "vt", "type": "virustotal_ip", "credential": "vt-key",
                     "data_domain": "virustotal-security-prod"}
        binding = resolve_production_connectors(inventory(), [connector])["vt"]
        self.assertEqual(binding.destination_host, "www.virustotal.com")

    def test_errors_do_not_echo_invalid_values(self):
        connector = chat("bad", "notes.example.test")
        connector["endpoint"] = "https://user:synthetic-secret@notes.example.test/v1/chat/completions"
        with self.assertRaises(InventoryError) as caught:
            resolve_production_connectors(inventory(), [connector])
        self.assertNotIn("synthetic-secret", repr(caught.exception.errors))


if __name__ == "__main__":
    unittest.main()
