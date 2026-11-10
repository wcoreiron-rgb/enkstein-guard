# Trusted backend inventory

Production network connectors need an operator-supplied backend inventory. The
inventory closes a classification gap that configuration warnings cannot: two
DNS names may reach the same backend even though Guard cannot safely discover
that relationship. Guard does not query DNS to infer aliases. Operators list
every accepted canonical HTTPS origin and deliberately place aliases in one
entry.

The schema is intentionally small and JSON-compatible:

```json
{
  "schema_version": 1,
  "backends": [
    {
      "backend_id": "notes-api",
      "account_id": "corp-prod",
      "data_domain": "notes-corp-prod",
      "tenants": ["tenant-a", "tenant-b"],
      "hosts": [
        "https://notes.example.test",
        "https://notes-alias.example.test"
      ]
    }
  ]
}
```

`backend_id` identifies the external service and `account_id` identifies the
external account, project, or deployment reached with the connector
credential. `data_domain` is the exact value each matching connector must
declare. The three values are lowercase canonical identifiers; they contain no
credential material. `tenants` explicitly lists the local tenants allowed to
route to that external account. `hosts` contains origins, not endpoint URLs:
each value is exactly `https://` plus one lowercase canonical host, with no
path, trailing slash, explicit port, query, fragment, user-info, or trailing
DNS dot.

At production configuration admission:

1. Validate the inventory with `validate_inventory(operator_data)`.
2. Pass the validated object, product connectors, and routes to
   `resolve_production_connectors(...)`.
3. Use each returned `BackendBinding.group_key` for clearance grouping and
   retain `destination_host` for the actual destination identity.

Every `chat_completions` and `virustotal_ip` connector must resolve to exactly
one inventory entry. Its `data_domain` must exactly match that entry. Missing
hosts and domains, case variants, duplicate hosts, ambiguous host mappings,
and conflicting backend/domain identities fail with fixed-code, JSON-path
errors. Alias hosts in one entry return the same group key. Separate account
identities return different group keys.

The inventory is trusted deployment configuration. It must come from an
operator-controlled file or equivalent protected deployment source, never from
an agent, request body, model output, tool result, or connector response. The
tenant list is an additional admission constraint; it does not replace or
weaken normal route ownership, principal authorization, credential scoping,
egress allowlisting, TLS verification, or Trust Fabric checks.

## Operational limits

One origin can belong to only one inventory entry. Multiple provider accounts
on the same SaaS hostname cannot be represented as separate backend identities
in this version; use the conservative shared classification domain, or separate
provider origins. This may restrict otherwise legitimate deployments. It does
not verify that an external credential belongs to the declared account.

This mechanism cannot prove that the inventory is correct or complete. An
operator can still misclassify two aliases as separate backends, assign the
wrong external account label to a connector credential, or omit a host needed
after a provider change. Omitted hosts fail closed, but incorrect declared
separations remain a trusted-configuration risk. Review inventory changes
alongside DNS/provider account changes and keep external account and local
tenant boundaries explicit.
