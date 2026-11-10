"""Trusted production inventory for canonical network backend identity.

The inventory is operator configuration, deliberately separate from request or
agent payloads.  It closes the DNS-alias classification gap without attempting
DNS discovery: every admitted network connector must name a host explicitly
listed by exactly one inventory entry and must declare that entry's data domain.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import urlsplit

from .egress import normalize_host


SCHEMA_VERSION = 1
NETWORK_CONNECTORS = ("chat_completions", "virustotal_ip")
_CANONICAL_ID = re.compile(r"[a-z0-9][a-z0-9._:-]{0,63}")
_VIRUSTOTAL_ORIGIN = "https://www.virustotal.com"


class InventoryError(Exception):
    """One or more fixed-code inventory admission errors.

    Error records contain only a JSON path and a stable code.  Invalid values
    are intentionally not copied into errors because connector endpoints may
    contain sensitive user-info when malformed.
    """

    def __init__(self, errors):
        super().__init__("backend_inventory_invalid")
        self.errors = tuple(errors)


@dataclass(frozen=True)
class BackendIdentity:
    """Canonical classification returned for an admitted connector."""

    backend_id: str
    account_id: str
    data_domain: str
    hosts: tuple[str, ...]
    tenants: frozenset[str]

    @property
    def group_key(self):
        """Stable clearance-group identity; aliases and tenants intentionally agree."""
        return ("trusted-backend", self.backend_id, self.account_id, self.data_domain)


@dataclass(frozen=True)
class BackendBinding:
    """Inventory identity plus the connector's preserved destination identity."""

    identity: BackendIdentity
    destination_host: str

    @property
    def group_key(self):
        return self.identity.group_key

    @property
    def data_domain(self):
        return self.identity.data_domain


class BackendInventory:
    """Validated, immutable lookup of operator-declared backend hosts."""

    def __init__(self, entries):
        self.entries = tuple(entries)
        by_host = {}
        for entry in self.entries:
            for origin in entry.hosts:
                by_host.setdefault(_origin_host(origin), []).append(entry)
        self._by_host = {host: tuple(matches) for host, matches in by_host.items()}

    def resolve_host(self, host, *, path="$"):
        """Resolve one already-canonical destination host, failing closed."""
        canonical = _canonical_host(host)
        if canonical is None:
            raise InventoryError([{"path": path, "code": "connector_host_not_canonical"}])
        matches = self._by_host.get(canonical, ())
        if not matches:
            raise InventoryError([{"path": path, "code": "connector_host_not_in_inventory"}])
        if len(matches) != 1:
            # Validated inventories cannot reach this branch; retaining the
            # check keeps admission fail-closed if an object is constructed by
            # future internal code incorrectly.
            raise InventoryError([{"path": path, "code": "connector_host_ambiguous"}])
        return BackendBinding(matches[0], canonical)


def _canonical_identifier(value):
    return value if isinstance(value, str) and _CANONICAL_ID.fullmatch(value) else None


def _canonical_host(value):
    if not isinstance(value, str):
        return None
    try:
        normalized, _ = normalize_host(value)
    except (TypeError, ValueError):
        return None
    # normalize_host accepts safe alternate spellings for egress matching.  An
    # inventory is an identity boundary, so it accepts only the one canonical
    # spelling rather than silently folding case or a trailing dot.
    return normalized if normalized == value else None


def _canonical_origin(value):
    """Return (origin, host) only for an exact canonical HTTPS origin."""
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        return None
    host = _canonical_host(parsed.hostname)
    if (parsed.scheme != "https" or host is None or parsed.username or parsed.password
            or port is not None or parsed.path or parsed.query or parsed.fragment):
        return None
    rendered_host = "[" + host + "]" if ":" in host else host
    origin = "https://" + rendered_host
    return (origin, host) if value == origin else None


def _origin_host(origin):
    return urlsplit(origin).hostname


def validate_inventory(data, *, path="$.backend_inventory"):
    """Validate the small JSON-compatible operator inventory schema.

    Schema::

        {"schema_version": 1, "backends": [{
          "backend_id": "vendor-service", "account_id": "corp-prod",
          "data_domain": "vendor-corp-prod", "tenants": ["tenant-a"],
          "hosts": ["https://api.vendor.example"]
        }]}
    """
    errors = []

    def error(at, code):
        errors.append({"path": at, "code": code})

    if type(data) is not dict:
        raise InventoryError([{"path": path, "code": "object_required"}])
    allowed_top = {"schema_version", "backends"}
    for key in data:
        if key not in allowed_top:
            error(f"{path}.{key}", "unknown_field")
    for key in allowed_top:
        if key not in data:
            error(f"{path}.{key}", "required_field_missing")
    if type(data.get("schema_version")) is not int or data.get("schema_version") != SCHEMA_VERSION:
        error(path + ".schema_version", "unsupported_schema_version")
    raw_entries = data.get("backends")
    if type(raw_entries) is not list:
        error(path + ".backends", "array_required")
        raw_entries = []
    elif not raw_entries:
        error(path + ".backends", "non_empty_array_required")
    elif len(raw_entries) > 256:
        error(path + ".backends", "array_too_long")
        raw_entries = raw_entries[:256]

    entries = []
    seen_identities = {}
    seen_domains = {}
    seen_hosts = {}
    required = {"backend_id", "account_id", "data_domain", "tenants", "hosts"}
    for index, raw in enumerate(raw_entries):
        entry_path = f"{path}.backends[{index}]"
        if type(raw) is not dict:
            error(entry_path, "object_required")
            continue
        for key in raw:
            if key not in required:
                error(f"{entry_path}.{key}", "unknown_field")
        for key in required:
            if key not in raw:
                error(f"{entry_path}.{key}", "required_field_missing")

        identifiers = {}
        for key in ("backend_id", "account_id", "data_domain"):
            value = _canonical_identifier(raw.get(key))
            if value is None:
                error(f"{entry_path}.{key}", "canonical_identifier_required")
            identifiers[key] = value

        raw_tenants = raw.get("tenants")
        tenants = []
        if type(raw_tenants) is not list:
            error(entry_path + ".tenants", "array_required")
        elif not raw_tenants:
            error(entry_path + ".tenants", "non_empty_array_required")
        elif len(raw_tenants) > 64:
            error(entry_path + ".tenants", "array_too_long")
        else:
            seen_tenants = set()
            for tenant_index, tenant in enumerate(raw_tenants):
                tenant_path = f"{entry_path}.tenants[{tenant_index}]"
                canonical = _canonical_identifier(tenant)
                if canonical is None:
                    error(tenant_path, "canonical_identifier_required")
                elif canonical in seen_tenants:
                    error(tenant_path, "duplicate_tenant")
                else:
                    seen_tenants.add(canonical)
                    tenants.append(canonical)

        raw_hosts = raw.get("hosts")
        hosts = []
        if type(raw_hosts) is not list:
            error(entry_path + ".hosts", "array_required")
        elif not raw_hosts:
            error(entry_path + ".hosts", "non_empty_array_required")
        elif len(raw_hosts) > 64:
            error(entry_path + ".hosts", "array_too_long")
        else:
            local_hosts = set()
            for host_index, value in enumerate(raw_hosts):
                host_path = f"{entry_path}.hosts[{host_index}]"
                parsed = _canonical_origin(value)
                if parsed is None:
                    error(host_path, "canonical_https_origin_required")
                    continue
                origin, host = parsed
                if host in local_hosts:
                    error(host_path, "duplicate_inventory_host")
                    continue
                local_hosts.add(host)
                hosts.append(origin)
                if host in seen_hosts:
                    error(host_path, "ambiguous_inventory_host")
                    previous_domain = seen_hosts[host][1]
                    if identifiers["data_domain"] is not None and previous_domain != identifiers["data_domain"]:
                        error(host_path, "conflicting_host_data_domain")
                else:
                    seen_hosts[host] = (entry_path, identifiers["data_domain"])

        identity = (identifiers["backend_id"], identifiers["account_id"])
        if None not in identity:
            if identity in seen_identities:
                error(entry_path, "duplicate_backend_account")
            else:
                seen_identities[identity] = entry_path
        domain = identifiers["data_domain"]
        if domain is not None:
            previous_identity = seen_domains.get(domain)
            if previous_identity is not None and previous_identity != identity:
                error(entry_path + ".data_domain", "data_domain_identity_conflict")
            else:
                seen_domains[domain] = identity

        if all(identifiers.values()) and tenants and hosts:
            entries.append(BackendIdentity(
                identifiers["backend_id"], identifiers["account_id"], identifiers["data_domain"],
                tuple(hosts), frozenset(tenants)))

    if errors:
        raise InventoryError(errors)
    return BackendInventory(entries)


def _connector_origin(connector):
    kind = connector.get("type")
    if kind == "virustotal_ip":
        return _VIRUSTOTAL_ORIGIN
    if kind != "chat_completions":
        return None
    endpoint = connector.get("endpoint")
    if not isinstance(endpoint, str):
        return None
    parsed = urlsplit(endpoint)
    try:
        port = parsed.port
    except ValueError:
        return None
    host = _canonical_host(parsed.hostname)
    if (parsed.scheme != "https" or host is None or parsed.username or parsed.password
            or port not in (None, 443) or parsed.query or parsed.fragment
            or not parsed.path.endswith("/chat/completions")):
        return None
    rendered_host = "[" + host + "]" if ":" in host else host
    if parsed.netloc not in (rendered_host, rendered_host + ":443"):
        return None
    return "https://" + rendered_host


def resolve_production_connectors(trusted_inventory, connectors, *, routes=(), path="$.connectors",
                                  routes_path="$.routes"):
    """Admit all production network connectors against trusted operator data.

    ``trusted_inventory`` may be a validated :class:`BackendInventory` or its
    raw JSON-compatible object.  Agent/request payloads must never be passed as
    this argument.  The returned mapping is keyed by connector name.

    Route tenant checks are an additional inventory scope check only; callers
    must retain the product configuration's normal route and principal tenant
    authorization.
    """
    inventory = (trusted_inventory if isinstance(trusted_inventory, BackendInventory)
                 else validate_inventory(trusted_inventory))
    errors = []
    bindings = {}
    if type(connectors) is not list:
        raise InventoryError([{"path": path, "code": "array_required"}])
    for index, connector in enumerate(connectors):
        connector_path = f"{path}[{index}]"
        if type(connector) is not dict or connector.get("type") not in NETWORK_CONNECTORS:
            continue
        name = connector.get("name")
        origin = _connector_origin(connector)
        if origin is None:
            errors.append({"path": connector_path, "code": "connector_destination_invalid"})
            continue
        try:
            binding = inventory.resolve_host(_origin_host(origin), path=connector_path)
        except InventoryError as exc:
            errors.extend(exc.errors)
            continue
        declared_domain = connector.get("data_domain")
        if declared_domain is None:
            errors.append({"path": connector_path + ".data_domain", "code": "connector_data_domain_required"})
            continue
        if declared_domain != binding.data_domain:
            errors.append({"path": connector_path + ".data_domain", "code": "connector_data_domain_mismatch"})
            continue
        bindings[name] = binding

    if type(routes) is not list and type(routes) is not tuple:
        errors.append({"path": routes_path, "code": "array_required"})
        routes = ()
    for index, route in enumerate(routes):
        if type(route) is not dict:
            continue
        binding = bindings.get(route.get("connector"))
        if binding is not None and route.get("tenant") not in binding.identity.tenants:
            errors.append({"path": f"{routes_path}[{index}].tenant", "code": "backend_tenant_not_permitted"})

    if errors:
        raise InventoryError(errors)
    return bindings
