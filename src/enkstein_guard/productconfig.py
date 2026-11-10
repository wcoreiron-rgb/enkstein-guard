"""Strict schema-version-2 product configuration for the enkstein-guard CLI.

Configuration holds identity, permissions and policy. It never holds secrets:
credentials live in Guard state (digests) and connector secrets in the
encrypted secret store. Validation collects every error with a stable code
and JSON path; nothing is executed or fetched.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
from pathlib import Path, PurePosixPath
import re
from urllib.parse import urlsplit

from .backend_inventory import InventoryError, resolve_production_connectors, validate_inventory
from .sensitivity import LEVELS

PRODUCTION = "production-linux-peer-bound"
DEVELOPMENT = "development"
PROFILES = (PRODUCTION, DEVELOPMENT)
CONNECTOR_TYPES = ("fixture", "chat_completions", "virustotal_ip", "retrieval_local")
NETWORK_CONNECTORS = ("chat_completions", "virustotal_ip")
CONTROL_NAMES = ("local_prompt", "sensitivity")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
_ROUTE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_POLICY_FIELD_SEGMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")
MAX_CONFIG_BYTES = 1_048_576


class ConfigError(Exception):
    def __init__(self, errors):
        super().__init__("configuration_invalid")
        self.errors = errors


def _pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate_field")
        result[key] = value
    return result


class _Checker:
    def __init__(self):
        self.errors = []

    def error(self, path, code, detail=None):
        self.errors.append({"path": path, "code": code, **({"detail": detail} if detail else {})})
        return None

    def obj(self, value, path, *, required=(), optional=()):
        if type(value) is not dict:
            return self.error(path, "object_required") or {}
        for key in value:
            if key not in required and key not in optional:
                self.error(f"{path}.{key}", "unknown_field")
        for key in required:
            if key not in value:
                self.error(f"{path}.{key}", "required_field_missing")
        return value

    def string(self, value, path, *, pattern=None, maximum=256, choices=None):
        if not isinstance(value, str) or not value or len(value) > maximum or value != value.strip():
            return self.error(path, "string_required")
        if choices is not None and value not in choices:
            return self.error(path, "unsupported_value")
        if pattern is not None and not pattern.fullmatch(value):
            return self.error(path, "invalid_identifier")
        return value

    def integer(self, value, path, minimum, maximum):
        if type(value) is not int or not minimum <= value <= maximum:
            return self.error(path, "integer_out_of_range")
        return value

    def number(self, value, path, minimum, maximum):
        if type(value) not in (int, float) or not minimum <= value <= maximum:
            return self.error(path, "number_out_of_range")
        return value

    def boolean(self, value, path):
        if type(value) is not bool:
            return self.error(path, "boolean_required")
        return value

    def level(self, value, path):
        return self.string(value, path, choices=LEVELS)

    def absolute(self, value, path):
        if not isinstance(value, str) or not value.startswith("/") or "\x00" in value or len(value) > 1024:
            return self.error(path, "absolute_path_required")
        if any(part in ("..", ".") for part in PurePosixPath(value).parts):
            return self.error(path, "normalized_path_required")
        return value

    def items(self, value, path, *, maximum=1024, required=False):
        if type(value) is not list:
            self.error(path, "array_required")
            return []
        if required and not value:
            self.error(path, "non_empty_array_required")
        if len(value) > maximum:
            self.error(path, "array_too_long")
            return []
        return value

    def unique(self, values, path, code="duplicate_value"):
        seen = set()
        for index, value in enumerate(values):
            if value is None:
                continue
            if value in seen:
                self.error(f"{path}[{index}]", code)
            seen.add(value)


def _defaults(data, key, defaults):
    section = dict(defaults)
    section.update(data.get(key) or {})
    return section


SERVICE_DEFAULTS = {"max_connections": 32, "per_peer_connections": 4, "socket_group": None,
                    "request_timeout_seconds": 60, "read_timeout_seconds": 2, "max_frame_bytes": 1_048_576,
                    "control_timeout_seconds": 2, "transport_timeout_seconds": 30, "drain_timeout_seconds": 10,
                    "approval_ttl_seconds": 900, "max_requests_per_second": None}
VAULT_DEFAULTS = {"max_bytes": 67_108_864, "max_entries": 10000, "token_ttl_seconds": 300}
OUTCOME_DEFAULTS = {"capacity": 10000, "max_request_age_seconds": 86400, "clock_skew_seconds": 300,
                    "time_bound_request_ids": True}
AUDIT_DEFAULTS = {"full_verify_every": 10000}
SENSITIVITY_DEFAULTS = {"detected_level": "confidential", "secret_level": "restricted", "field_rules": [],
                        "declared_context": [], "unlabelled_heuristics": "monitor"}
EGRESS_DEFAULTS = {"mode": "none", "socket": None, "client_uids": [], "socket_group": None, "allow": [],
                   "connect_timeout_seconds": 10, "idle_timeout_seconds": 60, "max_connections": 64}
RETENTION_DEFAULTS = {"audit_archive_threshold_events": 100000, "audit_archive_keep_events": 10000,
                      "outcome_archive_age_seconds": 2_592_000, "scheduled": True,
                      "outcome_archive_interval_seconds": 3600, "audit_archive_interval_seconds": 3600,
                      "vault_purge_interval_seconds": 600}
SECURITY_HISTORY_DEFAULTS = {"capacity": 10_000, "ttl_seconds": 3600, "per_actor_capacity": 64}
# Outcome records live from issuance until the first scheduled archival after
# they are older than the archive age; this headroom covers uncertain and
# approval-pending records kept for reconciliation.
OUTCOME_HEADROOM = 1.1


def outcome_sizing(data):
    """Required outcome-ledger capacity for the configured rate and schedule.

    Each agent may admit ``max_requests_per_second / agents`` tracked requests per
    second; a record lives at most archive age + archive interval + clock skew.
    The ledger reserves an equal share of capacity per tenant with agents, so
    the busiest tenant's share is checked as well as the total.
    """
    service, outcomes, retention = data["service"], data["outcomes"], data["retention"]
    rate = service.get("max_requests_per_second")
    result = {"max_requests_per_second": rate, "capacity": outcomes["capacity"], "headroom": OUTCOME_HEADROOM,
              "scheduled_archival": retention["scheduled"]}
    if rate is None:
        return {**result, "sufficient": None,
                "note": "no request rate configured: ledger growth is not bounded by configuration"}
    agents = [a for a in data["agents"] if isinstance(a, dict)]
    per_agent = rate / max(1, len(agents))
    tenants = {}
    for agent in agents:
        tenants[agent.get("tenant")] = tenants.get(agent.get("tenant"), 0) + 1
    if not retention["scheduled"]:
        return {**result, "sufficient": False, "per_agent_requests_per_second": per_agent,
                "note": "scheduled archival disabled: records accumulate until archived by an operator"}
    horizon = (retention["outcome_archive_age_seconds"] + retention["outcome_archive_interval_seconds"]
               + outcomes["clock_skew_seconds"])
    share = outcomes["capacity"] // max(1, len(tenants))
    busiest = max(tenants.values(), default=0)
    required_total = math.ceil(rate * horizon * OUTCOME_HEADROOM)
    required_share = math.ceil(busiest * per_agent * horizon * OUTCOME_HEADROOM)
    sustainable = min(outcomes["capacity"] / (horizon * OUTCOME_HEADROOM),
                      share / (horizon * OUTCOME_HEADROOM) / (busiest * per_agent / rate) if busiest else float("inf"))
    return {**result, "per_agent_requests_per_second": round(per_agent, 6), "record_lifetime_seconds": horizon,
            "required_capacity": required_total, "tenant_shares": len(tenants), "tenant_share_capacity": share,
            "required_busiest_tenant_share": required_share,
            "sustainable_requests_per_second": round(sustainable, 3),
            "sufficient": outcomes["capacity"] >= required_total and share >= required_share}


@dataclass(frozen=True)
class ProductConfig:
    data: dict
    source: str | None = None
    warnings: tuple = ()

    def __getitem__(self, key):
        return self.data[key]

    @property
    def production(self):
        return self.data["profile"] == PRODUCTION

    def connector(self, name):
        return next((item for item in self.data["connectors"] if item["name"] == name), None)

    def route(self, name):
        return next((item for item in self.data["routes"] if item["name"] == name), None)

    def agent(self, name):
        return next((item for item in self.data["agents"] if item["id"] == name), None)

    def security_engine(self, name):
        return next((item for item in self.data["security_engines"] if item["name"] == name), None)

    def policy_engine(self, name):
        return next((item for item in self.data["policy_engines"] if item["name"] == name), None)

    def summary(self):
        """Secret-free counts for status and doctor output."""
        exceptions = [{"route": route["name"], "privacy": route["privacy"], "reason_present": True}
                      for route in self.data["routes"] if route["privacy_exception_reason"] is not None]
        engines = []
        for engine in self.data["security_engines"]:
            model_route = self.route(engine["model_route"])
            connector = self.connector(model_route["connector"])
            engines.append({"name": engine["name"], "tenant": engine["tenant"],
                            "model_route": engine["model_route"], "connector": connector["name"],
                            "model": connector["model"], "provider_destination": model_route["destination"],
                            "timeout_seconds": engine["timeout_seconds"],
                            "confidence_threshold": engine["confidence_threshold"],
                            "failure_action": engine["failure_action"], "stage": "configured",
                            "provider_live_validation": "unknown"})
        policy_engines = [{"name": engine["name"], "kind": engine["kind"],
                           "tenant": engine["tenant"], "bindings": len(engine["bindings"]),
                           "conditions": sum(len(binding["conditions"]) for binding in engine["bindings"]),
                           "stage": "configured", "vendor_runtime_validation": "unknown"}
                          for engine in self.data["policy_engines"]]
        return {"profile": self.data["profile"], "tenants": len(self.data["tenants"]),
                "agents": len(self.data["agents"]), "approvers": len(self.data["approvers"]),
                "routes": len(self.data["routes"]), "connectors": len(self.data["connectors"]),
                "egress_mode": self.data["egress"]["mode"],
                "security_engine_count": len(engines), "security_engines": engines,
                "security_engine_route_count": sum(route["security_engine"] is not None
                                                   for route in self.data["routes"]),
                "policy_engine_count": len(policy_engines), "policy_engines": policy_engines,
                "policy_engine_route_count": sum(route["policy_engine"] is not None
                                                  for route in self.data["routes"]),
                "model_privacy_exception_count": len(exceptions), "model_privacy_exceptions": exceptions}

    def reload_key(self):
        """Fields that a running service cannot change without restart."""
        inspectors = []
        for engine in self.data["security_engines"]:
            route = self.route(engine["model_route"])
            inspectors.append({"route": route, "connector": self.connector(route["connector"])})
        return json.dumps({"paths": self.data["paths"], "service": self.data["service"],
                           "profile": self.data["profile"], "deployment": self.data["deployment"],
                           "agents": [(a["id"], a.get("uid")) for a in self.data["agents"]],
                           "egress": self.data["egress"], "vault": self.data["vault"],
                           "security_history": self.data["security_history"],
                           "security_engines": self.data["security_engines"], "security_inspectors": inspectors,
                           "policy_engines": self.data["policy_engines"],
                           "policy_engine_routes": [(route["name"], route["tenant"], route["policy_engine"])
                                                    for route in self.data["routes"]
                                                    if route["policy_engine"] is not None],
                           "outcomes": self.data["outcomes"], "tenants": self.data["tenants"],
                           "backend_inventory": self.data.get("backend_inventory")}, sort_keys=True)


def _canonical_host(host):
    """Egress-proxy normalization of a host name, or None when invalid."""
    from .egress import normalize_host
    try:
        return normalize_host(host)[0]
    except (ValueError, TypeError):
        return None


def backend_keys(route, connector):
    """Identities under which a route reaches a backend: the tenant's canonical
    destination, plus the connector's declared data_domain (shared across
    tenants). Routes sharing any key share one backend."""
    destination = route.get("destination")
    if isinstance(destination, str):
        destination = _canonical_host(destination) or destination.casefold()
    keys = [("tenant", route.get("tenant"), destination)]
    if connector.get("data_domain"):
        # Case-insensitive, like host names: "Notes" and "notes" are one backend.
        keys.append(("domain", connector["data_domain"].casefold()))
    return keys


def backend_groups(routes, connectors):
    """Route index -> backend group: connected components over backend keys,
    so a data_domain can only join backends, never split one."""
    parent = {}

    def find(key):
        parent.setdefault(key, key)
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    route_keys = {}
    for index, route in enumerate(routes):
        connector = connectors.get(route.get("connector")) or {}
        if connector.get("type") == "retrieval_local":
            continue
        keys = backend_keys(route, connector)
        route_keys[index] = keys
        for key in keys[1:]:
            parent[find(key)] = find(keys[0])
    return {index: find(keys[0]) for index, keys in route_keys.items()}


def possible_aliases(connectors):
    """Warnings (never errors) for network connectors that may be one backend.

    Guard cannot discover DNS-level aliases. As a hint, connectors to different
    host names under the same parent domain (last two labels) are reported
    unless both declare a data_domain: the same one if they are one backend,
    different ones if they are not. Heuristic: without a public-suffix list,
    names under a shared suffix such as co.uk are also reported.
    """
    hosts = {}
    for connector in connectors:
        binding = connector_binding(connector) if connector.get("type") in ("chat_completions", "virustotal_ip") else None
        host = _canonical_host(binding[1]) if binding and binding[1] else None
        if host and "." in host and not host.replace(".", "").isdigit():
            hosts[connector["name"]] = (host, connector.get("data_domain"))
    by_parent = {}
    for name, (host, domain) in hosts.items():
        by_parent.setdefault(".".join(host.split(".")[-2:]), []).append((name, host, domain))
    warnings = []
    for parent, members in sorted(by_parent.items()):
        distinct = {host for _, host, _ in members}
        undeclared = [name for name, _, domain in members if not domain]
        if len(distinct) > 1 and undeclared:
            warnings.append({"path": "$.connectors", "code": "connectors_may_alias_one_backend",
                             "detail": {"parent_domain": parent, "connectors": sorted(name for name, _, _ in members),
                                        "without_data_domain": sorted(undeclared)}})
    return warnings


def connector_binding(connector):
    """Trusted (resource, destination) fixed by a network/retrieval connector."""
    kind = connector["type"]
    if kind == "chat_completions":
        return connector["model"], urlsplit(connector["endpoint"]).hostname
    if kind == "virustotal_ip":
        return "ip-reputation", "www.virustotal.com"
    if kind == "retrieval_local":
        return "collection:" + connector["collection"], "guard-retrieval"
    return None


def load(path):
    raw = Path(path).read_bytes()
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError([{"path": "$", "code": "configuration_too_large"}])
    try:
        data = json.loads(raw, object_pairs_hook=_pairs)
    except ValueError:
        raise ConfigError([{"path": "$", "code": "invalid_or_duplicate_json"}]) from None
    return validate(data, source=str(path))


def validate(data, *, source=None):
    c = _Checker()
    top = c.obj(data, "$", required=("schema_version", "profile", "paths", "tenants", "agents", "routes", "connectors"),
                optional=("deployment", "service", "vault", "outcomes", "audit", "inspection", "approvers",
                          "sensitivity", "egress", "retention", "backend_inventory", "security_engines",
                          "policy_engines", "security_history"))
    if not top:
        raise ConfigError(c.errors)
    if top.get("schema_version") != 2:
        c.error("$.schema_version", "unsupported_schema_version")
    profile = c.string(top.get("profile"), "$.profile", choices=PROFILES)
    production = profile == PRODUCTION

    deployment = c.obj(top.get("deployment", {}), "$.deployment", optional=("guard_uid",))
    guard_uid = deployment.get("guard_uid")
    if guard_uid is not None:
        c.integer(guard_uid, "$.deployment.guard_uid", 1, 2_147_483_647)
    elif production:
        c.error("$.deployment.guard_uid", "required_in_production")

    paths = c.obj(top.get("paths"), "$.paths",
                  required=("state_directory", "key_directory", "socket", "admin_socket", "archive_directory"))
    for key in ("state_directory", "key_directory", "socket", "admin_socket", "archive_directory"):
        if key in paths:
            c.absolute(paths[key], f"$.paths.{key}")
    if all(isinstance(paths.get(k), str) for k in ("state_directory", "key_directory", "archive_directory")):
        state, keys, archive = (PurePosixPath(paths[k]) for k in ("state_directory", "key_directory", "archive_directory"))
        if state == keys or keys in state.parents or state in keys.parents:
            c.error("$.paths.key_directory", "keys_must_be_separate_from_state")
        if archive in (state, keys) or keys in archive.parents:
            c.error("$.paths.archive_directory", "archive_must_be_separate")
    if isinstance(paths.get("socket"), str) and isinstance(paths.get("admin_socket"), str):
        if PurePosixPath(paths["socket"]).parent == PurePosixPath(paths["admin_socket"]).parent:
            c.error("$.paths.admin_socket", "admin_socket_directory_must_be_separate")

    service = _defaults(top, "service", SERVICE_DEFAULTS)
    c.obj(top.get("service", {}), "$.service", optional=tuple(SERVICE_DEFAULTS))
    c.integer(service["max_connections"], "$.service.max_connections", 1, 1024)
    c.integer(service["per_peer_connections"], "$.service.per_peer_connections", 1, 1024)
    if service["socket_group"] is not None:
        c.integer(service["socket_group"], "$.service.socket_group", 1, 2_147_483_647)
    elif production:
        c.error("$.service.socket_group", "required_in_production")
    c.number(service["request_timeout_seconds"], "$.service.request_timeout_seconds", 0.01, 300)
    c.number(service["read_timeout_seconds"], "$.service.read_timeout_seconds", 0.01, 10)
    c.integer(service["max_frame_bytes"], "$.service.max_frame_bytes", 1024, 16_777_216)
    c.number(service["control_timeout_seconds"], "$.service.control_timeout_seconds", 0.01, 300)
    c.number(service["transport_timeout_seconds"], "$.service.transport_timeout_seconds", 0.01, 300)
    c.number(service["drain_timeout_seconds"], "$.service.drain_timeout_seconds", 0, 300)
    c.integer(service["approval_ttl_seconds"], "$.service.approval_ttl_seconds", 30, 3600)
    if service["max_requests_per_second"] is not None:
        c.number(service["max_requests_per_second"], "$.service.max_requests_per_second", 0.01, 100_000)
    elif production:
        c.error("$.service.max_requests_per_second", "required_in_production")

    vault = _defaults(top, "vault", VAULT_DEFAULTS)
    c.obj(top.get("vault", {}), "$.vault", optional=tuple(VAULT_DEFAULTS))
    c.integer(vault["max_bytes"], "$.vault.max_bytes", 1_048_576, 1_073_741_824)
    c.integer(vault["max_entries"], "$.vault.max_entries", 1, 200_000)
    c.integer(vault["token_ttl_seconds"], "$.vault.token_ttl_seconds", 1, 86400)

    security_history = _defaults(top, "security_history", SECURITY_HISTORY_DEFAULTS)
    c.obj(top.get("security_history", {}), "$.security_history", optional=tuple(SECURITY_HISTORY_DEFAULTS))
    c.integer(security_history["capacity"], "$.security_history.capacity", 16, 100_000)
    c.integer(security_history["ttl_seconds"], "$.security_history.ttl_seconds", 60, 86_400)
    c.integer(security_history["per_actor_capacity"], "$.security_history.per_actor_capacity", 16, 256)

    outcomes = _defaults(top, "outcomes", OUTCOME_DEFAULTS)
    c.obj(top.get("outcomes", {}), "$.outcomes", optional=tuple(OUTCOME_DEFAULTS))
    c.integer(outcomes["capacity"], "$.outcomes.capacity", 1, 1_000_000)
    c.integer(outcomes["max_request_age_seconds"], "$.outcomes.max_request_age_seconds", 60, 31_536_000)
    c.integer(outcomes["clock_skew_seconds"], "$.outcomes.clock_skew_seconds", 1, 3600)
    c.boolean(outcomes["time_bound_request_ids"], "$.outcomes.time_bound_request_ids")
    if production and outcomes["time_bound_request_ids"] is not True:
        c.error("$.outcomes.time_bound_request_ids", "required_in_production")

    audit = _defaults(top, "audit", AUDIT_DEFAULTS)
    c.obj(top.get("audit", {}), "$.audit", optional=tuple(AUDIT_DEFAULTS))
    c.integer(audit["full_verify_every"], "$.audit.full_verify_every", 0, 10_000_000)

    inspection = _defaults(top, "inspection", {"private_pack": None})
    c.obj(top.get("inspection", {}), "$.inspection", optional=("private_pack",))
    if inspection["private_pack"] is not None:
        c.absolute(inspection["private_pack"], "$.inspection.private_pack")

    retention = _defaults(top, "retention", RETENTION_DEFAULTS)
    c.obj(top.get("retention", {}), "$.retention", optional=tuple(RETENTION_DEFAULTS))
    c.integer(retention["audit_archive_threshold_events"], "$.retention.audit_archive_threshold_events", 1000, 10_000_000)
    c.integer(retention["audit_archive_keep_events"], "$.retention.audit_archive_keep_events", 0, 10_000_000)
    c.integer(retention["outcome_archive_age_seconds"], "$.retention.outcome_archive_age_seconds", 3600, 315_360_000)
    if (isinstance(retention["outcome_archive_age_seconds"], int) and isinstance(outcomes["max_request_age_seconds"], int)
            and retention["outcome_archive_age_seconds"] <= outcomes["max_request_age_seconds"]):
        c.error("$.retention.outcome_archive_age_seconds", "must_exceed_request_window")
    c.boolean(retention["scheduled"], "$.retention.scheduled")
    c.integer(retention["outcome_archive_interval_seconds"], "$.retention.outcome_archive_interval_seconds", 60, 86400)
    c.integer(retention["audit_archive_interval_seconds"], "$.retention.audit_archive_interval_seconds", 60, 86400)
    c.integer(retention["vault_purge_interval_seconds"], "$.retention.vault_purge_interval_seconds", 10, 86400)

    # -- tenants ---------------------------------------------------------
    tenants = []
    for index, item in enumerate(c.items(top.get("tenants"), "$.tenants", maximum=64, required=True)):
        path = f"$.tenants[{index}]"
        item = c.obj(item, path, required=("id",), optional=("vault_bytes",))
        tenant = {"id": c.string(item.get("id"), path + ".id", pattern=_ID),
                  "vault_bytes": item.get("vault_bytes")}
        if tenant["vault_bytes"] is not None:
            c.integer(tenant["vault_bytes"], path + ".vault_bytes", 1, 1_073_741_824)
        tenants.append(tenant)
    c.unique([t["id"] for t in tenants], "$.tenants", "duplicate_tenant")
    tenant_ids = {t["id"] for t in tenants if t["id"]}
    explicit = [t["vault_bytes"] for t in tenants if isinstance(t["vault_bytes"], int)]
    if explicit and len(explicit) != len(tenants):
        c.error("$.tenants", "vault_bytes_required_for_all_tenants_or_none")
    if explicit and isinstance(vault["max_bytes"], int) and sum(explicit) > vault["max_bytes"] // 2:
        c.error("$.tenants", "vault_reservations_exceed_capacity")

    # -- connectors ------------------------------------------------------
    connectors = []
    for index, item in enumerate(c.items(top.get("connectors"), "$.connectors", maximum=128)):
        path = f"$.connectors[{index}]"
        kind = item.get("type") if type(item) is dict else None
        optional = {"fixture": ("behavior", "data_domain", "delay_seconds"),
                    "chat_completions": ("endpoint", "model", "authentication", "credential", "timeout_seconds",
                                         "max_response_bytes", "ca_file", "data_domain", "max_concurrent_calls"),
                    "virustotal_ip": ("credential", "timeout_seconds", "data_domain", "max_concurrent_calls"),
                    "retrieval_local": ("collection", "max_results", "max_chars")}.get(kind, ())
        item = c.obj(item, path, required=("name", "type"), optional=optional)
        connector = dict(item)
        c.string(item.get("name"), path + ".name", pattern=_ID)
        c.string(kind, path + ".type", choices=CONNECTOR_TYPES)
        if kind in NETWORK_CONNECTORS:
            # Concurrent provider calls; beyond this a request is refused before
            # dispatch as connector_busy (never an unknown outcome).
            connector.setdefault("max_concurrent_calls", 16)
            c.integer(connector["max_concurrent_calls"], path + ".max_concurrent_calls", 1, 64)
        if "data_domain" in item:
            # Operator declaration that connectors reach the same backend (for
            # example two host names for one service); see the round-trip rule.
            c.string(item["data_domain"], path + ".data_domain", pattern=_ID)
        if kind == "fixture":
            connector.setdefault("behavior", "echo")
            c.string(connector["behavior"], path + ".behavior", choices=("echo", "accept", "fail", "slow", "delay"))
            connector.setdefault("delay_seconds", 1)
            c.number(connector["delay_seconds"], path + ".delay_seconds", 0.01, 60)
            if production:
                connector["synthetic"] = True
        elif kind == "chat_completions":
            for key in ("endpoint", "model", "credential"):
                if key not in item:
                    c.error(f"{path}.{key}", "required_field_missing")
            parsed = urlsplit(item.get("endpoint", "")) if isinstance(item.get("endpoint"), str) else None
            try:
                invalid_port = parsed is not None and parsed.port not in (None, 443)
            except ValueError:
                invalid_port = True
            if (parsed is None or parsed.scheme != "https" or not parsed.hostname or parsed.username
                    or parsed.password or parsed.query or parsed.fragment or invalid_port
                    or not parsed.path.endswith("/chat/completions")):
                c.error(path + ".endpoint", "https_chat_completions_endpoint_required")
            elif _canonical_host(parsed.hostname) != parsed.hostname:
                # One spelling per host (lower-case ASCII, no trailing dot,
                # canonical IP literal) so a destination cannot be aliased by
                # spelling; the egress proxy uses the same normalization.
                c.error(path + ".endpoint", "endpoint_host_not_canonical")
            c.string(item.get("model"), path + ".model", maximum=128)
            c.string(item.get("credential"), path + ".credential", pattern=_ID)
            connector.setdefault("authentication", "bearer")
            c.string(connector["authentication"], path + ".authentication", choices=("bearer", "x-api-key"))
            connector.setdefault("timeout_seconds", 20)
            c.number(connector["timeout_seconds"], path + ".timeout_seconds", 0.01, 120)
            connector.setdefault("max_response_bytes", 1_048_576)
            c.integer(connector["max_response_bytes"], path + ".max_response_bytes", 1, 16_777_216)
            connector.setdefault("ca_file", None)
            if connector["ca_file"] is not None:
                c.absolute(connector["ca_file"], path + ".ca_file")
        elif kind == "virustotal_ip":
            if "credential" not in item:
                c.error(path + ".credential", "required_field_missing")
            c.string(item.get("credential"), path + ".credential", pattern=_ID)
            connector.setdefault("timeout_seconds", 15)
            c.number(connector["timeout_seconds"], path + ".timeout_seconds", 0.01, 120)
        elif kind == "retrieval_local":
            if "collection" not in item:
                c.error(path + ".collection", "required_field_missing")
            c.string(item.get("collection"), path + ".collection", pattern=_ID)
            connector.setdefault("max_results", 5)
            c.integer(connector["max_results"], path + ".max_results", 1, 20)
            connector.setdefault("max_chars", 4000)
            c.integer(connector["max_chars"], path + ".max_chars", 100, 200_000)
        connectors.append(connector)
    c.unique([item.get("name") for item in connectors], "$.connectors", "duplicate_connector")
    by_connector = {item.get("name"): item for item in connectors}

    # -- routes ------------------------------------------------------------
    routes = []
    for index, item in enumerate(c.items(top.get("routes"), "$.routes", maximum=512, required=True)):
        path = f"$.routes[{index}]"
        item = c.obj(item, path, required=("name", "tenant", "operation", "connector", "clearance"),
                     optional=("resource", "destination", "controls", "produces", "approval", "privacy",
                               "privacy_exception_reason", "task_boundaries", "grounding", "security_engine",
                               "policy_engine"))
        route = {"name": c.string(item.get("name"), path + ".name", pattern=_ROUTE),
                 "tenant": item.get("tenant"), "operation": c.string(item.get("operation"), path + ".operation"),
                 "connector": item.get("connector"), "clearance": c.level(item.get("clearance"), path + ".clearance"),
                 "produces": item.get("produces", "public"), "approval": item.get("approval", "none"),
                 "privacy": item.get("privacy"), "privacy_exception_reason": item.get("privacy_exception_reason"),
                 "controls": item.get("controls", ["local_prompt", "sensitivity"]),
                 "task_boundaries": [], "grounding": None, "security_engine": item.get("security_engine"),
                 "policy_engine": item.get("policy_engine")}
        if route["tenant"] not in tenant_ids:
            c.error(path + ".tenant", "unknown_tenant")
        c.level(route["produces"], path + ".produces")
        c.string(route["approval"], path + ".approval", choices=("none", "required", "on_demand"))
        controls = c.items(route["controls"], path + ".controls", maximum=8)
        # Normalized policy owns its mutable collections; caller mutation after
        # validation must not change required controls or grants.
        route["controls"] = list(controls)
        for position, name in enumerate(controls):
            c.string(name, f"{path}.controls[{position}]", choices=CONTROL_NAMES)
        c.unique(controls, path + ".controls", "duplicate_control")
        if production and "sensitivity" not in controls:
            c.error(path + ".controls", "sensitivity_control_required_in_production")
        if not controls and route["approval"] != "required":
            c.error(path + ".controls", "at_least_one_control_required")
        connector = by_connector.get(route["connector"])
        if connector is None:
            c.error(path + ".connector", "unknown_connector")
            # Keep the normalized shape stable while reporting the connector error.
            route["privacy"] = item.get("privacy", "none")
        else:
            model_route = connector.get("type") == "chat_completions"
            route["privacy"] = item.get("privacy", "tokenize" if model_route else "none")
            if model_route and route["privacy"] in ("none", "restore"):
                if "privacy_exception_reason" not in item:
                    c.error(path + ".privacy_exception_reason", "required_field_missing")
                else:
                    c.string(route["privacy_exception_reason"], path + ".privacy_exception_reason", maximum=256)
            elif "privacy_exception_reason" in item:
                c.error(path + ".privacy_exception_reason", "privacy_exception_reason_not_applicable")
            binding = connector_binding(connector) if connector.get("type") in CONNECTOR_TYPES else None
            if binding is None:
                for key in ("resource", "destination"):
                    if key not in item:
                        c.error(f"{path}.{key}", "required_for_fixture_connector")
                    route[key] = c.string(item.get(key), f"{path}.{key}")
            else:
                for key, value in zip(("resource", "destination"), binding):
                    if key in item and item[key] != value:
                        c.error(f"{path}.{key}", "must_match_connector_binding")
                    route[key] = value
            if connector.get("type") == "retrieval_local" and route["privacy"] != "none":
                c.error(path + ".privacy", "unsupported_for_retrieval")
        c.string(route["privacy"], path + ".privacy", choices=("none", "tokenize", "restore"))
        for position, boundary in enumerate(c.items(item.get("task_boundaries", []), path + ".task_boundaries", maximum=64)):
            bpath = f"{path}.task_boundaries[{position}]"
            boundary = c.obj(boundary, bpath, required=("principal", "workflow", "fields"))
            fields = []
            for fposition, rule in enumerate(c.items(boundary.get("fields", []), bpath + ".fields", maximum=128)):
                fpath = f"{bpath}.fields[{fposition}]"
                rule = c.obj(rule, fpath, required=("path", "kind"),
                             optional=("required", "choices", "minimum", "maximum", "max_length"))
                parts = c.items(rule.get("path"), fpath + ".path", maximum=16, required=True)
                for part_index, part in enumerate(parts):
                    c.string(part, f"{fpath}.path[{part_index}]", maximum=128)
                c.string(rule.get("kind"), fpath + ".kind", choices=("str", "int", "bool"))
                normalized_rule = dict(rule)
                normalized_rule["path"] = list(parts)
                if type(normalized_rule.get("choices")) is list:
                    normalized_rule["choices"] = list(normalized_rule["choices"])
                fields.append(normalized_rule)
            route["task_boundaries"].append({"principal": c.string(boundary.get("principal"), bpath + ".principal"),
                                             "workflow": c.string(boundary.get("workflow"), bpath + ".workflow"),
                                             "fields": fields})
        if "grounding" in item:
            grounding = c.obj(item["grounding"], path + ".grounding", required=("citations",), optional=("mode",))
            c.string(grounding.get("citations"), path + ".grounding.citations", choices=("required", "optional"))
            mode = grounding.get("mode", "citations")
            c.string(mode, path + ".grounding.mode", choices=("citations", "extractive"))
            if mode == "extractive" and grounding.get("citations") != "required":
                c.error(path + ".grounding.citations", "extractive_requires_citations")
            route["grounding"] = {"citations": grounding.get("citations"), "mode": mode}
        if route["security_engine"] is not None:
            route["security_engine"] = c.string(route["security_engine"], path + ".security_engine", pattern=_ID)
        if route["policy_engine"] is not None:
            route["policy_engine"] = c.string(route["policy_engine"], path + ".policy_engine", pattern=_ID)
        routes.append(route)
    c.unique([r["name"] for r in routes], "$.routes", "duplicate_route")
    by_route = {r["name"]: r for r in routes}

    # -- AI security engines ----------------------------------------------
    security_engines = []
    for index, item in enumerate(c.items(top.get("security_engines", []), "$.security_engines", maximum=64)):
        path = f"$.security_engines[{index}]"
        item = c.obj(item, path, required=("name", "tenant", "model_route"),
                     optional=("timeout_seconds", "confidence_threshold", "failure_action"))
        engine = {"name": c.string(item.get("name"), path + ".name", pattern=_ID),
                  "tenant": c.string(item.get("tenant"), path + ".tenant", pattern=_ID),
                  "model_route": c.string(item.get("model_route"), path + ".model_route", pattern=_ROUTE),
                  "timeout_seconds": item.get("timeout_seconds", 1.5),
                  "confidence_threshold": item.get("confidence_threshold", 0.7),
                  "failure_action": item.get("failure_action", "deny")}
        if engine["tenant"] not in tenant_ids:
            c.error(path + ".tenant", "unknown_tenant")
        c.number(engine["timeout_seconds"], path + ".timeout_seconds", 0.01, 30)
        if (type(engine["timeout_seconds"]) in (int, float)
                and type(service["control_timeout_seconds"]) in (int, float)
                and engine["timeout_seconds"] > service["control_timeout_seconds"]):
            c.error(path + ".timeout_seconds", "exceeds_control_timeout")
        c.number(engine["confidence_threshold"], path + ".confidence_threshold", 0, 1)
        c.string(engine["failure_action"], path + ".failure_action", choices=("deny", "require_approval"))
        security_engines.append(engine)
    c.unique([engine["name"] for engine in security_engines], "$.security_engines", "duplicate_security_engine")
    by_engine = {engine["name"]: engine for engine in security_engines if engine["name"] is not None}

    for index, engine in enumerate(security_engines):
        path = f"$.security_engines[{index}].model_route"
        model_route = by_route.get(engine["model_route"])
        if model_route is None:
            c.error(path, "unknown_model_route")
            continue
        connector = by_connector.get(model_route["connector"])
        if model_route["tenant"] != engine["tenant"]:
            c.error(path, "cross_tenant_model_route")
        if connector is None or connector.get("type") != "chat_completions":
            c.error(path, "chat_completions_model_route_required")
        if model_route["operation"] != "security.assess":
            c.error(path, "security_assess_operation_required")
        if model_route["privacy"] != "tokenize":
            c.error(path, "tokenized_model_route_required")
        if model_route["approval"] != "none":
            c.error(path, "internal_model_approval_forbidden")
        if model_route["security_engine"] is not None:
            c.error(path, "recursive_security_engine_forbidden")
        if model_route["grounding"] is not None:
            c.error(path, "internal_model_grounding_forbidden")
        if model_route["task_boundaries"]:
            c.error(path, "internal_model_task_boundaries_forbidden")

    for index, inspected in enumerate(routes):
        if inspected["security_engine"] is None:
            continue
        path = f"$.routes[{index}].security_engine"
        engine = by_engine.get(inspected["security_engine"])
        if engine is None:
            c.error(path, "unknown_security_engine")
            continue
        if inspected["tenant"] != engine["tenant"]:
            c.error(path, "cross_tenant_security_engine")
        if inspected["operation"] == "security.assess" or inspected["name"] in {
                item["model_route"] for item in security_engines}:
            c.error(path, "recursive_security_engine_forbidden")
        if engine["failure_action"] == "require_approval" and inspected["approval"] == "none":
            c.error(path, "approval_capability_required")

    # -- agents ------------------------------------------------------------
    agents = []
    for index, item in enumerate(c.items(top.get("agents"), "$.agents", maximum=1024)):
        path = f"$.agents[{index}]"
        item = c.obj(item, path, required=("id", "tenant", "principal", "routes"),
                     optional=("uid", "clearance", "groups", "task"))
        granted_routes = list(c.items(item.get("routes"), path + ".routes", maximum=256))
        groups = list(c.items(item.get("groups", []), path + ".groups", maximum=64))
        agent = {"id": c.string(item.get("id"), path + ".id", pattern=_ID), "tenant": item.get("tenant"),
                 "principal": c.string(item.get("principal"), path + ".principal", pattern=_ID),
                 "uid": item.get("uid"), "routes": granted_routes,
                 "clearance": item.get("clearance", "internal"), "groups": groups,
                 "task": item.get("task", "default")}
        if agent["tenant"] not in tenant_ids:
            c.error(path + ".tenant", "unknown_tenant")
        c.level(agent["clearance"], path + ".clearance")
        c.string(agent["task"], path + ".task", pattern=_ID)
        for position, group in enumerate(agent["groups"]):
            c.string(group, f"{path}.groups[{position}]", pattern=_ID)
        for position, name in enumerate(agent["routes"]):
            route = by_route.get(name)
            if route is None:
                c.error(f"{path}.routes[{position}]", "unknown_route")
            elif route["tenant"] != agent["tenant"]:
                c.error(f"{path}.routes[{position}]", "cross_tenant_route_grant")
        c.unique(agent["routes"], path + ".routes", "duplicate_route_grant")
        if agent["uid"] is not None:
            c.integer(agent["uid"], path + ".uid", 1, 2_147_483_647)
            if guard_uid is not None and agent["uid"] == guard_uid:
                c.error(path + ".uid", "agent_uid_must_differ_from_guard_uid")
        elif production:
            c.error(path + ".uid", "peer_binding_required_in_production")
        agents.append(agent)
    c.unique([a["id"] for a in agents], "$.agents", "duplicate_agent")
    c.unique([a["uid"] for a in agents], "$.agents", "shared_agent_uid_forbidden")
    c.unique([(a["tenant"], a["principal"], a["id"]) for a in agents], "$.agents", "duplicate_identity")
    if production and not agents:
        c.error("$.agents", "agents_required_in_production")
    if (production and isinstance(service["per_peer_connections"], int) and isinstance(service["max_connections"], int)
            and len(agents) * service["per_peer_connections"] > service["max_connections"]):
        c.error("$.service.max_connections", "peer_reservations_exceed_capacity")
    internal_routes = {engine["model_route"] for engine in security_engines}
    for agent_index, agent in enumerate(agents):
        for route_index, name in enumerate(agent["routes"]):
            if name in internal_routes:
                c.error(f"$.agents[{agent_index}].routes[{route_index}]", "internal_security_route_granted")

    # -- optional local AGT policy engines --------------------------------
    # This is syntax and configuration binding validation only. Optional SDK
    # imports happen when the service constructs a required control.
    policy_engines = []
    for engine_index, item in enumerate(c.items(
            top.get("policy_engines", []), "$.policy_engines", maximum=32)):
        path = f"$.policy_engines[{engine_index}]"
        item = c.obj(item, path, required=("name", "kind", "tenant", "bindings"))
        engine = {
            "name": c.string(item.get("name"), path + ".name", pattern=_ID),
            "kind": c.string(item.get("kind"), path + ".kind", choices=("agt",)),
            "tenant": c.string(item.get("tenant"), path + ".tenant", pattern=_ID),
            "bindings": [],
        }
        if engine["tenant"] not in tenant_ids:
            c.error(path + ".tenant", "unknown_tenant")
        pairs = []
        for binding_index, raw_binding in enumerate(c.items(
                item.get("bindings"), path + ".bindings", maximum=256, required=True)):
            bpath = f"{path}.bindings[{binding_index}]"
            raw_binding = c.obj(raw_binding, bpath, required=("agent", "route", "conditions"))
            binding = {
                "agent": c.string(raw_binding.get("agent"), bpath + ".agent", pattern=_ID),
                "route": c.string(raw_binding.get("route"), bpath + ".route", pattern=_ROUTE),
                "conditions": [],
            }
            pairs.append((binding["agent"], binding["route"]))
            for condition_index, raw_condition in enumerate(c.items(
                    raw_binding.get("conditions"), bpath + ".conditions", maximum=16, required=True)):
                cpath = f"{bpath}.conditions[{condition_index}]"
                raw_condition = c.obj(
                    raw_condition, cpath, required=("field", "operator", "value"))
                field = raw_condition.get("field")
                if (type(field) is not str or not field or len(field) > 519
                        or field != field.strip()):
                    c.error(cpath + ".field", "invalid_policy_field")
                else:
                    segments = field.split(".")
                    if (not 1 <= len(segments) <= 8
                            or any(_POLICY_FIELD_SEGMENT.fullmatch(segment) is None
                                   or segment.startswith("__") for segment in segments)):
                        c.error(cpath + ".field", "invalid_policy_field")
                operator = c.string(raw_condition.get("operator"), cpath + ".operator",
                                    choices=("eq", "lte", "gte"))
                value = raw_condition.get("value")
                scalar = type(value) in (bool, int, float, str)
                if (not scalar or (type(value) is float and not math.isfinite(value))
                        or (type(value) is str and len(value) > 256)):
                    c.error(cpath + ".value", "policy_scalar_required")
                elif operator in ("lte", "gte") and type(value) not in (int, float):
                    c.error(cpath + ".value", "numeric_policy_value_required")
                binding["conditions"].append({
                    "field": field, "operator": operator, "value": value,
                })
            engine["bindings"].append(binding)
        c.unique(pairs, path + ".bindings", "duplicate_policy_binding")
        policy_engines.append(engine)
    c.unique([engine["name"] for engine in policy_engines],
             "$.policy_engines", "duplicate_policy_engine")
    by_policy_engine = {engine["name"]: engine for engine in policy_engines
                        if engine["name"] is not None}
    by_agent = {agent["id"]: agent for agent in agents if agent["id"] is not None}

    for route_index, route in enumerate(routes):
        if route["policy_engine"] is None:
            continue
        path = f"$.routes[{route_index}].policy_engine"
        engine = by_policy_engine.get(route["policy_engine"])
        if engine is None:
            c.error(path, "unknown_policy_engine")
            continue
        if route["tenant"] != engine["tenant"]:
            c.error(path, "cross_tenant_policy_engine")
        if route["name"] in internal_routes or route["operation"] == "security.assess":
            c.error(path, "internal_security_route_policy_forbidden")

    for engine_index, engine in enumerate(policy_engines):
        path = f"$.policy_engines[{engine_index}]"
        selected = {route["name"] for route in routes
                    if route["policy_engine"] == engine["name"]}
        if not selected:
            c.error(path, "unused_policy_engine")
        for binding_index, binding in enumerate(engine["bindings"]):
            bpath = f"{path}.bindings[{binding_index}]"
            agent = by_agent.get(binding["agent"])
            route = by_route.get(binding["route"])
            if agent is None:
                c.error(bpath + ".agent", "unknown_agent")
            elif agent["tenant"] != engine["tenant"]:
                c.error(bpath + ".agent", "cross_tenant_policy_binding")
            if route is None:
                c.error(bpath + ".route", "unknown_route")
                continue
            if route["tenant"] != engine["tenant"]:
                c.error(bpath + ".route", "cross_tenant_policy_binding")
            if route["name"] in internal_routes or route["operation"] == "security.assess":
                c.error(bpath + ".route", "internal_security_route_policy_forbidden")
            if route["policy_engine"] != engine["name"]:
                c.error(bpath + ".route", "route_policy_engine_mismatch")
            if agent is not None and route["name"] not in agent["routes"]:
                c.error(bpath + ".route", "route_not_granted_to_agent")

    if policy_engines and not c.errors:
        from .agt_policy import AGTPolicyError, validate_policy_engine
        try:
            policy_engines = [validate_policy_engine(
                engine, agents=agents, routes=routes) for engine in policy_engines]
        except AGTPolicyError:
            c.error("$.policy_engines", "invalid_policy_engine")

    protected_routes = {route["name"] for route in routes if route["security_engine"] is not None}
    protected_agents = sum(bool(set(agent["routes"]) & protected_routes) for agent in agents)
    if (type(security_history["capacity"]) is int and type(security_history["per_actor_capacity"]) is int
            and security_history["capacity"] < max(1, protected_agents) * security_history["per_actor_capacity"]):
        c.error("$.security_history.capacity", "insufficient_for_protected_agents")

    # -- approvers ---------------------------------------------------------
    approvers = []
    for index, item in enumerate(c.items(top.get("approvers", []), "$.approvers", maximum=256)):
        path = f"$.approvers[{index}]"
        item = c.obj(item, path, required=("id", "tenants"))
        approver = {"id": c.string(item.get("id"), path + ".id", pattern=_ID),
                    "tenants": c.items(item.get("tenants"), path + ".tenants", maximum=64, required=True)}
        for position, tenant in enumerate(approver["tenants"]):
            if tenant not in tenant_ids:
                c.error(f"{path}.tenants[{position}]", "unknown_tenant")
        approvers.append(approver)
    c.unique([a["id"] for a in approvers], "$.approvers", "duplicate_approver")
    if {a["id"] for a in approvers} & {a["id"] for a in agents}:
        c.error("$.approvers", "approver_and_agent_ids_must_differ")
    for index, route in enumerate(routes):
        if route["approval"] in ("required", "on_demand") and not any(
                route["tenant"] in a["tenants"] for a in approvers):
            c.error(f"$.routes[{index}].approval", "no_approver_for_tenant")
        engine = by_engine.get(route["security_engine"])
        if (engine is not None and engine["failure_action"] == "require_approval"
                and not any(route["tenant"] in approver["tenants"] for approver in approvers)):
            c.error(f"$.routes[{index}].security_engine", "security_engine_approver_required")

    # -- sensitivity ---------------------------------------------------------
    sensitivity = _defaults(top, "sensitivity", SENSITIVITY_DEFAULTS)
    c.obj(top.get("sensitivity", {}), "$.sensitivity", optional=tuple(SENSITIVITY_DEFAULTS))
    c.level(sensitivity["detected_level"], "$.sensitivity.detected_level")
    c.level(sensitivity["secret_level"], "$.sensitivity.secret_level")
    c.string(sensitivity["unlabelled_heuristics"], "$.sensitivity.unlabelled_heuristics",
             choices=("off", "monitor", "enforce"))
    for index, rule in enumerate(c.items(sensitivity["field_rules"], "$.sensitivity.field_rules", maximum=256)):
        path = f"$.sensitivity.field_rules[{index}]"
        rule = c.obj(rule, path, required=("path", "level"))
        for position, part in enumerate(c.items(rule.get("path"), path + ".path", maximum=16, required=True)):
            c.string(part, f"{path}.path[{position}]", maximum=128)
        c.level(rule.get("level"), path + ".level")
    for index, entry in enumerate(c.items(sensitivity["declared_context"], "$.sensitivity.declared_context", maximum=256)):
        path = f"$.sensitivity.declared_context[{index}]"
        entry = c.obj(entry, path, required=("name", "level", "file"), optional=("canary",))
        c.string(entry.get("name"), path + ".name", pattern=_ID)
        c.level(entry.get("level"), path + ".level")
        c.absolute(entry.get("file"), path + ".file")
        if "canary" in entry:
            c.boolean(entry["canary"], path + ".canary")

    # -- egress --------------------------------------------------------------
    egress = _defaults(top, "egress", EGRESS_DEFAULTS)
    c.obj(top.get("egress", {}), "$.egress", optional=tuple(EGRESS_DEFAULTS))
    mode = c.string(egress["mode"], "$.egress.mode", choices=("none", "proxy", "direct_development_only"))
    network = [item for item in connectors if item.get("type") in NETWORK_CONNECTORS]
    if mode == "direct_development_only" and production:
        c.error("$.egress.mode", "direct_egress_forbidden_in_production")
    if mode == "none" and network:
        c.error("$.egress.mode", "network_connectors_require_egress")
    allow = []
    if mode == "proxy":
        c.absolute(egress["socket"], "$.egress.socket")
        if isinstance(egress["socket"], str) and isinstance(paths.get("socket"), str) and (
                PurePosixPath(egress["socket"]).parent in (PurePosixPath(paths["socket"]).parent,
                                                           PurePosixPath(paths.get("admin_socket", "/")).parent)):
            c.error("$.egress.socket", "egress_socket_directory_must_be_separate")
        for position, uid in enumerate(c.items(egress["client_uids"], "$.egress.client_uids", maximum=16,
                                               required=production)):
            c.integer(uid, f"$.egress.client_uids[{position}]", 1, 2_147_483_647)
            if any(uid == agent.get("uid") for agent in agents):
                c.error(f"$.egress.client_uids[{position}]", "agent_uid_cannot_use_egress")
        if production and guard_uid is not None and egress["client_uids"] != [guard_uid]:
            c.error("$.egress.client_uids", "only_guard_uid_may_use_egress")
        if egress["socket_group"] is not None:
            c.integer(egress["socket_group"], "$.egress.socket_group", 1, 2_147_483_647)
    for index, rule in enumerate(c.items(egress["allow"], "$.egress.allow", maximum=256)):
        path = f"$.egress.allow[{index}]"
        rule = c.obj(rule, path, required=("host", "port"), optional=("addresses",))
        if c.string(rule.get("host"), path + ".host", maximum=253) is not None and _canonical_host(rule["host"]) is None:
            c.error(path + ".host", "invalid_egress_host")
        allow.append((_canonical_host(rule.get("host")), rule.get("port")))
        c.integer(rule.get("port"), path + ".port", 1, 65535)
    c.unique(allow, "$.egress.allow", "duplicate_egress_rule")
    c.number(egress["connect_timeout_seconds"], "$.egress.connect_timeout_seconds", 0.1, 120)
    c.number(egress["idle_timeout_seconds"], "$.egress.idle_timeout_seconds", 0.1, 3600)
    c.integer(egress["max_connections"], "$.egress.max_connections", 1, 1024)
    if mode == "proxy":
        for index, connector in enumerate(connectors):
            if connector.get("type") in NETWORK_CONNECTORS:
                binding = connector_binding(connector) if "endpoint" in connector or connector["type"] == "virustotal_ip" else None
                if binding and binding[1] and (binding[1], 443) not in allow:
                    c.error(f"$.connectors[{index}]", "destination_not_on_egress_allowlist")

    # Operator-declared backend identity closes the DNS-alias classification
    # gap in production. The section is product configuration, never request or
    # agent input. Every network host and data domain must resolve exactly once;
    # tenant scope remains an additional constraint, not a replacement for the
    # route/principal authorization above.
    backend_inventory = None
    trusted_inventory = None
    if "backend_inventory" in top:
        try:
            trusted_inventory = validate_inventory(top["backend_inventory"])
            backend_inventory = {
                "schema_version": 1,
                "backends": [{"backend_id": entry.backend_id, "account_id": entry.account_id,
                              "data_domain": entry.data_domain, "tenants": sorted(entry.tenants),
                              "hosts": list(entry.hosts)}
                             for entry in trusted_inventory.entries],
            }
        except InventoryError as exc:
            c.errors.extend(exc.errors)
    elif production and network:
        c.error("$.backend_inventory", "required_for_production_network_connectors")
    if production and network and trusted_inventory is not None:
        try:
            resolve_production_connectors(trusted_inventory, connectors, routes=routes)
        except InventoryError as exc:
            c.errors.extend(exc.errors)

    # Round trips: anything a route may send to a destination can come back
    # through any route to the same backend (echoes, stored records read by
    # another agent). In production every such route must label its responses
    # at least as high as the highest clearance into that backend, so data
    # cannot lose its level by being written and read back. The backend is the
    # declared data_domain (shared across tenants) or else the tenant's
    # canonical destination; host names that reach one service must be declared
    # with one data_domain because Guard cannot discover DNS-level aliases.
    # Retrieval routes are read-only and label responses per document.
    if production:
        groups = backend_groups(routes, by_connector)
        ceilings = {}
        for index, group in groups.items():
            if routes[index]["clearance"] in LEVELS:
                ceilings[group] = max(ceilings.get(group, "public"), routes[index]["clearance"], key=LEVELS.index)
        for index, group in groups.items():
            route, ceiling = routes[index], ceilings.get(group)
            if (ceiling is not None and route["produces"] in LEVELS
                    and LEVELS.index(route["produces"]) < LEVELS.index(ceiling)):
                c.error(f"$.routes[{index}].produces", "produces_below_destination_clearance")

    # Restored references may carry values at the detector levels; only routes
    # cleared for those levels may restore them.
    floor = None
    if sensitivity["detected_level"] in LEVELS and sensitivity["secret_level"] in LEVELS:
        floor = max(sensitivity["detected_level"], sensitivity["secret_level"], key=LEVELS.index)
    for index, route in enumerate(routes):
        if (route["privacy"] == "restore" and floor is not None and route["clearance"] in LEVELS
                and LEVELS.index(route["clearance"]) < LEVELS.index(floor)):
            c.error(f"$.routes[{index}].clearance", "restore_route_clearance_below_detector_levels")

    # Outcome-ledger sizing: the configured request rate, archive age, archive
    # interval and clock skew determine how many records can be live at once.
    warnings = []
    if production and retention["scheduled"] is False:
        c.error("$.retention.scheduled", "scheduled_retention_required_in_production")
    if not c.errors:
        sizing = outcome_sizing({"service": service, "outcomes": outcomes, "retention": retention, "agents": agents})
        if sizing["sufficient"] is False:
            detail = {key: sizing.get(key) for key in (
                "max_requests_per_second", "record_lifetime_seconds", "required_capacity", "capacity",
                "required_busiest_tenant_share", "tenant_share_capacity", "sustainable_requests_per_second", "note")
                if sizing.get(key) is not None}
            if production:
                c.error("$.outcomes.capacity", "outcome_capacity_insufficient_for_request_rate", detail)
            else:
                warnings.append({"path": "$.outcomes.capacity", "code": "outcome_capacity_insufficient_for_request_rate",
                                 "detail": detail})
        elif sizing["sufficient"] is None:
            warnings.append({"path": "$.service.max_requests_per_second", "code": "request_rate_not_configured"})
    if not c.errors:
        warnings += possible_aliases(connectors)
    if c.errors:
        raise ConfigError(c.errors)
    normalized = {"schema_version": 2, "profile": profile, "deployment": {"guard_uid": guard_uid},
                  "paths": dict(paths), "service": service, "vault": vault, "outcomes": outcomes, "audit": audit,
                  "security_history": security_history,
                  "inspection": inspection, "retention": retention, "tenants": tenants, "connectors": connectors,
                  "routes": routes, "security_engines": security_engines, "policy_engines": policy_engines,
                  "agents": agents, "approvers": approvers, "sensitivity": sensitivity,
                  "egress": egress, "backend_inventory": backend_inventory}
    # The validated product policy must not retain any caller-owned mutable
    # list/dict. Configuration is bounded JSON, so one final JSON round-trip is
    # a complete detached snapshot and also preserves the schema's JSON types.
    normalized = json.loads(json.dumps(
        normalized, allow_nan=False, separators=(",", ":")))
    detached_warnings = json.loads(json.dumps(
        warnings, allow_nan=False, separators=(",", ":")))
    return ProductConfig(normalized, source, tuple(detached_warnings))
