"""enkstein-guard operator CLI.

Every command (and ``--version``) prints exactly one JSON object on stdout with
``"schema": "enkstein-guard.cli/v1"`` (``scan``/``vault`` keep their earlier
fields and add the schema field). ``--help`` prints human-readable usage.
Nothing prompts. Secrets are
read only from private files or stdin, never from arguments, and are never
echoed. Errors carry fixed codes, never exception text or input.

Exit codes:
  0  success (or allowed / completed)
  2  policy outcome: denied, approval required or response withheld
  3  operation failed safely: invalid input, configuration, state or verification
  4  service unavailable or not ready
  5  outcome unknown: the action may have executed; reconcile before retrying
  64 usage error
"""

import argparse
import asyncio
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import time
from importlib.resources import files
from importlib.metadata import PackageNotFoundError, version

from . import __version__, scan_command, scan_content, scan_prompt
from .config import load_config

SCHEMA = "enkstein-guard.cli/v1"
EXIT_OK, EXIT_POLICY, EXIT_FAILED, EXIT_UNAVAILABLE, EXIT_UNKNOWN, EXIT_USAGE = 0, 2, 3, 4, 5, 64


class CommandError(Exception):
    def __init__(self, code, exit_code=EXIT_FAILED, **fields):
        super().__init__(code)
        self.code, self.exit_code, self.fields = code, exit_code, fields


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        print(json.dumps({"schema": SCHEMA, "status": "error", "error": "usage_error"}))
        raise SystemExit(EXIT_USAGE)


class _Version(argparse.Action):
    """--version prints the same JSON contract as every command."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings=option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        _print({"schema": SCHEMA, "command": "version", "status": "ok", "version": __version__})
        parser.exit(EXIT_OK)


def _print(payload):
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def _ok(command, **fields):
    _print({"schema": SCHEMA, "command": command, "status": "ok", **fields})
    return EXIT_OK


def _product(args):
    from .productconfig import ConfigError, load
    if not args.config:
        raise CommandError("product_configuration_required", EXIT_USAGE)
    try:
        return load(args.config)
    except ConfigError as error:
        raise CommandError("configuration_invalid", errors=error.errors) from None
    except OSError:
        raise CommandError("configuration_unreadable") from None


def _admin(config, command, arguments=None, timeout=30):
    from .host import admin_request
    path = config["paths"]["admin_socket"]
    try:
        return asyncio.run(admin_request(path, command, arguments, timeout=timeout))
    except (OSError, asyncio.TimeoutError, ValueError):
        raise CommandError("service_unavailable", EXIT_UNAVAILABLE) from None


def _service_running(config):
    from .host import admin_request
    try:
        return asyncio.run(admin_request(config["paths"]["admin_socket"], "status", timeout=3)).get("status") == "ok"
    except Exception:
        return False


def _admin_result(command, response):
    if response.get("status") != "ok":
        raise CommandError(str(response.get("error", "admin_command_failed")))
    return _ok(command, **{k: v for k, v in response.items() if k != "status"})


def _components(config):
    from .host import Components
    try:
        return Components(config)
    except Exception:
        raise CommandError("state_unavailable") from None


@contextmanager
def _offline(config):
    """Hold the single-owner state lock; refuse while the service runs."""
    from .host import HostError, state_lock
    try:
        manager = state_lock(config)
        manager.__enter__()
    except HostError as error:
        raise CommandError(str(error)) from None
    try:
        yield
    finally:
        manager.__exit__(None, None, None)


def _secret(source):
    from .identities import IdentityError, read_secret_input
    try:
        return read_secret_input(source)
    except IdentityError as error:
        raise CommandError(str(error)) from None


# -- command implementations ------------------------------------------------------
def cmd_init(args):
    from .host import HostError, initialize_state
    config = _product(args)
    try:
        result = initialize_state(config, adopt=args.adopt_existing)
    except HostError as error:
        raise CommandError(str(error)) from None
    except Exception:
        raise CommandError("state_initialization_failed") from None
    return _ok("init", **result)


def cmd_config(args):
    config = _product(args)
    if args.action == "validate":
        from .productconfig import outcome_sizing
        return _ok("config validate", valid=True, profile=config["profile"], summary=config.summary(),
                   warnings=list(config.warnings), outcome_sizing=outcome_sizing(config.data))
    from .host import policy_version
    return _ok("config show", policy_version=policy_version(config), configuration=config.data)


def cmd_service(args):
    config = _product(args)
    if args.action == "start":
        from .host import GuardHost, HostError, state_lock
        try:
            with state_lock(config):
                result = asyncio.run(GuardHost(config).serve())
        except HostError as error:
            raise CommandError(str(error), EXIT_UNAVAILABLE) from None
        except Exception:
            raise CommandError("service_start_failed", EXIT_UNAVAILABLE) from None
        if result.get("cancelled"):
            _print({"schema": SCHEMA, "command": "service start", "status": "stopped_outcome_unknown",
                    "cancelled_in_flight": result["cancelled"]})
            return EXIT_UNKNOWN
        return _ok("service start", stopped=True, cancelled_in_flight=0)
    if args.action == "ready":
        response = _admin(config, "ready", timeout=args.timeout)
        if response.get("status") == "ok" and response.get("ready"):
            return _ok("service ready", ready=True, checks=response["checks"])
        _print({"schema": SCHEMA, "command": "service ready", "status": "not_ready", "checks": response.get("checks", {})})
        return EXIT_UNAVAILABLE
    if args.action == "wait-ready":
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            try:
                response = _admin(config, "ready", timeout=2)
                if response.get("ready"):
                    return _ok("service wait-ready", ready=True, checks=response["checks"])
            except CommandError:
                pass
            time.sleep(0.2)
        raise CommandError("service_not_ready", EXIT_UNAVAILABLE)
    command = {"status": "status", "stop": "shutdown", "reload": "reload"}[args.action]
    return _admin_result("service " + args.action, _admin(config, command))


def _reload_if_running(config):
    if not _service_running(config):
        return {"service_running": False, "effective": "next_service_start"}
    response = _admin(config, "reload")
    return {"service_running": True, "reload": response}


def cmd_identity(args, kind):
    config = _product(args)
    from .identities import IdentityError, IdentityStore
    from .host import StateLayout
    layout = StateLayout(config)
    name = args.agent if kind == "agent" else args.approver
    if args.action in ("issue", "revoke"):
        configured = {item["id"] for item in config["agents" if kind == "agent" else "approvers"]}
        if name not in configured:
            raise CommandError("identity_not_configured")
    try:
        store = IdentityStore(*layout.identities)
        if args.action == "issue":
            result = store.issue(kind, name, args.output)
        elif args.action == "revoke":
            result = store.revoke(kind, name)
        else:
            listing = store.listing()[kind]
            entries = []
            for item in config["agents" if kind == "agent" else "approvers"]:
                record = listing.get(item["id"])
                entry = {"id": item["id"], "credential": "revoked" if record and record["revoked"] else
                         "active" if record else "not_issued", "generation": record["generation"] if record else 0}
                if kind == "agent":
                    entry.update(tenant=item["tenant"], principal=item["principal"], uid=item["uid"],
                                 routes=item["routes"], clearance=item["clearance"], task=item["task"])
                else:
                    entry.update(tenants=item["tenants"])
                entries.append(entry)
            return _ok(kind + " list", identities=entries)
    except IdentityError as error:
        raise CommandError(str(error)) from None
    except OSError:
        raise CommandError("identity_store_unavailable") from None
    return _ok(kind + " " + args.action, **result, **_reload_if_running(config))


def cmd_agent(args):
    if args.action == "reset-taint":
        config = _product(args)
        if config.agent(args.agent) is None:
            raise CommandError("identity_not_configured")
        if _service_running(config):
            return _admin_result("agent reset-taint", _admin(config, "taint.reset", {"agent": args.agent}))
        from .sensitivity import agent_key
        with _offline(config):
            components = _components(config)
            agent = config.agent(args.agent)
            previous = components.taint.reset(agent_key(agent["tenant"], agent["principal"], agent["id"]))
            components.audit({"event": "taint_reset", "outcome": "taint_reset", "agent_id": agent["id"],
                              "tenant_id": agent["tenant"], "previous_level": previous})
        return _ok("agent reset-taint", agent=args.agent, previous_level=previous)
    return cmd_identity(args, "agent")


def cmd_approvals(args):
    config = _product(args)
    if args.action == "list":
        return _admin_result("approvals list", _admin(config, "approvals.list"))
    credential = _secret(args.approver_credential_file)
    if args.action == "review":
        response = _admin(config, "approvals.review", {"ticket": args.ticket, "approver_credential": credential})
        return _admin_result("approvals review", response)
    response = _admin(config, "approvals.decide", {"ticket": args.ticket, "approver_credential": credential,
                                                   "action_digest": args.digest, "decision": args.action})
    return _admin_result("approvals " + args.action, response)


def cmd_policy(args):
    config = _product(args)
    routes = []
    for route in config["routes"]:
        if args.route and route["name"] != args.route:
            continue
        controls = list(route["controls"]) + (["task_boundary"] if route["task_boundaries"] else []) + (
            ["approval"] if route["approval"] == "required" else [])
        if route["security_engine"] is not None:
            controls.append("ai_security." + route["security_engine"])
        if route["policy_engine"] is not None:
            controls.append("agt." + route["policy_engine"])
        routes.append({"name": route["name"], "tenant": route["tenant"], "operation": route["operation"],
                       "resource": route["resource"], "destination": route["destination"],
                       "connector": route["connector"], "required_controls": controls,
                       "clearance": route["clearance"], "produces": route["produces"], "approval": route["approval"],
                       "privacy": route["privacy"], "grounding": route["grounding"],
                       "security_engine": route["security_engine"],
                       "policy_engine": route["policy_engine"],
                       "privacy_exception": bool(route.get("privacy_exception_reason")),
                       "task_boundaries": [{"principal": b["principal"], "workflow": b["workflow"],
                                            "fields": [{"path": f["path"], "kind": f["kind"],
                                                        "constrained": sorted(set(f) - {"path", "kind"})}
                                                       for f in b["fields"]]} for b in route["task_boundaries"]],
                       "agents": [a["id"] for a in config["agents"] if route["name"] in a["routes"]]})
    if args.route and not routes:
        raise CommandError("unknown_route")
    from .host import policy_version
    return _ok("policy explain", policy_version=policy_version(config), routes=routes,
               security_engines=config.summary()["security_engines"],
               policy_engines=config.summary()["policy_engines"],
               sensitivity={"detected_level": config["sensitivity"]["detected_level"],
                            "secret_level": config["sensitivity"]["secret_level"],
                            "field_rules": len(config["sensitivity"]["field_rules"]),
                            "declared_context": [e["name"] for e in config["sensitivity"]["declared_context"]],
                            "unlabelled_heuristics": config["sensitivity"]["unlabelled_heuristics"]})


def cmd_security(args):
    config = _product(args)
    if type(args.limit) is not int or not 1 <= args.limit <= 16:
        raise CommandError("invalid_limit", EXIT_USAGE)
    response = _admin(config, "security.history", {"agent": args.agent, "limit": args.limit})
    return _admin_result("security history", response)


def cmd_connector(args):
    config = _product(args)
    if args.action == "list":
        connectors = []
        for item in config["connectors"]:
            entry = {"name": item["name"], "type": item["type"], "synthetic": item["type"] == "fixture"}
            if "credential" in item:
                entry["credential"] = item["credential"]
            connectors.append(entry)
        return _ok("connector list", connectors=connectors)
    from .identities import IdentityError, SecretStore
    from .host import StateLayout
    try:
        store = SecretStore(*StateLayout(config).secrets)
        if args.action == "secret-list":
            return _ok("connector secret-list", secrets=store.listing())
        if args.action == "secret-remove":
            return _ok("connector secret-remove", name=args.name, removed=store.remove(args.name))
        referenced = {c["credential"] for c in config["connectors"] if "credential" in c}
        if args.name not in referenced:
            raise CommandError("secret_not_referenced_by_configuration")
        for route in args.route:
            entry = config.route(route)
            if entry is None or entry["tenant"] != args.tenant or entry["destination"] != args.destination:
                raise CommandError("secret_binding_does_not_match_route")
        value = _secret(args.value_file)
        if config.production and store.other_tenants_with_value(value, args.tenant):
            # One provider account for several tenants shares provider-side
            # state across tenant boundaries and label domains.
            raise CommandError("secret_value_shared_across_tenants")
        result = store.set(args.name, value, tenant=args.tenant, destination=args.destination, routes=args.route,
                           replace=args.replace)
        return _ok("connector secret-set", **result)
    except IdentityError as error:
        raise CommandError(str(error)) from None


def cmd_retrieval(args):
    config = _product(args)
    from .retrieval import DocumentStore, RetrievalError
    from .host import StateLayout
    if args.tenant not in {t["id"] for t in config["tenants"]}:
        raise CommandError("unknown_tenant")
    if args.collection not in {c["collection"] for c in config["connectors"] if c["type"] == "retrieval_local"}:
        raise CommandError("unknown_collection")
    try:
        store = DocumentStore(*StateLayout(config).documents)
        if args.action == "list":
            return _ok("retrieval list", documents=store.listing(args.tenant, args.collection))
        if args.action == "remove":
            return _ok("retrieval remove", removed=store.remove(args.tenant, args.collection, args.doc_id))
        count = 0
        path = Path(args.file)
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                if type(record) is not dict or set(record) - {"doc_id", "title", "content", "label", "principals", "groups"}:
                    raise ValueError()
            except ValueError:
                raise CommandError("invalid_document_record", line=line_number) from None
            store.put(tenant=args.tenant, collection=args.collection, doc_id=record.get("doc_id"),
                      title=record.get("title", ""), content=record.get("content"), label=record.get("label"),
                      principals=record.get("principals", []), groups=record.get("groups", []), replace=args.replace)
            count += 1
        return _ok("retrieval ingest", ingested=count)
    except RetrievalError as error:
        raise CommandError(str(error)) from None
    except OSError:
        raise CommandError("document_input_unavailable") from None


def cmd_audit(args):
    config = _product(args)
    from .audit import AuditError, DurableAudit
    from .host import StateLayout
    layout = StateLayout(config)
    if args.action == "archive" and _service_running(config):
        arguments = {} if args.keep is None else {"keep": args.keep}
        return _admin_result("audit archive", _admin(config, "audit.archive", arguments, timeout=600))
    try:
        audit = DurableAudit(*layout.audit, full_verify_every=0)
        archives = layout.archive if getattr(args, "with_archives", False) else None
        if args.action == "verify":
            checkpoint = None
            if args.checkpoint:
                checkpoint = json.loads(Path(args.checkpoint).read_text())
            result = audit.verify(checkpoint, archives=archives)
            return _ok("audit verify", checkpoint=result, archives_verified=archives is not None,
                       external_checkpoint_matched=checkpoint is not None, summary=audit.summary())
        if args.action == "checkpoint":
            result = audit.verify(archives=layout.archive)
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump(result, stream)
            return _ok("audit checkpoint", checkpoint=result, output=str(Path(args.output).resolve()))
        if args.action == "export":
            return _ok("audit export", output=str(Path(args.output).resolve()),
                       **audit.export(args.output, since=args.since, archives=archives))
        with _offline(config):
            keep = config["retention"]["audit_archive_keep_events"] if args.keep is None else args.keep
            return _ok("audit archive", **audit.archive(layout.archive, keep=keep))
    except AuditError as error:
        raise CommandError(str(error)) from None
    except (OSError, ValueError):
        raise CommandError("audit_operation_failed") from None


def cmd_outcomes(args):
    config = _product(args)
    from .outcomes import OutcomeError
    if args.action == "verify-archives":
        if _service_running(config):
            response = _admin(config, "outcomes.verify_archives", timeout=600)
            if response.get("status") == "ok" and not response.get("verified"):
                raise CommandError("outcome_archive_verification_failed",
                                   **{key: value for key, value in response.items() if key != "status"})
            return _admin_result("outcomes verify-archives", response)
        with _offline(config):
            components = _components(config)
            result = components.outcomes.verify_archives(components.layout.archive)
        if not result["verified"]:
            raise CommandError("outcome_archive_verification_failed", **result)
        return _ok("outcomes verify-archives", **result)
    if args.action == "archive" and _service_running(config):
        arguments = {"include_uncertain": args.include_uncertain}
        if args.before is not None:
            arguments["before"] = args.before
        return _admin_result("outcomes archive", _admin(config, "outcomes.archive", arguments, timeout=600))
    try:
        if args.action == "list":
            # Opening the ledger converts orphaned in-progress records to
            # uncertain, so a running service is asked instead of opening it.
            if _service_running(config):
                return _admin_result("outcomes list", _admin(config, "outcomes.list", {"state": args.state},
                                                             timeout=600))
            with _offline(config):
                components = _components(config)
                return _ok("outcomes list", records=components.outcomes.records(state=args.state),
                           usage=components.outcomes.usage())
        with _offline(config):
            components = _components(config)
            if args.action == "resolve":
                result = components.outcomes.resolve(args.id, args.reconciled)
                components.audit({"event": "outcome_reconciled", "outcome": "outcome_reconciled",
                                  "status": args.reconciled})
                return _ok("outcomes resolve", **result)
            before = args.before or int(time.time()) - config["retention"]["outcome_archive_age_seconds"]
            result = components.outcomes.archive(components.layout.archive, before=before,
                                                 include_uncertain=args.include_uncertain)
            components.audit({"event": "outcomes_archived", "outcome": "outcomes_archived",
                              "count": result["archived"], "cutoff": result["cutoff"]})
            return _ok("outcomes archive", **result)
    except OutcomeError as error:
        raise CommandError(str(error)) from None


def cmd_diagnose(args):
    config = _product(args)
    from .audit import AuditError, DurableAudit
    from .host import HostError, StateLayout
    from .maintenance import diagnose
    layout = StateLayout(config)
    try:
        audit = DurableAudit(*layout.audit, full_verify_every=0)
        return _ok("diagnose", diagnostic_id=args.id, **diagnose(audit, layout.archive, args.id))
    except (AuditError, HostError) as error:
        raise CommandError(str(error)) from None


def cmd_backup(args):
    config = _product(args)
    from .host import HostError
    from . import maintenance
    try:
        if args.action == "verify":
            return _ok("backup verify", **maintenance.verify_backup(args.data, args.keys))
        with _offline(config):
            if args.action == "create":
                return _ok("backup create", **maintenance.create_backup(config, args.data, args.keys))
            return _ok("backup restore", **maintenance.restore_backup(config, args.data, args.keys))
    except CommandError:
        raise
    except HostError as error:
        raise CommandError(str(error)) from None
    except Exception:
        raise CommandError("backup_operation_failed") from None


def cmd_retention(args):
    """Trigger one retention job in the running service (it also runs on schedule)."""
    config = _product(args)
    if not _service_running(config):
        raise CommandError("service_not_running_use_offline_archive_commands", EXIT_UNAVAILABLE)
    response = _admin(config, "retention.run", {"store": args.store}, timeout=600)
    if response.get("status") == "ok" and response.get("last_error"):
        raise CommandError(str(response["last_error"]), store=args.store)
    return _admin_result("retention run", response)


def _rotate_product_store(layout, store, resume, *, history_limits=None):
    """Called only while the product's exclusive offline state lock is held."""
    import re
    from .audit import DurableAudit
    from .identities import IdentityStore, SecretStore
    from .approval_store import ApprovalStore
    from .security_context import SecurityHistoryStore
    try:
        audit = DurableAudit(*layout.audit, full_verify_every=0)
        audit.verify(archives=layout.archive)
    except Exception:
        raise CommandError("audit_verification_failed", store=store, rotated=False) from None
    if store == "secrets":
        factory, paths = SecretStore, layout.secrets
    elif store == "approvals":
        factory, paths = ApprovalStore, layout.approvals
    elif store == "identities":
        factory, paths = IdentityStore, layout.identities
    elif store == "security-history" and history_limits is not None:
        def factory(*paths):
            return SecurityHistoryStore(*paths, **history_limits)
        paths = layout.security_history
    else:
        raise CommandError("unknown_key_store", store=store)
    try:
        instance = factory(*paths)
        identity_before = (instance.listing(), tuple(instance.digests(kind) for kind in ("agent", "approver"))) \
            if store == "identities" else None
        result = instance.rotate_key(resume=resume)
    except Exception as error:
        known = {"secret_store_rotation_busy", "secret_store_keyring_full",
                 "approval_key_rotation_in_progress", "approval_keyring_full",
                 "security_history_key_rotation_busy", "security_history_keyring_full",
                 "identity_key_rotation_busy", "identity_keyring_full"}
        if str(error) in known:
            raise CommandError(str(error), store=store) from None
        raise CommandError("key_rotation_state_unknown", store=store,
                           rotation_state="unknown", resume_may_be_required=True) from None
    try:
        fingerprint = result.get("current_key_fingerprint", result.get("key_fingerprint"))
        record_field = "records_reauthenticated" if store == "identities" else "records_reencrypted"
        records = result.get(record_field, result.get("records"))
        count = result.get("key_count")
        if (type(fingerprint) is not str or re.fullmatch(r"[a-f0-9]{64}", fingerprint) is None
                or type(records) is not int or records < 0 or type(count) is not int
                or not 1 <= count <= 32 or result.get("resumed") is not resume):
            raise ValueError()
        reopened = factory(*paths)
        if store == "secrets":
            verified_count = len(reopened.listing())
        elif store == "identities":
            verified_count = reopened.verify()["records"]
            identity_after = (reopened.listing(), tuple(reopened.digests(kind) for kind in ("agent", "approver")))
            if identity_before != identity_after:
                raise ValueError()
        else:
            verified_count = reopened.verify()["tickets" if store == "approvals" else "records"]
        # Opening history legitimately purges expired records. Authenticate the
        # remainder without turning a normal TTL boundary into a false failure.
        valid_count = (type(verified_count) is int and 0 <= verified_count <= records
                       if store == "security-history" else verified_count == records)
        if not valid_count:
            raise ValueError()
    except Exception:
        raise CommandError("rotated_but_store_verification_failed", store=store, rotated=True) from None
    try:
        event = {"secrets": "connector_secrets_key_rotated",
                 "approvals": "approval_store_key_rotated",
                 "security-history": "security_history_key_rotated",
                 "identities": "identity_signing_key_rotated"}[store]
        audit({"event": event, "outcome": event})
        audit.verify(archives=layout.archive)
    except Exception:
        raise CommandError("rotated_but_audit_unavailable", store=store, rotated=True) from None
    return _ok("keys rotate", store=store, rotated=True, resumed=resume,
               key_count=count, **{record_field: records},
               current_key_fingerprint=fingerprint)


def cmd_keys(args):
    """Offline key rotation for the product layout (service stopped)."""
    config = _product(args)
    resume = getattr(args, "resume", False)
    if resume and args.store not in ("secrets", "approvals", "security-history", "identities"):
        raise CommandError("resume_not_supported_for_store")
    from .host import StateLayout, security_history_limits
    with _offline(config):
        layout = StateLayout(config)
        if args.store in ("secrets", "approvals", "security-history", "identities"):
            return _rotate_product_store(layout, args.store, resume,
                                         history_limits=security_history_limits(config))
        if args.store == "audit":
            from .audit import AuditError, DurableAudit
            try:
                audit = DurableAudit(*layout.audit, full_verify_every=0)
                result = audit.rotate_key(archives=layout.archive)
            except AuditError as error:
                raise CommandError(str(error)) from None
            try:
                # Reopen from the published keyring before recording the
                # administrative action with the new primary key.
                audit = DurableAudit(*layout.audit, full_verify_every=0)
                audit.verify(result["checkpoint"], archives=layout.archive)
                audit({"event": "audit_key_rotated", "outcome": "audit_key_rotated"})
                checkpoint = audit.verify(archives=layout.archive)
            except AuditError:
                raise CommandError("rotated_but_audit_unavailable") from None
            return _ok("keys rotate", store="audit", rotated=True,
                       retained_keys=result["retained_keys"], checkpoint=checkpoint)
        from .host import vault_limits
        from .vault import LocalVault, VaultError
        try:
            vault = LocalVault(*layout.vault, **vault_limits(config))
            vault.rotate()
            LocalVault(*layout.vault, **vault_limits(config))
        except VaultError as error:
            raise CommandError(str(error)) from None
        try:
            from .audit import DurableAudit
            DurableAudit(*layout.audit)({"event": "vault_key_rotated", "outcome": "vault_key_rotated"})
        except Exception:
            raise CommandError("rotated_but_audit_unavailable") from None
    return _ok("keys rotate", store="vault", rotated=True)


def cmd_request(args):
    from .service import guarded_request
    from .outcomes import new_request_id
    credential = _secret(args.credential_file)
    try:
        raw = sys.stdin.read(16_777_217) if args.payload_file == "-" else Path(args.payload_file).read_text()
        payload = json.loads(raw)
        if type(payload) is not dict:
            raise ValueError()
    except (OSError, ValueError):
        raise CommandError("invalid_payload") from None
    request_id = new_request_id() if args.new_request_id else args.request_id
    try:
        response = asyncio.run(guarded_request(args.socket, credential, args.route, payload, request_id=request_id,
                                               approval=args.approval, timeout=args.timeout))
    except (OSError, asyncio.TimeoutError):
        raise CommandError("service_unavailable_outcome_unknown_if_sent", EXIT_UNKNOWN) from None
    except Exception:
        raise CommandError("service_disconnected_outcome_unknown", EXIT_UNKNOWN) from None
    status = response.get("status")
    exit_code = {"ok": EXIT_OK, "completed_no_replay": EXIT_OK, "denied": EXIT_POLICY,
                 "approval_required": EXIT_POLICY, "response_withheld": EXIT_POLICY,
                 "busy": EXIT_UNAVAILABLE, "in_progress": EXIT_UNAVAILABLE,
                 "unavailable_no_execution": EXIT_UNAVAILABLE,
                 "request_read_timeout_no_execution": EXIT_UNAVAILABLE,
                 "invalid_request_or_response": EXIT_FAILED,
                 "request_tracking_unavailable_or_conflict": EXIT_FAILED,
                 "durable_request_tracking_unavailable": EXIT_FAILED}.get(status, EXIT_UNKNOWN)
    _print({"schema": SCHEMA, "command": "request", "status": status, "request_id": request_id,
            "response": response})
    return exit_code


def cmd_egress(args):
    config = _product(args)
    from .egress import EgressPolicy, EgressProxy, normalize_host
    egress = config["egress"]
    if egress["mode"] != "proxy":
        raise CommandError("egress_proxy_not_configured")
    policy = EgressPolicy.from_config(egress["allow"])
    if args.action == "check":
        try:
            host, _ = normalize_host(args.host)
        except ValueError:
            raise CommandError("invalid_host") from None
        rule = policy.match(host, args.port)
        return _ok("egress check", host=host, port=args.port, allowlisted=rule is not None,
                   explicit_networks=[str(n) for n in rule.networks] if rule else [])

    async def serve():
        import signal
        log = lambda event: print(json.dumps(event, sort_keys=True), flush=True)
        from .daemon import _prepare_socket
        _prepare_socket(Path(egress["socket"]))  # removes only a stale socket we own
        proxy = EgressProxy(policy, egress["socket"], client_uids=egress["client_uids"] or None,
                            socket_group=egress["socket_group"], connect_timeout=egress["connect_timeout_seconds"],
                            idle_timeout=egress["idle_timeout_seconds"], max_connections=egress["max_connections"],
                            log=log)
        await proxy.start()
        log({"event": "egress_started", "rules": len(policy.rules)})
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, stop.set)
        await stop.wait()
        await proxy.close()
        return proxy.counters

    try:
        counters = asyncio.run(serve())
    except ValueError as error:
        raise CommandError(str(error), EXIT_UNAVAILABLE) from None
    return _ok("egress serve", stopped=True, counters=counters)


def _optional_packages():
    installed = {}
    for package in ("cryptography", "nemoguardrails", "cisco-aidefense-sdk", "agent-governance-toolkit-control-plane"):
        try:
            installed[package] = version(package)
        except PackageNotFoundError:
            installed[package] = "not_installed"
    return installed


def service_warnings(sizing, status):
    """Operator warnings derived from a running service's status."""
    warnings = []
    usage = status.get("outcomes") or {}
    if usage.get("maximum") and usage.get("records", 0) >= 0.8 * usage["maximum"]:
        warnings.append({"code": "outcome_ledger_near_capacity", "detail": {
            "records": usage["records"], "maximum": usage["maximum"]}})
    if (usage.get("fullest_tenant_share_used") or 0) >= 0.8:
        warnings.append({"code": "outcome_tenant_share_near_capacity",
                         "detail": {"fullest_tenant_share_used": usage["fullest_tenant_share_used"]}})
    retained = usage.get("retained_below_cutoff") or 0
    if retained:
        # Unreconciled uncertain records are kept past the archive horizon until
        # resolved, so the sizing headroom does not bound them.
        warnings.append({"code": "outcome_records_unreconciled", "detail": {"count": retained}})
        required = sizing.get("required_capacity")
        if required is not None and usage.get("maximum") and required + retained > usage["maximum"]:
            warnings.append({"code": "outcome_capacity_reduced_by_unreconciled_records",
                             "detail": {"required_capacity": required, "unreconciled": retained,
                                        "maximum": usage["maximum"]}})
    for store, item in (status.get("retention") or {}).items():
        if isinstance(item, dict) and item.get("last_error"):
            warnings.append({"code": "retention_failing", "detail": {"store": store, "error": item["last_error"]}})
    if status.get("audit_event_failures"):
        warnings.append({"code": "service_events_lost", "detail": {"count": status["audit_event_failures"]}})
    if status.get("unsettled_outcomes"):
        warnings.append({"code": "outcome_states_pending_write",
                         "detail": {"count": status["unsettled_outcomes"]}})
    return warnings


def cmd_doctor(args, inspection_config):
    import platform
    packages = _optional_packages()
    linux = sys.platform.startswith("linux")
    machine = platform.machine().lower()

    def state(value, detail=None):
        return {"state": value, **({"detail": detail} if detail else {})}

    controls = {
        "local_scanner": state("installed", "heuristic pattern scanner"),
        "vault_tokenization": state("installed"),
        "default_model_tokenization": state("installed", "chat connectors default to tokenization; operator exceptions are explicit"),
        "durable_audit": state("installed"),
        "outcome_ledger": state("installed"),
        "sensitivity_flow": state("installed"),
        "declared_context": state("installed"),
        "retrieval_authorization": state("installed"),
        "extractive_grounding": state("installed", "requires a configured extractive response contract"),
        "ai_security_engine": state("absent", "no configured product security engine"),
        "durable_orchestration": state("installed", "SDK hosts must explicitly attach a WorkflowStore; not automatically used by the CLI service"),
        "approvals": state("installed"),
        "task_boundaries": state("installed"),
        "peer_bound_admission": state("installed" if linux else "unsupported",
                                      None if linux else "requires Linux SO_PEERCRED"),
        "egress_restriction": state("installed", "requires separate egress proxy process and network-less Guard"),
        "macos_worker_sandbox": state("installed" if sys.platform == "darwin" else "unsupported"),
        "nemo_adapter": state("installed" if packages["nemoguardrails"] != "not_installed" else "unavailable",
                              "adapter only; not enabled by installation"),
        "cisco_adapter": state("installed" if packages["cisco-aidefense-sdk"] != "not_installed" else "unavailable",
                               "mock-tested only; no live service validation"),
        "agt_adapter": state("installed" if packages["agent-governance-toolkit-control-plane"] != "not_installed"
                             else "unavailable"),
        "agt_policy_engine": state("absent", "no configured local AGT policy engine"),
        "streaming": state("unsupported"),
        "multimodal": state("unsupported", "provider requests are text-only; media and URL parts are refused"),
        "windows": state("unsupported"), "cloud_isolation": state("unsupported"),
        "high_availability": state("unsupported", "single-host scope"),
        "network_agent_messaging": state("unsupported", "handoffs are in-coordinator only"),
        "cpu_architecture": state("validated" if machine in ("aarch64", "arm64") else "unsupported", machine),
    }
    mandatory = {"state": "not_established", "reasons": ["no_product_configuration"]}
    config = None
    if args.config and inspection_config is None:
        config = _product(args)
        agt_version = packages["agent-governance-toolkit-control-plane"]
        agt_runtime_ready = agt_version == "5.0.0"
        for name, present in (("sensitivity_flow", any("sensitivity" in r["controls"] for r in config["routes"])),
                              ("declared_context", bool(config["sensitivity"]["declared_context"])),
                              ("retrieval_authorization", any(c["type"] == "retrieval_local" for c in config["connectors"])),
                              ("approvals", any(r["approval"] != "none" for r in config["routes"])),
                              ("task_boundaries", any(r["task_boundaries"] for r in config["routes"])),
                              ("peer_bound_admission", config.production),
                              ("egress_restriction", config["egress"]["mode"] == "proxy")):
            if present and controls[name]["state"] == "installed":
                controls[name] = state("configured")
        if any(r["privacy"] == "tokenize" for r in config["routes"]):
            controls["vault_tokenization"] = state("configured")
        model_routes = [r for r in config["routes"]
                        if config.connector(r["connector"])["type"] == "chat_completions"]
        if model_routes:
            controls["default_model_tokenization"] = state("configured")
        if any((r.get("grounding") or {}).get("mode") == "extractive" for r in config["routes"]):
            controls["extractive_grounding"] = state("configured")
        if config["security_engines"]:
            try:
                from .ai_security import AISecurityControl
                from .security_assessment import ChatSecurityAnalyzer
                from .security_context import SecurityHistoryStore
                if not all((AISecurityControl, SecurityHistoryStore, ChatSecurityAnalyzer)):
                    raise ImportError()
                controls["ai_security_engine"] = state(
                    "configured", "configuration loaded; provider live validation unknown")
            except ImportError:
                controls["ai_security_engine"] = state("unavailable", "AI security engine runtime unavailable")
        if config["policy_engines"]:
            if agt_runtime_ready:
                controls["agt_policy_engine"] = state(
                    "configured",
                    "local required control configured; no live vendor or production validation implied")
            else:
                controls["agt_policy_engine"] = state(
                    "unavailable", "required AGT control-plane 5.0.0 runtime unavailable")
        for name in ("durable_audit", "outcome_ledger", "local_scanner"):
            controls[name] = state("configured")
        reasons = []
        status = None
        from .host import policy_version
        configured_policy_version = policy_version(config)
        active_policy_version = None
        if _service_running(config):
            status = _admin(config, "status")
            active_policy_version = status.get("policy_version")
            if active_policy_version == configured_policy_version:
                for name, value in controls.items():
                    if value["state"] == "configured":
                        controls[name] = state("active")
                if controls["ai_security_engine"]["state"] == "active":
                    controls["ai_security_engine"] = state(
                        "active", "control loaded; provider live validation unknown")
            else:
                reasons.append("configuration_not_active")
                if controls["ai_security_engine"]["state"] == "configured":
                    controls["ai_security_engine"] = state(
                        "configured", "pending restart; running service uses a different policy")
            if config["egress"]["mode"] == "proxy" and not status.get("preflight", {}).get("egress_proxy_healthy"):
                controls["egress_restriction"] = state("unavailable", "egress proxy unhealthy")
        else:
            reasons.append("service_not_running")
        if config["policy_engines"] and not agt_runtime_ready:
            reasons.append("agt_policy_engine_unavailable")
        if not config.production:
            reasons.append("profile_not_production")
        if status and not status.get("peer_bound"):
            reasons.append("peer_binding_inactive")
        if status and not status.get("preflight", {}).get("no_network_interfaces"):
            reasons.append("guard_has_network_interfaces")
        if status and status.get("synthetic_connectors"):
            reasons.append("synthetic_connectors_configured")
        try:
            from .host import StateLayout
            from .identities import SecretStore
            if SecretStore(*StateLayout(config).secrets).shared_value_groups():
                reasons.append("secret_value_shared_across_tenants")
        except Exception:
            reasons.append("secret_store_unreadable")
        mandatory = {"state": "active" if not reasons else "not_established", "reasons": reasons,
                     "note": "Active means this running service enforces its configured boundary; it does not cover agents outside the deployment profile."}
        from .productconfig import outcome_sizing
        sizing = outcome_sizing(config.data)
        warnings = list(config.warnings) + (service_warnings(sizing, status) if status else [])
        extra = {"outcome_sizing": sizing, "warnings": warnings,
                 "policy_versions": {"configured": configured_policy_version,
                                     "active": active_policy_version},
                 "ai_security": {"engines": config.summary()["security_engines"],
                                 "inspected_routes": [route["name"] for route in config["routes"]
                                                      if route["security_engine"] is not None]},
                 "agt_policy": {"engines": config.summary()["policy_engines"],
                                "selected_routes": [route["name"] for route in config["routes"]
                                                    if route["policy_engine"] is not None],
                                "local_only": True, "live_vendor_validation": "not_performed"},
                 "model_privacy": {"routes": len(model_routes),
                                   "tokenized": sum(r["privacy"] == "tokenize" for r in model_routes),
                                   "exceptions": [{"route": r["name"], "privacy": r["privacy"],
                                                   "reason_present": bool(r.get("privacy_exception_reason"))}
                                                  for r in model_routes if r["privacy"] != "tokenize"]}}
    else:
        extra = {}
    return _ok("doctor", version=__version__, contract_version="1.0", controls=controls,
               mandatory_enforcement_status=mandatory, **extra,
               mandatory_enforcement="requires_restricted_container_deployment_not_pip_install",
               installed_packages_not_activation_status=packages, scope="single_host_linux_arm64",
               owasp_atlas_validation="not_completed",
               max_input_bytes=inspection_config.max_input_bytes if inspection_config else 1_048_576)


# -- parser -----------------------------------------------------------------------
def build_parser():
    parser = _Parser(prog="enkstein-guard", description="Enkstein Guard operator CLI")
    parser.add_argument("--version", action=_Version, help="Print the version as JSON")
    parser.add_argument("--config", help="Configuration path (schema 1 inspection or schema 2 product)")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    commands.add_parser("doctor", help="Report control states")
    commands.add_parser("coverage", help="Show versioned framework mappings, not protection scores")
    vault_parser = commands.add_parser("vault", help="Standalone encrypted vault (SDK)")
    vault_parser.add_argument("action", choices=("init", "status", "rotate", "purge"))
    vault_parser.add_argument("--directory", required=True)
    vault_parser.add_argument("--key-file")
    scan = commands.add_parser("scan", help="Inspect UTF-8 text on stdin")
    scan.add_argument("--surface", choices=("prompt", "content", "command"), required=True)
    init = commands.add_parser("init", help="Create private state and keys exclusively")
    init.add_argument("--adopt-existing", action="store_true",
                      help="Upgrade: open and verify complete existing stores instead of refusing")
    config = commands.add_parser("config")
    config.add_argument("action", choices=("validate", "show"))
    service = commands.add_parser("service")
    service.add_argument("action", choices=("start", "status", "ready", "wait-ready", "stop", "reload"))
    service.add_argument("--timeout", type=float, default=30)
    for kind in ("agent", "approver"):
        sub = commands.add_parser(kind)
        actions = ("list", "issue", "revoke") + (("reset-taint",) if kind == "agent" else ())
        sub.add_argument("action", choices=actions)
        sub.add_argument("--" + kind)
        sub.add_argument("--output", help="New private file for the generated credential")
    approvals = commands.add_parser("approvals")
    approvals.add_argument("action", choices=("list", "review", "approve", "deny"))
    approvals.add_argument("--ticket")
    approvals.add_argument("--digest")
    approvals.add_argument("--approver-credential-file", default=None)
    policy = commands.add_parser("policy")
    policy.add_argument("action", choices=("explain",))
    policy.add_argument("--route")
    security = commands.add_parser("security")
    security.add_argument("action", choices=("history",))
    security.add_argument("--agent", required=True)
    security.add_argument("--limit", type=int, default=16)
    connector = commands.add_parser("connector")
    connector.add_argument("action", choices=("list", "secret-set", "secret-list", "secret-remove"))
    connector.add_argument("--name")
    connector.add_argument("--tenant")
    connector.add_argument("--destination")
    connector.add_argument("--route", action="append", default=[])
    connector.add_argument("--value-file", help="Private file or '-' for stdin")
    connector.add_argument("--replace", action="store_true")
    retrieval = commands.add_parser("retrieval")
    retrieval.add_argument("action", choices=("ingest", "list", "remove"))
    retrieval.add_argument("--tenant", required=True)
    retrieval.add_argument("--collection", required=True)
    retrieval.add_argument("--file")
    retrieval.add_argument("--doc-id")
    retrieval.add_argument("--replace", action="store_true")
    audit = commands.add_parser("audit")
    audit.add_argument("action", choices=("verify", "checkpoint", "export", "archive"))
    audit.add_argument("--checkpoint")
    audit.add_argument("--output")
    audit.add_argument("--since", type=int, default=0)
    audit.add_argument("--keep", type=int)
    audit.add_argument("--with-archives", action="store_true")
    outcomes = commands.add_parser("outcomes")
    outcomes.add_argument("action", choices=("list", "resolve", "archive", "verify-archives"))
    outcomes.add_argument("--state")
    outcomes.add_argument("--id")
    outcomes.add_argument("--reconciled", choices=("executed", "not_executed"))
    outcomes.add_argument("--before", type=int)
    outcomes.add_argument("--include-uncertain", action="store_true")
    diagnose = commands.add_parser("diagnose")
    diagnose.add_argument("--id", required=True)
    backup = commands.add_parser("backup")
    backup.add_argument("action", choices=("create", "verify", "restore"))
    backup.add_argument("--data", required=True, help="Backup data directory")
    backup.add_argument("--keys", required=True, help="Separate backup key directory")
    request = commands.add_parser("request", help="Send one request to a Guard socket (never retried)")
    request.add_argument("--socket", required=True)
    request.add_argument("--credential-file", required=True)
    request.add_argument("--route", required=True)
    request.add_argument("--payload-file", required=True)
    group = request.add_mutually_exclusive_group()
    group.add_argument("--request-id")
    group.add_argument("--new-request-id", action="store_true")
    request.add_argument("--approval")
    request.add_argument("--timeout", type=float, default=65)
    retention = commands.add_parser("retention", help="Run one scheduled retention job now (service running)")
    retention.add_argument("action", choices=("run",))
    retention.add_argument("--store", choices=("outcomes", "audit", "vault", "settlement"), required=True)
    keys = commands.add_parser("keys", help="Offline key maintenance (service stopped)")
    keys.add_argument("action", choices=("rotate",))
    keys.add_argument("--store", choices=("vault", "audit", "secrets", "approvals", "security-history", "identities"), required=True)
    keys.add_argument("--resume", action="store_true", help="Resume secrets/approvals/history reencryption with the published key")
    egress = commands.add_parser("egress")
    egress.add_argument("action", choices=("serve", "check"))
    egress.add_argument("--host")
    egress.add_argument("--port", type=int, default=443)
    return parser


def _require(args, *names):
    for name in names:
        if getattr(args, name.replace("-", "_"), None) in (None, "", []):
            raise CommandError("missing_argument_" + name.replace("-", "_"), EXIT_USAGE)


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    inspection = None
    if args.command in ("scan", "vault", "coverage") or (args.command == "doctor" and args.config):
        try:
            if args.command == "doctor" and args.config:
                raw = json.loads(Path(args.config).read_text())
                if type(raw) is dict and raw.get("schema_version") == 2:
                    inspection = None
                else:
                    inspection = load_config(args.config)
            else:
                inspection = load_config(args.config if args.command == "scan" else None)
        except (OSError, ValueError, TypeError):
            print(json.dumps({"schema": SCHEMA, "status": "configuration_error", "execution_authorized": False}))
            return EXIT_FAILED
    try:
        return dispatch(args, inspection)
    except CommandError as error:
        _print({"schema": SCHEMA, "command": args.command, "status": "error", "error": error.code, **error.fields})
        return error.exit_code
    except KeyboardInterrupt:
        _print({"schema": SCHEMA, "command": args.command, "status": "error", "error": "interrupted"})
        return EXIT_UNKNOWN


def dispatch(args, inspection):
    command = args.command
    if command == "coverage":
        mapping = json.loads(files("enkstein_guard").joinpath("coverage.json").read_text(encoding="utf-8"))
        return _ok("coverage", mapping=mapping)
    if command == "vault":
        return legacy_vault(args)
    if command == "doctor":
        return cmd_doctor(args, inspection)
    if command == "scan":
        return legacy_scan(args, inspection)
    if command == "init":
        return cmd_init(args)
    if command == "config":
        return cmd_config(args)
    if command == "service":
        return cmd_service(args)
    if command == "agent":
        if args.action in ("issue", "revoke", "reset-taint"):
            _require(args, "agent")
        if args.action == "issue":
            _require(args, "output")
        return cmd_agent(args)
    if command == "approver":
        if args.action in ("issue", "revoke"):
            _require(args, "approver")
        if args.action == "issue":
            _require(args, "output")
        return cmd_identity(args, "approver")
    if command == "approvals":
        if args.action != "list":
            _require(args, "ticket", "approver-credential-file")
        if args.action in ("approve", "deny"):
            _require(args, "digest")
        return cmd_approvals(args)
    if command == "policy":
        return cmd_policy(args)
    if command == "security":
        return cmd_security(args)
    if command == "connector":
        if args.action == "secret-set":
            _require(args, "name", "tenant", "destination", "route", "value-file")
        if args.action == "secret-remove":
            _require(args, "name")
        return cmd_connector(args)
    if command == "retrieval":
        if args.action == "ingest":
            _require(args, "file")
        if args.action == "remove":
            _require(args, "doc-id")
        return cmd_retrieval(args)
    if command == "audit":
        if args.action in ("checkpoint", "export"):
            _require(args, "output")
        return cmd_audit(args)
    if command == "outcomes":
        if args.action == "resolve":
            _require(args, "id", "reconciled")
        return cmd_outcomes(args)
    if command == "diagnose":
        return cmd_diagnose(args)
    if command == "backup":
        return cmd_backup(args)
    if command == "request":
        return cmd_request(args)
    if command == "keys":
        return cmd_keys(args)
    if command == "retention":
        return cmd_retention(args)
    if command == "egress":
        if args.action == "check":
            _require(args, "host")
        return cmd_egress(args)
    raise CommandError("unknown_command", EXIT_USAGE)


def legacy_vault(args):
    from .vault import LocalVault
    directory = Path(args.directory)
    database = directory / "data" / "vault.sqlite3"
    key_file = Path(args.key_file) if args.key_file else directory / "keys" / "keyring.json"
    try:
        if args.action == "init":
            LocalVault.initialize(database, key_file)
        else:
            vault = LocalVault(database, key_file)
            if args.action == "rotate":
                vault.rotate()
            elif args.action == "purge":
                count = vault.purge_expired()
                print(json.dumps({"schema": SCHEMA, "status": "ok", "expired_deleted": count}))
                return EXIT_OK
        print(json.dumps({"schema": SCHEMA, "status": "ok", "action": args.action}))
        return EXIT_OK
    except Exception:
        print(json.dumps({"schema": SCHEMA, "status": "vault_operation_failed"}))
        return EXIT_FAILED


def legacy_scan(args, config):
    try:
        text = sys.stdin.read(config.max_input_bytes + 1)
        if len(text.encode("utf-8")) > config.max_input_bytes:
            raise ValueError("Input limit exceeded")
        decision = {"prompt": scan_prompt, "content": scan_content, "command": scan_command}[args.surface](text)
    except Exception:
        print(json.dumps({"schema": SCHEMA, "status": "inspection_error", "execution_authorized": False}))
        return EXIT_FAILED
    print(json.dumps({
        "schema": SCHEMA,
        "decision": decision.decision,
        "inspection_only": True,
        "findings": [{"rule_id": f.rule_id, "action": f.decision, "line": f.line} for f in decision.findings],
    }))
    return EXIT_POLICY if decision.blocked else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
