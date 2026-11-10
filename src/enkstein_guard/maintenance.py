"""Offline operator maintenance: consistent backup/restore and diagnostics.

Backups require the service to be stopped (the state lock must be free).
Data and keys are written to separate private directories so they can be
stored under different access controls. Restores target empty state and key
directories only and verify every store before reporting success.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time

from . import __version__
from .approval_store import ApprovalStore, ApprovalStoreError
from .audit import DurableAudit
from .host import HostError, StateLayout, security_history_limits, vault_limits
from .identities import IdentityError, IdentityStore
from .outcomes import OutcomeLedger
from .security_context import SecurityHistoryError, SecurityHistoryStore
from .vault import LocalVault, _check_private

MANIFEST = "enkstein-guard-backup.json"


def _digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _new_private_directory(path):
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise HostError("backup_destination_exists")
    path.mkdir(mode=0o700, parents=True)
    _check_private(path, directory=True)
    return path


def _copy_private(source, target):
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with open(source, "rb") as reader, os.fdopen(fd, "wb") as writer:
        shutil.copyfileobj(reader, writer)
        writer.flush()
        os.fsync(writer.fileno())


def _sqlite_copy(source, target):
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    with closing(sqlite3.connect(source)) as reader, closing(sqlite3.connect(target)) as writer:
        reader.backup(writer)
    with open(target, "rb+") as stream:
        os.fsync(stream.fileno())


def _verify_approvals(database, key, reason):
    try:
        return ApprovalStore(database, key).verify()
    except ApprovalStoreError:
        raise HostError(reason) from None


def _verify_identities(database, key, reason):
    try:
        return IdentityStore(database, key).verify()
    except IdentityError:
        raise HostError(reason) from None


def _verify_security_history(options, database, key, reason):
    try:
        return SecurityHistoryStore(database, key, **dict(options)).verify()
    except (SecurityHistoryError, TypeError, ValueError):
        raise HostError(reason) from None


def _verify_security_history_backup(options, database, key, reason):
    # Store verification purges expired context. Verify private copies so a
    # read-only backup check never changes bytes covered by the manifest.
    with tempfile.TemporaryDirectory(prefix="eg-security-history-verify-") as temporary:
        root = Path(temporary)
        copied_database, copied_key = root / "security.sqlite3", root / "security.key"
        _copy_private(database, copied_database)
        _copy_private(key, copied_key)
        return _verify_security_history(options, copied_database, copied_key, reason)


def create_backup(config, data_output, keys_output):
    layout = StateLayout(config)
    if Path(data_output).resolve() == Path(keys_output).resolve():
        raise HostError("backup_keys_must_be_separate")
    data_dir, keys_dir = _new_private_directory(data_output), _new_private_directory(keys_output)
    audit = DurableAudit(*layout.audit)
    checkpoint = audit.verify(archives=layout.archive)
    _verify_identities(*layout.identities, "identity_store_invalid")
    _verify_approvals(*layout.approvals, "approval_store_invalid")
    _verify_security_history(security_history_limits(config), *layout.security_history,
                             "security_history_store_invalid")
    files = []
    for name, (database, key) in layout.stores().items():
        relative = database.relative_to(layout.state)
        if database.suffix == ".sqlite3":
            _sqlite_copy(database, data_dir / "state" / relative)
        else:
            _copy_private(database, data_dir / "state" / relative)
        _copy_private(key, keys_dir / key.name)
        files.append({"store": name, "data": str(Path("state") / relative), "key": key.name,
                      "data_sha256": _digest(data_dir / "state" / relative), "key_sha256": _digest(keys_dir / key.name)})
    archives = []
    if layout.archive.exists():
        for item in sorted(layout.archive.iterdir()):
            if item.is_file():
                _copy_private(item, data_dir / "archive" / item.name)
                archives.append({"file": item.name, "sha256": _digest(item)})
    manifest = {"format": "enkstein-guard-backup-v1", "version": __version__, "created_at": int(time.time()),
                "profile": config["profile"], "files": files, "archives": archives, "audit_checkpoint": checkpoint}
    manifest["security_history"] = security_history_limits(config)
    for directory in (data_dir, keys_dir):
        fd = os.open(directory / MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(manifest, stream, indent=2, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
    return {"stores": len(files), "archives": len(archives), "audit_checkpoint": checkpoint,
            "manifest_sha256": _digest(data_dir / MANIFEST)}


def _manifest(data_dir, keys_dir):
    data_dir, keys_dir = Path(data_dir), Path(keys_dir)
    for directory in (data_dir, keys_dir):
        _check_private(directory, directory=True)
    first = (data_dir / MANIFEST).read_bytes()
    if first != (keys_dir / MANIFEST).read_bytes():
        raise HostError("backup_manifest_mismatch")
    manifest = json.loads(first)
    if manifest.get("format") != "enkstein-guard-backup-v1":
        raise HostError("backup_format_unsupported")
    for item in manifest["files"]:
        if _digest(data_dir / item["data"]) != item["data_sha256"] or _digest(keys_dir / item["key"]) != item["key_sha256"]:
            raise HostError("backup_digest_mismatch")
    for item in manifest["archives"]:
        if _digest(data_dir / "archive" / item["file"]) != item["sha256"]:
            raise HostError("backup_digest_mismatch")
    return manifest


def verify_backup(data_dir, keys_dir):
    manifest = _manifest(data_dir, keys_dir)
    identity = next((item for item in manifest["files"] if item.get("store") == "identities"), None)
    if identity is None:
        raise HostError("backup_identity_store_missing")
    _verify_identities(Path(data_dir) / identity["data"], Path(keys_dir) / identity["key"],
                       "backup_identity_store_invalid")
    approval = next((item for item in manifest["files"] if item.get("store") == "approvals"), None)
    if approval is None:
        raise HostError("backup_approval_store_missing")
    _verify_approvals(Path(data_dir) / approval["data"], Path(keys_dir) / approval["key"],
                      "backup_approval_store_invalid")
    history = next((item for item in manifest["files"] if item.get("store") == "security_history"), None)
    if history is None:
        raise HostError("backup_security_history_store_missing")
    _verify_security_history_backup(manifest.get("security_history", {}),
                                    Path(data_dir) / history["data"], Path(keys_dir) / history["key"],
                                    "backup_security_history_store_invalid")
    return {"verified": True, "stores": len(manifest["files"]), "archives": len(manifest["archives"]),
            "audit_checkpoint": manifest["audit_checkpoint"], "version": manifest["version"]}


def restore_backup(config, data_dir, keys_dir):
    """Restore into empty configured directories, then verify every store."""
    data_dir, keys_dir = Path(data_dir), Path(keys_dir)
    manifest = _manifest(data_dir, keys_dir)
    layout = StateLayout(config)
    for directory in (layout.state, layout.keys, layout.archive):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        _check_private(directory, directory=True)
    if any(data.exists() or key.exists() for data, key in layout.stores().values()):
        raise HostError("restore_target_not_empty")
    if layout.archive.exists() and any(layout.archive.iterdir()):
        raise HostError("restore_target_not_empty")
    stores = layout.stores()
    if {item.get("store") for item in manifest["files"]} != set(stores):
        raise HostError("backup_store_set_mismatch")
    if manifest.get("security_history") != security_history_limits(config):
        raise HostError("backup_security_history_configuration_mismatch")
    identity = next(item for item in manifest["files"] if item["store"] == "identities")
    _verify_identities(data_dir / identity["data"], keys_dir / identity["key"],
                       "backup_identity_store_invalid")
    for item in manifest["files"]:
        database, key = stores[item["store"]]
        _copy_private(data_dir / item["data"], database)
        _copy_private(keys_dir / item["key"], key)
    for item in manifest["archives"]:
        _copy_private(data_dir / "archive" / item["file"], layout.archive / item["file"])
    audit = DurableAudit(*layout.audit)
    checkpoint = audit.verify(manifest["audit_checkpoint"], archives=layout.archive)
    LocalVault(*layout.vault, **vault_limits(config))
    OutcomeLedger(*layout.outcomes, maximum=config["outcomes"]["capacity"],
                  time_bound=config["outcomes"]["time_bound_request_ids"],
                  max_request_age=config["outcomes"]["max_request_age_seconds"],
                  clock_skew=config["outcomes"]["clock_skew_seconds"])
    _verify_approvals(*layout.approvals, "restored_approval_store_invalid")
    _verify_identities(*layout.identities, "restored_identity_store_invalid")
    _verify_security_history(security_history_limits(config), *layout.security_history,
                             "restored_security_history_store_invalid")
    audit({"event": "state_restored", "outcome": "restored", "version": __version__})
    return {"restored": True, "audit_checkpoint_verified": checkpoint, "stores": len(manifest["files"])}


GUIDANCE = {
    "denied": "A required control denied the request before any side effect. Review the denying controls and route policy.",
    "approval_required": "The action needs a bound human approval. An approver reviews and approves the ticket; the agent then resubmits the identical request with the ticket.",
    "authorized": "Controls allowed the request; see the following execution outcome.",
    "authorized_with_approval": "Controls required approval and a valid ticket satisfied it.",
    "transport_completed": "The connector completed. The response may still have been withheld (see response events).",
    "execution_failed_outcome_unknown": "The connector failed or timed out after dispatch. The destination may have executed the action: reconcile with the destination before submitting a new request ID. Never retry automatically.",
    "execution_cancelled_outcome_unknown": "The request was cancelled after dispatch (shutdown, revocation or timeout). Reconcile with the destination before any new request.",
    "dispatch_denied": "The approval ticket could not be consumed at dispatch; nothing was sent.",
    "transport_rejected_no_side_effect": "The connector rejected the request before any external call (validation, credential binding or reference restoration); nothing was sent.",
    "preparation_denied": "Payload preparation (privacy tokenization) failed; nothing was sent.",
    "response_withheld": "The action executed but its response was not released (sensitivity, grounding or taint storage).",
    "request_denied": "Authentication or route authorization failed before any control ran.",
    "request_tracking_rejected": "The request identifier was invalid, expired, outside the accepted window, conflicting or over capacity; nothing executed.",
    "taint_raised": "The agent received data of a higher sensitivity; later requests to lower-clearance routes are denied.",
    "request_unavailable_no_execution": "A required store (audit, vault or outcome ledger) failed before dispatch, for example because the disk is full; nothing was sent. Restore storage, then resubmit.",
    "preparation_unavailable_no_execution": "The vault could not store tokenized values (storage failure or vault capacity); nothing was sent.",
    "outcome_settle_failed": "The outcome ledger could not record the final state. Resubmitting the same request ID never replays it; Guard writes the state when storage recovers (service status shows pending writes).",
    "retention_failed": "A scheduled retention job failed; stores keep growing until it succeeds. See service status retention.",
    "retention_run": "A scheduled retention job archived or purged records.",
}


def diagnose(audit, archives, identifier):
    if not isinstance(identifier, str) or not 8 <= len(identifier) <= 64:
        raise HostError("invalid_diagnostic_id")
    events = []
    for sequence, time_ns, event in audit.events(archives=archives):
        if event.get("operation_id") == identifier or event.get("diagnostic_id") == identifier:
            from .audit import safe_event
            kept, _ = safe_event(event)
            events.append({"sequence": sequence, "time_ns": time_ns, **kept})
    if not events:
        return {"found": False, "events": [], "explanation": "No audit events match this identifier."}
    denying = sorted({control["id"] for event in events for control in event.get("controls", [])
                      if control.get("action") in ("deny", "require_approval") or control.get("status") != "ok"})
    outcomes = [event.get("outcome") for event in events]
    final = outcomes[-1]
    uncertain = any(str(item).endswith("outcome_unknown") for item in outcomes)
    reason = events[-1].get("reason")
    explanation = GUIDANCE.get(final, "See event sequence.")
    capacity = final == "request_tracking_rejected" and reason in ("outcome_capacity_reached",
                                                                   "tenant_outcome_capacity_reached")
    storage = final in ("request_unavailable_no_execution", "preparation_unavailable_no_execution") or (
        final == "request_tracking_rejected" and reason == "tracking_unavailable")
    if capacity:
        explanation = ("The outcome ledger (or this tenant's share) is full, so nothing was executed. Increase "
                       "outcomes.capacity or shorten retention.outcome_archive_age_seconds per the sizing shown by "
                       "config validate; service status shows scheduled archival results.")
    return {"found": True, "events": events, "final_outcome": final, "denying_or_failed_controls": denying,
            "outcome_unknown": uncertain, "explanation": explanation,
            "next_action": ("reconcile_with_destination_before_new_request" if uncertain else
                            "increase_outcome_capacity_or_archive" if capacity else
                            "check_state_storage_then_resubmit" if storage else
                            "review_policy" if final in ("denied", "request_denied") else
                            "obtain_approval" if final == "approval_required" else "none")}
