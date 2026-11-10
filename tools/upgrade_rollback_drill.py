"""Disposable upgrade/rollback drill: an older release's state -> this candidate.

1. The old interpreter creates vault, audit and outcome stores with data.
2. An offline backup is copied.
3. The new CLI adopts the stores (``init --adopt-existing``), verifies old data,
   records new activity, enables time-bound request IDs and archives audit.
4. The old interpreter must now refuse the migrated outcome ledger (and, for
   0.4.x, the archived audit ledger) instead of misreading it (fail closed).
5. Restoring the backup lets the old interpreter run again (rollback path).
Synthetic data only; writes the report to --output.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence  # noqa: E402

OLD_CREATE = r'''
import json, sys
from pathlib import Path
from enkstein_guard.vault import LocalVault, Scope
from enkstein_guard.audit import DurableAudit
from enkstein_guard.outcomes import OutcomeLedger
from enkstein_guard.runtime import Principal
state, keys = Path(sys.argv[1]), Path(sys.argv[2])
vault = LocalVault.initialize(state/"vault/vault.sqlite3", keys/"vault.keyring", tenant_limits={"tenant-a": 4194304})
reference = vault.put("synthetic-upgrade-secret", Scope("tenant-a", "p", "w", "o"), ("sink",), ttl=3600)
audit = DurableAudit.initialize(state/"audit/audit.sqlite3", keys/"audit.key")
for n in range(5):
    audit({"outcome": "legacy", "operation_id": "old-%d" % n})
ledger = OutcomeLedger.initialize(state/"outcomes/outcomes.sqlite3", keys/"outcomes.key", maximum=100)
ledger.configure_tenants(["tenant-a"])
name, _ = ledger.begin(Principal("tenant-a", "p", "agent-a", frozenset()), "legacy-request-0001", "r", {"x": 1})
ledger.finish(name, "completed")
print(json.dumps({"reference": reference, "checkpoint": audit.verify()}))
'''

OLD_OPEN = r'''
import json, sys
from pathlib import Path
from enkstein_guard.vault import LocalVault, Scope
from enkstein_guard.audit import DurableAudit
from enkstein_guard.outcomes import OutcomeLedger
state, keys, reference = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
result = {}
for name, opener in (("vault", lambda: LocalVault(state/"vault/vault.sqlite3", keys/"vault.keyring")),
                     ("audit", lambda: DurableAudit(state/"audit/audit.sqlite3", keys/"audit.key").verify()),
                     ("outcomes", lambda: OutcomeLedger(state/"outcomes/outcomes.sqlite3", keys/"outcomes.key", maximum=100))):
    try:
        opened = opener()
        result[name] = "opened"
        if name == "vault":
            result["old_reference_restored"] = opened.restore(reference, Scope("tenant-a", "p", "w", "o"), "sink", consume=False) == "synthetic-upgrade-secret"
    except Exception as error:
        result[name] = "refused:" + type(error).__name__
print(json.dumps(result))
'''

NEW_VERIFY = r'''
import json, sys, time
from pathlib import Path
from enkstein_guard.host import Components
from enkstein_guard.productconfig import load
from enkstein_guard.runtime import Principal
from enkstein_guard.vault import Scope
config = load(sys.argv[1])
components = Components(config)
result = {"old_reference_restored": components.vault.restore(sys.argv[2], Scope("tenant-a", "p", "w", "o"), "sink",
                                                             consume=False) == "synthetic-upgrade-secret"}
components.outcomes.configure_tenants(["tenant-a"])
principal = Principal("tenant-a", "p", "agent-a", frozenset())
result["legacy_completed_not_replayed"] = components.outcomes.begin(principal, "legacy-request-0001", "r", {"x": 1})[1] == "completed"
try:
    components.outcomes.begin(principal, "legacy-request-0002", "r", {"x": 2})
    result["legacy_format_rejected_in_time_bound_mode"] = False
except Exception:
    result["legacy_format_rejected_in_time_bound_mode"] = True
before = components.audit.verify()
components.audit({"outcome": "new_version_event"})
archive = components.audit.archive(components.layout.archive, keep=1)
result["audit_archived_events"] = archive["archived"]
result["audit_continuity_verified"] = components.audit.verify(archives=components.layout.archive)["sequence"] == before["sequence"] + 1
print(json.dumps(result))
'''


def run(python, script, *args, env=None):
    completed = subprocess.run([python, "-I", "-c", script, *map(str, args)], capture_output=True, text=True, env=env)
    if completed.returncode:
        raise RuntimeError(completed.stderr[-1500:])
    return json.loads(completed.stdout.strip().splitlines()[-1])


def version(python, env=None):
    return subprocess.run([python, "-I", "-c", "from importlib.metadata import version; print(version('enkstein-guard'))"],
                          capture_output=True, text=True, check=True, env=env).stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--old-python", required=True)
    parser.add_argument("--new-python", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    probes = {}
    for role, python in (("old", args.old_python), ("new", args.new_python)):
        probes[role] = json.loads(subprocess.run([python, "-I", str(Path(__file__).resolve().parent / "evidence.py"),
                                                  "probe"], capture_output=True, text=True, check=True).stdout)
    report = {"evidence": evidence.header("upgrade-rollback-drill", probe_info=probes["new"],
                                          extra={"old_interpreter": {"installed_package": probes["old"]["installed_package"],
                                                                     "environment": probes["old"]["environment"]}}),
              "old_version": version(args.old_python), "new_version": version(args.new_python), "steps": {}}
    with tempfile.TemporaryDirectory(prefix="eg-upgrade-") as temporary:
        root = Path(temporary)
        state, keys, archive = root / "state", root / "keys", root / "archive"
        for directory in (state / "vault", state / "audit", state / "outcomes", keys):
            directory.mkdir(parents=True, mode=0o700)
        for directory in (state, root / "sock", root / "admin"):
            directory.chmod(0o700) if directory.exists() else directory.mkdir(mode=0o700)
        created = run(args.old_python, OLD_CREATE, state, keys)
        report["steps"]["old_created_state"] = True
        backup = root / "backup"
        shutil.copytree(state, backup / "state")
        shutil.copytree(keys, backup / "keys")
        config = {"schema_version": 2, "profile": "development",
                  "paths": {"state_directory": str(state), "key_directory": str(keys), "socket": str(root / "sock/g.sock"),
                            "admin_socket": str(root / "admin/a.sock"), "archive_directory": str(archive)},
                  "vault": {"max_bytes": 67108864}, "outcomes": {"capacity": 100},
                  "tenants": [{"id": "tenant-a", "vault_bytes": 4194304}],
                  "connectors": [{"name": "echo", "type": "fixture"}],
                  "routes": [{"name": "r", "tenant": "tenant-a", "operation": "op", "resource": "res", "destination": "sink",
                              "connector": "echo", "clearance": "internal"}],
                  "agents": [{"id": "agent-a", "tenant": "tenant-a", "principal": "p", "routes": ["r"]}]}
        config_path = root / "config.json"
        config_path.write_text(json.dumps(config))
        refused = subprocess.run([args.new_python, "-m", "enkstein_guard", "--config", str(config_path), "init"],
                                 capture_output=True, text=True)
        report["steps"]["plain_init_refuses_existing_state"] = json.loads(refused.stdout).get("error") == "state_already_initialized"
        adopted = subprocess.run([args.new_python, "-m", "enkstein_guard", "--config", str(config_path), "init",
                                  "--adopt-existing"], capture_output=True, text=True)
        adopted_payload = json.loads(adopted.stdout)
        report["steps"]["adopted"] = sorted(adopted_payload.get("adopted", []))
        report["steps"]["created"] = sorted(adopted_payload.get("stores", []))
        report["steps"]["new_version_checks"] = run(args.new_python, NEW_VERIFY, config_path, created["reference"])
        report["steps"]["old_version_after_migration"] = run(args.old_python, OLD_OPEN, state, keys, created["reference"])
        shutil.rmtree(state)
        shutil.rmtree(keys)
        shutil.copytree(backup / "state", state)
        shutil.copytree(backup / "keys", keys)
        report["steps"]["old_version_after_backup_restore"] = run(args.old_python, OLD_OPEN, state, keys, created["reference"])
    steps = report["steps"]
    migrated = steps["old_version_after_migration"]
    restored = steps["old_version_after_backup_restore"]
    # 0.4.x cannot read archived audit ledgers; 0.5.0rc1 can, and keeps reading
    # them. Every older release refuses the schema-3 outcome ledger.
    legacy = report["old_version"].startswith("0.4.")
    audit_after = "refused" if legacy else "opened"
    vault_after = None if legacy else "opened"  # not asserted for 0.4.x (unchanged from the rc1 drill)
    report["expected_old_release_after_migration"] = {"outcomes": "refused", "audit": audit_after, "vault": vault_after}
    report["passed"] = bool(
        steps["plain_init_refuses_existing_state"] and steps["adopted"] == ["audit", "outcomes", "vault"]
        and all(steps["new_version_checks"].values())
        and migrated["outcomes"].startswith("refused") and migrated["audit"].startswith(audit_after)
        and (vault_after is None or migrated["vault"] == vault_after)
        and all(restored[name] == "opened" for name in ("vault", "audit", "outcomes"))
        and restored.get("old_reference_restored") is True)
    report["interpretation"] = ("Rollback after migration fails closed in the old release; the supported rollback is "
                                "restoring the pre-upgrade backup taken while the service was stopped.")
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
