"""Synthetic acceptance fixture only; never a live provider connector."""
import json
from pathlib import Path
from enkstein_guard import DurableAudit, GuardRuntime, Principal, Route, LocalVault
from enkstein_guard.privacy import Tokenizer
from enkstein_guard.private_ai import scope_for
from enkstein_guard.runtime import local_prompt_control
from enkstein_guard.service import GuardService
from enkstein_guard.outcomes import OutcomeLedger


def build_runtime():
    state = Path("/state")
    vault_db, key = state / "vault.sqlite3", state / "vault-key"
    if not vault_db.exists() and not key.exists():
        LocalVault.initialize(vault_db, key)
    vault = LocalVault(vault_db, key, tenant_limits={"a":16_777_216,"b":16_777_216})
    audit_db, audit_key = state / "audit.sqlite3", state / "audit-key"
    if not audit_db.exists() and not audit_key.exists():
        DurableAudit.initialize(audit_db, audit_key)
    audit = DurableAudit(audit_db, audit_key)
    tokenizer = Tokenizer(vault)
    config = json.loads(Path("/run/guard-secrets/registry.json").read_text())
    identities = {token: Principal(**item) for token, item in config.items()}
    def prepare(operation):
        return tokenizer.tokenize(operation.payload(), scope_for(operation), ("approved-local-sink",))
    async def execute(operation):
        return {"tenant": operation.context.tenant_id, "protected_payload": operation.payload()}
    routes = tuple(Route("read-"+tenant, "record.read", "fixture", "approved-local-sink", tenant,
                         ("local_prompt",), execute, prepare) for tenant in ("a", "b"))
    runtime = GuardRuntime(credentials=identities, routes=routes,
                        controls={"local_prompt": local_prompt_control}, audit=audit)

    outcome_db, outcome_key = state/"outcomes.sqlite3", state/"outcome-key"
    if not outcome_db.exists() and not outcome_key.exists():
        OutcomeLedger.initialize(outcome_db,outcome_key)
    peers=json.loads(Path("/run/guard-secrets/peers.json").read_text())
    return GuardService(runtime,"/run/guard/guard.sock",outcomes=OutcomeLedger(outcome_db,outcome_key),
                        peer_bindings={int(uid):tuple(identity) for uid,identity in peers.items()},
                        socket_group=10001,per_peer_connections=4)
