"""Host-side connector credentials. Never add resolved values to model context."""

import inspect
import secrets
import hashlib
import json
from dataclasses import asdict

from .runtime import AccessDenied, RejectedBeforeDispatch, UnavailableBeforeDispatch
from .vault import Scope


class CredentialBroker:
    def __init__(self, vault):
        self._vault = vault
        self._entries = {}

    @staticmethod
    def _alias(name, tenant, principal):
        return "broker:" + hashlib.sha256(json.dumps([name,tenant,principal]).encode()).hexdigest()

    def register(self, name, value, *, tenant, principal, route, destination, ttl=3600):
        if name in self._entries or not isinstance(name, str) or not name:
            raise ValueError("invalid_broker_registration")
        scope = Scope(tenant, principal, "credential-broker", secrets.token_hex(16))
        token = self._vault.put(value, scope, (destination,), ttl=ttl)
        self._vault.save_binding(self._alias(name, tenant, principal),
                                 {"scope": asdict(scope), "token": token, "route": route, "destination": destination})
        self._entries[name] = (scope, token, route, destination)

    def load(self, name, *, tenant, principal):
        binding = self._vault.load_binding(self._alias(name, tenant, principal))
        scope = Scope(**binding["scope"])
        if scope.tenant != tenant or scope.principal != principal:
            raise AccessDenied("credential_forbidden")
        self._entries[name] = (scope, binding["token"], binding["route"], binding["destination"])

    async def invoke(self, name, operation, connector):
        entry = self._entries.get(name)
        if entry is None or not inspect.iscoroutinefunction(connector):
            raise RejectedBeforeDispatch("credential_forbidden")
        scope, token, route, destination = entry
        if (operation.context.tenant_id != scope.tenant or operation.context.principal_id != scope.principal
                or operation.route != route or operation.destination != destination):
            raise RejectedBeforeDispatch("credential_forbidden")
        credential = self._vault.restore(token, scope, destination, consume=False)
        try:
            return await connector(credential, operation.payload())
        except (RejectedBeforeDispatch, UnavailableBeforeDispatch):
            raise
        except Exception:
            raise AccessDenied("connector_failed_outcome_unknown") from None

    def revoke(self, name):
        entry = self._entries.pop(name, None)
        if entry:
            self._vault.revoke_scope(entry[0])
            self._vault.delete_binding(self._alias(name, entry[0].tenant, entry[0].principal))
