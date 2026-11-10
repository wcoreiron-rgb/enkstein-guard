"""Vault-backed JSON model path and explicitly authorized restoration sinks."""

from dataclasses import dataclass, field, replace
import asyncio
import hashlib
import inspect
import json
import time

from .contracts import Action, ControlResult, Status, combine_results
from .privacy import Tokenizer
from .runtime import AccessDenied, GuardError, GuardRuntime, Operation, Principal, Route
from .vault import LocalVault, Scope, VaultError


@dataclass(frozen=True)
class PrivateReply:
    receipt: str
    content: object = field(repr=False)


def scope_for(operation):
    c = operation.context
    return Scope(c.tenant_id, c.principal_id, c.workflow_id, c.operation_id)


class PrivateAI:
    def __init__(self, *, vault: LocalVault, credentials: dict[str, Principal], tenant_id: str,
                 model, sinks: dict, input_controls: dict, output_controls: dict,
                 audit, control_timeout=2.0, ttl=300, sensitive_fields=None,
                 model_destination="model-provider", model_resource="configured-model", max_pending_replies=128):
        if not inspect.iscoroutinefunction(model) or not sinks or not input_controls or not output_controls:
            raise ValueError("private_runtime_requires_model_sinks_and_controls")
        if model_destination in sinks or "model-provider" in sinks:
            raise ValueError("restoration_to_model_forbidden")
        if any(not inspect.iscoroutinefunction(c) for c in output_controls.values()):
            raise ValueError("async_output_controls_required")
        try:
            vault.configure_tenants([tenant_id])
        except VaultError:
            raise AccessDenied("private_vault_unavailable") from None
        self._vault = vault
        self._tokenizer = Tokenizer(vault, ttl=ttl, **({"sensitive_fields": sensitive_fields} if sensitive_fields is not None else {}))
        self._receipts = {}
        self._prepared_scopes = {}
        if type(max_pending_replies) is not int or not 1 <= max_pending_replies <= 1024:
            raise ValueError("invalid_pending_reply_limit")
        self._max_pending = max_pending_replies
        self._inflight = 0
        self._destinations = tuple(sinks)
        self._ttl = ttl
        self._control_timeout = control_timeout
        self._output_controls = dict(output_controls)

        def prepare(operation):
            if operation.payload().get("stream") is True:
                raise ValueError("streaming_not_supported")
            scope = scope_for(operation)
            prepared = self._tokenizer.tokenize(operation.payload(), scope, self._destinations)
            self._prepared_scopes[asyncio.current_task()] = scope
            return prepared

        async def private_model(operation):
            # Model transport only receives the already-tokenized operation.
            response = await model(operation)
            sanitized = self._tokenizer.tokenize(response, scope_for(operation), self._destinations, allow_references=True,
                                                 numeric_cards="tokenize")
            encoded = json.dumps(sanitized, allow_nan=False)
            output_context = replace(operation.context, operation_id=operation.context.operation_id+":output", operation="model.output")
            output = Operation(output_context, operation.route, operation.resource, operation.destination,
                               encoded, hashlib.sha256(encoded.encode()).hexdigest())
            results = []
            for name, control in self._output_controls.items():
                try:
                    result = await asyncio.wait_for(control(output), control_timeout)
                    if not isinstance(result, ControlResult) or result.control_id != name:
                        raise ValueError()
                except Exception:
                    result = ControlResult(name, output.context.tenant_id, output.context.operation_id, Action.DENY, Status.ERROR)
                results.append(result)
            decision = combine_results(output.context, results, required_controls=self._output_controls)
            if decision.action not in (Action.ALLOW, Action.MONITOR):
                raise AccessDenied("private_output_denied")
            receipt = operation.context.operation_id
            self._receipts[receipt] = (scope_for(operation), encoded, time.time()+ttl)
            return PrivateReply(receipt, json.loads(encoded))

        async def sink_policy(operation):
            receipt = operation.payload().get("receipt")
            item = self._receipts.get(receipt) if isinstance(receipt, str) else None
            allowed = bool(item and item[0].tenant == operation.context.tenant_id
                           and item[0].principal == operation.context.principal_id and item[2] > time.time())
            return ControlResult("sink_policy", operation.context.tenant_id, operation.context.operation_id,
                                 Action.ALLOW if allowed else Action.DENY)

        def make_sink(destination, callback):
            if not inspect.iscoroutinefunction(callback):
                raise ValueError("async_sink_required")
            async def send(operation):
                receipt = operation.payload()["receipt"]
                # Pop before awaiting: a concurrent replay cannot reuse a receipt.
                scope, encoded, expires = self._receipts.pop(receipt)
                if expires <= time.time():
                    raise AccessDenied("receipt_expired")
                restored = self._vault.restore(encoded, scope, destination, json_encoded=True)
                return await callback(json.loads(restored))
            return send

        routes = [Route("model", "model.call", model_resource, model_destination, tenant_id,
                        tuple(input_controls), private_model, prepare)]
        routes.extend(Route("sink:"+name, "private.restore", "private-reply", name, tenant_id,
                            ("sink_policy",), make_sink(name, callback)) for name, callback in sinks.items())
        if "sink_policy" in input_controls:
            raise ValueError("reserved_control_name")
        self._runtime = GuardRuntime(credentials=credentials, routes=tuple(routes),
                                     controls={**input_controls, "sink_policy": sink_policy}, audit=audit,
                                     control_timeout=control_timeout)

    async def generate(self, credential: str, payload: dict) -> PrivateReply:
        self._purge_receipts()
        if len(self._receipts) + self._inflight >= self._max_pending:
            raise AccessDenied("pending_reply_limit")
        self._inflight += 1
        task = asyncio.current_task()
        succeeded = False
        try:
            reply = await self._runtime.execute(credential, "model", payload)
            succeeded = True
            return reply
        finally:
            self._inflight -= 1
            scope = self._prepared_scopes.pop(task, None)
            if scope is not None and not succeeded:
                self._receipts.pop(scope.operation, None)
                # Includes preparation failures, denied controls, timeouts and
                # cancellation: unreturned private references must not accumulate.
                try:
                    self._vault.revoke_scope(scope)
                except Exception:
                    raise GuardError("private_cleanup_unavailable_outcome_unknown") from None

    async def restore_to(self, credential: str, receipt: str, destination: str):
        self._purge_receipts()
        return await self._runtime.execute(credential, "sink:"+destination, {"receipt": receipt})

    def _purge_receipts(self):
        now = time.time()
        for receipt in [key for key, value in self._receipts.items() if value[2] <= now]:
            scope = self._receipts[receipt][0]
            self._vault.revoke_scope(scope)
            del self._receipts[receipt]
