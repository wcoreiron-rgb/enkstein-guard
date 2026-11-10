"""Strict adapters for host-configured engines. Optional SDKs are not bundled.

Only use after local tokenization for external inspection. Adapter contract tests
do not establish compatibility with every SDK release or a live inspection service.
"""

import asyncio
import inspect

from .contracts import Action, ControlResult


def _result(operation, name, allowed):
    if type(allowed) is not bool:
        raise ValueError("invalid_engine_verdict")
    return ControlResult(name, operation.context.tenant_id, operation.context.operation_id,
                         Action.ALLOW if allowed else Action.DENY)


def agt_control(engine, *, name="agt", role_for=None):
    """AGT control-plane PolicyEngine.check_violation adapter.

    Host supplies a frozen engine and optional trusted role resolver. Default role
    preserves tenant+principal+agent identity; configure the same role in AGT.
    This does not activate every AGT subsystem or certify its policies.
    """
    if getattr(engine, "is_frozen", None) is not True or not callable(getattr(engine, "check_violation", None)):
        raise ValueError("agt_frozen_engine_required")
    async def check(operation):
        import json
        c = operation.context
        role = role_for(c) if role_for else json.dumps([c.tenant_id, c.principal_id, c.agent_id], separators=(",", ":"))
        if not isinstance(role, str) or not role:
            raise ValueError("invalid_agt_role")
        if getattr(engine, "is_frozen", None) is not True or engine.is_shadow_mode(role):
            raise ValueError("agt_not_enforcing")
        violation = await asyncio.to_thread(engine.check_violation, role, operation.route, operation.payload())
        if violation is not None and not isinstance(violation, str):
            raise ValueError("invalid_agt_verdict")
        return _result(operation, name, violation is None)
    return check


def nemo_control(rails, *, stage="input", name="nemo"):
    """NeMo LLMRails.check_async; modified results block rather than lose rewrites."""
    if stage not in ("input", "output") or not inspect.iscoroutinefunction(getattr(rails, "check_async", None)):
        raise ValueError("invalid_nemo_configuration")
    flows = getattr(getattr(getattr(getattr(rails, "config", None), "rails", None), stage, None), "flows", None)
    if not flows:
        raise ValueError("nemo_rails_not_configured")
    async def check(operation):
        from nemoguardrails.rails.llm.options import RailType
        result = await rails.check_async(
            [{"role": "user" if stage == "input" else "assistant", "content": operation.payload_json}],
            rail_types=[RailType(stage)],
        )
        status = getattr(getattr(result, "status", None), "value", None)
        if not isinstance(status, str) or status.lower() not in ("passed", "blocked", "modified"):
            raise ValueError("invalid_nemo_verdict")
        return _result(operation, name, status.lower() == "passed")
    return check


def cisco_control(client, *, stage="input", name="cisco"):
    """Cisco AsyncChatInspectionClient; requires configured inspection service."""
    if stage not in ("input", "output"):
        raise ValueError("invalid_cisco_stage")
    method = getattr(client, "inspect_prompt" if stage == "input" else "inspect_response", None)
    if not inspect.iscoroutinefunction(method):
        raise ValueError("cisco_async_client_required")
    async def check(operation):
        kwargs = {"prompt" if stage == "input" else "response": operation.payload_json,
                  "request_id": operation.context.operation_id}
        result = await method(**kwargs)
        safe = getattr(result, "is_safe", None)
        action = getattr(getattr(result, "action", None), "value", None)
        if type(safe) is not bool or action not in ("Allow", "Block"):
            raise ValueError("invalid_cisco_verdict")
        return _result(operation, name, safe and action == "Allow")
    return check


async def local_inspection(operation):
    """Built-in detector over tokenized JSON. Privacy replacement happens first."""
    from .policy import scan_prompt
    decision = scan_prompt(operation.payload_json)
    return ControlResult("local", operation.context.tenant_id, operation.context.operation_id,
                         Action(decision.decision))
