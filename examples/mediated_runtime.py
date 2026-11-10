"""Offline reference; fake transport, no model API or credentials required."""

import asyncio
import secrets

from enkstein_guard.contracts import Action, ControlResult
from enkstein_guard.runtime import AccessDenied, GuardRuntime, Principal, Route, local_prompt_control


async def main():
    events, calls = [], []
    credential = secrets.token_urlsafe(32)

    async def authorization(operation):
        # Trusted bootstrap authorizes this one fixed fake route only.
        return ControlResult("policy", operation.context.tenant_id,
                             operation.context.operation_id, Action.ALLOW)

    async def fake_model(operation):
        calls.append(operation.context.operation_id)
        return "fake-model-response"

    runtime = GuardRuntime(
        credentials={credential: Principal("demo", "user", "agent", frozenset({"demo-model"}))},
        routes=(Route("demo-model", "model.call", "fake-model", "local", "demo",
                      ("policy", "local_prompt"), fake_model),),
        controls={"policy": authorization, "local_prompt": local_prompt_control}, audit=events.append,
    )
    await runtime.execute(credential, "demo-model", {"prompt": "Hello"})
    try:
        await runtime.execute(credential, "demo-model", {"prompt": "-----BEGIN PRIVATE KEY-----"})
    except AccessDenied:
        pass
    assert len(calls) == 1
    print("Allowed request executed; sensitive request blocked; transport calls: 1")


if __name__ == "__main__":
    asyncio.run(main())
