"""Framework-neutral session and LangGraph-compatible async node factory.

Keep the session/credential in trusted closures, never graph/checkpoint state.
Only artifact handles enter graph state. No automatic SDK monkeypatching.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AgentSession:
    orchestrator: object = field(repr=False)
    lease: object = field(repr=False)

    async def execute(self, route, payload, **kwargs):
        return await self.orchestrator.execute(self.lease.credential,route,payload,**kwargs)

    async def read(self, handle):
        return await self.orchestrator.read(self.lease.credential,handle)

    async def delegate(self, grants):
        lease = await self.orchestrator.delegate(self.lease.credential,frozenset(grants))
        return AgentSession(self.orchestrator,lease)

    def cancel(self):
        self.orchestrator.cancel(self.lease.credential)

    def tool_node(self, route, arguments, *, output_key="artifact"):
        """arguments is a trusted state-to-arguments callable, not model code."""
        async def node(state):
            artifact = await self.execute(route,arguments(state))
            return {output_key:artifact.handle}
        return node
