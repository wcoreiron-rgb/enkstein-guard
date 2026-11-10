"""Offline protected orchestration reference; optional actual LangGraph runner."""

import hashlib
from pathlib import Path
import tempfile

from .adapters import AgentSession
from .contracts import Action,ControlResult
from .orchestration import Admission,Budget,ProtectedOrchestrator,Tool,READ,DELEGATE
from .runtime import AccessDenied,Route
from .vault import LocalVault


async def orchestration_reference(*, langgraph=False):
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary)
        vault=LocalVault.initialize(root/'data/vault.db',root/'keys/key.json')
        source=Path(__file__)
        admission=Admission(str(source),hashlib.sha256(source.read_bytes()).hexdigest())
        sent,events=[],[]
        async def policy(op):
            return ControlResult('policy',op.context.tenant_id,op.context.operation_id,Action.ALLOW)
        async def read_database(op):return {'customer':'jane@example.com'}
        async def external_message(op):sent.append(op.payload());return {'sent':True}
        tools=(Tool(Route('database','tool.read','customers','internal','demo',('policy',),read_database),admission,
                    frozenset({'confidential','sensitive'}),frozenset({'confidential'})),
               Tool(Route('message','tool.send','public-channel','external','demo',('policy',),external_message),admission))
        guard=ProtectedOrchestrator(tools=tools,controls={'policy':policy},vault=vault,audit=events.append)
        lease=guard.start(tenant='demo',principal='user',grants=frozenset({'database','message',READ,DELEGATE}),budget=Budget())
        parent=AgentSession(guard,lease)
        child=await parent.delegate({'message',READ})
        source_node=parent.tool_node('database',lambda state:{},output_key='source_handle')
        async def message_node(state):
            # Read/summarize inside the node, not into graph checkpoint state.
            await child.read(state['source_handle'])
            try:
                await child.execute('message',{'message':'Summary: one customer'})
            except AccessDenied:
                return {'blocked':True}
            return {'blocked':False}
        if langgraph:
            from typing import TypedDict
            from langgraph.graph import StateGraph,START,END
            class State(TypedDict,total=False):
                source_handle:str
                blocked:bool
            graph=StateGraph(State)
            graph.add_node('read',source_node);graph.add_node('send',message_node)
            graph.add_edge(START,'read');graph.add_edge('read','send');graph.add_edge('send',END)
            result=await graph.compile().ainvoke({'blocked':False})
        else:
            result=await message_node(await source_node({}))
        assert result['blocked'] and not sent
        assert 'jane@example.com' not in str(result)+str(events)
        return {'blocked':result['blocked'],'external_calls':len(sent),'usage':guard.usage(lease.credential)}
