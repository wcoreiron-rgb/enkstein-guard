import asyncio
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest

from enkstein_guard.contracts import SecurityContext
from enkstein_guard.orchestration import Admission
from enkstein_guard.processes import SandboxedPythonWorker
from enkstein_guard.runtime import GuardError,Operation


@unittest.skipUnless(sys.platform=='darwin','macOS sandbox profile')
class ProcessTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();root=Path(self.tmp.name)
        self.worker=root/'worker.py'
        self.worker.write_text('''import json,sys,time,socket,errno,os
data=json.load(sys.stdin)
if data.get("sleep"): time.sleep(30)
if data.get("flood"): print("x"*100000)
elif data.get("path"):
 try:
  open(data["path"]).read()
  print(json.dumps({"denied":False}))
 except PermissionError: print(json.dumps({"denied":True}))
elif data.get("port"):
 try:
  socket.create_connection(("127.0.0.1",data["port"]),timeout=1)
  print(json.dumps({"denied":False}))
 except OSError as error: print(json.dumps({"denied":error.errno in (errno.EPERM,errno.EACCES)}))
else: print(json.dumps({"clean_env":"ENKSTEIN_FAKE_SECRET" not in os.environ}))
''')
        self.admission=Admission(str(self.worker),hashlib.sha256(self.worker.read_bytes()).hexdigest())

    def tearDown(self):self.tmp.cleanup()

    def operation(self,payload):
        import json
        return Operation(SecurityContext('t','p','a','w','o','worker','v'),'worker','worker','sandbox',json.dumps(payload),'digest')

    async def test_environment_scrubbed(self):
        os.environ['ENKSTEIN_FAKE_SECRET']='fixture'
        try:self.assertTrue((await SandboxedPythonWorker(self.admission).call(self.operation({})))['clean_env'])
        finally:os.environ.pop('ENKSTEIN_FAKE_SECRET',None)

    async def test_private_file_denied(self):
        victim=Path(self.tmp.name)/'private.txt';victim.write_text('fixture-private-content')
        self.assertTrue((await SandboxedPythonWorker(self.admission).call(self.operation({'path':str(victim)})))['denied'])

    async def test_network_denied(self):
        server=await asyncio.start_server(lambda reader,writer:writer.close(),'127.0.0.1',0)
        try:
            port=server.sockets[0].getsockname()[1]
            self.assertTrue((await SandboxedPythonWorker(self.admission).call(self.operation({'port':port})))['denied'])
        finally:server.close();await server.wait_closed()

    async def test_timeout_kills_process(self):
        worker=SandboxedPythonWorker(self.admission,timeout=.1)
        before=asyncio.get_running_loop().time()
        with self.assertRaises(GuardError):await worker.call(self.operation({'sleep':True}))
        self.assertGreaterEqual(asyncio.get_running_loop().time()-before,.08)
        with self.assertRaises(ProcessLookupError):os.kill(worker.last_pid,0)

    async def test_cancellation_kills_process(self):
        worker=SandboxedPythonWorker(self.admission)
        task=asyncio.create_task(worker.call(self.operation({'sleep':True})))
        while worker.last_pid is None:await asyncio.sleep(.001)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):await task
        with self.assertRaises(ProcessLookupError):os.kill(worker.last_pid,0)

    async def test_output_limit_kills_process(self):
        worker=SandboxedPythonWorker(self.admission,output_limit=1024)
        with self.assertRaises(GuardError):await worker.call(self.operation({'flood':True}))
        with self.assertRaises(ProcessLookupError):os.kill(worker.last_pid,0)

    async def test_orchestrator_cancellation_terminates_worker(self):
        from enkstein_guard.contracts import Action,ControlResult
        from enkstein_guard.orchestration import ProtectedOrchestrator,Tool
        from enkstein_guard.runtime import Route
        from enkstein_guard.vault import LocalVault
        root=Path(self.tmp.name)
        vault=LocalVault.initialize(root/'data/v.db',root/'keys/key.json')
        worker=SandboxedPythonWorker(self.admission)
        async def policy(op):return ControlResult('policy',op.context.tenant_id,op.context.operation_id,Action.ALLOW)
        tool=Tool(Route('worker','code.execute','worker','sandbox','t',('policy',),worker.call),self.admission)
        guard=ProtectedOrchestrator(tools=(tool,),controls={'policy':policy},vault=vault,audit=lambda event:None)
        agent=guard.start(tenant='t',principal='p',grants=frozenset({'worker'}))
        task=asyncio.create_task(guard.execute(agent.credential,'worker',{'sleep':True}))
        while worker.last_pid is None:await asyncio.sleep(.001)
        guard.cancel(agent.credential)
        with self.assertRaises(asyncio.CancelledError):await task
        with self.assertRaises(ProcessLookupError):os.kill(worker.last_pid,0)
