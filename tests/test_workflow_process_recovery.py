"""A real killed coordinator must not reset its spent workflow budget."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import enkstein_guard
from enkstein_guard.contracts import Action, ControlResult
from enkstein_guard.orchestration import Admission, Budget, ProtectedOrchestrator, Tool
from enkstein_guard.runtime import GuardError, Route
from enkstein_guard.vault import LocalVault
from enkstein_guard.workflow_store import WorkflowStore, WorkflowStoreError


def build(root, *, create):
    vault_paths = (root / "vault/data.sqlite3", root / "keys/vault.key")
    store_paths = (root / "workflows/data.sqlite3", root / "keys/workflows.key")
    vault = LocalVault.initialize(*vault_paths) if create else LocalVault(*vault_paths)
    store = WorkflowStore.initialize(*store_paths) if create else WorkflowStore(*store_paths)

    async def policy(operation):
        c = operation.context
        return ControlResult("policy", c.tenant_id, c.operation_id, Action.ALLOW)

    async def transport(operation):
        with (root / "effects").open("a") as stream:
            stream.write("executed\n")
            stream.flush()
            os.fsync(stream.fileno())
        (root / "dispatched").touch()
        await asyncio.Event().wait()

    source = Path(__file__).resolve()
    tool = Tool(Route("write", "write", "synthetic-record", "synthetic-service", "tenant-a",
                      ("policy",), transport), Admission(str(source), hashlib.sha256(source.read_bytes()).hexdigest()))
    return ProtectedOrchestrator(tools=(tool,), controls={"policy": policy}, vault=vault,
                                 audit=lambda event: None, store=store)


CHILD = """
import asyncio,json,os,sys
from pathlib import Path
from test_workflow_process_recovery import build,Budget
root=Path(sys.argv[1])
async def main():
    guard=build(root,create=True)
    lease=guard.start(tenant='tenant-a',principal='operator',grants=frozenset({'write'}),budget=Budget(calls=1,seconds=120))
    fd=os.open(root/'lease.json',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump({'credential':lease.credential},stream)
    await guard.execute(lease.credential,'write',{'record':'synthetic'})
asyncio.run(main())
"""


@unittest.skipUnless(os.name == "posix", "POSIX workflow ownership")
class WorkflowProcessRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_killed_owner_keeps_spent_budget_and_does_not_replay_effect(self):
        with tempfile.TemporaryDirectory(prefix="eg-workflow-crash-") as directory:
            root = Path(directory)
            package = str(Path(enkstein_guard.__file__).resolve().parent.parent)
            env = {**os.environ, "PYTHONPATH": os.pathsep.join([package, str(Path(__file__).parent)])}
            child = subprocess.Popen([sys.executable, "-c", CHILD, str(root)], env=env,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                for _ in range(1000):
                    if (root / "dispatched").exists():
                        break
                    if child.poll() is not None:
                        out, err = child.communicate()
                        self.fail("child failed before dispatch: " + (out + err)[-3000:])
                    await asyncio.sleep(0.02)
                else:
                    self.fail("coordinator did not dispatch within deadline")
                with self.assertRaises(WorkflowStoreError):
                    WorkflowStore(root / "workflows/data.sqlite3", root / "keys/workflows.key")
                child.kill()
                child.communicate(timeout=10)
                credential = json.loads((root / "lease.json").read_text())["credential"]
                recovered = build(root, create=False)
                try:
                    self.assertEqual(recovered.usage(credential)["calls"], 1)
                    self.assertEqual(recovered.usage(credential)["active"], 0)
                    with self.assertRaises(GuardError):
                        await recovered.execute(credential, "write", {"record": "synthetic"})
                    self.assertEqual((root / "effects").read_text().splitlines(), ["executed"])
                finally:
                    recovered.close()
            finally:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=10)
