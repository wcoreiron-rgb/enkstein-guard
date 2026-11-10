"""Product-host restart, adoption, and backup coverage for durable approvals."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from enkstein_guard import maintenance
from enkstein_guard.approval_store import ApprovalStoreError
from enkstein_guard.host import Components, GuardHost, StateLayout, initialize_state, state_lock
from enkstein_guard.identities import IdentityStore
from enkstein_guard.outcomes import new_request_id
from enkstein_guard.productconfig import validate
from enkstein_guard.service import guarded_request
from test_host import make_config


class DurableApprovalHostTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-approval-host-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("sock", "admin"):
            (self.root / name).mkdir(mode=0o700)
        (self.root / "declared.txt").write_text("cobalt orchard")
        self.config_path = self.root / "config.json"
        self.config_path.write_text(json.dumps(make_config(self.root)))
        self.config = validate(json.loads(self.config_path.read_text()), source=str(self.config_path))
        initialize_state(self.config)
        identities = IdentityStore(*StateLayout(self.config).identities)
        agent_path, approver_path = self.root / "agent.token", self.root / "approver.token"
        identities.issue("agent", "agent-a", agent_path)
        identities.issue("approver", "alice", approver_path)
        self.agent, self.approver = agent_path.read_text().strip(), approver_path.read_text().strip()
        self.host = None

    async def asyncTearDown(self):
        if self.host is not None:
            await self.host.stop()

    async def start(self):
        self.host = await GuardHost(self.config).start()

    async def stop(self):
        if self.host is not None:
            await self.host.stop()
            self.host = None

    async def request(self, payload, request_id, approval=None):
        return await guarded_request(self.config["paths"]["socket"], self.agent, "ticket.close", payload,
                                     request_id=request_id, approval=approval, timeout=20)

    async def approved_pending(self):
        payload, request_id = {"ticket": "INC-42", "reason": "resolved"}, new_request_id()
        required = await self.request(payload, request_id)
        self.assertEqual(required["status"], "approval_required")
        decided = await self.host.admin("approvals.decide", {
            "ticket": required["ticket"], "approver_credential": self.approver,
            "action_digest": required["action_digest"], "decision": "approve"})
        self.assertEqual(decided["status"], "ok")
        return payload, request_id, required

    async def test_approved_ticket_survives_host_restart_and_remains_single_use(self):
        await self.start()
        payload, request_id, approval = await self.approved_pending()
        await self.stop()

        await self.start()
        executed = await self.request(payload, request_id, approval["ticket"])
        self.assertEqual(executed["status"], "ok")
        await self.stop()

        await self.start()
        replay = await self.request(payload, new_request_id(), approval["ticket"])
        self.assertEqual(replay["status"], "approval_required")

    async def test_backup_restore_verifies_and_recovers_pending_approval(self):
        await self.start()
        payload, request_id, approval = await self.approved_pending()
        await self.stop()

        data_backup, key_backup = self.root / "backup-data", self.root / "backup-keys"
        with state_lock(self.config):
            created = maintenance.create_backup(self.config, data_backup, key_backup)
        self.assertEqual(created["stores"], len(StateLayout(self.config).stores()))
        self.assertTrue(maintenance.verify_backup(data_backup, key_backup)["verified"])

        # Restore the coordinated full-state backup to the same configuration,
        # preserving the policy-version component of the exact-action binding.
        layout = StateLayout(self.config)
        shutil.rmtree(layout.state)
        shutil.rmtree(layout.keys)
        restored = maintenance.restore_backup(self.config, data_backup, key_backup)
        self.assertTrue(restored["restored"])

        await self.start()
        executed = await self.request(payload, request_id, approval["ticket"])
        self.assertEqual(executed["status"], "ok")

    async def test_legacy_state_requires_explicit_adoption_to_add_store(self):
        layout = StateLayout(self.config)
        layout.approvals[0].unlink()
        layout.approvals[1].unlink()
        with self.assertRaises(ApprovalStoreError):
            Components(self.config)
        adopted = initialize_state(self.config, adopt=True)
        self.assertIn("approvals", adopted["stores"])
        self.assertTrue(layout.approvals[0].exists())
        self.assertTrue(layout.approvals[1].exists())


if __name__ == "__main__":
    unittest.main()
