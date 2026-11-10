import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest

from enkstein_guard import maintenance
from enkstein_guard.host import GuardHost, HostError, StateLayout, initialize_state, state_lock
from enkstein_guard.identities import IdentityStore
from enkstein_guard.outcomes import new_request_id
from enkstein_guard.productconfig import validate
from enkstein_guard.service import guarded_request
from test_host import make_config


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-backup-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def environment(self, name):
        root = self.root / name
        root.mkdir()
        for item in ("sock", "admin"):
            (root / item).mkdir(mode=0o700)
        (root / "declared.txt").write_text("cobalt orchard")
        path = root / "config.json"
        path.write_text(json.dumps(make_config(root)))
        return validate(json.loads(path.read_text()), source=str(path)), root

    def run_requests(self, config, token, request_id):
        async def scenario():
            host = await GuardHost(config).start()
            try:
                return await guarded_request(config["paths"]["socket"], token, "ticket.comment",
                                             {"ticket": "INC-42", "comment": "hello"}, request_id=request_id)
            finally:
                await host.stop()
        return asyncio.run(scenario())

    def test_backup_restore_preserves_deduplication_and_audit(self):
        config, root = self.environment("primary")
        initialize_state(config)
        IdentityStore(*StateLayout(config).identities).issue("agent", "agent-a", root / "token")
        token = (root / "token").read_text().strip()
        request_id = new_request_id()
        self.assertEqual(self.run_requests(config, token, request_id)["status"], "ok")
        with state_lock(config):
            created = maintenance.create_backup(config, self.root / "b-data", self.root / "b-keys")
        self.assertGreater(created["audit_checkpoint"]["sequence"], 3)
        for directory in ("b-data", "b-keys"):
            self.assertEqual((self.root / directory).stat().st_mode & 0o777, 0o700)
        self.assertFalse(any(p.name.endswith(".key") or p.name.endswith(".keyring")
                             for p in (self.root / "b-data").rglob("*")))
        restored, restored_root = self.environment("restored")
        result = maintenance.restore_backup(restored, self.root / "b-data", self.root / "b-keys")
        self.assertTrue(result["restored"])
        self.assertEqual(self.run_requests(restored, token, request_id)["status"], "completed_no_replay")
        with self.assertRaises(HostError):
            maintenance.restore_backup(restored, self.root / "b-data", self.root / "b-keys")

    def test_tampered_or_mismatched_backup_rejected(self):
        config, root = self.environment("primary")
        initialize_state(config)
        maintenance.create_backup(config, self.root / "b-data", self.root / "b-keys")
        target = next((self.root / "b-data" / "state").rglob("outcomes.sqlite3"))
        data = bytearray(target.read_bytes())
        data[-1] ^= 1
        target.write_bytes(bytes(data))
        with self.assertRaises(HostError):
            maintenance.verify_backup(self.root / "b-data", self.root / "b-keys")
        restored, _ = self.environment("restored")
        with self.assertRaises(HostError):
            maintenance.restore_backup(restored, self.root / "b-data", self.root / "b-keys")
        with self.assertRaises(HostError):
            maintenance.create_backup(config, self.root / "same", self.root / "same")

    def test_lock_prevents_second_owner(self):
        config, _ = self.environment("primary")
        initialize_state(config)
        with state_lock(config):
            with self.assertRaises(HostError):
                with state_lock(config):
                    pass
