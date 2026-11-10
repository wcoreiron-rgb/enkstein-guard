import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from enkstein_guard.vault import LocalVault, Scope, TENANT_RESERVATIONS, VaultError


class VaultReservationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.database = root / "data/vault.sqlite3"
        self.key_file = root / "keys/keyring.json"

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def scope(tenant):
        return Scope(tenant, "principal", "workflow", "operation")

    def put(self, vault, tenant, value="secret"):
        return vault.put(value, self.scope(tenant), ("approved-sink",))

    def test_default_vault_binds_first_tenant_and_rejects_second_after_reopen(self):
        vault = LocalVault.initialize(self.database, self.key_file)
        self.put(vault, "tenant-a")
        with self.assertRaisesRegex(VaultError, "tenant_not_reserved"):
            self.put(vault, "tenant-b")

        reopened = LocalVault(self.database, self.key_file)
        self.put(reopened, "tenant-a")
        with self.assertRaisesRegex(VaultError, "tenant_not_reserved"):
            self.put(reopened, "tenant-b")

    def test_failed_first_write_does_not_leave_an_uncommitted_binding(self):
        vault = LocalVault.initialize(
            self.database, self.key_file, tenant_bytes=600
        )
        with self.assertRaisesRegex(VaultError, "vault_capacity_exceeded"):
            self.put(vault, "tenant-a", "a" * 500)
        self.put(vault, "tenant-b", "safe")

    def test_configured_tenants_have_independent_reserved_capacity(self):
        vault = LocalVault.initialize(
            self.database, self.key_file, max_bytes=2_097_152, tenant_bytes=1_500
        )
        vault.configure_tenants(["tenant-a", "tenant-b"])

        self.put(vault, "tenant-a", "a" * 100)
        self.put(vault, "tenant-b", "b" * 100)
        with self.assertRaisesRegex(VaultError, "vault_capacity_exceeded"):
            self.put(vault, "tenant-a", "a" * 1_000)
        self.put(vault, "tenant-b", "still-available")

    def test_configure_is_idempotent_for_covered_tenants_and_rejects_expansion(self):
        vault = LocalVault.initialize(self.database, self.key_file)
        vault.configure_tenants(["tenant-a", "tenant-b"])
        vault.configure_tenants(["tenant-a", "tenant-b"])
        vault.configure_tenants(["tenant-a"])
        with self.assertRaisesRegex(VaultError, "tenant_reservation_mismatch"):
            vault.configure_tenants(["tenant-a", "tenant-b", "tenant-c"])

    def test_explicit_limits_persist_and_cannot_change_on_reopen(self):
        limits = {"tenant-a": 1_000, "tenant-b": 2_000}
        LocalVault.initialize(self.database, self.key_file, tenant_limits=limits)
        LocalVault(self.database, self.key_file, tenant_limits=limits)
        with self.assertRaisesRegex(VaultError, "tenant_reservation_mismatch"):
            LocalVault(
                self.database,
                self.key_file,
                tenant_limits={"tenant-a": 1_000, "tenant-b": 2_001},
            )

    def test_tampered_reservation_record_is_rejected(self):
        vault = LocalVault.initialize(self.database, self.key_file)
        vault.configure_tenants(["tenant-a"])
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "UPDATE metadata SET value=? WHERE name=?",
                (b"corrupt", TENANT_RESERVATIONS),
            )
        with self.assertRaisesRegex(VaultError, "vault_integrity_failed"):
            LocalVault(self.database, self.key_file)

    def test_rotation_and_reopen_preserve_tenant_binding(self):
        vault = LocalVault.initialize(self.database, self.key_file)
        self.put(vault, "tenant-a")
        vault.rotate()

        reopened = LocalVault(self.database, self.key_file)
        self.put(reopened, "tenant-a")
        with self.assertRaisesRegex(VaultError, "tenant_not_reserved"):
            self.put(reopened, "tenant-b")

    def test_single_tenant_legacy_vault_migrates_but_multiple_need_limits(self):
        vault = LocalVault.initialize(
            self.database,
            self.key_file,
            tenant_limits={"tenant-a": 2_000, "tenant-b": 2_000},
        )
        self.put(vault, "tenant-a")
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("DELETE FROM metadata WHERE name=?", (TENANT_RESERVATIONS,))
        migrated = LocalVault(self.database, self.key_file)
        self.put(migrated, "tenant-a")

        self.put(LocalVault(self.database, self.key_file), "tenant-a")
        # Recreate a legacy multi-tenant vault by explicitly covering both tenants first.
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("DELETE FROM entries")
            connection.execute("DELETE FROM metadata WHERE name=?", (TENANT_RESERVATIONS,))
        covered = LocalVault(
            self.database,
            self.key_file,
            tenant_limits={"tenant-a": 2_000, "tenant-b": 2_000},
        )
        self.put(covered, "tenant-a")
        self.put(covered, "tenant-b")
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("DELETE FROM metadata WHERE name=?", (TENANT_RESERVATIONS,))
        with self.assertRaisesRegex(VaultError, "tenant_reservations_required"):
            LocalVault(self.database, self.key_file)
        LocalVault(
            self.database,
            self.key_file,
            tenant_limits={"tenant-a": 2_000, "tenant-b": 2_000},
        )


if __name__ == "__main__":
    unittest.main()
