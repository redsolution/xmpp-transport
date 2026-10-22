import unittest
from typing import Any, List, Optional, Sequence, Tuple

from xmpp_transport.adapters.postgres.migrations import packaged_migrations
from xmpp_transport.adapters.postgres.repositories import (
    AsyncpgBindingRepository,
    AsyncpgMessageMappingRepository,
    AsyncpgRosterSyncRepository,
)
from xmpp_transport.domain.errors import DuplicateOperation
from xmpp_transport.domain.identifiers import BackendId, BindingId, RemoteObjectId


class FakePool:
    def __init__(self) -> None:
        self.rows: Sequence[Any] = ()
        self.fetch_results: List[Sequence[Any]] = []
        self.value: Optional[Any] = None
        self.status = "UPDATE 1"
        self.row: Optional[Any] = None
        self.calls: List[Tuple[str, Tuple[object, ...]]] = []

    def acquire(self):  # type: ignore[no-untyped-def]
        return self

    def transaction(self):  # type: ignore[no-untyped-def]
        return self

    async def __aenter__(self):  # type: ignore[no-untyped-def]
        return self

    async def __aexit__(self, *_args):  # type: ignore[no-untyped-def]
        return None

    async def fetch(self, query: str, *args: object) -> Sequence[Any]:
        self.calls.append((query, args))
        if self.fetch_results:
            return self.fetch_results.pop(0)
        return self.rows

    async def fetchrow(self, query: str, *args: object) -> Optional[Any]:
        self.calls.append((query, args))
        return self.row

    async def fetchval(self, query: str, *args: object) -> Optional[Any]:
        self.calls.append((query, args))
        return self.value

    async def execute(self, query: str, *args: object) -> str:
        self.calls.append((query, args))
        return self.status


class BindingRepositoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_ensure_binding_upserts_account_and_pending_binding(self) -> None:
        pool = FakePool()
        pool.row = {"binding_id": "binding-1", "backend_id": "max"}
        repository = AsyncpgBindingRepository(pool)

        record = await repository.ensure_binding("user@example.com", BackendId("max"))

        self.assertEqual(BindingId("binding-1"), record.binding_id)
        query, arguments = pool.calls[0]
        self.assertIn("ON CONFLICT (bare_jid)", query)
        self.assertIn("ON CONFLICT (xmpp_account_id, backend_id)", query)
        self.assertIn("WHEN backend_bindings.status = 'disabled' THEN 'pending'", query)
        self.assertIn("ELSE backend_bindings.status", query)
        self.assertEqual("user@example.com", arguments[1])
        self.assertEqual("max", arguments[3])

    async def test_active_bindings_are_mapped_to_strong_ids(self) -> None:
        pool = FakePool()
        pool.rows = [{"binding_id": "binding-1", "backend_id": "telegram"}]
        repository = AsyncpgBindingRepository(pool)
        records = await repository.active_bindings()
        self.assertEqual(BindingId("binding-1"), records[0].binding_id)
        self.assertEqual(BackendId("telegram"), records[0].backend_id)

    async def test_active_bindings_can_be_scoped_to_one_backend(self) -> None:
        pool = FakePool()
        repository = AsyncpgBindingRepository(pool, BackendId("telegram"))
        await repository.active_bindings()
        self.assertIn("backend_id = $1", pool.calls[0][0])
        self.assertEqual(("telegram",), pool.calls[0][1])

    async def test_credentials_are_copied_from_database_buffer(self) -> None:
        pool = FakePool()
        pool.value = bytearray(b"encrypted")
        repository = AsyncpgBindingRepository(pool)
        value = await repository.encrypted_credentials(BindingId("binding-1"))
        self.assertEqual(b"encrypted", value)
        self.assertIsInstance(value, bytes)

    async def test_credential_update_requires_existing_binding_and_backend(self) -> None:
        pool = FakePool()
        pool.status = "UPDATE 0"
        repository = AsyncpgBindingRepository(pool)
        with self.assertRaises(LookupError):
            await repository.save_encrypted_credentials(
                BindingId("missing"), BackendId("telegram"), b"encrypted"
            )

    async def test_credential_update_activates_binding(self) -> None:
        pool = FakePool()
        repository = AsyncpgBindingRepository(pool)

        await repository.save_encrypted_credentials(
            BindingId("binding-1"), BackendId("max"), b"encrypted"
        )

        self.assertIn("status = 'active'", pool.calls[0][0])

    async def test_exclusive_credential_update_disables_previous_owner(self) -> None:
        pool = FakePool()
        pool.fetch_results = [
            [{"binding_id": "old-owner", "encrypted_credentials": b"old-encrypted"}],
            [{"binding_id": "old-owner"}],
        ]
        repository = AsyncpgBindingRepository(pool)

        displaced = await repository.save_exclusive_credentials(
            BindingId("new-owner"), BackendId("max"), b"encrypted", b"digest",
            lambda value: value == b"old-encrypted",
        )

        self.assertEqual((BindingId("old-owner"),), displaced)
        self.assertIn("pg_advisory_xact_lock", pool.calls[0][0])
        self.assertEqual(("exclusive-account:max",), pool.calls[0][1])
        self.assertIn("remote_account_key IS NULL", pool.calls[1][0])
        self.assertIn("encrypted_credentials = NULL", pool.calls[2][0])
        self.assertIn("status = 'disabled'", pool.calls[2][0])
        self.assertEqual(
            ("max", b"digest", "new-owner", ["old-owner"]), pool.calls[2][1]
        )
        self.assertIn("remote_account_key = $4", pool.calls[3][0])
        self.assertEqual(("new-owner", "max", b"encrypted", b"digest"), pool.calls[3][1])

    async def test_exclusive_update_keeps_unrelated_legacy_owner(self) -> None:
        pool = FakePool()
        pool.fetch_results = [
            [{"binding_id": "unrelated", "encrypted_credentials": b"other-account"}],
            [],
        ]
        repository = AsyncpgBindingRepository(pool)

        displaced = await repository.save_exclusive_credentials(
            BindingId("new-owner"), BackendId("max"), b"encrypted", b"digest",
            lambda value: value == b"same-account",
        )

        self.assertEqual((), displaced)
        self.assertEqual([], pool.calls[2][1][3])

    async def test_marks_active_binding_authorization_lost(self) -> None:
        pool = FakePool()
        repository = AsyncpgBindingRepository(pool)

        await repository.mark_authorization_lost(BindingId("binding-1"))

        self.assertIn("status = 'authorization_lost'", pool.calls[0][0])
        self.assertEqual(("binding-1",), pool.calls[0][1])

    async def test_resolves_active_binding_by_owner_and_backend(self) -> None:
        pool = FakePool()
        pool.row = {"binding_id": "binding-1", "backend_id": "telegram"}
        repository = AsyncpgBindingRepository(pool)
        record = await repository.binding_for_xmpp_account(
            "user@example.com", BackendId("telegram")
        )
        self.assertEqual(BindingId("binding-1"), record.binding_id)
        self.assertEqual(("user@example.com", "telegram"), pool.calls[0][1])

    async def test_resolves_pending_binding_for_authentication(self) -> None:
        pool = FakePool()
        pool.row = {"binding_id": "binding-1", "backend_id": "max"}
        repository = AsyncpgBindingRepository(pool)

        record = await repository.binding_for_authentication(
            "user@example.com", BackendId("max")
        )

        self.assertEqual(BindingId("binding-1"), record.binding_id)
        self.assertIn("'pending'", pool.calls[0][0])

    async def test_resolves_owner_for_active_binding(self) -> None:
        pool = FakePool()
        pool.value = "user@example.com"
        repository = AsyncpgBindingRepository(pool)
        owner = await repository.xmpp_account_for_binding(BindingId("binding-1"))
        self.assertEqual("user@example.com", owner)
        self.assertEqual(("binding-1",), pool.calls[0][1])

    async def test_resolves_owner_for_pending_authentication_binding(self) -> None:
        pool = FakePool()
        pool.value = "user@example.com"
        repository = AsyncpgBindingRepository(pool)

        owner = await repository.xmpp_account_for_authentication(
            BindingId("binding-1")
        )

        self.assertEqual("user@example.com", owner)
        self.assertNotIn("binding.status", pool.calls[0][0])


class MessageMappingRepositoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_save_mapping_is_idempotent_for_same_remote_id(self) -> None:
        pool = FakePool()
        pool.value = "remote-1"
        repository = AsyncpgMessageMappingRepository(pool)
        await repository.save_mapping(
            BindingId("binding-1"), "client-1", RemoteObjectId("remote-1")
        )

    async def test_save_mapping_rejects_conflicting_remote_id(self) -> None:
        pool = FakePool()
        pool.value = "remote-existing"
        repository = AsyncpgMessageMappingRepository(pool)
        with self.assertRaises(DuplicateOperation):
            await repository.save_mapping(
                BindingId("binding-1"), "client-1", RemoteObjectId("remote-new")
            )

    async def test_lookup_returns_opaque_remote_id(self) -> None:
        pool = FakePool()
        pool.value = "not-a-number"
        repository = AsyncpgMessageMappingRepository(pool)
        result = await repository.remote_id_for_client_message(
            BindingId("binding-1"), "client-1"
        )
        self.assertEqual(RemoteObjectId("not-a-number"), result)

    async def test_incoming_delivery_lookup_is_boolean(self) -> None:
        pool = FakePool()
        pool.value = True
        repository = AsyncpgMessageMappingRepository(pool)
        self.assertTrue(
            await repository.incoming_delivered(
                BindingId("binding-1"), RemoteObjectId("remote-1")
            )
        )

    async def test_mark_incoming_delivery_is_idempotent_sql(self) -> None:
        pool = FakePool()
        repository = AsyncpgMessageMappingRepository(pool)
        await repository.mark_incoming_delivered(
            BindingId("binding-1"), RemoteObjectId("remote-1")
        )
        self.assertIn("ON CONFLICT DO NOTHING", pool.calls[0][0])


class MigrationTests(unittest.TestCase):
    def test_initial_migration_is_packaged(self) -> None:
        migrations = packaged_migrations()
        self.assertEqual([1, 2, 3], [migration.version for migration in migrations])
        self.assertIn("CREATE TABLE backend_bindings", migrations[0].sql)
        self.assertIn("CREATE TABLE message_mappings", migrations[0].sql)
        self.assertIn("CREATE TABLE incoming_message_deliveries", migrations[1].sql)
        self.assertIn("xmpp_account_id, backend_id", migrations[2].sql)


class RosterSyncRepositoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_reads_signature(self) -> None:
        pool = FakePool()
        pool.value = "signature-1"
        repository = AsyncpgRosterSyncRepository(pool)
        result = await repository.signature(
            BindingId("binding-1"), RemoteObjectId("contact-1")
        )
        self.assertEqual("signature-1", result)

    async def test_signature_upsert_is_idempotent_sql(self) -> None:
        pool = FakePool()
        repository = AsyncpgRosterSyncRepository(pool)
        await repository.save_signature(
            BindingId("binding-1"), RemoteObjectId("contact-1"), "signature-1"
        )
        self.assertIn("ON CONFLICT", pool.calls[0][0])

    async def test_delete_is_scoped_by_binding_and_contact(self) -> None:
        pool = FakePool()
        repository = AsyncpgRosterSyncRepository(pool)
        await repository.delete_signature(
            BindingId("binding-1"), RemoteObjectId("contact-1")
        )
        self.assertEqual(("binding-1", "contact-1"), pool.calls[0][1])


if __name__ == "__main__":
    unittest.main()
