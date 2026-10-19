"""PostgreSQL implementations of shared repository ports."""

from typing import Any, Optional, Protocol, Sequence
from uuid import uuid4

from xmpp_transport.domain.errors import DuplicateOperation
from xmpp_transport.domain.identifiers import BackendId, BindingId, RemoteObjectId
from xmpp_transport.ports.repositories import BindingRecord


class DatabasePool(Protocol):
    async def fetch(self, query: str, *args: object) -> Sequence[Any]:
        ...

    async def fetchrow(self, query: str, *args: object) -> Optional[Any]:
        ...

    async def fetchval(self, query: str, *args: object) -> Optional[Any]:
        ...

    async def execute(self, query: str, *args: object) -> str:
        ...


class AsyncpgBindingRepository:
    def __init__(
        self, pool: DatabasePool, backend_id: Optional[BackendId] = None
    ) -> None:
        self._pool = pool
        self._backend_id = backend_id

    async def ensure_binding(
        self, bare_jid: str, backend_id: BackendId
    ) -> BindingRecord:
        account_id = uuid4()
        binding_id = BindingId(str(uuid4()))
        row = await self._pool.fetchrow(
            """
            WITH account AS (
                INSERT INTO xmpp_accounts (id, bare_jid)
                VALUES ($1, $2)
                ON CONFLICT (bare_jid) DO UPDATE
                SET updated_at = CURRENT_TIMESTAMP
                RETURNING id
            ), binding AS (
                INSERT INTO backend_bindings (
                    binding_id, xmpp_account_id, backend_id, status
                )
                SELECT $3, account.id, $4, 'pending'
                FROM account
                ON CONFLICT (xmpp_account_id, backend_id) DO UPDATE
                SET updated_at = CURRENT_TIMESTAMP
                RETURNING binding_id, backend_id
            )
            SELECT binding_id, backend_id FROM binding
            """,
            account_id,
            bare_jid,
            str(binding_id),
            str(backend_id),
        )
        if row is None:
            raise RuntimeError("binding upsert did not return a row")
        return BindingRecord(
            binding_id=BindingId(str(row["binding_id"])),
            backend_id=BackendId(str(row["backend_id"])),
        )

    async def active_bindings(self) -> Sequence[BindingRecord]:
        if self._backend_id is None:
            rows = await self._pool.fetch(
                """
                SELECT binding_id, backend_id
                FROM backend_bindings
                WHERE status = 'active'
                ORDER BY binding_id
                """
            )
        else:
            rows = await self._pool.fetch(
                """
                SELECT binding_id, backend_id
                FROM backend_bindings
                WHERE status = 'active' AND backend_id = $1
                ORDER BY binding_id
                """,
                str(self._backend_id),
            )
        return tuple(
            BindingRecord(
                binding_id=BindingId(str(row["binding_id"])),
                backend_id=BackendId(str(row["backend_id"])),
            )
            for row in rows
        )

    async def encrypted_credentials(self, binding_id: BindingId) -> Optional[bytes]:
        value = await self._pool.fetchval(
            """
            SELECT encrypted_credentials
            FROM backend_bindings
            WHERE binding_id = $1
            """,
            str(binding_id),
        )
        return bytes(value) if value is not None else None

    async def binding_for_xmpp_account(
        self, bare_jid: str, backend_id: BackendId
    ) -> Optional[BindingRecord]:
        row = await self._pool.fetchrow(
            """
            SELECT binding.binding_id, binding.backend_id
            FROM backend_bindings AS binding
            JOIN xmpp_accounts AS account ON account.id = binding.xmpp_account_id
            WHERE account.bare_jid = $1
              AND binding.backend_id = $2
              AND binding.status = 'active'
            """,
            bare_jid,
            str(backend_id),
        )
        if row is None:
            return None
        return BindingRecord(
            binding_id=BindingId(str(row["binding_id"])),
            backend_id=BackendId(str(row["backend_id"])),
        )

    async def xmpp_account_for_binding(self, binding_id: BindingId) -> Optional[str]:
        value = await self._pool.fetchval(
            """
            SELECT account.bare_jid
            FROM backend_bindings AS binding
            JOIN xmpp_accounts AS account ON account.id = binding.xmpp_account_id
            WHERE binding.binding_id = $1 AND binding.status = 'active'
            """,
            str(binding_id),
        )
        return str(value) if value is not None else None

    async def xmpp_account_for_authentication(
        self, binding_id: BindingId
    ) -> Optional[str]:
        value = await self._pool.fetchval(
            """
            SELECT account.bare_jid
            FROM backend_bindings AS binding
            JOIN xmpp_accounts AS account ON account.id = binding.xmpp_account_id
            WHERE binding.binding_id = $1
            """,
            str(binding_id),
        )
        return str(value) if value is not None else None

    async def binding_for_authentication(
        self, bare_jid: str, backend_id: BackendId
    ) -> Optional[BindingRecord]:
        row = await self._pool.fetchrow(
            """
            SELECT binding.binding_id, binding.backend_id
            FROM backend_bindings AS binding
            JOIN xmpp_accounts AS account ON account.id = binding.xmpp_account_id
            WHERE account.bare_jid = $1
              AND binding.backend_id = $2
              AND binding.status IN ('pending', 'active', 'authorization_lost')
            """,
            bare_jid,
            str(backend_id),
        )
        if row is None:
            return None
        return BindingRecord(
            binding_id=BindingId(str(row["binding_id"])),
            backend_id=BackendId(str(row["backend_id"])),
        )

    async def save_encrypted_credentials(
        self, binding_id: BindingId, backend_id: BackendId, credentials: bytes
    ) -> None:
        status = await self._pool.execute(
            """
            UPDATE backend_bindings
            SET encrypted_credentials = $3,
                status = 'active',
                updated_at = CURRENT_TIMESTAMP
            WHERE binding_id = $1 AND backend_id = $2
            """,
            str(binding_id),
            str(backend_id),
            credentials,
        )
        if status != "UPDATE 1":
            raise LookupError("binding not found for credential update: {}".format(binding_id))

    async def disable_binding(self, binding_id: BindingId) -> None:
        status = await self._pool.execute(
            """
            UPDATE backend_bindings
            SET encrypted_credentials = NULL,
                status = 'disabled',
                updated_at = CURRENT_TIMESTAMP
            WHERE binding_id = $1
            """,
            str(binding_id),
        )
        if status != "UPDATE 1":
            raise LookupError("binding not found for logout: {}".format(binding_id))

    async def mark_authorization_lost(self, binding_id: BindingId) -> None:
        status = await self._pool.execute(
            """
            UPDATE backend_bindings
            SET status = 'authorization_lost',
                updated_at = CURRENT_TIMESTAMP
            WHERE binding_id = $1 AND status = 'active'
            """,
            str(binding_id),
        )
        if status not in ("UPDATE 0", "UPDATE 1"):
            raise RuntimeError("unexpected authorization status update: {}".format(status))


class AsyncpgMessageMappingRepository:
    def __init__(self, pool: DatabasePool) -> None:
        self._pool = pool

    async def remote_id_for_client_message(
        self, binding_id: BindingId, client_message_id: str
    ) -> Optional[RemoteObjectId]:
        value = await self._pool.fetchval(
            """
            SELECT remote_message_id
            FROM message_mappings
            WHERE binding_id = $1 AND client_message_id = $2
            """,
            str(binding_id),
            client_message_id,
        )
        return RemoteObjectId(str(value)) if value is not None else None

    async def save_mapping(
        self,
        binding_id: BindingId,
        client_message_id: str,
        remote_message_id: RemoteObjectId,
    ) -> None:
        stored = await self._pool.fetchval(
            """
            WITH inserted AS (
                INSERT INTO message_mappings (
                    binding_id, client_message_id, remote_message_id
                ) VALUES ($1, $2, $3)
                ON CONFLICT DO NOTHING
                RETURNING remote_message_id
            )
            SELECT remote_message_id FROM inserted
            UNION ALL
            SELECT remote_message_id
            FROM message_mappings
            WHERE binding_id = $1 AND client_message_id = $2
            LIMIT 1
            """,
            str(binding_id),
            client_message_id,
            str(remote_message_id),
        )
        if stored is None or str(stored) != str(remote_message_id):
            raise DuplicateOperation(
                "client message already maps to a different remote message"
            )

    async def incoming_delivered(
        self, binding_id: BindingId, remote_message_id: RemoteObjectId
    ) -> bool:
        value = await self._pool.fetchval(
            """
            SELECT EXISTS (
                SELECT 1
                FROM incoming_message_deliveries
                WHERE binding_id = $1 AND remote_message_id = $2
            )
            """,
            str(binding_id),
            str(remote_message_id),
        )
        return bool(value)

    async def mark_incoming_delivered(
        self, binding_id: BindingId, remote_message_id: RemoteObjectId
    ) -> None:
        await self._pool.execute(
            """
            INSERT INTO incoming_message_deliveries (binding_id, remote_message_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            """,
            str(binding_id),
            str(remote_message_id),
        )


class AsyncpgRosterSyncRepository:
    def __init__(self, pool: DatabasePool) -> None:
        self._pool = pool

    async def signature(
        self, binding_id: BindingId, remote_contact_id: RemoteObjectId
    ) -> Optional[str]:
        value = await self._pool.fetchval(
            """
            SELECT signature
            FROM roster_sync_records
            WHERE binding_id = $1 AND remote_contact_id = $2
            """,
            str(binding_id),
            str(remote_contact_id),
        )
        return str(value) if value is not None else None

    async def save_signature(
        self,
        binding_id: BindingId,
        remote_contact_id: RemoteObjectId,
        signature: str,
    ) -> None:
        await self._pool.execute(
            """
            INSERT INTO roster_sync_records (binding_id, remote_contact_id, signature)
            VALUES ($1, $2, $3)
            ON CONFLICT (binding_id, remote_contact_id) DO UPDATE
            SET signature = EXCLUDED.signature, updated_at = CURRENT_TIMESTAMP
            """,
            str(binding_id),
            str(remote_contact_id),
            signature,
        )

    async def delete_signature(
        self, binding_id: BindingId, remote_contact_id: RemoteObjectId
    ) -> None:
        await self._pool.execute(
            """
            DELETE FROM roster_sync_records
            WHERE binding_id = $1 AND remote_contact_id = $2
            """,
            str(binding_id),
            str(remote_contact_id),
        )
