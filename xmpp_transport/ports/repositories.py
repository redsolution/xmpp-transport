from dataclasses import dataclass
from typing import Callable, Optional, Protocol, Sequence

from xmpp_transport.domain.identifiers import BackendId, BindingId, RemoteObjectId


@dataclass(frozen=True)
class BindingRecord:
    binding_id: BindingId
    backend_id: BackendId


class BindingRepository(Protocol):
    async def ensure_binding(
        self, bare_jid: str, backend_id: BackendId
    ) -> BindingRecord:
        ...

    async def active_bindings(self) -> Sequence[BindingRecord]:
        ...

    async def encrypted_credentials(self, binding_id: BindingId) -> Optional[bytes]:
        ...

    async def binding_for_xmpp_account(
        self, bare_jid: str, backend_id: BackendId
    ) -> Optional[BindingRecord]:
        ...

    async def binding_for_authentication(
        self, bare_jid: str, backend_id: BackendId
    ) -> Optional[BindingRecord]:
        ...

    async def xmpp_account_for_binding(self, binding_id: BindingId) -> Optional[str]:
        ...

    async def xmpp_account_for_authentication(
        self, binding_id: BindingId
    ) -> Optional[str]:
        ...

    async def save_encrypted_credentials(
        self, binding_id: BindingId, backend_id: BackendId, credentials: bytes
    ) -> None:
        ...

    async def save_exclusive_credentials(
        self,
        binding_id: BindingId,
        backend_id: BackendId,
        credentials: bytes,
        remote_account_key: bytes,
        matches_legacy: Callable[[bytes], bool],
    ) -> Sequence[BindingId]:
        """Atomically transfer account ownership and return displaced bindings."""
        ...

    async def disable_binding(self, binding_id: BindingId) -> None:
        ...

    async def mark_authorization_lost(self, binding_id: BindingId) -> None:
        ...


class CredentialCipher(Protocol):
    def decrypt(self, encrypted: bytes) -> bytes:
        """Decrypt an opaque credential payload without logging either value."""
        ...

    def encrypt(self, plaintext: bytes) -> bytes:
        ...

    def remote_account_key(self, backend_id: BackendId, account_id: str) -> bytes:
        """Derive a stable keyed digest without storing a public account ID."""
        ...


class MessageMappingRepository(Protocol):
    async def remote_id_for_client_message(
        self, binding_id: BindingId, client_message_id: str
    ) -> Optional[RemoteObjectId]:
        ...

    async def save_mapping(
        self,
        binding_id: BindingId,
        client_message_id: str,
        remote_message_id: RemoteObjectId,
    ) -> None:
        ...

    async def incoming_delivered(
        self, binding_id: BindingId, remote_message_id: RemoteObjectId
    ) -> bool:
        ...

    async def mark_incoming_delivered(
        self, binding_id: BindingId, remote_message_id: RemoteObjectId
    ) -> None:
        ...


class RosterSyncRepository(Protocol):
    async def signature(
        self, binding_id: BindingId, remote_contact_id: RemoteObjectId
    ) -> Optional[str]:
        ...

    async def save_signature(
        self,
        binding_id: BindingId,
        remote_contact_id: RemoteObjectId,
        signature: str,
    ) -> None:
        ...

    async def delete_signature(
        self, binding_id: BindingId, remote_contact_id: RemoteObjectId
    ) -> None:
        ...
