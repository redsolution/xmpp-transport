import asyncio
import socket
import unittest
from typing import Dict, List, Optional, Sequence

from xmpp_transport.application.session_supervisor import (
    SessionLifecycleError,
    SessionSupervisor,
    _root_exception_type,
)
from xmpp_transport.domain.errors import AuthorizationRequired
from xmpp_transport.domain.identifiers import BackendId, BindingId
from xmpp_transport.ports.repositories import BindingRecord
from xmpp_transport.runtime.registry import BackendRegistry
from xmpp_transport.testing.fakes import RecordingEventSink


class IdentityCipher:
    def decrypt(self, encrypted: bytes) -> bytes:
        return encrypted

    def encrypt(self, plaintext: bytes) -> bytes:
        return plaintext


class FakeBindingRepository:
    def __init__(self) -> None:
        self.records: List[BindingRecord] = []
        self.credentials: Dict[BindingId, bytes] = {}

    async def active_bindings(self) -> Sequence[BindingRecord]:
        return tuple(self.records)

    async def encrypted_credentials(self, binding_id: BindingId) -> Optional[bytes]:
        return self.credentials.get(binding_id)

    async def save_encrypted_credentials(
        self, binding_id: BindingId, backend_id: BackendId, credentials: bytes
    ) -> None:
        self.credentials[binding_id] = credentials


class FakeSession:
    def __init__(
        self, binding_id: BindingId, fail_start: bool = False,
        start_error: Optional[Exception] = None,
        success_event: Optional[asyncio.Event] = None,
    ) -> None:
        self._binding_id = binding_id
        self.fail_start = fail_start
        self.start_error = start_error
        self.success_event = success_event
        self.started = 0
        self.closed = 0

    @property
    def binding_id(self) -> BindingId:
        return self._binding_id

    async def start(self) -> None:
        self.started += 1
        await asyncio.sleep(0)
        if self.fail_start:
            raise ConnectionError("provider details")
        if self.start_error is not None:
            raise self.start_error
        if self.success_event is not None:
            self.success_event.set()

    async def close(self) -> None:
        self.closed += 1

    def features(self):  # type: ignore[no-untyped-def]
        return {}


class FakePlugin:
    def __init__(self, backend_id: BackendId = BackendId("fake")) -> None:
        self.backend_id = backend_id
        self.created: List[FakeSession] = []
        self.fail_start = False
        self.start_errors: List[Exception] = []
        self.success_event = asyncio.Event()

    def create_session(self, binding_id, credentials, event_sink):  # type: ignore[no-untyped-def]
        error = self.start_errors.pop(0) if self.start_errors else None
        session = FakeSession(binding_id, self.fail_start, error, self.success_event)
        self.created.append(session)
        return session

    def create_authentication(self, binding_id):  # type: ignore[no-untyped-def]
        raise NotImplementedError


class SessionSupervisorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.binding_id = BindingId("binding-1")
        self.repository = FakeBindingRepository()
        self.repository.credentials[self.binding_id] = b"encrypted"
        self.plugin = FakePlugin()
        self.supervisor = SessionSupervisor(
            BackendRegistry([self.plugin]),  # type: ignore[list-item]
            self.repository,
            IdentityCipher(),
            RecordingEventSink(),
        )

    async def test_concurrent_start_is_idempotent(self) -> None:
        first, second = await asyncio.gather(
            self.supervisor.start(self.binding_id, self.plugin.backend_id),
            self.supervisor.start(self.binding_id, self.plugin.backend_id),
        )
        self.assertIs(first, second)
        self.assertEqual(1, len(self.plugin.created))
        self.assertEqual(1, self.plugin.created[0].started)
        await self.supervisor.close()

    async def test_stop_is_idempotent(self) -> None:
        session = await self.supervisor.start(self.binding_id, self.plugin.backend_id)
        await self.supervisor.stop(self.binding_id)
        await self.supervisor.stop(self.binding_id)
        self.assertEqual(1, session.closed)

    async def test_missing_credentials_requires_authorization(self) -> None:
        missing = BindingId("missing")
        with self.assertRaises(AuthorizationRequired):
            await self.supervisor.start(missing, self.plugin.backend_id)

    async def test_failed_start_closes_partial_session_and_redacts_error(self) -> None:
        self.plugin.fail_start = True
        with self.assertRaises(SessionLifecycleError) as context:
            await self.supervisor.start(self.binding_id, self.plugin.backend_id)
        self.assertEqual(1, self.plugin.created[0].closed)
        self.assertEqual("ConnectionError", context.exception.failures[0].exception_type)
        self.assertIn("binding_id=binding-1", str(context.exception))
        self.assertIn("exception_type=ConnectionError", str(context.exception))
        self.assertNotIn("provider details", str(context.exception))

    def test_root_exception_type_uses_original_failure_without_its_text(self) -> None:
        try:
            raise TimeoutError("private provider response")
        except TimeoutError as cause:
            try:
                raise RuntimeError("wrapped provider response") from cause
            except RuntimeError as wrapped:
                self.assertEqual("TimeoutError", _root_exception_type(wrapped))

    async def test_restore_starts_all_active_bindings(self) -> None:
        second = BindingId("binding-2")
        self.repository.credentials[second] = b"encrypted-2"
        self.repository.records = [
            BindingRecord(self.binding_id, self.plugin.backend_id),
            BindingRecord(second, self.plugin.backend_id),
        ]
        await self.supervisor.restore()
        self.assertEqual(2, len(self.plugin.created))
        await self.supervisor.close()

    async def test_max_dns_failure_retries_without_stopping_restore(self) -> None:
        self.plugin = FakePlugin(BackendId("max"))
        self.plugin.start_errors = [
            socket.gaierror("temporary DNS failure"),
            socket.gaierror("temporary DNS failure again"),
        ]
        self.supervisor = SessionSupervisor(
            BackendRegistry([self.plugin]),  # type: ignore[list-item]
            self.repository, IdentityCipher(), RecordingEventSink(),
            restore_retry_delay=0.01,
        )
        self.repository.records = [BindingRecord(self.binding_id, self.plugin.backend_id)]

        await self.supervisor.restore()
        await asyncio.wait_for(self.plugin.success_event.wait(), timeout=1)

        self.assertEqual(3, len(self.plugin.created))
        self.assertEqual(1, self.plugin.created[0].closed)
        self.assertEqual(1, self.plugin.created[1].closed)
        await self.supervisor.close()
        self.assertEqual(1, self.plugin.created[2].closed)

    async def test_max_non_dns_failure_still_fails_restore(self) -> None:
        self.plugin = FakePlugin(BackendId("max"))
        self.plugin.start_errors = [PermissionError("authorization rejected")]
        self.supervisor = SessionSupervisor(
            BackendRegistry([self.plugin]),  # type: ignore[list-item]
            self.repository, IdentityCipher(), RecordingEventSink(),
            restore_retry_delay=0.01,
        )
        self.repository.records = [BindingRecord(self.binding_id, self.plugin.backend_id)]

        with self.assertRaises(SessionLifecycleError) as context:
            await self.supervisor.restore()
        self.assertEqual("PermissionError", context.exception.failures[0].exception_type)
        self.assertEqual(1, len(self.plugin.created))
        await self.supervisor.close()

    async def test_stop_cancels_pending_max_dns_retry(self) -> None:
        self.plugin = FakePlugin(BackendId("max"))
        self.plugin.start_errors = [socket.gaierror("temporary DNS failure")]
        self.supervisor = SessionSupervisor(
            BackendRegistry([self.plugin]),  # type: ignore[list-item]
            self.repository, IdentityCipher(), RecordingEventSink(),
            restore_retry_delay=60,
        )
        self.repository.records = [BindingRecord(self.binding_id, self.plugin.backend_id)]

        await self.supervisor.restore()
        await self.supervisor.stop(self.binding_id)

        self.assertEqual(1, len(self.plugin.created))
        self.assertFalse(self.supervisor._restore_retries)
        await self.supervisor.close()

    async def test_close_rejects_new_sessions(self) -> None:
        await self.supervisor.close()
        with self.assertRaises(RuntimeError):
            await self.supervisor.start(self.binding_id, self.plugin.backend_id)


if __name__ == "__main__":
    unittest.main()
