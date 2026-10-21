"""Own backend-session lifecycle without depending on concrete providers."""

import asyncio
import logging
import socket
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Type, TypeVar, cast

from xmpp_transport.domain.errors import AuthorizationRequired, TransportError
from xmpp_transport.domain.identifiers import BackendId, BindingId
from xmpp_transport.ports.backend import BackendPluginProvider, BackendSession
from xmpp_transport.ports.events import BackendEventSink
from xmpp_transport.ports.repositories import BindingRepository, CredentialCipher


FeatureT = TypeVar("FeatureT")
log = logging.getLogger(__name__)


@dataclass(frozen=True)
class LifecycleFailure:
    binding_id: BindingId
    operation: str
    exception_type: str


class SessionLifecycleError(TransportError):
    def __init__(self, failures: Tuple[LifecycleFailure, ...]) -> None:
        self.failures = failures
        details = ", ".join(
            "binding_id={} operation={} exception_type={}".format(
                failure.binding_id, failure.operation, failure.exception_type
            )
            for failure in failures
        )
        super().__init__(
            "{} session lifecycle operation(s) failed: {}".format(len(failures), details)
        )


@dataclass
class _ManagedSession:
    backend_id: BackendId
    session: BackendSession


class SessionSupervisor:
    """Starts each binding at most once and owns every created session."""

    def __init__(
        self,
        registry: BackendPluginProvider,
        bindings: BindingRepository,
        credential_cipher: CredentialCipher,
        event_sink: BackendEventSink,
        restore_retry_delay: float = 5.0,
    ) -> None:
        self._registry = registry
        self._bindings = bindings
        self._credential_cipher = credential_cipher
        self._event_sink = event_sink
        self._sessions: Dict[BindingId, _ManagedSession] = {}
        self._binding_locks: Dict[BindingId, asyncio.Lock] = {}
        self._state_lock = asyncio.Lock()
        self._closed = False
        self._restore_retry_delay = restore_retry_delay
        self._restore_retries: Dict[BindingId, asyncio.Task[None]] = {}

    async def start(self, binding_id: BindingId, backend_id: BackendId) -> BackendSession:
        lock = await self._lock_for(binding_id)
        async with lock:
            async with self._state_lock:
                if self._closed:
                    raise RuntimeError("session supervisor is closed")
                current = self._sessions.get(binding_id)
                if current is not None:
                    if current.backend_id != backend_id:
                        raise ValueError(
                            "binding {} is already owned by backend {}".format(
                                binding_id, current.backend_id
                            )
                        )
                    return current.session

            encrypted = await self._bindings.encrypted_credentials(binding_id)
            if encrypted is None:
                raise AuthorizationRequired(
                    "binding {} has no stored credentials".format(binding_id)
                )
            credentials = self._credential_cipher.decrypt(encrypted)
            plugin = self._registry.get(backend_id)
            session = plugin.create_session(binding_id, credentials, self._event_sink)

            try:
                await session.start()
            except asyncio.CancelledError:
                await self._close_after_failed_start(session)
                raise
            except Exception as exc:
                await self._close_after_failed_start(session)
                raise SessionLifecycleError(
                    (LifecycleFailure(binding_id, "start", _root_exception_type(exc)),)
                ) from exc

            async with self._state_lock:
                # close() cannot pass this binding's lock while start() is active.
                if self._closed:
                    await session.close()
                    raise RuntimeError("session supervisor is closed")
                self._sessions[binding_id] = _ManagedSession(backend_id, session)
            return session

    async def stop(self, binding_id: BindingId) -> None:
        retry = self._restore_retries.pop(binding_id, None)
        if retry is not None and retry is not asyncio.current_task():
            retry.cancel()
            await asyncio.gather(retry, return_exceptions=True)
        lock = await self._lock_for(binding_id)
        async with lock:
            async with self._state_lock:
                managed = self._sessions.pop(binding_id, None)
            if managed is None:
                return
            try:
                await managed.session.close()
            except Exception as exc:
                raise SessionLifecycleError(
                    (LifecycleFailure(binding_id, "stop", type(exc).__name__),)
                ) from exc

    async def feature(
        self, binding_id: BindingId, feature_type: Type[FeatureT]
    ) -> Optional[FeatureT]:
        """Resolve an optional feature from a currently active session."""
        async with self._state_lock:
            managed = self._sessions.get(binding_id)
            if managed is None:
                return None
            feature = managed.session.features().get(feature_type)
        return cast(Optional[FeatureT], feature)

    async def restore(self) -> None:
        """Restore bindings independently so one MAX account cannot block the process."""
        records = await self._bindings.active_bindings()
        results = await asyncio.gather(
            *(self.start(record.binding_id, record.backend_id) for record in records),
            return_exceptions=True,
        )
        failures: List[LifecycleFailure] = []
        for record, result in zip(records, results):
            if isinstance(result, BaseException):
                if isinstance(result, asyncio.CancelledError):
                    raise result
                root = _root_exception(result)
                if record.backend_id == BackendId("max") and isinstance(
                    result, AuthorizationRequired
                ):
                    await self._bindings.mark_authorization_lost(record.binding_id)
                    log.warning(
                        "MAX session has no usable credentials binding_id=%s; "
                        "send /login to authorize again",
                        record.binding_id,
                    )
                    continue
                if record.backend_id == BackendId("max") and isinstance(
                    root, AuthorizationRequired
                ) and getattr(root, "terminal", False):
                    await self._bindings.mark_authorization_lost(record.binding_id)
                    log.warning(
                        "MAX session needs renewed authorization binding_id=%s; "
                        "send /login to authorize again",
                        record.binding_id,
                    )
                    continue
                if record.backend_id == BackendId("max") and isinstance(
                    root, (socket.gaierror, AuthorizationRequired)
                ):
                    if record.binding_id not in self._restore_retries and not self._closed:
                        self._restore_retries[record.binding_id] = asyncio.create_task(
                            self._retry_restore(record.binding_id, record.backend_id),
                            name="max-session-restore-retry",
                        )
                    log.warning(
                        "MAX session restore deferred binding_id=%s exception_type=%s",
                        record.binding_id, type(root).__name__,
                    )
                    continue
                if record.backend_id == BackendId("max"):
                    # Keep the binding active for the next process start, as the old
                    # transport did for sessions with a non-authentication error.
                    # Exception text may contain provider data, so log metadata only.
                    log.error(
                        "MAX session restore failed binding_id=%s exception_type=%s",
                        record.binding_id, _root_exception_type(result),
                    )
                    continue
                if isinstance(result, SessionLifecycleError):
                    failures.extend(result.failures)
                else:
                    failures.append(
                        LifecycleFailure(
                            record.binding_id,
                            "restore",
                            _root_exception_type(result),
                        )
                    )
        if failures:
            raise SessionLifecycleError(tuple(failures))

    async def _retry_restore(self, binding_id: BindingId, backend_id: BackendId) -> None:
        delay = self._restore_retry_delay
        try:
            while not self._closed:
                await asyncio.sleep(delay)
                if self._closed:
                    return
                try:
                    await self.start(binding_id, backend_id)
                except SessionLifecycleError as exc:
                    root = _root_exception(exc)
                    if isinstance(root, AuthorizationRequired) and getattr(
                        root, "terminal", False
                    ):
                        await self._bindings.mark_authorization_lost(binding_id)
                        log.warning(
                            "MAX session needs renewed authorization binding_id=%s; "
                            "send /login to authorize again",
                            binding_id,
                        )
                        return
                    if not isinstance(root, (socket.gaierror, AuthorizationRequired)):
                        log.error(
                            "MAX session restore retry stopped binding_id=%s exception_type=%s",
                            binding_id, exc.failures[0].exception_type,
                        )
                        return
                    log.warning(
                        "MAX session restore retry deferred binding_id=%s exception_type=%s",
                        binding_id, type(root).__name__,
                    )
                    delay = min(delay * 2, 60.0)
                except Exception as exc:
                    log.error(
                        "MAX session restore retry stopped binding_id=%s exception_type=%s",
                        binding_id, _root_exception_type(exc),
                    )
                    return
                else:
                    log.info("MAX session restored binding_id=%s", binding_id)
                    return
        finally:
            if self._restore_retries.get(binding_id) is asyncio.current_task():
                self._restore_retries.pop(binding_id, None)

    async def close(self) -> None:
        async with self._state_lock:
            if self._closed:
                return
            self._closed = True
            binding_ids = tuple(self._sessions)

        retries = tuple(self._restore_retries.values())
        for retry in retries:
            retry.cancel()
        if retries:
            await asyncio.gather(*retries, return_exceptions=True)
        self._restore_retries.clear()

        results = await asyncio.gather(
            *(self._stop_during_close(binding_id) for binding_id in binding_ids),
            return_exceptions=True,
        )
        failures = tuple(
            failure
            for result in results
            if isinstance(result, SessionLifecycleError)
            for failure in result.failures
        )
        if failures:
            raise SessionLifecycleError(failures)

    async def __aenter__(self) -> "SessionSupervisor":
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        await self.close()

    async def _lock_for(self, binding_id: BindingId) -> asyncio.Lock:
        async with self._state_lock:
            lock = self._binding_locks.get(binding_id)
            if lock is None:
                lock = asyncio.Lock()
                self._binding_locks[binding_id] = lock
            return lock

    async def _stop_during_close(self, binding_id: BindingId) -> None:
        lock = await self._lock_for(binding_id)
        async with lock:
            async with self._state_lock:
                managed = self._sessions.pop(binding_id, None)
            if managed is None:
                return
            try:
                await managed.session.close()
            except Exception as exc:
                raise SessionLifecycleError(
                    (LifecycleFailure(binding_id, "close", type(exc).__name__),)
                ) from exc

    @staticmethod
    async def _close_after_failed_start(session: BackendSession) -> None:
        try:
            await session.close()
        except Exception:
            # The start failure is primary; both errors must avoid secret-bearing text.
            pass


def _root_exception_type(exc: BaseException) -> str:
    """Expose only the type of the original failure, never its possibly private text."""
    return type(_root_exception(exc)).__name__


def _root_exception(exc: BaseException) -> BaseException:
    seen = set()
    current = exc
    while current.__cause__ is not None and id(current.__cause__) not in seen:
        seen.add(id(current))
        current = current.__cause__
    return current
