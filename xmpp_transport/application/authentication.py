"""Provider-neutral orchestration for short-lived authentication flows."""

import asyncio
import logging
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, Optional, Protocol

from xmpp_transport.domain.auth import AuthChallenge, AuthResponse, AuthResponseKind, AuthState
from xmpp_transport.domain.errors import InvalidCommand
from xmpp_transport.domain.identifiers import BackendId, BindingId
from xmpp_transport.ports.backend import AuthenticationFlow, BackendPluginProvider
from xmpp_transport.ports.repositories import BindingRepository, CredentialCipher


log = logging.getLogger(__name__)
ChallengeHandler = Callable[[BindingId, AuthChallenge], Awaitable[None]]


class SessionStarter(Protocol):
    async def start(self, binding_id: BindingId, backend_id: BackendId) -> object:
        ...

    async def stop(self, binding_id: BindingId) -> None:
        ...


@dataclass
class _ManagedFlow:
    backend_id: BackendId
    flow: AuthenticationFlow


class AuthenticationCoordinator:
    """Own auth flows and persist credentials only after successful completion."""

    def __init__(
        self,
        plugins: BackendPluginProvider,
        bindings: BindingRepository,
        cipher: CredentialCipher,
        sessions: SessionStarter,
        challenge_handler: Optional[ChallengeHandler] = None,
    ) -> None:
        self._plugins = plugins
        self._bindings = bindings
        self._cipher = cipher
        self._sessions = sessions
        self._challenge_handler = challenge_handler
        self._flows: Dict[BindingId, _ManagedFlow] = {}
        self._tasks: Dict[BindingId, asyncio.Task] = {}
        self._states: Dict[BindingId, AuthState] = {}
        self._locks: Dict[BindingId, asyncio.Lock] = {}
        self._state_lock = asyncio.Lock()
        self._closed = False

    async def begin(self, binding_id: BindingId, backend_id: BackendId) -> AuthChallenge:
        # A running provider wait may own the binding lock until QR completion.
        # Cancel it first so a repeated /login replaces the attempt immediately.
        await self._cancel_task(binding_id)
        lock = await self._lock_for(binding_id)
        async with lock:
            self._ensure_open()
            previous = self._flows.pop(binding_id, None)
            if previous is not None:
                await previous.flow.close()
            flow = self._plugins.get(backend_id).create_authentication(binding_id)
            self._flows[binding_id] = _ManagedFlow(backend_id, flow)
            try:
                challenge = await flow.start()
            except BaseException:
                self._flows.pop(binding_id, None)
                await flow.close()
                raise
            if challenge.state is AuthState.WAITING_QR:
                task = asyncio.create_task(
                    self._continue_automatically(binding_id, backend_id)
                )
                self._tasks[binding_id] = task
            self._states[binding_id] = challenge.state
            return challenge

    async def respond(
        self,
        binding_id: BindingId,
        backend_id: BackendId,
        response: AuthResponse,
    ) -> AuthChallenge:
        log.debug(
            "Authentication response received backend_id=%s binding_id=%s kind=%s state=%s",
            backend_id, binding_id, response.kind.value,
            self._states.get(binding_id).value if binding_id in self._states else "missing",
        )
        lock = await self._lock_for(binding_id)
        async with lock:
            log.debug(
                "Authentication response lock acquired backend_id=%s binding_id=%s kind=%s",
                backend_id, binding_id, response.kind.value,
            )
            self._ensure_open()
            managed = self._flows.get(binding_id)
            if managed is None:
                raise InvalidCommand("authentication flow is not active")
            if managed.backend_id != backend_id:
                raise InvalidCommand("authentication flow belongs to another backend")
            flow = managed.flow
            challenge = await flow.respond(response)
            log.debug(
                "Authentication response completed backend_id=%s binding_id=%s state=%s",
                backend_id, binding_id, challenge.state.value,
            )
            self._states[binding_id] = challenge.state
            if challenge.state is AuthState.CONNECTED:
                plaintext = flow.credentials()
                encrypted = self._cipher.encrypt(plaintext)
                await self._bindings.save_encrypted_credentials(
                    binding_id, backend_id, encrypted
                )
                await self._sessions.stop(binding_id)
                await self._sessions.start(binding_id, backend_id)
                self._flows.pop(binding_id, None)
                self._states.pop(binding_id, None)
                await flow.close()
            elif challenge.state in (AuthState.EXPIRED, AuthState.FAILED):
                self._flows.pop(binding_id, None)
                self._states.pop(binding_id, None)
                await flow.close()
            return challenge

    async def cancel(self, binding_id: BindingId) -> None:
        await self._cancel_task(binding_id)
        lock = await self._lock_for(binding_id)
        async with lock:
            flow = self._flows.pop(binding_id, None)
            if flow is not None:
                await flow.flow.close()
            self._states.pop(binding_id, None)

    def state(self, binding_id: BindingId) -> Optional[AuthState]:
        return self._states.get(binding_id)

    async def close(self) -> None:
        async with self._state_lock:
            if self._closed:
                return
            self._closed = True
            tasks = tuple(self._tasks.values())
            self._tasks.clear()
            flows = tuple(managed.flow for managed in self._flows.values())
            self._flows.clear()
            self._states.clear()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.gather(*(flow.close() for flow in flows), return_exceptions=True)

    async def _continue_automatically(
        self, binding_id: BindingId, backend_id: BackendId
    ) -> None:
        try:
            try:
                challenge = await self.respond(
                    binding_id,
                    backend_id,
                    AuthResponse(AuthResponseKind.CONFIRMATION, "provider-confirmation"),
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.error(
                    "Automatic authentication continuation failed backend_id=%s "
                    "binding_id=%s exception_type=%s",
                    backend_id,
                    binding_id,
                    type(exc).__name__,
                )
                challenge = AuthChallenge(
                    AuthState.FAILED,
                    message="Авторизация завершилась с ошибкой. Повторите /login.",
                )
            await self._deliver_challenge(binding_id, backend_id, challenge)
        finally:
            current = asyncio.current_task()
            if self._tasks.get(binding_id) is current:
                self._tasks.pop(binding_id, None)

    async def _deliver_challenge(
        self,
        binding_id: BindingId,
        backend_id: BackendId,
        challenge: AuthChallenge,
    ) -> None:
        if self._challenge_handler is None:
            return
        try:
            await self._challenge_handler(binding_id, challenge)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Authentication state and credentials are already committed here.
            # A notification failure must not turn a successful login into a
            # failed flow or escape from this background task.
            log.error(
                "Authentication notification failed backend_id=%s binding_id=%s "
                "state=%s exception_type=%s",
                backend_id,
                binding_id,
                challenge.state.value,
                type(exc).__name__,
            )

    async def _cancel_task(self, binding_id: BindingId) -> None:
        task = self._tasks.pop(binding_id, None)
        if task is None or task is asyncio.current_task():
            return
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def _lock_for(self, binding_id: BindingId) -> asyncio.Lock:
        async with self._state_lock:
            lock = self._locks.get(binding_id)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[binding_id] = lock
            return lock

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("authentication coordinator is closed")
