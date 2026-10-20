"""Provider-neutral inbound and outbound direct-message routing."""

import asyncio
import re
from contextlib import asynccontextmanager
from dataclasses import replace
from typing import AsyncIterator, Dict, Hashable, Tuple

from xmpp_transport.domain.errors import FeatureUnavailable
from xmpp_transport.domain.events import MessageReceived
from xmpp_transport.domain.identifiers import BindingId, RemoteObjectId
from xmpp_transport.domain.models import MessageButton, OutgoingMessage
from xmpp_transport.ports.backend import (
    BackendFeatureProvider,
    ButtonActions,
    MessageSender,
    SendResult,
)
from xmpp_transport.ports.repositories import MessageMappingRepository
from xmpp_transport.ports.xmpp import XmppMessageSink


class _KeyedLocks:
    """Serialize duplicate operations without retaining every message key forever."""

    def __init__(self) -> None:
        self._guard = asyncio.Lock()
        self._entries: Dict[Hashable, Tuple[asyncio.Lock, int]] = {}

    @asynccontextmanager
    async def hold(self, key: Hashable) -> AsyncIterator[None]:
        async with self._guard:
            lock, users = self._entries.get(key, (asyncio.Lock(), 0))
            self._entries[key] = (lock, users + 1)
        await lock.acquire()
        try:
            yield
        finally:
            lock.release()
            async with self._guard:
                current_lock, users = self._entries[key]
                if users == 1:
                    del self._entries[key]
                else:
                    self._entries[key] = (current_lock, users - 1)


class MessageRouter:
    BUTTON_COMMAND_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")

    def __init__(
        self,
        features: BackendFeatureProvider,
        mappings: MessageMappingRepository,
        xmpp: XmppMessageSink,
    ) -> None:
        self._features = features
        self._mappings = mappings
        self._xmpp = xmpp
        self._locks = _KeyedLocks()
        self._buttons: Dict[Tuple[BindingId, RemoteObjectId, str], MessageButton] = {}

    async def send(self, message: OutgoingMessage) -> SendResult:
        """Send once per binding/client ID and persist the provider mapping."""
        key = ("out", message.binding_id, message.client_message_id)
        async with self._locks.hold(key):
            existing = await self._mappings.remote_id_for_client_message(
                message.binding_id, message.client_message_id
            )
            if existing is not None:
                return SendResult(existing)

            sender = await self._features.feature(message.binding_id, MessageSender)
            if sender is None:
                raise FeatureUnavailable(
                    "active binding does not provide message sending: {}".format(
                        message.binding_id
                    )
                )
            message = await self._resolve_forward_source(message)
            result = await sender.send_message(message)
            await self._mappings.save_mapping(
                message.binding_id,
                message.client_message_id,
                result.remote_message_id,
            )
            return result

    async def _resolve_forward_source(self, message: OutgoingMessage) -> OutgoingMessage:
        reference = message.forwarded_from
        if reference is None or not reference.is_self:
            return message
        candidates = reference.source_message_ids or (
            (reference.source_message_id,) if reference.source_message_id is not None else ()
        )
        for candidate in candidates:
            remote_id = await self._mappings.remote_id_for_client_message(
                message.binding_id, str(candidate)
            )
            if remote_id is not None:
                return replace(
                    message,
                    forwarded_from=replace(reference, source_message_id=remote_id),
                )
        return message

    async def receive(self, event: MessageReceived) -> bool:
        """Deliver a remote message once; return False for an acknowledged duplicate."""
        message = event.message
        self._validate_envelope(event)
        key = ("in", message.binding_id, message.id)
        async with self._locks.hold(key):
            if await self._mappings.incoming_delivered(message.binding_id, message.id):
                return False
            await self._xmpp.deliver_message(message)
            self._remember_buttons(message)
            await self._mappings.mark_incoming_delivered(message.binding_id, message.id)
            return True

    async def activate_button(
        self,
        binding_id: BindingId,
        conversation_id: RemoteObjectId,
        value: str,
    ) -> bool:
        normalized = value.strip()
        button = self._buttons.get((binding_id, conversation_id, normalized))
        if button is None and normalized.startswith("/"):
            command = normalized[1:].split(maxsplit=1)[0].strip()
            button = self._buttons.get((binding_id, conversation_id, command))
        if button is None:
            return False
        if not button.callback_id:
            raise FeatureUnavailable(
                "MAX button callback identifier is unavailable"
            )
        actions = await self._features.feature(binding_id, ButtonActions)
        if actions is None:
            raise FeatureUnavailable("active binding does not provide button actions")
        await actions.activate_button(
            conversation_id,
            button.callback_id,
            button.payload,
            button.kind,
        )
        return True

    def _remember_buttons(self, message) -> None:  # type: ignore[no-untyped-def]
        if not message.buttons or message.attributes.get("is_group") == "true":
            return
        prefix = (message.binding_id, message.conversation_id)
        for key in [key for key in self._buttons if key[:2] == prefix]:
            self._buttons.pop(key, None)
        for row_index, row in enumerate(message.buttons):
            for button_index, button in enumerate(row):
                payload = button.payload.strip()
                if not payload:
                    continue
                command = self._button_command(button, row_index, button_index)
                self._buttons[(prefix[0], prefix[1], command)] = button
                self._buttons[(prefix[0], prefix[1], payload)] = button

    @classmethod
    def _button_command(
        cls, button: MessageButton, row_index: int, button_index: int
    ) -> str:
        payload = button.payload.strip()
        if cls.BUTTON_COMMAND_RE.fullmatch(payload):
            return payload
        return "button_{}_{}".format(row_index + 1, button_index + 1)

    @staticmethod
    def _validate_envelope(event: MessageReceived) -> None:
        if event.envelope.binding_id != event.message.binding_id:
            raise ValueError("message binding does not match event envelope")
