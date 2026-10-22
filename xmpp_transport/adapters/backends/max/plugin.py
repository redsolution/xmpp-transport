"""MAX plugin boundary for the shared transport runtime.

The network client is intentionally introduced behind this boundary so MAX
wire details do not leak into the application and domain packages.
"""

import hashlib
import json
import logging
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Mapping, Optional, Protocol, Sequence, Tuple, Type
from uuid import uuid4

from xmpp_transport.domain.auth import AuthChallenge, AuthResponse, AuthState
from xmpp_transport.domain.errors import BackendUnavailable, InvalidCommand
from xmpp_transport.domain.events import (
    AuthorizationLost,
    ContactChanged,
    ConversationChanged,
    EventEnvelope,
    MessageReceived,
    SessionState,
    SessionStateChanged,
)
from xmpp_transport.domain.identifiers import BackendId, BindingId, EventId, RemoteObjectId
from xmpp_transport.domain.models import (
    Avatar,
    Contact,
    Conversation,
    ConversationKind,
    ForwardReference,
    IncomingMessage,
    MessageButton,
    Media,
    MediaKind,
    OutgoingMessage,
    Participant,
    ReplyReference,
)
from xmpp_transport.ports.backend import (
    ButtonActions,
    ContactAdder,
    ContactSource,
    MessageSender,
    SendResult,
)
from xmpp_transport.ports.events import BackendEventSink

from .models import (
    MaxAuthorizationError,
    MaxChat,
    MaxContact,
    MaxForwardReference,
    MaxIncomingMessage,
    MaxMedia,
)


log = logging.getLogger(__name__)


class MaxClient(Protocol):
    def set_message_handler(self, handler: Callable[[MaxIncomingMessage], object]) -> None:
        ...

    def set_authorization_lost_handler(
        self, handler: Callable[[MaxAuthorizationError], object]
    ) -> None:
        ...

    def set_chat_handler(self, handler: Callable[[MaxChat], object]) -> None:
        ...

    async def start(self) -> None:
        ...

    async def close(self) -> None:
        ...

    async def send_message(
        self,
        text: str,
        chat_id: Optional[str] = None,
        reply_to_message_id: Optional[str] = None,
        media: tuple[object, ...] = (),
        forward_reference: Optional[MaxForwardReference] = None,
    ) -> dict:
        ...

    async def list_contacts(self) -> list[MaxContact]:
        ...

    async def add_contact_by_phone(self, phone: str) -> MaxContact:
        ...

    async def send_button_callback(
        self,
        *,
        chat_id: str,
        callback_id: str,
        payload: str,
        button_type: str = "CALLBACK",
    ) -> dict:
        ...


MaxClientFactory = Callable[["MaxCredentials"], MaxClient]


class MaxQrClient(Protocol):
    async def start(self):  # type: ignore[no-untyped-def]
        ...

    async def wait_for_credentials(self) -> Tuple[str, str, str]:
        ...

    async def submit_password(self, password: str) -> Tuple[str, str, str]:
        ...

    async def close(self) -> None:
        ...


@dataclass(frozen=True)
class MaxCredentials:
    token: str
    device_id: str
    account_id: str

    @classmethod
    def decode(cls, payload: bytes) -> "MaxCredentials":
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("MAX credentials must be a UTF-8 JSON object") from exc
        if not isinstance(value, dict):
            raise ValueError("MAX credentials must be a JSON object")
        fields = {}
        for name in ("token", "device_id", "account_id"):
            item = value.get(name)
            if not isinstance(item, str) or not item:
                raise ValueError("MAX credentials require a non-empty {}".format(name))
            fields[name] = item
        return cls(**fields)

    def encode(self) -> bytes:
        return json.dumps(
            {
                "token": self.token,
                "device_id": self.device_id,
                "account_id": self.account_id,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    def __repr__(self) -> str:
        return "MaxCredentials(token=<redacted>, device_id=<redacted>, account_id={!r})".format(
            self.account_id
        )


class MaxAuthenticationFlow:
    def __init__(
        self,
        client: MaxQrClient,
        password_required_error: Type[Exception],
        login_error: Type[Exception],
    ) -> None:
        self._client = client
        self._password_required_error = password_required_error
        self._login_error = login_error
        self._credentials: Optional[MaxCredentials] = None
        self._started = False
        self._closed = False

    async def start(self) -> AuthChallenge:
        if self._closed:
            raise RuntimeError("MAX authentication flow is closed")
        if self._started:
            raise InvalidCommand("MAX authentication flow is already started")
        self._started = True
        try:
            challenge = await self._client.start()
        except self._login_error as exc:
            return AuthChallenge(AuthState.FAILED, message=str(exc))
        return AuthChallenge(
            AuthState.WAITING_QR,
            expires_at=challenge.expires_at,
            public_url=challenge.qr_link,
            message="Scan the QR code with the MAX application",
        )

    async def respond(self, response: AuthResponse) -> AuthChallenge:
        if self._closed:
            raise RuntimeError("MAX authentication flow is closed")
        if not self._started:
            raise InvalidCommand("MAX authentication flow has not been started")
        try:
            if response.kind.value == "password":
                log.debug("MAX flow submitting password to API")
                values = await self._client.submit_password(response.secret)
            else:
                values = await self._client.wait_for_credentials()
        except self._password_required_error:
            log.debug("MAX flow entered waiting_password state")
            return AuthChallenge(
                AuthState.WAITING_PASSWORD,
                message="MAX requires a two-factor authentication password",
            )
        except self._login_error as exc:
            if response.kind.value == "password":
                log.warning("MAX password rejected exception_type=%s", type(exc).__name__)
                return AuthChallenge(
                    AuthState.WAITING_PASSWORD,
                    message="MAX password was not accepted",
                )
            return AuthChallenge(AuthState.FAILED, message=str(exc))
        token, device_id, account_id = values
        self._credentials = MaxCredentials(token, device_id, account_id)
        return AuthChallenge(AuthState.CONNECTED, message="MAX authorization completed")

    def credentials(self) -> bytes:
        if self._credentials is None:
            raise InvalidCommand("MAX authentication has not completed")
        return self._credentials.encode()

    def remote_account_id(self) -> str:
        if self._credentials is None:
            raise InvalidCommand("MAX authentication has not completed")
        return self._credentials.account_id

    def matches_account(self, credentials: bytes) -> bool:
        return MaxCredentials.decode(credentials).account_id == self.remote_account_id()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._client.close()


class MaxBackendSession:
    def __init__(
        self,
        binding_id: BindingId,
        credentials: MaxCredentials,
        event_sink: BackendEventSink,
        client_factory: MaxClientFactory,
        test_self_messages: bool = False,
    ) -> None:
        self._binding_id = binding_id
        self._credentials = credentials
        self._event_sink = event_sink
        self._client = client_factory(credentials)
        self._test_self_messages = test_self_messages
        self._group_chats = {}
        self._pending_group_echoes = set()
        self._sent_group_message_ids = set()
        self._group_reply_contexts: OrderedDict[tuple[str, str], ReplyReference] = OrderedDict()
        self._started = False
        self._closed = False

    @property
    def binding_id(self) -> BindingId:
        return self._binding_id

    async def start(self) -> None:
        if self._closed:
            raise BackendUnavailable("MAX backend session is closed")
        if self._started:
            return
        self._client.set_message_handler(self._receive_message)
        self._client.set_authorization_lost_handler(self._authorization_lost)
        self._client.set_chat_handler(self._receive_chat)
        await self._publish_state(SessionState.STARTING)
        try:
            await self._client.start()
        except Exception as exc:
            await self._publish_state(SessionState.FAILED, str(exc))
            raise BackendUnavailable("MAX session failed to start") from exc
        self._started = True
        await self._publish_state(SessionState.CONNECTED)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._started = False
        await self._client.close()
        await self._publish_state(SessionState.STOPPED)

    def features(self) -> Mapping[type, object]:
        return {
            MessageSender: self,
            ContactSource: self,
            ContactAdder: self,
            ButtonActions: self,
        }

    async def contacts(self) -> Sequence[Contact]:
        contacts = await self._client.list_contacts()
        return tuple(self._contact(item) for item in contacts)

    async def add_contact_by_phone(self, phone: str) -> Contact:
        if not self._started or self._closed:
            raise BackendUnavailable("MAX backend session is not active")
        return self._contact(await self._client.add_contact_by_phone(phone))

    async def activate_button(
        self,
        conversation_id: RemoteObjectId,
        callback_id: str,
        payload: str,
        button_type: str,
    ) -> None:
        if not self._started or self._closed:
            raise BackendUnavailable("MAX backend session is not active")
        try:
            await self._client.send_button_callback(
                chat_id=str(conversation_id),
                callback_id=callback_id,
                payload=payload,
                button_type=button_type,
            )
        except Exception as exc:
            raise BackendUnavailable("MAX button callback failed") from exc

    async def send_message(self, message: OutgoingMessage) -> SendResult:
        if not self._started or self._closed:
            raise BackendUnavailable("MAX backend session is not active")
        if message.binding_id != self._binding_id:
            raise InvalidCommand("message belongs to another binding")
        group_echo = None
        if message.attributes.get("is_group") == "true":
            group_echo = (str(message.conversation_id), message.text or "")
            self._pending_group_echoes.add(group_echo)
        try:
            forward_reference = self._max_forward_reference(message.forwarded_from)
            payload = await self._client.send_message(
                text=(message.text or "") if forward_reference is None else "",
                chat_id=str(message.conversation_id),
                reply_to_message_id=(
                    str(message.reply_to.message_id) if message.reply_to is not None else None
                ),
                media=tuple(message.media) if forward_reference is None else (),
                forward_reference=forward_reference,
            )
        except Exception as exc:
            if group_echo is not None:
                self._pending_group_echoes.discard(group_echo)
            raise BackendUnavailable("MAX message send failed") from exc
        response_message = payload.get("message") or {}
        remote_id = response_message.get("id")
        if remote_id is None:
            if group_echo is not None:
                self._pending_group_echoes.discard(group_echo)
            raise BackendUnavailable("MAX send response did not contain a message ID")
        if group_echo is not None:
            self._pending_group_echoes.discard(group_echo)
            self._sent_group_message_ids.add(str(remote_id))
            if len(self._sent_group_message_ids) > 2048:
                self._sent_group_message_ids.pop()
            self._remember_group_reply_context(
                str(message.conversation_id),
                ReplyReference(
                    RemoteObjectId(str(remote_id)),
                    body=message.text,
                    sender_id=RemoteObjectId(self._credentials.account_id),
                    is_self=True,
                    media=message.media,
                ),
            )
        return SendResult(RemoteObjectId(str(remote_id)))

    async def _receive_message(self, message: MaxIncomingMessage) -> None:
        if not message.chat_id or not message.message_id:
            return
        if message.is_self and message.is_group and (
            message.message_id in self._sent_group_message_ids
            or (message.chat_id, message.text) in self._pending_group_echoes
        ):
            self._sent_group_message_ids.discard(message.message_id)
            return
        if message.is_self and (
            not message.is_group or not self._test_self_messages
        ):
            return
        if message.is_group:
            chat = self._group_chats.get(message.chat_id)
            if chat is None:
                chat = MaxChat(
                    chat_id=message.chat_id,
                    title=message.chat_title
                    or "MAX group {}".format(message.chat_id),
                    is_group=True,
                    members=(),
                )
            await self._publish_group_conversation(chat)
        if message.is_group and not message.is_self:
            direct_chat_id = self._member_direct_chat_id(message.sender_id)
            if direct_chat_id is not None:
                await self._event_sink.publish(
                    ContactChanged(
                        envelope=self._envelope(ContactChanged.EVENT_TYPE),
                        contact=Contact(
                            id=RemoteObjectId(direct_chat_id),
                            display_name=message.sender_title
                            or "MAX user {}".format(message.sender_id),
                        ),
                    )
                )
        if message.is_group:
            reply = self._group_reply_reference(message)
        elif message.reply_to_message_id:
            reply = ReplyReference(RemoteObjectId(message.reply_to_message_id))
        else:
            reply = None
        if message.is_group:
            self._remember_group_reply_context(
                message.chat_id,
                ReplyReference(
                    RemoteObjectId(message.message_id),
                    body=message.text,
                    sender_id=RemoteObjectId(message.sender_id),
                    is_self=message.is_self,
                    media=tuple(self._media(item) for item in message.media),
                ),
            )
        forwarded_from = self._forward_reference(message)
        await self._event_sink.publish(
            MessageReceived(
                envelope=self._envelope(MessageReceived.EVENT_TYPE),
                message=IncomingMessage(
                    id=RemoteObjectId(message.message_id),
                    binding_id=self._binding_id,
                    conversation_id=RemoteObjectId(message.chat_id),
                    sender_id=RemoteObjectId(message.sender_id),
                    occurred_at=datetime.now(timezone.utc),
                    text=(
                        self._outer_text(message)
                        if forwarded_from is not None
                        else message.text or None
                    ),
                    reply_to=reply,
                    buttons=tuple(
                        tuple(
                            MessageButton(
                                text=button.text,
                                payload=button.payload,
                                callback_id=button.callback_id,
                                kind=button.kind,
                            )
                            for button in row
                        )
                        for row in message.buttons
                    ),
                    media=tuple(self._media(item) for item in message.media),
                    forwarded_from=forwarded_from,
                    attributes={
                        "is_group": "true" if message.is_group else "false",
                        "is_self": "true" if message.is_self else "false",
                        "sender_title": message.sender_title or "",
                        "chat_title": message.chat_title or "",
                        "owner_remote_id": self._credentials.account_id,
                    },
                ),
            )
        )

    def _forward_reference(self, message: MaxIncomingMessage) -> Optional[ForwardReference]:
        raw_message = (message.raw or {}).get("message") or {}
        link = raw_message.get("link") or {} if isinstance(raw_message, dict) else {}
        if not isinstance(link, dict) or str(link.get("type") or "").upper() != "FORWARD":
            return None
        linked = link.get("message") or {}
        if not isinstance(linked, dict) or linked.get("sender") is None:
            return None
        source_chat_id = link.get("chatId") or message.chat_id
        return ForwardReference(
            source_message_id=RemoteObjectId(str(linked.get("id") or message.message_id)),
            source_conversation_id=(
                RemoteObjectId(str(source_chat_id)) if source_chat_id is not None else None
            ),
            sender_id=RemoteObjectId(str(linked["sender"])),
            body=str(linked.get("text") or "").strip() or None,
            media=tuple(self._media(item) for item in message.media),
            is_self=str(linked["sender"]) == self._credentials.account_id,
        )

    def _group_reply_reference(self, message: MaxIncomingMessage) -> Optional[ReplyReference]:
        if not message.reply_to_message_id or not message.chat_id:
            return None
        message_id = RemoteObjectId(message.reply_to_message_id)
        context = self._group_reply_contexts.get((message.chat_id, message.reply_to_message_id))
        if context is not None:
            return context
        raw_message = (message.raw or {}).get("message") or {}
        link = raw_message.get("link") or {} if isinstance(raw_message, dict) else {}
        linked = link.get("message") or {} if isinstance(link, dict) else {}
        if isinstance(linked, dict) and linked.get("sender") is not None:
            sender_id = str(linked["sender"])
            return ReplyReference(
                message_id,
                body=str(linked.get("text") or "").strip() or None,
                sender_id=RemoteObjectId(sender_id),
                is_self=sender_id == self._credentials.account_id,
            )
        return ReplyReference(message_id)

    def _remember_group_reply_context(self, chat_id: str, reference: ReplyReference) -> None:
        key = (chat_id, str(reference.message_id))
        self._group_reply_contexts[key] = reference
        self._group_reply_contexts.move_to_end(key)
        if len(self._group_reply_contexts) > 2048:
            self._group_reply_contexts.popitem(last=False)

    @staticmethod
    def _outer_text(message: MaxIncomingMessage) -> Optional[str]:
        raw_message = (message.raw or {}).get("message") or {}
        if not isinstance(raw_message, dict):
            return None
        return str(raw_message.get("text") or "").strip() or None

    @staticmethod
    def _max_forward_reference(
        reference: Optional[ForwardReference],
    ) -> Optional[MaxForwardReference]:
        if reference is None or reference.source_message_id is None:
            return None
        for jid in (reference.source_name, reference.source_recipient):
            chat_id = MaxBackendSession._chat_id_from_forward_jid(jid or "")
            if chat_id is not None:
                return MaxForwardReference(chat_id, str(reference.source_message_id))
        return None

    @staticmethod
    def _chat_id_from_forward_jid(jid: str) -> Optional[str]:
        localpart = jid.split("@", 1)[0]
        if localpart.startswith("chat-"):
            return localpart[5:] or None
        if localpart.startswith("maxg-") and "-" in localpart[5:]:
            return localpart.rsplit("-", 1)[-1] or None
        return None

    async def _receive_chat(self, chat: MaxChat) -> None:
        if chat.is_group:
            self._group_chats[chat.chat_id] = chat
            for member in chat.members:
                if member.user_id == self._credentials.account_id:
                    continue
                direct_chat_id = self._member_direct_chat_id(member.user_id)
                if direct_chat_id is None:
                    continue
                await self._event_sink.publish(
                    ContactChanged(
                        envelope=self._envelope(ContactChanged.EVENT_TYPE),
                        contact=Contact(
                            id=RemoteObjectId(direct_chat_id),
                            display_name=member.title,
                            avatar=(
                                Avatar(
                                    member.avatar.url,
                                    member.avatar.avatar_id,
                                    member.avatar.mime_type,
                                    member.avatar.bytes,
                                )
                                if member.avatar is not None
                                else None
                            ),
                        ),
                    )
                )
            await self._publish_group_conversation(chat)
            return
        await self._event_sink.publish(
            ContactChanged(
                envelope=self._envelope(ContactChanged.EVENT_TYPE),
                contact=Contact(
                    id=RemoteObjectId(chat.chat_id),
                    display_name=chat.title,
                    avatar=(
                        Avatar(
                            chat.avatar.url,
                            chat.avatar.avatar_id,
                            chat.avatar.mime_type,
                            chat.avatar.bytes,
                        )
                        if chat.avatar is not None
                        else None
                    ),
                ),
                force=chat.force_roster_sync,
            )
        )

    async def _publish_group_conversation(self, chat: MaxChat) -> None:
        await self._event_sink.publish(
            ConversationChanged(
                envelope=self._envelope(ConversationChanged.EVENT_TYPE),
                conversation=Conversation(
                    id=RemoteObjectId(chat.chat_id),
                    kind=ConversationKind.GROUP,
                    title=chat.title,
                    participants=tuple(
                        Participant(
                            id=RemoteObjectId(member.user_id),
                            display_name=member.title,
                        )
                        for member in chat.members
                    ),
                    avatar=(
                        Avatar(
                            chat.avatar.url,
                            chat.avatar.avatar_id,
                            chat.avatar.mime_type,
                            chat.avatar.bytes,
                        )
                        if chat.avatar is not None
                        else None
                    ),
                    attributes={"owner_remote_id": self._credentials.account_id},
                ),
            )
        )

    @staticmethod
    def _contact(contact: MaxContact) -> Contact:
        return Contact(
            id=RemoteObjectId(contact.chat_id),
            display_name=contact.title,
            avatar=(
                Avatar(
                    contact.avatar.url,
                    contact.avatar.avatar_id,
                    contact.avatar.mime_type,
                    contact.avatar.bytes,
                )
                if contact.avatar is not None
                else None
            ),
        )

    @staticmethod
    def _media(media: MaxMedia) -> Media:
        content_type = media.mime_type or "application/octet-stream"
        if media.voice or content_type.startswith("audio/"):
            kind = MediaKind.AUDIO
        elif content_type.startswith("image/"):
            kind = MediaKind.IMAGE
        elif content_type.startswith("video/"):
            kind = MediaKind.VIDEO
        else:
            kind = MediaKind.FILE
        return Media(
            id=RemoteObjectId(hashlib.sha256(media.url.encode("utf-8")).hexdigest()),
            kind=kind,
            content_type=content_type,
            file_name=media.name or None,
            size=media.size or None,
            source_url=media.url,
            thumbnail_url=media.thumbnail_url,
            width=media.width,
            height=media.height,
            duration=media.duration,
            voice=media.voice,
        )

    def _member_direct_chat_id(self, member_user_id: str) -> Optional[str]:
        try:
            return str(int(self._credentials.account_id) ^ int(member_user_id))
        except (TypeError, ValueError):
            return None

    async def _authorization_lost(self, exc: MaxAuthorizationError) -> None:
        self._started = False
        await self._event_sink.publish(
            AuthorizationLost(
                envelope=self._envelope(AuthorizationLost.EVENT_TYPE),
                reason=str(exc),
            )
        )

    async def _publish_state(self, state: SessionState, detail: Optional[str] = None) -> None:
        await self._event_sink.publish(
            SessionStateChanged(
                envelope=self._envelope(SessionStateChanged.EVENT_TYPE),
                state=state,
                detail=detail,
            )
        )

    def _envelope(self, event_type: str) -> EventEnvelope:
        return EventEnvelope(
            event_id=EventId(str(uuid4())),
            event_type=event_type,
            schema_version=1,
            backend_id=MaxBackendPlugin.backend_id,
            binding_id=self._binding_id,
            occurred_at=datetime.now(timezone.utc),
        )


class MaxBackendPlugin:
    backend_id = BackendId("max")
    supported_features = frozenset(
        (MessageSender, ContactSource, ContactAdder, ButtonActions)
    )

    def __init__(
        self,
        client_factory: Optional[MaxClientFactory] = None,
        *,
        test_self_messages: bool = False,
    ) -> None:
        self._client_factory = client_factory or self._create_client
        self._test_self_messages = test_self_messages

    def configure(self, options: Mapping[str, str]) -> None:
        value = options.get("test_self_messages", "false").strip().lower()
        if value not in ("true", "false"):
            raise ValueError("test_self_messages must be true or false")
        self._test_self_messages = value == "true"

    @staticmethod
    def _create_client(credentials: MaxCredentials) -> MaxClient:
        from .client import PersonalMaxBackend

        return PersonalMaxBackend(token=credentials.token, device_id=credentials.device_id)

    def create_authentication(self, binding_id: BindingId) -> MaxAuthenticationFlow:
        from .auth import MaxLoginError, MaxPasswordRequired, MaxQrAuthorizationFlow

        return MaxAuthenticationFlow(
            MaxQrAuthorizationFlow(),
            password_required_error=MaxPasswordRequired,
            login_error=MaxLoginError,
        )

    def create_session(
        self, binding_id: BindingId, credentials: bytes, event_sink: BackendEventSink
    ) -> MaxBackendSession:
        return MaxBackendSession(
            binding_id,
            MaxCredentials.decode(credentials),
            event_sink,
            self._client_factory,
            self._test_self_messages,
        )
