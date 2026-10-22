import unittest
from dataclasses import dataclass
from datetime import datetime, timezone

from xmpp_transport.adapters.backends.max import (
    MaxAuthenticationFlow,
    MaxBackendPlugin,
    MaxCredentials,
)
from xmpp_transport.adapters.backends.max.client import PersonalMaxBackend
from xmpp_transport.adapters.backends.max.models import (
    MaxAuthorizationError,
    MaxChat,
    MaxContact,
    MaxForwardReference,
    MaxIncomingMessage,
    MaxButton,
    MaxMedia,
)
from xmpp_transport.domain.auth import AuthResponse, AuthResponseKind, AuthState
from xmpp_transport.domain.events import (
    AuthorizationLost,
    ContactChanged,
    ConversationChanged,
    MessageReceived,
    SessionStateChanged,
)
from xmpp_transport.domain.identifiers import BackendId, BindingId, RemoteObjectId
from xmpp_transport.domain.models import (
    ForwardReference,
    Media,
    MediaKind,
    OutgoingMessage,
    ReplyReference,
)
from xmpp_transport.ports.backend import ButtonActions, ContactAdder, ContactSource, MessageSender


class EventSink:
    def __init__(self) -> None:
        self.events = []

    async def publish(self, event) -> None:  # type: ignore[no-untyped-def]
        self.events.append(event)


class MaxClient:
    def __init__(self) -> None:
        self.message_handler = None
        self.authorization_lost_handler = None
        self.chat_handler = None
        self.started = 0
        self.closed = 0
        self.sent = []
        self.callbacks = []
        self.forwards = []

    def set_message_handler(self, handler) -> None:  # type: ignore[no-untyped-def]
        self.message_handler = handler

    def set_authorization_lost_handler(self, handler) -> None:  # type: ignore[no-untyped-def]
        self.authorization_lost_handler = handler

    def set_chat_handler(self, handler) -> None:  # type: ignore[no-untyped-def]
        self.chat_handler = handler

    async def start(self) -> None:
        self.started += 1

    async def close(self) -> None:
        self.closed += 1

    async def send_message(  # type: ignore[no-untyped-def]
        self, text, chat_id=None, reply_to_message_id=None, media=(), forward_reference=None
    ):
        self.sent.append((text, chat_id, reply_to_message_id, media))
        self.forwards.append(forward_reference)
        return {"message": {"id": "sent-1"}}

    async def list_contacts(self):  # type: ignore[no-untyped-def]
        return [MaxContact("user-1", "Alice", "chat-1")]

    async def add_contact_by_phone(self, phone):  # type: ignore[no-untyped-def]
        return MaxContact("user-2", "Bob", "chat-2")

    async def send_button_callback(
        self, *, chat_id, callback_id, payload, button_type="CALLBACK"  # type: ignore[no-untyped-def]
    ):
        self.callbacks.append((chat_id, callback_id, payload, button_type))
        return {}


class LoginError(RuntimeError):
    pass


class PasswordRequired(LoginError):
    pass


@dataclass(frozen=True)
class QrChallenge:
    qr_link: str
    expires_at: datetime


class QrClient:
    def __init__(self, password_required: bool = False) -> None:
        self.password_required = password_required
        self.closed = 0

    async def start(self) -> QrChallenge:
        return QrChallenge("https://max.example/qr/opaque", datetime.now(timezone.utc))

    async def wait_for_credentials(self):  # type: ignore[no-untyped-def]
        if self.password_required:
            raise PasswordRequired("password required")
        return "token", "device", "account"

    async def submit_password(self, password):  # type: ignore[no-untyped-def]
        if password != "correct":
            raise LoginError("invalid password")
        return "token", "device", "account"

    async def close(self) -> None:
        self.closed += 1


class MaxCredentialsTests(unittest.TestCase):
    def test_round_trips_credentials_without_exposing_secrets(self) -> None:
        credentials = MaxCredentials("secret-token", "secret-device", "42")

        self.assertEqual(credentials, MaxCredentials.decode(credentials.encode()))
        self.assertNotIn("secret-token", repr(credentials))
        self.assertNotIn("secret-device", repr(credentials))

    def test_rejects_missing_or_invalid_fields(self) -> None:
        invalid = (b"not-json", b"[]", b'{}', b'{"token":"x"}')
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                MaxCredentials.decode(payload)


class MaxWireForwardTests(unittest.IsolatedAsyncioTestCase):
    async def test_own_forward_uses_native_max_link(self) -> None:
        client = PersonalMaxBackend(token="token", device_id="device")
        payloads = []

        async def send_payload(payload, *, chat_id, reply_to_message_id, attaches):
            payloads.append(payload)
            return {"payload": {"message": {"id": "sent-1"}}}

        client._send_message_payload_with_attachment_retry = send_payload
        await client.send_message(
            text="", chat_id="22",
            forward_reference=MaxForwardReference("11", "116974846586354125"),
        )

        self.assertEqual(
            {"type": "FORWARD", "chatId": 11, "messageId": "116974846586354125"},
            payloads[0]["message"]["link"],
        )
        self.assertEqual("", payloads[0]["message"]["text"])

    async def test_reply_uses_native_max_link_without_quoted_fallback(self) -> None:
        client = PersonalMaxBackend(token="token", device_id="device")
        payloads = []

        async def send_payload(payload, *, chat_id, reply_to_message_id, attaches):
            payloads.append(payload)
            return {"payload": {"message": {"id": "sent-1"}}}

        client._send_message_payload_with_attachment_retry = send_payload
        await client.send_message(
            text="response", chat_id="888", reply_to_message_id="116974846586354125",
        )

        self.assertEqual(
            {"type": "REPLY", "messageId": "116974846586354125"},
            payloads[0]["message"]["link"],
        )
        self.assertEqual("response", payloads[0]["message"]["text"])


class MaxSnapshotDispatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_syncs_contacts_and_direct_chats_but_skips_groups(self) -> None:
        client = PersonalMaxBackend(token="token", device_id="device")
        received: list[MaxChat] = []

        async def handle_chat(chat: MaxChat) -> None:
            received.append(chat)

        client.set_chat_handler(handle_chat)
        client._snapshot_cache.address_book["user-1"] = MaxContact(
            "user-1", "Alice", "chat-1"
        )

        await client._dispatch_snapshot_contacts([
            MaxChat("chat-1", "Alice"),
            MaxChat("chat-2", "Bob"),
            MaxChat("group-1", "Group", is_group=True),
        ])

        self.assertEqual(["chat-1", "chat-2"], [chat.chat_id for chat in received])
        self.assertTrue(all(chat.force_roster_sync for chat in received))


class MaxBackendPluginTests(unittest.TestCase):
    def test_identifies_as_max_and_validates_session_credentials(self) -> None:
        plugin = MaxBackendPlugin()
        self.assertEqual(BackendId("max"), plugin.backend_id)

        with self.assertRaises(ValueError):
            plugin.create_session(BindingId("binding-1"), b"invalid", object())  # type: ignore[arg-type]

    def test_rejects_invalid_self_message_setting(self) -> None:
        plugin = MaxBackendPlugin()

        with self.assertRaisesRegex(ValueError, "test_self_messages"):
            plugin.configure({"test_self_messages": "sometimes"})


class MaxBackendSessionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.client = MaxClient()
        self.sink = EventSink()
        plugin = MaxBackendPlugin(lambda credentials: self.client)  # type: ignore[arg-type]
        credentials = MaxCredentials("token", "device", "account").encode()
        self.session = plugin.create_session(
            BindingId("binding-1"), credentials, self.sink  # type: ignore[arg-type]
        )

    async def test_starts_sends_text_and_closes_client(self) -> None:
        await self.session.start()
        sender = self.session.features()[MessageSender]
        result = await sender.send_message(  # type: ignore[attr-defined]
            OutgoingMessage(
                client_message_id="client-1",
                binding_id=BindingId("binding-1"),
                conversation_id=RemoteObjectId("chat-1"),
                text="hello",
            )
        )
        await self.session.close()

        self.assertEqual(RemoteObjectId("sent-1"), result.remote_message_id)
        self.assertEqual([("hello", "chat-1", None, ())], self.client.sent)
        self.assertEqual((1, 1), (self.client.started, self.client.closed))
        states = [event.state.value for event in self.sink.events if isinstance(event, SessionStateChanged)]
        self.assertEqual(["starting", "connected", "stopped"], states)

    async def test_sends_media_through_max_client(self) -> None:
        await self.session.start()
        media = Media(
            id=RemoteObjectId("media-1"),
            kind=MediaKind.IMAGE,
            content_type="image/jpeg",
            file_name="photo.jpg",
            source_url="https://xabber.example/upload/photo.jpg",
        )
        await self.session.send_message(
            OutgoingMessage(
                client_message_id="client-media-1",
                binding_id=BindingId("binding-1"),
                conversation_id=RemoteObjectId("chat-1"),
                media=(media,),
            )
        )
        self.assertEqual("", self.client.sent[0][0])
        self.assertEqual((media,), self.client.sent[0][3])

    async def test_sends_xabber_forward_as_native_max_forward(self) -> None:
        await self.session.start()
        await self.session.send_message(
            OutgoingMessage(
                client_message_id="client-forward-1",
                binding_id=BindingId("binding-1"),
                conversation_id=RemoteObjectId("22"),
                text="fallback",
                forwarded_from=ForwardReference(
                    source_name="chat-11@max.example",
                    source_message_id=RemoteObjectId("116974846586354125"),
                ),
            )
        )
        self.assertEqual("", self.client.sent[0][0])
        self.assertEqual("11", self.client.forwards[0].source_chat_id)
        self.assertEqual("116974846586354125", self.client.forwards[0].message_id)

    async def test_sends_own_xabber_forward_as_native_max_forward(self) -> None:
        await self.session.start()
        await self.session.send_message(
            OutgoingMessage(
                client_message_id="forward-own-1",
                binding_id=BindingId("binding-1"),
                conversation_id=RemoteObjectId("22"),
                forwarded_from=ForwardReference(
                    source_name="user@example.com",
                    source_recipient="chat-11@max.example.com",
                    source_message_id=RemoteObjectId("116974846586354125"),
                    body="Own message", is_self=True,
                ),
            )
        )
        self.assertEqual("11", self.client.forwards[0].source_chat_id)
        self.assertEqual("116974846586354125", self.client.forwards[0].message_id)
        self.assertEqual("", self.client.sent[0][0])

    async def test_sends_group_reply_with_only_response_text(self) -> None:
        await self.session.start()
        await self.session.send_message(
            OutgoingMessage(
                client_message_id="reply-1", binding_id=BindingId("binding-1"),
                conversation_id=RemoteObjectId("888"), text="response",
                reply_to=ReplyReference(RemoteObjectId("116974846586354125")),
                attributes={"is_group": "true"},
            )
        )
        self.assertEqual(
            ("response", "888", "116974846586354125", ()), self.client.sent[0]
        )
        self.assertIsNone(self.client.forwards[0])

    async def test_suppresses_MAX_echo_after_xabber_group_send(self) -> None:
        await self.session.start()
        sender = self.session.features()[MessageSender]
        await sender.send_message(  # type: ignore[attr-defined]
            OutgoingMessage(
                client_message_id="group-client-1",
                binding_id=BindingId("binding-1"),
                conversation_id=RemoteObjectId("888"),
                text="hello group",
                attributes={"is_group": "true"},
            )
        )
        await self.client.message_handler(  # type: ignore[misc]
            MaxIncomingMessage(
                sender_id="account",
                text="hello group",
                chat_id="888",
                message_id="sent-1",
                is_self=True,
                is_group=True,
            )
        )

        self.assertFalse(
            any(isinstance(event, MessageReceived) for event in self.sink.events)
        )

    async def test_publishes_incoming_message_and_authorization_loss(self) -> None:
        await self.session.start()
        await self.client.message_handler(  # type: ignore[misc]
            MaxIncomingMessage(
                sender_id="user-1",
                text="incoming",
                chat_id="chat-1",
                message_id="message-1",
            )
        )
        await self.client.authorization_lost_handler(  # type: ignore[misc]
            MaxAuthorizationError("expired", terminal=True)
        )

        messages = [event for event in self.sink.events if isinstance(event, MessageReceived)]
        lost = [event for event in self.sink.events if isinstance(event, AuthorizationLost)]
        self.assertEqual("incoming", messages[0].message.text)
        self.assertEqual(RemoteObjectId("chat-1"), messages[0].message.conversation_id)
        self.assertEqual("expired", lost[0].reason)

    async def test_maps_buttons_and_sends_callback_through_feature(self) -> None:
        await self.session.start()
        await self.client.message_handler(  # type: ignore[misc]
            MaxIncomingMessage(
                sender_id="user-1",
                text="Confirm?",
                chat_id="chat-1",
                message_id="message-1",
                buttons=((MaxButton("OK", "confirm", "callback-1"),),),
            )
        )
        message = next(
            event.message for event in self.sink.events if isinstance(event, MessageReceived)
        )
        actions = self.session.features()[ButtonActions]
        await actions.activate_button(  # type: ignore[attr-defined]
            RemoteObjectId("chat-1"), "callback-1", "confirm", "CALLBACK"
        )

        self.assertEqual("confirm", message.buttons[0][0].payload)
        self.assertEqual(
            [("chat-1", "callback-1", "confirm", "CALLBACK")],
            self.client.callbacks,
        )

    async def test_maps_incoming_max_media_to_provider_neutral_metadata(self) -> None:
        await self.session.start()
        await self.client.message_handler(  # type: ignore[misc]
            MaxIncomingMessage(
                sender_id="user-1",
                text="photo",
                chat_id="chat-1",
                message_id="message-1",
                media=(
                    MaxMedia(
                        url="https://cdn.example/photo.jpg",
                        name="photo.jpg",
                        mime_type="image/jpeg",
                        size=123,
                        thumbnail_url="https://cdn.example/thumb.jpg",
                        width=640,
                        height=480,
                    ),
                ),
            )
        )

        message = next(
            event.message for event in self.sink.events if isinstance(event, MessageReceived)
        )
        media = message.media[0]
        self.assertEqual("image", media.kind.value)
        self.assertEqual("https://cdn.example/photo.jpg", media.source_url)
        self.assertEqual((640, 480), (media.width, media.height))

    async def test_ignores_self_messages_in_direct_chats(self) -> None:
        plugin = MaxBackendPlugin(
            lambda credentials: self.client,
            test_self_messages=True,
        )  # type: ignore[arg-type]
        session = plugin.create_session(
            BindingId("binding-1"),
            MaxCredentials("token", "device", "account").encode(),
            self.sink,  # type: ignore[arg-type]
        )
        await session.start()

        await self.client.message_handler(  # type: ignore[misc]
            MaxIncomingMessage(
                sender_id="account",
                text="direct self",
                chat_id="chat-1",
                message_id="self-direct-1",
                is_self=True,
            )
        )

        self.assertFalse(
            any(isinstance(event, MessageReceived) for event in self.sink.events)
        )

    async def test_publishes_group_self_message_when_enabled(self) -> None:
        plugin = MaxBackendPlugin(lambda credentials: self.client)  # type: ignore[arg-type]
        plugin.configure({"test_self_messages": "true"})
        session = plugin.create_session(
            BindingId("binding-1"),
            MaxCredentials("token", "device", "account").encode(),
            self.sink,  # type: ignore[arg-type]
        )
        await session.start()

        await self.client.message_handler(  # type: ignore[misc]
            MaxIncomingMessage(
                sender_id="account",
                text="group self",
                chat_id="group-1",
                message_id="self-group-1",
                is_self=True,
                is_group=True,
            )
        )

        messages = [
            event for event in self.sink.events if isinstance(event, MessageReceived)
        ]
        conversations = [
            event
            for event in self.sink.events
            if isinstance(event, ConversationChanged)
        ]
        self.assertEqual(1, len(conversations))
        self.assertEqual(1, len(messages))
        self.assertEqual("true", messages[0].message.attributes["is_self"])
        self.assertEqual("true", messages[0].message.attributes["is_group"])

    async def test_group_reply_uses_linked_original_after_restart(self) -> None:
        plugin = MaxBackendPlugin(lambda credentials: self.client)  # type: ignore[arg-type]
        plugin.configure({"test_self_messages": "true"})
        session = plugin.create_session(
            BindingId("binding-1"),
            MaxCredentials("token", "device", "account").encode(),
            self.sink,  # type: ignore[arg-type]
        )
        await session.start()
        await self.client.message_handler(  # type: ignore[misc]
            MaxIncomingMessage(
                sender_id="account", text="Ответ", chat_id="group-1",
                message_id="reply-1", reply_to_message_id="original-1",
                is_self=True, is_group=True,
                raw={"message": {"link": {"type": "REPLY", "messageId": "original-1",
                                           "message": {"id": "original-1", "sender": "account",
                                                       "text": "Исходное сообщение"}}}},
            )
        )
        received = [
            event.message for event in self.sink.events if isinstance(event, MessageReceived)
        ]
        self.assertEqual("Исходное сообщение", received[0].reply_to.body)
        self.assertTrue(received[0].reply_to.is_self)
        self.assertEqual(RemoteObjectId("original-1"), received[0].reply_to.message_id)

    async def test_group_reply_uses_recent_message_when_link_has_no_body(self) -> None:
        await self.session.start()
        await self.client.message_handler(  # type: ignore[misc]
            MaxIncomingMessage(
                sender_id="member-1", text="Первое", chat_id="group-1",
                message_id="original-1", is_group=True,
            )
        )
        await self.client.message_handler(  # type: ignore[misc]
            MaxIncomingMessage(
                sender_id="member-2", text="Ответ", chat_id="group-1",
                message_id="reply-1", reply_to_message_id="original-1", is_group=True,
            )
        )
        received = [
            event.message for event in self.sink.events if isinstance(event, MessageReceived)
        ]
        self.assertEqual("Первое", received[1].reply_to.body)
        self.assertEqual(RemoteObjectId("member-1"), received[1].reply_to.sender_id)

    async def test_ignores_group_self_message_when_disabled(self) -> None:
        await self.session.start()

        await self.client.message_handler(  # type: ignore[misc]
            MaxIncomingMessage(
                sender_id="account",
                text="group self",
                chat_id="group-1",
                message_id="self-group-1",
                is_self=True,
                is_group=True,
            )
        )

        self.assertFalse(
            any(isinstance(event, MessageReceived) for event in self.sink.events)
        )

    async def test_group_message_syncs_sender_before_publishing_message(self) -> None:
        plugin = MaxBackendPlugin(lambda credentials: self.client)  # type: ignore[arg-type]
        session = plugin.create_session(
            BindingId("binding-1"),
            MaxCredentials("token", "device", "100").encode(),
            self.sink,  # type: ignore[arg-type]
        )
        await session.start()

        await self.client.message_handler(  # type: ignore[misc]
            MaxIncomingMessage(
                sender_id="7",
                sender_title="Alice",
                text="group incoming",
                chat_id="888",
                chat_title="MAX Group",
                message_id="group-message-1",
                is_group=True,
            )
        )

        relevant = [
            event
            for event in self.sink.events
            if isinstance(event, (ConversationChanged, ContactChanged, MessageReceived))
        ]
        self.assertIsInstance(relevant[0], ConversationChanged)
        self.assertIsInstance(relevant[1], ContactChanged)
        self.assertEqual(RemoteObjectId("99"), relevant[1].contact.id)
        self.assertIsInstance(relevant[2], MessageReceived)
        self.assertEqual(
            "100", relevant[2].message.attributes["owner_remote_id"]
        )

    async def test_publishes_direct_snapshot_chat_as_roster_contact(self) -> None:
        await self.session.start()

        await self.client.chat_handler(  # type: ignore[misc]
            MaxChat("chat-42", "Alice", force_roster_sync=True)
        )

        contacts = [event for event in self.sink.events if isinstance(event, ContactChanged)]
        self.assertEqual(RemoteObjectId("chat-42"), contacts[0].contact.id)
        self.assertEqual("Alice", contacts[0].contact.display_name)
        self.assertTrue(contacts[0].force)

    async def test_publishes_group_snapshot_as_conversation(self) -> None:
        from xmpp_transport.adapters.backends.max.models import MaxChatMember

        await self.session.start()
        await self.client.chat_handler(  # type: ignore[misc]
            MaxChat(
                "group-42",
                "MAX Group",
                is_group=True,
                members=(MaxChatMember("user-7", "Alice"),),
            )
        )

        conversations = [
            event
            for event in self.sink.events
            if isinstance(event, ConversationChanged)
        ]
        self.assertEqual(1, len(conversations))
        self.assertEqual("MAX Group", conversations[0].conversation.title)
        self.assertEqual("Alice", conversations[0].conversation.participants[0].display_name)
        self.assertEqual(
            "account",
            conversations[0].conversation.attributes["owner_remote_id"],
        )
        # Non-numeric fixture IDs cannot be mapped through MAX's XOR dialog rule.
        self.assertFalse(any(isinstance(event, ContactChanged) for event in self.sink.events))

    async def test_syncs_numeric_group_member_as_direct_roster_contact(self) -> None:
        from xmpp_transport.adapters.backends.max.models import MaxChatMember

        plugin = MaxBackendPlugin(lambda credentials: self.client)  # type: ignore[arg-type]
        session = plugin.create_session(
            BindingId("binding-1"),
            MaxCredentials("token", "device", "100").encode(),
            self.sink,  # type: ignore[arg-type]
        )
        await session.start()
        await self.client.chat_handler(  # type: ignore[misc]
            MaxChat(
                "group-42",
                "MAX Group",
                is_group=True,
                members=(MaxChatMember("7", "Alice"),),
            )
        )

        contacts = [event for event in self.sink.events if isinstance(event, ContactChanged)]
        self.assertEqual(RemoteObjectId(str(100 ^ 7)), contacts[0].contact.id)
        self.assertEqual("Alice", contacts[0].contact.display_name)

    async def test_exposes_address_book_through_contact_source(self) -> None:
        await self.session.start()

        source = self.session.features()[ContactSource]
        contacts = await source.contacts()  # type: ignore[attr-defined]

        self.assertEqual(RemoteObjectId("chat-1"), contacts[0].id)

    async def test_adds_contact_by_phone_through_optional_feature(self) -> None:
        await self.session.start()

        adder = self.session.features()[ContactAdder]
        contact = await adder.add_contact_by_phone("+79990000000")  # type: ignore[attr-defined]

        self.assertEqual(RemoteObjectId("chat-2"), contact.id)
        self.assertEqual("Bob", contact.display_name)


class MaxAuthenticationFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_qr_flow_exports_credentials_after_connection(self) -> None:
        client = QrClient()
        flow = MaxAuthenticationFlow(client, PasswordRequired, LoginError)  # type: ignore[arg-type]

        challenge = await flow.start()
        connected = await flow.respond(
            AuthResponse(AuthResponseKind.CONFIRMATION, "confirmed")
        )

        self.assertEqual(AuthState.WAITING_QR, challenge.state)
        self.assertEqual(AuthState.CONNECTED, connected.state)
        self.assertEqual("account", MaxCredentials.decode(flow.credentials()).account_id)
        self.assertEqual("account", flow.remote_account_id())
        self.assertTrue(flow.matches_account(MaxCredentials("other", "device", "account").encode()))
        self.assertFalse(flow.matches_account(MaxCredentials("other", "device", "different").encode()))

    async def test_qr_flow_supports_two_factor_password(self) -> None:
        client = QrClient(password_required=True)
        flow = MaxAuthenticationFlow(client, PasswordRequired, LoginError)  # type: ignore[arg-type]

        await flow.start()
        password = await flow.respond(
            AuthResponse(AuthResponseKind.CONFIRMATION, "confirmed")
        )
        connected = await flow.respond(AuthResponse(AuthResponseKind.PASSWORD, "correct"))
        await flow.close()

        self.assertEqual(AuthState.WAITING_PASSWORD, password.state)
        self.assertEqual(AuthState.CONNECTED, connected.state)
        self.assertEqual(1, client.closed)

    async def test_rejected_two_factor_password_keeps_flow_active(self) -> None:
        client = QrClient(password_required=True)
        flow = MaxAuthenticationFlow(client, PasswordRequired, LoginError)  # type: ignore[arg-type]

        await flow.start()
        await flow.respond(AuthResponse(AuthResponseKind.CONFIRMATION, "confirmed"))
        rejected = await flow.respond(AuthResponse(AuthResponseKind.PASSWORD, "wrong"))
        connected = await flow.respond(AuthResponse(AuthResponseKind.PASSWORD, "correct"))

        self.assertEqual(AuthState.WAITING_PASSWORD, rejected.state)
        self.assertEqual(AuthState.CONNECTED, connected.state)


if __name__ == "__main__":
    unittest.main()
