import unittest
from datetime import datetime, timezone
from html import escape
from typing import Optional, Sequence
from xml.etree import ElementTree as ET

from xmpp_transport.adapters.xmpp.addressing import ContactAddressCodec, DirectRouteResolver
from xmpp_transport.adapters.xmpp.auth_commands import ControlResponse
from xmpp_transport.adapters.xmpp.component import ComponentSettings
from xmpp_transport.adapters.xmpp.gateway import XmppDirectMessageGateway
from xmpp_transport.adapters.xmpp.message_codec import XmppMessageCodec
from xmpp_transport.adapters.xmpp.namespaces import (
    CHAT_MARKERS_NS,
    CLIENT_NS,
    FORWARDED_NS,
    GROUPS_NS,
    REPLY_NS,
    STANZAS_NS,
    XABBER_REFERENCES_NS,
)
from xmpp_transport.domain.errors import FeatureUnavailable
from xmpp_transport.domain.identifiers import BackendId, BindingId, RemoteObjectId
from xmpp_transport.domain.models import IncomingMessage, OutgoingMessage, ReplyReference
from xmpp_transport.ports.backend import SendResult
from xmpp_transport.ports.repositories import BindingRecord


class FakeWire:
    def __init__(self) -> None:
        self.handler = None
        self.sent = []
        self.started = 0
        self.closed = 0

    def set_message_handler(self, handler):  # type: ignore[no-untyped-def]
        self.handler = handler

    async def start(self) -> None:
        self.started += 1

    async def send(self, element: ET.Element) -> None:
        self.sent.append(element)

    async def close(self) -> None:
        self.closed += 1


class FakeBindings:
    def __init__(self) -> None:
        self.record: Optional[BindingRecord] = BindingRecord(
            BindingId("binding-1"), BackendId("telegram")
        )
        self.owner: Optional[str] = "user@example.com"

    async def binding_for_xmpp_account(self, bare_jid: str, backend_id: BackendId):  # type: ignore[no-untyped-def]
        return self.record

    async def xmpp_account_for_binding(self, binding_id: BindingId) -> Optional[str]:
        return self.owner

    async def active_bindings(self) -> Sequence[BindingRecord]:
        return ()

    async def encrypted_credentials(self, binding_id: BindingId) -> Optional[bytes]:
        return None

    async def save_encrypted_credentials(
        self, binding_id: BindingId, backend_id: BackendId, credentials: bytes
    ) -> None:
        return None


class FakeMessageRouter:
    def __init__(self) -> None:
        self.outgoing = []
        self.failure: Optional[Exception] = None
        self.button_actions = []

    async def send(self, message: OutgoingMessage) -> SendResult:
        if self.failure is not None:
            raise self.failure
        self.outgoing.append(message)
        return SendResult(RemoteObjectId("remote-result"))

    async def activate_button(self, binding_id, conversation_id, value):  # type: ignore[no-untyped-def]
        if value not in ("confirm", "/confirm"):
            return False
        self.button_actions.append((binding_id, conversation_id, value))
        return True


class FakeControl:
    def __init__(self, fail_on_handle: bool = True) -> None:
        self.commands = []
        self.fail_on_handle = fail_on_handle

    def accepts(self, to_jid: str) -> bool:
        return to_jid.split("/", 1)[0] == "bot@telegram.example.com"

    async def handle(
        self, from_jid: str, command: str, form_fields=None  # type: ignore[no-untyped-def]
    ):
        self.commands.append((from_jid, command, form_fields))
        if self.fail_on_handle:
            raise AssertionError("group system message reached the control handler")
        return ControlResponse("ok")


def error_condition(stanza: ET.Element) -> str:
    error = stanza.find("error")
    assert error is not None
    for child in error:
        if child.tag != "{{{}}}text".format(STANZAS_NS):
            return child.tag.rsplit("}", 1)[-1]
    raise AssertionError("missing error condition")


class XmppGatewayTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.wire = FakeWire()
        self.bindings = FakeBindings()
        self.router = FakeMessageRouter()
        self.addresses = ContactAddressCodec("telegram.example.com")
        self.gateway = XmppDirectMessageGateway(
            self.wire,
            DirectRouteResolver(BackendId("telegram"), self.addresses, self.bindings),
            self.addresses,
            self.bindings,
            self.router,  # type: ignore[arg-type]
            XmppMessageCodec(),
            transport_namespace="urn:xabber:transport:telegram:1",
        )

    async def test_lifecycle_delegates_to_wire(self) -> None:
        await self.gateway.start()
        await self.gateway.close()
        self.assertEqual((1, 1), (self.wire.started, self.wire.closed))
        self.assertIsNotNone(self.wire.handler)

    async def test_routes_outgoing_stanza_to_message_router(self) -> None:
        stanza = ET.fromstring(
            """
            <message from='user@example.com/device'
                     to='chat-123@telegram.example.com' type='chat' id='client-1'>
              <body>Hello</body>
            </message>
            """
        )
        await self.gateway.handle_stanza(stanza)
        self.assertEqual(1, len(self.router.outgoing))
        message = self.router.outgoing[0]
        self.assertEqual(BindingId("binding-1"), message.binding_id)
        self.assertEqual(RemoteObjectId("123"), message.conversation_id)
        self.assertEqual([], self.wire.sent)

    async def test_routes_direct_bot_ui_callback_without_sending_text(self) -> None:
        stanza = ET.fromstring(
            """
            <message from='user@example.com/device' to='chat-123@telegram.example.com'>
              <callback xmlns='https://xabber.com/protocol/bot-ui' data='confirm'/>
            </message>
            """
        )

        await self.gateway.handle_stanza(stanza)

        self.assertEqual(
            [(BindingId("binding-1"), RemoteObjectId("123"), "confirm")],
            self.router.button_actions,
        )
        self.assertEqual([], self.router.outgoing)

    async def test_ignores_transport_generated_fake_outgoing_stanza(self) -> None:
        stanza = ET.fromstring(
            """
            <message from='bot@max.example.com'
                     to='maxg-owner-888@example.com' type='chat' id='remote-1'>
              <body>Sent from MAX</body>
              <fake-outgoing xmlns='urn:xabber:transport:telegram:1'/>
            </message>
            """
        )

        await self.gateway.handle_stanza(stanza)

        self.assertEqual([], self.router.outgoing)
        self.assertEqual([], self.wire.sent)

    async def test_ignores_xabber_group_system_message(self) -> None:
        control = FakeControl()
        gateway = XmppDirectMessageGateway(
            self.wire,
            DirectRouteResolver(BackendId("telegram"), self.addresses, self.bindings),
            self.addresses,
            self.bindings,
            self.router,  # type: ignore[arg-type]
            XmppMessageCodec(),
            control=control,  # type: ignore[arg-type]
            transport_namespace="urn:xabber:transport:telegram:1",
        )
        stanza = ET.fromstring(
            """
            <message from='maxg-owner-888@example.com'
                     to='bot@telegram.example.com' type='chat' id='system-1'>
              <body>MAX user 7 joined group chat.</body>
              <x xmlns='https://xabber.com/protocol/groups'>
                <system-message>user-joined</system-message>
              </x>
            </message>
            """
        )

        await gateway.handle_stanza(stanza)

        self.assertEqual([], self.router.outgoing)
        self.assertEqual([], self.wire.sent)
        self.assertEqual([], control.commands)
        self.assertIsNotNone(stanza.find("{{{}}}x".format(GROUPS_NS)))

    async def test_routes_owner_group_fanout_before_control_handler(self) -> None:
        control = FakeControl()
        gateway = XmppDirectMessageGateway(
            self.wire,
            DirectRouteResolver(BackendId("telegram"), self.addresses, self.bindings),
            self.addresses,
            self.bindings,
            self.router,  # type: ignore[arg-type]
            XmppMessageCodec(),
            control=control,  # type: ignore[arg-type]
            transport_namespace="urn:xabber:transport:telegram:1",
            server_domain="example.com",
            group_localpart_prefix="telegramg",
        )
        stanza = ET.fromstring(
            """
            <message from='telegramg-75736572406578616d706c652e636f6d-888@example.com'
                     to='bot@telegram.example.com' type='chat' id='group-client-1'>
              <body>user@example.com:\nHello MAX group</body>
              <x xmlns='https://xabber.com/protocol/groups'>
                <user><jid xmlns=''>user@example.com/device</jid></user>
              </x>
            </message>
            """
        )

        await gateway.handle_stanza(stanza)

        self.assertEqual([], control.commands)
        self.assertEqual(1, len(self.router.outgoing))
        message = self.router.outgoing[0]
        self.assertEqual(RemoteObjectId("888"), message.conversation_id)
        self.assertEqual("Hello MAX group", message.text)
        self.assertEqual("true", message.attributes["is_group"])
        self.assertEqual([], self.wire.sent)

    async def test_routes_owner_group_fanout_without_sender_marker(self) -> None:
        control = FakeControl()
        gateway = XmppDirectMessageGateway(
            self.wire,
            DirectRouteResolver(BackendId("telegram"), self.addresses, self.bindings),
            self.addresses,
            self.bindings,
            self.router,  # type: ignore[arg-type]
            XmppMessageCodec(),
            control=control,  # type: ignore[arg-type]
            transport_namespace="urn:xabber:transport:telegram:1",
            server_domain="example.com",
            group_localpart_prefix="telegramg",
        )
        stanza = ET.fromstring(
            """
            <message from='telegramg-75736572406578616d706c652e636f6d-888@example.com'
                     to='bot@telegram.example.com' type='chat' id='group-client-2'>
              <body>user@example.com:\nMessage without sender marker</body>
            </message>
            """
        )

        await gateway.handle_stanza(stanza)

        self.assertEqual([], control.commands)
        self.assertEqual(1, len(self.router.outgoing))
        self.assertEqual("Message without sender marker", self.router.outgoing[0].text)
        self.assertEqual([], self.wire.sent)

    async def test_ignores_reflected_group_message_from_provider_member(self) -> None:
        control = FakeControl()
        gateway = XmppDirectMessageGateway(
            self.wire,
            DirectRouteResolver(BackendId("telegram"), self.addresses, self.bindings),
            self.addresses,
            self.bindings,
            self.router,  # type: ignore[arg-type]
            XmppMessageCodec(),
            control=control,  # type: ignore[arg-type]
            transport_namespace="urn:xabber:transport:telegram:1",
            server_domain="example.com",
            group_localpart_prefix="telegramg",
        )
        stanza = ET.fromstring(
            """
            <message from='telegramg-75736572406578616d706c652e636f6d-888@example.com'
                     to='bot@telegram.example.com' type='chat' id='provider-member-1'>
              <body>Incoming from Telegram member</body>
              <x xmlns='https://xabber.com/protocol/groups'>
                <user><jid xmlns=''>chat-99@telegram.example.com</jid></user>
              </x>
            </message>
            """
        )

        await gateway.handle_stanza(stanza)

        self.assertEqual([], control.commands)
        self.assertEqual([], self.router.outgoing)
        self.assertEqual([], self.wire.sent)

    async def test_group_media_url_is_not_reintroduced_as_caption(self) -> None:
        control = FakeControl()
        gateway = XmppDirectMessageGateway(
            self.wire,
            DirectRouteResolver(BackendId("telegram"), self.addresses, self.bindings),
            self.addresses,
            self.bindings,
            self.router,  # type: ignore[arg-type]
            XmppMessageCodec(),
            control=control,  # type: ignore[arg-type]
            transport_namespace="urn:xabber:transport:telegram:1",
            server_domain="example.com",
            group_localpart_prefix="telegramg",
        )
        media_url = "http://127.0.0.1:8000/gallery/symlinks/token/example.png"
        stanza = ET.fromstring(
            """
            <message from='telegramg-75736572406578616d706c652e636f6d-888@example.com'
                     to='bot@telegram.example.com' type='chat' id='group-media-1'>
              <body>user@example.com:\n{}</body>
            </message>
            """.format(media_url)
        )

        await gateway.handle_stanza(stanza)

        self.assertEqual([], control.commands)
        self.assertEqual(1, len(self.router.outgoing))
        message = self.router.outgoing[0]
        self.assertIsNone(message.text)
        self.assertEqual(media_url, message.media[0].source_url)
        self.assertEqual([], self.wire.sent)

    async def test_routes_group_reply_to_max_as_reply_without_quoted_text(self) -> None:
        control = FakeControl()
        gateway = XmppDirectMessageGateway(
            self.wire,
            DirectRouteResolver(BackendId("telegram"), self.addresses, self.bindings),
            self.addresses, self.bindings, self.router,  # type: ignore[arg-type]
            XmppMessageCodec(), control=control,  # type: ignore[arg-type]
            transport_namespace="urn:xabber:transport:telegram:1",
            server_domain="example.com", group_localpart_prefix="telegramg",
        )
        group_jid = "telegramg-75736572406578616d706c652e636f6d-888@example.com"
        stanza = ET.fromstring(
            """
            <message from='{group}' to='bot@telegram.example.com'
                     type='chat' id='reply-1'>
              <body>user@example.com:\n&gt; Tuesday, October 20, 2026
&gt; [12:07:23] Alice:
&gt; test
response</body>
              <x xmlns='https://xabber.com/protocol/groups'>
                <user><jid xmlns=''>user@example.com</jid></user>
              </x>
              <reference xmlns='https://xabber.com/protocol/references' type='mutable'>
                <forwarded xmlns='urn:xmpp:forward:0'>
                  <message xmlns='jabber:client' from='chat-99@telegram.example.com'
                           to='{group}' id='max-original-1'>
                    <origin-id xmlns='urn:xmpp:sid:0' id='max-original-1'/>
                    <body>test</body>
                  </message>
                </forwarded>
              </reference>
            </message>
            """.format(group=group_jid)
        )

        await gateway.handle_stanza(stanza)

        self.assertEqual(1, len(self.router.outgoing))
        message = self.router.outgoing[0]
        self.assertEqual("response", message.text)
        self.assertIsNone(message.forwarded_from)
        self.assertEqual(RemoteObjectId("max-original-1"), message.reply_to.message_id)
        self.assertEqual("true", message.attributes["is_group"])
        self.assertEqual([], self.wire.sent)

    async def test_group_reply_reference_range_uses_original_body_offsets(self) -> None:
        control = FakeControl()
        gateway = XmppDirectMessageGateway(
            self.wire,
            DirectRouteResolver(BackendId("telegram"), self.addresses, self.bindings),
            self.addresses, self.bindings, self.router,  # type: ignore[arg-type]
            XmppMessageCodec(), control=control,  # type: ignore[arg-type]
            transport_namespace="urn:xabber:transport:telegram:1",
            server_domain="example.com", group_localpart_prefix="telegramg",
        )
        group_jid = "telegramg-75736572406578616d706c652e636f6d-888@example.com"
        prefix = "user@example.com:\n"
        quote = "> Tuesday, October 20, 2026\n> [12:37:47] Илья:\n> testtest\n"
        stanza = ET.fromstring(
            """
            <message from='{group}' to='bot@telegram.example.com' type='chat' id='reply-2'>
              <body>{body}</body>
              <reference xmlns='https://xabber.com/protocol/references' type='mutable'
                         begin='{begin}' end='{end}'>
                <forwarded xmlns='urn:xmpp:forward:0'>
                  <message xmlns='jabber:client' from='chat-99@telegram.example.com'
                           to='{group}' id='max-original-2'>
                    <body>testtest</body>
                  </message>
                </forwarded>
              </reference>
            </message>
            """.format(
                group=group_jid,
                body=prefix + quote + "test123",
                begin=len(escape(prefix, quote=False).encode("utf-16-le")) // 2,
                end=len(escape(prefix + quote, quote=False).encode("utf-16-le")) // 2,
            )
        )

        await gateway.handle_stanza(stanza)

        self.assertEqual(1, len(self.router.outgoing))
        message = self.router.outgoing[0]
        self.assertEqual("test123", message.text)
        self.assertEqual(RemoteObjectId("max-original-2"), message.reply_to.message_id)
        self.assertEqual([], self.wire.sent)

    async def test_ignores_group_service_message_without_sender_marker(self) -> None:
        control = FakeControl()
        gateway = XmppDirectMessageGateway(
            self.wire,
            DirectRouteResolver(BackendId("telegram"), self.addresses, self.bindings),
            self.addresses,
            self.bindings,
            self.router,  # type: ignore[arg-type]
            XmppMessageCodec(),
            control=control,  # type: ignore[arg-type]
            transport_namespace="urn:xabber:transport:telegram:1",
            server_domain="example.com",
            group_localpart_prefix="telegramg",
        )
        stanza = ET.fromstring(
            """
            <message from='telegramg-75736572406578616d706c652e636f6d-888@example.com'
                     to='bot@telegram.example.com' type='chat' id='group-service-1'>
              <body>Alice joined the group</body>
            </message>
            """
        )

        await gateway.handle_stanza(stanza)

        self.assertEqual([], control.commands)
        self.assertEqual([], self.router.outgoing)
        self.assertEqual([], self.wire.sent)

    async def test_routes_bot_ui_callback_and_submitted_form_to_control(self) -> None:
        control = FakeControl(fail_on_handle=False)
        gateway = XmppDirectMessageGateway(
            self.wire,
            DirectRouteResolver(BackendId("telegram"), self.addresses, self.bindings),
            self.addresses,
            self.bindings,
            self.router,  # type: ignore[arg-type]
            XmppMessageCodec(),
            control=control,  # type: ignore[arg-type]
        )
        callback = ET.fromstring(
            """
            <message from='user@example.com/device' to='bot@telegram.example.com'>
              <callback xmlns='https://xabber.com/protocol/bot-ui' data='/status'/>
            </message>
            """
        )
        form = ET.fromstring(
            """
            <message from='user@example.com/device' to='bot@telegram.example.com'>
              <x xmlns='jabber:x:data' type='submit'>
                <field var='command'><value>password</value></field>
                <field var='password'><value>secret</value></field>
              </x>
            </message>
            """
        )

        await gateway.handle_stanza(callback)
        await gateway.handle_stanza(form)

        self.assertEqual("/status", control.commands[0][1])
        self.assertEqual(
            {"command": "password", "password": "secret"},
            control.commands[1][2],
        )
        self.assertEqual(2, len(self.wire.sent))

    async def test_missing_binding_returns_service_unavailable(self) -> None:
        self.bindings.record = None
        stanza = ET.fromstring(
            """
            <message from='user@example.com/device'
                     to='chat-123@telegram.example.com' type='chat' id='client-1'>
              <body>Hello</body>
            </message>
            """
        )
        await self.gateway.handle_stanza(stanza)
        self.assertEqual("service-unavailable", error_condition(self.wire.sent[0]))

    async def test_invalid_stanza_returns_bad_request_without_body_reflection(self) -> None:
        stanza = ET.fromstring(
            """
            <message from='user@example.com/device'
                     to='chat-123@telegram.example.com' type='chat' id='client-1'>
              <body>private body</body>
              <reply xmlns='urn:xmpp:reply:0'/>
            </message>
            """
        )
        await self.gateway.handle_stanza(stanza)
        response = self.wire.sent[0]
        self.assertEqual("bad-request", error_condition(response))
        self.assertNotIn("private body", ET.tostring(response, encoding="unicode"))

    async def test_backend_unavailable_is_normalized(self) -> None:
        self.router.failure = FeatureUnavailable("provider private detail")
        stanza = ET.fromstring(
            """
            <message from='user@example.com/device'
                     to='chat-123@telegram.example.com' type='chat' id='client-1'>
              <body>Hello</body>
            </message>
            """
        )
        await self.gateway.handle_stanza(stanza)
        xml = ET.tostring(self.wire.sent[0], encoding="unicode")
        self.assertEqual("service-unavailable", error_condition(self.wire.sent[0]))
        self.assertNotIn("provider private detail", xml)

    async def test_delivers_incoming_message_to_binding_owner(self) -> None:
        message = IncomingMessage(
            id=RemoteObjectId("remote-message-1"),
            binding_id=BindingId("binding-1"),
            conversation_id=RemoteObjectId("123"),
            sender_id=RemoteObjectId("123"),
            occurred_at=datetime.now(timezone.utc),
            text="Incoming",
        )
        await self.gateway.deliver_message(message)
        stanza = self.wire.sent[0]
        self.assertEqual("chat-123@telegram.example.com", stanza.attrib["from"])
        self.assertEqual("user@example.com", stanza.attrib["to"])

    async def test_incoming_message_requires_active_owner(self) -> None:
        self.bindings.owner = None
        message = IncomingMessage(
            id=RemoteObjectId("remote-message-1"),
            binding_id=BindingId("binding-1"),
            conversation_id=RemoteObjectId("123"),
            sender_id=RemoteObjectId("123"),
            occurred_at=datetime.now(timezone.utc),
            text="Incoming",
        )
        with self.assertRaises(LookupError):
            await self.gateway.deliver_message(message)

    async def test_delivers_group_self_message_as_fake_outgoing(self) -> None:
        # Exercise the separately configured delivery sink used by composition.
        from xmpp_transport.adapters.xmpp.gateway import XmppMessageDelivery

        sink = XmppMessageDelivery(
            self.wire,
            ContactAddressCodec("max.example.com"),
            self.bindings,
            XmppMessageCodec(),
            server_domain="example.com",
            control_jid="bot@max.example.com",
            transport_namespace="urn:xabber:transport:max:1",
            group_localpart_prefix="maxg",
            member_fallback_prefix="max",
        )
        message = IncomingMessage(
            id=RemoteObjectId("group-message-1"),
            binding_id=BindingId("binding-1"),
            conversation_id=RemoteObjectId("888"),
            sender_id=RemoteObjectId("100"),
            occurred_at=datetime.now(timezone.utc),
            text="Sent from MAX",
            attributes={"is_group": "true", "is_self": "true"},
        )

        await sink.deliver_message(message)

        stanza = self.wire.sent[0]
        self.assertEqual("bot@max.example.com", stanza.attrib["from"])
        self.assertEqual(
            "maxg-75736572406578616d706c652e636f6d-888@example.com",
            stanza.attrib["to"],
        )
        self.assertIsNotNone(stanza.find("{{{}}}markable".format(CHAT_MARKERS_NS)))
        self.assertIsNotNone(
            stanza.find("{urn:xabber:transport:max:1}fake-outgoing")
        )

    async def test_delivers_group_self_reply_with_xabber_reference(self) -> None:
        from xmpp_transport.adapters.xmpp.gateway import XmppMessageDelivery

        sink = XmppMessageDelivery(
            self.wire, ContactAddressCodec("max.example.com"), self.bindings,
            XmppMessageCodec(), server_domain="example.com",
            control_jid="bot@max.example.com",
            transport_namespace="urn:xabber:transport:max:1",
            group_localpart_prefix="maxg", member_fallback_prefix="max",
        )
        message = IncomingMessage(
            id=RemoteObjectId("reply-1"), binding_id=BindingId("binding-1"),
            conversation_id=RemoteObjectId("888"), sender_id=RemoteObjectId("100"),
            occurred_at=datetime.now(timezone.utc), text="Ответ",
            reply_to=ReplyReference(
                RemoteObjectId("original-1"), body="Исходное & сообщение",
                sender_id=RemoteObjectId("100"), is_self=True,
            ),
            attributes={"is_group": "true", "is_self": "true", "owner_remote_id": "100"},
        )

        await sink.deliver_message(message)

        stanza = self.wire.sent[0]
        fallback = "> bot@max.example.com:\n> Исходное & сообщение\n"
        self.assertEqual("bot@max.example.com", stanza.attrib["from"])
        self.assertEqual(fallback + "Ответ", stanza.findtext("body"))
        self.assertEqual("original-1", stanza.find("{%s}reply" % REPLY_NS).attrib["id"])
        reference = stanza.find("{%s}reference" % XABBER_REFERENCES_NS)
        self.assertEqual("mutable", reference.attrib["type"])
        self.assertEqual("0", reference.attrib["begin"])
        from html import escape
        self.assertEqual(
            str(len(escape(fallback, quote=False).encode("utf-16-le")) // 2),
            reference.attrib["end"],
        )
        inner = reference.find("{%s}forwarded/{%s}message" % (FORWARDED_NS, CLIENT_NS))
        self.assertEqual("original-1", inner.attrib["id"])
        self.assertEqual("bot@max.example.com", inner.attrib["from"])
        self.assertEqual(stanza.attrib["to"], inner.attrib["to"])
        self.assertEqual("Исходное & сообщение", inner.findtext("{%s}body" % CLIENT_NS))
        self.assertIsNotNone(inner.find("{urn:xabber:transport:max:1}fake-outgoing"))

    async def test_delivers_group_message_from_virtual_member_contact(self) -> None:
        from xmpp_transport.adapters.xmpp.gateway import XmppMessageDelivery

        sink = XmppMessageDelivery(
            self.wire,
            ContactAddressCodec("max.example.com"),
            self.bindings,
            XmppMessageCodec(),
            server_domain="example.com",
            control_jid="bot@max.example.com",
            transport_namespace="urn:xabber:transport:max:1",
            group_localpart_prefix="maxg",
            member_fallback_prefix="max",
        )
        message = IncomingMessage(
            id=RemoteObjectId("group-message-2"),
            binding_id=BindingId("binding-1"),
            conversation_id=RemoteObjectId("888"),
            sender_id=RemoteObjectId("7"),
            occurred_at=datetime.now(timezone.utc),
            text="Incoming from member",
            attributes={
                "is_group": "true",
                "is_self": "false",
                "owner_remote_id": "100",
            },
        )

        await sink.deliver_message(message)

        stanza = self.wire.sent[0]
        self.assertEqual("chat-99@max.example.com", stanza.attrib["from"])
        self.assertEqual(
            "maxg-75736572406578616d706c652e636f6d-888@example.com",
            stanza.attrib["to"],
        )
        self.assertIsNotNone(stanza.find("{{{}}}markable".format(CHAT_MARKERS_NS)))
        self.assertIsNone(stanza.find("{urn:xabber:transport:max:1}fake-outgoing"))


class ComponentSettingsTests(unittest.TestCase):
    def test_secret_is_hidden_from_repr(self) -> None:
        settings = ComponentSettings("telegram.example.com", "super-secret")
        self.assertNotIn("super-secret", repr(settings))


if __name__ == "__main__":
    unittest.main()
