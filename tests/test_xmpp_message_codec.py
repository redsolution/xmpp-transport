import unittest
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

from xmpp_transport.adapters.xmpp.message_codec import XmppMessageCodec, XmppMessageError
from xmpp_transport.adapters.xmpp.namespaces import (
    BOT_UI_NS,
    DATA_FORMS_NS,
    DELAY_NS,
    FILES_NS,
    REPLY_NS,
    SID_NS,
    STANZAS_NS,
    THUMBS_NS,
    VOICE_MESSAGES_NS,
)
from xmpp_transport.adapters.xmpp.auth_commands import (
    ControlButton,
    ControlForm,
    ControlFormField,
    ControlResponse,
)
from xmpp_transport.domain.errors import InvalidCommand
from xmpp_transport.domain.identifiers import BindingId, RemoteObjectId
from xmpp_transport.domain.models import (
    ForwardReference,
    IncomingMessage,
    Media,
    MediaKind,
    MessageButton,
    ReplyReference,
)


def _escaped_length(value: str) -> int:
    from html import escape

    return len(escape(value, quote=False).encode("utf-16-le")) // 2


def tag(namespace: str, name: str) -> str:
    return "{{{}}}{}".format(namespace, name)


class ParseOutgoingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.codec = XmppMessageCodec()
        self.binding_id = BindingId("binding-1")
        self.conversation_id = RemoteObjectId("opaque-conversation")

    def test_parses_direct_text_and_prefers_origin_id(self) -> None:
        stanza = ET.fromstring(
            """
            <message xmlns='jabber:client' type='chat' id='server-copy-id'>
              <body>Hello</body>
              <origin-id xmlns='urn:xmpp:sid:0' id='client-stable-id'/>
            </message>
            """
        )
        message = self.codec.parse_outgoing(
            stanza, self.binding_id, self.conversation_id
        )
        self.assertEqual("client-stable-id", message.client_message_id)
        self.assertEqual("Hello", message.text)

    def test_parses_body_from_component_accept_stanza(self) -> None:
        stanza = ET.fromstring(
            """
            <message xmlns='jabber:component:accept'
                     from='user@example.com/device'
                     to='chat-123@max.example.com'
                     type='chat' id='client-component-1'>
              <body>Hello from Xabber</body>
            </message>
            """
        )
        message = self.codec.parse_outgoing(
            stanza, self.binding_id, self.conversation_id
        )
        self.assertEqual("client-component-1", message.client_message_id)
        self.assertEqual("Hello from Xabber", message.text)

    def test_parses_standard_reply_reference(self) -> None:
        stanza = ET.fromstring(
            """
            <message type='chat' id='message-1'>
              <body>Reply</body>
              <reply xmlns='urn:xmpp:reply:0' id='remote-message-1'/>
            </message>
            """
        )
        message = self.codec.parse_outgoing(
            stanza, self.binding_id, self.conversation_id
        )
        self.assertEqual(
            ReplyReference(RemoteObjectId("remote-message-1")), message.reply_to
        )

    def test_rejects_missing_stable_identifier(self) -> None:
        stanza = ET.fromstring("<message type='chat'><body>Hello</body></message>")
        with self.assertRaises(InvalidCommand):
            self.codec.parse_outgoing(stanza, self.binding_id, self.conversation_id)

    def test_parses_xabber_file_sharing_and_strips_url_fallback(self) -> None:
        stanza = ET.fromstring(
            """
            <message type='chat' id='media-1'>
              <body>caption
https://xabber.example/upload/photo.jpg</body>
              <reference xmlns='https://xabber.com/protocol/references' type='mutable'>
                <file-sharing xmlns='https://xabber.com/protocol/files'>
                  <file><media-type>image/jpeg</media-type><name>photo.jpg</name>
                    <size>123</size><width>640</width><height>480</height></file>
                  <sources><uri>https://xabber.example/upload/photo.jpg</uri></sources>
                </file-sharing>
              </reference>
            </message>
            """
        )
        message = self.codec.parse_outgoing(stanza, self.binding_id, self.conversation_id)
        self.assertEqual("caption", message.text)
        self.assertEqual("https://xabber.example/upload/photo.jpg", message.media[0].source_url)
        self.assertEqual("photo.jpg", message.media[0].file_name)
        self.assertEqual((640, 480), (message.media[0].width, message.media[0].height))

    def test_parses_media_only_voice_message(self) -> None:
        stanza = ET.fromstring(
            """
            <message type='chat' id='voice-1'>
              <reference xmlns='https://xabber.com/protocol/references' type='mutable'>
                <voice-message xmlns='https://xabber.com/protocol/voice-messages'>
                  <file-sharing xmlns='https://xabber.com/protocol/files'>
                    <file><media-type>audio/ogg; codecs=opus</media-type>
                      <name>voice.ogg</name><duration>3</duration></file>
                    <sources><uri>https://xabber.example/upload/voice.ogg</uri></sources>
                  </file-sharing>
                </voice-message>
              </reference>
            </message>
            """
        )
        message = self.codec.parse_outgoing(stanza, self.binding_id, self.conversation_id)
        self.assertIsNone(message.text)
        self.assertTrue(message.media[0].voice)
        self.assertEqual(3, message.media[0].duration)

    def test_parses_xabber_forward_reference(self) -> None:
        fallback = "> chat-11@max.example:\n> Forwarded text\n"
        stanza = ET.fromstring(
            """
            <message type='chat' id='forward-1' to='chat-22@max.example'>
              <body>{fallback}comment</body>
              <reference xmlns='https://xabber.com/protocol/references'
                         type='mutable' begin='0' end='{end}'>
                <forwarded xmlns='urn:xmpp:forward:0'>
                  <message xmlns='jabber:client' from='chat-11@max.example'
                           to='user@example' id='116974846586354125'>
                    <body>Forwarded text</body>
                  </message>
                </forwarded>
              </reference>
            </message>
            """.format(fallback=fallback, end=_escaped_length(fallback))
        )
        message = self.codec.parse_outgoing(stanza, self.binding_id, self.conversation_id)
        self.assertEqual("comment", message.text)
        self.assertEqual("chat-11@max.example", message.forwarded_from.source_name)
        self.assertEqual(
            RemoteObjectId("116974846586354125"),
            message.forwarded_from.source_message_id,
        )

    def test_parses_own_forward_with_origin_id_before_server_stanza_id(self) -> None:
        fallback = "> user@example.com:\n> Own message\n"
        stanza = ET.fromstring(
            """
            <message from='user@example.com/phone' to='chat-22@max.example.com'
                     type='chat' id='forward-1'>
              <body>{fallback}</body>
              <reference xmlns='https://xabber.com/protocol/references'
                         type='mutable' begin='0' end='{end}'>
                <forwarded xmlns='urn:xmpp:forward:0'>
                  <message xmlns='jabber:client' from='user@example.com/phone'
                           to='chat-11@max.example.com' id='server-copy-id'>
                    <origin-id xmlns='urn:xmpp:sid:0' id='original-client-id'/>
                    <stanza-id xmlns='urn:xmpp:sid:0' id='archive-id'/>
                    <body>Own message</body>
                  </message>
                </forwarded>
              </reference>
            </message>
            """.format(fallback=fallback, end=_escaped_length(fallback))
        )

        message = self.codec.parse_outgoing(stanza, self.binding_id, self.conversation_id)

        self.assertTrue(message.forwarded_from.is_self)
        self.assertEqual("Own message", message.forwarded_from.body)
        self.assertEqual(
            RemoteObjectId("server-copy-id"), message.forwarded_from.source_message_id
        )
        self.assertEqual(
            (RemoteObjectId("original-client-id"), RemoteObjectId("server-copy-id"),
             RemoteObjectId("archive-id")),
            message.forwarded_from.source_message_ids,
        )

    def test_rejects_empty_body(self) -> None:
        stanza = ET.fromstring("<message type='chat' id='1'><body> </body></message>")
        with self.assertRaises(InvalidCommand):
            self.codec.parse_outgoing(stanza, self.binding_id, self.conversation_id)

    def test_rejects_groupchat_on_direct_path(self) -> None:
        stanza = ET.fromstring(
            "<message type='groupchat' id='1'><body>Hello</body></message>"
        )
        with self.assertRaises(InvalidCommand):
            self.codec.parse_outgoing(stanza, self.binding_id, self.conversation_id)

    def test_rejects_oversized_body(self) -> None:
        stanza = ET.Element("message", {"type": "chat", "id": "1"})
        ET.SubElement(stanza, "body").text = "x" * (self.codec.MAX_BODY_LENGTH + 1)
        with self.assertRaises(InvalidCommand):
            self.codec.parse_outgoing(stanza, self.binding_id, self.conversation_id)


class SerializeIncomingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.codec = XmppMessageCodec()

    def test_serializes_incoming_max_forward_reference(self) -> None:
        message = IncomingMessage(
            id=RemoteObjectId("outer-1"),
            binding_id=BindingId("binding-1"),
            conversation_id=RemoteObjectId("22"),
            sender_id=RemoteObjectId("33"),
            occurred_at=datetime.now(timezone.utc),
            text="comment",
            forwarded_from=ForwardReference(
                source_message_id=RemoteObjectId("inner-1"),
                source_conversation_id=RemoteObjectId("11"),
                sender_id=RemoteObjectId("44"),
                body="Forwarded text",
            ),
        )
        stanza = self.codec.serialize_incoming(
            message, "chat-33@max.example", "user@example"
        )
        reference = stanza.find(tag("https://xabber.com/protocol/references", "reference"))
        forwarded = reference.find(tag("urn:xmpp:forward:0", "forwarded"))
        inner = forwarded.find(tag("jabber:client", "message"))
        self.assertEqual("inner-1", inner.attrib["id"])
        self.assertEqual("Forwarded text", inner.findtext(tag("jabber:client", "body")))

    def test_serializes_body_origin_reply_and_utc_delay(self) -> None:
        message = IncomingMessage(
            id=RemoteObjectId("remote-message-1"),
            binding_id=BindingId("binding-1"),
            conversation_id=RemoteObjectId("conversation-1"),
            sender_id=RemoteObjectId("sender-1"),
            occurred_at=datetime(2026, 9, 28, 8, 30, tzinfo=timezone.utc),
            text="Hello",
            reply_to=ReplyReference(RemoteObjectId("remote-parent-1")),
        )
        stanza = self.codec.serialize_incoming(
            message, "contact@transport.example", "user@example.com"
        )
        self.assertEqual("chat", stanza.attrib["type"])
        self.assertEqual("Hello", stanza.find("body").text)
        self.assertEqual(
            "remote-message-1", stanza.find(tag(SID_NS, "origin-id")).attrib["id"]
        )
        self.assertEqual(
            "remote-parent-1", stanza.find(tag(REPLY_NS, "reply")).attrib["id"]
        )
        self.assertEqual(
            "2026-09-28T08:30:00Z", stanza.find(tag(DELAY_NS, "delay")).attrib["stamp"]
        )

    def test_rejects_missing_addresses(self) -> None:
        message = IncomingMessage(
            id=RemoteObjectId("remote-message-1"),
            binding_id=BindingId("binding-1"),
            conversation_id=RemoteObjectId("conversation-1"),
            sender_id=RemoteObjectId("sender-1"),
            occurred_at=datetime.now(timezone.utc),
            text="Hello",
        )
        with self.assertRaises(ValueError):
            self.codec.serialize_incoming(message, "", "user@example.com")

    def test_serializes_max_message_buttons_with_callback_fallback(self) -> None:
        message = IncomingMessage(
            id=RemoteObjectId("remote-message-1"),
            binding_id=BindingId("binding-1"),
            conversation_id=RemoteObjectId("conversation-1"),
            sender_id=RemoteObjectId("sender-1"),
            occurred_at=datetime.now(timezone.utc),
            text="Confirm?",
            buttons=((MessageButton("OK", "confirm", "callback-1"),),),
        )

        stanza = self.codec.serialize_incoming(
            message, "chat-1@max.example.com", "user@example.com"
        )

        self.assertIn("/confirm - OK", stanza.findtext("body"))
        button = stanza.find(".//{{{}}}button".format(BOT_UI_NS))
        self.assertEqual(
            {"id": "confirm", "type": "callback", "label": "OK", "data": "confirm"},
            button.attrib,
        )

    def test_serializes_incoming_image_as_xabber_file_sharing(self) -> None:
        message = IncomingMessage(
            id=RemoteObjectId("remote-message-1"),
            binding_id=BindingId("binding-1"),
            conversation_id=RemoteObjectId("conversation-1"),
            sender_id=RemoteObjectId("sender-1"),
            occurred_at=datetime.now(timezone.utc),
            text="Hi 😀 & <tag>",
            media=(
                Media(
                    id=RemoteObjectId("media-1"),
                    kind=MediaKind.IMAGE,
                    content_type="image/jpeg",
                    file_name="photo.jpg",
                    size=211834,
                    source_url="https://i.oneme.ru/i?r=a&x=😀",
                    thumbnail_url="https://i.oneme.ru/thumb?r=a&x=😀",
                    width=1280,
                    height=960,
                ),
            ),
        )

        stanza = self.codec.serialize_incoming(
            message, "chat-1@max.example.com", "user@example.com"
        )

        self.assertEqual(
            "Hi 😀 & <tag>\nhttps://i.oneme.ru/i?r=a&x=😀",
            stanza.findtext("body"),
        )
        reference = stanza.find("{https://xabber.com/protocol/references}reference")
        self.assertEqual(("24", "57"), (reference.attrib["begin"], reference.attrib["end"]))
        sharing = reference.find("{{{}}}file-sharing".format(FILES_NS))
        self.assertEqual("photo.jpg", sharing.findtext("file/name"))
        self.assertEqual("1280", sharing.findtext("file/width"))
        thumbnail = sharing.find("file/{{{}}}thumbnail".format(THUMBS_NS))
        self.assertEqual("https://i.oneme.ru/thumb?r=a&x=😀", thumbnail.attrib["uri"])
        self.assertEqual(
            "https://i.oneme.ru/i?r=a&x=😀", sharing.findtext("sources/uri")
        )

    def test_wraps_voice_media_in_voice_message(self) -> None:
        message = IncomingMessage(
            id=RemoteObjectId("remote-message-1"),
            binding_id=BindingId("binding-1"),
            conversation_id=RemoteObjectId("conversation-1"),
            sender_id=RemoteObjectId("sender-1"),
            occurred_at=datetime.now(timezone.utc),
            media=(
                Media(
                    id=RemoteObjectId("voice-1"),
                    kind=MediaKind.AUDIO,
                    content_type="audio/ogg; codecs=opus",
                    file_name="voice.ogg",
                    source_url="https://cdn.example/voice.ogg",
                    duration=4,
                    voice=True,
                ),
            ),
        )

        stanza = self.codec.serialize_incoming(
            message, "chat-1@max.example.com", "user@example.com"
        )

        voice = stanza.find(
            ".//{{{}}}voice-message".format(VOICE_MESSAGES_NS)
        )
        self.assertIsNotNone(voice)
        self.assertIsNotNone(voice.find("{{{}}}file-sharing".format(FILES_NS)))

    def test_builds_client_safe_error_without_reflecting_body(self) -> None:
        request = ET.fromstring(
            """
            <message from='user@example.com/device' to='contact@transport.example'
                     id='message-1' type='chat'>
              <body>private message body</body>
            </message>
            """
        )
        response = self.codec.error_reply(
            request, XmppMessageError.SERVICE_UNAVAILABLE, "Transport unavailable"
        )
        xml = ET.tostring(response, encoding="unicode")
        self.assertEqual("error", response.attrib["type"])
        self.assertEqual("contact@transport.example", response.attrib["from"])
        self.assertEqual("user@example.com/device", response.attrib["to"])
        self.assertIsNotNone(
            response.find("error/" + tag(STANZAS_NS, "service-unavailable"))
        )
        self.assertNotIn("private message body", xml)

    def test_serializes_bot_ui_keyboard_and_private_form(self) -> None:
        request = ET.Element(
            "message", {"from": "user@example.com", "to": "bot@max.example.com"}
        )
        response = self.codec.control_reply(
            request,
            ControlResponse(
                "MAX bot",
                buttons=((ControlButton("Статус", "/status"),),),
                forms=(
                    ControlForm(
                        "Пароль MAX 2FA",
                        "Введите пароль",
                        (
                            ControlFormField(
                                "password",
                                label="Пароль",
                                type="text-private",
                                required=True,
                            ),
                        ),
                    ),
                ),
            ),
        )

        button = response.find(
            ".//{{{}}}button".format(BOT_UI_NS)
        )
        self.assertEqual("/status", button.attrib["data"])
        field = response.find("{{{}}}x/{{{}}}field".format(DATA_FORMS_NS, DATA_FORMS_NS))
        self.assertEqual("text-private", field.attrib["type"])
        self.assertIsNotNone(field.find("{{{}}}required".format(DATA_FORMS_NS)))


if __name__ == "__main__":
    unittest.main()
