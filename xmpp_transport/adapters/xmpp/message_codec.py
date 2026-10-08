"""Provider-neutral XML codec for direct text messages.

This adapter accepts and returns stdlib XML elements. slixmpp stanza objects are
unwrapped only at the future component boundary, keeping them out of application
and domain layers.
"""

import hashlib
import mimetypes
import re
from datetime import timezone
from enum import Enum
from html import escape
from typing import TYPE_CHECKING, Optional
from urllib.parse import unquote, urlsplit
from xml.etree import ElementTree as ET

from xmpp_transport.domain.errors import InvalidCommand
from xmpp_transport.domain.identifiers import BindingId, RemoteObjectId
from xmpp_transport.domain.models import (
    IncomingMessage,
    ForwardReference,
    Media,
    MediaKind,
    MessageButton,
    OutgoingMessage,
    ReplyReference,
)

from .namespaces import (
    CLIENT_NS,
    BOT_UI_NS,
    CHAT_MARKERS_NS,
    COMPONENT_ACCEPT_NS,
    DELAY_NS,
    DATA_FORMS_NS,
    FILES_NS,
    FORWARDED_NS,
    REPLY_NS,
    SID_NS,
    STANZAS_NS,
    THUMBS_NS,
    VOICE_MESSAGES_NS,
    XABBER_REFERENCES_NS,
)

if TYPE_CHECKING:
    from .auth_commands import ControlResponse


class XmppMessageError(str, Enum):
    BAD_REQUEST = "bad-request"
    FEATURE_NOT_IMPLEMENTED = "feature-not-implemented"
    SERVICE_UNAVAILABLE = "service-unavailable"


class XmppMessageCodec:
    MAX_BODY_LENGTH = 65536
    MAX_ID_LENGTH = 512
    BUTTON_COMMAND_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")

    def parse_outgoing(
        self,
        element: ET.Element,
        binding_id: BindingId,
        conversation_id: RemoteObjectId,
    ) -> OutgoingMessage:
        if _local_name(element.tag) != "message":
            raise InvalidCommand("expected an XMPP message stanza")
        message_type = element.attrib.get("type", "normal")
        if message_type not in ("chat", "normal"):
            raise InvalidCommand("unsupported XMPP message type")

        client_message_id = self._client_message_id(element)
        body = self._body(element)
        forwarded_from, forward_range = self._outgoing_forward(element)
        if forward_range is not None:
            body = _strip_escaped_ranges(body, (forward_range,)).strip()
        media = self._outgoing_media(element, body)
        if forwarded_from is not None:
            media = tuple(forwarded_from.media)
        for item in media:
            if item.source_url:
                body = "\n".join(
                    line for line in body.splitlines() if line.strip() != item.source_url
                )
        body = body.strip()
        if not body and not media and forwarded_from is None:
            raise InvalidCommand("message must contain text or media")
        reply = self._reply(element)
        return OutgoingMessage(
            client_message_id=client_message_id,
            binding_id=binding_id,
            conversation_id=conversation_id,
            text=body or None,
            media=media,
            reply_to=reply,
            forwarded_from=forwarded_from,
        )

    def serialize_incoming(
        self,
        message: IncomingMessage,
        from_jid: str,
        to_jid: str,
    ) -> ET.Element:
        message_id = _bounded_id(str(message.id), self.MAX_ID_LENGTH)
        element = ET.Element(
            "message",
            {
                "from": _required_address(from_jid, "from_jid"),
                "to": _required_address(to_jid, "to_jid"),
                "type": "chat",
                "id": message_id,
            },
        )
        body, forward_range = self._body_with_forward(
            message.text or "", message.forwarded_from, from_jid, to_jid
        )
        outer_media = () if message.forwarded_from is not None else message.media
        body, media_ranges = self._body_with_media(body, outer_media)
        body, button_range = self._body_with_buttons(body, message.buttons)
        if body and len(body) > self.MAX_BODY_LENGTH:
            raise ValueError("incoming text message body is too large")
        if body:
            ET.SubElement(element, "body").text = body
        ET.SubElement(element, _tag(SID_NS, "origin-id"), {"id": message_id})
        if message.reply_to is not None:
            ET.SubElement(
                element,
                _tag(REPLY_NS, "reply"),
                {"id": _bounded_id(str(message.reply_to.message_id), self.MAX_ID_LENGTH)},
            )
        occurred_at = message.occurred_at
        if occurred_at.tzinfo is None:
            occurred_at = occurred_at.replace(tzinfo=timezone.utc)
        stamp = occurred_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        ET.SubElement(element, _tag(DELAY_NS, "delay"), {"stamp": stamp})
        for media, begin, end in media_ranges:
            self._append_media_reference(element, media, begin, end)
        if forward_range is not None and message.forwarded_from is not None:
            self._append_forward_reference(
                element,
                message.forwarded_from,
                forward_range,
                from_jid,
                to_jid,
            )
        if button_range is not None:
            self._append_message_keyboard(element, message.buttons, button_range)
        return element

    def _body_with_forward(
        self,
        body: str,
        reference: Optional[ForwardReference],
        from_jid: str,
        to_jid: str,
    ) -> tuple[str, Optional[tuple[int, int]]]:
        if reference is None:
            return body, None
        sender, _recipient = self._forward_addresses(reference, from_jid, to_jid)
        parts = []
        if reference.body:
            parts.append(reference.body.strip())
        for media in reference.media:
            if media.source_url and media.source_url not in parts:
                parts.append(media.source_url)
        quoted = "\n".join("> {}".format(line) if line else ">" for line in "\n".join(parts).splitlines())
        fallback = "> {}:\n{}\n".format(sender, quoted)
        return fallback + body, (0, _escaped_text_length(fallback))

    def _append_forward_reference(
        self,
        element: ET.Element,
        reference: ForwardReference,
        body_range: tuple[int, int],
        from_jid: str,
        to_jid: str,
    ) -> None:
        sender, recipient = self._forward_addresses(reference, from_jid, to_jid)
        outer = ET.SubElement(
            element,
            _tag(XABBER_REFERENCES_NS, "reference"),
            {"type": "mutable", "begin": str(body_range[0]), "end": str(body_range[1])},
        )
        forwarded = ET.SubElement(outer, _tag(FORWARDED_NS, "forwarded"))
        message_id = str(reference.source_message_id or "")
        inner = ET.SubElement(
            forwarded,
            _tag(CLIENT_NS, "message"),
            {"from": sender, "to": recipient, "type": "chat", "id": message_id},
        )
        if message_id:
            ET.SubElement(inner, _tag(SID_NS, "origin-id"), {"id": message_id})
        inner_body, ranges = self._body_with_media(reference.body or "", reference.media)
        ET.SubElement(inner, _tag(CLIENT_NS, "body")).text = inner_body
        for media, begin, end in ranges:
            self._append_media_reference(inner, media, begin, end)

    @staticmethod
    def _forward_addresses(
        reference: ForwardReference, from_jid: str, to_jid: str
    ) -> tuple[str, str]:
        domain = from_jid.split("@", 1)[-1]
        sender = reference.source_name or (
            to_jid
            if reference.is_self
            else "chat-{}@{}".format(reference.sender_id or "unknown", domain)
        )
        recipient = reference.source_recipient or (
            "chat-{}@{}".format(reference.source_conversation_id, domain)
            if reference.source_conversation_id is not None
            else to_jid
        )
        return sender, recipient

    def _body_with_buttons(
        self, body: str, buttons  # type: ignore[no-untyped-def]
    ) -> tuple[str, Optional[tuple[int, int]]]:
        lines = []
        for row_index, row in enumerate(buttons):
            for button_index, button in enumerate(row):
                command = self._message_button_command(button, row_index, button_index)
                action = (
                    "/{}".format(command)
                    if self._message_button_type(button) == "callback"
                    else button.payload.strip() or "/{}".format(command)
                )
                if button.text.strip() and action:
                    lines.append("{} - {}".format(action, button.text.strip()))
        if not lines:
            return body, None
        result = body.rstrip()
        if result:
            result += "\n\n"
        begin = _escaped_text_length(result)
        fallback = "Команды кнопок:\n" + "\n".join(lines)
        return result + fallback, (begin, begin + _escaped_text_length(fallback))

    @staticmethod
    def _body_with_media(body, media):  # type: ignore[no-untyped-def]
        ranges = []
        items = tuple(item for item in media if item.source_url)
        result = body
        if items and result and not result.endswith("\n"):
            result += "\n"
        for index, item in enumerate(items):
            begin = _escaped_text_length(result)
            fallback = (
                item.file_name or "attachment"
                if item.source_url.startswith("data:")
                else item.source_url
            )
            result += fallback
            end = _escaped_text_length(result)
            ranges.append((item, begin, end))
            if index != len(items) - 1:
                result += "\n"
        return result, ranges

    @staticmethod
    def _append_media_reference(element, media, begin, end):  # type: ignore[no-untyped-def]
        reference = ET.SubElement(
            element,
            _tag(XABBER_REFERENCES_NS, "reference"),
            {"type": "mutable", "begin": str(begin), "end": str(end)},
        )
        parent = reference
        if media.voice:
            parent = ET.SubElement(reference, _tag(VOICE_MESSAGES_NS, "voice-message"))
        sharing = ET.SubElement(parent, _tag(FILES_NS, "file-sharing"))
        file_element = ET.SubElement(sharing, "file")
        fields = (
            ("media-type", media.content_type),
            ("name", media.file_name),
            ("size", media.size),
            ("height", media.height),
            ("width", media.width),
            ("duration", media.duration),
        )
        for name, value in fields:
            if value is not None and value != "" and not (
                isinstance(value, int) and value <= 0
            ):
                ET.SubElement(file_element, name).text = str(value)
        if media.thumbnail_url:
            ET.SubElement(
                file_element,
                _tag(THUMBS_NS, "thumbnail"),
                {"uri": media.thumbnail_url},
            )
        sources = ET.SubElement(sharing, "sources")
        ET.SubElement(sources, "uri").text = media.source_url

    def _append_message_keyboard(
        self,
        element: ET.Element,
        buttons,  # type: ignore[no-untyped-def]
        body_range: tuple[int, int],
    ) -> None:
        reference = ET.SubElement(
            element,
            _tag(XABBER_REFERENCES_NS, "reference"),
            {
                "type": "mutable",
                "begin": str(body_range[0]),
                "end": str(body_range[1]),
            },
        )
        keyboard = ET.SubElement(reference, _tag(BOT_UI_NS, "keyboard"), {"type": "inline"})
        for row_index, row in enumerate(buttons):
            row_element = ET.SubElement(keyboard, _tag(BOT_UI_NS, "row"))
            for button_index, button in enumerate(row):
                command = self._message_button_command(button, row_index, button_index)
                ET.SubElement(
                    row_element,
                    _tag(BOT_UI_NS, "button"),
                    {
                        "id": command,
                        "type": self._message_button_type(button),
                        "label": button.text.strip(),
                        "data": button.payload.strip() or "/{}".format(command),
                    },
                )

    @classmethod
    def _message_button_command(
        cls, button: MessageButton, row_index: int, button_index: int
    ) -> str:
        payload = button.payload.strip()
        if payload.startswith("/"):
            payload = payload[1:].strip()
        if cls.BUTTON_COMMAND_RE.fullmatch(payload):
            return payload
        return "button_{}_{}".format(row_index + 1, button_index + 1)

    @staticmethod
    def _message_button_type(button: MessageButton) -> str:
        kind = button.kind.strip().lower()
        if kind == "url":
            return "url"
        if kind in ("command", "webapp"):
            return kind
        return "callback" if kind or button.callback_id else "command"

    def serialize_group_message(
        self,
        message: IncomingMessage,
        from_jid: str,
        group_jid: str,
        transport_namespace: Optional[str] = None,
        fake_outgoing: bool = False,
    ) -> ET.Element:
        """Render an incoming provider message through the Xabber group protocol."""
        element = self.serialize_incoming(message, from_jid, group_jid)
        message_id = element.attrib["id"]
        ET.SubElement(element, _tag(CHAT_MARKERS_NS, "markable"))
        if fake_outgoing:
            if not transport_namespace:
                raise ValueError("transport namespace is required for fake outgoing")
            # Prevent a synthetic self-message from being sent back to the provider.
            ET.SubElement(element, _tag(transport_namespace, "fake-outgoing"))
        origin = element.find(_tag(SID_NS, "origin-id"))
        if origin is None:
            ET.SubElement(element, _tag(SID_NS, "origin-id"), {"id": message_id})
        return element

    def error_reply(
        self,
        request: ET.Element,
        condition: XmppMessageError,
        public_text: Optional[str] = None,
    ) -> ET.Element:
        attributes = {"type": "error"}
        if request.attrib.get("to"):
            attributes["from"] = request.attrib["to"]
        if request.attrib.get("from"):
            attributes["to"] = request.attrib["from"]
        request_id = request.attrib.get("id")
        if request_id:
            attributes["id"] = _bounded_id(request_id, self.MAX_ID_LENGTH)
        response = ET.Element("message", attributes)
        error = ET.SubElement(response, "error", {"type": _error_type(condition)})
        ET.SubElement(error, _tag(STANZAS_NS, condition.value))
        if public_text:
            ET.SubElement(error, _tag(STANZAS_NS, "text")).text = public_text
        return response

    def text_reply(self, request: ET.Element, text: str) -> ET.Element:
        if not text or len(text) > self.MAX_BODY_LENGTH:
            raise ValueError("reply text is invalid")
        attributes = {"type": "chat"}
        if request.attrib.get("to"):
            attributes["from"] = request.attrib["to"]
        if request.attrib.get("from"):
            attributes["to"] = request.attrib["from"]
        request_id = request.attrib.get("id")
        if request_id:
            attributes["id"] = _bounded_id(request_id, self.MAX_ID_LENGTH)
        response = ET.Element("message", attributes)
        ET.SubElement(response, "body").text = text
        return response

    def control_reply(self, request: ET.Element, reply: "ControlResponse") -> ET.Element:
        body = reply.body
        media_ranges = []
        for media in reply.media:
            if body and not body.endswith("\n"):
                body += "\n"
            begin = len(body)
            body += media.name
            media_ranges.append((media, begin, len(body)))
        button_range = None
        if reply.buttons:
            lines = []
            for row_index, row in enumerate(reply.buttons):
                for button_index, button in enumerate(row):
                    action = button.data or "/button_{}_{}".format(
                        row_index + 1, button_index + 1
                    )
                    lines.append("{} - {}".format(action, button.label))
            if lines:
                if body:
                    body = body.rstrip() + "\n\n"
                begin = len(escape(body))
                fallback = "Команды кнопок:\n" + "\n".join(lines)
                body += fallback
                button_range = (begin, begin + len(escape(fallback)))
        response = self.text_reply(request, body)
        for media, begin, end in media_ranges:
            reference = ET.SubElement(
                response,
                _tag(XABBER_REFERENCES_NS, "reference"),
                {"type": "mutable", "begin": str(begin), "end": str(end)},
            )
            sharing = ET.SubElement(reference, _tag(FILES_NS, "file-sharing"))
            file_element = ET.SubElement(sharing, "file")
            ET.SubElement(file_element, "media-type").text = media.mime_type
            ET.SubElement(file_element, "name").text = media.name
            ET.SubElement(file_element, "size").text = str(media.size)
            sources = ET.SubElement(sharing, "sources")
            ET.SubElement(sources, "uri").text = media.uri
        if button_range is not None:
            reference = ET.SubElement(
                response,
                _tag(XABBER_REFERENCES_NS, "reference"),
                {
                    "type": "mutable",
                    "begin": str(button_range[0]),
                    "end": str(button_range[1]),
                },
            )
            keyboard = ET.SubElement(reference, _tag(BOT_UI_NS, "keyboard"), {"type": "inline"})
            for row_index, row in enumerate(reply.buttons):
                row_element = ET.SubElement(keyboard, _tag(BOT_UI_NS, "row"))
                for button_index, button in enumerate(row):
                    data = button.data
                    command = data[1:].strip() if data.startswith("/") else data
                    if not command or any(character.isspace() for character in command):
                        command = "button_{}_{}".format(row_index + 1, button_index + 1)
                    ET.SubElement(
                        row_element,
                        _tag(BOT_UI_NS, "button"),
                        {
                            "id": command,
                            "type": button.type,
                            "label": button.label,
                            "data": data,
                        },
                    )
        for form in reply.forms:
            form_element = ET.SubElement(response, _tag(DATA_FORMS_NS, "x"), {"type": "form"})
            ET.SubElement(form_element, _tag(DATA_FORMS_NS, "title")).text = form.title
            ET.SubElement(form_element, _tag(DATA_FORMS_NS, "instructions")).text = form.instructions
            for field in form.fields:
                attributes = {"var": field.name, "type": field.type}
                if field.label:
                    attributes["label"] = field.label
                field_element = ET.SubElement(form_element, _tag(DATA_FORMS_NS, "field"), attributes)
                if field.value:
                    ET.SubElement(field_element, _tag(DATA_FORMS_NS, "value")).text = field.value
                if field.required:
                    ET.SubElement(field_element, _tag(DATA_FORMS_NS, "required"))
        return response

    def control_notice(
        self, from_jid: str, to_jid: str, reply: "ControlResponse"
    ) -> ET.Element:
        request = ET.Element("message", {"from": to_jid, "to": from_jid})
        return self.control_reply(request, reply)

    def _client_message_id(self, element: ET.Element) -> str:
        origin = element.find(_tag(SID_NS, "origin-id"))
        origin_id = origin.attrib.get("id") if origin is not None else None
        candidate = origin_id or element.attrib.get("id")
        if not candidate:
            raise InvalidCommand("message requires id or origin-id")
        return _bounded_id(candidate, self.MAX_ID_LENGTH)

    def _body(self, element: ET.Element) -> str:
        body_element = None
        for child in element:
            if _local_name(child.tag) == "body" and _namespace(child.tag) in (
                "",
                CLIENT_NS,
                COMPONENT_ACCEPT_NS,
            ):
                body_element = child
                break
        body = "" if body_element is None else "".join(body_element.itertext())
        if len(body) > self.MAX_BODY_LENGTH:
            raise InvalidCommand("text message body is too large")
        return body

    def _outgoing_media(self, element: ET.Element, body: str) -> tuple[Media, ...]:
        result = []
        seen = set()
        for reference in element:
            if reference.tag != _tag(XABBER_REFERENCES_NS, "reference"):
                continue
            voice = _child(reference, "voice-message", VOICE_MESSAGES_NS)
            parent = voice if voice is not None else reference
            sharing = _child(parent, "file-sharing", FILES_NS)
            item = self._media_from_file_sharing(sharing, voice is not None)
            if item is not None and item.source_url not in seen:
                seen.add(item.source_url)
                result.append(item)
        for line in body.splitlines():
            item = self._media_from_gallery_url(line.strip())
            if item is not None and item.source_url not in seen:
                seen.add(item.source_url)
                result.append(item)
        return tuple(result)

    def _outgoing_forward(
        self, element: ET.Element
    ) -> tuple[Optional[ForwardReference], Optional[tuple[int, int]]]:
        outer_to = element.attrib.get("to", "").split("/", 1)[0]
        for reference in element:
            if reference.tag != _tag(XABBER_REFERENCES_NS, "reference"):
                continue
            forwarded = _child(reference, "forwarded", FORWARDED_NS)
            if forwarded is None:
                continue
            inner = _child(forwarded, "message", CLIENT_NS)
            if inner is None:
                inner = _child(forwarded, "message")
            if inner is None:
                continue
            inner_from = inner.attrib.get("from", "").split("/", 1)[0]
            inner_to = inner.attrib.get("to", "").split("/", 1)[0]
            if not outer_to or outer_to in (inner_from, inner_to):
                continue
            inner_body = self._body_text(inner)
            media = self._outgoing_media(inner, inner_body)
            for item in media:
                if item.source_url:
                    inner_body = "\n".join(
                        line
                        for line in inner_body.splitlines()
                        if line.strip() != item.source_url
                    )
            origin = inner.find(_tag(SID_NS, "origin-id"))
            message_id = inner.attrib.get("id") or (
                origin.attrib.get("id") if origin is not None else None
            )
            body_range = _reference_range(reference)
            return (
                ForwardReference(
                    source_name=inner_from or None,
                    source_recipient=inner_to or None,
                    source_message_id=(RemoteObjectId(message_id) if message_id else None),
                    body=inner_body.strip() or None,
                    media=media,
                ),
                body_range,
            )
        return None, None

    @staticmethod
    def _body_text(element: ET.Element) -> str:
        for child in element:
            if _local_name(child.tag) == "body":
                return "".join(child.itertext())
        return ""

    @staticmethod
    def _media_from_file_sharing(
        sharing: Optional[ET.Element], voice: bool
    ) -> Optional[Media]:
        if sharing is None:
            return None
        sources = _child(sharing, "sources")
        url = ""
        if sources is not None:
            for child in sources:
                candidate = (child.text or "").strip()
                if _local_name(child.tag) == "uri" and candidate.startswith(
                    ("http://", "https://")
                ):
                    url = candidate
                    break
        if not url:
            return None
        fields = {}
        thumbnail_url = None
        file_element = _child(sharing, "file")
        if file_element is not None:
            for child in file_element:
                name = _local_name(child.tag)
                if name == "thumbnail":
                    thumbnail_url = (child.attrib.get("uri") or "").strip() or None
                else:
                    fields[name] = (child.text or "").strip()
        content_type = (
            fields.get("media-type")
            or fields.get("mime-type")
            or "application/octet-stream"
        )
        kind = _media_kind(content_type, voice)
        return Media(
            id=RemoteObjectId(hashlib.sha256(url.encode("utf-8")).hexdigest()),
            kind=kind,
            content_type=content_type,
            file_name=fields.get("name") or None,
            size=_positive_int(fields.get("size")),
            source_url=url,
            thumbnail_url=thumbnail_url,
            width=_positive_int(fields.get("width")),
            height=_positive_int(fields.get("height")),
            duration=_positive_int(fields.get("duration")),
            voice=voice,
        )

    @staticmethod
    def _media_from_gallery_url(url: str) -> Optional[Media]:
        if not url.startswith(("http://", "https://")):
            return None
        parsed = urlsplit(url)
        if "/gallery/" not in parsed.path and "/upload/" not in parsed.path:
            return None
        name = unquote(parsed.path.rstrip("/").rsplit("/", 1)[-1])
        if not name or "." not in name:
            return None
        content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
        return Media(
            id=RemoteObjectId(hashlib.sha256(url.encode("utf-8")).hexdigest()),
            kind=_media_kind(content_type, False),
            content_type=content_type,
            file_name=name,
            source_url=url,
        )

    def _reply(self, element: ET.Element) -> Optional[ReplyReference]:
        reply = element.find(_tag(REPLY_NS, "reply"))
        if reply is None:
            return None
        reply_id = reply.attrib.get("id")
        if not reply_id:
            raise InvalidCommand("reply element requires an id")
        return ReplyReference(RemoteObjectId(_bounded_id(reply_id, self.MAX_ID_LENGTH)))


def _tag(namespace: str, local_name: str) -> str:
    return "{{{}}}{}".format(namespace, local_name)


def _escaped_text_length(value: str) -> int:
    escaped = escape(value, quote=False)
    return len(escaped.encode("utf-16-le")) // 2


def _child(
    parent: ET.Element, local_name: str, namespace: Optional[str] = None
) -> Optional[ET.Element]:
    for child in parent:
        if _local_name(child.tag) != local_name:
            continue
        if namespace is not None and _namespace(child.tag) != namespace:
            continue
        return child
    return None


def _positive_int(value: object) -> Optional[int]:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _media_kind(content_type: str, voice: bool) -> MediaKind:
    if voice or content_type.startswith("audio/"):
        return MediaKind.AUDIO
    if content_type.startswith("image/"):
        return MediaKind.IMAGE
    if content_type.startswith("video/"):
        return MediaKind.VIDEO
    return MediaKind.FILE


def _reference_range(element: ET.Element) -> Optional[tuple[int, int]]:
    begin = _nonnegative_int(element.attrib.get("begin"))
    end = _nonnegative_int(element.attrib.get("end"))
    if begin is None or end is None or end < begin:
        return None
    return begin, end


def _nonnegative_int(value: object) -> Optional[int]:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _strip_escaped_ranges(body: str, ranges) -> str:  # type: ignore[no-untyped-def]
    result = []
    escaped_offset = 0
    sorted_ranges = sorted(ranges)
    range_index = 0
    for character in body:
        next_offset = escaped_offset + _escaped_text_length(character)
        while range_index < len(sorted_ranges) and escaped_offset >= sorted_ranges[range_index][1]:
            range_index += 1
        if not (
            range_index < len(sorted_ranges)
            and escaped_offset >= sorted_ranges[range_index][0]
            and next_offset <= sorted_ranges[range_index][1]
        ):
            result.append(character)
        escaped_offset = next_offset
    return "".join(result)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _namespace(tag: str) -> str:
    if not tag.startswith("{"):
        return ""
    return tag[1:].partition("}")[0]


def _bounded_id(value: str, maximum: int) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise InvalidCommand("message identifier is invalid")
    return normalized


def _required_address(value: str, field: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError("{} must not be empty".format(field))
    return normalized


def _error_type(condition: XmppMessageError) -> str:
    if condition is XmppMessageError.BAD_REQUEST:
        return "modify"
    return "cancel"
