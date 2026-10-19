"""Direct-message boundary between XEP-0114 wire traffic and the application."""

import logging
from dataclasses import replace
from typing import Awaitable, Callable, Optional, Protocol
from xml.etree import ElementTree as ET

from xmpp_transport.application.message_router import MessageRouter
from xmpp_transport.domain.errors import AuthorizationRequired, FeatureUnavailable, InvalidCommand
from xmpp_transport.domain.identifiers import RemoteObjectId
from xmpp_transport.domain.models import IncomingMessage
from xmpp_transport.ports.repositories import BindingRepository

from .addressing import ContactAddressCodec, DirectRouteResolver, InvalidXmppAddress
from .auth_commands import ControlResponse
from .message_codec import XmppMessageCodec, XmppMessageError
from .namespaces import BOT_UI_NS, DATA_FORMS_NS, GROUPS_NS


log = logging.getLogger(__name__)
MessageHandler = Callable[[ET.Element], Awaitable[None]]


class ControlHandler(Protocol):
    def accepts(self, to_jid: str) -> bool:
        ...

    async def handle(
        self, from_jid: str, command: str, form_fields: Optional[dict] = None
    ) -> ControlResponse:
        ...


class XmppWire(Protocol):
    def set_message_handler(self, handler: MessageHandler) -> None:
        ...

    async def start(self) -> None:
        ...

    async def send(self, element: ET.Element) -> None:
        ...

    async def close(self) -> None:
        ...


class XmppDirectMessageGateway:
    def __init__(
        self,
        wire: XmppWire,
        routes: DirectRouteResolver,
        addresses: ContactAddressCodec,
        bindings: BindingRepository,
        messages: MessageRouter,
        codec: XmppMessageCodec,
        control: Optional[ControlHandler] = None,
        transport_namespace: Optional[str] = None,
        server_domain: Optional[str] = None,
        group_localpart_prefix: Optional[str] = None,
    ) -> None:
        self._wire = wire
        self._routes = routes
        self._addresses = addresses
        self._bindings = bindings
        self._messages = messages
        self._codec = codec
        self._control = control
        self._transport_namespace = transport_namespace
        self._server_domain = server_domain
        self._group_localpart_prefix = group_localpart_prefix
        self._wire.set_message_handler(self.handle_stanza)

    async def start(self) -> None:
        await self._wire.start()

    async def close(self) -> None:
        await self._wire.close()

    async def handle_stanza(self, stanza: ET.Element) -> None:
        try:
            groups = stanza.find("{{{}}}x".format(GROUPS_NS))
            if groups is not None and groups.find(
                "{{{}}}system-message".format(GROUPS_NS)
            ) is not None:
                return
            fake_outgoing_tag = (
                "{{{}}}fake-outgoing".format(self._transport_namespace)
                if self._transport_namespace
                else None
            )
            if fake_outgoing_tag and stanza.find(fake_outgoing_tag) is not None:
                return
            group_route = await self._group_route(stanza)
            if group_route is not None:
                route, body = group_route
                message = self._codec.parse_outgoing(
                    stanza, route.binding_id, route.conversation_id
                )
                await self._messages.send(
                    replace(
                        message,
                        text=_strip_group_author_prefix(message.text or "") or None,
                        attributes={"is_group": "true"},
                    )
                )
                return
            if self._is_group_fanout_stanza(stanza):
                return
            if self._is_group_service_stanza(stanza):
                return
            if self._control is not None and self._control.accepts(
                stanza.attrib.get("to", "")
            ):
                body = ""
                for child in stanza:
                    if child.tag.rsplit("}", 1)[-1] == "body":
                        body = "".join(child.itertext())
                        break
                callback = stanza.find("{{{}}}callback".format(BOT_UI_NS))
                if callback is not None and callback.attrib.get("data"):
                    body = callback.attrib["data"]
                if body.strip().lower().startswith("/password"):
                    log.debug("XMPP control password stanza received")
                response = await self._control.handle(
                    stanza.attrib.get("from", ""),
                    body,
                    _data_form_fields(stanza),
                )
                await self._wire.send(self._codec.control_reply(stanza, response))
                return
            route = await self._routes.resolve(
                stanza.attrib.get("from", ""), stanza.attrib.get("to", "")
            )
            if route is None:
                await self._send_error(stanza, XmppMessageError.SERVICE_UNAVAILABLE)
                return
            callback = stanza.find("{{{}}}callback".format(BOT_UI_NS))
            if callback is not None and callback.attrib.get("data"):
                if not await self._messages.activate_button(
                    route.binding_id,
                    route.conversation_id,
                    callback.attrib["data"],
                ):
                    raise InvalidCommand("unknown message button callback")
                return
            message = self._codec.parse_outgoing(
                stanza, route.binding_id, route.conversation_id
            )
            if message.text and await self._messages.activate_button(
                route.binding_id, route.conversation_id, message.text
            ):
                return
            await self._messages.send(message)
        except (InvalidCommand, InvalidXmppAddress):
            await self._send_error(stanza, XmppMessageError.BAD_REQUEST)
        except (AuthorizationRequired, FeatureUnavailable, LookupError):
            await self._send_error(stanza, XmppMessageError.SERVICE_UNAVAILABLE)
        except Exception as exc:
            log.error(
                "XMPP message handling failed exception_type=%s",
                type(exc).__name__,
            )
            await self._send_error(stanza, XmppMessageError.SERVICE_UNAVAILABLE)

    async def _group_route(self, stanza: ET.Element):  # type: ignore[no-untyped-def]
        if not self._server_domain or not self._group_localpart_prefix:
            return None
        if self._control is None or not self._control.accepts(
            stanza.attrib.get("to", "")
        ):
            return None
        from_jid = stanza.attrib.get("from", "").split("/", 1)[0]
        localpart, separator, domain = from_jid.partition("@")
        prefix = self._group_localpart_prefix + "-"
        if not separator or domain != self._server_domain or not localpart.startswith(prefix):
            return None
        payload = localpart[len(prefix) :]
        owner_hex, separator, conversation_id = payload.partition("-")
        if not separator or not owner_hex or not conversation_id:
            return None
        try:
            owner_jid = bytes.fromhex(owner_hex).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
        body = next(
            ("".join(child.itertext()) for child in stanza if child.tag.rsplit("}", 1)[-1] == "body"),
            "",
        )
        groups = stanza.find("{{{}}}x".format(GROUPS_NS))
        user = (
            groups.find("{{{}}}user".format(GROUPS_NS))
            if groups is not None
            else None
        )
        jid = self._child_by_local_name(user, "jid") if user is not None else None
        embedded_sender = (jid.text or "").strip().split("/", 1)[0] if jid is not None else ""
        if not embedded_sender and body and not _looks_like_group_service_message(body):
            embedded_sender = owner_jid
        if embedded_sender != owner_jid:
            return None
        route = await self._routes.resolve_group(
            owner_jid, RemoteObjectId(conversation_id)
        )
        if route is None:
            return None
        return route, body

    def _is_group_service_stanza(self, stanza: ET.Element) -> bool:
        if not self._server_domain or not self._group_localpart_prefix:
            return False
        if self._control is None or not self._control.accepts(
            stanza.attrib.get("to", "")
        ):
            return False
        from_jid = stanza.attrib.get("from", "").split("/", 1)[0]
        localpart, separator, domain = from_jid.partition("@")
        if (
            not separator
            or domain != self._server_domain
            or not localpart.startswith(self._group_localpart_prefix + "-")
        ):
            return False
        body = next(
            ("".join(child.itertext()) for child in stanza if child.tag.rsplit("}", 1)[-1] == "body"),
            "",
        )
        return not body or _looks_like_group_service_message(body)

    def _is_group_fanout_stanza(self, stanza: ET.Element) -> bool:
        if not self._server_domain or not self._group_localpart_prefix:
            return False
        if self._control is None or not self._control.accepts(
            stanza.attrib.get("to", "")
        ):
            return False
        from_jid = stanza.attrib.get("from", "").split("/", 1)[0]
        localpart, separator, domain = from_jid.partition("@")
        return (
            bool(separator)
            and domain == self._server_domain
            and localpart.startswith(self._group_localpart_prefix + "-")
        )

    @staticmethod
    def _child_by_local_name(parent: ET.Element, local_name: str) -> Optional[ET.Element]:
        for child in parent:
            if child.tag.rsplit("}", 1)[-1] == local_name:
                return child
        return None

    async def deliver_message(self, message: IncomingMessage) -> None:
        delivery = XmppMessageDelivery(
            self._wire, self._addresses, self._bindings, self._codec
        )
        await delivery.deliver_message(message)

    async def _send_error(
        self, request: ET.Element, condition: XmppMessageError
    ) -> None:
        response = self._codec.error_reply(request, condition)
        await self._wire.send(response)


class XmppMessageDelivery:
    """Outbound XMPP sink separated from stanza ingestion for acyclic wiring."""

    def __init__(
        self,
        wire: XmppWire,
        addresses: ContactAddressCodec,
        bindings: BindingRepository,
        codec: XmppMessageCodec,
        *,
        server_domain: Optional[str] = None,
        control_jid: Optional[str] = None,
        transport_namespace: Optional[str] = None,
        group_localpart_prefix: Optional[str] = None,
        member_fallback_prefix: Optional[str] = None,
    ) -> None:
        self._wire = wire
        self._addresses = addresses
        self._bindings = bindings
        self._codec = codec
        self._server_domain = server_domain
        self._control_jid = control_jid
        self._transport_namespace = transport_namespace
        self._group_localpart_prefix = group_localpart_prefix
        self._member_fallback_prefix = member_fallback_prefix

    async def deliver_message(self, message: IncomingMessage) -> None:
        owner_jid = await self._bindings.xmpp_account_for_binding(message.binding_id)
        if owner_jid is None:
            raise LookupError("active XMPP account not found for binding")
        if message.attributes.get("is_group") == "true":
            if not all(
                (
                    self._server_domain,
                    self._control_jid,
                    self._transport_namespace,
                    self._group_localpart_prefix,
                    self._member_fallback_prefix,
                )
            ):
                raise LookupError("group message delivery is not configured")
            token = "".join(
                character
                for character in str(message.conversation_id)
                if character.isalnum() or character in "-_"
            ) or "unknown"
            group_jid = "{}-{}-{}@{}".format(
                self._group_localpart_prefix,
                owner_jid.encode("utf-8").hex(),
                token,
                self._server_domain,
            )
            is_self = message.attributes.get("is_self") == "true"
            sender_jid = (
                self._control_jid
                if is_self
                else self._group_member_jid(message)
            )
            message = self._with_forward_addresses(message, owner_jid, group_jid)
            stanza = self._codec.serialize_group_message(
                message,
                sender_jid,
                group_jid,
                self._transport_namespace,
                fake_outgoing=is_self,
            )
            await self._wire.send(stanza)
            return
        sender_jid = self._addresses.contact_jid(message.conversation_id)
        message = self._with_forward_addresses(message, owner_jid, owner_jid)
        stanza = self._codec.serialize_incoming(message, sender_jid, owner_jid)
        await self._wire.send(stanza)

    def _with_forward_addresses(
        self, message: IncomingMessage, owner_jid: str, fallback_recipient: str
    ) -> IncomingMessage:
        reference = message.forwarded_from
        if reference is None or reference.source_name:
            return message
        sender_jid = owner_jid if reference.is_self else None
        if sender_jid is None and message.attributes.get("is_group") == "true":
            owner_remote_id = message.attributes.get("owner_remote_id", "")
            try:
                direct_chat_id = str(int(owner_remote_id) ^ int(str(reference.sender_id)))
            except (TypeError, ValueError):
                direct_chat_id = ""
            if direct_chat_id:
                sender_jid = self._addresses.contact_jid(RemoteObjectId(direct_chat_id))
        if sender_jid is None and reference.source_conversation_id is not None:
            sender_jid = self._addresses.contact_jid(reference.source_conversation_id)
        sender_jid = sender_jid or fallback_recipient
        recipient = fallback_recipient
        if (
            reference.source_conversation_id is not None
            and reference.source_conversation_id != message.conversation_id
        ):
            recipient = self._addresses.contact_jid(reference.source_conversation_id)
        return replace(
            message,
            forwarded_from=replace(
                reference,
                source_name=sender_jid,
                source_recipient=recipient,
            ),
        )

    def _group_member_jid(self, message: IncomingMessage) -> str:
        owner_remote_id = message.attributes.get("owner_remote_id", "")
        try:
            localpart = "chat-{}".format(
                int(owner_remote_id) ^ int(str(message.sender_id))
            )
        except (TypeError, ValueError):
            safe = "".join(
                character
                for character in str(message.sender_id)
                if character.isalnum() or character in "-_"
            ) or "unknown"
            localpart = "{}-user-{}".format(self._member_fallback_prefix, safe)
        return "{}@{}".format(localpart, self._addresses.component_domain)


def _strip_group_author_prefix(body: str) -> str:
    if ":\n" not in body:
        stripped = body.strip()
        if "\n" not in body and stripped.endswith(":") and "@" in stripped:
            return ""
        return body
    _author, text = body.split(":\n", 1)
    return text


def _looks_like_group_service_message(body: str) -> bool:
    normalized = " ".join(body.lower().split())
    return any(
        fragment in normalized
        for fragment in (
            " joined the group",
            " left the group",
            " was invited to the group",
            " was removed from the group",
        )
    )


def _data_form_fields(stanza: ET.Element) -> Optional[dict]:
    form = stanza.find("{{{}}}x".format(DATA_FORMS_NS))
    if form is None or form.attrib.get("type") != "submit":
        return None
    fields = {}
    for field in form.findall("{{{}}}field".format(DATA_FORMS_NS)):
        name = (field.attrib.get("var") or "").strip()
        value = field.find("{{{}}}value".format(DATA_FORMS_NS))
        if name:
            fields[name] = "" if value is None else (value.text or "")
    return fields
