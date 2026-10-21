"""Roster mutations through the privileged Xabber Server helper module."""

import hashlib
import hmac
import time
from typing import Protocol, Sequence
from xml.etree import ElementTree as ET

from xmpp_transport.domain.identifiers import BindingId
from xmpp_transport.domain.models import Contact
from xmpp_transport.ports.repositories import BindingRepository

from .addressing import ContactAddressCodec
from .namespaces import PUBSUB_AVATAR_METADATA_NS, PUBSUB_EVENT_NS


class IqWire(Protocol):
    async def request(self, element: ET.Element, timeout: float = 10.0) -> ET.Element:
        ...


    async def send(self, element: ET.Element) -> None:
        ...

class XmppServerRoster:
    TOTP_PERIOD = 30
    TOTP_DIGITS = 8

    def __init__(
        self,
        wire: IqWire,
        bindings: BindingRepository,
        addresses: ContactAddressCodec,
        component_domain: str,
        server_domain: str,
        namespace: str,
        groups: Sequence[str],
        component_password: str,
    ) -> None:
        if not component_password:
            raise ValueError("component_password must not be empty")
        self._wire = wire
        self._bindings = bindings
        self._addresses = addresses
        self._component_domain = component_domain
        self._server_domain = server_domain
        self._namespace = namespace
        self._groups = tuple(groups)
        self._component_password = component_password.encode("utf-8")

    async def add_contact(self, binding_id: BindingId, contact: Contact) -> None:
        await self._mutate("add-roster-contact", binding_id, contact)

    async def rename_contact(self, binding_id: BindingId, contact: Contact) -> None:
        await self._mutate("rename-roster-contact", binding_id, contact)

    async def remove_contact(self, binding_id: BindingId, contact: Contact) -> None:
        await self._mutate("remove-roster-contact", binding_id, contact)

    async def _mutate(
        self, operation: str, binding_id: BindingId, contact: Contact
    ) -> None:
        owner_jid = await self._bindings.xmpp_account_for_binding(binding_id)
        if owner_jid is None:
            raise LookupError("active XMPP account not found for roster synchronization")
        iq = ET.Element(
            "iq",
            {
                "type": "set",
                "from": self._component_domain,
                "to": self._server_domain,
            },
        )
        query = ET.SubElement(iq, "{{{}}}query".format(self._namespace))
        request = ET.Element("request", {"op": operation})
        fields = {
            "owner_jid": owner_jid,
            "contact_jid": self._addresses.contact_jid(contact.id),
            "name": contact.display_name,
        }
        for name, value in fields.items():
            field = ET.SubElement(request, "field", {"name": name})
            field.text = value
        if operation != "remove-roster-contact":
            for group_name in self._groups:
                ET.SubElement(request, "group").text = group_name
        query.append(request)
        counter = int(time.time()) // self.TOTP_PERIOD
        counter_bytes = counter.to_bytes(8, "big")
        digest = hmac.new(self._component_password, counter_bytes, hashlib.sha256).digest()
        offset = digest[-1] & 0x0F
        code = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
        code %= 10 ** self.TOTP_DIGITS
        ET.SubElement(
            query,
            "verification_code",
            {
                "algorithm": "totp-sha256",
            },
        ).text = "{:08d}".format(code)
        response = await self._wire.request(iq)
        result = response.find("{{{}}}query".format(self._namespace))
        if result is not None and result.attrib.get("status", "ok") not in {
            "ok", "updated", "unchanged", "removed"
        }:
            raise ConnectionError("XMPP roster helper did not complete operation")
        if operation != "remove-roster-contact" and contact.avatar is not None:
            await self._publish_avatar(owner_jid, contact)

    async def _publish_avatar(self, owner_jid: str, contact: Contact) -> None:
        avatar = contact.avatar
        if avatar is None:
            return
        avatar_id = avatar.version or avatar.reference
        message = ET.Element(
            "message",
            {
                "from": self._addresses.contact_jid(contact.id),
                "to": owner_jid,
                "type": "headline",
            },
        )
        event = ET.SubElement(message, "{{{}}}event".format(PUBSUB_EVENT_NS))
        items = ET.SubElement(
            event,
            "{{{}}}items".format(PUBSUB_EVENT_NS),
            {"node": PUBSUB_AVATAR_METADATA_NS},
        )
        item = ET.SubElement(
            items, "{{{}}}item".format(PUBSUB_EVENT_NS), {"id": avatar_id}
        )
        metadata = ET.SubElement(
            item, "{{{}}}metadata".format(PUBSUB_AVATAR_METADATA_NS)
        )
        ET.SubElement(
            metadata,
            "info",
            {
                "bytes": str(max(avatar.size, 0)),
                "id": avatar_id,
                "type": avatar.content_type,
                "url": avatar.reference,
            },
        )
        await self._wire.send(message)
