import base64
import hashlib
import unittest
from xml.etree import ElementTree as ET

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from xmpp_transport.adapters.xmpp.addressing import ContactAddressCodec
from xmpp_transport.adapters.xmpp.roster import XmppServerRoster
from xmpp_transport.domain.identifiers import BindingId, RemoteObjectId
from xmpp_transport.domain.models import Avatar, Contact


NAMESPACE = "urn:xabber:transport:max:1"


class Wire:
    def __init__(self) -> None:
        self.requests = []
        self.sent = []

    async def request(self, element: ET.Element, timeout: float = 10.0) -> ET.Element:
        self.requests.append(element)
        response = ET.Element("iq", {"type": "result"})
        ET.SubElement(response, "{{{}}}query".format(NAMESPACE), {"status": "updated"})
        return response


    async def send(self, element: ET.Element) -> None:
        self.sent.append(element)

class Bindings:
    async def xmpp_account_for_binding(self, binding_id):  # type: ignore[no-untyped-def]
        return "user@example.com"


class XmppServerRosterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.wire = Wire()
        self.roster = XmppServerRoster(
            self.wire,
            Bindings(),  # type: ignore[arg-type]
            ContactAddressCodec("max.example.com"),
            "max.example.com",
            "example.com",
            NAMESPACE,
            ("MAX",),
            "shared-roster-iq-secret-at-least-32-bytes",
        )
        self.contact = Contact(RemoteObjectId("42"), "Alice")

    def decrypted_request(self, iq: ET.Element) -> ET.Element:
        query = iq.find("{{{}}}query".format(NAMESPACE))
        assert query is not None
        payload = query.find("payload")
        assert payload is not None and payload.text is not None
        self.assertEqual("aes-256-gcm", payload.attrib["encoding"])
        packed = base64.b64decode(payload.text)
        key = hashlib.sha256(
            b"xabber-roster-iq-v1\x00shared-roster-iq-secret-at-least-32-bytes"
        ).digest()
        return ET.fromstring(AESGCM(key).decrypt(packed[:12], packed[12:], None))

    async def test_add_contact_matches_server_module_contract(self) -> None:
        await self.roster.add_contact(BindingId("binding-1"), self.contact)

        iq = self.wire.requests[0]
        query = self.decrypted_request(iq)
        fields = {
            child.attrib["name"]: child.text
            for child in query
            if child.tag.rsplit("}", 1)[-1] == "field"
        }
        self.assertEqual("set", iq.attrib["type"])
        self.assertNotIn("id", iq.attrib)
        self.assertEqual("max.example.com", iq.attrib["from"])
        self.assertEqual("example.com", iq.attrib["to"])
        self.assertEqual("add-roster-contact", query.attrib["op"])
        self.assertEqual("user@example.com", fields["owner_jid"])
        self.assertEqual("chat-42@max.example.com", fields["contact_jid"])
        self.assertEqual("Alice", fields["name"])
        self.assertEqual("MAX", query.findtext("group"))

    async def test_encrypted_payload_changes_for_each_request(self) -> None:
        await self.roster.add_contact(BindingId("binding-1"), self.contact)
        await self.roster.add_contact(BindingId("binding-1"), self.contact)
        first = self.wire.requests[0].find(".//payload")
        second = self.wire.requests[1].find(".//payload")
        assert first is not None and second is not None
        self.assertNotEqual(first.text, second.text)
        self.assertEqual(
            ET.tostring(self.decrypted_request(self.wire.requests[0])),
            ET.tostring(self.decrypted_request(self.wire.requests[1])),
        )

    async def test_modified_payload_cannot_be_decrypted(self) -> None:
        await self.roster.add_contact(BindingId("binding-1"), self.contact)
        payload = self.wire.requests[0].find(".//payload")
        assert payload is not None and payload.text is not None
        packed = bytearray(base64.b64decode(payload.text))
        packed[-1] ^= 1
        payload.text = base64.b64encode(packed).decode("ascii")
        with self.assertRaises(Exception):
            self.decrypted_request(self.wire.requests[0])

    def test_rejects_empty_component_password(self) -> None:
        with self.assertRaisesRegex(ValueError, "component_password"):
            XmppServerRoster(
                self.wire,
                Bindings(),  # type: ignore[arg-type]
                ContactAddressCodec("telegram.example.com"),
                "telegram.example.com",
                "example.com",
                NAMESPACE,
                ("Telegram",),
                "",
            )

    async def test_remove_contact_omits_group(self) -> None:
        await self.roster.remove_contact(BindingId("binding-1"), self.contact)

        query = self.decrypted_request(self.wire.requests[0])
        self.assertEqual("remove-roster-contact", query.attrib["op"])
        self.assertIsNone(query.find("group"))

    async def test_add_contact_publishes_external_avatar_metadata(self) -> None:
        contact = Contact(
            RemoteObjectId("42"),
            "Alice",
            avatar=Avatar(
                "https://max.example/avatar.jpg",
                "avatar-id",
                "image/jpeg",
                12345,
            ),
        )

        await self.roster.add_contact(BindingId("binding-1"), contact)

        message = self.wire.sent[0]
        self.assertEqual("chat-42@max.example.com", message.attrib["from"])
        self.assertEqual("user@example.com", message.attrib["to"])
        self.assertEqual("headline", message.attrib["type"])
        metadata = message.find(".//{urn:xmpp:avatar:metadata}metadata")
        assert metadata is not None
        info = metadata.find("info")
        self.assertIsNotNone(info)
        assert info is not None
        self.assertEqual(
            {
                "bytes": "12345",
                "id": "avatar-id",
                "type": "image/jpeg",
                "url": "https://max.example/avatar.jpg",
            },
            info.attrib,
        )

if __name__ == "__main__":
    unittest.main()
