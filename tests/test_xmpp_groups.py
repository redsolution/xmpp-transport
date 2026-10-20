import unittest
from typing import Optional, Sequence
from xml.etree import ElementTree as ET

from xmpp_transport.adapters.xmpp.groups import XmppGroupManager
from xmpp_transport.adapters.xmpp.namespaces import GROUPS_NS
from xmpp_transport.domain.identifiers import BackendId, BindingId, RemoteObjectId
from xmpp_transport.domain.models import Avatar, Conversation, ConversationKind, Participant
from xmpp_transport.ports.repositories import BindingRecord


class FakeBindings:
    async def xmpp_account_for_binding(self, binding_id: BindingId) -> Optional[str]:
        return "user@example.com"

    async def active_bindings(self) -> Sequence[BindingRecord]:
        return ()


class FakeWire:
    def __init__(self) -> None:
        self.requests = []
        self.sent = []

    async def request(self, element: ET.Element, timeout: float = 10.0) -> ET.Element:
        self.requests.append(element)
        return ET.Element("iq", {"type": "result"})

    async def send(self, element: ET.Element) -> None:
        self.sent.append(element)


class AvatarRejectingWire(FakeWire):
    async def request(self, element: ET.Element, timeout: float = 10.0) -> ET.Element:
        self.requests.append(element)
        if element.find(".//{urn:xmpp:avatar:metadata}info") is not None:
            response = ET.fromstring(
                """
                <iq xmlns='jabber:client' type='error'>
                  <error code='500' type='wait'>
                    <internal-server-error xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>
                  </error>
                </iq>
                """
            )
            error = RuntimeError("avatar rejected")
            error.iq = type("Iq", (), {"xml": response})()  # type: ignore[attr-defined]
            raise error
        return ET.Element("iq", {"type": "result"})


class ExistingInvitationWire(FakeWire):
    async def request(self, element: ET.Element, timeout: float = 10.0) -> ET.Element:
        self.requests.append(element)
        if element.find("{{{}}}invite".format(GROUPS_NS)) is not None:
            response = ET.fromstring(
                "<iq type='error'><error><conflict "
                "xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"
            )
            error = RuntimeError("already invited")
            error.iq = type("Iq", (), {"xml": response})()  # type: ignore[attr-defined]
            raise error
        return ET.Element("iq", {"type": "result"})


class XmppGroupManagerTests(unittest.IsolatedAsyncioTestCase):
    async def test_creates_and_updates_transport_owned_group(self) -> None:
        wire = FakeWire()
        manager = XmppGroupManager(
            wire,  # type: ignore[arg-type]
            FakeBindings(),  # type: ignore[arg-type]
            "max.example.com",
            "example.com",
            "bot",
            "maxg",
            "MAX",
        )

        await manager.ensure_group(
            BindingId("binding-1"),
            Conversation(
                RemoteObjectId("-888"),
                ConversationKind.GROUP,
                "MAX Group",
                participants=(Participant(RemoteObjectId("7"), "Alice"),),
                attributes={"owner_remote_id": "100"},
            ),
        )

        self.assertEqual(3, len(wire.requests))
        create_iq, owner_invite, member_invite = wire.requests
        localpart = "maxg-75736572406578616d706c652e636f6d--888"
        self.assertEqual("bot@max.example.com", create_iq.attrib["from"])
        self.assertEqual("example.com", create_iq.attrib["to"])
        create = create_iq.find("{{{}}}create".format(GROUPS_NS))
        self.assertIsNotNone(create)
        assert create is not None
        self.assertEqual(localpart, create.find("group/localpart").text)
        self.assertEqual("MAX Group", create.find("group/info/name").text)
        self.assertEqual("public", create.find("group").attrib["privacy"])
        self.assertEqual("private", create.find("group/settings/membership").text)
        invite_tag = "{{{}}}invite".format(GROUPS_NS)
        self.assertEqual(
            "user@example.com", owner_invite.find(invite_tag + "/jid").text
        )
        self.assertEqual("false", owner_invite.find(invite_tag + "/send").text)
        self.assertEqual(
            "chat-99@max.example.com",
            member_invite.find(invite_tag + "/jid").text,
        )
        self.assertEqual(3, len(wire.sent))
        owner_message = wire.sent[0]
        self.assertEqual("message", owner_message.tag)
        self.assertEqual("user@example.com", owner_message.attrib["to"])
        self.assertEqual("bot@max.example.com", owner_message.attrib["from"])
        self.assertEqual(
            localpart + "@example.com",
            owner_message.find("{{{}}}invite".format(GROUPS_NS)).attrib["jid"],
        )
        self.assertEqual(
            "MAX Group",
            owner_message.find("{{{}}}group/info/name".format(GROUPS_NS)).text,
        )
        self.assertEqual(
            ["subscribe", "subscribed"],
            [presence.attrib["type"] for presence in wire.sent[1:]],
        )
        self.assertEqual("chat-99@max.example.com", wire.sent[1].attrib["from"])

        await manager.ensure_group(
            BindingId("binding-1"),
            Conversation(
                RemoteObjectId("-888"),
                ConversationKind.GROUP,
                "MAX Group",
                participants=(Participant(RemoteObjectId("7"), "Alice"),),
                attributes={"owner_remote_id": "100"},
            ),
        )
        self.assertEqual(3, len(wire.requests))
        self.assertEqual(3, len(wire.sent))

    async def test_existing_invitation_still_sends_owner_message(self) -> None:
        wire = ExistingInvitationWire()
        manager = XmppGroupManager(
            wire,  # type: ignore[arg-type]
            FakeBindings(),  # type: ignore[arg-type]
            "max.example.com",
            "example.com",
            "bot",
            "maxg",
            "MAX",
        )
        await manager.ensure_group(
            BindingId("binding-1"),
            Conversation(RemoteObjectId("-888"), ConversationKind.GROUP, "MAX Group"),
        )
        self.assertEqual(1, len(wire.sent))
        self.assertIsNotNone(
            wire.sent[0].find("{{{}}}invite".format(GROUPS_NS))
        )


    async def test_updates_group_avatar_with_external_metadata(self) -> None:
        wire = FakeWire()
        manager = XmppGroupManager(
            wire,  # type: ignore[arg-type]
            FakeBindings(),  # type: ignore[arg-type]
            "max.example.com",
            "example.com",
            "bot",
            "maxg",
            "MAX",
        )
        await manager.ensure_group(
            BindingId("binding-1"),
            Conversation(
                RemoteObjectId("-888"),
                ConversationKind.GROUP,
                "MAX Group",
                avatar=Avatar(
                    "https://max.example/avatar.jpg",
                    "avatar-id",
                    "image/jpeg",
                ),
            ),
        )

        avatar_iq = wire.requests[2]
        info = avatar_iq.find(".//{urn:xmpp:avatar:metadata}info")
        self.assertIsNotNone(info)
        assert info is not None
        self.assertEqual("524288", info.attrib["bytes"])
        self.assertEqual("avatar-id", info.attrib["id"])
        self.assertEqual("image/jpeg", info.attrib["type"])
        self.assertEqual("https://max.example/avatar.jpg", info.attrib["url"])

    async def test_handles_group_avatar_iq_rejection_without_traceback(self) -> None:
        wire = AvatarRejectingWire()
        manager = XmppGroupManager(
            wire,  # type: ignore[arg-type]
            FakeBindings(),  # type: ignore[arg-type]
            "telegram.example.com",
            "example.com",
            "bot",
            "telegramg",
            "TELEGRAM",
        )

        with self.assertLogs(
            "xmpp_transport.adapters.xmpp.groups", level="WARNING"
        ) as captured:
            await manager.ensure_group(
                BindingId("binding-1"),
                Conversation(
                    RemoteObjectId("-888"),
                    ConversationKind.GROUP,
                    "Telegram Group",
                    avatar=Avatar(
                        "http://127.0.0.1:8088/avatar/avatar.jpg",
                        "avatar-id",
                        "image/jpeg",
                        4570,
                    ),
                ),
            )

        self.assertEqual(1, len(captured.records))
        self.assertIsNone(captured.records[0].exc_info)
        self.assertIn("code=500", captured.output[0])
        self.assertIn("condition=internal-server-error", captured.output[0])

if __name__ == "__main__":
    unittest.main()
